package _189pc

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

const (
	casKey     = "zhlhlf"
	casExt     = ".bin"
	casContent = "zhlhlf"
)

type casPayload struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	MD5      string `json:"md5"`
	SliceMD5 string `json:"smd5"`
}

type casObject struct {
	model.Obj
	payload *casPayload
}

func (o *casObject) GetName() string {
	return o.payload.Name
}

func (o *casObject) GetSize() int64 {
	return o.payload.Size
}

func (o *casObject) GetHash() utils.HashInfo {
	return utils.NewHashInfo(utils.MD5, o.payload.MD5)
}

func encodeCASName(info *UploadHashInfo) (string, error) {
	if info == nil {
		return "", fmt.Errorf("missing cas upload info")
	}
	payload, err := utils.Json.Marshal(casPayload{
		Name:     info.Name,
		Size:     info.Size,
		MD5:      info.FileMD5,
		SliceMD5: info.SliceMD5,
	})
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(xorCAS(payload))
	return encoded + casExt, nil
}

func decodeCASName(name string) (*casPayload, error) {
	if !strings.HasSuffix(strings.ToLower(name), casExt) {
		return nil, fmt.Errorf("not a cas bin")
	}
	rawName := strings.TrimSuffix(name, path.Ext(name))
	data, err := base64.RawURLEncoding.DecodeString(rawName)
	if err != nil {
		return nil, err
	}
	var payload casPayload
	if err = utils.Json.Unmarshal(xorCAS(data), &payload); err != nil {
		return nil, err
	}
	if payload.Name == "" || payload.Size < 0 || payload.MD5 == "" {
		return nil, fmt.Errorf("invalid cas payload")
	}
	if payload.SliceMD5 == "" {
		payload.SliceMD5 = payload.MD5
	}
	return &payload, nil
}

func xorCAS(data []byte) []byte {
	out := make([]byte, len(data))
	key := []byte(casKey)
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func (y *Cloud189PC) decorateCASObjects(objs []model.Obj) []model.Obj {
	if !y.EnableCAS {
		return objs
	}
	for i, obj := range objs {
		if obj.IsDir() {
			continue
		}
		payload, err := decodeCASName(obj.GetName())
		if err != nil {
			continue
		}
		objs[i] = &casObject{Obj: obj, payload: payload}
	}
	return objs
}

func (y *Cloud189PC) uploadCASPlaceholder(ctx context.Context, dstDir model.Obj, info *UploadHashInfo) (model.Obj, error) {
	casName, err := encodeCASName(info)
	if err != nil {
		return nil, err
	}
	payload, err := decodeCASName(casName)
	if err != nil {
		return nil, err
	}
	content := []byte(casContent)
	now := time.Now()
	obj := &model.Object{
		Name:     casName,
		Size:     int64(len(content)),
		Modified: now,
		Ctime:    now,
		HashInfo: utils.NewHashInfo(utils.MD5, utils.HashData(utils.MD5, content)),
	}
	fs := &stream.FileStream{
		Ctx:      ctx,
		Obj:      obj,
		Reader:   bytes.NewReader(content),
		Mimetype: "application/octet-stream",
	}
	casObj, err := y.putFile(ctx, dstDir, fs, func(float64) {}, false)
	if err != nil {
		return nil, err
	}
	return &casObject{Obj: casObj, payload: payload}, nil
}

func (y *Cloud189PC) linkCAS(ctx context.Context, obj *casObject, args model.LinkArgs) (*model.Link, error) {
	if y.familyTransferFolder == nil || y.familyTransferFolder.GetID() == "" {
		if err := y.createFamilyTransferFolder(); err != nil {
			return nil, err
		}
	}
	restoreInfo := &casPayload{
		Name:     fmt.Sprintf("00-zhlhlf-00--%s%s", uuid.NewString(), path.Ext(obj.payload.Name)),
		Size:     obj.payload.Size,
		MD5:      obj.payload.MD5,
		SliceMD5: obj.payload.SliceMD5,
	}
	restored, err := y.restoreCASDirect(ctx, y.familyTransferFolder, restoreInfo, true, true)
	if err != nil {
		return nil, err
	}
	link, err := y.linkObj(ctx, restored, args, true)
	go func() {
		if err := y.Delete(context.TODO(), y.FamilyID, restored); err != nil {
			utils.Log.Errorf("189pc cas temp delete error: %s", err)
		}
	}()
	return link, err
}

func (y *Cloud189PC) restoreCASDirect(ctx context.Context, dstDir model.Obj, info *casPayload, isFamily bool, overwrite bool) (model.Obj, error) {
	sliceSize := partSize(info.Size)
	fullUrl := UPLOAD_URL
	if isFamily {
		fullUrl += "/family"
	} else {
		fullUrl += "/person"
	}
	params := Params{
		"parentFolderId": dstDir.GetID(),
		"fileName":       url.QueryEscape(info.Name),
		"fileSize":       fmt.Sprint(info.Size),
		"fileMd5":        strings.ToUpper(info.MD5),
		"sliceSize":      fmt.Sprint(sliceSize),
		"sliceMd5":       strings.ToUpper(info.SliceMD5),
	}
	if isFamily {
		params.Set("familyId", y.FamilyID)
	}
	var uploadInfo InitMultiUploadResp
	_, err := y.request(fullUrl+"/initMultiUpload", http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, params, &uploadInfo, isFamily)
	if err != nil {
		return nil, err
	}
	if uploadInfo.Data.FileDataExists != 1 {
		return nil, fmt.Errorf("cas restore failed: source file data does not exist in cloud")
	}
	var resp CommitMultiUploadFileResp
	_, err = y.request(fullUrl+"/commitMultiUploadFile", http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, Params{
		"uploadFileId": uploadInfo.Data.UploadFileID,
		"isLog":        "0",
		"opertype":     IF(overwrite, "3", "1"),
	}, &resp, isFamily)
	if err != nil {
		return nil, err
	}
	return resp.toFile(), nil
}

func (y *Cloud189PC) linkObj(ctx context.Context, file model.Obj, args model.LinkArgs, isFamily bool) (*model.Link, error) {
	var downloadUrl struct {
		URL string `json:"fileDownloadUrl"`
	}
	fullUrl := API_URL
	if isFamily {
		fullUrl += "/family/file"
	}
	fullUrl += "/getFileDownloadUrl.action"

	_, err := y.get(fullUrl, func(r *resty.Request) {
		r.SetContext(ctx)
		r.SetQueryParam("fileId", file.GetID())
		if isFamily {
			r.SetQueryParams(map[string]string{
				"familyId": y.FamilyID,
			})
		} else {
			r.SetQueryParams(map[string]string{
				"dt":   "3",
				"flag": "1",
			})
		}
	}, &downloadUrl, isFamily)
	if err != nil {
		return nil, err
	}
	downloadUrl.URL = strings.Replace(strings.ReplaceAll(downloadUrl.URL, "&amp;", "&"), "http://", "https://", 1)
	res, err := base.NoRedirectClient.R().SetContext(ctx).SetDoNotParseResponse(true).Get(downloadUrl.URL)
	if err != nil {
		return nil, err
	}
	defer res.RawBody().Close()
	if res.StatusCode() == 302 {
		downloadUrl.URL = res.Header().Get("location")
	}
	return &model.Link{
		URL: downloadUrl.URL,
		Header: http.Header{
			"User-Agent": []string{base.UserAgent},
		},
	}, nil
}
