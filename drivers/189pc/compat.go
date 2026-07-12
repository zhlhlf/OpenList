package _189pc

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/torrent"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/go-resty/resty/v2"
)

func ComputeSliceMD5sFromReader(reader io.Reader, sliceSize int64) (string, []string, error) {
	if sliceSize <= 0 {
		sliceSize = 10 * 1024 * 1024
	}

	fileMD5Hash := utils.MD5.NewFunc()
	sliceMD5s := make([]string, 0)
	buf := make([]byte, sliceSize)

	for {
		n, err := io.ReadFull(reader, buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = fileMD5Hash.Write(chunk)
			sliceMD5s = append(sliceMD5s, strings.ToUpper(utils.HashData(utils.MD5, chunk)))
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "", nil, err
		}
	}

	fileMD5Hex := strings.ToUpper(hex.EncodeToString(fileMD5Hash.Sum(nil)))
	return fileMD5Hex, sliceMD5s, nil
}

func (y *Cloud189PC) OldUploadCreate(ctx context.Context, parentFolderID, fileMD5, fileName, fileSize string, isFamily bool) (*CreateUploadFileResp, error) {
	size, err := strconv.ParseInt(fileSize, 10, 64)
	if err != nil {
		return nil, err
	}

	fullURL := UPLOAD_URL
	if isFamily {
		fullURL += "/family"
	} else {
		fullURL += "/person"
	}

	params := Params{
		"parentFolderId": parentFolderID,
		"fileName":       url.QueryEscape(fileName),
		"fileSize":       fileSize,
		"fileMd5":        strings.ToUpper(fileMD5),
		"sliceSize":      fmt.Sprint(partSize(size)),
		"sliceMd5":       strings.ToUpper(fileMD5),
	}
	if isFamily {
		params.Set("familyId", y.FamilyID)
	}

	var uploadInfo InitMultiUploadResp
	_, err = y.request(fullURL+"/initMultiUpload", http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, params, &uploadInfo, isFamily)
	if err != nil {
		return nil, err
	}

	uploadFileID, err := strconv.ParseInt(uploadInfo.Data.UploadFileID, 10, 64)
	if err != nil {
		return nil, err
	}

	return &CreateUploadFileResp{
		UploadFileId:   uploadFileID,
		FileCommitUrl:  fullURL + "/commitMultiUploadFile",
		FileDataExists: uploadInfo.Data.FileDataExists,
	}, nil
}

func (y *Cloud189PC) OldUploadCommit(ctx context.Context, fileCommitURL string, uploadFileID int64, isFamily bool, overwrite bool) (model.Obj, error) {
	params := Params{
		"uploadFileId": fmt.Sprint(uploadFileID),
		"isLog":        "0",
		"opertype":     IF(overwrite, "3", "1"),
	}

	var resp CommitMultiUploadFileResp
	_, err := y.request(fileCommitURL, http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, params, &resp, isFamily)
	if err == nil {
		return resp.toFile(), nil
	}

	var oldResp OldCommitUploadFileResp
	_, oldErr := y.request(fileCommitURL, http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, params, &oldResp, isFamily)
	if oldErr != nil {
		return nil, err
	}
	return oldResp.toFile(), nil
}

func (y *Cloud189PC) RapidUploadFromTorrent(ctx context.Context, dstDir model.Obj, torrentData []byte, overwrite bool) (model.Obj, error) {
	isFamily := y.isFamily()

	t, err := torrent.Decode(torrentData)
	if err != nil {
		return nil, fmt.Errorf("decode torrent failed: %w", err)
	}
	if !t.HasCASInfo() {
		return nil, fmt.Errorf("torrent does not contain CAS info")
	}

	cas := t.CAS
	fileName := t.Info.Name
	fileSize := t.GetTotalSize()
	fileMD5Upper := strings.ToUpper(cas.FileMD5)

	sliceSize := cas.SliceSize
	if sliceSize <= 0 {
		sliceSize = partSize(fileSize)
	}

	sliceMD5Hex := strings.ToUpper(cas.SliceMD5)
	if sliceMD5Hex == "" {
		sliceMD5Hex = fileMD5Upper
	}
	if len(cas.SliceMD5s) > 1 {
		upperSliceMD5s := make([]string, len(cas.SliceMD5s))
		for i, s := range cas.SliceMD5s {
			upperSliceMD5s[i] = strings.ToUpper(s)
		}
		sliceMD5Hex = strings.ToUpper(utils.GetMD5EncodeStr(strings.Join(upperSliceMD5s, "\n")))
	}

	fullURL := UPLOAD_URL
	if isFamily {
		fullURL += "/family"
	} else {
		fullURL += "/person"
	}

	initParams := Params{
		"parentFolderId": dstDir.GetID(),
		"fileName":       url.QueryEscape(fileName),
		"fileSize":       fmt.Sprint(fileSize),
		"sliceSize":      fmt.Sprint(sliceSize),
		"lazyCheck":      "1",
	}
	if isFamily {
		initParams.Set("familyId", y.FamilyID)
	}

	var uploadInfo InitMultiUploadResp
	_, err = y.request(fullURL+"/initMultiUpload", http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, initParams, &uploadInfo, isFamily)
	if err != nil {
		return nil, fmt.Errorf("init multi upload failed: %w", err)
	}

	uploadFileID := uploadInfo.Data.UploadFileID
	checkParams := Params{
		"fileMd5":      fileMD5Upper,
		"sliceMd5":     sliceMD5Hex,
		"uploadFileId": uploadFileID,
	}
	var checkResp struct {
		Data struct {
			FileDataExists int `json:"fileDataExists"`
		} `json:"data"`
	}
	_, err = y.request(fullURL+"/checkTransSecond", http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, checkParams, &checkResp, isFamily)
	if err != nil {
		return nil, fmt.Errorf("rapid upload check failed: %w", err)
	}
	if checkResp.Data.FileDataExists != 1 {
		return nil, fmt.Errorf("rapid upload failed: file data not found in cloud (fileMD5=%s, sliceMD5=%s, size=%d)", fileMD5Upper, sliceMD5Hex, fileSize)
	}

	commitParams := Params{
		"uploadFileId": uploadFileID,
		"fileMd5":      fileMD5Upper,
		"sliceMd5":     sliceMD5Hex,
		"lazyCheck":    "1",
		"opertype":     IF(overwrite, "3", "1"),
	}
	var resp CommitMultiUploadFileResp
	_, err = y.request(fullURL+"/commitMultiUploadFile", http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, commitParams, &resp, isFamily)
	if err != nil {
		return nil, fmt.Errorf("commit rapid upload failed: %w", err)
	}
	return resp.toFile(), nil
}
