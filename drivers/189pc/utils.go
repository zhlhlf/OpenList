package _189pc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/pkg/errgroup"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"

	"github.com/avast/retry-go"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

const (
	ACCOUNT_TYPE = "02"
	APP_ID       = "8025431004"
	CLIENT_TYPE  = "10020"
	VERSION      = "6.2"

	WEB_URL    = "https://cloud.189.cn"
	AUTH_URL   = "https://open.e.189.cn"
	API_URL    = "https://api.cloud.189.cn"
	UPLOAD_URL = "https://upload.cloud.189.cn"

	RETURN_URL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"

	PC  = "TELEPC"
	MAC = "TELEMAC"

	CHANNEL_ID = "web_cloud.189.cn"
)

func (y *Cloud189PC) SignatureHeader(url, method, params string, isFamily bool) map[string]string {
	dateOfGmt := getHttpDateStr()
	sessionKey := y.getTokenInfo().SessionKey
	sessionSecret := y.getTokenInfo().SessionSecret
	if isFamily {
		sessionKey = y.getTokenInfo().FamilySessionKey
		sessionSecret = y.getTokenInfo().FamilySessionSecret
	}

	header := map[string]string{
		"Date":         dateOfGmt,
		"SessionKey":   sessionKey,
		"X-Request-ID": uuid.NewString(),
		"Signature":    signatureOfHmac(sessionSecret, sessionKey, method, url, dateOfGmt, params),
	}
	return header
}

func (y *Cloud189PC) EncryptParams(params Params, isFamily bool) string {
	sessionSecret := y.getTokenInfo().SessionSecret
	if isFamily {
		sessionSecret = y.getTokenInfo().FamilySessionSecret
	}
	if params != nil {
		return AesECBEncrypt(params.Encode(), sessionSecret[:16])
	}
	return ""
}

func (y *Cloud189PC) request(url, method string, callback base.ReqCallback, params Params, resp interface{}, isFamily ...bool) ([]byte, error) {
	req := y.getClient().R().SetQueryParams(clientSuffix())

	// 璁剧疆params
	paramsData := y.EncryptParams(params, isBool(isFamily...))
	if paramsData != "" {
		req.SetQueryParam("params", paramsData)
	}

	// Signature
	req.SetHeaders(y.SignatureHeader(url, method, paramsData, isBool(isFamily...)))

	var erron RespErr
	req.SetError(&erron)

	if callback != nil {
		callback(req)
	}
	if resp != nil {
		req.SetResult(resp)
	}
	res, err := req.Execute(method, url)
	if err != nil {
		return nil, err
	}
	if strings.Contains(res.String(), "userSessionBO is null") {
		if err = y.refreshSession(); err != nil {
			return nil, err
		}
		return y.request(url, method, callback, params, resp, isFamily...)
	}

	// if erron.ErrorCode == "InvalidSessionKey" || erron.Code == "InvalidSessionKey" {
	if strings.Contains(res.String(), "InvalidSessionKey") {
		if err = y.refreshSession(); err != nil {
			return nil, err
		}
		return y.request(url, method, callback, params, resp, isFamily...)
	}
	// 澶勭悊閿欒
	if erron.HasError() {
		return nil, &erron
	}
	return res.Body(), nil
}

func (y *Cloud189PC) get(url string, callback base.ReqCallback, resp interface{}, isFamily ...bool) ([]byte, error) {
	return y.request(url, http.MethodGet, callback, nil, resp, isFamily...)
}

func (y *Cloud189PC) post(url string, callback base.ReqCallback, resp interface{}, isFamily ...bool) ([]byte, error) {
	return y.request(url, http.MethodPost, callback, nil, resp, isFamily...)
}

func (y *Cloud189PC) put(ctx context.Context, url string, headers map[string]string, sign bool, file io.Reader, isFamily bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, file)
	if err != nil {
		return nil, err
	}

	query := req.URL.Query()
	for key, value := range clientSuffix() {
		query.Add(key, value)
	}
	req.URL.RawQuery = query.Encode()

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	if sign {
		for key, value := range y.SignatureHeader(url, http.MethodPut, "", isFamily) {
			req.Header.Add(key, value)
		}
	}

	resp, err := base.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var erron RespErr
	_ = jsoniter.Unmarshal(body, &erron)
	_ = xml.Unmarshal(body, &erron)
	if erron.HasError() {
		return nil, &erron
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("put fail,err:%s", string(body))
	}
	return body, nil
}
func (y *Cloud189PC) getFiles(ctx context.Context, fileId string, isFamily bool) ([]model.Obj, error) {
	res := make([]model.Obj, 0, 100)
	for pageNum := 1; ; pageNum++ {
		resp, err := y.getFilesWithPage(ctx, fileId, isFamily, pageNum, 1000, y.OrderBy, y.OrderDirection)
		if err != nil {
			return nil, err
		}
		// 鑾峰彇瀹屾瘯璺冲嚭
		if resp.FileListAO.Count == 0 {
			break
		}

		for i := 0; i < len(resp.FileListAO.FolderList); i++ {
			res = append(res, &resp.FileListAO.FolderList[i])
		}
		for i := 0; i < len(resp.FileListAO.FileList); i++ {
			res = append(res, &resp.FileListAO.FileList[i])
		}
	}
	return res, nil
}

func (y *Cloud189PC) getFilesWithPage(ctx context.Context, fileId string, isFamily bool, pageNum int, pageSize int, orderBy string, orderDirection string) (*Cloud189FilesResp, error) {
	fullUrl := API_URL
	if isFamily {
		fullUrl += "/family/file"
	}
	fullUrl += "/listFiles.action"

	var resp Cloud189FilesResp
	_, err := y.get(fullUrl, func(r *resty.Request) {
		r.SetContext(ctx)
		r.SetQueryParams(map[string]string{
			"folderId":   fileId,
			"fileType":   "0",
			"mediaAttr":  "0",
			"iconOption": "5",
			"pageNum":    fmt.Sprint(pageNum),
			"pageSize":   fmt.Sprint(pageSize),
		})
		if isFamily {
			r.SetQueryParams(map[string]string{
				"familyId":   y.FamilyID,
				"orderBy":    toFamilyOrderBy(orderBy),
				"descending": toDesc(orderDirection),
			})
		} else {
			r.SetQueryParams(map[string]string{
				"recursive":  "0",
				"orderBy":    orderBy,
				"descending": toDesc(orderDirection),
			})
		}
	}, &resp, isFamily)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (y *Cloud189PC) findFileByName(ctx context.Context, searchName string, folderId string, isFamily bool) (*Cloud189File, error) {
	for pageNum := 1; ; pageNum++ {
		resp, err := y.getFilesWithPage(ctx, folderId, isFamily, pageNum, 10, "filename", "asc")
		if err != nil {
			return nil, err
		}
		// 鑾峰彇瀹屾瘯璺冲嚭
		if resp.FileListAO.Count == 0 {
			return nil, errs.ObjectNotFound
		}
		for i := 0; i < len(resp.FileListAO.FileList); i++ {
			file := resp.FileListAO.FileList[i]
			if file.Name == searchName {
				return &file, nil
			}
		}
	}
}

func (y *Cloud189PC) login() (err error) {
	// 鍒濆鍖栫櫥闄嗘墍闇€鍙傛暟
	if y.loginParam == nil {
		if err = y.initLoginParam(); err != nil {
			// 楠岃瘉鐮佷篃閫氳繃閿欒杩斿洖
			return err
		}
	}
	defer func() {
		// 閿€姣侀獙璇佺爜
		y.VCode = ""
		// 閿€姣佺櫥闄嗗弬鏁?
		y.loginParam = nil
		// 閬囧埌閿欒锛岄噸鏂板姞杞界櫥闄嗗弬鏁?鍒锋柊楠岃瘉鐮?
		if err != nil && y.NoUseOcr {
			if err1 := y.initLoginParam(); err1 != nil {
				err = fmt.Errorf("err1: %s \nerr2: %s", err, err1)
			}
		}
	}()

	param := y.loginParam
	var loginresp LoginResp
	_, err = y.client.R().
		ForceContentType("application/json;charset=UTF-8").SetResult(&loginresp).
		SetHeaders(map[string]string{
			"REQID": param.ReqId,
			"lt":    param.Lt,
		}).
		SetFormData(map[string]string{
			"appKey":       APP_ID,
			"accountType":  ACCOUNT_TYPE,
			"userName":     param.RsaUsername,
			"password":     param.RsaPassword,
			"validateCode": y.VCode,
			"captchaToken": param.CaptchaToken,
			"returnUrl":    RETURN_URL,
			// "mailSuffix":   "@189.cn",
			"dynamicCheck": "FALSE",
			"clientType":   CLIENT_TYPE,
			"cb_SaveName":  "1",
			"isOauth2":     "false",
			"state":        "",
			"paramId":      param.ParamId,
		}).
		Post(AUTH_URL + "/api/logbox/oauth2/loginSubmit.do")
	if err != nil {
		return err
	}
	if loginresp.ToUrl == "" {
		return fmt.Errorf("login failed,No toUrl obtained, msg: %s", loginresp.Msg)
	}

	// 鑾峰彇Session
	var erron RespErr
	var tokenInfo AppSessionResp
	_, err = y.client.R().
		SetResult(&tokenInfo).SetError(&erron).
		SetQueryParams(clientSuffix()).
		SetQueryParam("redirectURL", loginresp.ToUrl).
		Post(API_URL + "/getSessionForPC.action")
	if err != nil {
		return
	}

	if erron.HasError() {
		return &erron
	}
	if tokenInfo.ResCode != 0 {
		err = fmt.Errorf("%s", tokenInfo.ResMessage)
		return
	}
	y.tokenInfo = &tokenInfo
	y.updateValue(&y.AccessToken, tokenInfo.AccessToken)
	return
}

/* 鍒濆鍖栫櫥闄嗛渶瑕佺殑鍙傛暟
*  濡傛灉閬囧埌楠岃瘉鐮佽繑鍥為敊璇?
 */
func (y *Cloud189PC) initLoginParam() error {
	// 娓呴櫎cookie
	jar, _ := cookiejar.New(nil)
	y.client.SetCookieJar(jar)

	res, err := y.client.R().
		SetQueryParams(map[string]string{
			"appId":      APP_ID,
			"clientType": CLIENT_TYPE,
			"returnURL":  RETURN_URL,
			"timeStamp":  fmt.Sprint(timestamp()),
		}).
		Get(WEB_URL + "/api/portal/unifyLoginForPC.action")
	if err != nil {
		return err
	}

	param := LoginParam{
		CaptchaToken: regexp.MustCompile(`'captchaToken' value='(.+?)'`).FindStringSubmatch(res.String())[1],
		Lt:           regexp.MustCompile(`lt = "(.+?)"`).FindStringSubmatch(res.String())[1],
		ParamId:      regexp.MustCompile(`paramId = "(.+?)"`).FindStringSubmatch(res.String())[1],
		ReqId:        regexp.MustCompile(`reqId = "(.+?)"`).FindStringSubmatch(res.String())[1],
		// jRsaKey:      regexp.MustCompile(`"j_rsaKey" value="(.+?)"`).FindStringSubmatch(res.String())[1],
	}

	// 鑾峰彇rsa鍏挜
	var encryptConf EncryptConfResp
	_, err = y.client.R().
		ForceContentType("application/json;charset=UTF-8").SetResult(&encryptConf).
		SetFormData(map[string]string{"appId": APP_ID}).
		Post(AUTH_URL + "/api/logbox/config/encryptConf.do")
	if err != nil {
		return err
	}

	param.jRsaKey = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", encryptConf.Data.PubKey)
	param.RsaUsername = encryptConf.Data.Pre + RsaEncrypt(param.jRsaKey, y.Username)
	param.RsaPassword = encryptConf.Data.Pre + RsaEncrypt(param.jRsaKey, y.Password)
	y.loginParam = &param

	// 鍒ゆ柇鏄惁闇€瑕侀獙璇佺爜
	resp, err := y.client.R().
		SetHeader("REQID", param.ReqId).
		SetFormData(map[string]string{
			"appKey":      APP_ID,
			"accountType": ACCOUNT_TYPE,
			"userName":    param.RsaUsername,
		}).Post(AUTH_URL + "/api/logbox/oauth2/needcaptcha.do")
	if err != nil {
		return err
	}
	if resp.String() == "0" {
		return nil
	}

	// 鎷夊彇楠岃瘉鐮?
	imgRes, err := y.client.R().
		SetQueryParams(map[string]string{
			"token": param.CaptchaToken,
			"REQID": param.ReqId,
			"rnd":   fmt.Sprint(timestamp()),
		}).
		Get(AUTH_URL + "/api/logbox/oauth2/picCaptcha.do")
	if err != nil {
		return fmt.Errorf("failed to obtain verification code")
	}
	if imgRes.Size() > 20 {
		if setting.GetStr(conf.OcrApi) != "" && !y.NoUseOcr {
			vRes, err := base.RestyClient.R().
				SetMultipartField("image", "validateCode.png", "image/png", bytes.NewReader(imgRes.Body())).
				Post(setting.GetStr(conf.OcrApi))
			if err != nil {
				return err
			}
			if jsoniter.Get(vRes.Body(), "status").ToInt() == 200 {
				y.VCode = jsoniter.Get(vRes.Body(), "result").ToString()
				return nil
			}
		}

		// 杩斿洖楠岃瘉鐮佸浘鐗囩粰鍓嶇
		return fmt.Errorf(`need img validate code: <img src="data:image/png;base64,%s"/>`, base64.StdEncoding.EncodeToString(imgRes.Body()))
	}
	return nil
}

// 鍒锋柊浼氳瘽
func (y *Cloud189PC) refreshSession() (err error) {
	if y.ref != nil {
		return y.ref.refreshSession()
	}
	var erron RespErr
	var userSessionResp UserSessionResp
	_, err = y.client.R().
		SetResult(&userSessionResp).SetError(&erron).
		SetQueryParams(clientSuffix()).
		SetQueryParams(map[string]string{
			"appId":       APP_ID,
			"accessToken": y.tokenInfo.AccessToken,
		}).
		SetHeader("X-Request-ID", uuid.NewString()).
		Get(API_URL + "/getSessionForPC.action")
	if err != nil {
		return err
	}
	// 閿欒褰卞搷姝ｅ父璁块棶锛屼笅绾胯鍌ㄥ瓨
	defer func() {
		if err != nil {
			y.GetStorage().SetStatus(fmt.Sprintf("%+v", err.Error()))
			op.MustSaveDriverStorage(y)
		}
	}()

	if erron.HasError() {
		if y.Username == "" && y.Password == "" {
			return fmt.Errorf("access_token invalid or expired")
		}
		if erron.ResCode == "UserInvalidOpenToken" {
			if err = y.login(); err != nil {
				return err
			}
		}
		return &erron
	}
	y.tokenInfo.UserSessionResp = userSessionResp
	return
}

func (y *Cloud189PC) updateValue(str *string, str2 string) {
	*str = str2
}

func (y *Cloud189PC) useAccessTokenAndInit(accessToken string) error {
	y.tokenInfo = &AppSessionResp{}
	y.tokenInfo.AccessToken = accessToken
	// 閿欒褰卞搷姝ｅ父璁块棶锛屼笅绾胯鍌ㄥ瓨
	var err error
	defer func() {
		if err != nil {
			y.GetStorage().SetStatus(fmt.Sprintf("%+v", err.Error()))
			op.MustSaveDriverStorage(y)
		}
	}()

	err = y.refreshSession()
	return err
}

// 蹇紶
type UploadHashInfo struct {
	Name          string
	Size          int64
	SliceSize     int64
	Count         int
	LastSliceSize int64
	FileMD5       string
	SliceMD5      string
	PartInfos     []string
	Cache         io.ReaderAt
	Cleanup       func()
}

func (y *Cloud189PC) FastUpload(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress, isFamily bool, overwrite bool) (model.Obj, error) {
	obj, _, err := y.FastUploadWithInfo(ctx, dstDir, file, up, isFamily, overwrite)
	return obj, err
}

func (y *Cloud189PC) FastUploadWithInfo(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress, isFamily bool, overwrite bool) (model.Obj, *UploadHashInfo, error) {
	var (
		cache = file.GetFile()
		tmpF  *os.File
		err   error
	)
	size := file.GetSize()
	if _, ok := cache.(io.ReaderAt); !ok && size > 0 {
		tmpF, err = os.CreateTemp(conf.Conf.TempDir, "file-*")
		if err != nil {
			return nil, nil, err
		}
		defer func() {
			_ = tmpF.Close()
			_ = os.Remove(tmpF.Name())
		}()
		cache = tmpF
	}
	sliceSize := partSize(size)
	count := int(size / sliceSize)
	lastSliceSize := size % sliceSize
	if lastSliceSize > 0 {
		count++
	} else {
		lastSliceSize = sliceSize
	}
	//step.1 浼樺厛璁＄畻鎵€闇€淇℃伅
	byteSize := sliceSize
	fileMd5 := utils.MD5.NewFunc()
	sliceMd5 := utils.MD5.NewFunc()
	sliceMd5Hexs := make([]string, 0, count)
	partInfos := make([]string, 0, count)
	writers := []io.Writer{fileMd5, sliceMd5}
	if tmpF != nil {
		writers = append(writers, tmpF)
	}
	written := int64(0)
	for i := 1; i <= count; i++ {
		if utils.IsCanceled(ctx) {
			return nil, nil, ctx.Err()
		}

		if i == count {
			byteSize = lastSliceSize
		}

		n, err := utils.CopyWithBufferN(io.MultiWriter(writers...), file, byteSize)
		written += n
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		md5Byte := sliceMd5.Sum(nil)
		sliceMd5Hexs = append(sliceMd5Hexs, strings.ToUpper(hex.EncodeToString(md5Byte)))
		partInfos = append(partInfos, fmt.Sprint(i, "-", base64.StdEncoding.EncodeToString(md5Byte)))
		sliceMd5.Reset()
	}

	if tmpF != nil {
		if size > 0 && written != size {
			return nil, nil, errs.NewErr(err, "CreateTempFile failed, incoming stream actual size= %d, expect = %d ", written, size)
		}
		_, err = tmpF.Seek(0, io.SeekStart)
		if err != nil {
			return nil, nil, errs.NewErr(err, "CreateTempFile failed, can't seek to 0 ")
		}
	}

	fileMd5Hex := strings.ToUpper(hex.EncodeToString(fileMd5.Sum(nil)))
	sliceMd5Hex := fileMd5Hex
	if size > sliceSize {
		sliceMd5Hex = strings.ToUpper(utils.GetMD5EncodeStr(strings.Join(sliceMd5Hexs, "\n")))
	}
	fullUrl := UPLOAD_URL
	if isFamily {
		fullUrl += "/family"
	} else {
		//params.Set("extend", `{"opScene":"1","relativepath":"","rootfolderid":""}`)
		fullUrl += "/person"
	}
	// 灏濊瘯鎭㈠杩涘害
	uploadProgress, ok := base.GetUploadProgress[*UploadProgress](y, y.getTokenInfo().SessionKey, fileMd5Hex)
	if !ok {
		//step.2 棰勪笂浼?
		params := Params{
			"parentFolderId": dstDir.GetID(),
			"fileName":       url.QueryEscape(file.GetName()),
			"fileSize":       fmt.Sprint(file.GetSize()),
			"fileMd5":        fileMd5Hex,
			"sliceSize":      fmt.Sprint(sliceSize),
			"sliceMd5":       sliceMd5Hex,
		}
		if isFamily {
			params.Set("familyId", y.FamilyID)
		}
		var uploadInfo InitMultiUploadResp
		_, err = y.request(fullUrl+"/initMultiUpload", http.MethodGet, func(req *resty.Request) {
			req.SetContext(ctx)
		}, params, &uploadInfo, isFamily)
		if err != nil {
			return nil, nil, err
		}
		uploadProgress = &UploadProgress{
			UploadInfo:  uploadInfo,
			UploadParts: partInfos,
		}
	}

	uploadInfo := uploadProgress.UploadInfo.Data
	// 缃戠洏涓笉瀛樺湪璇ユ枃浠讹紝寮€濮嬩笂浼?
	if uploadInfo.FileDataExists != 1 {
		threadG, upCtx := errgroup.NewGroupWithContext(ctx, y.uploadThread,
			retry.Attempts(3),
			retry.Delay(time.Second),
			retry.DelayType(retry.BackOffDelay))
		for i, uploadPart := range uploadProgress.UploadParts {
			if utils.IsCanceled(upCtx) {
				break
			}

			i, uploadPart := i, uploadPart
			threadG.Go(func(ctx context.Context) error {
				// step.3 鑾峰彇涓婁紶閾炬帴
				uploadUrls, err := y.GetMultiUploadUrls(ctx, isFamily, uploadInfo.UploadFileID, uploadPart)
				if err != nil {
					return err
				}
				uploadUrl := uploadUrls[0]

				byteSize, offset := sliceSize, int64(uploadUrl.PartNumber-1)*sliceSize
				if uploadUrl.PartNumber == count {
					byteSize = lastSliceSize
				}

				// step.4 涓婁紶鍒囩墖
				_, err = y.put(ctx, uploadUrl.RequestURL, uploadUrl.Headers, false, io.NewSectionReader(cache, offset, byteSize), isFamily)
				if err != nil {
					return err
				}

				up(float64(threadG.Success()) * 100 / float64(len(uploadUrls)))
				uploadProgress.UploadParts[i] = ""
				return nil
			})
		}
		if err = threadG.Wait(); err != nil {
			if errors.Is(err, context.Canceled) {
				uploadProgress.UploadParts = utils.SliceFilter(uploadProgress.UploadParts, func(s string) bool { return s != "" })
				base.SaveUploadProgress(y, uploadProgress, y.getTokenInfo().SessionKey, fileMd5Hex)
			}
			return nil, nil, err
		}
	}

	// step.5 鎻愪氦
	var resp CommitMultiUploadFileResp
	_, err = y.request(fullUrl+"/commitMultiUploadFile", http.MethodGet,
		func(req *resty.Request) {
			req.SetContext(ctx)
		}, Params{
			"uploadFileId": uploadInfo.UploadFileID,
			"isLog":        "0",
			"opertype":     IF(overwrite, "3", "1"),
		}, &resp, isFamily)
	if err != nil {
		return nil, nil, err
	}
	return resp.toFile(), &UploadHashInfo{
		Name:          file.GetName(),
		Size:          size,
		SliceSize:     sliceSize,
		Count:         count,
		LastSliceSize: lastSliceSize,
		FileMD5:       fileMd5Hex,
		SliceMD5:      sliceMd5Hex,
		PartInfos:     partInfos,
		Cache:         cache.(io.ReaderAt),
	}, nil
}

// 鑾峰彇涓婁紶鍒囩墖淇℃伅
// 瀵筯ttp body鏈夊ぇ灏忛檺鍒讹紝鍒嗙墖淇℃伅澶浼氬嚭閿?
func (y *Cloud189PC) GetMultiUploadUrls(ctx context.Context, isFamily bool, uploadFileId string, partInfo ...string) ([]UploadUrlInfo, error) {
	fullUrl := UPLOAD_URL
	if isFamily {
		fullUrl += "/family"
	} else {
		fullUrl += "/person"
	}

	var uploadUrlsResp UploadUrlsResp
	_, err := y.request(fullUrl+"/getMultiUploadUrls", http.MethodGet,
		func(req *resty.Request) {
			req.SetContext(ctx)
		}, Params{
			"uploadFileId": uploadFileId,
			"partInfo":     strings.Join(partInfo, ","),
		}, &uploadUrlsResp, isFamily)
	if err != nil {
		return nil, err
	}
	uploadUrls := uploadUrlsResp.Data

	if len(uploadUrls) != len(partInfo) {
		return nil, fmt.Errorf("uploadUrls get error, due to get length %d, real length %d", len(partInfo), len(uploadUrls))
	}

	uploadUrlInfos := make([]UploadUrlInfo, 0, len(uploadUrls))
	for k, uploadUrl := range uploadUrls {
		partNumber, err := strconv.Atoi(strings.TrimPrefix(k, "partNumber_"))
		if err != nil {
			return nil, err
		}
		uploadUrlInfos = append(uploadUrlInfos, UploadUrlInfo{
			PartNumber:     partNumber,
			Headers:        ParseHttpHeader(uploadUrl.RequestHeader),
			UploadUrlsData: uploadUrl,
		})
	}
	sort.Slice(uploadUrlInfos, func(i, j int) bool {
		return uploadUrlInfos[i].PartNumber < uploadUrlInfos[j].PartNumber
	})
	return uploadUrlInfos, nil
}

func (y *Cloud189PC) isFamily() bool {
	return y.Type == "family"
}

func (y *Cloud189PC) isLogin() bool {
	if y.tokenInfo == nil {
		return false
	}
	_, err := y.get(API_URL+"/getUserInfo.action", nil, nil)
	return err == nil
}

// 鍒涘缓瀹跺涵浜戜腑杞枃浠跺す
func (y *Cloud189PC) createFamilyTransferFolder() error {
	var rootFolder Cloud189Folder
	_, err := y.post(API_URL+"/family/file/createFolder.action", func(req *resty.Request) {
		req.SetQueryParams(map[string]string{
			"folderName": "FamilyTransferFolder",
			"familyId":   y.FamilyID,
		})
	}, &rootFolder, true)
	if err != nil {
		return err
	}
	y.familyTransferFolder = &rootFolder
	return nil
}

// 娓呯悊涓浆鏂囦欢澶?
func (y *Cloud189PC) cleanFamilyTransfer(ctx context.Context) error {
	transferFolderId := y.familyTransferFolder.GetID()
	for pageNum := 1; ; pageNum++ {
		resp, err := y.getFilesWithPage(ctx, transferFolderId, true, pageNum, 100, "lastOpTime", "asc")
		if err != nil {
			return err
		}
		// 鑾峰彇瀹屾瘯璺冲嚭
		if resp.FileListAO.Count == 0 {
			break
		}

		var tasks []BatchTaskInfo
		for i := 0; i < len(resp.FileListAO.FolderList); i++ {
			folder := resp.FileListAO.FolderList[i]
			tasks = append(tasks, BatchTaskInfo{
				FileId:   folder.GetID(),
				FileName: folder.GetName(),
				IsFolder: BoolToNumber(folder.IsDir()),
			})
		}
		for i := 0; i < len(resp.FileListAO.FileList); i++ {
			file := resp.FileListAO.FileList[i]
			tasks = append(tasks, BatchTaskInfo{
				FileId:   file.GetID(),
				FileName: file.GetName(),
				IsFolder: BoolToNumber(file.IsDir()),
			})
		}

		if len(tasks) > 0 {
			// 鍒犻櫎
			resp, err := y.CreateBatchTask("DELETE", y.FamilyID, "", nil, tasks...)
			if err != nil {
				return err
			}
			err = y.WaitBatchTask("DELETE", resp.TaskID, time.Second)
			if err != nil {
				return err
			}
			// 姘镐箙鍒犻櫎
			resp, err = y.CreateBatchTask("CLEAR_RECYCLE", y.FamilyID, "", nil, tasks...)
			if err != nil {
				return err
			}
			err = y.WaitBatchTask("CLEAR_RECYCLE", resp.TaskID, time.Second)
			return err
		}
	}
	return nil
}

// 鑾峰彇瀹跺涵浜戞墍鏈夌敤鎴蜂俊鎭?
func (y *Cloud189PC) getFamilyInfoList() ([]FamilyInfoResp, error) {
	var resp FamilyInfoListResp
	_, err := y.get(API_URL+"/family/manage/getFamilyList.action", nil, &resp, true)
	if err != nil {
		return nil, err
	}
	return resp.FamilyInfoResp, nil
}

// 鎶藉彇瀹跺涵浜慖D
func (y *Cloud189PC) getFamilyID() (string, error) {
	infos, err := y.getFamilyInfoList()
	if err != nil {
		return "", err
	}
	if len(infos) == 0 {
		return "", fmt.Errorf("cannot get automatically,please input family_id")
	}
	for _, info := range infos {
		if strings.Contains(y.getTokenInfo().LoginName, info.RemarkName) {
			return fmt.Sprint(info.FamilyID), nil
		}
	}
	return fmt.Sprint(infos[0].FamilyID), nil
}

// 淇濆瓨瀹跺涵浜戜腑鐨勬枃浠跺埌涓汉浜?
func (y *Cloud189PC) SaveFamilyFileToPersonCloud(ctx context.Context, familyId string, srcObj, dstDir model.Obj, overwrite bool) error {

	task := BatchTaskInfo{
		FileId:   srcObj.GetID(),
		FileName: srcObj.GetName(),
		IsFolder: BoolToNumber(srcObj.IsDir()),
	}
	resp, err := y.CreateBatchTask("COPY", familyId, dstDir.GetID(), map[string]string{
		"groupId":  "null",
		"copyType": "2",
		"shareId":  "null",
	}, task)
	if err != nil {
		return err
	}

	for {
		state, err := y.CheckBatchTask("COPY", resp.TaskID)
		if err != nil {
			return err
		}
		switch state.TaskStatus {
		case 2:
			task.DealWay = IF(overwrite, 3, 2)
			// 鍐茬獊鏃惰鐩栨枃浠?
			if err := y.ManageBatchTask("COPY", resp.TaskID, dstDir.GetID(), task); err != nil {
				return err
			}
		case 4:
			return nil
		}
		time.Sleep(time.Millisecond * 400)
	}
}

// 姘镐箙鍒犻櫎鏂囦欢
func (y *Cloud189PC) Delete(ctx context.Context, familyId string, srcObj model.Obj) error {
	task := BatchTaskInfo{
		FileId:   srcObj.GetID(),
		FileName: srcObj.GetName(),
		IsFolder: BoolToNumber(srcObj.IsDir()),
	}
	// 鍒犻櫎婧愭枃浠?
	resp, err := y.CreateBatchTask("DELETE", familyId, "", nil, task)
	if err != nil {
		return err
	}
	err = y.WaitBatchTask("DELETE", resp.TaskID, time.Second)
	if err != nil {
		return err
	}
	// 娓呴櫎鍥炴敹绔?
	resp, err = y.CreateBatchTask("CLEAR_RECYCLE", familyId, "", nil, task)
	if err != nil {
		return err
	}
	err = y.WaitBatchTask("CLEAR_RECYCLE", resp.TaskID, time.Second)
	if err != nil {
		return err
	}
	return nil
}

func (y *Cloud189PC) CreateBatchTask(aType string, familyID string, targetFolderId string, other map[string]string, taskInfos ...BatchTaskInfo) (*CreateBatchTaskResp, error) {
	var resp CreateBatchTaskResp
	_, err := y.post(API_URL+"/batch/createBatchTask.action", func(req *resty.Request) {
		req.SetFormData(map[string]string{
			"type":      aType,
			"taskInfos": MustString(utils.Json.MarshalToString(taskInfos)),
		})
		if targetFolderId != "" {
			req.SetFormData(map[string]string{"targetFolderId": targetFolderId})
		}
		if familyID != "" {
			req.SetFormData(map[string]string{"familyId": familyID})
		}
		req.SetFormData(other)
	}, &resp, familyID != "")
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// 妫€娴嬩换鍔＄姸鎬?
func (y *Cloud189PC) CheckBatchTask(aType string, taskID string) (*BatchTaskStateResp, error) {
	var resp BatchTaskStateResp
	_, err := y.post(API_URL+"/batch/checkBatchTask.action", func(req *resty.Request) {
		req.SetFormData(map[string]string{
			"type":   aType,
			"taskId": taskID,
		})
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// 鑾峰彇鍐茬獊鐨勪换鍔′俊鎭?
func (y *Cloud189PC) GetConflictTaskInfo(aType string, taskID string) (*BatchTaskConflictTaskInfoResp, error) {
	var resp BatchTaskConflictTaskInfoResp
	_, err := y.post(API_URL+"/batch/getConflictTaskInfo.action", func(req *resty.Request) {
		req.SetFormData(map[string]string{
			"type":   aType,
			"taskId": taskID,
		})
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// 澶勭悊鍐茬獊
func (y *Cloud189PC) ManageBatchTask(aType string, taskID string, targetFolderId string, taskInfos ...BatchTaskInfo) error {
	_, err := y.post(API_URL+"/batch/manageBatchTask.action", func(req *resty.Request) {
		req.SetFormData(map[string]string{
			"targetFolderId": targetFolderId,
			"type":           aType,
			"taskId":         taskID,
			"taskInfos":      MustString(utils.Json.MarshalToString(taskInfos)),
		})
	}, nil)
	return err
}

var ErrIsConflict = errors.New("there is a conflict with the target object")

// 绛夊緟浠诲姟瀹屾垚
func (y *Cloud189PC) WaitBatchTask(aType string, taskID string, t time.Duration) error {
	for {
		state, err := y.CheckBatchTask(aType, taskID)
		if err != nil {
			return err
		}
		switch state.TaskStatus {
		case 2:
			return ErrIsConflict
		case 4:
			return nil
		}
		time.Sleep(t)
	}
}

func (y *Cloud189PC) getTokenInfo() *AppSessionResp {
	if y.ref != nil {
		return y.ref.getTokenInfo()
	}
	return y.tokenInfo
}

func (y *Cloud189PC) getClient() *resty.Client {
	if y.ref != nil {
		return y.ref.getClient()
	}
	return y.client
}

func (y *Cloud189PC) getCapacityInfo(ctx context.Context) (*CapacityResp, error) {
	fullUrl := API_URL + "/portal/getUserSizeInfo.action"
	var resp CapacityResp
	_, err := y.get(fullUrl, func(req *resty.Request) {
		req.SetContext(ctx)
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
