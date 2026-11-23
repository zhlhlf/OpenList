package _189pc

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"

	"github.com/go-resty/resty/v2"
	jsoniter "github.com/json-iterator/go"
)

const (
	// 189 DCI 上传接口单次请求最多稳定落盘 6MiB（返回 InputStreamReadError
	// 属于正常现象，随后用 getUploadFileStatus 查询实际已上传大小）。
	resumeChunkSize = 6 * 1024 * 1024
	// 断点状态只放内存，3 天过期；进程重启会丢。
	resumeStateTTL = 72 * time.Hour
)

// LegacyUploadFileStatus 对应官方 createUploadFile.action /
// getUploadFileStatus.action 的 XML 返回。
type LegacyUploadFileStatus struct {
	XMLName        xml.Name `xml:"uploadFile"`
	UploadFileID   int64    `xml:"uploadFileId"`
	Size           int64    `xml:"size"`
	FileUploadURL  string   `xml:"fileUploadUrl"`
	FileCommitURL  string   `xml:"fileCommitUrl"`
	FileDataExists int      `xml:"fileDataExists"`
}

type uploadResumeState struct {
	Account       string `json:"account"`
	DstDirID      string `json:"dstDirId"`
	FileMD5       string `json:"fileMd5"`
	FileName      string `json:"fileName"`
	FileSize      int64  `json:"fileSize"`
	UploadFileID  int64  `json:"uploadFileId"`
	FileUploadURL string `json:"fileUploadUrl"`
	FileCommitURL string `json:"fileCommitUrl"`
	UploadedSize  int64  `json:"uploadedSize"`
	UpdatedAt     int64  `json:"updatedAt"`
}

var resumeStoreMu sync.Mutex

type resumeMemEntry struct {
	legacy    *uploadResumeState
	v2        *v2UploadState
	updatedAt time.Time
}

var resumeMem = make(map[string]*resumeMemEntry)

func sweepResumeMemLocked(now time.Time) {
	for key, entry := range resumeMem {
		if now.Sub(entry.updatedAt) > resumeStateTTL {
			delete(resumeMem, key)
		}
	}
}

func (y *Cloud189PC) sweepResumeMem() {
	resumeStoreMu.Lock()
	defer resumeStoreMu.Unlock()
	sweepResumeMemLocked(time.Now())
}

func resumeStateKey(dstDirID, fileMD5, fileName string, fileSize int64) string {
	return fmt.Sprintf("%s--%d--%s--%s", strings.ToUpper(fileMD5), fileSize, dstDirID, fileName)
}

func (y *Cloud189PC) resumeAccount() string {
	if y.Username != "" {
		return y.Username
	}
	return y.identity
}

func (y *Cloud189PC) loadResumeState(dstDirID, fileMD5, fileName string, fileSize int64) *uploadResumeState {
	resumeStoreMu.Lock()
	defer resumeStoreMu.Unlock()
	sweepResumeMemLocked(time.Now())

	entry, ok := resumeMem[resumeStateKey(dstDirID, fileMD5, fileName, fileSize)]
	if !ok || entry.legacy == nil {
		return nil
	}
	st := entry.legacy
	if st.UploadFileID == 0 || st.FileSize != fileSize || !strings.EqualFold(st.FileMD5, fileMD5) ||
		st.FileName != fileName || st.DstDirID != dstDirID {
		return nil
	}
	return st
}

func (y *Cloud189PC) saveResumeState(st *uploadResumeState) error {
	resumeStoreMu.Lock()
	defer resumeStoreMu.Unlock()
	sweepResumeMemLocked(time.Now())

	st.UpdatedAt = time.Now().Unix()
	cp := *st
	key := resumeStateKey(st.DstDirID, st.FileMD5, st.FileName, st.FileSize)
	entry := resumeMem[key]
	if entry == nil {
		entry = &resumeMemEntry{}
		resumeMem[key] = entry
	}
	entry.legacy = &cp
	entry.updatedAt = time.Now()
	return nil
}

func (y *Cloud189PC) deleteResumeState(dstDirID, fileMD5, fileName string, fileSize int64) {
	resumeStoreMu.Lock()
	defer resumeStoreMu.Unlock()
	key := resumeStateKey(dstDirID, fileMD5, fileName, fileSize)
	if entry := resumeMem[key]; entry != nil {
		entry.legacy = nil
		if entry.v2 == nil {
			delete(resumeMem, key)
		}
	}
}

// GetUploadFileStatus 查询官方断点续传进度：
// GET https://api.cloud.189.cn/getUploadFileStatus.action?uploadFileId=...&resumePolicy=1
// 返回的 size 是云端已经确认落盘的字节数。
func (y *Cloud189PC) GetUploadFileStatus(ctx context.Context, uploadFileID int64, isFamily bool) (*LegacyUploadFileStatus, error) {
	fullURL := API_URL + "/getUploadFileStatus.action"
	if isFamily {
		fullURL = API_URL + "/family/file/getFamilyFileStatus.action"
	}
	var resp LegacyUploadFileStatus
	_, err := y.get(fullURL, func(req *resty.Request) {
		req.SetContext(ctx).SetQueryParams(map[string]string{
			"uploadFileId": fmt.Sprint(uploadFileID),
			"resumePolicy": "1",
		})
		if isFamily {
			req.SetQueryParam("familyId", y.FamilyID)
		}
	}, &resp, isFamily)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (y *Cloud189PC) legacyCreateUploadFile(ctx context.Context, parentFolderID, fileName, fileMD5 string, fileSize int64, overwrite bool) (*LegacyUploadFileStatus, error) {
	var resp LegacyUploadFileStatus
	_, err := y.post(API_URL+"/createUploadFile.action", func(req *resty.Request) {
		req.SetContext(ctx).SetFormData(map[string]string{
			"parentFolderId": parentFolderID,
			"fileName":       fileName,
			"size":           fmt.Sprint(fileSize),
			"md5":            fileMD5,
			"opertype":       IF(overwrite, "3", "1"),
			"flag":           "1",
			"resumePolicy":   "1",
			"isLog":          "0",
		})
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.UploadFileID == 0 {
		return nil, fmt.Errorf("createUploadFile returned empty uploadFileId")
	}
	return &resp, nil
}

func (y *Cloud189PC) legacyCommitUploadFile(ctx context.Context, fileCommitURL string, uploadFileID int64, overwrite bool) (model.Obj, error) {
	var resp OldCommitUploadFileResp
	_, err := y.post(fileCommitURL, func(req *resty.Request) {
		req.SetContext(ctx).SetFormData(map[string]string{
			"opertype":     IF(overwrite, "3", "1"),
			"resumePolicy": "1",
			"uploadFileId": fmt.Sprint(uploadFileID),
			"isLog":        "0",
		})
	}, &resp)
	if err != nil {
		return nil, err
	}
	return resp.toFile(), nil
}

// putResumeChunk 上传一个带 Content-Range 的分片。
// 服务端在达到内部落盘边界时会返回 600 InputStreamReadError，
// 这不代表失败；调用方随后用 GetUploadFileStatus 获取真实进度即可。
func (y *Cloud189PC) putResumeChunk(ctx context.Context, url string, header map[string]string, body io.Reader, contentLength int64, isFamily bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, body)
	if err != nil {
		return err
	}
	req.ContentLength = contentLength

	query := req.URL.Query()
	for key, value := range clientSuffix() {
		query.Add(key, value)
	}
	req.URL.RawQuery = query.Encode()

	for key, value := range header {
		req.Header.Add(key, value)
	}
	for key, value := range y.SignatureHeader(url, http.MethodPut, "", isFamily) {
		req.Header.Add(key, value)
	}

	resp, err := base.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var erron RespErr
	_ = jsoniter.Unmarshal(bs, &erron)
	_ = xml.Unmarshal(bs, &erron)
	if erron.HasError() {
		// 服务端按自己的 6MiB 边界截断请求体时返回该错误，进度以 status 为准。
		if erron.Code == "InputStreamReadError" {
			return nil
		}
		return &erron
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		if strings.Contains(string(bs), "InputStreamReadError") {
			return nil
		}
		return fmt.Errorf("189 resume chunk upload failed: http %d, body=%s", resp.StatusCode, string(bs))
	}
	return nil
}

// ResumeUpload 使用官方 createUploadFile/getUploadFileStatus/commitUploadFile
// 流程上传，并把 uploadFileId 落盘，进程重启后可以继续。
func (y *Cloud189PC) ResumeUpload(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress, overwrite bool) (model.Obj, error) {
	if y.isFamily() {
		return nil, errs.NotSupport
	}
	size := file.GetSize()
	if size <= 0 {
		return nil, fmt.Errorf("189 resume upload: invalid file size %d", size)
	}

	// 官方接口要求完整文件 MD5；CacheFullAndHash 会同时把文件缓存到临时文件，
	// 后续分片用 ReaderAt 读取，不会重复下载/读取网络流。
	tempFile, fileMD5, err := stream.CacheFullAndHash(file, &up, utils.MD5)
	if err != nil {
		return nil, err
	}
	fileMD5 = strings.ToUpper(fileMD5)
	fileName := file.GetName()

	state := y.loadResumeState(dstDir.GetID(), fileMD5, fileName, size)
	if state == nil {
		info, err := y.legacyCreateUploadFile(ctx, dstDir.GetID(), fileName, fileMD5, size, overwrite)
		if err != nil {
			return nil, fmt.Errorf("189 resume upload: create session failed: %w", err)
		}
		state = &uploadResumeState{
			Account:       y.resumeAccount(),
			DstDirID:      dstDir.GetID(),
			FileMD5:       fileMD5,
			FileName:      fileName,
			FileSize:      size,
			UploadFileID:  info.UploadFileID,
			FileUploadURL: info.FileUploadURL,
			FileCommitURL: info.FileCommitURL,
		}
		if err = y.saveResumeState(state); err != nil {
			return nil, fmt.Errorf("189 resume upload: save state failed: %w", err)
		}
	}

	lastUploaded := int64(-1)
	stuck := 0
	for attempt := 0; attempt < 4096; attempt++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		status, err := y.GetUploadFileStatus(ctx, state.UploadFileID, false)
		if err != nil {
			return nil, fmt.Errorf("189 resume upload: query status failed (uploadFileId=%d): %w", state.UploadFileID, err)
		}
		if status.FileUploadURL != "" {
			state.FileUploadURL = status.FileUploadURL
		}
		if status.FileCommitURL != "" {
			state.FileCommitURL = status.FileCommitURL
		}
		if status.FileDataExists == 1 || status.Size >= size {
			break
		}
		uploaded := status.Size
		if uploaded == lastUploaded {
			stuck++
			if stuck >= 3 {
				return nil, fmt.Errorf("189 resume upload: no progress after 3 attempts, uploaded=%d/%d", uploaded, size)
			}
		} else {
			stuck = 0
			lastUploaded = uploaded
		}

		end := uploaded + resumeChunkSize
		if end > size {
			end = size
		}
		header := map[string]string{
			"Edrive-UploadFileId": fmt.Sprint(state.UploadFileID),
			"ResumePolicy":        "1",
			"Content-Type":        "application/octet-stream",
			"Content-Range":       fmt.Sprintf("bytes %d-%d/%d", uploaded, end-1, size),
			"Expect":              "100-continue",
		}
		section := io.NewSectionReader(tempFile, uploaded, end-uploaded)
		if err = y.putResumeChunk(ctx, state.FileUploadURL, header, driver.NewLimitedUploadStream(ctx, section), end-uploaded, false); err != nil {
			state.UploadedSize = uploaded
			_ = y.saveResumeState(state)
			return nil, fmt.Errorf("189 resume upload: chunk %d-%d failed: %w", uploaded, end-1, err)
		}
		state.UploadedSize = end
		if err = y.saveResumeState(state); err != nil {
			return nil, fmt.Errorf("189 resume upload: save state failed: %w", err)
		}
		up(float64(end) * 100 / float64(size))
	}

	obj, err := y.legacyCommitUploadFile(ctx, state.FileCommitURL, state.UploadFileID, overwrite)
	if err != nil {
		return nil, fmt.Errorf("189 resume upload: commit failed: %w", err)
	}
	y.deleteResumeState(dstDir.GetID(), fileMD5, fileName, size)
	up(100)
	return obj, nil
}

// UploadedPartsInfoResp 是 v2 分片上传的“已上传分片”查询返回。
// GET /person/getUploadedPartsInfo 或 /family/getUploadedPartsInfo
type UploadedPartsInfoResp struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		UploadFileID     string `json:"uploadFileId"`
		UploadedPartList string `json:"uploadedPartList"`
	} `json:"data"`
}

// GetUploadedPartsInfo 查询 v2 分片上传中服务端已经确认落盘的分片号。
// 官方 App 使用 params 加密传 uploadFileId，返回形如 "1,2"。
func (y *Cloud189PC) GetUploadedPartsInfo(ctx context.Context, uploadFileID string, isFamily bool) (map[int]bool, error) {
	// 每次调用都顺手清掉 3 天前的内存状态。
	y.sweepResumeMem()

	fullURL := UPLOAD_URL
	if isFamily {
		fullURL += "/family"
	} else {
		fullURL += "/person"
	}
	fullURL += "/getUploadedPartsInfo"

	var resp UploadedPartsInfoResp
	_, err := y.request(fullURL, http.MethodGet, func(req *resty.Request) {
		req.SetContext(ctx)
	}, Params{"uploadFileId": uploadFileID}, &resp, isFamily)
	if err != nil {
		return nil, err
	}
	if resp.Code != "" && resp.Code != "SUCCESS" {
		return nil, fmt.Errorf("getUploadedPartsInfo: %s %s", resp.Code, resp.Msg)
	}
	uploaded := make(map[int]bool)
	for _, item := range strings.Split(resp.Data.UploadedPartList, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		n, err := strconv.Atoi(item)
		if err == nil {
			uploaded[n] = true
		}
	}
	return uploaded, nil
}

type v2UploadState struct {
	Account     string              `json:"account"`
	DstDirID    string              `json:"dstDirId"`
	FileMD5     string              `json:"fileMd5"`
	FileName    string              `json:"fileName"`
	FileSize    int64               `json:"fileSize"`
	UploadInfo  InitMultiUploadResp `json:"uploadInfo"`
	UploadParts []string            `json:"uploadParts"`
	UpdatedAt   int64               `json:"updatedAt"`
}

func (y *Cloud189PC) loadV2UploadProgress(dstDirID, fileMD5, fileName string, fileSize int64) *UploadProgress {
	resumeStoreMu.Lock()
	defer resumeStoreMu.Unlock()
	sweepResumeMemLocked(time.Now())

	entry, ok := resumeMem[resumeStateKey(dstDirID, fileMD5, fileName, fileSize)]
	if !ok || entry.v2 == nil {
		return nil
	}
	st := entry.v2
	if st.UploadInfo.Data.UploadFileID == "" || st.FileSize != fileSize ||
		!strings.EqualFold(st.FileMD5, fileMD5) || st.FileName != fileName || st.DstDirID != dstDirID {
		return nil
	}
	return &UploadProgress{
		UploadInfo:  st.UploadInfo,
		UploadParts: append([]string(nil), st.UploadParts...),
	}
}

func (y *Cloud189PC) saveV2UploadProgress(dstDirID, fileMD5, fileName string, fileSize int64, progress *UploadProgress) error {
	resumeStoreMu.Lock()
	defer resumeStoreMu.Unlock()
	sweepResumeMemLocked(time.Now())

	st := &v2UploadState{
		Account:     y.resumeAccount(),
		DstDirID:    dstDirID,
		FileMD5:     fileMD5,
		FileName:    fileName,
		FileSize:    fileSize,
		UploadInfo:  progress.UploadInfo,
		UploadParts: append([]string(nil), progress.UploadParts...),
		UpdatedAt:   time.Now().Unix(),
	}
	key := resumeStateKey(dstDirID, fileMD5, fileName, fileSize)
	entry := resumeMem[key]
	if entry == nil {
		entry = &resumeMemEntry{}
		resumeMem[key] = entry
	}
	entry.v2 = st
	entry.updatedAt = time.Now()
	return nil
}

func (y *Cloud189PC) deleteV2UploadProgress(dstDirID, fileMD5, fileName string, fileSize int64) {
	resumeStoreMu.Lock()
	defer resumeStoreMu.Unlock()
	key := resumeStateKey(dstDirID, fileMD5, fileName, fileSize)
	if entry := resumeMem[key]; entry != nil {
		entry.v2 = nil
		if entry.legacy == nil {
			delete(resumeMem, key)
		}
	}
}

func uploadPartNumber(partInfo string) int {
	if idx := strings.IndexByte(partInfo, '-'); idx > 0 {
		n, _ := strconv.Atoi(partInfo[:idx])
		return n
	}
	return 0
}
