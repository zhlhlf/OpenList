//go:build live189

package _189pc

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
)

// 实网测试：需要 S189_AT=<天翼云盘 accessToken>。
// 第一次故意超时中断，第二次从落盘的 uploadFileId + getUploadFileStatus 续传。
func TestLiveResume(t *testing.T) {
	token := os.Getenv("S189_AT")
	if token == "" {
		t.Skip("S189_AT not set")
	}
	conf.Conf = &conf.Config{TempDir: t.TempDir()}
	base.InitClient()

	y := &Cloud189PC{}
	y.Addition.AccessToken = token
	y.Addition.UploadMethod = "resumable"
	if err := y.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	const size = 30 * 1024 * 1024
	r := rand.New(rand.NewSource(20261123))
	data := make([]byte, size)
	_, _ = r.Read(data)
	name := fmt.Sprintf("go-resume-%d.bin", time.Now().Unix())
	dst := &model.Object{ID: "-11"}
	mkStream := func() model.FileStreamer {
		return &stream.FileStream{
			Ctx:      context.Background(),
			Obj:      &model.Object{Name: name, Size: size},
			Reader:   bytes.NewReader(data),
			Mimetype: "application/octet-stream",
		}
	}

	sum := md5.Sum(data)
	md5Hex := fmt.Sprintf("%X", sum[:])

	// 第一次：落盘第一个分片后立刻取消，模拟上传中断/进程退出。
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			st := y.loadResumeState("-11", md5Hex, name, size)
			if st != nil && st.UploadedSize >= resumeChunkSize {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	_, err := y.ResumeUpload(ctx, dst, mkStream(), func(p float64) { t.Logf("first progress %.1f%%", p) }, true)
	t.Logf("first attempt ended with: %v", err)
	if err == nil {
		t.Fatalf("first attempt unexpectedly completed; cannot test resume")
	}

	// 直接查一次云端进度，证明 status 接口能拿到已上传大小。
	state := y.loadResumeState("-11", md5Hex, name, size)
	if state != nil {
		st, serr := y.GetUploadFileStatus(context.Background(), state.UploadFileID, false)
		if serr != nil {
			t.Fatalf("status: %v", serr)
		}
		t.Logf("cloud status: uploadFileId=%d size=%d/%d", st.UploadFileID, st.Size, size)
	} else {
		t.Logf("no resume state found (first attempt may have failed before create)")
	}

	// 第二次：新进程/新 context，从状态续传并提交。
	obj, err := y.ResumeUpload(context.Background(), dst, mkStream(), func(p float64) { t.Logf("resume progress %.1f%%", p) }, true)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Logf("uploaded: name=%s id=%s", obj.GetName(), obj.GetID())
	if err := y.Delete(context.Background(), "", obj); err != nil {
		t.Logf("cleanup delete failed: %v", err)
	}
}

// 实网测试 v2 分片：第一次传完 1/3 后取消，第二次通过
// getUploadedPartsInfo 查到已上传分片并只补剩余分片。
func TestLiveResumeV2(t *testing.T) {
	token := os.Getenv("S189_AT")
	if token == "" {
		t.Skip("S189_AT not set")
	}
	conf.Conf = &conf.Config{TempDir: t.TempDir()}
	base.InitClient()

	y := &Cloud189PC{}
	y.Addition.AccessToken = token
	if err := y.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	y.uploadThread = 1

	const size = 30 * 1024 * 1024
	// 每次用不同的内容，避免 189 秒传把测试变成 fileDataExists=1。
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	data := make([]byte, size)
	_, _ = r.Read(data)
	sum := md5.Sum(data)
	md5Hex := fmt.Sprintf("%X", sum[:])
	name := fmt.Sprintf("go-v2-resume-%d.bin", time.Now().UnixNano())
	dst := &model.Object{ID: "-11"}
	mkStream := func() model.FileStreamer {
		return &stream.FileStream{
			Ctx:      context.Background(),
			Obj:      &model.Object{Name: name, Size: size},
			Reader:   bytes.NewReader(data),
			Mimetype: "application/octet-stream",
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, _, err := y.FastUploadWithInfo(ctx, dst, mkStream(), func(p float64) {
		t.Logf("first progress %.1f%%", p)
		if p >= 30 {
			cancel()
		}
	}, false, true)
	cancel()
	t.Logf("first attempt ended with: %v", err)
	if err == nil {
		t.Fatalf("first attempt unexpectedly completed")
	}

	state := y.loadV2UploadProgress("-11", md5Hex, name, size)
	if state == nil {
		t.Fatalf("no v2 state persisted")
	}
	uploaded, err := y.GetUploadedPartsInfo(context.Background(), state.UploadInfo.Data.UploadFileID, false)
	if err != nil {
		t.Fatalf("getUploadedPartsInfo: %v", err)
	}
	t.Logf("server uploaded parts: %v (uploadFileId=%s)", uploaded, state.UploadInfo.Data.UploadFileID)
	if len(uploaded) == 0 {
		t.Fatalf("server reported no uploaded parts")
	}

	obj, _, err := y.FastUploadWithInfo(context.Background(), dst, mkStream(), func(p float64) {
		t.Logf("resume progress %.1f%%", p)
	}, false, true)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Logf("uploaded: name=%s id=%s", obj.GetName(), obj.GetID())
	if err := y.Delete(context.Background(), "", obj); err != nil {
		t.Logf("cleanup delete failed: %v", err)
	}
}

// 实网测试：同一份内容（同 md5/大小/文件名）传另一个目录时，不能复用旧目录的 uploadFileId。
// 服务端的目录绑定发生在 initMultiUpload，commitMultiUploadFile 只带 uploadFileId，
// 所以一旦复用，文件会落进旧目录。
func TestLiveSameMd5OtherDir(t *testing.T) {
	token := os.Getenv("S189_AT")
	if token == "" {
		t.Skip("S189_AT not set")
	}
	conf.Conf = &conf.Config{TempDir: t.TempDir()}
	base.InitClient()

	y := &Cloud189PC{}
	y.Addition.AccessToken = token
	y.Addition.UploadMethod = "rapid"
	if err := y.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	const size = 12 * 1024 * 1024
	r := rand.New(rand.NewSource(20261124))
	data := make([]byte, size)
	_, _ = r.Read(data)
	name := fmt.Sprintf("go-dirk-%d.bin", time.Now().UnixNano())
	sum := md5.Sum(data)
	md5Hex := fmt.Sprintf("%X", sum[:])
	mkStream := func() model.FileStreamer {
		return &stream.FileStream{
			Ctx:      context.Background(),
			Obj:      &model.Object{Name: name, Size: size},
			Reader:   bytes.NewReader(data),
			Mimetype: "application/octet-stream",
		}
	}

	root := &model.Object{ID: "-11"}
	dirName := fmt.Sprintf("go-dirk-dir-%d", time.Now().UnixNano())
	other, err := y.MakeDir(context.Background(), root, dirName)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	defer func() {
		if err := y.Remove(context.Background(), other); err != nil {
			t.Logf("cleanup rmdir failed: %v", err)
		}
	}()

	// 在 old 目录（root）传一半后中断，留下 old 目录的会话。
	ctx, cancel := context.WithCancel(context.Background())
	_, _, err = y.FastUploadWithInfo(ctx, root, mkStream(), func(p float64) {
		if p >= 30 {
			cancel()
		}
	}, false, true)
	cancel()
	oldState := y.loadV2UploadProgress(root.GetID(), md5Hex, name, size)
	if oldState == nil {
		t.Fatalf("expected cached state for root dir")
	}
	t.Logf("old dir uploadFileId=%s", oldState.UploadInfo.Data.UploadFileID)

	// 同一文件传到新目录，必须重新 init，并且最终落在新目录。
	obj, _, err := y.FastUploadWithInfo(context.Background(), other, mkStream(), func(p float64) {}, false, true)
	if err != nil {
		t.Fatalf("upload to other dir: %v", err)
	}
	t.Logf("uploaded: name=%s id=%s", obj.GetName(), obj.GetID())
	defer func() {
		if err := y.Delete(context.Background(), "", obj); err != nil {
			t.Logf("cleanup delete failed: %v", err)
		}
	}()

	if st := y.loadV2UploadProgress(other.GetID(), md5Hex, name, size); st != nil {
		if st.UploadInfo.Data.UploadFileID == oldState.UploadInfo.Data.UploadFileID {
			t.Fatalf("new dir reused old uploadFileId %s", st.UploadInfo.Data.UploadFileID)
		}
	}

	items, err := y.List(context.Background(), other, model.ListArgs{})
	if err != nil {
		t.Fatalf("list other dir: %v", err)
	}
	found := false
	for _, it := range items {
		if it.GetID() == obj.GetID() {
			found = true
		}
	}
	if !found {
		t.Fatalf("uploaded file %s not found in target dir %s", obj.GetID(), other.GetID())
	}
	t.Logf("file %s confirmed inside dir %s", obj.GetID(), other.GetID())
}
