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
			st := y.loadResumeState(md5Hex, name, size)
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
	state := y.loadResumeState(md5Hex, name, size)
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
