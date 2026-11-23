package _189pc

import (
	"testing"
	"time"
)

func TestSweepResumeMem(t *testing.T) {
	y := &Cloud189PC{}
	y.Addition.Username = "test-user"

	legacy := &uploadResumeState{
		FileMD5:      "ABCDEF",
		FileName:     "legacy.bin",
		FileSize:     1024,
		UploadFileID: 1,
	}
	if err := y.saveResumeState(legacy); err != nil {
		t.Fatalf("save legacy: %v", err)
	}
	v2 := &UploadProgress{
		UploadInfo:  InitMultiUploadResp{},
		UploadParts: []string{"1-aaa", "2-bbb"},
	}
	v2.UploadInfo.Data.UploadFileID = "2706_3_2~test"
	if err := y.saveV2UploadProgress("-11", "ABCDEF", "v2.bin", 2048, v2); err != nil {
		t.Fatalf("save v2: %v", err)
	}

	// 把两条都改成 4 天前，模拟过期。
	resumeStoreMu.Lock()
	resumeMem[resumeStateKey("ABCDEF", 1024)].updatedAt = time.Now().Add(-4 * 24 * time.Hour)
	resumeMem[resumeStateKey("ABCDEF", 2048)].updatedAt = time.Now().Add(-4 * 24 * time.Hour)
	resumeStoreMu.Unlock()

	y.sweepResumeMem()

	if got := y.loadResumeState("ABCDEF", "legacy.bin", 1024); got != nil {
		t.Fatalf("legacy state should be swept, got %+v", got)
	}
	if got := y.loadV2UploadProgress("-11", "ABCDEF", "v2.bin", 2048); got != nil {
		t.Fatalf("v2 state should be swept, got %+v", got)
	}
}
