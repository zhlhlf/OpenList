package _189pc

import "testing"

// 设备号必须固定可复现：同一账号、同一配置，多次调用结果一致。
func TestAppDeviceIDStable(t *testing.T) {
	y := &Cloud189PC{}
	y.Addition.Username = "user1"
	first := y.appDeviceID()
	for i := 0; i < 5; i++ {
		if got := y.appDeviceID(); got != first {
			t.Fatalf("device id changed: %s != %s", got, first)
		}
	}
	if len(first) != 32 {
		t.Fatalf("unexpected device id shape: %q", first)
	}

	other := &Cloud189PC{}
	other.Addition.Username = "user2"
	if other.appDeviceID() == first {
		t.Fatalf("different accounts must get different device ids")
	}
}
