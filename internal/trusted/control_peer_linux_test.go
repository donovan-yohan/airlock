//go:build linux

package trusted

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestControlSocketParentMustBeOwnedByDaemon(t *testing.T) {
	daemonUID := os.Geteuid()
	if err := validateControlSocketParentInfo(controlParentInfo{uid: uint32(daemonUID)}, daemonUID); err != nil {
		t.Fatalf("daemon-owned control parent rejected: %v", err)
	}
	if err := validateControlSocketParentInfo(controlParentInfo{uid: uint32(daemonUID) + 1}, daemonUID); err == nil {
		t.Fatal("foreign-owned control parent accepted")
	}
}

type controlParentInfo struct{ uid uint32 }

func (info controlParentInfo) Name() string       { return "control-parent" }
func (info controlParentInfo) Size() int64        { return 0 }
func (info controlParentInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (info controlParentInfo) ModTime() time.Time { return time.Time{} }
func (info controlParentInfo) IsDir() bool        { return true }
func (info controlParentInfo) Sys() any           { return &syscall.Stat_t{Uid: info.uid} }
