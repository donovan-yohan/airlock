//go:build !linux

package trusted

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestControlPlaneRequiresLinuxPeerCredentials(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := trustedTestStore(t, privateKey, time.Now().UTC().Truncate(time.Second))
	_, err = NewControlPlane(t.TempDir()+"/control.sock", NewActionService(store))
	if err == nil || !strings.Contains(err.Error(), "Linux SO_PEERCRED") {
		t.Fatalf("unsupported platform control socket error=%v", err)
	}
}
