package netguard

import (
	"errors"
	"syscall"
	"testing"
)

func TestLoopbackDefaultAndNonLoopbackRefusal(t *testing.T) {
	listener, err := Listen("127.0.0.1:0", false)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skip("sandbox does not permit loopback sockets")
		}
		t.Fatalf("loopback listen failed: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen("0.0.0.0:0", false); err == nil {
		t.Fatal("non-loopback listener accepted without unsafe opt-in")
	}
	if _, err := Listen("localhost:0", false); err == nil {
		t.Fatal("hostname listener accepted; expected explicit IP")
	}
}
