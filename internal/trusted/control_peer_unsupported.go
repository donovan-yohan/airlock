//go:build !linux

package trusted

import (
	"errors"
	"net"
	"os"
)

func requireControlPeerAuthentication() error {
	return errors.New("trusted control socket requires Linux SO_PEERCRED peer authentication")
}

func validateControlSocketParent(string) error { return requireControlPeerAuthentication() }

func acquireControlLifecycleLock(string) (*os.File, error) {
	return nil, requireControlPeerAuthentication()
}

func releaseControlLifecycleLock(*os.File) error { return nil }

func newPeerAuthenticatedControlListener(net.Listener, int) (net.Listener, error) {
	return nil, requireControlPeerAuthentication()
}
