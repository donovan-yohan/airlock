//go:build linux

package trusted

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

type peerAuthenticatedControlListener struct {
	*net.UnixListener
	trustedUID uint32
}

func requireControlPeerAuthentication() error { return nil }

func validateControlSocketParent(socket string) error {
	info, err := os.Lstat(filepath.Dir(socket))
	if err != nil {
		return fmt.Errorf("inspect trusted control socket parent: %w", err)
	}
	return validateControlSocketParentInfo(info, os.Geteuid())
}

func validateControlSocketParentInfo(info os.FileInfo, daemonUID int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !controlSocketParentOwnedBy(stat.Uid, daemonUID) {
		return errors.New("trusted control socket parent must be owned by the daemon UID")
	}
	return nil
}

func controlSocketParentOwnedBy(parentUID uint32, daemonUID int) bool {
	return daemonUID >= 0 && parentUID == uint32(daemonUID)
}

// acquireControlLifecycleLock serializes the complete socket lifecycle across
// daemon processes. flock is released by the kernel when this process exits,
// including after a crash.
func acquireControlLifecycleLock(socket string) (*os.File, error) {
	lockPath := filepath.Join(filepath.Dir(socket), filepath.Base(socket)+".lock")
	fd, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open trusted control lifecycle lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	if err := validateControlLifecycleLock(fd); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("trusted control socket lifecycle lock is already held")
		}
		return nil, fmt.Errorf("lock trusted control socket lifecycle: %w", err)
	}
	return lock, nil
}

func validateControlLifecycleLock(fd int) error {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect trusted control lifecycle lock: %w", err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return errors.New("trusted control lifecycle lock must be a regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("trusted control lifecycle lock must be owned by the daemon UID")
	}
	if stat.Mode&0o077 != 0 {
		return errors.New("trusted control lifecycle lock must be accessible only by its owner")
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("set trusted control lifecycle lock mode: %w", err)
	}
	return nil
}

func releaseControlLifecycleLock(lock *os.File) error {
	if lock == nil {
		return nil
	}
	return lock.Close()
}

func newPeerAuthenticatedControlListener(listener net.Listener, trustedUID int) (net.Listener, error) {
	if trustedUID < 0 {
		return nil, errors.New("trusted control daemon effective UID is invalid")
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return nil, errors.New("trusted control listener is not a Unix listener")
	}
	return &peerAuthenticatedControlListener{UnixListener: unixListener, trustedUID: uint32(trustedUID)}, nil
}

func (l *peerAuthenticatedControlListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if err := authenticateControlPeer(connection, l.trustedUID); err == nil {
			return connection, nil
		}
		// This loop blocks in AcceptUnix between rejected connections. Do not
		// surface a temporary error to http.Server, which would otherwise retry.
		_ = connection.Close()
	}
}

func authenticateControlPeer(connection *net.UnixConn, trustedUID uint32) error {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return fmt.Errorf("get Unix peer socket: %w", err)
	}
	var credentials *syscall.Ucred
	var socketErr error
	if err := rawConnection.Control(func(fd uintptr) {
		credentials, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("inspect Unix peer credentials: %w", err)
	}
	if socketErr != nil {
		return fmt.Errorf("read Unix peer credentials: %w", socketErr)
	}
	if credentials == nil {
		return errors.New("Unix peer credentials are unavailable")
	}
	if !controlPeerUIDAuthorized(credentials.Uid, trustedUID) {
		return errors.New("trusted control peer UID does not match daemon UID")
	}
	return nil
}
