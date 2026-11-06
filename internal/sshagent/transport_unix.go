//go:build linux || darwin

package sshagent

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/jihuayu/locklark/internal/localpath"
)

func DefaultEndpoint() (string, error) {
	parent, e := localpath.TrustedTemporaryParent(os.TempDir())
	if e != nil {
		return "", ErrUnavailable
	}
	return filepath.Join(parent, "locklark-ssh-"+strconv.Itoa(os.Geteuid()), "agent.sock"), nil
}
func prepareConnection(c net.Conn) (Peer, []byte, error) {
	peer, e := authenticatedPeer(c)
	return peer, nil, e
}

type unixListener struct {
	*net.UnixListener
	path     string
	identity os.FileInfo
	once     sync.Once
	lstat    func(string) (os.FileInfo, error)
	remove   func(string) error
	closeErr error
}

func (l *unixListener) Close() error {
	l.once.Do(func() {
		if l.UnixListener.Close() != nil {
			l.closeErr = ErrUnavailable
		}
		current, err := l.lstat(l.path)
		switch {
		case os.IsNotExist(err):
			// An absent endpoint confirms cleanup even if another same-user
			// action removed it first. A replacement must never be removed.
		case err != nil:
			l.closeErr = ErrUnavailable
		case !os.SameFile(l.identity, current) || current.Mode()&os.ModeSocket == 0:
			l.closeErr = ErrUnavailable
		case l.remove(l.path) != nil:
			l.closeErr = ErrUnavailable
		}
	})
	return l.closeErr
}
func listenLocal(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || len(path) > 100 {
		return nil, ErrUnavailable
	}
	dir := filepath.Dir(path)
	parent, e := localpath.TrustedTemporaryParent(filepath.Dir(dir))
	if e != nil {
		return nil, ErrUnavailable
	}
	dir = filepath.Join(parent, filepath.Base(dir))
	path = filepath.Join(dir, filepath.Base(path))
	if len(path) > 100 {
		return nil, ErrUnavailable
	}
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return nil, ErrUnavailable
	}
	if _, e := localpath.TrustedTemporaryParent(dir); e != nil {
		return nil, ErrUnavailable
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, ErrUnavailable
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		return nil, ErrUnavailable
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, ErrUnavailable
	}
	l.SetUnlinkOnClose(false)
	info, e = os.Lstat(path)
	if e != nil {
		_ = l.Close()
		return nil, ErrUnavailable
	}
	wrapper := &unixListener{UnixListener: l, path: path, identity: info, lstat: os.Lstat, remove: os.Remove}
	if os.Chmod(path, 0600) != nil {
		_ = wrapper.Close()
		return nil, ErrUnavailable
	}
	return wrapper, nil
}
