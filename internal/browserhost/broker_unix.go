//go:build linux || darwin

package browserhost

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jihuayu/locklark/internal/localpath"
)

// trustedBrokerParent is the localpath trust check. It is a variable so the
// package's own tests can exercise the socket protocol on odd CI filesystems;
// the shipped default is the strict localpath validator.
var trustedBrokerParent = localpath.TrustedTemporaryParent

func DefaultBrokerEndpoint() (string, error) {
	if custom := os.Getenv("LOCKLARK_BROWSER_SOCKET"); custom != "" {
		if !filepath.IsAbs(custom) || len(custom) > 100 {
			return "", ErrBrokerUnavailable
		}
		if _, e := trustedBrokerParent(filepath.Dir(custom)); e != nil {
			return "", ErrBrokerUnavailable
		}
		return custom, nil
	}
	parent, e := trustedBrokerParent(os.TempDir())
	if e != nil {
		return "", ErrBrokerUnavailable
	}
	return filepath.Join(parent, "locklark-brw-"+strconv.Itoa(os.Geteuid()), "b.sock"), nil
}

type brokerUnixListener struct {
	*net.UnixListener
	path     string
	identity os.FileInfo
	once     sync.Once
	err      error
}

func (l *brokerUnixListener) Close() error {
	l.once.Do(func() {
		if l.UnixListener.Close() != nil {
			l.err = ErrBrokerUnavailable
		}
		current, e := os.Lstat(l.path)
		switch {
		case os.IsNotExist(e):
		case e != nil:
			l.err = ErrBrokerUnavailable
		case !os.SameFile(l.identity, current) || current.Mode()&os.ModeSocket == 0:
			l.err = ErrBrokerUnavailable
		case os.Remove(l.path) != nil:
			l.err = ErrBrokerUnavailable
		}
	})
	return l.err
}

func listenLocal(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || len(path) > 100 {
		return nil, ErrBrokerUnavailable
	}
	dir := filepath.Dir(path)
	if _, e := trustedBrokerParent(dir); e != nil {
		if _, parentErr := trustedBrokerParent(filepath.Dir(dir)); parentErr != nil {
			return nil, ErrBrokerUnavailable
		}
		if os.Mkdir(dir, 0700) != nil {
			return nil, ErrBrokerUnavailable
		}
		if _, e := trustedBrokerParent(dir); e != nil {
			return nil, ErrBrokerUnavailable
		}
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrBrokerUnavailable
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, ErrBrokerUnavailable
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return nil, ErrBrokerUnavailable
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, ErrBrokerUnavailable
	}
	l.SetUnlinkOnClose(false)
	info, e = os.Lstat(path)
	if e != nil {
		_ = l.Close()
		return nil, ErrBrokerUnavailable
	}
	wrapper := &brokerUnixListener{UnixListener: l, path: path, identity: info}
	if os.Chmod(path, 0600) != nil {
		_ = wrapper.Close()
		return nil, ErrBrokerUnavailable
	}
	return wrapper, nil
}

func dialLocal(ctx context.Context, endpoint string) (net.Conn, error) {
	d := net.Dialer{Timeout: 300 * time.Millisecond}
	return d.DialContext(ctx, "unix", endpoint)
}
