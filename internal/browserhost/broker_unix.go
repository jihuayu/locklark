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
	l, e := listenUnixLocal(path)
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

// brokerEndpointForClient resolves the CLI client's endpoint without collapsing
// configuration errors into the fallback-safe "absent" sentinel. A custom
// endpoint or parent that fails trust validation is a configuration error the
// caller must refuse, never treat as a missing default broker.
func brokerEndpointForClient() (string, error) {
	if custom := os.Getenv("LOCKLARK_BROWSER_SOCKET"); custom != "" {
		if !filepath.IsAbs(custom) || len(custom) > 100 {
			return "", ErrBrokerRefused
		}
		return custom, nil
	}
	path, ok := defaultBrokerEndpointPath()
	if !ok {
		return "", ErrBrokerRefused
	}
	return path, nil
}

// defaultBrokerEndpointPath derives the shipped default endpoint from the
// trusted temporary parent. It never creates a directory.
func defaultBrokerEndpointPath() (string, bool) {
	parent, e := trustedBrokerParent(os.TempDir())
	if e != nil {
		return "", false
	}
	return filepath.Join(parent, "locklark-brw-"+strconv.Itoa(os.Geteuid()), "b.sock"), true
}

// verifyBrokerSocket checks the endpoint itself: a UNIX socket owned by the
// current effective UID with private 0600 permissions, reached through a
// trusted parent directory, and not a final symlink. A missing socket is the
// only fallback-safe outcome; everything else is a fixed refusal so a hostile
// or misconfigured endpoint can never select the automatic fallback path.
func verifyBrokerSocket(path string) error {
	if !filepath.IsAbs(path) || len(path) > 100 {
		return ErrBrokerRefused
	}
	dir := filepath.Dir(path)
	if _, e := trustedBrokerParent(dir); e != nil {
		if brokerDefaultPathAbsent(path, dir) {
			return ErrBrokerUnavailable
		}
		return ErrBrokerRefused
	}
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return ErrBrokerUnavailable
	}
	if e != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return ErrBrokerRefused
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return ErrBrokerRefused
	}
	return nil
}

// brokerDefaultPathAbsent reports whether path is exactly the default endpoint
// whose private broker directory has never been created. A desktop broker that
// has never run is simply absent, so fallback is safe. This narrow case never
// creates anything and never excuses an existing directory, a symlink, a
// public directory, or any custom endpoint.
func brokerDefaultPathAbsent(path, dir string) bool {
	if os.Getenv("LOCKLARK_BROWSER_SOCKET") != "" {
		return false
	}
	def, ok := defaultBrokerEndpointPath()
	if !ok || path != def {
		return false
	}
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		return false
	}
	_, e := trustedBrokerParent(filepath.Dir(dir))
	return e == nil
}

// authenticatedBrokerPeer verifies the process listening on the broker socket.
// The shipped policy is a same-UID OS boundary, so the client reuses the
// server's peer-credential check (SO_PEERCRED/LOCAL_PEERCRED) instead of
// trusting the pathname alone. It is a variable so tests can prove the
// unverifiable-identity refusal without faking a foreign UID.
var authenticatedBrokerPeer = authenticatedPeer

// dialVerifiedBroker validates the socket path and the server's OS identity
// before returning a connection, so no hello or secret request is ever written
// to an unverified endpoint. Failures are fixed refusals except for a socket
// that is simply absent or a connection that was never established.
func dialVerifiedBroker(ctx context.Context, endpoint string) (net.Conn, error) {
	if e := verifyBrokerSocket(endpoint); e != nil {
		return nil, e
	}
	conn, e := dialLocal(ctx, endpoint)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ErrBrokerRefused
		}
		return nil, ErrBrokerUnavailable
	}
	if _, e := authenticatedBrokerPeer(conn); e != nil {
		_ = conn.Close()
		return nil, ErrBrokerRefused
	}
	return conn, nil
}
