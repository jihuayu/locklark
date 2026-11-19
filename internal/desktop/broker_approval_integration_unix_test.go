//go:build linux || darwin

package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

// desktopBrokerSocket returns a socket path inside a private directory under
// the standard sticky /tmp. localpath.TrustedTemporaryParent only trusts that
// root, so the broker's Unix endpoint checks accept it.
func desktopBrokerSocket(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("/tmp", "llb-desktop-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private test directory")
	}
	return filepath.Join(dir, "b.sock")
}
