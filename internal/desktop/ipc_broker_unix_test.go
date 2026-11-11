//go:build linux || darwin

package desktop

import (
	"os"
	"testing"
)

// desktopBrokerTempRoot creates the socket's parent directory under the
// standard sticky /tmp explicitly, even when TMPDIR points elsewhere.
func desktopBrokerTempRoot(t *testing.T) (string, error) {
	t.Helper()
	return os.MkdirTemp("/tmp", "llb-")
}
