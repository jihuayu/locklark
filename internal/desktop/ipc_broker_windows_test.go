//go:build windows

package desktop

import (
	"os"
	"testing"
)

// desktopBrokerTempRoot creates the private directory whose path becomes
// LOCKLARK_BROWSER_SOCKET. There is no /tmp on Windows; the caller still
// applies the localpath.TrustedTemporaryParent guard before using it.
func desktopBrokerTempRoot(t *testing.T) (string, error) {
	t.Helper()
	return os.MkdirTemp("", "llb-")
}
