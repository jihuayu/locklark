//go:build !windows

package desktop

import "testing"

func desktopPrivateTestRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
