//go:build !windows

package desktop

import (
	"os"
	"testing"
)

func newPrivateCLIConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
