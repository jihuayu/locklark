//go:build !windows

package main

import "testing"

func newPrivateCLITestDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
