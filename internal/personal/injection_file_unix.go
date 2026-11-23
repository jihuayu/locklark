//go:build !windows

package personal

import "os"

func createInjectionTemp(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".passme-inject-*") // Created as 0600, before any value is written.
}
