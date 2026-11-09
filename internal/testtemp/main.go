// Package testtemp gives authenticated Windows tests a private temporary
// directory even when the surrounding host TEMP directory inherits broader
// access. Test packages that exercise owner/ACL trust checks call Main so
// testing.TempDir resolves below a directory whose ancestry is acceptable to
// the production checks.
package testtemp

import (
	"fmt"
	"os"
	"testing"
)

// Main installs an owner-only temporary root, runs the package tests, and
// removes the root before exiting. Non-Windows platforms leave TMP and TEMP
// unchanged.
func Main(m *testing.M) {
	cleanup, err := install()
	if err != nil {
		fmt.Fprintln(os.Stderr, "private test temp unavailable:", err)
		os.Exit(1)
	}
	code := m.Run()
	if err := cleanup(); err != nil {
		fmt.Fprintln(os.Stderr, "private test temp cleanup failed:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}
