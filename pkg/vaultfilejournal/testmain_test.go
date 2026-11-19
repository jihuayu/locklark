package vaultfilejournal

import (
	"testing"

	"github.com/jihuayu/locklark/internal/testtemp"
)

func TestMain(m *testing.M) {
	// The journal refuses a non-private parent, and on Windows that includes
	// the whole ancestry of t.TempDir.
	testtemp.Main(m)
}
