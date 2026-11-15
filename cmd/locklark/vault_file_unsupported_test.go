//go:build !darwin && !linux

package main

import (
	"bytes"
	"testing"
)

func TestVaultFileUnsupported(t *testing.T) {
	for _, command := range []string{"track-existing", "status", "import-prepared", "resume-prepared"} {
		var out bytes.Buffer
		if err := run([]string{"vault-file", command, "--config", "unopened"}, &out, &out); err != errVaultFileUnsupported || out.Len() != 0 {
			t.Fatal("UNSUPPORTED_PLATFORM_NOT_REFUSED")
		}
	}
}
