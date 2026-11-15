//go:build !darwin && !linux

package main

import (
	"bytes"
	"testing"
)

func TestVaultFileUnsupported(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"vault-file", "resume-prepared", "--config", "unopened"}, &out, &out); err != errVaultFileUnsupported || out.Len() != 0 {
		t.Fatal("UNSUPPORTED_PLATFORM_NOT_REFUSED")
	}
}
