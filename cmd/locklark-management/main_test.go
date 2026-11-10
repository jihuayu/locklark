package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/management"
)

func TestManagementHelpAndArgumentRefusals(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		var out bytes.Buffer
		if err := run([]string{arg}, &out); err != nil {
			t.Fatalf("run(%q) failed: %v", arg, err)
		}
		text := out.String()
		for _, want := range []string{"USAGE", "MODES", "FLAGS", "--directory", "--read-connection", "127.0.0.1"} {
			if !strings.Contains(text, want) {
				t.Fatalf("management help missing %q: %s", want, text)
			}
		}
	}

	for _, bad := range [][]string{
		nil,
		{"--unknown"},
		{"--read-connection", "/tmp/conn.json", "--directory", "/tmp/dir.db"},
		{"--directory", "/tmp/dir.db"},
		{"positional"},
	} {
		var out bytes.Buffer
		if err := run(bad, &out); !errors.Is(err, management.ErrUnavailable) || out.Len() != 0 {
			t.Fatalf("run(%v) = %v, out=%q; want ErrUnavailable", bad, err, out.String())
		}
	}
}
