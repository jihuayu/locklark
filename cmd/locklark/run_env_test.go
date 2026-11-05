package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunEnvCLIBoundary(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	valid := []string{"run-env", "--file", "owner.ll", "--id", strings.Repeat("1", 32), "--revision", strings.Repeat("a", 64), "--field", "password", "--name", "TOKEN", "--cwd", t.TempDir(), "--timeout", "10", "--", exe, "argument", ""}
	if e := runPersonal(valid, &bytes.Buffer{}); e == nil || !strings.Contains(e.Error(), "interactive terminal") {
		t.Fatal("no terminal gate", e)
	}
	for _, tc := range []struct {
		at    int
		value string
	}{{8, "otp"}, {10, "systemROOT"}, {12, "relative"}, {14, "01"}, {16, "relative"}, {10, "bad=name"}} {
		args := append([]string(nil), valid...)
		args[tc.at] = tc.value
		if e := runPersonal(args, &bytes.Buffer{}); e != personalUsage {
			t.Fatal("invalid accepted", e)
		}
	}
	for _, args := range [][]string{valid[:15], valid[:16], append([]string{"list", "--file", "owner.ll", "--"}, exe)} {
		if e := runPersonal(args, &bytes.Buffer{}); e != personalUsage {
			t.Fatal("separator invalid", e)
		}
	}
}
