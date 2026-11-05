package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestJSONInjectionCLIBoundary(t *testing.T) {
	valid := []string{"inject-json", "--file", "owner.ll", "--id", strings.Repeat("1", 32), "--revision", strings.Repeat("a", 64), "--field", "password", "--name", "TOKEN", "--out", "new.json"}
	if e := runPersonal(valid, &bytes.Buffer{}); e == nil || !strings.Contains(e.Error(), "interactive terminal") {
		t.Fatal("terminal gate absent", e)
	}
	for _, test := range []struct {
		at    int
		value string
	}{{8, "otp"}, {10, "bad property"}, {10, ""}, {6, "old"}} {
		args := append([]string(nil), valid...)
		args[test.at] = test.value
		if e := runPersonal(args, &bytes.Buffer{}); e != personalUsage {
			t.Fatal("invalid injection shape accepted", e)
		}
	}
}
