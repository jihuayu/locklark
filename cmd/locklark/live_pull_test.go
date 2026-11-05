package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLivePullCLIRequiresHumanTerminal(t *testing.T) {
	valid := []string{"github-pull", "--file", "owner.ll", "--id", strings.Repeat("1", 32), "--revision", strings.Repeat("a", 64), "--repository-id", "1445507532", "--owner", "jihuayu", "--repository", "locklark", "--number", "18", "--api-ip", "140.82.112.6"}
	if e := runPersonal(valid, &bytes.Buffer{}); e == nil || !strings.Contains(e.Error(), "interactive terminal") {
		t.Fatal("terminal gate", e)
	}
	for _, change := range []struct {
		at    int
		value string
	}{{8, "01"}, {10, "bad/owner"}, {12, "../other"}, {14, "018"}, {14, "0"}, {16, "127.0.0.1"}, {16, "https://evil.example"}} {
		args := append([]string(nil), valid...)
		args[change.at] = change.value
		if e := runPersonal(args, &bytes.Buffer{}); e != personalUsage {
			t.Fatal("invalid live target", e)
		}
	}
	if e := runPersonal(append(valid, "--backend", "recorded-response/v1"), &bytes.Buffer{}); e != personalUsage {
		t.Fatal("backend switch", e)
	}
}
