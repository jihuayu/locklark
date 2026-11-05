package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReferenceCLIArgumentsAndTerminal(t *testing.T) {
	for _, action := range []string{"reveal-ref", "otp-ref"} {
		for _, test := range []struct {
			ref, revision string
			valid         bool
		}{
			{"op://Personal/item/password", strings.Repeat("b", 64), true},
			{"op://Personal/item/otp", strings.Repeat("b", 64), true},
			{"op://Personal/item/password?attribute=type", strings.Repeat("b", 64), false},
			{"op://Personal/中文/password", strings.Repeat("b", 64), false},
			{"op://Personal/item/password", "bad", false},
		} {
			var out bytes.Buffer
			err := runPersonal([]string{action, "--file", "unused.ll", "--ref", test.ref, "--revision", test.revision}, &out)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "interactive terminal") != test.valid {
				t.Fatal("reference CLI validation boundary", err)
			}
		}
	}
	var out bytes.Buffer
	if err := runPersonal([]string{"references", "--file", "unused.ll"}, &out); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatal("index accepted noninteractive access", err)
	}
}
