package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOTPCLIArgumentsAndTerminal(t *testing.T) {
	for _, args := range [][]string{
		{"otp", "--file", "unused.ll", "--id", strings.Repeat("a", 32), "--revision", strings.Repeat("b", 64)},
		{"edit-login", "--file", "unused.ll", "--id", strings.Repeat("a", 32), "--revision", strings.Repeat("b", 64), "--field", "otp"},
	} {
		var out bytes.Buffer
		if err := runPersonal(args, &out); err == nil || !strings.Contains(err.Error(), "interactive terminal") || out.Len() != 0 {
			t.Fatal("OTP accepted noninteractive input", err)
		}
		for _, extra := range [][]string{{"--at", "59"}, {"--seed", "secret"}, {"--field", "otp-code"}} {
			if err := runPersonal(append(append([]string(nil), args...), extra...), &out); err != personalUsage {
				t.Fatal("OTP accepted caller time/seed/field", err)
			}
		}
	}
}
