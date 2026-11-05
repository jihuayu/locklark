package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRevealRejectsNoninteractiveAndInvalidTargets(t *testing.T) {
	base := []string{"reveal-login", "--file", "unused.ll", "--id", strings.Repeat("a", 32), "--revision", strings.Repeat("b", 64), "--field", "password"}
	for _, field := range []string{"password", "otp", "title", "PASSWORD"} {
		args := append([]string(nil), base...)
		args[len(args)-1] = field
		var out bytes.Buffer
		err := runPersonal(args, &out)
		if err == nil || out.Len() != 0 {
			t.Fatal("accepted noninteractive disclosure")
		}
		if field == "password" && !strings.Contains(err.Error(), "interactive terminal") {
			t.Fatal(err)
		}
		if field != "password" && err != personalUsage {
			t.Fatal("field was not rejected before authentication", err)
		}
	}
}
