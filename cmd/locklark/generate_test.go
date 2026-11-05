package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerationCLIArgumentsAndTerminal(t *testing.T) {
	for _, action := range []string{"generate-login", "regenerate-password"} {
		base := []string{action, "--file", "unused.ll"}
		if action == "regenerate-password" {
			base = append(base, "--id", strings.Repeat("a", 32), "--revision", strings.Repeat("b", 64))
		}
		for _, test := range []struct {
			options []string
			valid   bool
		}{
			{nil, true}, {[]string{"--length", "22"}, true}, {[]string{"--length", "256"}, true},
			{[]string{"--length", "21"}, false}, {[]string{"--length", "257"}, false}, {[]string{"--length", "+24"}, false}, {[]string{"--length", "024"}, false},
			{[]string{"--length", "-1"}, false}, {[]string{"--alphabet", "a"}, false}, {[]string{"--length", "24", "--unknown", "x"}, false},
		} {
			args := append(append([]string(nil), base...), test.options...)
			var out bytes.Buffer
			err := runPersonal(args, &out)
			if err == nil || out.Len() != 0 {
				t.Fatal("accepted noninteractive generation")
			}
			if strings.Contains(err.Error(), "interactive terminal") != test.valid {
				t.Fatal("argument validation boundary", action, test.options, err)
			}
		}
	}
}
