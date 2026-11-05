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
			options      []string
			valid        bool
			regeneration bool
		}{
			{nil, true, true}, {[]string{"--length", "22"}, true, true}, {[]string{"--length", "256"}, true, true},
			{[]string{"--length", "21"}, false, true}, {[]string{"--length", "257"}, false, true}, {[]string{"--length", "+24"}, false, false}, {[]string{"--length", "024"}, false, false},
			{[]string{"--length", "-1"}, false, true}, {[]string{"--alphabet", "a"}, false, false}, {[]string{"--length", "24", "--unknown", "x"}, false, false},
		} {
			args := append(append([]string(nil), base...), test.options...)
			var out bytes.Buffer
			err := runPersonal(args, &out)
			if err == nil || out.Len() != 0 {
				t.Fatal("accepted noninteractive generation")
			}
			wantTerminal := test.valid
			// Regeneration policy is evaluated after authentication and target state.
			if action == "regenerate-password" {
				wantTerminal = test.regeneration
			}
			if strings.Contains(err.Error(), "interactive terminal") != wantTerminal {
				t.Fatal("argument validation boundary", action, test.options, err)
			}
		}
	}
}
