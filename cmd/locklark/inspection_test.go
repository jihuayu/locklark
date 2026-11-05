package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInspectionCLIRequiresTerminal(t *testing.T) {
	var out bytes.Buffer
	err := runPersonal([]string{"inspect-1pux", "--file", "unused.ll", "--source", "unused.1pux"}, &out)
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") || out.Len() != 0 {
		t.Fatal("inspection accepted noninteractive caller", err)
	}
	for _, args := range [][]string{{"inspect-1pux", "--file", "unused.ll"}, {"inspect-1pux", "--file", "unused.ll", "--extra", "unused.1pux"}} {
		if err := runPersonal(args, &out); err != personalUsage {
			t.Fatal("malformed inspection arguments accepted", err)
		}
	}
}
