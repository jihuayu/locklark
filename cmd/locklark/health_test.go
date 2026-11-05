package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHealthNeedsTerminalAndExactOptions(t *testing.T) {
	err := runPersonal([]string{"health", "--file", "owner.ll"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatal("nonterminal health accepted", err)
	}
	err = runPersonal([]string{"health", "--file", "owner.ll", "--network", "true"}, &bytes.Buffer{})
	if err != personalUsage {
		t.Fatal("unimplemented options accepted", err)
	}
}
