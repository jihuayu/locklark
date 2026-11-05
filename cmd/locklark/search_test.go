package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestTitleSearchCLIHiddenQueryOnly(t *testing.T) {
	for _, args := range [][]string{{"search", "--file", "owner.ll"}, {"search", "--file", "owner.ll", "--state", "all"}} {
		if e := runPersonal(args, &bytes.Buffer{}); e == nil || !strings.Contains(e.Error(), "interactive terminal") {
			t.Fatal("terminal gate", e)
		}
	}
	for _, args := range [][]string{{"search", "--file", "owner.ll", "--query", "private query"}, {"search", "--file", "owner.ll", "--state", "unknown"}, {"search", "--file", "owner.ll", "--state", "all", "--query", "private query"}} {
		if e := runPersonal(args, &bytes.Buffer{}); e != personalUsage || strings.Contains(e.Error(), "private query") {
			t.Fatal("argv query accepted or echoed", e)
		}
	}
}
