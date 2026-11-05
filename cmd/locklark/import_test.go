package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestImportCommandRequiresPlanDigestAndTerminal(t *testing.T) {
	for _, args := range [][]string{
		{"import-1pux", "--file", "vault", "--source", "source"},
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", "bad"},
		{"plan-import-1pux", "--file", "vault", "--source", "source", "--digest", strings.Repeat("0", 64)},
	} {
		if err := runPersonal(args, &bytes.Buffer{}); err != personalUsage {
			t.Fatal("invalid import shape", err)
		}
	}
	for _, args := range [][]string{
		{"import-1pux", "--file", "vault", "--source", "source", "--digest", strings.Repeat("0", 64)},
		{"plan-import-1pux", "--file", "vault", "--source", "source"},
	} {
		err := runPersonal(args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
			t.Fatal("missing terminal boundary", err)
		}
	}
}
