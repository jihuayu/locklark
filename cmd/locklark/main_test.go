package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoThenExplicitExport(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "demo")
	var out, diagnostics bytes.Buffer
	if err := run([]string{"demo", "--out", root, "--session", "migration", "--reason", "test"}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("[1,2,3]")) {
		t.Fatal("demo output omits edited snapshot")
	}
	out.Reset()
	if err := run([]string{"fixture-export", "--bundle", filepath.Join(root, "share", "epoch-3"), "--device", filepath.Join(root, "clients", "B"), "--epoch", "3", "--out", filepath.Join(dir, "sample.1pux")}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("otpauth")) || !bytes.Contains(out.Bytes(), []byte("\"synthetic\":true")) {
		t.Fatal("unexpected export receipt")
	}
}

func TestStructuredHelpAndPersonalHelp(t *testing.T) {
	for _, flag := range [][]string{nil, {"help"}, {"--help"}, {"-h"}} {
		var out, diag bytes.Buffer
		if err := run(flag, &out, &diag); err != nil || diag.Len() != 0 {
			t.Fatalf("help %v failed: err=%v diag=%q", flag, err, diag.String())
		}
		text := out.String()
		for _, want := range []string{
			"USAGE", "COMMAND GROUPS", "PERSONAL VAULT", "CLI WRAPPERS", "TEAM BOOTSTRAP", "PLUGIN CATALOG",
			"add-item", "reveal-ref", "passkey-invite", "cli profiles", "cli run <tool>", "cli shell-init", "--passthrough",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("top-level help missing %q", want)
			}
		}
	}

	for _, args := range [][]string{
		{"personal", "--help"},
		{"personal", "-h"},
		{"personal", "help"},
		{"personal", "add-item", "--help"},
		{"personal", "passkey-invite", "-h"},
		{"personal", "run-cli", "--help"},
	} {
		var out, diag bytes.Buffer
		if err := run(args, &out, &diag); err != nil || diag.Len() != 0 {
			t.Fatalf("personal help %v failed: err=%v diag=%q", args, err, diag.String())
		}
		if !strings.Contains(out.String(), "usage: locklark personal") {
			t.Fatalf("personal help %v missing usage header: %q", args, out.String())
		}
	}

	var out bytes.Buffer
	if err := runPersonal([]string{"unknown-action", "--help"}, &out); err != personalUsage || out.Len() != 0 {
		t.Fatalf("unknown personal action --help = %v, out=%q", err, out.String())
	}
	if !strings.HasPrefix(personalUsage.Error(), "usage: locklark personal") {
		t.Fatalf("personalUsage prefix changed: %q", personalUsage.Error())
	}
}
