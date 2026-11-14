package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain makes this binary usable as a real brokered child on every
// platform: only the exact two-argument mode form with exit status 0 or 7
// exits with that status, only the exact four-argument readiness mode runs the
// long-lived cancellation child, and every other invocation runs the suite
// normally.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == cliBrokerReadyChildMode {
		os.Exit(runCLIBrokerReadyChild(os.Args[2], os.Args[3]))
	}
	if len(os.Args) == 3 && os.Args[1] == "locklark-test-child-exit" {
		if code := os.Args[2]; code == "0" || code == "7" {
			os.Exit(int(code[0] - '0'))
		}
	}
	os.Exit(m.Run())
}

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
