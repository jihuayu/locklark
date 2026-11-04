package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIWitnessGuardsFilteredResults(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	var out, diag bytes.Buffer
	if err := run([]string{"demo", "--out", root, "--session", "audit-test", "--reason", "synthetic check"}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	args := []string{"audit", "--bundle", filepath.Join(root, "share", "epoch-2"), "--epoch", "2", "--device", filepath.Join(root, "clients", "B"), "--session", "audit-test", "--checkpoint"}
	for _, bad := range []string{"", filepath.Join(root, "witness", "epoch-3.json")} {
		out.Reset()
		if err := run(append(args, bad), &out, &diag); err == nil || out.Len() != 0 {
			t.Fatal("released audit rows without requested witness")
		}
	}
	out.Reset()
	if err := run(append(args, filepath.Join(root, "witness", "epoch-2.json")), &out, &diag); err != nil || !strings.Contains(out.String(), "synthetic check") {
		t.Fatal("witnessed query failed", err)
	}
}
