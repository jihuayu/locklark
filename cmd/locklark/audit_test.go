package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestPartialWitnessMarksNewRows(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	var out, diag bytes.Buffer
	if err := run([]string{"demo", "--out", root, "--session", "job", "--reason", "reason"}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"audit", "--bundle", filepath.Join(root, "share", "epoch-3"), "--epoch", "3", "--device", filepath.Join(root, "clients", "B"), "--session", "locklark-bootstrap", "--checkpoint", filepath.Join(root, "witness", "epoch-2.json")}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Events, Witnessed int
		Rows              []struct {
			Sequence  int
			Witnessed bool
		}
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Events != 4 || report.Witnessed != 3 || len(report.Rows) != 3 || !report.Rows[0].Witnessed || report.Rows[2].Witnessed || report.Rows[2].Sequence != 4 {
		t.Fatal("did not distinguish unwitnessed tail", err)
	}
}

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
