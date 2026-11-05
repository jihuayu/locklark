package main

import (
	"bytes"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/preview"
	"path/filepath"
	"testing"
)

func TestCLIReviewDecideAndReadJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	var out, diag bytes.Buffer
	call := func(argv ...string) []byte {
		t.Helper()
		out.Reset()
		if err := run(argv, &out, &diag); err != nil {
			t.Fatal(argv[0], err)
		}
		return out.Bytes()
	}
	call("demo", "--out", root, "--session", "init", "--reason", "run fixture")
	inbox, b := filepath.Join(root, "inbox"), filepath.Join(root, "clients", "B")
	key := filepath.Join(t.TempDir(), "release.sessionkey")
	var identity struct{ Public string }
	if json.Unmarshal(call("session-keygen", "--out", key), &identity) != nil || identity.Public == "" {
		t.Fatal("missing public key")
	}
	call("session-enroll", "--device", b, "--session", "release", "--public", identity.Public, "--reason", "runner setup")
	call("request", "--inbox", inbox, "--recipient", filepath.Join(root, "agent", "approval.pub"), "--session", "release", "--reason", "inspect sample", "--ref", preview.FixtureRef, "--session-key", key)
	var report preview.InboxReport
	if json.Unmarshal(call("inbox", "--inbox", inbox, "--device", b, "--session", "release"), &report) != nil || len(report.Requests) != 1 {
		t.Fatal("missing request")
	}
	req := report.Requests[0]
	call("decide", "--inbox", inbox, "--device", b, "--bundle", filepath.Join(root, "share", "epoch-3"), "--id", req.ID, "--review", req.Review, "--choice", "approve", "--reason", "reviewed sample")
	var rows []preview.Decision
	if json.Unmarshal(call("decisions", "--device", b, "--session", "release"), &rows) != nil || len(rows) != 1 || rows[0].Result != "approved" || rows[0].Expires == nil {
		t.Fatal("decision not durable")
	}
}
