package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestHealthLocalRulesAndPrivacy(t *testing.T) {
	items := []vault.Item{
		{ID: strings.Repeat("1", 32), Kind: "login", Title: "private-title", Username: "private-user", Password: "reuse-private-value", OTP: "present"},
		{ID: strings.Repeat("2", 32), Kind: "login", Password: "reuse-private-value", OTP: "present"},
		{ID: strings.Repeat("3", 32), Kind: "login", Password: "", ImportSource: []byte("reuse-private-value")},
		{ID: strings.Repeat("4", 32), Kind: "login", Password: "password"},
		{ID: strings.Repeat("5", 32), Kind: "login", Password: "aaaaaaaaaaaa", OTP: "present"},
		{ID: strings.Repeat("6", 32), Kind: "login", Password: "archived-private", State: "archived"},
		{ID: strings.Repeat("7", 32), Kind: "login", Password: "reuse-private-value", State: "trashed"},
		{ID: strings.Repeat("8", 32), Kind: "document", Filename: "private.txt", Attachment: []byte("secret")},
	}
	revisions := map[string]string{}
	for _, item := range items {
		revisions[item.ID] = strings.Repeat("0123456789abcdef", 4)
	}
	report, err := localHealth(items, revisions)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 5 || report.Skipped != 3 || len(report.Findings) != 5 || report.Profile != "local-heuristics-v1" {
		t.Fatal("wrong scope")
	}
	want := [][]string{{"reused"}, {"reused"}, {"empty", "totp-not-stored"}, {"short", "common-example", "totp-not-stored"}, {"low-variety"}}
	for i, finding := range report.Findings {
		if !reflect.DeepEqual(finding.Flags, want[i]) {
			t.Fatal("wrong local flags", i, finding.Flags)
		}
	}
	raw, _ := json.Marshal(report)
	for _, marker := range []string{"private-", "password", "aaaaaa", "secret", "present"} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatal("health leaked fields")
		}
	}
	// No unconditional strength claim and no normalization of distinct values.
	items = []vault.Item{{ID: strings.Repeat("1", 32), Kind: "login", Password: "abcdefghijkL", OTP: "present"}, {ID: strings.Repeat("2", 32), Kind: "login", Password: "abcdefghijkl", OTP: "present"}}
	report, err = localHealth(items, revisions)
	if err != nil || len(report.Findings) != 0 {
		t.Fatal("case-sensitive equality changed", err)
	}
	delete(revisions, items[0].ID)
	if _, err = localHealth(items, revisions); err == nil {
		t.Fatal("unversioned finding accepted")
	}
}

func TestHealthAuthenticatedAuditAndRollback(t *testing.T) {
	path, key, _ := revealFixture(t)
	before, err := List(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := Health(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "checked-local" || receipt.Report.Checked != 2 {
		t.Fatal("health receipt")
	}
	after, err := List(path, "fixture", key)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("health changed revisions", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := digest(receipt.Report)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.Action == healthAction {
			found = true
			if ev.ReportDigest != expected || ev.hash() != receipt.Event || ev.Session != receipt.Session {
				t.Fatal("unbound health report")
			}
		}
	}
	if !found {
		t.Fatal("no audit")
	}
	if receipt, err := Health(path, "wrong", key); err == nil || !reflect.DeepEqual(receipt, HealthReceipt{}) {
		t.Fatal("wrong factors released report")
	}
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected")
	result, err := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if e := fn(tx); e != nil {
				return e
			}
			return injected
		})
	}, "fixture", key, healthAction, vault.Item{}, nil)
	db.Close()
	if !errors.Is(err, injected) || !reflect.DeepEqual(result.health, HealthReport{}) {
		t.Fatal("rollback released report", err)
	}
}
