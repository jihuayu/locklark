package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

type disclosureWriter func([]byte) (int, error)

func (f disclosureWriter) Write(p []byte) (int, error) { return f(p) }

func revealFixture(t *testing.T) (string, []byte, RevealTarget) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owner.ll")
	key := bytes.Repeat([]byte{4}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	if _, err := AddLogin(path, "fixture", key, "same", "fixture-user", "private-value\t\"quoted\"\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := AddLogin(path, "fixture", key, "same", "other-user", "other-password"); err != nil {
		t.Fatal(err)
	}
	rows, err := List(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	return path, key, RevealTarget{ID: rows[0].ID, Revision: rows[0].Revision, Field: "password"}
}

func TestRevealRollbackNeverWrites(t *testing.T) {
	path, key, target := revealFixture(t)
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected commit failure")
	var output bytes.Buffer
	_, err = revealLogin(target, &output, func() (result, error) {
		return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
			return db.Update(func(tx *bolt.Tx) error {
				if err := fn(tx); err != nil {
					return err
				}
				// The complete intended append exists inside the transaction, but
				// publication fails. Roll back instead of committing any of it.
				return injected
			})
		}, "fixture", key, "item.reveal.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field})
	})
	db.Close()
	if !errors.Is(err, injected) || output.Len() != 0 {
		t.Fatal("failed transaction disclosed", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if revealAction(ev.Action) {
			t.Fatal("rollback left intent")
		}
	}
}

func TestRevealCorruptJournalNeverWrites(t *testing.T) {
	path, key, target := revealFixture(t)
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucket).Put(tipKey, []byte("corrupt")) })
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err = RevealLogin(path, "fixture", key, target, &out); err == nil || out.Len() != 0 {
		t.Fatal("damaged journal disclosed")
	}
}

func TestRevealEscapesUnicodeControls(t *testing.T) {
	path, key, target := revealFixture(t)
	value := "可见😀\u0085\u009b\u200b\u202e\u2066\U000e0001tail"
	revision, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "password", Value: value})
	if err != nil {
		t.Fatal(err)
	}
	target.Revision = revision
	var output bytes.Buffer
	if _, err = RevealLogin(path, "fixture", key, target, &output); err != nil {
		t.Fatal(err)
	}
	var decoded string
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &decoded) != nil || decoded != value {
		t.Fatal("quoting changed the field value")
	}
	for _, control := range []string{"\u0085", "\u009b", "\u200b", "\u202e", "\u2066", "\U000e0001"} {
		if strings.Contains(output.String(), control) {
			t.Fatal("Unicode control reached terminal unescaped")
		}
	}
	if !strings.Contains(output.String(), "可见😀") {
		t.Fatal("ordinary Unicode unnecessarily changed")
	}
}

func TestRevealConcurrentEditAndRecovery(t *testing.T) {
	path, key, target := revealFixture(t)
	var output bytes.Buffer
	var readErr, editErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, readErr = RevealLogin(path, "fixture", key, target, &output) }()
	go func() {
		defer wg.Done()
		_, editErr = EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "password", Value: "replacement-private"})
	}()
	wg.Wait()
	if editErr != nil {
		t.Fatal(editErr)
	}
	if readErr == nil {
		var value string
		if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &value) != nil || value != "private-value\t\"quoted\"\n" {
			t.Fatal("disclosed a different revision")
		}
	} else if !errors.Is(readErr, ErrConflict) || output.Len() != 0 {
		t.Fatal("unexpected race result", readErr)
	}
	output.Reset()
	if _, err := RevealLogin(path, "fixture", key, target, &output); !errors.Is(err, ErrConflict) || output.Len() != 0 {
		t.Fatal("stale target disclosed", err)
	}
	rows, err := List(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	target.Revision = rows[0].Revision
	target.Field = "username"
	if _, err = RevealLogin(path, "fixture", key, target, &output); err != nil || output.String() != "\"fixture-user\"\r\n" {
		t.Fatal("username not disclosed", err)
	}
	archive := filepath.Join(t.TempDir(), "backup.llb")
	backup, err := PrepareBackup(path, archive, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	kit := backup.Material()
	if err = backup.Publish(); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.ll")
	recovery, err := PrepareRestore(archive, restored, "fixture", key, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	fresh := bytes.Repeat([]byte{6}, 16)
	if err = recovery.Publish(fresh); err != nil {
		t.Fatal(err)
	}
	chains, err := ArchivedAudit(restored, "fixture", fresh)
	if err != nil {
		t.Fatal("disclosure chain cannot recover", err)
	}
	intents := 0
	for _, chain := range chains {
		for _, event := range chain.Events {
			if event.Action == "item.reveal.username" && event.Result == "intent" && event.Item == target.ID && event.BaseRevision == target.Revision {
				intents++
			}
		}
	}
	if intents != 1 {
		t.Fatal("recovery lost or duplicated disclosure intent")
	}
	output.Reset()
	if _, err = RevealLogin(restored, "fixture", fresh, target, &output); !errors.Is(err, ErrConflict) || output.Len() != 0 {
		t.Fatal("recovery accepted old revision", err)
	}
	rows, err = List(restored, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	target.Revision = rows[0].Revision
	target.Field = "password"
	if _, err = RevealLogin(restored, "fixture", fresh, target, &output); err != nil || output.String() != "\"replacement-private\"\r\n" {
		t.Fatal("recovered value mismatch", err)
	}
}

func TestRevealIntentCommittedBeforeOutput(t *testing.T) {
	path, key, target := revealFixture(t)
	var output bytes.Buffer
	var intent Event
	w := disclosureWriter(func(p []byte) (int, error) {
		// Opening a second transaction here also proves the writer is not called
		// while the preparation transaction/file lock is still held.
		events, err := Audit(path, "fixture", key)
		if err != nil {
			t.Fatal(err)
		}
		intent = events[len(events)-2]
		if intent.Action != "item.reveal.password" || intent.Result != "intent" || intent.Item != target.ID || intent.BaseRevision != target.Revision {
			t.Fatal("missing durable intent")
		}
		return output.Write(p)
	})
	receipt, err := RevealLogin(path, "fixture", key, target, w)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Session != intent.Session || receipt.Intent != intent.hash() || receipt.Status != "written-to-terminal" {
		t.Fatal("receipt does not identify intent")
	}
	var decoded string
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &decoded) != nil || decoded != "private-value\t\"quoted\"\n" || bytes.Contains(output.Bytes(), []byte{27}) {
		t.Fatal("field not safely quoted")
	}
	rows, err := List(path, "fixture", key)
	if err != nil || rows[0].Revision != target.Revision {
		t.Fatal("disclosure changed item revision", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]any{receipt, events})
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-value", "fixture-user", "other-password"} {
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(disk, []byte(secret)) {
			t.Fatal("secret outside explicit output")
		}
	}
}

func TestRevealRefusalsAndOutputFailure(t *testing.T) {
	path, key, target := revealFixture(t)
	var out bytes.Buffer
	for _, wrong := range []struct {
		pw  string
		key []byte
	}{{"wrong", key}, {"fixture", bytes.Repeat([]byte{8}, 16)}} {
		if _, err := RevealLogin(path, wrong.pw, wrong.key, target, &out); err == nil || out.Len() != 0 {
			t.Fatal("wrong factors disclosed")
		}
	}
	unknown := target
	unknown.ID = strings.Repeat("a", 32)
	if _, err := RevealLogin(path, "fixture", key, unknown, &out); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	stale := target
	stale.Revision = strings.Repeat("0", 64)
	if _, err := RevealLogin(path, "fixture", key, stale, &out); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	bad := target
	bad.Field = "otp"
	if _, err := RevealLogin(path, "fixture", key, bad, &out); err == nil {
		t.Fatal("unsupported field accepted")
	}
	if out.Len() != 0 {
		t.Fatal("rejection disclosed")
	}
	for _, w := range []io.Writer{
		disclosureWriter(func(p []byte) (int, error) { return 0, errors.New("private-value") }),
		disclosureWriter(func(p []byte) (int, error) { return len(p) - 1, nil }),
	} {
		r, err := RevealLogin(path, "fixture", key, target, w)
		if !errors.Is(err, ErrDisclosureOutput) || strings.Contains(err.Error(), "private-value") || r != (DisclosureReceipt{}) {
			t.Fatal("output failure claimed success or leaked")
		}
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, e := range events {
		if e.Action == "item.reveal.password" {
			outcomes = append(outcomes, e.Result)
		}
	}
	if strings.Join(outcomes, ",") != "not-found,conflict,intent,intent" {
		t.Fatal("incorrect disclosure audit", outcomes)
	}
}
