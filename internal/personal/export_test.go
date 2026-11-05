package personal

import (
	"bytes"
	"errors"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"testing"
)

func TestKDBXExportIntentBeforePublish(t *testing.T) {
	path, key, _ := revealFixture(t)
	dest := filepath.Join(t.TempDir(), "export.kdbx")
	r, err := exportKDBX(path, "fixture", key, "synthetic-export-password", dest, func(raw []byte, dest string) error {
		events, err := Audit(path, "fixture", key)
		if err != nil {
			t.Fatal(err)
		}
		e := events[len(events)-2]
		if e.Action != exportAction || e.Result != "intent" {
			t.Fatal("export before intent")
		}
		return publishExport(raw, dest)
	})
	if err != nil || r.Status != "exported-encrypted" || !digestOK(r.Intent) {
		t.Fatal("export failed", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil || len(raw) == 0 || bytes.Contains(raw, []byte("private-value")) {
		t.Fatal("invalid encrypted file", err)
	}
	if _, err := ExportKDBX(path, "fixture", key, "synthetic-export-password", dest); err == nil {
		t.Fatal("existing output overwritten")
	}
	after, _ := os.ReadFile(dest)
	if !bytes.Equal(raw, after) {
		t.Fatal("existing file changed")
	}
	bad := filepath.Join(t.TempDir(), "never.kdbx")
	if _, err := ExportKDBX(path, "wrong", key, "synthetic-export-password", bad); err == nil {
		t.Fatal("wrong factors accepted")
	}
	if _, err := os.Stat(bad); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong factors left output")
	}
	if _, err := exportKDBX(path, "fixture", key, "synthetic-export-password", bad, func([]byte, string) error { return errors.New("private-writer-error") }); !errors.Is(err, ErrExportOutput) {
		t.Fatal("publisher error leaked", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == exportAction {
			n++
		}
	}
	if n != 2 {
		t.Fatal("failed publication lost intent or bad factors added one", n)
	}
}

func TestKDBXExportRollbackAndRecovery(t *testing.T) {
	path, key, _ := revealFixture(t)
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("commit failed")
	r, err := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return fault
		})
	}, "fixture", key, exportAction, vault.Item{}, nil, commandOption{export: &exportRequest{password: "synthetic-export-password"}})
	db.Close()
	if !errors.Is(err, fault) || r.archive != nil || r.intent != "" {
		t.Fatal("rollback released encrypted export", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == exportAction {
			t.Fatal("rollback retained intent")
		}
	}
	receipt, err := ExportKDBX(path, "fixture", key, "synthetic-export-password", filepath.Join(t.TempDir(), "out.kdbx"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := PrepareBackup(path, filepath.Join(t.TempDir(), "backup.llb"), "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	kit := b.Material()
	if err = b.Publish(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored.ll")
	rec, err := PrepareRestore(b.dest, dest, "fixture", key, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	fresh := bytes.Repeat([]byte{7}, 16)
	if err = rec.Publish(fresh); err != nil {
		t.Fatal(err)
	}
	chains, err := ArchivedAudit(dest, "fixture", fresh)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range chains {
		for _, e := range c.Events {
			if e.hash() == receipt.Intent {
				found++
			}
		}
	}
	if found != 1 {
		t.Fatal("recovery lost export intent")
	}
}
