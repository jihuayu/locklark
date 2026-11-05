package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestInjectionJSONPermissionAuditAndNoOverwrite(t *testing.T) {
	path, key, target := revealFixture(t)
	dest := filepath.Join(t.TempDir(), "config.json")
	receipt, e := InjectJSON(path, "fixture", key, target, "TOKEN", dest)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(dest)
	if e != nil {
		t.Fatal(e)
	}
	var document map[string]string
	if json.Unmarshal(raw, &document) != nil || len(document) != 1 || document["TOKEN"] != "private-value\t\"quoted\"\n" {
		t.Fatal("value not exactly JSON encoded")
	}
	st, e := os.Stat(dest)
	if e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatal("file permissions")
	}
	if got, e := InjectJSON(path, "fixture", key, target, "TOKEN", dest); !errors.Is(e, ErrInjectionOutput) || !reflect.DeepEqual(got, InjectionReceipt{}) {
		t.Fatal("existing output overwritten", e)
	}
	after, e := os.ReadFile(dest)
	if e != nil || !bytes.Equal(raw, after) {
		t.Fatal("existing bytes changed")
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ev := range events {
		if ev.hash() == receipt.Intent {
			found = true
			if ev.Action != "item.inject.password" || ev.Result != "intent" || ev.Link != receipt.DestinationDigest || ev.BaseRevision != target.Revision {
				t.Fatal("intent not bound")
			}
		}
	}
	if !found {
		t.Fatal("intent missing")
	}
	encoded, _ := json.Marshal([]any{receipt, events})
	for _, secret := range []string{"private-value", dest, "TOKEN"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("injection exposed value/destination")
		}
	}
	entries, e := os.ReadDir(filepath.Dir(dest))
	if e != nil || len(entries) != 1 {
		t.Fatal("plaintext temporary file left behind")
	}
}

func TestInjectionRefusalsAndRollbackNeverPublish(t *testing.T) {
	path, key, target := revealFixture(t)
	dest := filepath.Join(t.TempDir(), "config.json")
	target.Revision = strings.Repeat("0", 64)
	if _, e := InjectJSON(path, "fixture", key, target, "TOKEN", dest); !errors.Is(e, ErrConflict) {
		t.Fatal("stale accepted", e)
	}
	if _, e := os.Stat(dest); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("stale wrote output")
	}
	rows, e := List(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	target.Revision = rows[0].Revision
	target.Revision, e = SetTrashed(path, "fixture", key, target.ID, target.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := InjectJSON(path, "fixture", key, target, "TOKEN", dest); !errors.Is(e, ErrTrashed) {
		t.Fatal("trash accepted", e)
	}
	if _, e := os.Stat(dest); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("trash wrote output")
	}
	target.Revision, e = SetTrashed(path, "fixture", key, target.ID, target.Revision, false)
	if e != nil {
		t.Fatal(e)
	}
	db, e := existing(path)
	if e != nil {
		t.Fatal(e)
	}
	injected := errors.New("injected commit failure")
	calls := 0
	_, e = injectJSON(target, "TOKEN", dest, func(request *injectionRequest) (result, error) {
		return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
			return db.Update(func(tx *bolt.Tx) error {
				if e := fn(tx); e != nil {
					return e
				}
				return injected
			})
		}, "fixture", key, "item.inject.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{injection: request})
	}, func([]byte, string) error { calls++; return nil })
	db.Close()
	if !errors.Is(e, injected) || calls != 0 {
		t.Fatal("rollback reached output", e)
	}
	_, e = injectJSON(target, "TOKEN", dest, func(*injectionRequest) (result, error) { return result{value: []byte("private-value")}, nil }, func([]byte, string) error { return errors.New("private-value / private-output-path") })
	if !errors.Is(e, ErrInjectionOutput) || strings.Contains(e.Error(), "private") {
		t.Fatal("writer error leaked")
	}
}
