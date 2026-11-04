package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReadOnlyOperationLeavesVaultCiphertextUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if e := Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	snapshot := func() []byte {
		db, e := existing(path)
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		var v []byte
		e = db.View(func(tx *bolt.Tx) error { v = bytes.Clone(tx.Bucket(bucket).Get(snapshotKey)); return nil })
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	before := snapshot()
	if _, e := List(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("listing rewrote the vault solely to append an audit event")
	}
}
func TestAuditAndSnapshotTampering(t *testing.T) {
	for _, kind := range []string{"missing event", "corrupt event", "old snapshot", "altered tip"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v")
			key := bytes.Repeat([]byte{9}, 16)
			if e := Create(path, "fixture", key); e != nil {
				t.Fatal(e)
			}
			change := func(fn func(*bolt.Bucket) error) {
				db, e := existing(path)
				if e != nil {
					t.Fatal(e)
				}
				e = db.Update(func(tx *bolt.Tx) error { return fn(tx.Bucket(bucket)) })
				db.Close()
				if e != nil {
					t.Fatal(e)
				}
			}
			var old []byte
			change(func(b *bolt.Bucket) error { old = bytes.Clone(b.Get(snapshotKey)); return nil })
			if _, e := AddLogin(path, "fixture", key, "sample", "owner", "login-value"); e != nil {
				t.Fatal(e)
			}
			change(func(b *bolt.Bucket) error {
				events := b.Bucket(eventsKey)
				seq, last := events.Cursor().Last()
				switch kind {
				case "missing event":
					return events.Delete(seq)
				case "old snapshot":
					return b.Put(snapshotKey, old)
				case "altered tip":
					return b.Put(tipKey, []byte("bad"))
				default:
					raw := bytes.Clone(last)
					raw[len(raw)-1] ^= 1
					return events.Put(seq, raw)
				}
			})
			if _, e := AddLogin(path, "fixture", key, "after", "", "test"); e == nil {
				t.Fatal("accepted damaged history")
			}
		})
	}
}

func TestSavedLoginDataAndSeparateJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v")
	key := bytes.Repeat([]byte{7}, 16)
	if e := Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	id, e := AddLogin(path, "fixture", key, "first", "user-example", "test-value")
	if e != nil {
		t.Fatal(e)
	}
	db, e := existing(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	e = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		var slot account.Slot
		var s vault.Snapshot
		if json.Unmarshal(b.Get(slotKey), &slot) != nil || json.Unmarshal(b.Get(snapshotKey), &s) != nil {
			return invalid
		}
		p, e := account.Unwrap("fixture", key, slot)
		if e != nil {
			return e
		}
		defer clear(p)
		var i identity
		if json.Unmarshal(p, &i) != nil {
			return invalid
		}
		defer i.clear()
		dev, e := age.ParseX25519Identity(i.Device)
		if e != nil {
			return e
		}
		priv := ed25519.NewKeyFromSeed(i.Signing)
		defer clear(priv)
		meta, items, e := vault.OpenItems(s, dev, priv.Public().(ed25519.PublicKey), 2)
		if e != nil || string(meta) != schema || len(items) != 1 || items[0].ID != id || items[0].Username != "user-example" || items[0].Password != "test-value" {
			return invalid
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestPublishDoesNotClobberConcurrentCreator(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "owner.ll")
	tmp := filepath.Join(dir, "source")
	if err := os.WriteFile(tmp, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publish(tmp, target); err == nil {
		t.Fatal("clobbered a competing creator")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "existing" {
		t.Fatal("destination changed")
	}
}
func TestPersonalVaultLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.ll")
	key := bytes.Repeat([]byte{0x27}, 16)
	pw := "synthetic owner passphrase"
	value := "only-in-the-item-fixture"
	if err := Create(path, pw, key); err != nil {
		t.Fatal(err)
	}
	rows, err := List(path, pw, key)
	if err != nil || len(rows) != 0 {
		t.Fatal("empty vault", err)
	}
	if err = Create(path, "replacement", bytes.Repeat([]byte{1}, 16)); err == nil {
		t.Fatal("replaced existing vault")
	}
	if _, err = AddLogin(path, "wrong", key, "bad", "", "bad"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err = List(path, pw, bytes.Repeat([]byte{0x28}, 16)); err == nil {
		t.Fatal("wrong Secret Key accepted")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := AddLogin(path, pw, key, "same", "local-user", value); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err = List(path, pw, key)
	if err != nil || len(rows) != 2 || rows[0].ID == rows[1].ID || rows[0].Title != "same" {
		t.Fatal("lost overlapping write", err)
	}
	events, err := Audit(path, pw, key)
	if err != nil || len(events) != 6 {
		t.Fatal("wrong event count", len(events), err)
	}
	if events[0].Action != "vault.create" || events[5].Action != "audit.list" {
		t.Fatal("incorrect event history")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range [][]byte{[]byte(value), []byte("local-user"), []byte(pw), key, []byte("AGE-SECRET-KEY-"), []byte("item.add")} {
		if bytes.Contains(raw, marker) {
			t.Fatal("credential or event visible in local database")
		}
	}
	if _, err = List(filepath.Join(t.TempDir(), "missing"), pw, key); err == nil {
		t.Fatal("opened missing database")
	}
}
