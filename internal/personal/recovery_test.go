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
	"reflect"
	"testing"
)

func TestIndependentRecovery(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "source")
	archive := filepath.Join(dir, "backup")
	next := filepath.Join(t.TempDir(), "restored")
	key := bytes.Repeat([]byte{2}, 16)
	fresh := bytes.Repeat([]byte{3}, 16)
	pw := "synthetic"
	kit, _ := NewRecovery()
	other, _ := NewRecovery()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(Create(file, pw, key))
	id, err := AddLogin(file, pw, key, "sample", "fixture-user", "synthetic-value")
	must(err)
	before := readStoredItems(t, file, pw, key)
	var old identity
	db, err := existing(file)
	must(err)
	must(db.View(func(tx *bolt.Tx) error {
		var slot account.Slot
		if err := json.Unmarshal(tx.Bucket(bucket).Get(slotKey), &slot); err != nil {
			return err
		}
		p, err := account.Unwrap(pw, key, slot)
		if err != nil {
			return err
		}
		return json.Unmarshal(p, &old)
	}))
	must(db.Close())
	must(Backup(file, archive, pw, key, kit))
	if Backup(file, archive, pw, key, other) == nil {
		t.Fatal("overwrote archive")
	}
	logged, err := Audit(file, pw, key)
	must(err)
	must(os.Rename(file, file+".unavailable"))
	raw, err := os.ReadFile(archive)
	must(err)
	if bytes.Contains(raw, []byte("synthetic-value")) || bytes.Contains(raw, []byte(kit)) {
		t.Fatal("plaintext in backup")
	}
	for _, c := range []struct {
		pw  string
		k   []byte
		rec string
	}{{"wrong", key, kit}, {pw, fresh, kit}, {pw, key, other}} {
		if Restore(archive, next, c.pw, c.k, c.rec, fresh) == nil {
			t.Fatal("wrong factors accepted")
		}
		if _, e := os.Stat(next); !os.IsNotExist(e) {
			t.Fatal("output left behind")
		}
	}
	must(Restore(archive, next, pw, key, kit, fresh))
	if Restore(archive, next, pw, key, kit, fresh) == nil {
		t.Fatal("clobbered vault")
	}
	if _, err = List(next, pw, key); err == nil {
		t.Fatal("old account factors accepted")
	}
	after := readStoredItems(t, next, pw, fresh)
	if !reflect.DeepEqual(before, after) || after[0].ID != id {
		t.Fatal("changed item")
	}
	db, err = existing(next)
	must(err)
	must(db.View(func(tx *bolt.Tx) error {
		var s vault.Snapshot
		if err := json.Unmarshal(tx.Bucket(bucket).Get(snapshotKey), &s); err != nil {
			return err
		}
		device, _ := age.ParseX25519Identity(old.Device)
		if s.Epoch != 3 || vault.VerifySnapshot(s, ed25519.NewKeyFromSeed(old.Signing).Public().(ed25519.PublicKey), s.Epoch) == nil {
			t.Fatal("restored signer or epoch")
		}
		var slot account.Slot
		json.Unmarshal(tx.Bucket(bucket).Get(slotKey), &slot)
		p, err := account.Unwrap(pw, fresh, slot)
		if err != nil {
			return err
		}
		var i identity
		json.Unmarshal(p, &i)
		if bytes.Equal(old.Audit, i.Audit) || bytes.Equal(old.AuditEncryption, i.AuditEncryption) {
			t.Fatal("cloned audit authority")
		}
		if _, _, err = vault.OpenItems(s, device, ed25519.NewKeyFromSeed(i.Signing).Public().(ed25519.PublicKey), s.Epoch); err == nil {
			t.Fatal("old device opened new snapshot")
		}
		return nil
	}))
	must(db.Close())
	history, err := ArchivedAudit(next, pw, fresh)
	must(err)
	if len(history) != 1 || !reflect.DeepEqual(history[0].Events, logged[:len(logged)-1]) || history[0].Events[len(history[0].Events)-1].Action != "backup.prepare" {
		t.Fatal("source signatures not preserved")
	}
	second := archive + ".2"
	must(Backup(next, second, pw, fresh, other))
	twice := next + ".2"
	must(Restore(second, twice, pw, fresh, other, key))
	chains, err := ArchivedAudit(twice, pw, key)
	must(err)
	if len(chains) != 2 || !reflect.DeepEqual(chains[0], history[0]) {
		t.Fatal("dropped earlier history")
	}
	var env envelope
	must(json.Unmarshal(raw, &env))
	env.Data[len(env.Data)-1] ^= 1
	bad, _ := json.Marshal(env)
	must(os.WriteFile(archive+".bad", bad, 0600))
	if Restore(archive+".bad", next+".bad", pw, key, kit, fresh) == nil {
		t.Fatal("accepted corrupt archive")
	}
}
