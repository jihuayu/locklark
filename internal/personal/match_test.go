package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	"testing"
)

func TestMatchLogins(t *testing.T) {
	path, key, target := revealFixture(t)
	revision, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "url", Value: "https://EXAMPLE.com:443/login"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := MatchLogins(path, "fixture", key, "https://example.com", "https://EXAMPLE.com:443/")
	if err != nil || len(rows) != 1 || rows[0].ID != target.ID || rows[0].Revision != revision {
		t.Fatal("match", err)
	}
	for _, site := range []string{"https://example.com.evil.test", "https://sub.example.com", "https://example.com:8443", "https://example.net"} {
		rows, err := MatchLogins(path, "fixture", key, site, site)
		if err != nil || len(rows) != 0 {
			t.Fatal("nonexact match", site, err)
		}
	}
	if rows, err := MatchLogins(path, "fixture", key, "https://example.com", "https://evil.test"); !errors.Is(err, ErrCrossOrigin) || rows != nil {
		t.Fatal("cross origin", err)
	}
	if rows, err := MatchLogins(path, "wrong", key, "https://example.com", "https://example.com"); err == nil || rows != nil {
		t.Fatal("wrong factors", err)
	}
	if _, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: revision, Field: "url", Value: "https://example.com?secret=hidden"}); err == nil {
		t.Fatal("unsafe URL")
	}
	archive := filepath.Join(t.TempDir(), "backup.llb")
	kit, err := Backup(path, archive, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored.ll")
	fresh := bytes.Repeat([]byte{8}, 16)
	if err = Restore(archive, dest, "fixture", key, kit, fresh); err != nil {
		t.Fatal(err)
	}
	if rows, err := MatchLogins(dest, "fixture", fresh, "https://example.com", "https://example.com"); err != nil || len(rows) != 1 || rows[0].Revision == revision {
		t.Fatal("URL recovery", err)
	}
	if _, err := SetArchived(path, "fixture", key, target.ID, revision, true); err != nil {
		t.Fatal(err)
	}
	if rows, err := MatchLogins(path, "fixture", key, "https://example.com", "https://example.com"); err != nil || len(rows) != 0 {
		t.Fatal("archived match", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, ev := range events {
		if ev.Action == matchAction {
			counts[ev.Result]++
			if ev.Item != "" || ev.BaseRevision != "" {
				t.Fatal("match target journaled")
			}
		}
	}
	if counts["succeeded"] != 6 || counts["cross-origin"] != 1 {
		t.Fatal("match audit", counts)
	}
	raw, _ := json.Marshal(events)
	for _, secret := range []string{"example.com", "evil.test", "private-value", "hidden"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("audit data leak")
		}
	}
	if items := readStoredItems(t, path, "fixture", key); items[0].URL != "https://EXAMPLE.com:443/login" {
		t.Fatal("URL lost")
	}
}

func TestMatchRollback(t *testing.T) {
	path, key, target := revealFixture(t)
	if _, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "url", Value: "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("commit failure")
	r, err := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return fault
		})
	}, "fixture", key, matchAction, vault.Item{}, nil, commandOption{match: &matchRequest{"https://example.com", "https://example.com"}})
	db.Close()
	if !errors.Is(err, fault) || r.rows != nil {
		t.Fatal("uncommitted candidates released", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == matchAction {
			t.Fatal("rolled-back match event retained")
		}
	}
}
