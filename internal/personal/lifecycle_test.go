package personal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	"sync"
	"testing"
)

func TestArchiveLifecycle(t *testing.T) {
	path, key, target := revealFixture(t)
	old := target.Revision
	revision, err := SetArchived(path, "fixture", key, target.ID, old, true)
	if err != nil || revision == old {
		t.Fatal("archive", err)
	}
	if rows, err := List(path, "fixture", key); err != nil || len(rows) != 1 {
		t.Fatal("active list", err)
	}
	rows, err := ListState(path, "fixture", key, "archived")
	if err != nil || len(rows) != 1 || rows[0].State != "archived" || rows[0].Revision != revision {
		t.Fatal("archived list", err)
	}
	if index, err := References(path, "fixture", key); err != nil || len(index.Items) != 1 {
		t.Fatal("archived suggested", err)
	}
	if _, err = SetArchived(path, "fixture", key, target.ID, revision, true); !errors.Is(err, ErrAlreadyArchived) {
		t.Fatal("repeat archive", err)
	}
	if _, err = SetArchived(path, "fixture", key, target.ID, old, false); !errors.Is(err, ErrConflict) {
		t.Fatal("stale unarchive", err)
	}
	var value bytes.Buffer
	target.Revision = revision
	if _, err := RevealLogin(path, "fixture", key, target, &value); err != nil {
		t.Fatal("explicit archived read", err)
	}
	kitPath := filepath.Join(t.TempDir(), "backup.llb")
	kit, err := Backup(path, kitPath, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.ll")
	fresh := bytes.Repeat([]byte{9}, 16)
	if err = Restore(kitPath, restored, "fixture", key, kit, fresh); err != nil {
		t.Fatal(err)
	}
	recovered, err := ListState(restored, "fixture", fresh, "archived")
	if err != nil || len(recovered) != 1 || recovered[0].Revision == revision {
		t.Fatal("recovery", err)
	}
	revision, err = SetArchived(path, "fixture", key, target.ID, revision, false)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err = List(path, "fixture", key); err != nil || len(rows) != 2 || rows[0].State != "active" || rows[0].Revision != revision {
		t.Fatal("unarchive", err)
	}
	if _, err = SetArchived(path, "fixture", key, target.ID, revision, false); !errors.Is(err, ErrAlreadyActive) {
		t.Fatal("repeat unarchive", err)
	}
	if _, err = ListState(path, "fixture", key, "invalid"); err == nil {
		t.Fatal("unknown filter")
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range events {
		if lifecycleAction(e.Action) {
			counts[e.Result]++
		}
	}
	if counts["succeeded"] != 2 || counts["conflict"] != 1 || counts["already-archived"] != 1 || counts["already-active"] != 1 {
		t.Fatal("lifecycle outcomes", counts)
	}
}

func TestArchiveConcurrentAndAmbiguousReferences(t *testing.T) {
	path, key, target := revealFixture(t)
	rows, err := List(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := SetArchived(path, "fixture", key, target.ID, target.Revision, true)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("archive CAS", success, conflict)
	}
	index, err := References(path, "fixture", key)
	if err != nil || len(index.Items) != 1 {
		t.Fatal("active suggestions", err)
	}
	_, err = RevealReference(path, "fixture", key, "op://"+index.VaultID+"/"+rows[0].Title+"/password", target.Revision, &bytes.Buffer{})
	if !errors.Is(err, reference.ErrAmbiguous) {
		t.Fatal("archived identity removed from ambiguity checks", err)
	}
}

func TestArchiveRollbackAndEventSchema(t *testing.T) {
	path, key, target := revealFixture(t)
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected commit failure")
	r, err := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return fault
		})
	}, "fixture", key, "item.archive", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision})
	db.Close()
	if !errors.Is(err, fault) || r.revision != "" {
		t.Fatal("rollback released revision", err)
	}
	rows, err := List(path, "fixture", key)
	if err != nil || len(rows) != 2 || rows[0].Revision != target.Revision {
		t.Fatal("rollback changed state", err)
	}
	if _, err = SetArchived(path, "fixture", key, target.ID, target.Revision, true); err != nil {
		t.Fatal(err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	for _, e := range events {
		if e.Action == "item.archive" {
			event = e
		}
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	pub := priv.Public().(ed25519.PublicKey)
	for _, result := range []string{"succeeded", "already-archived", "already-active", "intent"} {
		e := event
		e.Result = result
		e.Signature = ed25519.Sign(priv, e.proof())
		err = e.verify(pub, e.Sequence, e.Previous)
		if (err == nil) != (result == "succeeded" || result == "already-archived") {
			t.Fatal("lifecycle schema result", result, err)
		}
	}
}
