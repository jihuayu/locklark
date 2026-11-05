package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestTrashBlocksEveryUsePath(t *testing.T) {
	path, key, target := revealFixture(t)
	rev, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "url", Value: "https://example.com/login"})
	if err != nil {
		t.Fatal(err)
	}
	rev, err = EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: rev, Field: "otp", Value: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})
	if err != nil {
		t.Fatal(err)
	}
	index, err := References(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	rev, err = SetTrashed(path, "fixture", key, target.ID, rev, true)
	if err != nil {
		t.Fatal(err)
	}
	before := readStoredItems(t, path, "fixture", key)
	for _, field := range []string{"title", "username", "password", "otp", "url"} {
		value := "blocked-replacement"
		if field == "otp" {
			value = ""
		}
		if field == "url" {
			value = "https://example.com/changed"
		}
		if _, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: rev, Field: field, Value: value}); !errors.Is(err, ErrTrashed) {
			t.Fatal("trashed edit", field, err)
		}
	}
	for _, archived := range []bool{false, true} {
		if _, err := SetArchived(path, "fixture", key, target.ID, rev, archived); !errors.Is(err, ErrTrashed) {
			t.Fatal("archive bypass", err)
		}
	}
	called := false
	opt, err := generationOption(24)
	if err != nil {
		t.Fatal(err)
	}
	opt.generation.generate = func(password.Policy) (password.Secret, error) {
		called = true
		return password.Secret{}, errors.New("must not generate")
	}
	if r, err := command(path, "fixture", key, "item.regenerate.password", vault.Item{}, &Edit{ID: target.ID, Revision: rev}, opt); !errors.Is(err, ErrTrashed) || called || r.revision != "" {
		t.Fatal("generated for trashed item", err)
	}
	var out bytes.Buffer
	for _, field := range []string{"username", "password"} {
		target.Revision = rev
		target.Field = field
		if _, err := RevealLogin(path, "fixture", key, target, &out); !errors.Is(err, ErrTrashed) {
			t.Fatal("direct reveal", err)
		}
	}
	if _, err := RevealOTP(path, "fixture", key, target.ID, rev, &out); !errors.Is(err, ErrTrashed) {
		t.Fatal("OTP reveal", err)
	}
	if _, err := RevealReference(path, "fixture", key, index.Items[0].References["password"], rev, &out); !errors.Is(err, ErrTrashed) {
		t.Fatal("reference reveal", err)
	}
	if _, err := RevealOTPReference(path, "fixture", key, index.Items[0].References["otp"], rev, &out); !errors.Is(err, ErrTrashed) {
		t.Fatal("OTP reference", err)
	}
	if _, err := RevealReference(path, "fixture", key, "op://"+index.VaultID+"/same/password", rev, &out); !errors.Is(err, reference.ErrAmbiguous) {
		t.Fatal("trash removed name ambiguity", err)
	}
	if out.Len() != 0 {
		t.Fatal("trashed output")
	}
	if rows, err := List(path, "fixture", key); err != nil || len(rows) != 1 {
		t.Fatal("default discovery", err)
	}
	if rows, err := ListState(path, "fixture", key, "all"); err != nil || len(rows) != 2 || rows[0].RestoreState != "active" {
		t.Fatal("all metadata", err)
	}
	if index, err := References(path, "fixture", key); err != nil || len(index.Items) != 1 {
		t.Fatal("trash recommended", err)
	}
	if rows, err := MatchLogins(path, "fixture", key, "https://example.com", "https://example.com"); err != nil || len(rows) != 0 {
		t.Fatal("trash website candidate", err)
	}
	if !reflect.DeepEqual(before, readStoredItems(t, path, "fixture", key)) {
		t.Fatal("refusal changed items")
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	blocked := 0
	for _, e := range events {
		if e.Result == "trashed" {
			blocked++
			if e.Item != target.ID || e.BaseRevision != rev {
				t.Fatal("refusal not revision-bound")
			}
		}
	}
	if blocked != 13 {
		t.Fatal("missing refusal audit", blocked)
	}
	raw, _ := json.Marshal(events)
	for _, value := range []string{"blocked-replacement", "private-value", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "example.com"} {
		if bytes.Contains(raw, []byte(value)) {
			t.Fatal("audit leaked field")
		}
	}
}

func TestTrashConcurrentAndRollback(t *testing.T) {
	path, key, target := revealFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := SetTrashed(path, "fixture", key, target.ID, target.Revision, true)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent trash", success, conflict)
	}
	for _, action := range []string{"item.untrash", "item.trash"} {
		rows, err := ListState(path, "fixture", key, "all")
		if err != nil {
			t.Fatal(err)
		}
		if action == "item.trash" {
			if _, err := SetTrashed(path, "fixture", key, target.ID, rows[0].Revision, false); err != nil {
				t.Fatal(err)
			}
			rows, err = ListState(path, "fixture", key, "all")
			if err != nil {
				t.Fatal(err)
			}
		}
		before := readStoredItems(t, path, "fixture", key)
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
		}, "fixture", key, action, vault.Item{}, &Edit{ID: target.ID, Revision: rows[0].Revision})
		db.Close()
		if !errors.Is(err, fault) || r.revision != "" {
			t.Fatal("rollback result", err)
		}
		if !reflect.DeepEqual(before, readStoredItems(t, path, "fixture", key)) {
			t.Fatal("rollback changed state")
		}
	}
}

func TestTrashBackupRecovery(t *testing.T) {
	path, key, target := revealFixture(t)
	rev, err := SetArchived(path, "fixture", key, target.ID, target.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	rev, err = SetTrashed(path, "fixture", key, target.ID, rev, true)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "backup.llb")
	kit, err := Backup(path, archive, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored.ll")
	fresh := bytes.Repeat([]byte{9}, 16)
	if err = Restore(archive, dest, "fixture", key, kit, fresh); err != nil {
		t.Fatal(err)
	}
	rows, err := ListState(dest, "fixture", fresh, "trashed")
	if err != nil || len(rows) != 1 || rows[0].Revision == rev || rows[0].RestoreState != "archived" {
		t.Fatal("trash backup recovery", err)
	}
	if _, err := SetTrashed(dest, "fixture", fresh, target.ID, rows[0].Revision, false); err != nil {
		t.Fatal(err)
	}
	if rows, err = ListState(dest, "fixture", fresh, "archived"); err != nil || len(rows) != 1 {
		t.Fatal("recovered archive state", err)
	}
}

func TestTrashAndRevisionPrecedeInvalidValues(t *testing.T) {
	path, key, target := revealFixture(t)
	rev, err := SetTrashed(path, "fixture", key, target.ID, target.Revision, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{target.Revision, rev} {
		want := ErrTrashed
		if r == target.Revision {
			want = ErrConflict
		}
		for _, edit := range []Edit{{Field: "title", Value: ""}, {Field: "password", Value: ""}, {Field: "otp", Value: "invalid-otp"}, {Field: "url", Value: "not a URL"}} {
			edit.ID, edit.Revision = target.ID, r
			if _, err := EditLogin(path, "fixture", key, edit); !errors.Is(err, want) {
				t.Fatal("validation precedes target checks", edit.Field, err)
			}
		}
		if _, err := RegeneratePassword(path, "fixture", key, target.ID, r, 0); !errors.Is(err, want) {
			t.Fatal("policy precedes target checks", err)
		}
	}
	opt := commandOption{generation: &generationRequest{policy: password.Policy{Length: 0, Alphabet: password.DefaultAlphabet}, generate: func(password.Policy) (password.Secret, error) {
		t.Fatal("invalid policy consumed entropy")
		return password.Secret{}, nil
	}}}
	if _, err := command(path, "fixture", key, "item.regenerate.password", vault.Item{}, &Edit{ID: target.ID, Revision: rev}, opt); !errors.Is(err, ErrTrashed) {
		t.Fatal(err)
	}
	rev, err = SetTrashed(path, "fixture", key, target.ID, rev, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command(path, "fixture", key, "item.regenerate.password", vault.Item{}, &Edit{ID: target.ID, Revision: rev}, opt); !errors.Is(err, password.ErrInvalid) {
		t.Fatal("active invalid policy", err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Result]++
	}
	if counts["conflict"] != 5 || counts["trashed"] != 6 {
		t.Fatal("validation order not audited", counts)
	}
}
