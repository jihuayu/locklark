package personal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestTrashRestoresPriorState(t *testing.T) {
	for _, archived := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "archived"}[archived], func(t *testing.T) {
			path, key, target := revealFixture(t)
			rev := target.Revision
			var err error
			if archived {
				rev, err = SetArchived(path, "fixture", key, target.ID, rev, true)
				if err != nil {
					t.Fatal(err)
				}
			}
			trashed, err := SetTrashed(path, "fixture", key, target.ID, rev, true)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := ListState(path, "fixture", key, "trashed")
			if err != nil || len(rows) != 1 || rows[0].State != "trashed" || rows[0].Revision != trashed {
				t.Fatal("trash list", err)
			}
			stored := readStoredItems(t, path, "fixture", key)
			if stored[0].State != "trashed" || (stored[0].PreviousState == "archived") != archived {
				t.Fatal("previous state lost")
			}
			if _, err := SetTrashed(path, "fixture", key, target.ID, trashed, true); !errors.Is(err, ErrAlreadyTrashed) {
				t.Fatal("repeat trash", err)
			}
			target.Revision = trashed
			var output bytes.Buffer
			if _, err := RevealLogin(path, "fixture", key, target, &output); !errors.Is(err, ErrTrashed) || output.Len() != 0 {
				t.Fatal("trashed value released", err)
			}
			if _, err := SetTrashed(path, "fixture", key, target.ID, rev, false); !errors.Is(err, ErrConflict) {
				t.Fatal("stale restore", err)
			}
			restored, err := SetTrashed(path, "fixture", key, target.ID, trashed, false)
			if err != nil || restored == trashed {
				t.Fatal("restore", err)
			}
			stored = readStoredItems(t, path, "fixture", key)
			if stored[0].PreviousState != "" || (stored[0].State == "archived") != archived {
				t.Fatal("wrong restored state")
			}
			if _, err := SetTrashed(path, "fixture", key, target.ID, restored, false); !errors.Is(err, ErrNotTrashed) {
				t.Fatal("repeat restore", err)
			}
			if _, err := Audit(path, "fixture", key); err != nil {
				t.Fatal("invalid audit", err)
			}
		})
	}
}

func TestTrashEventSchema(t *testing.T) {
	path, key, target := revealFixture(t)
	if _, err := SetTrashed(path, "fixture", key, target.ID, target.Revision, true); err != nil {
		t.Fatal(err)
	}
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	var source Event
	for _, e := range events {
		if e.Action == "item.trash" {
			source = e
		}
	}
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	defer clear(signer)
	for _, test := range []struct {
		action, result string
		valid          bool
	}{
		{"item.trash", "already-trashed", true}, {"item.trash", "not-trashed", false}, {"item.trash", "trashed", false},
		{"item.untrash", "not-trashed", true}, {"item.untrash", "already-trashed", false},
		{"item.edit.password", "trashed", true}, {"item.edit.password", "already-trashed", false}, {"item.reveal.password", "trashed", true},
	} {
		e := source
		e.Action, e.Result = test.action, test.result
		e.Signature = ed25519.Sign(signer, e.proof())
		if (e.verify(signer.Public().(ed25519.PublicKey), e.Sequence, e.Previous) == nil) != test.valid {
			t.Fatal("trash event schema", test)
		}
	}
}
