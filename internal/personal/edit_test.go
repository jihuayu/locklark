package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestEditTargetsObservedItem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ll")
	pw := "synthetic"
	key := bytes.Repeat([]byte{3}, 16)
	if e := Create(path, pw, key); e != nil {
		t.Fatal(e)
	}
	a, e := AddLogin(path, pw, key, "same", "one", "original-a")
	if e != nil {
		t.Fatal(e)
	}
	b, e := AddLogin(path, pw, key, "same", "two", "original-b")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := List(path, pw, key)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 2 || rows[0].Revision == rows[1].Revision || len(rows[0].Revision) != 64 {
		t.Fatal("no independent revisions")
	}
	first := Edit{ID: a, Revision: rows[0].Revision, Field: "password", Value: "sample-new-secret"}
	second := Edit{ID: b, Revision: rows[1].Revision, Field: "title", Value: "renamed"}
	if _, e = EditLogin(path, pw, key, second); e != nil {
		t.Fatal(e)
	}
	type attempt struct {
		value, revision string
		err             error
	}
	res := make(chan attempt, 2)
	var wg sync.WaitGroup
	for _, value := range []string{"sample-new-secret", "different-secret"} {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			p := first
			p.Value = v
			revision, err := EditLogin(path, pw, key, p)
			res <- attempt{v, revision, err}
		}(value)
	}
	wg.Wait()
	close(res)
	ok, conflict := 0, 0
	var winner attempt
	for a := range res {
		err := a.err
		switch {
		case err == nil:
			winner = a
			ok++
		case errors.Is(err, ErrConflict):
			conflict++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal("both writes won or both failed")
	}
	rows, e = List(path, pw, key)
	if e != nil || rows[0].Title != "same" || rows[1].Title != "renamed" || rows[0].Revision != winner.revision || rows[0].Revision == first.Revision {
		t.Fatal("wrong row changed", e)
	}
	saved := readStoredItems(t, path, pw, key)
	if len(saved) != 2 || saved[0].ID != a || saved[0].Username != "one" || saved[0].Password != winner.value || saved[1].ID != b || saved[1].Username != "two" || saved[1].Password != "original-b" {
		t.Fatal("field edit corrupted stored login")
	}
	if _, e := EditLogin(path, pw, key, Edit{ID: a, Revision: winner.revision, Field: "username", Value: ""}); e != nil {
		t.Fatal(e)
	}
	saved = readStoredItems(t, path, pw, key)
	if saved[0].Username != "" || saved[0].Password != winner.value || saved[1].Username != "two" {
		t.Fatal("username clear affected other fields")
	}
	unknown := first
	unknown.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, e = EditLogin(path, pw, key, unknown); !errors.Is(e, ErrNotFound) {
		t.Fatal("missing target", e)
	}
	ev, e := Audit(path, pw, key)
	if e != nil {
		t.Fatal(e)
	}
	counts := map[string]int{}
	for _, v := range ev {
		if v.Action == "item.edit.password" {
			counts[v.Result]++
			switch v.Result {
			case "succeeded":
				if v.Item != a || v.BaseRevision != first.Revision || v.hash() != winner.revision {
					t.Fatal("successful revision did not bind its observed base")
				}
			case "conflict":
				if v.Item != a || v.BaseRevision != winner.revision {
					t.Fatal("conflict did not bind actual current revision")
				}
			case "not-found":
				if v.Item != "" || v.BaseRevision != "" {
					t.Fatal("recorded an unverified target")
				}
			}
		}
	}
	if counts["succeeded"] != 1 || counts["conflict"] != 1 || counts["not-found"] != 1 {
		t.Fatal("incorrect edit outcomes", counts)
	}
	out, _ := json.Marshal(ev)
	for _, v := range []string{"original-a", "sample-new-secret", "different-secret", "renamed", unknown.ID} {
		if bytes.Contains(out, []byte(v)) {
			t.Fatal("audit leaked data")
		}
	}
}
