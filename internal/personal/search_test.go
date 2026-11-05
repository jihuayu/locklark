package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

func TestTitleSearchProfileUnicodeVersion(t *testing.T) {
	// Updating the tables changes matching/input semantics: revise the profile
	// and its compatibility documentation instead of silently changing v1.
	if cases.UnicodeVersion != "15.0.0" || norm.Version != "15.0.0" || unicode.Version != "15.0.0" {
		t.Fatal("search profile v1 requires Unicode 15.0.0 tables")
	}
}

func TestTitleSearchUnicodeScopeAndJSON(t *testing.T) {
	items := []vault.Item{
		{ID: fmt.Sprintf("%032x", 1), Kind: "login", Title: "Straße Café 中文"},
		{ID: fmt.Sprintf("%032x", 2), Kind: "login", Title: "Straße Café 中文"},
		{ID: fmt.Sprintf("%032x", 3), Kind: "login", Title: "Straße archived", State: "archived"},
		{ID: fmt.Sprintf("%032x", 4), Kind: "login", Title: "Straße trash", State: "trashed", PreviousState: "archived"},
		{ID: fmt.Sprintf("%032x", 5), Kind: "login", Title: "safe\u202e中文\u0085", Password: "only-in-password", Username: "only-in-username", OTP: "only-in-otp", URL: "https://only-in-url.example", ImportSource: []byte("only-in-source")},
	}
	revs := map[string]string{}
	for _, it := range items {
		revs[it.ID] = strings.Repeat("a", 64)
	}
	for _, test := range []struct {
		query, state string
		count        int
	}{{"STRASSE", "active", 2}, {"Cafe\u0301", "active", 2}, {"中文", "active", 3}, {"STRASSE", "archived", 1}, {"STRASSE", "trashed", 1}, {"STRASSE", "all", 4}, {" STRASSE ", "all", 0}, {"only-in", "all", 0}} {
		rows, e := searchRows(items, revs, searchRequest{test.query, test.state})
		if e != nil || len(rows) != test.count {
			t.Fatal(test, e, len(rows))
		}
		if test.state == "trashed" && rows[0].RestoreState != "archived" {
			t.Fatal("restore state")
		}
	}
	rows, e := searchRows(items, revs, searchRequest{"safe", "active"})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(SearchReceipt{Rows: rows})
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("\u202e")) || bytes.Contains(raw, []byte("\u0085")) || !bytes.Contains(raw, []byte(`\u202e`)) || !bytes.Contains(raw, []byte("中文")) {
		t.Fatal("unsafe title JSON")
	}
	var decoded SearchReceipt
	if json.Unmarshal(raw, &decoded) != nil || decoded.Rows[0].Title != items[4].Title {
		t.Fatal("title not lossless")
	}
	for _, q := range []string{"", "  ", "\xff", "a\n", "a\u202e", strings.Repeat("x", 257)} {
		if ValidSearchQuery(q) {
			t.Fatal("invalid query accepted")
		}
	}
	if !ValidSearchQuery(strings.Repeat("x", 256)) {
		t.Fatal("query boundary")
	}
}

func TestTitleSearchAuditAndPrivateBinding(t *testing.T) {
	path, key, target := revealFixture(t)
	// This search term is absent from titles; searching secrets must not return it.
	receipt, e := Search(path, "fixture", key, "private-value", "all")
	if e != nil || len(receipt.Rows) != 0 {
		t.Fatal("secret field searched", e)
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ev := range events {
		if ev.hash() == receipt.Event {
			found = true
			if ev.Action != searchAction || ev.Result != "succeeded" || ev.Link != receipt.QueryDigest {
				t.Fatal("unbound search event")
			}
		}
	}
	if !found {
		t.Fatal("search absent from audit")
	}
	raw, _ := json.Marshal([]any{receipt, events})
	if bytes.Contains(raw, []byte("private-value")) {
		t.Fatal("query echoed")
	}
	rows, e := List(path, "fixture", key)
	if e != nil || rows[0].Revision != target.Revision {
		t.Fatal("search advanced revision", e)
	}
	request := searchRequest{"raw query", "active"}
	digest, e := request.binding(bytes.Repeat([]byte{1}, 32))
	if e != nil {
		t.Fatal(e)
	}
	for _, other := range []searchRequest{{"RAW QUERY", "active"}, {"raw query", "all"}} {
		got, e := other.binding(bytes.Repeat([]byte{1}, 32))
		if e != nil || got == digest {
			t.Fatal("query/scope not bound")
		}
	}
	got, e := request.binding(bytes.Repeat([]byte{2}, 32))
	if e != nil || got == digest {
		t.Fatal("cross-vault search binding")
	}
	if got, e := Search(path, "wrong", key, "private-value", "all"); e == nil || !reflect.DeepEqual(got, SearchReceipt{}) {
		t.Fatal("wrong factors released results")
	}
	archive := filepath.Join(t.TempDir(), "backup.llb")
	kit, e := Backup(path, archive, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := NewSecret()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(fresh)
	restored := filepath.Join(t.TempDir(), "restored.ll")
	if e = Restore(archive, restored, "fixture", key, kit, fresh); e != nil {
		t.Fatal("search history restore", e)
	}
	if _, e = Search(restored, "fixture", fresh, "missing", "active"); e != nil {
		t.Fatal("search after restore", e)
	}
}

func TestTitleSearchCommitAndCloseFailures(t *testing.T) {
	path, key, _ := revealFixture(t)
	db, e := existing(path)
	if e != nil {
		t.Fatal(e)
	}
	injected := errors.New("rollback")
	got, e := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if e := fn(tx); e != nil {
				return e
			}
			return injected
		})
	}, "fixture", key, searchAction, vault.Item{}, nil, commandOption{search: &searchRequest{"synthetic", "all"}})
	db.Close()
	if e != injected || !reflect.DeepEqual(got, result{}) {
		t.Fatal("rollback result", e)
	}
	got, e = commandWithClose(func() (result, error) { return result{rows: []Row{{Title: "private title"}}}, nil }, func() error { return injected })
	if e != ErrCommandClose || !reflect.DeepEqual(got, result{}) {
		t.Fatal("close result", e)
	}
}
