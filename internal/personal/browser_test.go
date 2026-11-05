package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestBrowserCandidateBudgetIncludesJSONEscaping(t *testing.T) {
	rows := make([]Row, 100)
	for i := range rows {
		rows[i] = Row{ID: strings.Repeat("a", 32), Revision: strings.Repeat("b", 64), Title: strings.Repeat("<&>", 341), State: "active"}
	}
	if browserCandidateBudget(rows) {
		t.Fatal("escaped metadata exceeded native response budget")
	}
	if !browserCandidateBudget(rows[:10]) {
		t.Fatal("ordinary bounded metadata refused")
	}
}

func browserFixture(t *testing.T) (*Session, BrowserFillTarget) {
	t.Helper()
	path, key, target := revealFixture(t)
	rev, err := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "url", Value: "https://example.test/login"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Lock)
	return s, BrowserFillTarget{ID: target.ID, Revision: rev, Context: BrowserContext{RequestID: "11111111111111111111111111111111", Origin: "https://example.test", TabID: 1, DocumentID: "document-1"}}
}

func TestBrowserFillAtomicOriginRevisionAndOneUse(t *testing.T) {
	s, target := browserFixture(t)
	last := s.last
	rows, err := s.BrowserMatch(target.Context)
	if err != nil || len(rows) != 1 || s.last != last {
		t.Fatal("match/idle", err)
	}
	bad := target
	bad.Context.Origin = "https://similar-example.test"
	if _, err = s.PrepareBrowserFill(bad); err == nil {
		t.Fatal("cross origin accepted")
	}
	fill, err := s.PrepareBrowserFill(target)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	err = s.ConsumeBrowserFill(fill, func(user, pass []byte) error {
		called++
		if string(user) != "fixture-user" || !bytes.Contains(pass, []byte("private-value")) {
			t.Fatal("wrong pair")
		}
		return nil
	})
	if err != nil || called != 1 {
		t.Fatal(err)
	}
	if s.ConsumeBrowserFill(fill, func([]byte, []byte) error { called++; return nil }) == nil || called != 1 {
		t.Fatal("replayed")
	}
	_, err = s.Edit(Edit{ID: target.ID, Revision: target.Revision, Field: "password", Value: "new-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PrepareBrowserFill(target); !errors.Is(err, ErrConflict) {
		t.Fatal("stale", err)
	}
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == browserFillAction && event.Result == "succeeded" {
			t.Fatal("false delivery receipt")
		}
	}
	encoded, _ := json.Marshal(events)
	if bytes.Contains(encoded, []byte("fixture-user")) || bytes.Contains(encoded, []byte("private-value")) {
		t.Fatal("secret in browser audit")
	}
}

func TestBrowserFillCloseFailureClearsBothValues(t *testing.T) {
	pair := &NativeBrowserFill{username: []byte("fixture-user"), password: []byte("fixture-password")}
	r, e := commandWithClose(func() (result, error) { return result{browser: pair}, nil }, func() error { return errors.New("close failure") })
	if !errors.Is(e, ErrCommandClose) || r.browser != nil || len(pair.username) != 0 || len(pair.password) != 0 {
		t.Fatal("close failure disclosed")
	}
}

func TestBrowserFillLockExpiryAndInactive(t *testing.T) {
	s, target := browserFixture(t)
	fill, err := s.PrepareBrowserFill(target)
	if err != nil {
		t.Fatal(err)
	}
	fill.until = time.Now().Add(-time.Second)
	if s.ConsumeBrowserFill(fill, func([]byte, []byte) error { t.Fatal("expired callback"); return nil }) == nil {
		t.Fatal("expired fill")
	}
	fill, err = s.PrepareBrowserFill(target)
	if err != nil {
		t.Fatal(err)
	}
	s.RequestLock()
	if s.ConsumeBrowserFill(fill, func([]byte, []byte) error { t.Fatal("locked callback"); return nil }) == nil {
		t.Fatal("lock bypass")
	}
	if len(fill.username) != 0 || len(fill.password) != 0 {
		t.Fatal("retained locked pair")
	}
	s2, target2 := browserFixture(t)
	rev, err := s2.SetState(target2.ID, target2.Revision, "item.archive")
	if err != nil {
		t.Fatal(err)
	}
	target2.Revision = rev
	if _, err = s2.PrepareBrowserFill(target2); err == nil {
		t.Fatal("archived accepted")
	}
	rev, err = s2.SetState(target2.ID, target2.Revision, "item.trash")
	if err != nil {
		t.Fatal(err)
	}
	target2.Revision = rev
	if _, err = s2.PrepareBrowserFill(target2); err == nil {
		t.Fatal("trashed accepted")
	}
}

func TestBrowserFillRollbackReturnsNoValues(t *testing.T) {
	s, target := browserFixture(t)
	db, err := existing(s.path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("rollback")
	r, err := commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if e := fn(tx); e != nil {
				return e
			}
			return injected
		})
	}, "", nil, browserFillAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision}, commandOption{unlocked: s, browser: &target})
	db.Close()
	if !errors.Is(err, injected) || r.browser != nil {
		t.Fatal("rollback disclosed", err)
	}
	rows, err := s.BrowserMatch(target.Context)
	if err != nil || len(rows) != 1 {
		t.Fatal("rollback corrupted history", err)
	}
}
