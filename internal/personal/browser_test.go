package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// The browser fixture image is built once per test process. It holds only the
// closed encrypted database and the post-edit target; each caller gets its own
// fresh 0600 copy and performs the real unlock against that copy.
var browserFixtureImage struct {
	once   sync.Once
	body   []byte
	target BrowserFillTarget
	err    error
}

func buildBrowserFixtureImage() ([]byte, BrowserFillTarget, error) {
	dir, err := os.MkdirTemp("", "locklark-browser-fixture-*")
	if err != nil {
		return nil, BrowserFillTarget{}, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "owner.ll")
	key := bytes.Repeat([]byte{4}, 16)
	defer clear(key)
	if err = Create(path, "fixture", key); err != nil {
		return nil, BrowserFillTarget{}, err
	}
	if _, err = AddLogin(path, "fixture", key, "same", "fixture-user", "private-value\t\"quoted\"\n"); err != nil {
		return nil, BrowserFillTarget{}, err
	}
	if _, err = AddLogin(path, "fixture", key, "same", "other-user", "other-password"); err != nil {
		return nil, BrowserFillTarget{}, err
	}
	rows, err := List(path, "fixture", key)
	if err != nil {
		return nil, BrowserFillTarget{}, err
	}
	if len(rows) == 0 {
		return nil, BrowserFillTarget{}, errors.New("browser fixture has no login rows")
	}
	rev, err := EditLogin(path, "fixture", key, Edit{ID: rows[0].ID, Revision: rows[0].Revision, Field: "url", Value: "https://example.test/login"})
	if err != nil {
		return nil, BrowserFillTarget{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, BrowserFillTarget{}, err
	}
	if len(body) == 0 {
		return nil, BrowserFillTarget{}, errors.New("browser fixture image is empty")
	}
	return body, BrowserFillTarget{ID: rows[0].ID, Revision: rev, Context: BrowserContext{RequestID: "11111111111111111111111111111111", Origin: "https://example.test", TabID: 1, DocumentID: "document-1"}}, nil
}

func browserFixture(t *testing.T) (*Session, BrowserFillTarget) {
	t.Helper()
	browserFixtureImage.once.Do(func() {
		browserFixtureImage.body, browserFixtureImage.target, browserFixtureImage.err = buildBrowserFixtureImage()
	})
	if browserFixtureImage.err != nil {
		t.Fatal(browserFixtureImage.err)
	}
	path := filepath.Join(t.TempDir(), "owner.ll")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(browserFixtureImage.body); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	password := []byte("fixture")
	key := bytes.Repeat([]byte{4}, 16)
	defer clear(password)
	defer clear(key)
	s, err := UnlockSession(path, password, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Lock)
	return s, browserFixtureImage.target
}

func TestBrowserFixtureCallersHaveIsolatedFilesRevisionsAndPendingState(t *testing.T) {
	s1, target1 := browserFixture(t)
	s2, target2 := browserFixture(t)
	if s1.path == s2.path {
		t.Fatal("browser fixture callers shared a path")
	}
	first, err := os.Stat(s1.path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(s2.path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Mode().IsRegular() || !second.Mode().IsRegular() || os.SameFile(first, second) {
		t.Fatal("browser fixture callers did not get separate files")
	}
	otherBefore, err := os.ReadFile(s2.path)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := s1.Edit(Edit{ID: target1.ID, Revision: target1.Revision, Field: "password", Value: "clone-one-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if rev == target1.Revision {
		t.Fatal("browser fixture mutation did not advance its revision")
	}
	otherAfter, err := os.ReadFile(s2.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(otherBefore, otherAfter) {
		t.Fatal("browser fixture mutation changed the other clone")
	}
	rows, err := s2.List("active")
	if err != nil {
		t.Fatal(err)
	}
	otherRevision := ""
	for _, row := range rows {
		if row.ID == target2.ID {
			otherRevision = row.Revision
		}
	}
	if otherRevision != target2.Revision {
		t.Fatal("browser fixture mutation advanced the other clone's revision")
	}
	fill, err := s1.PrepareBrowserFill(BrowserFillTarget{ID: target1.ID, Revision: rev, Context: target1.Context})
	if err != nil {
		t.Fatal(err)
	}
	defer s1.DiscardBrowserFill(fill)
	s1.mu.Lock()
	onePending := len(s1.browserPending)
	s1.mu.Unlock()
	s2.mu.Lock()
	twoPending := len(s2.browserPending)
	s2.mu.Unlock()
	if onePending != 1 || twoPending != 0 {
		t.Fatal("browser fixture pending state was shared")
	}
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
