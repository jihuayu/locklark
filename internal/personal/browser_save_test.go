package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func saveTarget(fill BrowserFillTarget) BrowserSaveTarget {
	return BrowserSaveTarget{Context: BrowserSaveContext{BrowserContext: fill.Context, WindowID: 1}, ID: fill.ID, Revision: fill.Revision}
}

func TestBrowserSaveUpdatePreservesExistingEmptyTitle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.ll")
	key := bytes.Repeat([]byte{8}, 16)
	if e := Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(dir, "backup.age")
	kit, e := Backup(path, archive, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := decodeArchive(archive, "fixture", key, kit)
	if e != nil {
		t.Fatal(e)
	}
	// The signed snapshot schema accepts an empty title even though current
	// editing and import entry points require a nonempty one.
	recovered.Items = []vault.Item{{ID: "22222222222222222222222222222222", Kind: "login", URL: "https://example.test/login", Username: "old-user", Password: "old-password"}}
	restored := filepath.Join(dir, "empty-title.ll")
	if e = create(restored, "fixture", key, recovered); e != nil {
		t.Fatal(e)
	}
	s, e := UnlockSession(restored, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	context := BrowserContext{RequestID: "11111111111111111111111111111111", Origin: "https://example.test", TabID: 1, DocumentID: "doc-1"}
	rows, e := s.BrowserMatch(context)
	if e != nil || len(rows) != 1 || rows[0].Title != "" {
		t.Fatal("empty title snapshot did not match", e)
	}
	target := BrowserSaveTarget{ID: rows[0].ID, Revision: rows[0].Revision, Context: BrowserSaveContext{BrowserContext: context, WindowID: 1}}
	receipt, e := s.SaveBrowser(target, []byte("updated-user"), []byte("updated-password"), saveGate(t, s))
	if e != nil || receipt.ID != target.ID || receipt.Revision == target.Revision {
		t.Fatal("empty title update", e)
	}
	items := readStoredItems(t, restored, "fixture", key)
	if len(items) != 1 || items[0].Title != "" || items[0].Username != "updated-user" || items[0].Password != "updated-password" {
		t.Fatal("update replaced empty title or credentials")
	}
}

func TestBrowserSavePreservesMetadataRefusalSnapshotAndRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.ll")
	key := bytes.Repeat([]byte{6}, 16)
	if Create(path, "fixture", key) != nil {
		t.Fatal("create")
	}
	original := vault.Item{Kind: "login", Title: "Original title", URL: "https://example.test/original-path", Username: "old-user", Password: "old-password", OTP: "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP", ImportSource: []byte("opaque-import-provenance")}
	added, e := command(path, "fixture", key, "item.add", original, nil)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := List(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	target := BrowserSaveTarget{ID: added.id, Revision: rows[0].Revision, Context: BrowserSaveContext{BrowserContext: BrowserContext{RequestID: "11111111111111111111111111111111", Origin: "https://example.test", TabID: 1, DocumentID: "doc-1"}, WindowID: 1}}
	receipt, e := s.SaveBrowser(target, []byte("new-user"), []byte("new-password"), saveGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	items := readStoredItems(t, path, "fixture", key)
	got := items[0]
	if got.Title != original.Title || got.URL != original.URL || got.OTP != original.OTP || !bytes.Equal(got.ImportSource, original.ImportSource) || got.Username != "new-user" || got.Password != "new-password" {
		t.Fatal("update replaced unrelated metadata")
	}
	snapshot := func() []byte {
		db, e := existing(path)
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		var raw []byte
		db.View(func(tx *bolt.Tx) error { raw = bytes.Clone(tx.Bucket(bucket).Get(snapshotKey)); return nil })
		return raw
	}
	before := snapshot()
	target.Revision = receipt.Revision
	target.Context.Origin = "https://other.test"
	if _, e = s.SaveBrowser(target, []byte("rejected"), []byte("rejected"), saveGate(t, s)); !errors.Is(e, ErrBrowserSaveRefused) {
		t.Fatal(e)
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("refusal resealed snapshot")
	}
	rows, e = s.List("active")
	if e != nil || rows[0].Revision != receipt.Revision {
		t.Fatal("refusal changed revision")
	}
	archive := filepath.Join(dir, "backup.age")
	kit, e := Backup(path, archive, "fixture", key)
	if e != nil {
		t.Fatal("backup history", e)
	}
	restored := filepath.Join(dir, "restored.ll")
	fresh := bytes.Repeat([]byte{7}, 16)
	if e = Restore(archive, restored, "fixture", key, kit, fresh); e != nil {
		t.Fatal("restore browser audit", e)
	}
	recovered := readStoredItems(t, restored, "fixture", fresh)
	if len(recovered) != 1 || recovered[0].Password != "new-password" || recovered[0].OTP != original.OTP || !bytes.Equal(recovered[0].ImportSource, original.ImportSource) {
		t.Fatal("recovery lost saved metadata")
	}
	if _, e = ArchivedAudit(restored, "fixture", fresh); e != nil {
		t.Fatal("browser audit chain did not reopen", e)
	}
}

func TestBrowserSavePrivateFormattingAndExpiredApproval(t *testing.T) {
	s, fill := browserFixture(t)
	target := saveTarget(fill)
	g := saveGate(t, s)
	rq := &browserSaveRequest{target: target, username: []byte("secret-user"), password: []byte("secret-password"), gate: g}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if bytes.Contains([]byte(fmt.Sprintf(format, rq)), []byte("secret-")) {
			t.Fatal("formatted secret")
		}
	}
	if raw, e := json.Marshal(rq); e == nil || len(raw) > 0 {
		t.Fatal("serialized secret request")
	}
	g.Shorten(time.Now().Add(-time.Second))
	if s.TouchBrowserSave(g) == nil || g.Pending() {
		t.Fatal("expired native approval renewed session")
	}
}

func TestBrowserSaveCancelledBusinessRefusalDoesNotAppendAudit(t *testing.T) {
	s, fill := browserFixture(t)
	target := saveTarget(fill)
	target.Context.Origin = "https://other.test"
	g := saveGate(t, s)
	db, e := existing(s.path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var beforeSnapshot, beforeTip []byte
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		beforeSnapshot = bytes.Clone(b.Get(snapshotKey))
		beforeTip = bytes.Clone(b.Get(tipKey))
		return nil
	})
	run := func() (result, error) {
		return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
			return db.Update(func(tx *bolt.Tx) error { g.Cancel(); return fn(tx) })
		}, "", nil, browserUpdateAction, vault.Item{}, nil, commandOption{unlocked: s, browserSave: &browserSaveRequest{target: target, username: []byte("u"), password: []byte("p"), gate: g}})
	}
	if _, e = s.saveBrowser(target, []byte("u"), []byte("p"), g, run); !errors.Is(e, ErrBrowserSaveCancelled) {
		t.Fatal(e)
	}
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if !bytes.Equal(beforeSnapshot, b.Get(snapshotKey)) || !bytes.Equal(beforeTip, b.Get(tipKey)) {
			t.Fatal("cancel winner persisted refusal audit")
		}
		return nil
	})
}

func TestBrowserSaveGateRequestLockDoesNotWaitForDisk(t *testing.T) {
	s, _ := browserFixture(t)
	g := saveGate(t, s)
	s.mu.Lock()
	defer s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.RequestLock(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RequestLock waited for disk mutex")
	}
	if g.Pending() || s.Unlocked() {
		t.Fatal("lock did not cancel registered gate")
	}
}
func TestBrowserSaveGateHasExactlyOnePersistenceWinner(t *testing.T) {
	for n := 0; n < 128; n++ {
		g := NewBrowserSaveGate(time.Now().Add(time.Second))
		start := make(chan struct{})
		a, b := make(chan bool, 1), make(chan bool, 1)
		go func() { <-start; a <- g.Cancel() }()
		go func() { <-start; b <- g.win() }()
		close(start)
		cancel, commit := <-a, <-b
		if cancel == commit {
			t.Fatal("gate has zero or two winners")
		}
	}
}
func TestBrowserSaveBindingIncludesModeTargetRevisionAndWindow(t *testing.T) {
	_, fill := browserFixture(t)
	target := saveTarget(fill)
	key := bytes.Repeat([]byte{2}, 32)
	binding := func(target BrowserSaveTarget) string {
		r := &browserSaveRequest{target: target}
		digest, e := r.binding(key)
		if e != nil {
			t.Fatal(e)
		}
		return digest
	}
	base := binding(target)
	for _, change := range []func(*BrowserSaveTarget){func(v *BrowserSaveTarget) { v.ID = ""; v.Revision = ""; v.Title = "origin" }, func(v *BrowserSaveTarget) { v.ID = "22222222222222222222222222222222" }, func(v *BrowserSaveTarget) { v.Revision = string(bytes.Repeat([]byte{'3'}, 64)) }, func(v *BrowserSaveTarget) { v.Context.WindowID++ }} {
		other := target
		change(&other)
		if binding(other) == base {
			t.Fatal("audit binding omitted authorization target")
		}
	}
}
func saveGate(t *testing.T, s *Session) *BrowserSaveGate {
	t.Helper()
	g := NewBrowserSaveGate(time.Now().Add(time.Minute))
	if e := s.RegisterBrowserSave(g); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.ReleaseBrowserSave(g) })
	return g
}
func TestBrowserSaveNewAndAtomicPairUpdate(t *testing.T) {
	s, fill := browserFixture(t)
	target := saveTarget(fill)
	target.ID = ""
	target.Revision = ""
	target.Title = "https://example.test"
	g := saveGate(t, s)
	receipt, e := s.SaveBrowser(target, []byte(""), []byte("new-secret"), g)
	if e != nil || receipt.ID == "" || !digestOK(receipt.Revision) {
		t.Fatal("new save", e)
	}
	s.ReleaseBrowserSave(g)
	target.ID = receipt.ID
	target.Revision = receipt.Revision
	target.Title = ""
	g = saveGate(t, s)
	receipt2, e := s.SaveBrowser(target, []byte("updated-user"), []byte("updated-secret"), g)
	if e != nil || receipt2.ID != receipt.ID || receipt2.Revision == receipt.Revision {
		t.Fatal("update", e)
	}
	s.ReleaseBrowserSave(g)
	f, e := s.PrepareBrowserFill(BrowserFillTarget{ID: receipt.ID, Revision: receipt2.Revision, Context: fill.Context})
	if e != nil {
		t.Fatal(e)
	}
	if s.ConsumeBrowserFill(f, func(u, p []byte) error {
		if string(u) != "updated-user" || string(p) != "updated-secret" {
			t.Fatal("partial update")
		}
		return nil
	}) != nil {
		t.Fatal("fill saved login")
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(events)
	if bytes.Contains(raw, []byte("updated-user")) || bytes.Contains(raw, []byte("updated-secret")) {
		t.Fatal("secret audit")
	}
}
func TestBrowserSaveRefusalAuditAndCancel(t *testing.T) {
	s, fill := browserFixture(t)
	target := saveTarget(fill)
	target.Context.Origin = "https://other.test"
	g := saveGate(t, s)
	if _, e := s.SaveBrowser(target, []byte("new-user"), []byte("new-password"), g); !errors.Is(e, ErrBrowserSaveRefused) {
		t.Fatal("origin", e)
	}
	s.ReleaseBrowserSave(g)
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ev := range events {
		if ev.Action == browserUpdateAction {
			found = true
			if ev.Result != "browser-refused" || ev.BaseRevision != fill.Revision {
				t.Fatal("refusal changed revision")
			}
		}
	}
	if !found {
		t.Fatal("missing refusal audit")
	}
	g = saveGate(t, s)
	g.Cancel()
	target.Context.Origin = fill.Context.Origin
	if _, e = s.SaveBrowser(target, []byte("new-user"), []byte("new-password"), g); !errors.Is(e, ErrBrowserSaveCancelled) {
		t.Fatal("cancel", e)
	}
}
func TestBrowserSaveRollbackAndLockAfterGateUnknown(t *testing.T) {
	for _, lock := range []bool{false, true} {
		s, fill := browserFixture(t)
		target := saveTarget(fill)
		g := saveGate(t, s)
		db, e := existing(s.path)
		if e != nil {
			t.Fatal(e)
		}
		injected := errors.New("rollback")
		run := func() (result, error) {
			return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
				return db.Update(func(tx *bolt.Tx) error {
					if e := fn(tx); e != nil {
						return e
					}
					if lock {
						s.RequestLock()
						return nil
					}
					return injected
				})
			}, "", nil, browserUpdateAction, vault.Item{}, nil, commandOption{unlocked: s, browserSave: &browserSaveRequest{target: target, username: []byte("pair-user"), password: []byte("pair-secret"), gate: g}})
		}
		_, e = s.saveBrowser(target, []byte("pair-user"), []byte("pair-secret"), g, run)
		db.Close()
		if !errors.Is(e, ErrBrowserSaveUnknown) || !g.CommitWon() {
			t.Fatal("unknown lost", e)
		}
		s.ReleaseBrowserSave(g)
	}
}

func TestBrowserSaveSuccessAndRefusalCloseFailureAreUnknown(t *testing.T) {
	for _, outcome := range []string{"success", "refusal"} {
		t.Run(outcome, func(t *testing.T) {
			s, fill := browserFixture(t)
			target := saveTarget(fill)
			if outcome == "refusal" {
				target.Context.Origin = "https://other.test"
			}
			g := saveGate(t, s)
			run := func() (result, error) {
				return commandWithClose(func() (result, error) {
					return command(s.path, "", nil, browserUpdateAction, vault.Item{}, nil, commandOption{unlocked: s, browserSave: &browserSaveRequest{target: target, username: []byte("u"), password: []byte("p"), gate: g}})
				}, func() error { return errors.New("close failed") })
			}
			if _, e := s.saveBrowser(target, []byte("u"), []byte("p"), g, run); !errors.Is(e, ErrBrowserSaveUnknown) || !g.CommitWon() {
				t.Fatal("close failure looked like a known result", e)
			}
		})
	}
}
func TestBrowserSaveOwnsPayloadAndReleasedGateCannotBeReused(t *testing.T) {
	s, fill := browserFixture(t)
	g := saveGate(t, s)
	target := saveTarget(fill)
	u, p := []byte("private-user"), []byte{}
	if _, e := s.SaveBrowser(target, u, p, g); e == nil {
		t.Fatal("empty password")
	}
	if !bytes.Equal(u, make([]byte, len(u))) {
		t.Fatal("invalid payload retained")
	}
	s.ReleaseBrowserSave(g)
	if s.RegisterBrowserSave(g) == nil {
		t.Fatal("released gate reused")
	}
	expired := NewBrowserSaveGate(time.Now().Add(-time.Second))
	if s.RegisterBrowserSave(expired) == nil {
		t.Fatal("expired gate registered")
	}
}
