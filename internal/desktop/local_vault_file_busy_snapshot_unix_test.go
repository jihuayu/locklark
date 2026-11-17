//go:build darwin || linux

package desktop

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

func prepareLocalVaultBusyField(t *testing.T, session *personal.Session) *personal.NativeField {
	t.Helper()
	id, err := session.AddLogin("busy-snapshot-title", "busy-snapshot-user", "busy-snapshot-value")
	if err != nil {
		t.Fatal("LOCAL_VAULT_BUSY_FIELD_ADD_FAILED")
	}
	rows, err := session.List("active")
	if err != nil {
		t.Fatal("LOCAL_VAULT_BUSY_FIELD_LIST_FAILED")
	}
	revision := ""
	for _, row := range rows {
		if row.ID == id {
			revision = row.Revision
			break
		}
	}
	if revision == "" {
		t.Fatal("LOCAL_VAULT_BUSY_FIELD_ROW_MISSING")
	}
	field, err := session.PrepareField(personal.RevealTarget{ID: id, Revision: revision, Field: "password"}, "show")
	if err != nil {
		t.Fatal("LOCAL_VAULT_BUSY_FIELD_PREPARE_FAILED")
	}
	return field
}

// installLocalVaultBusyAfterActive starts a real parent Consume from the
// production after-Active snapshot seam and waits only until deliver has
// entered the actual Session.mu. The delivered bytes are ignored entirely.
func installLocalVaultBusyAfterActive(t *testing.T, f *localVaultSessionFixture, field *personal.NativeField) (done chan error, calls *atomic.Int32, release func()) {
	t.Helper()
	entered := make(chan struct{})
	releaseCh := make(chan struct{})
	done = make(chan error, 1)
	calls = &atomic.Int32{}
	var releaseOnce sync.Once
	release = func() { releaseOnce.Do(func() { close(releaseCh) }) }
	t.Cleanup(release)
	f.app.localVaultFiles.afterActiveSnapshotForTest = func() {
		calls.Add(1)
		go func() {
			done <- f.parent.Consume(field, func(_ []byte) error {
				close(entered)
				<-releaseCh
				return nil
			})
		}()
		<-entered
	}
	return done, calls, release
}

func TestDesktopLocalVaultFileBusyAfterActiveWithholdsCache(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_VAULT_BUSY_SETUP_FAILED")
	}
	bSession := bSlot.session
	aRef := localVaultNavigationRef(aPath, aManifest)
	bRef := localVaultNavigationRef(bPath, bManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef, bRef}

	field := prepareLocalVaultBusyField(t, f.parent)
	done, calls, release := installLocalVaultBusyAfterActive(t, f, field)
	if scope, ok := f.app.localVaultFileSessionScopeFor(bRef); !ok || scope != bScope {
		release()
		t.Fatal("LOCAL_VAULT_BUSY_SCOPE_HINT_FAILED")
	}
	// The UI returned above while Consume still holds the real parent mutex.
	// The next cache gate must see Busy, withhold and preserve B.
	if summary, ok := f.app.readLocalVaultFileSession(bScope); ok || summary.VaultID != "" {
		t.Fatal("LOCAL_VAULT_BUSY_CACHE_DELIVERED")
	}
	f.app.selectLocalVaultFile(bRef)
	if f.app.localVaultFiles.selected != bPath ||
		f.app.localVaultFiles.status != localVaultFileStatusUnavailable {
		t.Fatal("LOCAL_VAULT_BUSY_SELECT_NOT_FINITE_UNAVAILABLE")
	}
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_VAULT_BUSY_SELECT_REPLACED_SIBLING")
	}
	if calls.Load() != 1 {
		t.Fatal("LOCAL_VAULT_BUSY_SEAM_NOT_ONCE")
	}
	release()
	if err := <-done; err != nil {
		t.Fatal("LOCAL_VAULT_BUSY_CONSUME_FAILED")
	}
	if state, path := f.parent.VaultFileCacheSnapshot(); state != personal.VaultFileCacheActive || path == "" {
		t.Fatal("LOCAL_VAULT_BUSY_PARENT_PROOF_CHANGED")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_VAULT_BUSY_SIBLING_CHILD_LOST")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_VAULT_BUSY_PARENT_LOCKED")
	}
}

func TestDesktopLocalVaultFileBusyAfterActiveBeginRefreshReturns(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_SETUP_FAILED")
	}
	bSession := bSlot.session
	f.app.localVaultFiles.selected = bPath
	f.app.localVaultFiles.refs = []localVaultFileRef{localVaultNavigationRef(aPath, aManifest), localVaultNavigationRef(bPath, bManifest)}
	q.launches, q.dispatches = nil, nil

	field := prepareLocalVaultBusyField(t, f.parent)
	done, calls, release := installLocalVaultBusyAfterActive(t, f, field)
	op := f.app.beginLocalVaultFileRefresh(bScope)
	if op == nil || op.parentPath == "" {
		release()
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_DID_NOT_FREEZE_PATH")
	}
	// The begin call returned while the real parent mutex is still held by
	// Consume; no blocking VaultPath call occurred.
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_WORKER_NOT_QUEUED")
	}
	if summary, ok := f.app.readLocalVaultFileSession(bScope); ok || summary.VaultID != "" {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_CACHE_GATE_DELIVERED")
	}
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_REPLACED_SIBLING")
	}
	if calls.Load() != 1 {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_SEAM_NOT_ONCE")
	}
	release()
	if err := <-done; err != nil {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_CONSUME_FAILED")
	}
	if path, cache := f.app.localVaultFileRoutingPath(); cache != personal.VaultFileCacheActive || path != op.parentPath {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_FROZEN_PATH_CHANGED")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_SIBLING_CHILD_LOST")
	}
	f.app.cancelLocalVaultFileRefreshExact(op)
	q.runLaunch(t)
	if len(q.dispatches) != 0 {
		t.Fatal("LOCAL_VAULT_BUSY_REFRESH_TERMINAL_DISPATCHED")
	}
}
