//go:build darwin || linux

package personal

import (
	"sync"
	"testing"
	"time"
)

func assertVaultFileCacheStateWithin(t *testing.T, s *Session, want VaultFileCacheState) {
	t.Helper()
	got := make(chan VaultFileCacheState, 1)
	go func() { got <- s.VaultFileCacheState() }()
	select {
	case state := <-got:
		if state != want {
			t.Fatal("VAULT_FILE_CACHE_STATE_UNEXPECTED")
		}
	case <-time.After(time.Second):
		t.Fatal("VAULT_FILE_CACHE_STATE_BLOCKED")
	}
}

func TestVaultFileCacheStateBoundaries(t *testing.T) {
	now := time.Now()
	requestLocked := &Session{material: []byte{1}, last: now, idle: time.Hour}
	requestLocked.lockRequested.Store(true)
	vaultRevoked := &Session{material: []byte{1}, last: now, idle: time.Hour}
	vaultRevoked.vaultFileRevoked.Store(true)
	for _, tc := range []struct {
		name    string
		session *Session
		want    VaultFileCacheState
	}{
		{name: "nil", session: nil, want: VaultFileCacheRevoked},
		{name: "zero", session: &Session{}, want: VaultFileCacheRevoked},
		{name: "empty-material", session: &Session{last: now, idle: time.Hour}, want: VaultFileCacheRevoked},
		{name: "fresh", session: &Session{material: []byte{1}, last: now, idle: time.Hour}, want: VaultFileCacheActive},
		{name: "idle-expired", session: &Session{material: []byte{1}, last: now.Add(-2 * time.Second), idle: time.Second}, want: VaultFileCacheRevoked},
		{name: "request-locked", session: requestLocked, want: VaultFileCacheRevoked},
		{name: "vault-revoked", session: vaultRevoked, want: VaultFileCacheRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.session.VaultFileCacheState(); got != tc.want {
				t.Fatal("VAULT_FILE_CACHE_STATE_BOUNDARY_FAILED")
			}
		})
	}

	fx := newScopedChildFixture(t)
	if got := fx.session.VaultFileCacheState(); got != VaultFileCacheActive {
		t.Fatal("VAULT_FILE_CACHE_STATE_FRESH_SESSION_FAILED")
	}
	fx.session.mu.Lock()
	originalLast, originalIdle := fx.session.last, fx.session.idle
	fx.session.last = time.Now().Add(-2 * time.Minute)
	fx.session.idle = time.Minute
	fx.session.mu.Unlock()
	if got := fx.session.VaultFileCacheState(); got != VaultFileCacheRevoked {
		t.Fatal("VAULT_FILE_CACHE_STATE_REAL_IDLE_EXPIRED_FAILED")
	}
	fx.session.mu.Lock()
	fx.session.last, fx.session.idle = originalLast, originalIdle
	fx.session.mu.Unlock()
	if got := fx.session.VaultFileCacheState(); got != VaultFileCacheActive {
		t.Fatal("VAULT_FILE_CACHE_STATE_REAL_IDLE_RESTORED_FAILED")
	}
}

func TestVaultFileCacheStateBusyAndActive(t *testing.T) {
	fx := newScopedChildFixture(t)
	tokenA, tokenB, _, _ := openScopedChildPair(t, fx)
	fx.session.mu.Lock()
	originalLast, originalFullUnlock := fx.session.last, fx.session.fullUnlock
	fx.session.mu.Unlock()
	if got := fx.session.VaultFileCacheState(); got != VaultFileCacheActive {
		t.Fatal("VAULT_FILE_CACHE_STATE_ACTIVE_FAILED")
	}

	fx.session.mu.Lock()
	if got := fx.session.VaultFileCacheState(); got != VaultFileCacheBusy {
		fx.session.mu.Unlock()
		t.Fatal("VAULT_FILE_CACHE_STATE_BUSY_FAILED")
	}
	fx.session.mu.Unlock()
	if got := fx.session.VaultFileCacheState(); got != VaultFileCacheActive {
		t.Fatal("VAULT_FILE_CACHE_STATE_RELEASED_ACTIVE_FAILED")
	}

	fx.session.mu.Lock()
	last, fullUnlock := fx.session.last, fx.session.fullUnlock
	fx.session.mu.Unlock()
	if !last.Equal(originalLast) || !fullUnlock.Equal(originalFullUnlock) {
		t.Fatal("VAULT_FILE_CACHE_STATE_REFRESHED_TIMESTAMPS")
	}
	if fx.registryLen() != 2 {
		t.Fatal("VAULT_FILE_CACHE_STATE_CHANGED_CHILDREN")
	}
	assertScopedChildForSessionRead(t, fx.session, tokenA, fx.a.itemID)
	assertScopedChildForSessionRead(t, fx.session, tokenB, fx.b.itemID)
}

func TestVaultFileCacheStateParentLockGate(t *testing.T) {
	fx := newScopedChildFixture(t)
	tokenA, tokenB, handleA, handleB := openScopedChildPair(t, fx)
	pause := installScopedClosePause(t)
	var wg sync.WaitGroup
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(pause.release) }) }
	t.Cleanup(func() {
		release()
		wg.Wait()
	})

	closeA := make(chan error, 1)
	wg.Add(1)
	go func() { defer wg.Done(); closeA <- fx.session.LockVaultFileChild(tokenA) }()
	waitScopedCloseSeam(t, pause)

	// The seam is claimed by A only; B's real close must finish while A is
	// paused rather than inheriting a blocking-once wait.
	closeB := make(chan error, 1)
	wg.Add(1)
	go func() { defer wg.Done(); closeB <- fx.session.LockVaultFileChild(tokenB) }()
	select {
	case err := <-closeB:
		if err != nil {
			t.Fatal("VAULT_FILE_CACHE_STATE_SIBLING_CLOSE_FAILED")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VAULT_FILE_CACHE_STATE_SIBLING_CLOSE_BLOCKED")
	}
	assertScopedChildHandleClosed(t, handleB)

	parentDone := make(chan struct{})
	wg.Add(1)
	go func() { defer wg.Done(); fx.session.Lock(); close(parentDone) }()
	deadline := time.Now().Add(5 * time.Second)
	for !fx.session.lockRequested.Load() {
		if time.Now().After(deadline) {
			t.Fatal("VAULT_FILE_CACHE_STATE_PARENT_LOCK_START_TIMEOUT")
		}
		time.Sleep(time.Millisecond)
	}

	assertVaultFileCacheStateWithin(t, fx.session, VaultFileCacheRevoked)
	select {
	case <-parentDone:
		t.Fatal("VAULT_FILE_CACHE_STATE_PARENT_LOCK_DID_NOT_WAIT")
	default:
	}

	release()
	select {
	case err := <-closeA:
		if err != nil {
			t.Fatal("VAULT_FILE_CACHE_STATE_CHILD_CLOSE_FAILED")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VAULT_FILE_CACHE_STATE_CHILD_CLOSE_STUCK")
	}
	select {
	case <-parentDone:
	case <-time.After(5 * time.Second):
		t.Fatal("VAULT_FILE_CACHE_STATE_PARENT_LOCK_STUCK")
	}
	if got := fx.session.VaultFileCacheState(); got != VaultFileCacheRevoked {
		t.Fatal("VAULT_FILE_CACHE_STATE_REVOKED_AFTER_CLOSE_FAILED")
	}
	assertScopedChildHandleClosed(t, handleA)
}
