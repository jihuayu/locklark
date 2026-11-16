//go:build darwin || linux

package vaultfileclient

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// TestLocalGenesisSessionFastFailJoinsInProgressFirstClose proves the real
// first closer may still be waiting for parent.LockVaultFileChild after the
// wrapper has already become closed. A second real Summary must fast-fail
// against that terminal flag, while the sibling remains readable and the actual
// A child only refuses reads after the first closer completes. The test never
// calls Close to manufacture the acceptance path.
func TestLocalGenesisSessionFastFailJoinsInProgressFirstClose(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)
	if a == nil || a.state == nil || b == nil {
		t.Fatal("LOCAL_GENESIS_FASTFAIL_SETUP_FAILED")
	}
	token := a.state.token
	closeDone := a.state.closeDone

	// Move only A's manifest so the next old A Summary fails locator
	// revalidation and initiates the real internal close.
	moved := f.firstConfig + ".first-close"
	if err := os.Rename(f.firstConfig, moved); err != nil {
		t.Fatal("LOCAL_GENESIS_FASTFAIL_MANIFEST_MOVE_FAILED")
	}
	t.Cleanup(func() { _ = os.Rename(moved, f.firstConfig) })

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	var paused atomic.Bool
	a.state.firstCloseForTest = func() {
		if paused.CompareAndSwap(false, true) {
			close(closeEntered)
			<-closeRelease
		}
	}

	oldResult := make(chan error, 1)
	go func() {
		_, err := a.Summary()
		oldResult <- err
	}()
	select {
	case <-closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_GENESIS_FASTFAIL_FIRST_CLOSE_NOT_ENTERED")
	}

	// closed is already true, so a new Summary returns without waiting for the
	// first closer or the real child Close.
	if summary, err := a.Summary(); err == nil || summary.Items != nil {
		t.Fatal("LOCAL_GENESIS_FASTFAIL_FAST_PATH_NOT_TERMINAL")
	}
	select {
	case <-oldResult:
		t.Fatal("LOCAL_GENESIS_FASTFAIL_OLD_SUMMARY_RETURNED_EARLY")
	default:
	}
	select {
	case <-closeDone:
		t.Fatal("LOCAL_GENESIS_FASTFAIL_CLOSE_DONE_CLOSED_EARLY")
	default:
	}

	sibling, err := b.Summary()
	if err != nil || sibling.VaultID != f.secondVaultID {
		t.Fatal("LOCAL_GENESIS_FASTFAIL_SIBLING_LOST")
	}

	close(closeRelease)
	select {
	case err := <-oldResult:
		if err == nil {
			t.Fatal("LOCAL_GENESIS_FASTFAIL_OLD_SUMMARY_DID_NOT_FAIL")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_GENESIS_FASTFAIL_OLD_SUMMARY_STUCK")
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_GENESIS_FASTFAIL_REAL_CLOSE_NOT_DONE")
	}
	if _, err := f.session.ReadVaultFileChild(token, personal.VaultFileChildOptions{}); err == nil {
		t.Fatal("LOCAL_GENESIS_FASTFAIL_CLOSED_CHILD_STILL_READS")
	}
}
