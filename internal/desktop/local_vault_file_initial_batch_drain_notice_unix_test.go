//go:build darwin || linux

package desktop

import (
	"sync"
	"testing"
)

func TestLocalVaultFileInitialDrainNotice(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	f.createVault(t)
	f.createVault(t)
	if _, err := f.parent.AddLogin("drain-notice", "notice-user", "notice-value"); err != nil {
		t.Fatal("DRAIN_NOTICE_ROW_SETUP_FAILED")
	}
	profileDir, backendRoot := localVaultFilePaths(f.settingsPath, f.personalPath)
	refs, err := listLocalVaultFileRefs(profileDir, backendRoot, f.personalPath)
	if err != nil || len(refs) != 2 {
		t.Fatal("DRAIN_NOTICE_REFS_FAILED")
	}
	pre, _, _ := newDrainSummaryBatch(t, f, refs, 0, false)
	post, _, _ := newDrainSummaryBatch(t, f, refs, 1, false)

	t.Run("pre-drain", func(t *testing.T) {
		notice, ok := pre.drainNotice()
		if !ok || notice == nil {
			t.Fatal("DRAIN_NOTICE_SUBSCRIBE_FAILED")
		}
		if _, duplicate := pre.drainNotice(); duplicate {
			t.Fatal("DRAIN_NOTICE_DUPLICATE_SUBSCRIBE")
		}
		select {
		case <-notice:
			t.Fatal("DRAIN_NOTICE_EARLY_EVENT")
		default:
		}
		pre.drain()
		summary, open := <-notice
		if !open || summary.state != localVaultFileInitialDrainComplete ||
			summary.closedWrappers != 1 || !summary.parentLocked ||
			!summary.refsCleared || !summary.rowsCleared {
			t.Fatal("DRAIN_NOTICE_FINAL_EVENT_FAILED")
		}
		if _, open := <-notice; open {
			t.Fatal("DRAIN_NOTICE_NOT_EOF")
		}
		pre.drain()
		if got := pre.drainSummary(); got != summary {
			t.Fatal("DRAIN_NOTICE_REPEAT_CHANGED_SUMMARY")
		}
		if _, duplicate := pre.drainNotice(); duplicate {
			t.Fatal("DRAIN_NOTICE_REPEAT_SUBSCRIBE")
		}
	})

	t.Run("post-drain", func(t *testing.T) {
		post.drain()
		notice, ok := post.drainNotice()
		if !ok || notice == nil {
			t.Fatal("DRAIN_NOTICE_POST_SUBSCRIBE_FAILED")
		}
		summary, open := <-notice
		if !open || summary.state != localVaultFileInitialDrainComplete ||
			summary.closedWrappers != 1 || !summary.parentLocked {
			t.Fatal("DRAIN_NOTICE_POST_EVENT_FAILED")
		}
		if _, open := <-notice; open {
			t.Fatal("DRAIN_NOTICE_POST_NOT_EOF")
		}
		if got := post.drainSummary(); got != summary {
			t.Fatal("DRAIN_NOTICE_POST_SUMMARY_CHANGED")
		}
	})

	t.Run("adopted", func(t *testing.T) {
		adopted := &localVaultFileInitialBatch{done: make(chan struct{})}
		notice, ok := adopted.drainNotice()
		if !ok || notice == nil {
			t.Fatal("DRAIN_NOTICE_ADOPT_SUBSCRIBE_FAILED")
		}
		if !adopted.takeForAdoption() {
			t.Fatal("DRAIN_NOTICE_ADOPT_FAILED")
		}
		if _, open := <-notice; open {
			t.Fatal("DRAIN_NOTICE_ADOPTED_SENT_SUMMARY")
		}
		if _, duplicate := adopted.drainNotice(); duplicate {
			t.Fatal("DRAIN_NOTICE_ADOPTED_RESUBSCRIBE")
		}
		select {
		case <-adopted.done:
			t.Fatal("DRAIN_NOTICE_ADOPTED_CLOSED_DONE")
		default:
		}
	})

	t.Run("nil", func(t *testing.T) {
		var nilBatch *localVaultFileInitialBatch
		if notice, ok := nilBatch.drainNotice(); ok || notice != nil {
			t.Fatal("DRAIN_NOTICE_NIL_SUBSCRIBE")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		invalid := &localVaultFileInitialBatch{done: make(chan struct{})}
		invalid.drain()
		notice, ok := invalid.drainNotice()
		if !ok || notice == nil {
			t.Fatal("DRAIN_NOTICE_INVALID_SUBSCRIBE_FAILED")
		}
		summary, open := <-notice
		if !open || summary.state != localVaultFileInitialDrainInvalid {
			t.Fatal("DRAIN_NOTICE_INVALID_FAKE_COMPLETE")
		}
		if _, open := <-notice; open {
			t.Fatal("DRAIN_NOTICE_INVALID_NOT_EOF")
		}
	})

	t.Run("concurrent-register-drain", func(t *testing.T) {
		for iteration := 0; iteration < 2; iteration++ {
			batch := &localVaultFileInitialBatch{done: make(chan struct{})}
			start := make(chan struct{})
			var wait sync.WaitGroup
			var notice <-chan localVaultFileInitialDrainSummary
			var subscribed bool
			wait.Add(2)
			go func() {
				defer wait.Done()
				<-start
				notice, subscribed = batch.drainNotice()
			}()
			go func() {
				defer wait.Done()
				<-start
				batch.drain()
			}()
			close(start)
			wait.Wait()
			if !subscribed || notice == nil {
				t.Fatal("DRAIN_NOTICE_CONCURRENT_SUBSCRIBE_FAILED")
			}
			summary, open := <-notice
			if !open || summary.state != localVaultFileInitialDrainInvalid {
				t.Fatal("DRAIN_NOTICE_CONCURRENT_NOT_INVALID")
			}
			if _, open := <-notice; open {
				t.Fatal("DRAIN_NOTICE_CONCURRENT_NOT_EOF")
			}
		}
	})
}
