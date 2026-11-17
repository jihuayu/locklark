//go:build darwin || linux

package personal

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

func ownedBatchTargets(vaults ...ownedChildVault) []OwnedVaultFileTarget {
	targets := make([]OwnedVaultFileTarget, 0, len(vaults))
	for _, vault := range vaults {
		targets = append(targets, OwnedVaultFileTarget{
			JournalPath: vault.journal,
			Checkpoint:  *vault.checkpoint,
			Options:     VaultFileChildOptions{IncludeItemIDs: true},
		})
	}
	return targets
}

func TestUnlockSessionWithOwnedVaultFileChildrenBuildsIndependentRealChildren(t *testing.T) {
	fx := newOwnedChildFixture(t)
	b := fx.addVault(t, "batch-b")
	targets := ownedBatchTargets(fx.a, b)
	var authCount atomic.Int32
	vaultFileOwnedBatchAuthForTest = func() { authCount.Add(1) }
	t.Cleanup(func() { vaultFileOwnedBatchAuthForTest = nil })

	parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
		context.Background(), fx.session.path, fx.password, fx.key, time.Minute, targets)
	if err != nil {
		t.Fatal("OWNED_BATCH_UNLOCK_FAILED")
	}
	t.Cleanup(parent.Lock)
	if authCount.Load() != 1 {
		t.Fatal("OWNED_BATCH_AUTH_NOT_ONCE")
	}
	if len(results) != 2 || results[0].Err != nil || results[1].Err != nil {
		t.Fatal("OWNED_BATCH_TARGET_RESULTS_FAILED")
	}
	if results[0].Token == (VaultFileChildToken{}) || results[1].Token == (VaultFileChildToken{}) ||
		results[0].Token == results[1].Token {
		t.Fatal("OWNED_BATCH_TOKENS_NOT_INDEPENDENT")
	}
	aChild := parent.vaultFileChildren[fx.a.journal]
	bChild := parent.vaultFileChildren[b.journal]
	if aChild == nil || bChild == nil || aChild == bChild {
		t.Fatal("OWNED_BATCH_CHILDREN_MISSING")
	}
	if aChild.fullFactorDeadline.IsZero() || !aChild.fullFactorDeadline.Equal(bChild.fullFactorDeadline) {
		t.Fatal("OWNED_BATCH_COMMON_PROOF_BUDGET_MISMATCH")
	}
	if aChild.idleDeadline.IsZero() || !aChild.idleDeadline.Equal(bChild.idleDeadline) {
		t.Fatal("OWNED_BATCH_COMMON_IDLE_BUDGET_MISMATCH")
	}
	if len(results[0].Items) != 1 || results[0].Items[0] == (VaultFileBaselineItem{}) ||
		len(results[1].Items) != 1 || results[1].Items[0] == (VaultFileBaselineItem{}) {
		t.Fatal("OWNED_BATCH_REAL_SUMMARIES_MISSING")
	}
	if err := parent.LockVaultFileChild(results[0].Token); err != nil {
		t.Fatal("OWNED_BATCH_CLOSE_A_FAILED")
	}
	if ownedChildAt(parent, fx.a.journal) != nil {
		t.Fatal("OWNED_BATCH_CLOSED_A_RETAINED")
	}
	if len(results[1].Items) != 1 || results[1].Items[0] == (VaultFileBaselineItem{}) {
		t.Fatal("OWNED_BATCH_DELIVERED_B_SUMMARY_CLEARED")
	}
	assertOwnedChildRead(t, parent, results[1].Token)
	if ownedChildAt(parent, b.journal) == nil {
		t.Fatal("OWNED_BATCH_B_LOST_AFTER_A_CLOSE")
	}
}

func TestUnlockSessionWithOwnedVaultFileChildrenIsolatesAndRejects(t *testing.T) {
	fx := newOwnedChildFixture(t)
	b := fx.addVault(t, "batch-isolated-b")
	var authCount atomic.Int32
	vaultFileOwnedBatchAuthForTest = func() { authCount.Add(1) }
	t.Cleanup(func() { vaultFileOwnedBatchAuthForTest = nil })

	t.Run("wrong-target-does-not-corrupt-b", func(t *testing.T) {
		wrongA := cloneVaultFileCheckpoint(fx.a.checkpoint)
		wrongA.OwnerRootPublicKey[0] ^= 0xff
		targets := []OwnedVaultFileTarget{
			{JournalPath: fx.a.journal, Checkpoint: wrongA, Options: VaultFileChildOptions{IncludeItemIDs: true}},
			{JournalPath: b.journal, Checkpoint: *b.checkpoint, Options: VaultFileChildOptions{IncludeItemIDs: true}},
		}
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, fx.password, fx.key, time.Minute, targets)
		if err != nil {
			t.Fatal("OWNED_BATCH_WRONG_TARGET_UNLOCK_FAILED")
		}
		t.Cleanup(parent.Lock)
		if authCount.Load() != 1 {
			t.Fatal("OWNED_BATCH_WRONG_TARGET_AUTH_NOT_ONCE")
		}
		if len(results) != 2 || !errors.Is(results[0].Err, ErrVaultFileOwnership) ||
			results[1].Err != nil {
			t.Fatal("OWNED_BATCH_WRONG_TARGET_RESULT_MISMATCH")
		}
		if ownedChildAt(parent, fx.a.journal) != nil {
			t.Fatal("OWNED_BATCH_WRONG_TARGET_REGISTERED_A")
		}
		if ownedChildAt(parent, b.journal) == nil {
			t.Fatal("OWNED_BATCH_WRONG_TARGET_LOST_B")
		}
		assertOwnedChildRead(t, parent, results[1].Token)
	})

	t.Run("account-auth-failure-no-parent", func(t *testing.T) {
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, []byte("wrong-batch-factor"), fx.key, time.Minute, ownedBatchTargets(b))
		if err == nil || parent != nil || results != nil {
			t.Fatal("OWNED_BATCH_ACCOUNT_FAILURE_DELIVERED")
		}
		if authCount.Load() != 0 {
			t.Fatal("OWNED_BATCH_ACCOUNT_FAILURE_AUTH_OBSERVED")
		}
	})

	t.Run("bounded-and-conflicting-inputs-before-auth", func(t *testing.T) {
		authCount.Store(0)
		tooMany := make([]OwnedVaultFileTarget, 0, maxOwnedVaultFileBatchTargets+1)
		for i := 0; i <= maxOwnedVaultFileBatchTargets; i++ {
			tooMany = append(tooMany, OwnedVaultFileTarget{
				JournalPath: b.journal,
				Checkpoint:  *b.checkpoint,
				Options:     VaultFileChildOptions{IncludeItemIDs: true},
			})
		}
		if parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, fx.password, fx.key, time.Minute, tooMany); err == nil || parent != nil || results != nil {
			t.Fatal("OWNED_BATCH_TOO_MANY_DELIVERED")
		}
		conflict := []OwnedVaultFileTarget{
			{JournalPath: b.journal, Checkpoint: *b.checkpoint, Options: VaultFileChildOptions{}},
			{JournalPath: b.journal, Checkpoint: *b.checkpoint, Options: VaultFileChildOptions{IncludeItemIDs: true}},
		}
		if parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, fx.password, fx.key, time.Minute, conflict); err == nil ||
			parent != nil || results != nil {
			t.Fatal("OWNED_BATCH_CONFLICT_DELIVERED")
		}
		if authCount.Load() != 0 {
			t.Fatal("OWNED_BATCH_INVALID_INPUT_AUTH_OBSERVED")
		}
	})

	t.Run("all-targets-fail-account-usable", func(t *testing.T) {
		wrongA := cloneVaultFileCheckpoint(fx.a.checkpoint)
		wrongA.OwnerRootKeyID = wrongA.OwnerRootKeyID + "-wrong"
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, fx.password, fx.key, time.Minute,
			[]OwnedVaultFileTarget{{JournalPath: fx.a.journal, Checkpoint: wrongA, Options: VaultFileChildOptions{IncludeItemIDs: true}}})
		if err != nil || parent == nil || len(results) != 1 ||
			!errors.Is(results[0].Err, ErrVaultFileOwnership) {
			t.Fatal("OWNED_BATCH_ALL_FAIL_LOST_ACCOUNT")
		}
		t.Cleanup(parent.Lock)
		if authCount.Load() != 1 {
			t.Fatal("OWNED_BATCH_ALL_FAIL_AUTH_NOT_ONCE")
		}
		if ownedChildAllCount(parent) != 0 {
			t.Fatal("OWNED_BATCH_ALL_FAIL_GRANTED_CHILD")
		}
		if _, err := parent.List("active"); err != nil {
			t.Fatal("OWNED_BATCH_ALL_FAIL_ACCOUNT_UNUSABLE")
		}
	})

	t.Run("empty-targets-valid-account", func(t *testing.T) {
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, fx.password, fx.key, time.Minute, nil)
		if err != nil || parent == nil || len(results) != 0 {
			t.Fatal("OWNED_BATCH_EMPTY_FAILED")
		}
		t.Cleanup(parent.Lock)
		if authCount.Load() != 1 {
			t.Fatal("OWNED_BATCH_EMPTY_AUTH_NOT_ONCE")
		}
		if ownedChildAllCount(parent) != 0 {
			t.Fatal("OWNED_BATCH_EMPTY_GRANTED_CHILD")
		}
		if _, err := parent.List("active"); err != nil {
			t.Fatal("OWNED_BATCH_EMPTY_ACCOUNT_UNUSABLE")
		}
	})

	t.Run("empty-targets-wrong-account", func(t *testing.T) {
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, []byte("wrong-empty-batch-factor"), fx.key, time.Minute, nil)
		if err == nil || parent != nil || results != nil {
			t.Fatal("OWNED_BATCH_EMPTY_WRONG_ACCOUNT_DELIVERED")
		}
		if authCount.Load() != 0 {
			t.Fatal("OWNED_BATCH_EMPTY_WRONG_ACCOUNT_AUTH_OBSERVED")
		}
	})

	t.Run("exact-duplicates-share-one-child", func(t *testing.T) {
		target := OwnedVaultFileTarget{
			JournalPath: b.journal,
			Checkpoint:  *b.checkpoint,
			Options:     VaultFileChildOptions{IncludeItemIDs: true},
		}
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
			context.Background(), fx.session.path, fx.password, fx.key, time.Minute,
			[]OwnedVaultFileTarget{target, target})
		if err != nil {
			t.Fatal("OWNED_BATCH_DUPLICATE_UNLOCK_FAILED")
		}
		t.Cleanup(parent.Lock)
		if authCount.Load() != 1 || len(results) != 2 ||
			results[0].Err != nil || results[1].Err != nil ||
			results[0].Token != results[1].Token {
			t.Fatal("OWNED_BATCH_DUPLICATE_NOT_DEDUPLICATED")
		}
		if ownedChildAllCount(parent) != 1 {
			t.Fatal("OWNED_BATCH_DUPLICATE_REGISTERED_TWICE")
		}
		if len(results[0].Items) != 1 || len(results[1].Items) != 1 ||
			results[0].Items[0] == (VaultFileBaselineItem{}) ||
			results[1].Items[0] == (VaultFileBaselineItem{}) {
			t.Fatal("OWNED_BATCH_DUPLICATE_SUMMARIES_MISSING")
		}
		results[0].Items[0].Title = "mutated-delivered-copy"
		if results[1].Items[0].Title == "mutated-delivered-copy" {
			t.Fatal("OWNED_BATCH_DUPLICATE_SUMMARIES_ALIASED")
		}
		assertOwnedChildRead(t, parent, results[0].Token)
	})
}

func TestUnlockSessionWithOwnedVaultFileChildrenCancellationDrainsOnlyBatch(t *testing.T) {
	fx := newOwnedChildFixture(t)
	b := fx.addVault(t, "batch-cancel-b")
	sibling := fx.addVault(t, "batch-cancel-sibling")
	siblingToken, _ := openOwnedChild(t, fx.session, sibling, fx.password, fx.key)
	assertOwnedChildRead(t, fx.session, siblingToken)

	var batchCloses atomic.Int32
	vaultFileChildBeforeHandleClose = func() { batchCloses.Add(1) }
	t.Cleanup(func() { vaultFileChildBeforeHandleClose = nil })

	ctx, cancel := context.WithCancel(context.Background())
	var opens atomic.Int32
	vaultFileChildCandidateReady = func(*vaultfile.ScopedUnlock) {
		if opens.Add(1) == 2 {
			cancel()
		}
	}
	t.Cleanup(func() { vaultFileChildCandidateReady = nil })

	var observed bool
	var observedCurrent []VaultFileBaselineItem
	var observedResults []OwnedVaultFileChildResult
	var observedResultItems [][]VaultFileBaselineItem
	var currentNonEmpty, resultNonEmpty bool
	vaultFileOwnedBatchUndeliveredForTest = func(current []VaultFileBaselineItem, results []OwnedVaultFileChildResult) {
		observed = true
		observedCurrent = current
		observedResults = results
		observedResultItems = make([][]VaultFileBaselineItem, len(results))
		currentNonEmpty = len(current) > 0
		for i := range results {
			observedResultItems[i] = results[i].Items
			if len(results[i].Items) > 0 {
				resultNonEmpty = true
			}
		}
	}
	t.Cleanup(func() { vaultFileOwnedBatchUndeliveredForTest = nil })

	parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
		ctx, fx.session.path, fx.password, fx.key, time.Minute, ownedBatchTargets(fx.a, b))
	if !errors.Is(err, context.Canceled) || parent != nil || results != nil {
		t.Fatal("OWNED_BATCH_CANCELLED_DELIVERED")
	}
	if !observed || !currentNonEmpty || !resultNonEmpty {
		t.Fatal("OWNED_BATCH_CANCEL_UNDELIVERED_SUMMARIES_NOT_OBSERVED")
	}
	if batchCloses.Load() != 2 {
		t.Fatal("OWNED_BATCH_CANCEL_DID_NOT_JOIN_BOTH_CLOSES")
	}
	for _, item := range observedCurrent {
		if item != (VaultFileBaselineItem{}) {
			t.Fatal("OWNED_BATCH_CANCEL_CURRENT_SUMMARY_NOT_CLEARED")
		}
	}
	for _, items := range observedResultItems {
		for _, item := range items {
			if item != (VaultFileBaselineItem{}) {
				t.Fatal("OWNED_BATCH_CANCEL_RESULT_SUMMARY_NOT_CLEARED")
			}
		}
	}
	for _, result := range observedResults {
		if result.Token != (VaultFileChildToken{}) || result.Items != nil {
			t.Fatal("OWNED_BATCH_CANCEL_RESULT_OWNERSHIP_NOT_CLEARED")
		}
	}
	assertOwnedChildRead(t, fx.session, siblingToken)
	if ownedChildAt(fx.session, sibling.journal) == nil {
		t.Fatal("OWNED_BATCH_CANCEL_DRAINED_EXISTING_SIBLING")
	}
}
