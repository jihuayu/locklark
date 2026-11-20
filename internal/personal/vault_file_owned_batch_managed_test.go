//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

type managedBatchScope struct {
	journal string
	target  VaultFileManagedDeviceSuccessorTarget
	pin     VaultFileManagedDeviceSuccessorPin
	receipt VaultFileManagedDeviceSuccessorReceipt
	items   []VaultFileBaselineItem
	public  VaultFileOwnershipPublic
}

type managedBatchScopes struct {
	base *managedSuccessorPublishFixture
	a    *managedBatchScope
	b    *managedBatchScope
}

// newManagedBatchScopes publishes two independently pinned managed successors
// for two distinct vaults into the same clean destination account, using the
// existing encrypted source fixtures and the real publish path.
func newManagedBatchScopes(t *testing.T) *managedBatchScopes {
	t.Helper()
	a := newManagedSuccessorPublishFixture(t, "managed-batch-a")
	b := newManagedSuccessorPublishFixture(t, "managed-batch-b")

	if _, err := a.destSession.RestoreVaultFileBackupCustodyOwner(context.Background(),
		b.artifact, b.expected, b.factor, b.binding, b.target); err != nil {
		t.Fatalf("MANAGED_BATCH_RESTORE_B_FAILED: %v", err)
	}
	receiptA, err := a.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		a.journalPath, a.target, a.pin)
	if err != nil {
		t.Fatalf("MANAGED_BATCH_PUBLISH_A_FAILED: %v", err)
	}
	t.Cleanup(receiptA.Clear)
	receiptB, err := a.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		b.journalPath, b.target, b.pin)
	if err != nil {
		t.Fatalf("MANAGED_BATCH_PUBLISH_B_FAILED: %v", err)
	}
	t.Cleanup(receiptB.Clear)
	if receiptA.VaultID == receiptB.VaultID || receiptA.OperationID == receiptB.OperationID ||
		receiptA.SuccessorRevision == receiptB.SuccessorRevision ||
		receiptA.SuccessorSHA256 == receiptB.SuccessorSHA256 ||
		receiptA.SuccessorRevision == "" || receiptA.OperationID == "" {
		t.Fatal("MANAGED_BATCH_PUBLISHED_IDENTITIES_NOT_INDEPENDENT")
	}
	a.destSession.Lock()
	a.destSession = nil
	return &managedBatchScopes{
		base: a,
		a: &managedBatchScope{
			journal: a.journalPath, target: a.target, pin: a.pin,
			receipt: receiptA, items: a.baseItems, public: a.public,
		},
		b: &managedBatchScope{
			journal: b.journalPath, target: b.target, pin: b.pin,
			receipt: receiptB, items: b.baseItems, public: b.public,
		},
	}
}

func newManagedBatchTarget(scope *managedBatchScope) OwnedVaultFileTarget {
	managed := cloneOwnedVaultFileManagedSuccessorTarget(OwnedVaultFileManagedSuccessorTarget{
		JournalPath:  scope.journal,
		BackendRoot:  scope.target.Root,
		BackendName:  scope.target.Name,
		Pin:          scope.pin,
		OperationID:  scope.receipt.OperationID,
		SuccessorRev: scope.receipt.SuccessorRevision,
	})
	return OwnedVaultFileTarget{
		JournalPath: scope.journal,
		Checkpoint:  cloneVaultFileCheckpoint(&scope.pin.Checkpoint),
		Options:     VaultFileChildOptions{IncludeItemIDs: true},
		Managed:     &managed,
	}
}

func assertManagedBatchItems(t *testing.T, got, want []VaultFileBaselineItem, code string) {
	t.Helper()
	if len(got) != len(want) || len(want) == 0 {
		t.Fatal(code)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(code)
		}
	}
}

func assertManagedBatchChild(t *testing.T, parent *Session, result OwnedVaultFileChildResult,
	scope *managedBatchScope, code string) {
	t.Helper()
	if result.Err != nil || result.Token == (VaultFileChildToken{}) {
		t.Fatal(code)
	}
	assertManagedBatchItems(t, result.Items, scope.items, code)
	child := parent.vaultFileChildren[scope.journal]
	if child == nil || child.managed == nil || child.successor != nil ||
		child.managed.operationID != scope.receipt.OperationID ||
		child.managed.successorRevision != scope.receipt.SuccessorRevision {
		t.Fatal(code)
	}
	read, err := parent.ReadVaultFileChild(result.Token, VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal(code)
	}
	defer clearVaultFileChildItems(read)
	assertManagedBatchItems(t, read, scope.items, code)
}

func TestUnlockSessionWithOwnedVaultFileChildrenManagedSuccessorBatch(t *testing.T) {
	scopes := newManagedBatchScopes(t)
	if scopes.a.journal == scopes.b.journal ||
		scopes.a.pin.SealedSHA256 == scopes.b.pin.SealedSHA256 ||
		scopes.a.pin.BackendRevision == scopes.b.pin.BackendRevision {
		t.Fatal("MANAGED_BATCH_SCOPES_NOT_INDEPENDENT")
	}
	var authCount atomic.Int32
	vaultFileOwnedBatchAuthForTest = func() { authCount.Add(1) }
	t.Cleanup(func() { vaultFileOwnedBatchAuthForTest = nil })

	t.Run("dual-managed-success", func(t *testing.T) {
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(context.Background(),
			scopes.base.destPath, scopes.base.destPassword, scopes.base.destKey, time.Minute,
			[]OwnedVaultFileTarget{newManagedBatchTarget(scopes.a), newManagedBatchTarget(scopes.b)})
		if err != nil {
			t.Fatalf("MANAGED_BATCH_DUAL_UNLOCK_FAILED: %v", err)
		}
		t.Cleanup(parent.Lock)
		if authCount.Load() != 1 {
			t.Fatal("MANAGED_BATCH_DUAL_AUTH_NOT_ONCE")
		}
		if len(results) != 2 || results[0].Token == (VaultFileChildToken{}) ||
			results[1].Token == (VaultFileChildToken{}) ||
			results[0].Token == results[1].Token {
			t.Fatal("MANAGED_BATCH_DUAL_RESULTS_INVALID")
		}
		assertManagedBatchChild(t, parent, results[0], scopes.a,
			"MANAGED_BATCH_DUAL_A_PROJECTION_FAILED")
		assertManagedBatchChild(t, parent, results[1], scopes.b,
			"MANAGED_BATCH_DUAL_B_PROJECTION_FAILED")
		if ownedChildAllCount(parent) != 2 {
			t.Fatal("MANAGED_BATCH_DUAL_CHILD_COUNT_CHANGED")
		}
		owners, err := parent.VaultFileOwnerships()
		if err != nil || len(owners) != 2 || owners[0] == owners[1] ||
			(owners[0] != scopes.a.public && owners[1] != scopes.a.public) ||
			(owners[0] != scopes.b.public && owners[1] != scopes.b.public) {
			t.Fatal("MANAGED_BATCH_DUAL_OWNER_PROJECTION_CHANGED")
		}
		if err := parent.LockVaultFileChild(results[0].Token); err != nil {
			t.Fatal("MANAGED_BATCH_DUAL_CLOSE_A_FAILED")
		}
		if closed, err := parent.ReadVaultFileChild(results[0].Token,
			VaultFileChildOptions{IncludeItemIDs: true}); !errors.Is(err, ErrVaultFileScopedChild) ||
			len(closed) != 0 {
			clearVaultFileChildItems(closed)
			t.Fatal("MANAGED_BATCH_DUAL_CLOSED_A_STILL_READS")
		}
		stillB, err := parent.ReadVaultFileChild(results[1].Token,
			VaultFileChildOptions{IncludeItemIDs: true})
		if err != nil {
			t.Fatal("MANAGED_BATCH_DUAL_B_HURT_BY_A_CLOSE")
		}
		defer clearVaultFileChildItems(stillB)
		assertManagedBatchItems(t, stillB, scopes.b.items,
			"MANAGED_BATCH_DUAL_B_CHANGED_BY_A_CLOSE")
	})
}

func TestUnlockSessionWithOwnedVaultFileChildrenManagedSuccessorRefusals(t *testing.T) {
	scopes := newManagedBatchScopes(t)
	var authCount atomic.Int32
	vaultFileOwnedBatchAuthForTest = func() { authCount.Add(1) }
	t.Cleanup(func() { vaultFileOwnedBatchAuthForTest = nil })

	assertRefusedAStillReadsB := func(t *testing.T, mutate func(*OwnedVaultFileTarget),
		want error, code string) {
		t.Helper()
		badA := newManagedBatchTarget(scopes.a)
		mutate(&badA)
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(context.Background(),
			scopes.base.destPath, scopes.base.destPassword, scopes.base.destKey, time.Minute,
			[]OwnedVaultFileTarget{badA, newManagedBatchTarget(scopes.b)})
		if err != nil {
			t.Fatalf("%s_UNLOCK_FAILED: %v", code, err)
		}
		t.Cleanup(parent.Lock)
		if authCount.Load() != 1 {
			t.Fatal(code + "_AUTH_NOT_ONCE")
		}
		if len(results) != 2 || results[0].Err == nil ||
			!errors.Is(results[0].Err, want) {
			t.Fatalf("%s_A_ERROR_MISMATCH: %v", code, results[0].Err)
		}
		if results[0].Token != (VaultFileChildToken{}) || len(results[0].Items) != 0 {
			t.Fatal(code + "_A_LEAKED_TOKEN_OR_ITEMS")
		}
		if parent.vaultFileChildren[scopes.a.journal] != nil {
			t.Fatal(code + "_A_REGISTERED_CHILD")
		}
		assertManagedBatchChild(t, parent, results[1], scopes.b, code+"_B_PROJECTION_FAILED")
	}

	t.Run("wrong-expected-operation", func(t *testing.T) {
		assertRefusedAStillReadsB(t, func(target *OwnedVaultFileTarget) {
			target.Managed.OperationID = target.Managed.OperationID + "-wrong"
		}, ErrVaultFileManagedDeviceSuccessorReopen, "MANAGED_BATCH_WRONG_OPERATION")
	})

	t.Run("wrong-expected-settled-revision", func(t *testing.T) {
		assertRefusedAStillReadsB(t, func(target *OwnedVaultFileTarget) {
			target.Managed.SuccessorRev = vaultfilebackend.Revision("\"wrong-settled-revision\"")
		}, ErrVaultFileManagedDeviceSuccessorReopen, "MANAGED_BATCH_WRONG_SETTLED_REVISION")
	})

	t.Run("missing-managed-journal", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing-managed.journal")
		assertRefusedAStillReadsB(t, func(target *OwnedVaultFileTarget) {
			target.JournalPath = missing
			target.Managed.JournalPath = missing
		}, ErrVaultFileManagedDeviceSuccessorPath, "MANAGED_BATCH_MISSING_JOURNAL")
	})

	t.Run("exact-backend-drift", func(t *testing.T) {
		copyRoot := filepath.Join(t.TempDir(), "managed-batch-copied-backend")
		copyManagedSuccessorBackendRoot(t, scopes.a.target.Root, copyRoot)
		assertRefusedAStillReadsB(t, func(target *OwnedVaultFileTarget) {
			target.Managed.BackendRoot = copyRoot
		}, ErrVaultFileManagedDeviceSuccessorConflict, "MANAGED_BATCH_BACKEND_DRIFT")
	})
}

func TestUnlockSessionWithOwnedVaultFileChildrenManagedSuccessorPreAuth(t *testing.T) {
	scopes := newManagedBatchScopes(t)
	var authCount atomic.Int32
	vaultFileOwnedBatchAuthForTest = func() { authCount.Add(1) }
	t.Cleanup(func() { vaultFileOwnedBatchAuthForTest = nil })
	missingAccount := filepath.Join(t.TempDir(), "missing-account.ll")

	refuseBeforeAuth := func(t *testing.T, targets []OwnedVaultFileTarget, want error, code string) {
		t.Helper()
		authCount.Store(0)
		parent, results, err := UnlockSessionWithOwnedVaultFileChildren(context.Background(),
			missingAccount, scopes.base.destPassword, scopes.base.destKey, time.Minute, targets)
		if !errors.Is(err, want) || parent != nil || results != nil {
			t.Fatalf("%s_NOT_REFUSED: %v", code, err)
		}
		if authCount.Load() != 0 {
			t.Fatal(code + "_ACCOUNT_AUTH_OBSERVED")
		}
	}

	t.Run("invalid-explicit-targets", func(t *testing.T) {
		bothModes := newManagedBatchTarget(scopes.a)
		bothModes.Successor = &OwnedVaultFileFirstSuccessorTarget{
			BackendRoot: scopes.a.target.Root,
			BackendName: scopes.a.target.Name,
			Pin: vaultfilejournal.OwnedGenesisPin{
				Root: vaultfile.GenesisRootPin{
					VaultID:            scopes.a.pin.Checkpoint.VaultID,
					OwnerRootKeyID:     scopes.a.pin.Checkpoint.OwnerRootKeyID,
					OwnerRootPublicKey: bytes.Clone(scopes.a.pin.Checkpoint.OwnerRootPublicKey),
				},
				SealedSHA256: scopes.a.pin.SealedSHA256,
				OperationID:  scopes.a.receipt.OperationID,
			},
		}
		refuseBeforeAuth(t, []OwnedVaultFileTarget{bothModes},
			ErrVaultFileBaselineVerification, "MANAGED_BATCH_BOTH_MODES")

		journalMismatch := newManagedBatchTarget(scopes.a)
		journalMismatch.Managed.JournalPath = scopes.b.journal
		refuseBeforeAuth(t, []OwnedVaultFileTarget{journalMismatch},
			ErrVaultFileBaselineVerification, "MANAGED_BATCH_JOURNAL_MISMATCH")

		checkpointMismatch := newManagedBatchTarget(scopes.a)
		checkpointMismatch.Managed.Pin.Checkpoint.PolicySeq++
		refuseBeforeAuth(t, []OwnedVaultFileTarget{checkpointMismatch},
			ErrVaultFileBaselineVerification, "MANAGED_BATCH_PIN_CHECKPOINT_MISMATCH")

		batchCheckpointMismatch := newManagedBatchTarget(scopes.a)
		batchCheckpointMismatch.Checkpoint.PolicySeq++
		refuseBeforeAuth(t, []OwnedVaultFileTarget{batchCheckpointMismatch},
			ErrVaultFileBaselineVerification, "MANAGED_BATCH_INPUT_CHECKPOINT_MISMATCH")

		emptyOperation := newManagedBatchTarget(scopes.a)
		emptyOperation.Managed.OperationID = ""
		refuseBeforeAuth(t, []OwnedVaultFileTarget{emptyOperation},
			ErrVaultFileBaselineVerification, "MANAGED_BATCH_EMPTY_OPERATION")

		emptyRevision := newManagedBatchTarget(scopes.a)
		emptyRevision.Managed.SuccessorRev = ""
		refuseBeforeAuth(t, []OwnedVaultFileTarget{emptyRevision},
			ErrVaultFileBaselineVerification, "MANAGED_BATCH_EMPTY_REVISION")
	})

	t.Run("conflicting-same-journal", func(t *testing.T) {
		first := newManagedBatchTarget(scopes.a)
		second := newManagedBatchTarget(scopes.a)
		second.Managed.OperationID = second.Managed.OperationID + "-other"
		refuseBeforeAuth(t, []OwnedVaultFileTarget{first, second},
			ErrVaultFileScopedChild, "MANAGED_BATCH_OPERATION_CONFLICT")

		plain := OwnedVaultFileTarget{
			JournalPath: scopes.a.journal,
			Checkpoint:  cloneVaultFileCheckpoint(&scopes.a.pin.Checkpoint),
			Options:     VaultFileChildOptions{IncludeItemIDs: true},
		}
		refuseBeforeAuth(t, []OwnedVaultFileTarget{plain, newManagedBatchTarget(scopes.a)},
			ErrVaultFileScopedChild, "MANAGED_BATCH_MODE_CONFLICT")

		otherName := newManagedBatchTarget(scopes.a)
		otherName.Managed.BackendName = "owned-recovery-import-other"
		refuseBeforeAuth(t, []OwnedVaultFileTarget{newManagedBatchTarget(scopes.a), otherName},
			ErrVaultFileScopedChild, "MANAGED_BATCH_BACKEND_CONFLICT")

		otherPin := newManagedBatchTarget(scopes.a)
		otherPin.Managed.Pin.KeyEpoch++
		refuseBeforeAuth(t, []OwnedVaultFileTarget{newManagedBatchTarget(scopes.a), otherPin},
			ErrVaultFileScopedChild, "MANAGED_BATCH_PIN_CONFLICT")

		otherOptions := newManagedBatchTarget(scopes.a)
		otherOptions.Options = VaultFileChildOptions{}
		refuseBeforeAuth(t, []OwnedVaultFileTarget{newManagedBatchTarget(scopes.a), otherOptions},
			ErrVaultFileScopedChild, "MANAGED_BATCH_OPTIONS_CONFLICT")
	})
}

func TestUnlockSessionWithOwnedVaultFileChildrenManagedSuccessorDuplicate(t *testing.T) {
	scopes := newManagedBatchScopes(t)
	var authCount atomic.Int32
	vaultFileOwnedBatchAuthForTest = func() { authCount.Add(1) }
	t.Cleanup(func() { vaultFileOwnedBatchAuthForTest = nil })

	authCount.Store(0)
	parent, results, err := UnlockSessionWithOwnedVaultFileChildren(context.Background(),
		scopes.base.destPath, scopes.base.destPassword, scopes.base.destKey, time.Minute,
		[]OwnedVaultFileTarget{newManagedBatchTarget(scopes.a), newManagedBatchTarget(scopes.a)})
	if err != nil {
		t.Fatalf("MANAGED_BATCH_DUPLICATE_UNLOCK_FAILED: %v", err)
	}
	t.Cleanup(parent.Lock)
	if authCount.Load() != 1 || len(results) != 2 ||
		results[0].Err != nil || results[1].Err != nil ||
		results[0].Token == (VaultFileChildToken{}) || results[0].Token != results[1].Token {
		t.Fatal("MANAGED_BATCH_DUPLICATE_NOT_DEDUPLICATED")
	}
	if ownedChildAllCount(parent) != 1 {
		t.Fatal("MANAGED_BATCH_DUPLICATE_REGISTERED_TWICE")
	}
	assertManagedBatchItems(t, results[0].Items, scopes.a.items,
		"MANAGED_BATCH_DUPLICATE_A_PROJECTION_FAILED")
	assertManagedBatchItems(t, results[1].Items, scopes.a.items,
		"MANAGED_BATCH_DUPLICATE_B_PROJECTION_FAILED")
	if len(results[0].Items) == 0 {
		t.Fatal("MANAGED_BATCH_DUPLICATE_NO_ITEMS")
	}
	results[0].Items[0].Title = "mutated-managed-batch-copy"
	if results[1].Items[0].Title == "mutated-managed-batch-copy" {
		t.Fatal("MANAGED_BATCH_DUPLICATE_SUMMARIES_ALIASED")
	}
}
