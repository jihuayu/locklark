//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// localManagedQueryScope is one real dual-clean recovery destination scope:
// the independently transported selector, the exact settled receipt and the
// focused source projection that the recovered item must still produce.
type localManagedQueryScope struct {
	selector   LocalManagedRecoverySelector
	receipt    personal.VaultFileManagedDeviceSuccessorReceipt
	expected   []personal.VaultFileBaselineItem
	locator    LocalOwnedBackupRestoreBackendLocator
	initial    []byte
	initialRev vaultfilebackend.Revision
}

type localManagedQueryFixture struct {
	accountPath   string
	password, key []byte
	a, b          *localManagedQueryScope
}

func (s *localManagedQueryScope) candidate() LocalGenesisBatchCandidate {
	return LocalGenesisBatchCandidate{
		WorkspaceRoot: s.selector.WorkspaceRoot,
		VaultID:       s.selector.VaultID,
		JournalPath:   s.selector.JournalPath,
		Managed:       cloneLocalManagedRecoverySelector(&s.selector),
	}
}

func clearLocalManagedQueryScope(s *localManagedQueryScope) {
	if s == nil {
		return
	}
	clearLocalManagedRecoverySelector(&s.selector)
	clear(s.expected)
	clear(s.initial)
	s.receipt.Clear()
	*s = localManagedQueryScope{}
}

// newLocalManagedQueryFixture builds the existing real dual-clean recovery:
// two independent source accounts/vaults, their transferred artifacts and
// journals, one fresh destination account that restores both owners, and the
// two genuine managed-successor publications through the normal personal path.
// The destination session is then locked; every later read must start from an
// explicit selector, the durable account and the two dedicated journals.
func newLocalManagedQueryFixture(t *testing.T) *localManagedQueryFixture {
	t.Helper()
	passwordA := []byte("local-managed-query-source-a")
	keyA := bytes.Repeat([]byte{0x61}, 16)
	passwordB := []byte("local-managed-query-source-b")
	keyB := bytes.Repeat([]byte{0x72}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)

	fxA := newLocalCustodyFileFixture(t, "managed-query-a", passwordA, keyA,
		localFirstWriteSecret+"-managed-query-a")
	fxB := newLocalCustodyFileFixture(t, "managed-query-b", passwordB, keyB,
		localFirstWriteSecret+"-managed-query-b")
	transferA := newLocalRestorePreflightFixture(t, fxA, "managed-query-a")
	transferB := newLocalRestorePreflightFixture(t, fxB, "managed-query-b")
	expectedA := localCleanRecoveryExpectedItems(t, fxA)
	expectedB := localCleanRecoveryExpectedItems(t, fxB)
	if len(expectedA) != 1 || len(expectedB) != 1 ||
		expectedA[0].Title != expectedB[0].Title ||
		expectedA[0].ID == expectedB[0].ID {
		t.Fatal("LOCAL_MANAGED_QUERY_SOURCE_PROJECTION_FAILED")
	}
	artifactA := bytes.Clone(fxA.artifact)
	artifactB := bytes.Clone(fxB.artifact)
	t.Cleanup(func() {
		clear(artifactA)
		clear(artifactB)
		clearLocalGenesisItems(expectedA)
		clearLocalGenesisItems(expectedB)
	})
	sourceTargetA, sourceRevisionA := localRestorePreflightTarget(t, fxA.v)
	sourceTargetB, sourceRevisionB := localRestorePreflightTarget(t, fxB.v)
	defer clear(sourceTargetA)
	defer clear(sourceTargetB)
	localCleanRecoveryCloseSource(t, fxA)
	localCleanRecoveryCloseSource(t, fxB)

	destPassword := []byte("local-managed-query-destination")
	destKey := bytes.Repeat([]byte{0x48}, 16)
	dest := localIsolationCreation(t, "managed-query-destination", destPassword, destKey)
	destination, err := personal.UnlockSession(dest.proposal.PersonalFile, destPassword, destKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_QUERY_DESTINATION_UNLOCK_FAILED")
	}
	if _, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transferA.path, transferA.pin, transferA.expected, fxA.factor,
		transferA.locator, destination); err != nil {
		t.Fatal("LOCAL_MANAGED_QUERY_RESTORE_A_FAILED")
	}
	if _, err := RestoreTransferredLocalOwnedBackupOwner(context.Background(),
		transferB.path, transferB.pin, transferB.expected, fxB.factor,
		transferB.locator, destination); err != nil {
		t.Fatal("LOCAL_MANAGED_QUERY_RESTORE_B_FAILED")
	}
	vaultA := localCleanRecoveryPrepareTarget(t, "managed-query-a", fxA, transferA,
		artifactA, sourceTargetA, sourceRevisionA, dest.root, destination)
	vaultB := localCleanRecoveryPrepareTarget(t, "managed-query-b", fxB, transferB,
		artifactB, sourceTargetB, sourceRevisionB, dest.root, destination)
	receiptA, err := destination.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		vaultA.journal, personal.VaultFileManagedDeviceSuccessorTarget{
			Root: transferA.locator.Root, Name: transferA.locator.Name,
		}, vaultA.pin)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_QUERY_PUBLISH_A_FAILED")
	}
	receiptB, err := destination.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		vaultB.journal, personal.VaultFileManagedDeviceSuccessorTarget{
			Root: transferB.locator.Root, Name: transferB.locator.Name,
		}, vaultB.pin)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_QUERY_PUBLISH_B_FAILED")
	}
	if receiptA.OperationID == receiptB.OperationID ||
		receiptA.SuccessorRevision == receiptB.SuccessorRevision ||
		receiptA.SuccessorSHA256 == receiptB.SuccessorSHA256 ||
		receiptA.VaultID == receiptB.VaultID ||
		receiptA.OperationID == "" || receiptA.SuccessorRevision == "" {
		t.Fatal("LOCAL_MANAGED_QUERY_PUBLISHED_IDENTITIES_NOT_INDEPENDENT")
	}
	destination.Lock()

	fixture := &localManagedQueryFixture{
		accountPath: dest.proposal.PersonalFile,
		password:    bytes.Clone(destPassword),
		key:         bytes.Clone(destKey),
		a: &localManagedQueryScope{
			selector: LocalManagedRecoverySelector{
				AccountPath:   dest.proposal.PersonalFile,
				WorkspaceRoot: transferA.locator.Root,
				BackendName:   transferA.locator.Name,
				VaultID:       vaultA.pin.Checkpoint.VaultID,
				JournalPath:   vaultA.journal,
				Pin:           cloneLocalManagedRecoveryPin(vaultA.pin),
				OperationID:   receiptA.OperationID,
				SuccessorRev:  receiptA.SuccessorRevision,
			},
			receipt:  receiptA,
			expected: expectedA,
			locator:  transferA.locator,
		},
		b: &localManagedQueryScope{
			selector: LocalManagedRecoverySelector{
				AccountPath:   dest.proposal.PersonalFile,
				WorkspaceRoot: transferB.locator.Root,
				BackendName:   transferB.locator.Name,
				VaultID:       vaultB.pin.Checkpoint.VaultID,
				JournalPath:   vaultB.journal,
				Pin:           cloneLocalManagedRecoveryPin(vaultB.pin),
				OperationID:   receiptB.OperationID,
				SuccessorRev:  receiptB.SuccessorRevision,
			},
			receipt:  receiptB,
			expected: expectedB,
			locator:  transferB.locator,
		},
	}
	for _, scope := range []*localManagedQueryScope{fixture.a, fixture.b} {
		raw, revision := localCleanRecoveryReadTarget(t, scope.locator)
		scope.initial, scope.initialRev = raw, revision
	}
	t.Cleanup(func() {
		clear(fixture.password)
		clear(fixture.key)
		clearLocalManagedQueryScope(fixture.a)
		clearLocalManagedQueryScope(fixture.b)
	})
	return fixture
}

func (f *localManagedQueryFixture) open(t *testing.T, ctx context.Context,
	candidates []LocalGenesisBatchCandidate) (*personal.Session, []LocalGenesisBatchResult, error) {
	t.Helper()
	return OpenLocalGenesisSessionsForAccount(ctx, f.accountPath, f.password, f.key,
		time.Minute, candidates)
}

func assertLocalManagedScope(t *testing.T, got *LocalManagedRecoveryScope,
	want LocalManagedRecoveryScope, code string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatal(code)
	}
}

func assertLocalManagedTargetPreserved(t *testing.T, scope *localManagedQueryScope, code string) {
	t.Helper()
	raw, revision := localCleanRecoveryReadTarget(t, scope.locator)
	defer clear(raw)
	if revision != scope.initialRev || !bytes.Equal(raw, scope.initial) ||
		sha256.Sum256(raw) != sha256.Sum256(scope.initial) {
		t.Fatal(code)
	}
}

func TestOpenLocalGenesisSessionsForAccountManagedExactQuery(t *testing.T) {
	fx := newLocalManagedQueryFixture(t)
	title := localFirstWriteTitle

	t.Run("dual-query-and-activation", func(t *testing.T) {
		var batches int
		localGenesisBatchAfterAuthForTest = func() { batches++ }
		t.Cleanup(func() { localGenesisBatchAfterAuthForTest = nil })

		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{fx.a.candidate(), fx.b.candidate()})
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatalf("LOCAL_MANAGED_QUERY_DUAL_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		if batches != 1 {
			t.Fatal("LOCAL_MANAGED_QUERY_DUAL_NOT_ONE_BATCH")
		}
		for index := range results {
			if results[index].Index != index || results[index].Err != nil ||
				results[index].Wrapper == nil || results[index].Baseline.VaultID == "" {
				t.Fatal("LOCAL_MANAGED_QUERY_DUAL_RESULT_INVALID")
			}
		}
		if results[0].Wrapper == results[1].Wrapper ||
			results[0].Baseline.VaultID != fx.a.selector.VaultID ||
			results[1].Baseline.VaultID != fx.b.selector.VaultID {
			t.Fatal("LOCAL_MANAGED_QUERY_DUAL_SCOPES_NOT_INDEPENDENT")
		}
		if sumA, err := results[0].Wrapper.Summary(); err != nil ||
			sumA.VaultID != fx.a.selector.VaultID {
			t.Fatal("LOCAL_MANAGED_QUERY_DUAL_SUMMARY_A_FAILED")
		}
		if sumB, err := results[1].Wrapper.Summary(); err != nil ||
			sumB.VaultID != fx.b.selector.VaultID {
			t.Fatal("LOCAL_MANAGED_QUERY_DUAL_SUMMARY_B_FAILED")
		}

		resultA, err := results[0].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(resultA.Hits) != 1 {
			t.Fatalf("LOCAL_MANAGED_QUERY_A_QUERY_FAILED: %v", err)
		}
		resultB, err := results[1].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(resultB.Hits) != 1 {
			t.Fatalf("LOCAL_MANAGED_QUERY_B_QUERY_FAILED: %v", err)
		}
		if resultA.Hits[0].ID != fx.a.expected[0].ID ||
			resultB.Hits[0].ID != fx.b.expected[0].ID ||
			resultA.Hits[0].ID == resultB.Hits[0].ID {
			t.Fatal("LOCAL_MANAGED_QUERY_HIT_PROJECTION_MISMATCH")
		}
		hitA, hitB := resultA.Hits[0], resultB.Hits[0]
		if resultA.ConfigPath != "" || resultA.ManifestSHA256 != "" ||
			resultB.ConfigPath != "" || resultB.ManifestSHA256 != "" ||
			resultA.JournalRevision != string(fx.a.selector.SuccessorRev) ||
			resultB.JournalRevision != string(fx.b.selector.SuccessorRev) {
			t.Fatal("LOCAL_MANAGED_QUERY_SCOPE_SHAPE_INVALID")
		}
		assertLocalManagedScope(t, resultA.Managed, fx.a.selector.scope(),
			"LOCAL_MANAGED_QUERY_A_SCOPE_MISMATCH")
		assertLocalManagedScope(t, resultB.Managed, fx.b.selector.scope(),
			"LOCAL_MANAGED_QUERY_B_SCOPE_MISMATCH")

		if err := results[0].Wrapper.ValidateExactQueryHit(resultA,
			hitA.ID, title); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_A_ACTIVATION_FAILED")
		}
		if err := results[1].Wrapper.ValidateExactQueryHit(resultB,
			hitB.ID, title); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_B_ACTIVATION_FAILED")
		}

		// A result/child is bound to its exact wrapper. Cross-proof,
		// cross-vault and cross-receiver activation are refused without
		// touching the valid sibling.
		if err := results[1].Wrapper.ValidateExactQueryHit(resultA,
			hitA.ID, title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("LOCAL_MANAGED_QUERY_CROSS_RECEIVER_ACCEPTED")
		}
		if err := results[0].Wrapper.ValidateExactQueryHit(resultA,
			hitB.ID, title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("LOCAL_MANAGED_QUERY_CROSS_VAULT_HIT_ACCEPTED")
		}

		changed := resultA
		changed.JournalRevision = "foreign-revision"
		if err := results[0].Wrapper.ValidateExactQueryHit(changed,
			hitA.ID, title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("LOCAL_MANAGED_QUERY_CHANGED_REVISION_ACCEPTED")
		}
		scope := *resultA.Managed
		scope.SuccessorRevision = "foreign-successor-revision"
		changed = resultA
		changed.Managed = &scope
		if err := results[0].Wrapper.ValidateExactQueryHit(changed,
			hitA.ID, title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("LOCAL_MANAGED_QUERY_CHANGED_MANAGED_REVISION_ACCEPTED")
		}
		scope = *resultA.Managed
		scope.JournalPath = fx.b.selector.JournalPath
		changed = resultA
		changed.Managed = &scope
		if err := results[0].Wrapper.ValidateExactQueryHit(changed,
			hitA.ID, title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("LOCAL_MANAGED_QUERY_CHANGED_SELECTED_SCOPE_ACCEPTED")
		}
		changed = resultA
		changed.Hits = append([]personal.VaultFileBaselineItem(nil), resultA.Hits...)
		changed.Hits[0] = hitB
		if err := results[0].Wrapper.ValidateExactQueryHit(changed,
			hitB.ID, title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("LOCAL_MANAGED_QUERY_UNRETURNED_HIT_ACCEPTED")
		}
		if err := results[0].Wrapper.ValidateExactQueryHit(resultA,
			hitA.ID, title); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_IMMUTABLE_PROOF_LOST")
		}

		// Closing A must refuse only A. B stays independently live and
		// current, and neither selected backend object changes.
		if err := results[0].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_CLOSE_A_FAILED")
		}
		if _, err := results[0].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1}); err == nil {
			t.Fatal("LOCAL_MANAGED_QUERY_CLOSED_A_STILL_QUERIES")
		}
		if _, err := results[0].Wrapper.Summary(); err == nil {
			t.Fatal("LOCAL_MANAGED_QUERY_CLOSED_A_STILL_SUMMARISES")
		}
		liveB, err := results[1].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(liveB.Hits) != 1 || liveB.Hits[0].ID != fx.b.expected[0].ID {
			t.Fatalf("LOCAL_MANAGED_QUERY_A_CLOSE_HURT_B: %v", err)
		}
		if err := results[1].Wrapper.ValidateExactQueryHit(liveB,
			liveB.Hits[0].ID, title); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_B_ACTIVATION_AFTER_A_CLOSE_FAILED")
		}
		if err := results[1].Wrapper.ValidateExactQueryHit(resultA,
			hitA.ID, title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("LOCAL_MANAGED_QUERY_CLOSED_A_PROOF_ACCEPTED_BY_B")
		}
		if !parent.Unlocked() {
			t.Fatal("LOCAL_MANAGED_QUERY_A_CLOSE_LOCKED_PARENT")
		}
		assertLocalManagedTargetPreserved(t, fx.a,
			"LOCAL_MANAGED_QUERY_TARGET_A_CHANGED")
		assertLocalManagedTargetPreserved(t, fx.b,
			"LOCAL_MANAGED_QUERY_TARGET_B_CHANGED")
		if err := results[1].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_CLOSE_B_FAILED")
		}
	})

	t.Run("wrong-selector-is-target-local", func(t *testing.T) {
		bad := fx.a.candidate()
		bad.Managed.OperationID += "-wrong"
		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{bad, fx.b.candidate()})
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatalf("LOCAL_MANAGED_QUERY_WRONG_OPERATION_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		if !errors.Is(results[0].Err, ErrLocalReview) ||
			results[0].Wrapper != nil || len(results[0].Baseline.Items) != 0 {
			t.Fatal("LOCAL_MANAGED_QUERY_WRONG_OPERATION_NOT_LOCAL")
		}
		if results[1].Err != nil || results[1].Wrapper == nil {
			t.Fatal("LOCAL_MANAGED_QUERY_WRONG_OPERATION_HURT_B")
		}
		resultB, err := results[1].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(resultB.Hits) != 1 || resultB.Hits[0].ID != fx.b.expected[0].ID {
			t.Fatal("LOCAL_MANAGED_QUERY_WRONG_OPERATION_B_QUERY_FAILED")
		}
		if err := results[1].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_WRONG_OPERATION_CLOSE_B_FAILED")
		}
		assertLocalManagedTargetPreserved(t, fx.a,
			"LOCAL_MANAGED_QUERY_WRONG_OPERATION_WROTE_A")
		assertLocalManagedTargetPreserved(t, fx.b,
			"LOCAL_MANAGED_QUERY_WRONG_OPERATION_WROTE_B")
	})

	t.Run("foreign-account-selector-is-local", func(t *testing.T) {
		bad := fx.a.candidate()
		bad.Managed.AccountPath = fx.a.selector.AccountPath + ".other"
		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{bad, fx.b.candidate()})
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatalf("LOCAL_MANAGED_QUERY_FOREIGN_ACCOUNT_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		if !errors.Is(results[0].Err, ErrLocalReview) || results[0].Wrapper != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_FOREIGN_ACCOUNT_NOT_LOCAL")
		}
		if results[1].Err != nil || results[1].Wrapper == nil {
			t.Fatal("LOCAL_MANAGED_QUERY_FOREIGN_ACCOUNT_HURT_B")
		}
		if err := results[1].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_FOREIGN_ACCOUNT_CLOSE_B_FAILED")
		}
	})

	t.Run("duplicate-and-conflicting-selectors", func(t *testing.T) {
		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{fx.a.candidate(), fx.a.candidate()})
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatalf("LOCAL_MANAGED_QUERY_DUPLICATE_DELIVERY_FAILED: %v", err)
		}
		if results[0].Err != nil || results[1].Err != nil ||
			results[0].Wrapper == nil || results[0].Wrapper != results[1].Wrapper ||
			results[0].Baseline.VaultID != fx.a.selector.VaultID {
			parent.Lock()
			t.Fatal("LOCAL_MANAGED_QUERY_DUPLICATE_NOT_SHARED")
		}
		if err := results[0].Wrapper.Close(); err != nil {
			parent.Lock()
			t.Fatal("LOCAL_MANAGED_QUERY_DUPLICATE_CLOSE_FAILED")
		}
		parent.Lock()

		other := fx.a.candidate()
		other.Managed.SuccessorRev = "another-settled-revision"
		parent, results, err = fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{fx.a.candidate(), other})
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatalf("LOCAL_MANAGED_QUERY_CONFLICT_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		for index := range results {
			if !errors.Is(results[index].Err, ErrLocalReview) ||
				results[index].Wrapper != nil || len(results[index].Baseline.Items) != 0 {
				t.Fatal("LOCAL_MANAGED_QUERY_ALIAS_CONFLICT_NOT_LOCAL")
			}
		}
	})

	t.Run("cancellation-drains-all-children", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		observed := false
		closedWrappers, summaryBuffers := 0, 0
		summariesCleared := false
		localGenesisBatchBeforeDeliveryForTest = func() { cancel() }
		localGenesisBatchCleanupForTest = func(closed, summaries int, cleared bool) {
			observed = true
			closedWrappers, summaryBuffers, summariesCleared = closed, summaries, cleared
		}
		t.Cleanup(func() {
			localGenesisBatchBeforeDeliveryForTest = nil
			localGenesisBatchCleanupForTest = nil
		})
		parent, results, err := fx.open(t, ctx,
			[]LocalGenesisBatchCandidate{fx.a.candidate(), fx.b.candidate()})
		localGenesisBatchBeforeDeliveryForTest = nil
		localGenesisBatchCleanupForTest = nil
		if !errors.Is(err, context.Canceled) || parent != nil || results != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_CANCEL_DELIVERED")
		}
		if !observed || closedWrappers != 2 || summaryBuffers != 2 || !summariesCleared {
			t.Fatal("LOCAL_MANAGED_QUERY_CANCEL_CLEANUP_INCOMPLETE")
		}
		assertLocalManagedTargetPreserved(t, fx.a,
			"LOCAL_MANAGED_QUERY_CANCEL_WROTE_A")
		assertLocalManagedTargetPreserved(t, fx.b,
			"LOCAL_MANAGED_QUERY_CANCEL_WROTE_B")
	})

	t.Run("backend-opaque-revision-drift-refuses-a-keeps-b", func(t *testing.T) {
		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{fx.a.candidate(), fx.b.candidate()})
		if err != nil || parent == nil || len(results) != 2 ||
			results[0].Wrapper == nil || results[1].Wrapper == nil {
			t.Fatalf("LOCAL_MANAGED_QUERY_DRIFT_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		if _, err := results[0].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1}); err != nil {
			t.Fatalf("LOCAL_MANAGED_QUERY_DRIFT_A_BASELINE_FAILED: %v", err)
		}
		if _, err := results[1].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1}); err != nil {
			t.Fatalf("LOCAL_MANAGED_QUERY_DRIFT_B_BASELINE_FAILED: %v", err)
		}

		// Commit the exact same selected ciphertext under a genuinely new
		// opaque revision. The managed production reader must refuse that
		// drifted revision even though the bytes are unchanged.
		current, revision := localCleanRecoveryReadTarget(t, fx.a.locator)
		next := localFirstRewriteBackend(t, Manifest{
			BackendRoot: fx.a.locator.Root, Name: fx.a.locator.Name,
		}, current)
		clear(current)
		if next == revision {
			t.Fatal("LOCAL_MANAGED_QUERY_DRIFT_REVISION_NOT_CHANGED")
		}

		if _, err := results[0].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1}); err == nil {
			t.Fatal("LOCAL_MANAGED_QUERY_DRIFT_A_ACCEPTED")
		}
		liveB, err := results[1].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(liveB.Hits) != 1 || liveB.Hits[0].ID != fx.b.expected[0].ID {
			t.Fatalf("LOCAL_MANAGED_QUERY_DRIFT_HURT_B: %v", err)
		}
		if err := results[1].Wrapper.ValidateExactQueryHit(liveB, liveB.Hits[0].ID, title); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_DRIFT_B_ACTIVATION_FAILED")
		}
		assertLocalManagedTargetPreserved(t, fx.b,
			"LOCAL_MANAGED_QUERY_DRIFT_CHANGED_B")
		if err := results[0].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_DRIFT_CLOSE_A_FAILED")
		}
		if err := results[1].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_QUERY_DRIFT_CLOSE_B_FAILED")
		}
	})
}

func localManagedSyntheticSelector() LocalManagedRecoverySelector {
	return LocalManagedRecoverySelector{
		AccountPath:   "/synthetic/account.ll",
		WorkspaceRoot: "/synthetic/backend",
		BackendName:   "managed-object",
		VaultID:       "synthetic-vault",
		JournalPath:   "/synthetic/journal",
		Pin: personal.VaultFileManagedDeviceSuccessorPin{
			Checkpoint: vaultfile.PolicyCheckpoint{
				VaultID:            "synthetic-vault",
				OwnerRootKeyID:     "synthetic-root",
				OwnerRootPublicKey: make([]byte, ed25519.PublicKeySize),
				PolicySeq:          3,
				PolicyDigest:       make([]byte, sha256.Size),
			},
			KeyEpoch:        2,
			ContentSeq:      4,
			SealedSHA256:    sha256.Sum256([]byte("synthetic-base")),
			BackendRevision: "synthetic-base-revision",
		},
		OperationID:  "synthetic-operation",
		SuccessorRev: "synthetic-successor-revision",
	}
}

func localManagedSyntheticCandidate(selector *LocalManagedRecoverySelector) LocalGenesisBatchCandidate {
	return LocalGenesisBatchCandidate{
		WorkspaceRoot: selector.WorkspaceRoot,
		VaultID:       selector.VaultID,
		JournalPath:   selector.JournalPath,
		Managed:       selector,
	}
}

func copyLocalManagedJournal(t *testing.T, source, label string) string {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal("LOCAL_MANAGED_ALIAS_JOURNAL_READ_FAILED")
	}
	defer clear(raw)
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("LOCAL_MANAGED_ALIAS_JOURNAL_DIR_FAILED")
	}
	path := filepath.Join(dir, label)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal("LOCAL_MANAGED_ALIAS_JOURNAL_WRITE_FAILED")
	}
	return path
}

func localManagedAliasWorkspaceRoot(t *testing.T, canonical string) (aliasRoot, aliasParent string) {
	t.Helper()
	aliasParent = filepath.Join(t.TempDir(), "alias-parent")
	if err := os.Symlink(filepath.Dir(canonical), aliasParent); err != nil {
		t.Fatal("LOCAL_MANAGED_ALIAS_SYMLINK_FAILED")
	}
	aliasRoot = filepath.Join(aliasParent, filepath.Base(canonical))
	if !validLocalManagedRecoveryPath(aliasRoot) {
		t.Fatal("LOCAL_MANAGED_ALIAS_NOT_CLEAN_ABSOLUTE")
	}
	return aliasRoot, aliasParent
}

func localManagedAliasCandidate(t *testing.T, fx *localManagedQueryFixture) LocalGenesisBatchCandidate {
	t.Helper()
	aliasRoot, _ := localManagedAliasWorkspaceRoot(t, fx.a.selector.WorkspaceRoot)
	journal := copyLocalManagedJournal(t, fx.a.selector.JournalPath, "managed-alias.journal")
	selector := fx.a.selector
	selector.WorkspaceRoot = aliasRoot
	selector.JournalPath = journal
	candidate := LocalGenesisBatchCandidate{
		WorkspaceRoot: selector.WorkspaceRoot,
		VaultID:       selector.VaultID,
		JournalPath:   selector.JournalPath,
		Managed:       cloneLocalManagedRecoverySelector(&selector),
	}
	return candidate
}

func TestLocalManagedRecoverySelectorShape(t *testing.T) {
	valid := localManagedSyntheticSelector()
	if !validLocalGenesisBatchCandidate(localManagedSyntheticCandidate(&valid), valid.AccountPath) {
		t.Fatal("LOCAL_MANAGED_SELECTOR_VALID_SHAPE_REJECTED")
	}

	mutations := []struct {
		name   string
		mutate func(*LocalManagedRecoverySelector)
	}{
		{"config-path", func(s *LocalManagedRecoverySelector) {}},
		{"account-path", func(s *LocalManagedRecoverySelector) { s.AccountPath = "/synthetic/other.ll" }},
		{"account-relative", func(s *LocalManagedRecoverySelector) { s.AccountPath = "relative.ll" }},
		{"workspace-other", func(s *LocalManagedRecoverySelector) { s.WorkspaceRoot = "/synthetic/other-backend" }},
		{"workspace-relative", func(s *LocalManagedRecoverySelector) { s.WorkspaceRoot = "relative" }},
		{"journal-other", func(s *LocalManagedRecoverySelector) { s.JournalPath = "/synthetic/other-journal" }},
		{"journal-relative", func(s *LocalManagedRecoverySelector) { s.JournalPath = "relative.journal" }},
		{"vault-other", func(s *LocalManagedRecoverySelector) { s.VaultID = "other-vault" }},
		{"backend-name", func(s *LocalManagedRecoverySelector) { s.BackendName = "../escape" }},
		{"pin-vault", func(s *LocalManagedRecoverySelector) { s.Pin.Checkpoint.VaultID = "other-vault" }},
		{"owner-root", func(s *LocalManagedRecoverySelector) { s.Pin.Checkpoint.OwnerRootKeyID = "" }},
		{"owner-public", func(s *LocalManagedRecoverySelector) { s.Pin.Checkpoint.OwnerRootPublicKey = nil }},
		{"policy-digest", func(s *LocalManagedRecoverySelector) { s.Pin.Checkpoint.PolicyDigest = nil }},
		{"key-epoch", func(s *LocalManagedRecoverySelector) { s.Pin.KeyEpoch = 0 }},
		{"sealed-sha", func(s *LocalManagedRecoverySelector) { s.Pin.SealedSHA256 = [sha256.Size]byte{} }},
		{"base-revision", func(s *LocalManagedRecoverySelector) { s.Pin.BackendRevision = "" }},
		{"operation", func(s *LocalManagedRecoverySelector) { s.OperationID = "" }},
		{"operation-long", func(s *LocalManagedRecoverySelector) {
			s.OperationID = strings.Repeat("o", 65)
		}},
		{"successor-revision", func(s *LocalManagedRecoverySelector) { s.SuccessorRev = "" }},
		{"successor-revision-long", func(s *LocalManagedRecoverySelector) {
			s.SuccessorRev = vaultfilebackend.Revision(strings.Repeat("r", 1025))
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			selector := localManagedSyntheticSelector()
			candidate := localManagedSyntheticCandidate(&selector)
			switch test.name {
			case "config-path":
				candidate.ConfigPath = "/synthetic/create.json"
			case "workspace-other":
				candidate.WorkspaceRoot = "/synthetic/other-backend"
			case "journal-other":
				candidate.JournalPath = "/synthetic/other-journal"
			default:
				test.mutate(&selector)
				candidate = localManagedSyntheticCandidate(&selector)
			}
			if validLocalGenesisBatchCandidate(candidate, valid.AccountPath) {
				t.Fatal("LOCAL_MANAGED_SELECTOR_INVALID_SHAPE_ACCEPTED")
			}
			clearLocalManagedRecoverySelector(&selector)
		})
	}
}

func TestOpenLocalGenesisSessionsForAccountManagedPhysicalAliasRejected(t *testing.T) {
	fx := newLocalManagedQueryFixture(t)
	title := localFirstWriteTitle
	aliasCandidate := localManagedAliasCandidate(t, fx)
	if aliasCandidate.Managed.WorkspaceRoot == fx.a.selector.WorkspaceRoot ||
		aliasCandidate.Managed.JournalPath == fx.a.selector.JournalPath {
		t.Fatal("LOCAL_MANAGED_ALIAS_NOT_DISTINCT")
	}

	// The alias descriptor is a genuinely openable target on its own. This
	// proves the later mixed batch is not refusing an unrelated bad path.
	t.Run("alias-descriptor-is-real", func(t *testing.T) {
		if _, err := localManagedBackendIdentity(aliasCandidate.Managed.WorkspaceRoot); err != nil {
			t.Fatalf("LOCAL_MANAGED_ALIAS_IDENTITY_FAILED: %v", err)
		}
		journal, err := vaultfilejournal.OpenExisting(aliasCandidate.Managed.JournalPath)
		if err != nil {
			t.Fatalf("LOCAL_MANAGED_ALIAS_JOURNAL_OPEN_FAILED: %v", err)
		}
		if err := journal.Close(); err != nil {
			t.Fatalf("LOCAL_MANAGED_ALIAS_JOURNAL_CLOSE_FAILED: %v", err)
		}
		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{aliasCandidate, fx.b.candidate()})
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatalf("LOCAL_MANAGED_ALIAS_SINGLE_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		if results[0].Err != nil || results[0].Wrapper == nil ||
			results[1].Err != nil || results[1].Wrapper == nil {
			t.Fatalf("LOCAL_MANAGED_ALIAS_SINGLE_NOT_WRAPPED: alias=%v b=%v",
				results[0].Err, results[1].Err)
		}
		aliasHit, err := results[0].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(aliasHit.Hits) != 1 || aliasHit.Hits[0].ID != fx.a.expected[0].ID {
			t.Fatalf("LOCAL_MANAGED_ALIAS_SINGLE_QUERY_FAILED: %v", err)
		}
		if err := results[0].Wrapper.ValidateExactQueryHit(aliasHit, aliasHit.Hits[0].ID, title); err != nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_SINGLE_ACTIVATION_FAILED")
		}
		bHit, err := results[1].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(bHit.Hits) != 1 || bHit.Hits[0].ID != fx.b.expected[0].ID {
			t.Fatalf("LOCAL_MANAGED_ALIAS_SINGLE_B_QUERY_FAILED: %v", err)
		}
		if err := results[0].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_SINGLE_CLOSE_A_FAILED")
		}
		if err := results[1].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_SINGLE_CLOSE_B_FAILED")
		}
	})

	// The canonical descriptor is also a genuinely openable target on its own,
	// so the mixed batch below has two individually valid selectors for the
	// same physical object rather than one valid and one unrelated failure.
	t.Run("canonical-descriptor-is-real", func(t *testing.T) {
		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{fx.a.candidate(), fx.b.candidate()})
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatalf("LOCAL_MANAGED_ALIAS_CANONICAL_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		if results[0].Err != nil || results[0].Wrapper == nil ||
			results[1].Err != nil || results[1].Wrapper == nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_CANONICAL_NOT_WRAPPED")
		}
		canonicalHit, err := results[0].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(canonicalHit.Hits) != 1 || canonicalHit.Hits[0].ID != fx.a.expected[0].ID {
			t.Fatalf("LOCAL_MANAGED_ALIAS_CANONICAL_QUERY_FAILED: %v", err)
		}
		if err := results[0].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_CANONICAL_CLOSE_A_FAILED")
		}
		if err := results[1].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_CANONICAL_CLOSE_B_FAILED")
		}
	})

	// The canonical descriptor and the ancestor-symlink alias have different
	// journal strings and different lexical roots, but they address the exact
	// same physical named backend object. Both must fail target-locally, while
	// unrelated B remains a real independently readable child.
	t.Run("canonical-and-alias-rejected-together", func(t *testing.T) {
		parent, results, err := fx.open(t, context.Background(),
			[]LocalGenesisBatchCandidate{fx.a.candidate(), aliasCandidate, fx.b.candidate()})
		if err != nil || parent == nil || len(results) != 3 {
			t.Fatalf("LOCAL_MANAGED_ALIAS_DUAL_DELIVERY_FAILED: %v", err)
		}
		defer parent.Lock()
		for _, index := range []int{0, 1} {
			if !errors.Is(results[index].Err, ErrLocalReview) ||
				results[index].Wrapper != nil || len(results[index].Baseline.Items) != 0 ||
				results[index].Baseline.VaultID != "" {
				t.Fatal("LOCAL_MANAGED_ALIAS_DUAL_NOT_LOCAL")
			}
		}
		if results[2].Err != nil || results[2].Wrapper == nil ||
			results[2].Baseline.VaultID != fx.b.selector.VaultID {
			t.Fatal("LOCAL_MANAGED_ALIAS_DUAL_HURT_B")
		}
		bHit, err := results[2].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
		if err != nil || len(bHit.Hits) != 1 || bHit.Hits[0].ID != fx.b.expected[0].ID {
			t.Fatalf("LOCAL_MANAGED_ALIAS_DUAL_B_QUERY_FAILED: %v", err)
		}
		if err := results[2].Wrapper.ValidateExactQueryHit(bHit, bHit.Hits[0].ID, title); err != nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_DUAL_B_ACTIVATION_FAILED")
		}
		if err := results[2].Wrapper.Close(); err != nil {
			t.Fatal("LOCAL_MANAGED_ALIAS_DUAL_CLOSE_B_FAILED")
		}
		assertLocalManagedTargetPreserved(t, fx.a,
			"LOCAL_MANAGED_ALIAS_DUAL_CHANGED_A")
		assertLocalManagedTargetPreserved(t, fx.b,
			"LOCAL_MANAGED_ALIAS_DUAL_CHANGED_B")
	})
}

func TestOpenLocalGenesisSessionsForAccountManagedPostAuthIdentityReplacementRefused(t *testing.T) {
	fx := newLocalManagedQueryFixture(t)
	title := localFirstWriteTitle
	aliasRoot, aliasParent := localManagedAliasWorkspaceRoot(t, fx.a.selector.WorkspaceRoot)
	aliasJournal := copyLocalManagedJournal(t, fx.a.selector.JournalPath, "managed-swap.journal")
	selector := fx.a.selector
	selector.WorkspaceRoot = aliasRoot
	selector.JournalPath = aliasJournal
	aliasCandidate := LocalGenesisBatchCandidate{
		WorkspaceRoot: selector.WorkspaceRoot,
		VaultID:       selector.VaultID,
		JournalPath:   selector.JournalPath,
		Managed:       cloneLocalManagedRecoverySelector(&selector),
	}
	if filepath.Base(fx.a.selector.WorkspaceRoot) != filepath.Base(fx.b.selector.WorkspaceRoot) {
		t.Fatal("LOCAL_MANAGED_SWAP_ROOTS_NOT_COMPARABLE")
	}

	oldHook := localGenesisBatchAfterAuthForTest
	t.Cleanup(func() { localGenesisBatchAfterAuthForTest = oldHook })
	swapped := false
	var swapErr error
	localGenesisBatchAfterAuthForTest = func() {
		if swapped {
			return
		}
		swapped = true
		if err := os.Remove(aliasParent); err != nil {
			swapErr = err
			return
		}
		swapErr = os.Symlink(filepath.Dir(fx.b.selector.WorkspaceRoot), aliasParent)
	}

	parent, results, err := fx.open(t, context.Background(),
		[]LocalGenesisBatchCandidate{aliasCandidate, fx.b.candidate()})
	parentLocked := false
	if parent != nil {
		defer func() {
			if !parentLocked {
				parent.Lock()
			}
		}()
	}
	if !swapped || swapErr != nil {
		t.Fatalf("LOCAL_MANAGED_SWAP_NOT_PERFORMED: %v", swapErr)
	}
	if err != nil || parent == nil || len(results) != 2 {
		t.Fatalf("LOCAL_MANAGED_SWAP_DELIVERY_FAILED: %v", err)
	}
	if !errors.Is(results[0].Err, ErrLocalReview) ||
		results[0].Wrapper != nil || len(results[0].Baseline.Items) != 0 ||
		results[0].Baseline.VaultID != "" {
		t.Fatal("LOCAL_MANAGED_SWAP_ALIAS_NOT_REFUSED")
	}
	if results[1].Err != nil || results[1].Wrapper == nil {
		t.Fatal("LOCAL_MANAGED_SWAP_HURT_B")
	}
	bHit, err := results[1].Wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
	if err != nil || len(bHit.Hits) != 1 || bHit.Hits[0].ID != fx.b.expected[0].ID {
		t.Fatalf("LOCAL_MANAGED_SWAP_B_QUERY_FAILED: %v", err)
	}
	if err := results[1].Wrapper.ValidateExactQueryHit(bHit, bHit.Hits[0].ID, title); err != nil {
		t.Fatal("LOCAL_MANAGED_SWAP_B_ACTIVATION_FAILED")
	}
	if err := results[1].Wrapper.Close(); err != nil {
		t.Fatal("LOCAL_MANAGED_SWAP_CLOSE_B_FAILED")
	}
	assertLocalManagedTargetPreserved(t, fx.a,
		"LOCAL_MANAGED_SWAP_CHANGED_A")
	assertLocalManagedTargetPreserved(t, fx.b,
		"LOCAL_MANAGED_SWAP_CHANGED_B")
}
