//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

type managedSuccessorPublishFixture struct {
	*managedDeviceSuccessorFixture

	journalPath string
	baseItems   []VaultFileBaselineItem
	artifactSHA [sha256.Size]byte
}

func newManagedSuccessorPublishFixture(t *testing.T, label string) *managedSuccessorPublishFixture {
	t.Helper()
	return newManagedSuccessorPublishFixtureFromSource(t, label, loadOwnerRecoveryImportSource(t))
}

func newFreshManagedSuccessorPublishFixture(t *testing.T, label string) *managedSuccessorPublishFixture {
	t.Helper()
	return newManagedSuccessorPublishFixtureFromSource(t, label, newFreshOwnerRecoveryImportSource(t))
}

func newManagedSuccessorPublishFixtureFromSource(t *testing.T, label string,
	source *ownerRecoveryImportSourceFixture) *managedSuccessorPublishFixture {
	t.Helper()
	base := newManagedDeviceSuccessorFixtureFromSource(t, label, source)
	journalDir := filepath.Join(t.TempDir(), "managed-successor-journal")
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_JOURNAL_DIR_FAILED")
	}
	journalPath := filepath.Join(journalDir, "managed-successor.journal")
	if err := vaultfilejournal.CreateNewState(journalPath, vaultfilejournal.State{
		BaseBytes:      bytes.Clone(base.base),
		RemoteRevision: base.baseRevision,
		WorkingBytes:   bytes.Clone(base.base),
		Generation:     0,
	}); err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_JOURNAL_CREATE_FAILED: %v", err)
	}
	recoveryAge, err := age.ParseX25519Identity(string(base.owner.RecoveryAgeIdentity))
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_RECOVERY_AGE_FAILED")
	}
	handle, err := vaultfile.NewScopedUnlock(base.base, &base.pin.Checkpoint,
		base.recoveryDevice, recoveryAge)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_BASE_UNLOCK_FAILED")
	}
	summaries, err := vault.ReadScopedItemSummaries(handle, base.base,
		vault.ItemSummaryOptions{IncludeID: true})
	if closeErr := handle.Close(); closeErr != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_BASE_CLOSE_FAILED")
	}
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_BASE_READ_FAILED")
	}
	items := vaultFileChildItems(summaries)
	f := &managedSuccessorPublishFixture{
		managedDeviceSuccessorFixture: base,
		journalPath:                   journalPath,
		baseItems:                     items,
		artifactSHA:                   sha256.Sum256(base.artifact),
	}
	t.Cleanup(f.clear)
	return f
}

func (f *managedSuccessorPublishFixture) clear() {
	if f == nil {
		return
	}
	clearVaultFileChildItems(f.baseItems)
	*f = managedSuccessorPublishFixture{}
}

func assertManagedSuccessorJournalPristine(t *testing.T, journalPath string, base []byte,
	revision vaultfilebackend.Revision) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_JOURNAL_OPEN_FAILED")
	}
	state, loadErr := j.LoadState()
	_, preparedErr := j.LoadPrepared()
	_, auditErr := j.LoadRebaseAudit(1)
	_, bindingErr := j.LoadManagedSuccessorBinding()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil || closeErr != nil || state.Generation != 0 ||
		!bytes.Equal(state.BaseBytes, base) || state.RemoteRevision != revision ||
		!errors.Is(preparedErr, vaultfilejournal.ErrEmpty) ||
		!errors.Is(auditErr, vaultfilejournal.ErrEmpty) ||
		!errors.Is(bindingErr, vaultfilejournal.ErrEmpty) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_JOURNAL_CHANGED")
	}
}

func assertManagedSuccessorJournalPrepared(t *testing.T, journalPath string) (string, []byte) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_PREPARED_OPEN_FAILED")
	}
	prepared, preparedErr := j.LoadPrepared()
	state, stateErr := j.LoadState()
	audit, auditErr := j.LoadRebaseAudit(state.Generation)
	binding, bindingErr := j.LoadManagedSuccessorBinding()
	closeErr := j.Close()
	if preparedErr != nil || stateErr != nil || auditErr != nil ||
		bindingErr != nil || closeErr != nil ||
		binding.Generation != 1 || binding.OperationID != prepared.Proposal.OperationID ||
		binding.TargetDigest == ([sha256.Size]byte{}) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_PREPARED_SHAPE_FAILED")
	}
	if prepared.WorkingGeneration != 1 || state.Generation != 1 ||
		audit.NewGeneration != 1 ||
		!bytes.Equal(prepared.Proposal.Bytes, state.WorkingBytes) ||
		!bytes.Equal(audit.Proposal.Bytes, prepared.Proposal.Bytes) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_PREPARED_RELATION_FAILED")
	}
	successor := bytes.Clone(prepared.Proposal.Bytes)
	operation := prepared.Proposal.OperationID
	clear(prepared.Proposal.Bytes)
	clear(audit.OldState.BaseBytes)
	clear(audit.OldState.WorkingBytes)
	clear(audit.RemoteBase)
	clear(audit.Proposal.Bytes)
	clear(state.BaseBytes)
	clear(state.WorkingBytes)
	return operation, successor
}

func TestVaultFileManagedDeviceSuccessorPublishAndFreshReopen(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-publish-reopen")

	receipt, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_FAILED: %v", err)
	}
	defer receipt.Clear()
	if !receipt.Signed || !receipt.LocallyObserved || receipt.OperationID == "" ||
		receipt.VaultID != f.pin.Checkpoint.VaultID ||
		receipt.BasePolicySeq != f.pin.Checkpoint.PolicySeq ||
		receipt.NextPolicySeq != f.pin.Checkpoint.PolicySeq+1 ||
		receipt.BaseKeyEpoch != f.pin.KeyEpoch ||
		receipt.NextKeyEpoch != f.pin.KeyEpoch+1 ||
		receipt.BaseContentSeq != f.pin.ContentSeq ||
		receipt.NextContentSeq != f.pin.ContentSeq+1 ||
		receipt.BaseSHA256 != f.pin.SealedSHA256 ||
		receipt.BaseRevision != f.pin.BackendRevision ||
		receipt.SuccessorRevision == "" ||
		receipt.SuccessorRevision == f.pin.BackendRevision ||
		receipt.SuccessorSHA256 == [sha256.Size]byte{} {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_RECEIPT_INVALID")
	}
	for _, output := range []string{receipt.String(), receipt.GoString()} {
		if output != vaultFileManagedDeviceSuccessorReceiptRedacted {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_RECEIPT_NOT_REDACTED")
		}
	}
	jsonText, err := receipt.MarshalJSON()
	if err != nil || string(jsonText) != `"[redacted]"` {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_RECEIPT_JSON_NOT_REDACTED")
	}

	successor, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(successor)
	if revision != receipt.SuccessorRevision ||
		sha256.Sum256(successor) != receipt.SuccessorSHA256 ||
		vaultfile.VerifyManagedTransition(f.base, successor, &f.pin.Checkpoint) != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_TARGET_NOT_EXACT")
	}
	if _, db, err := vaultfile.OpenAuthenticatedFile(successor, &receipt.Next,
		receipt.DestinationDeviceID, f.destinationAge); err != nil || db == nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_NEW_DEVICE_OPEN_FAILED")
	}

	j, err := vaultfilejournal.OpenExisting(f.journalPath)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_JOURNAL_OPEN_FAILED")
	}
	state, stateErr := j.LoadState()
	_, preparedErr := j.LoadPrepared()
	audit, auditErr := j.LoadRebaseAudit(1)
	binding, bindingErr := j.LoadManagedSuccessorBinding()
	if closeErr := j.Close(); stateErr != nil || auditErr != nil ||
		bindingErr != nil || closeErr != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_JOURNAL_READ_FAILED")
	}
	if !errors.Is(preparedErr, vaultfilejournal.ErrEmpty) ||
		state.Generation != 1 || state.RemoteRevision != receipt.SuccessorRevision ||
		!bytes.Equal(state.BaseBytes, successor) ||
		!bytes.Equal(state.WorkingBytes, successor) ||
		!bytes.Equal(audit.OldState.BaseBytes, f.base) ||
		audit.OldState.RemoteRevision != f.pin.BackendRevision ||
		!bytes.Equal(audit.Proposal.Bytes, successor) ||
		audit.Proposal.OperationID != receipt.OperationID ||
		binding.Generation != 1 || binding.OperationID != receipt.OperationID ||
		binding.TargetDigest == ([sha256.Size]byte{}) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_JOURNAL_PROOF_FAILED")
	}
	clear(state.BaseBytes)
	clear(state.WorkingBytes)
	clear(audit.OldState.BaseBytes)
	clear(audit.OldState.WorkingBytes)
	clear(audit.RemoteBase)
	clear(audit.Proposal.Bytes)

	// Close the active destination provider/session handle. The durable
	// journal and the exact backend object must be sufficient for a fresh
	// unlock and ordinary new-device reopen.
	f.destSession.Lock()
	f.destSession = nil
	fresh, err := UnlockSession(f.destPath, f.destPassword, f.destKey, 0)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_FRESH_UNLOCK_FAILED")
	}
	defer fresh.Lock()
	token, items, err := fresh.OpenVaultFileManagedDeviceSuccessorVaultFileChild(
		f.journalPath, f.target, f.pin, f.destPassword, f.destKey,
		VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_REOPEN_FAILED: %v", err)
	}
	defer clearVaultFileChildItems(items)
	if len(items) != len(f.baseItems) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_ITEM_COUNT_CHANGED")
	}
	for i := range f.baseItems {
		if items[i] != f.baseItems[i] {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_ITEM_CONTENT_CHANGED")
		}
	}
	readItems, err := fresh.ReadVaultFileChild(token, VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_CHILD_READ_FAILED")
	}
	defer clearVaultFileChildItems(readItems)
	if len(readItems) != len(f.baseItems) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_CHILD_ITEM_COUNT_CHANGED")
	}
	for i := range f.baseItems {
		if readItems[i] != f.baseItems[i] {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_CHILD_ITEM_CONTENT_CHANGED")
		}
	}
	if err := fresh.LockVaultFileChild(token); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_CHILD_LOCK_FAILED")
	}

	after, afterRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(after)
	if afterRevision != receipt.SuccessorRevision ||
		sha256.Sum256(after) != receipt.SuccessorSHA256 {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_REOPEN_CHANGED_TARGET")
	}
	if sha256.Sum256(f.artifact) != f.artifactSHA {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_MUTATED_ORIGINAL_BACKUP")
	}
}

func TestVaultFileManagedDeviceSuccessorPublishRejectsWrongOwnerAndPath(t *testing.T) {
	t.Run("wrong-owner", func(t *testing.T) {
		f := newManagedSuccessorPublishFixture(t, "managed-wrong-owner")
		path := filepath.Join(t.TempDir(), "wrong-owner.ll")
		password := []byte("managed-wrong-owner")
		key := bytes.Repeat([]byte{0x6c}, 16)
		if Create(path, string(password), key) != nil {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_WRONG_OWNER_CREATE_FAILED")
		}
		wrong, err := UnlockSession(path, password, key, 0)
		if err != nil {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_WRONG_OWNER_UNLOCK_FAILED")
		}
		defer wrong.Lock()
		_, err = wrong.PublishVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, f.target, f.pin)
		if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_WRONG_OWNER_ACCEPTED: %v", err)
		}
		assertManagedSuccessorJournalPristine(t, f.journalPath, f.base, f.baseRevision)
		after, revision := readManagedDeviceSuccessorBase(t, f.target)
		defer clear(after)
		if !bytes.Equal(after, f.base) || revision != f.baseRevision {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_WRONG_OWNER_MUTATED_TARGET")
		}
	})

	t.Run("missing-path", func(t *testing.T) {
		f := newManagedSuccessorPublishFixture(t, "managed-missing-path")
		target := f.target
		target.Name = "missing-managed-successor"
		_, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, target, f.pin)
		if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorPath) {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_MISSING_PATH_ACCEPTED: %v", err)
		}
		assertManagedSuccessorJournalPristine(t, f.journalPath, f.base, f.baseRevision)
	})

	t.Run("canceled-before", func(t *testing.T) {
		f := newManagedSuccessorPublishFixture(t, "managed-canceled-publish")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(ctx,
			f.journalPath, f.target, f.pin)
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_CANCELED_ACCEPTED: %v", err)
		}
		assertManagedSuccessorJournalPristine(t, f.journalPath, f.base, f.baseRevision)
	})

	t.Run("wrong-base-pin", func(t *testing.T) {
		f := newManagedSuccessorPublishFixture(t, "managed-wrong-pin")
		pin := cloneManagedDeviceSuccessorPin(f.pin)
		pin.SealedSHA256[0] ^= 0xff
		_, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, f.target, pin)
		clearVaultFilePolicyCheckpoint(&pin.Checkpoint)
		if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_WRONG_PIN_ACCEPTED: %v", err)
		}
		assertManagedSuccessorJournalPristine(t, f.journalPath, f.base, f.baseRevision)
		after, revision := readManagedDeviceSuccessorBase(t, f.target)
		defer clear(after)
		if !bytes.Equal(after, f.base) || revision != f.baseRevision {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_WRONG_PIN_MUTATED_TARGET")
		}
	})
}

func TestVaultFileManagedDeviceSuccessorPublishRejectsSameBytesNewRevision(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-stale-revision")
	backend, err := vaultfilebackend.OpenExistingDir(f.target.Root)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_STALE_BACKEND_FAILED")
	}
	if err := backend.ReplaceIfVersion(context.Background(), f.target.Name,
		f.baseRevision, bytes.Clone(f.base)); err != nil {
		_ = backend.Close()
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_STALE_REWRITE_FAILED")
	}
	if err := backend.Close(); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_STALE_CLOSE_FAILED")
	}
	after, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(after)
	if revision == f.baseRevision || !bytes.Equal(after, f.base) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_STALE_SETUP_FAILED")
	}
	_, err = f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
		t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_STALE_ACCEPTED: %v", err)
	}
	assertManagedSuccessorJournalPristine(t, f.journalPath, f.base, f.baseRevision)
}

type managedSuccessorUnknownBackend struct {
	vaultFileManagedDeviceSuccessorBackend
	mode string
	done bool
}

func (b *managedSuccessorUnknownBackend) ReplaceIfVersion(ctx context.Context, name string,
	expected vaultfilebackend.Revision, value []byte) error {
	if !b.done {
		b.done = true
		switch b.mode {
		case "nowrite":
			return vaultfilebackend.ErrUnknown
		case "different":
			if err := b.vaultFileManagedDeviceSuccessorBackend.ReplaceIfVersion(ctx, name,
				expected, []byte("different-managed-successor")); err != nil {
				return err
			}
			return vaultfilebackend.ErrUnknown
		}
	}
	if err := b.vaultFileManagedDeviceSuccessorBackend.ReplaceIfVersion(ctx, name, expected, value); err != nil {
		return err
	}
	if b.mode == "commit" && b.done {
		return vaultfilebackend.ErrUnknown
	}
	return nil
}

func withManagedSuccessorUnknownBackend(t *testing.T, mode string) func() {
	t.Helper()
	previous := openVaultFileManagedDeviceSuccessorBackend
	openVaultFileManagedDeviceSuccessorBackend = func(root string) (vaultFileManagedDeviceSuccessorBackend, error) {
		backend, err := previous(root)
		if err != nil {
			return nil, err
		}
		return &managedSuccessorUnknownBackend{
			vaultFileManagedDeviceSuccessorBackend: backend, mode: mode,
		}, nil
	}
	restore := func() { openVaultFileManagedDeviceSuccessorBackend = previous }
	t.Cleanup(restore)
	return restore
}

func TestVaultFileManagedDeviceSuccessorPublishUnknownWithDurableReconciliation(t *testing.T) {
	t.Run("commit-unknown-reconciled", func(t *testing.T) {
		f := newManagedSuccessorPublishFixture(t, "managed-unknown-commit")
		withManagedSuccessorUnknownBackend(t, "commit")
		receipt, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, f.target, f.pin)
		if err != nil {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_COMMIT_FAILED: %v", err)
		}
		defer receipt.Clear()
		successor, revision := readManagedDeviceSuccessorBase(t, f.target)
		defer clear(successor)
		if revision != receipt.SuccessorRevision ||
			sha256.Sum256(successor) != receipt.SuccessorSHA256 {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_COMMIT_NOT_SETTLED")
		}
	})

	t.Run("no-write-unknown-resumed-same-operation", func(t *testing.T) {
		f := newManagedSuccessorPublishFixture(t, "managed-unknown-nowrite")
		restore := withManagedSuccessorUnknownBackend(t, "nowrite")
		_, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, f.target, f.pin)
		if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorUnknown) {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_NOWRITE_ACCEPTED: %v", err)
		}
		operation, prepared := assertManagedSuccessorJournalPrepared(t, f.journalPath)
		defer clear(prepared)
		if operation == "" {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_NOWRITE_NO_OPERATION")
		}
		back, backRevision := readManagedDeviceSuccessorBase(t, f.target)
		defer clear(back)
		if !bytes.Equal(back, f.base) || backRevision != f.baseRevision {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_NOWRITE_MUTATED_TARGET")
		}
		restore()

		receipt, err := f.destSession.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, f.target, f.pin)
		if err != nil {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_NOWRITE_RESUME_FAILED: %v", err)
		}
		defer receipt.Clear()
		if receipt.OperationID != operation {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_RESUME_RE-SIGNED")
		}
		successor, revision := readManagedDeviceSuccessorBase(t, f.target)
		defer clear(successor)
		if revision != receipt.SuccessorRevision ||
			sha256.Sum256(successor) != receipt.SuccessorSHA256 ||
			!bytes.Equal(successor, prepared) {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_RESUME_DID_NOT_FINISH_EXACT_OPERATION")
		}
	})

	t.Run("different-unknown-hard-refusal", func(t *testing.T) {
		f := newManagedSuccessorPublishFixture(t, "managed-unknown-different")
		restore := withManagedSuccessorUnknownBackend(t, "different")
		_, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, f.target, f.pin)
		if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorUnknown) {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_DIFFERENT_ACCEPTED: %v", err)
		}
		operation, prepared := assertManagedSuccessorJournalPrepared(t, f.journalPath)
		defer clear(prepared)
		if operation == "" {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_DIFFERENT_NO_OPERATION")
		}
		restore()
		_, err = f.destSession.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
			f.journalPath, f.target, f.pin)
		if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorUnknown) {
			t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_DIFFERENT_RESUME_ACCEPTED: %v", err)
		}
		operationAgain, preparedAgain := assertManagedSuccessorJournalPrepared(t, f.journalPath)
		defer clear(preparedAgain)
		if operationAgain != operation || !bytes.Equal(preparedAgain, prepared) {
			t.Fatal("MANAGED_SUCCESSOR_PUBLISH_UNKNOWN_DIFFERENT_LOST_EVIDENCE")
		}
	})
}

func TestVaultFileManagedDeviceSuccessorPublishLockAfterPrepareThenResume(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-late-lock-publish")
	previous := vaultFileManagedDeviceSuccessorAfterPrepareForTest
	vaultFileManagedDeviceSuccessorAfterPrepareForTest = func() {
		f.destSession.RequestLock()
	}
	defer func() { vaultFileManagedDeviceSuccessorAfterPrepareForTest = previous }()

	_, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err == nil || !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_LATE_LOCK_ACCEPTED: %v", err)
	}
	operation, prepared := assertManagedSuccessorJournalPrepared(t, f.journalPath)
	defer clear(prepared)
	if operation == "" {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_LATE_LOCK_NO_DURABLE_OPERATION")
	}
	back, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(back)
	if !bytes.Equal(back, f.base) || revision != f.baseRevision {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_LATE_LOCK_MUTATED_TARGET")
	}

	f.destSession.Lock()
	f.destSession = nil
	fresh, err := UnlockSession(f.destPath, f.destPassword, f.destKey, 0)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_LATE_LOCK_FRESH_UNLOCK_FAILED")
	}
	defer fresh.Lock()
	receipt, err := fresh.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_PUBLISH_LATE_LOCK_RESUME_FAILED: %v", err)
	}
	defer receipt.Clear()
	if receipt.OperationID != operation {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_LATE_LOCK_RE-SIGNED")
	}
	successor, newRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(successor)
	if newRevision != receipt.SuccessorRevision ||
		sha256.Sum256(successor) != receipt.SuccessorSHA256 ||
		!bytes.Equal(successor, prepared) {
		t.Fatal("MANAGED_SUCCESSOR_PUBLISH_LATE_LOCK_RESUME_DID_NOT_FINISH_EXACT_OPERATION")
	}
}

func TestVaultFileManagedDeviceSuccessorReopenRejectsAdvancedTarget(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-reopen-negative")
	if _, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin); err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_REOPEN_NEGATIVE_PUBLISH_FAILED: %v", err)
	}
	successor, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(successor)

	t.Run("wrong-device", func(t *testing.T) {
		backend, err := vaultfilebackend.OpenExistingDir(f.target.Root)
		if err != nil {
			t.Fatal("MANAGED_SUCCESSOR_REOPEN_NEGATIVE_BACKEND_FAILED")
		}
		if err := backend.ReplaceIfVersion(context.Background(), f.target.Name,
			revision, bytes.Clone(successor)); err != nil {
			_ = backend.Close()
			t.Fatal("MANAGED_SUCCESSOR_REOPEN_NEGATIVE_REVISION_FAILED")
		}
		if err := backend.Close(); err != nil {
			t.Fatal("MANAGED_SUCCESSOR_REOPEN_NEGATIVE_CLOSE_FAILED")
		}
		// Restore the exact settled revision before the next subtest by
		// treating this as a one-shot witness of a later authenticated advance.
		_, _, err = f.destSession.OpenVaultFileManagedDeviceSuccessorVaultFileChild(
			f.journalPath, f.target, f.pin, f.destPassword, f.destKey,
			VaultFileChildOptions{})
		if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
			t.Fatalf("MANAGED_SUCCESSOR_REOPEN_ADVANCED_TARGET_ACCEPTED: %v", err)
		}
	})
}

func TestVaultFileManagedDeviceSuccessorReopenRejectsOtherAccountDevice(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-other-device")
	otherPath := filepath.Join(t.TempDir(), "other-device.ll")
	otherPassword := []byte("managed-other-device")
	otherKey := bytes.Repeat([]byte{0x7d}, 16)
	if Create(otherPath, string(otherPassword), otherKey) != nil {
		t.Fatal("MANAGED_SUCCESSOR_OTHER_DEVICE_CREATE_FAILED")
	}
	other, err := UnlockSession(otherPath, otherPassword, otherKey, 0)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_OTHER_DEVICE_UNLOCK_FAILED")
	}
	defer other.Lock()
	if _, err := other.RestoreVaultFileBackupCustodyOwner(context.Background(),
		f.artifact, f.expected, f.factor, f.binding, f.target); err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_OTHER_DEVICE_RESTORE_FAILED: %v", err)
	}
	if _, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin); err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_OTHER_DEVICE_PUBLISH_FAILED: %v", err)
	}
	_, _, err = other.OpenVaultFileManagedDeviceSuccessorVaultFileChild(
		f.journalPath, f.target, f.pin, otherPassword, otherKey, VaultFileChildOptions{})
	if err == nil || (!errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) &&
		!errors.Is(err, ErrVaultFileManagedDeviceSuccessorReopen)) {
		t.Fatalf("MANAGED_SUCCESSOR_OTHER_DEVICE_OPEN_ACCEPTED: %v", err)
	}
}
