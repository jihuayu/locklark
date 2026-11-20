//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

func copyManagedSuccessorBackendRoot(t *testing.T, src, dst string) {
	t.Helper()
	if err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode().Perm())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
			return err
		}
		return os.Chmod(target, info.Mode().Perm())
	}); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_COPY_FAILED")
	}
}

// stagePendingManagedSuccessor uses the existing narrow after-prepare seam to
// cancel after the durable prepared operation exists and before the first real
// backend write. The journal keeps the exact prepared generation and binding.
func stagePendingManagedSuccessor(t *testing.T, f *managedSuccessorPublishFixture) (string, []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fired := false
	previous := vaultFileManagedDeviceSuccessorAfterPrepareForTest
	vaultFileManagedDeviceSuccessorAfterPrepareForTest = func() {
		fired = true
		cancel()
	}
	defer func() { vaultFileManagedDeviceSuccessorAfterPrepareForTest = previous }()
	_, err := f.destSession.PublishVaultFileManagedDeviceSuccessor(ctx,
		f.journalPath, f.target, f.pin)
	if err == nil || !errors.Is(err, context.Canceled) || !fired {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_STAGE_FAILED: %v", err)
	}
	operation, prepared := assertManagedSuccessorJournalPrepared(t, f.journalPath)
	if operation == "" || len(prepared) == 0 {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_STAGE_NO_PREPARED")
	}
	base, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(base)
	if !bytes.Equal(base, f.base) || revision != f.baseRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_STAGE_WROTE_TARGET")
	}
	backend, err := vaultfilebackend.OpenExistingDir(f.target.Root)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_STAGE_IDENTITY_OPEN_FAILED")
	}
	identity, identityErr := backend.StableIdentity()
	closeErr := backend.Close()
	if identityErr != nil || closeErr != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_STAGE_IDENTITY_FAILED")
	}
	j, err := vaultfilejournal.OpenExisting(f.journalPath)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_STAGE_JOURNAL_OPEN_FAILED")
	}
	binding, bindingErr := j.LoadManagedSuccessorBinding()
	if err := j.Close(); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_STAGE_JOURNAL_CLOSE_FAILED")
	}
	if bindingErr != nil ||
		binding.TargetDigest != managedSuccessorTargetDigest(identity, f.target.Name) ||
		binding.TargetDigest == ([32]byte{}) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_STAGE_DIGEST_MISMATCH")
	}
	return operation, prepared
}

func assertManagedSuccessorBindingNoDisclosure(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_DISCLOSURE_WITHOUT_ERROR")
	}
	text := err.Error()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatal("MANAGED_SUCCESSOR_BINDING_DISCLOSURE")
		}
	}
}

func TestVaultFileManagedDeviceSuccessorResumeRejectsCopiedBackendIdentity(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-binding-copied-root")
	operation, prepared := stagePendingManagedSuccessor(t, f)
	defer clear(prepared)

	// Close the preparing session and reopen the same account and journal, so
	// every rejection and the eventual finish run through a fresh handle.
	f.destSession.Lock()
	f.destSession = nil
	fresh, err := UnlockSession(f.destPath, f.destPassword, f.destKey, 0)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_FRESH_UNLOCK_FAILED")
	}
	defer fresh.Lock()

	original, originalRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(original)
	copyRoot := filepath.Join(t.TempDir(), "backend-copy")
	copyManagedSuccessorBackendRoot(t, f.target.Root, copyRoot)
	copiedTarget := f.target
	copiedTarget.Root = copyRoot
	copied, copiedRevision := readManagedDeviceSuccessorBase(t, copiedTarget)
	defer clear(copied)
	if !bytes.Equal(copied, original) || copiedRevision != originalRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_COPY_NOT_EXACT")
	}

	_, err = fresh.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, copiedTarget, f.pin)
	if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_COPY_RESUME_ACCEPTED: %v", err)
	}
	assertManagedSuccessorBindingNoDisclosure(t, err, copyRoot, f.target.Root,
		f.target.Name, string(f.pin.BackendRevision), operation)

	afterOriginal, afterOriginalRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(afterOriginal)
	afterCopied, afterCopiedRevision := readManagedDeviceSuccessorBase(t, copiedTarget)
	defer clear(afterCopied)
	if !bytes.Equal(afterOriginal, original) || afterOriginalRevision != originalRevision ||
		!bytes.Equal(afterCopied, original) || afterCopiedRevision != originalRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_COPY_WROTE_OBJECT")
	}
	operationAgain, preparedAgain := assertManagedSuccessorJournalPrepared(t, f.journalPath)
	defer clear(preparedAgain)
	if operationAgain != operation || !bytes.Equal(preparedAgain, prepared) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_COPY_LOST_PREPARED")
	}

	receipt, err := fresh.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_ORIGINAL_RESUME_FAILED: %v", err)
	}
	defer receipt.Clear()
	if receipt.OperationID != operation {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_ORIGINAL_RE-SIGNED")
	}
	successor, successorRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(successor)
	if successorRevision != receipt.SuccessorRevision ||
		sha256.Sum256(successor) != receipt.SuccessorSHA256 ||
		!bytes.Equal(successor, prepared) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_ORIGINAL_NOT_EXACT")
	}

	// After settlement, the copied exact pair must still be refused by
	// idempotent Publish/Resume and the dedicated reopen.
	idempotent, err := fresh.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err != nil || idempotent.OperationID != operation {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_SETTLED_IDEMPOTENT_PUBLISH_FAILED: %v", err)
	}
	idempotent.Clear()
	if _, err := fresh.PublishVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, copiedTarget, f.pin); err == nil ||
		!errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_SETTLED_COPY_PUBLISH_ACCEPTED: %v", err)
	}
	if _, err := fresh.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, copiedTarget, f.pin); err == nil ||
		!errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_SETTLED_COPY_RESUME_ACCEPTED: %v", err)
	}
	token, items, err := fresh.OpenVaultFileManagedDeviceSuccessorVaultFileChild(
		f.journalPath, f.target, f.pin, f.destPassword, f.destKey,
		VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_ORIGINAL_REOPEN_FAILED: %v", err)
	}
	defer clearVaultFileChildItems(items)
	if len(items) != len(f.baseItems) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_REOPEN_ITEM_COUNT_CHANGED")
	}
	for i := range f.baseItems {
		if items[i] != f.baseItems[i] {
			t.Fatal("MANAGED_SUCCESSOR_BINDING_REOPEN_ITEM_CONTENT_CHANGED")
		}
	}
	if err := fresh.LockVaultFileChild(token); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_CHILD_LOCK_FAILED")
	}
	if _, _, err := fresh.OpenVaultFileManagedDeviceSuccessorVaultFileChild(
		f.journalPath, copiedTarget, f.pin, f.destPassword, f.destKey,
		VaultFileChildOptions{}); err == nil ||
		(!errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) &&
			!errors.Is(err, ErrVaultFileManagedDeviceSuccessorReopen)) {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_SETTLED_COPY_REOPEN_ACCEPTED: %v", err)
	}
	afterSettledCopy, afterSettledCopyRevision := readManagedDeviceSuccessorBase(t, copiedTarget)
	defer clear(afterSettledCopy)
	if !bytes.Equal(afterSettledCopy, original) || afterSettledCopyRevision != originalRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SETTLED_COPY_WROTE_OBJECT")
	}
}

func TestVaultFileManagedDeviceSuccessorResumeRejectsOtherExactName(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-binding-other-name")
	operation, prepared := stagePendingManagedSuccessor(t, f)
	defer clear(prepared)

	dataDir := filepath.Join(f.target.Root, "vaultfile-backend", "v1", "data")
	entries, err := os.ReadDir(dataDir)
	if err != nil || len(entries) != 1 || entries[0].IsDir() {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_NAME_FIXTURE_FAILED")
	}
	originalRecord, err := os.ReadFile(filepath.Join(dataDir, entries[0].Name()))
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_NAME_READ_FAILED")
	}
	otherName := "other-managed-successor"
	otherHash := sha256.Sum256([]byte(otherName))
	if err := os.WriteFile(filepath.Join(dataDir, hex.EncodeToString(otherHash[:])),
		originalRecord, 0600); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_NAME_COPY_FAILED")
	}
	otherTarget := f.target
	otherTarget.Name = otherName
	otherBytes, otherRevision := readManagedDeviceSuccessorBase(t, otherTarget)
	defer clear(otherBytes)
	if !bytes.Equal(otherBytes, f.base) || otherRevision != f.baseRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_NAME_COPY_NOT_EXACT")
	}

	_, err = f.destSession.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, otherTarget, f.pin)
	if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_OTHER_NAME_ACCEPTED: %v", err)
	}
	assertManagedSuccessorBindingNoDisclosure(t, err, otherName, f.target.Name,
		string(f.pin.BackendRevision), operation)
	operationAgain, preparedAgain := assertManagedSuccessorJournalPrepared(t, f.journalPath)
	defer clear(preparedAgain)
	if operationAgain != operation || !bytes.Equal(preparedAgain, prepared) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_OTHER_NAME_LOST_PREPARED")
	}
	base, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(base)
	if !bytes.Equal(base, f.base) || revision != f.baseRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_OTHER_NAME_WROTE_ORIGINAL")
	}
}

func TestVaultFileManagedDeviceSuccessorResumeRejectsSamePathRootReplacement(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-binding-same-path")
	operation, prepared := stagePendingManagedSuccessor(t, f)
	defer clear(prepared)

	// Close the preparing session and reopen the same account and journal, so
	// every rejection and the eventual finish run through a fresh handle.
	f.destSession.Lock()
	f.destSession = nil
	fresh, err := UnlockSession(f.destPath, f.destPassword, f.destKey, 0)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_FRESH_UNLOCK_FAILED")
	}
	defer fresh.Lock()

	original, originalRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(original)
	copyRoot := filepath.Join(t.TempDir(), "backend-copy")
	copyManagedSuccessorBackendRoot(t, f.target.Root, copyRoot)
	moved := filepath.Join(t.TempDir(), "backend-original")
	if err := os.Rename(f.target.Root, moved); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_MOVE_FAILED")
	}
	if err := os.Rename(copyRoot, f.target.Root); err != nil {
		_ = os.Rename(moved, f.target.Root)
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_REPLACE_FAILED")
	}
	restored := false
	t.Cleanup(func() {
		if restored {
			return
		}
		_ = os.RemoveAll(f.target.Root)
		_ = os.Rename(moved, f.target.Root)
	})
	replaced, replacedRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(replaced)
	if !bytes.Equal(replaced, original) || replacedRevision != originalRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_NOT_EXACT")
	}

	_, err = fresh.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_SAME_PATH_ACCEPTED: %v", err)
	}
	assertManagedSuccessorBindingNoDisclosure(t, err, f.target.Root,
		f.target.Name, string(f.pin.BackendRevision), operation)
	operationAgain, preparedAgain := assertManagedSuccessorJournalPrepared(t, f.journalPath)
	defer clear(preparedAgain)
	if operationAgain != operation || !bytes.Equal(preparedAgain, prepared) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_LOST_PREPARED")
	}
	replacedAfter, replacedAfterRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(replacedAfter)
	if !bytes.Equal(replacedAfter, original) || replacedAfterRevision != originalRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_WROTE_SUBSTITUTE")
	}

	if err := os.RemoveAll(f.target.Root); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_REMOVE_FAILED")
	}
	if err := os.Rename(moved, f.target.Root); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_RESTORE_FAILED")
	}
	restored = true
	receipt, err := fresh.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_SAME_PATH_RESUME_FAILED: %v", err)
	}
	defer receipt.Clear()
	if receipt.OperationID != operation {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_RE-SIGNED")
	}
	successor, successorRevision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(successor)
	if successorRevision != receipt.SuccessorRevision ||
		sha256.Sum256(successor) != receipt.SuccessorSHA256 ||
		!bytes.Equal(successor, prepared) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_SAME_PATH_NOT_SETTLED_EXACT")
	}
}

func TestVaultFileManagedDeviceSuccessorUnboundPreparedStateFailsClosed(t *testing.T) {
	f := newManagedSuccessorPublishFixture(t, "managed-binding-unbound")
	draft, err := f.destSession.PrepareVaultFileManagedDeviceSuccessor(context.Background(),
		f.target, f.pin)
	if err != nil {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_UNBOUND_PREPARE_FAILED: %v", err)
	}
	defer draft.Clear()
	parsed, err := vaultfile.ParseFile(draft.Draft)
	if err != nil || parsed.Header.OpID == "" {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_UNBOUND_DRAFT_FAILED")
	}
	j, err := vaultfilejournal.OpenExisting(f.journalPath)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_UNBOUND_OPEN_FAILED")
	}
	state, stateErr := j.LoadState()
	proposal := vaultfilejournal.Proposal{
		Generation:       1,
		OperationID:      parsed.Header.OpID,
		ExpectedRevision: f.pin.BackendRevision,
		Bytes:            bytes.Clone(draft.Draft),
	}
	prepareErr := j.RebaseAndPrepare(state, state.BaseBytes, state.RemoteRevision, proposal)
	_, bindingErr := j.LoadManagedSuccessorBinding()
	closeErr := j.Close()
	clear(state.BaseBytes)
	clear(state.WorkingBytes)
	clear(proposal.Bytes)
	if stateErr != nil || prepareErr != nil || closeErr != nil ||
		!errors.Is(bindingErr, vaultfilejournal.ErrEmpty) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_UNBOUND_FIXTURE_FAILED")
	}
	_, err = f.destSession.ResumeVaultFileManagedDeviceSuccessor(context.Background(),
		f.journalPath, f.target, f.pin)
	if err == nil || !errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) {
		t.Fatalf("MANAGED_SUCCESSOR_BINDING_UNBOUND_RESUME_ACCEPTED: %v", err)
	}
	base, revision := readManagedDeviceSuccessorBase(t, f.target)
	defer clear(base)
	if !bytes.Equal(base, f.base) || revision != f.baseRevision {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_UNBOUND_WROTE_TARGET")
	}
	// The unbound prepared record is preserved; nothing is re-signed.
	j, err = vaultfilejournal.OpenExisting(f.journalPath)
	if err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_UNBOUND_REOPEN_FAILED")
	}
	prepared, preparedErr := j.LoadPrepared()
	_, bindingErr = j.LoadManagedSuccessorBinding()
	if err := j.Close(); err != nil {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_UNBOUND_REOPEN_CLOSE_FAILED")
	}
	defer clear(prepared.Proposal.Bytes)
	if preparedErr != nil || !errors.Is(bindingErr, vaultfilejournal.ErrEmpty) ||
		prepared.Proposal.OperationID != parsed.Header.OpID ||
		!bytes.Equal(prepared.Proposal.Bytes, draft.Draft) {
		t.Fatal("MANAGED_SUCCESSOR_BINDING_UNBOUND_LOST_PREPARED")
	}
}
