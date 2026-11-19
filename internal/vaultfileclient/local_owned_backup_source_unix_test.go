//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

const localOwnedBackupRedacted = "[local owned backup source]"

func localBackupManifest(t *testing.T, config string) Manifest {
	t.Helper()
	manifest, exists, err := ReadManifest(config)
	if err != nil || !exists {
		t.Fatal("LOCAL_OWNED_BACKUP_MANIFEST_FAILED")
	}
	return manifest
}

func localBackupCompanion(t *testing.T, config string, manifest Manifest) Companion {
	t.Helper()
	companion, exists, err := ReadCompanion(config, manifest)
	if err != nil || !exists || companion.Resume.Checkpoint == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_COMPANION_FAILED")
	}
	return companion
}

func localBackupPin(t *testing.T, manifest Manifest, companion Companion) vaultfilejournal.OwnedGenesisPin {
	t.Helper()
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		t.Fatal("LOCAL_OWNED_BACKUP_ROOT_DECODE_FAILED")
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		t.Fatal("LOCAL_OWNED_BACKUP_PIN_FAILED")
	}
	return pin
}

func localBackupPristineState(t *testing.T, manifest Manifest) vaultfilejournal.State {
	t.Helper()
	journal, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_PRISTINE_OPEN_FAILED")
	}
	state, loadErr := journal.LoadGenesisBaseline()
	closeErr := journal.Close()
	if loadErr != nil || closeErr != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_PRISTINE_LOAD_FAILED")
	}
	return state
}

func localBackupSuccessorRecord(t *testing.T, manifest Manifest, pin vaultfilejournal.OwnedGenesisPin) vaultfilejournal.OwnedFirstSuccessor {
	t.Helper()
	record, err := vaultfilejournal.ReadOwnedFirstSuccessor(manifest.Journal, pin)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_SUCCESSOR_RECORD_FAILED")
	}
	return record
}

func localBackupCapture(t *testing.T, f *localGenesisTwoVaultFixture, config string, manifest Manifest) LocalOwnedBackupSource {
	t.Helper()
	source, err := CaptureLocalOwnedBackupSource(context.Background(), f.session, config,
		manifest.BackendRoot, manifest.VaultID, manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CAPTURE_FAILED")
	}
	return source
}

func localBackupAssertRedacted(t *testing.T, source LocalOwnedBackupSource) {
	t.Helper()
	for _, formatted := range []string{
		fmt.Sprintf("%v", source), fmt.Sprintf("%+v", source), fmt.Sprintf("%#v", source),
		fmt.Sprintf("%v", &source), fmt.Sprintf("%+v", &source), fmt.Sprintf("%#v", &source),
		fmt.Sprintf("%v", LocalOwnedBackupSource{}), fmt.Sprintf("%v", (*LocalOwnedBackupSource)(nil)),
	} {
		if formatted != localOwnedBackupRedacted {
			t.Fatal("LOCAL_OWNED_BACKUP_FORMAT_NOT_REDACTED")
		}
	}
	raw, err := json.Marshal(source)
	if err != nil || string(raw) != "{}" {
		t.Fatal("LOCAL_OWNED_BACKUP_JSON_EXPOSED_PRIVATE_FIELDS")
	}
}

func localBackupAssertDigests(t *testing.T, source LocalOwnedBackupSource) {
	t.Helper()
	var zero [32]byte
	if source.CheckpointDigest == zero || source.IdentityDigest == zero {
		t.Fatal("LOCAL_OWNED_BACKUP_DIGEST_MISSING")
	}
	if source.VaultID == "" || source.Checkpoint.VaultID != source.VaultID ||
		source.Checkpoint.PolicySeq != 0 || len(source.Checkpoint.OwnerRootPublicKey) != ed25519.PublicKeySize ||
		len(source.Checkpoint.PolicyDigest) != 32 {
		t.Fatal("LOCAL_OWNED_BACKUP_CHECKPOINT_INVALID")
	}
}

func localBackupAssertBackend(t *testing.T, manifest Manifest, expected []byte, revision vaultfilebackend.Revision) {
	t.Helper()
	got, gotRevision := localFirstReadBackend(t, manifest)
	defer clear(got)
	if !bytes.Equal(got, expected) || gotRevision != revision {
		t.Fatal("LOCAL_OWNED_BACKUP_BACKEND_MISMATCH")
	}
}

func TestLocalOwnedBackupSourceCapturePristineSettledAndRefusals(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	manifestA := localBackupManifest(t, f.firstConfig)
	companionA := localBackupCompanion(t, f.firstConfig, manifestA)
	pinA := localBackupPin(t, manifestA, companionA)

	// A real sibling owned child must stay live across A's temporary child.
	siblingB, siblingSummary := f.open(t, f.secondConfig, f.secondVaultID)
	assertLocalGenesisSummary(t, siblingSummary, f.secondVaultID)
	defer siblingB.Close()
	secondBefore := localFirstSecondFingerprint(t, f)

	// Pristine A: current bytes are the generation-zero encrypted genesis.
	pristine := localBackupCapture(t, f, f.firstConfig, manifestA)
	localBackupAssertDigests(t, pristine)
	localBackupAssertRedacted(t, pristine)
	if pristine.Origin != nil || pristine.OriginRevision != "" || pristine.ContentSeq != 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_PRISTINE_SHAPE_FAILED")
	}
	if pristine.JournalRevision == "" || pristine.JournalRevision != pristine.BackendRevision {
		t.Fatal("LOCAL_OWNED_BACKUP_PRISTINE_REVISION_FAILED")
	}
	pristineState := localBackupPristineState(t, manifestA)
	defer clear(pristineState.BaseBytes)
	defer clear(pristineState.WorkingBytes)
	if pristineState.Generation != 0 || !bytes.Equal(pristineState.BaseBytes, pristineState.WorkingBytes) ||
		!bytes.Equal(pristine.Current, pristineState.BaseBytes) ||
		pristine.JournalRevision != pristineState.RemoteRevision {
		t.Fatal("LOCAL_OWNED_BACKUP_PRISTINE_JOURNAL_FAILED")
	}
	pristineCheckpoint, err := vaultfile.VerifyGenesis(pristine.Current, &pinA.Root)
	if err != nil || !localGenesisCheckpointMatchesCompanion(pristineCheckpoint, companionA.Resume.Checkpoint) {
		t.Fatal("LOCAL_OWNED_BACKUP_PRISTINE_VERIFY_FAILED")
	}
	clearLocalGenesisCheckpoint(pristineCheckpoint)
	localBackupAssertBackend(t, manifestA, pristine.Current, pristine.BackendRevision)
	if _, err := siblingB.Summary(); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_SIBLING_LOST_AFTER_PRISTINE")
	}
	if secondBefore != localFirstSecondFingerprint(t, f) {
		t.Fatal("LOCAL_OWNED_BACKUP_SECOND_CHANGED_BY_PRISTINE")
	}
	pristine.Clear()
	if pristine.Current != nil || pristine.Origin != nil || pristine.Checkpoint.OwnerRootPublicKey != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CLEAR_FAILED")
	}

	// Publish A's real first successor, then capture the exact settled bytes.
	fxA := newLocalFirstWriteFixtureFor(t, f, f.firstConfig, f.firstVaultID)
	result, err := fxA.write(context.Background())
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_FIRST_WRITE_FAILED")
	}
	settled := localBackupCapture(t, f, f.firstConfig, manifestA)
	localBackupAssertDigests(t, settled)
	if settled.Origin == nil || settled.OriginRevision == "" || settled.ContentSeq != 1 {
		t.Fatal("LOCAL_OWNED_BACKUP_SETTLED_SHAPE_FAILED")
	}
	if settled.JournalRevision != vaultfilebackend.Revision(result.Revision) ||
		settled.BackendRevision != vaultfilebackend.Revision(result.Revision) {
		t.Fatal("LOCAL_OWNED_BACKUP_SETTLED_REVISION_FAILED")
	}
	record := localBackupSuccessorRecord(t, manifestA, pinA)
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)
	if !bytes.Equal(record.GenesisBytes, settled.Origin) ||
		!bytes.Equal(record.SuccessorBytes, settled.Current) ||
		record.SuccessorRevision != settled.BackendRevision ||
		record.GenesisRevision != settled.OriginRevision ||
		record.SuccessorRevision != vaultfilebackend.Revision(result.Revision) {
		t.Fatal("LOCAL_OWNED_BACKUP_SETTLED_JOURNAL_FAILED")
	}
	settledCheckpoint, err := vaultfile.VerifyGenesis(settled.Origin, &pinA.Root)
	if err != nil || !localGenesisCheckpointMatchesCompanion(settledCheckpoint, companionA.Resume.Checkpoint) {
		t.Fatal("LOCAL_OWNED_BACKUP_SETTLED_ORIGIN_FAILED")
	}
	clearLocalGenesisCheckpoint(settledCheckpoint)
	if err := vaultfile.VerifyContentTransition(settled.Origin, settled.Current, &settled.Checkpoint); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_SETTLED_TRANSITION_FAILED")
	}
	localBackupAssertBackend(t, manifestA, settled.Current, settled.BackendRevision)

	// Reopen the captured ciphertext through the normal authenticated content
	// verifier, not a projected summary.
	signing, localAge, recipient := localClientAccountIdentity(
		t, f.f.proposal.PersonalFile, []byte(f.f.password), f.f.key)
	defer clear(signing)
	originFile, err := vaultfile.ParseFile(settled.Origin)
	if err != nil || len(originFile.SignedPolicyProofs) == 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_ORIGIN_PARSE_FAILED")
	}
	policy := &originFile.SignedPolicyProofs[len(originFile.SignedPolicyProofs)-1].Policy
	deviceID, ok := localOwnedWriterDevice(policy, recipient, signing.Public().(ed25519.PublicKey))
	if !ok {
		t.Fatal("LOCAL_OWNED_BACKUP_DEVICE_FAILED")
	}
	_, metadata, items, err := vault.OpenAuthenticatedItems(
		settled.Current, &settled.Checkpoint, deviceID, localAge)
	if err != nil || len(items) != 1 || items[0].Title != fxA.item.Title {
		t.Fatal("LOCAL_OWNED_BACKUP_CONTENT_REOPEN_FAILED")
	}
	clear(metadata)
	for i := range items {
		items[i] = vault.Item{}
	}

	// The same authenticated source opens the ordinary read-only child path.
	reopened, reopenedSummary, err := OpenLocalGenesisSessionForJournal(
		f.session, f.firstConfig, manifestA.BackendRoot, manifestA.VaultID,
		manifestA.Journal, []byte(f.f.password), f.f.key)
	if err != nil || len(reopenedSummary.Items) != 1 ||
		reopenedSummary.Items[0].Title != fxA.item.Title {
		t.Fatal("LOCAL_OWNED_BACKUP_NORMAL_REOPEN_FAILED")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_NORMAL_REOPEN_CLOSE_FAILED")
	}
	if _, err := siblingB.Summary(); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_SIBLING_LOST_AFTER_SETTLED")
	}
	if secondBefore != localFirstSecondFingerprint(t, f) {
		t.Fatal("LOCAL_OWNED_BACKUP_SECOND_CHANGED_BY_SETTLED")
	}

	// Same encrypted bytes at a new opaque revision must be refused, and the
	// original journal sealed bytes/revision must remain retained.
	newRevision := localFirstRewriteBackend(t, manifestA, settled.Current)
	if newRevision == settled.BackendRevision {
		t.Fatal("LOCAL_OWNED_BACKUP_DRIFT_NOT_REAL")
	}
	if _, err := CaptureLocalOwnedBackupSource(context.Background(), f.session, f.firstConfig,
		manifestA.BackendRoot, manifestA.VaultID, manifestA.Journal,
		[]byte(f.f.password), f.f.key); !errors.Is(err, ErrLocalOwnedBackupConflict) {
		t.Fatal("LOCAL_OWNED_BACKUP_SAME_BYTES_REVISION_ACCEPTED")
	}
	afterDrift := localBackupSuccessorRecord(t, manifestA, pinA)
	defer clear(afterDrift.GenesisBytes)
	defer clear(afterDrift.SuccessorBytes)
	if !bytes.Equal(afterDrift.SuccessorBytes, settled.Current) ||
		afterDrift.SuccessorRevision != settled.BackendRevision {
		t.Fatal("LOCAL_OWNED_BACKUP_JOURNAL_REVISION_NOT_RETAINED")
	}
	if secondBefore != localFirstSecondFingerprint(t, f) {
		t.Fatal("LOCAL_OWNED_BACKUP_SECOND_CHANGED_BY_DRIFT")
	}
	settled.Clear()

	// A prepared journal is an explicit conflict and is preserved untouched.
	t.Run("pending", func(t *testing.T) {
		f2 := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f2.firstConfig)
		state := localBackupPristineState(t, manifest)
		defer clear(state.BaseBytes)
		defer clear(state.WorkingBytes)
		journal, err := vaultfilejournal.OpenExisting(manifest.Journal)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_PENDING_OPEN_FAILED")
		}
		proposal := vaultfilejournal.Proposal{
			Generation: 1, OperationID: "backup-pending-op",
			ExpectedRevision: state.RemoteRevision,
			Bytes:            []byte("authenticated pending successor placeholder"),
		}
		if err := journal.PrepareWorkingIfState(state, proposal); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_PENDING_PREPARE_FAILED")
		}
		pending, prepared, err := journal.LoadOwnedFirstPending()
		closeErr := journal.Close()
		if err != nil || closeErr != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_PENDING_LOAD_FAILED")
		}
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)

		_, err = CaptureLocalOwnedBackupSource(context.Background(), f2.session, f2.firstConfig,
			manifest.BackendRoot, manifest.VaultID, manifest.Journal,
			[]byte(f2.f.password), f2.f.key)
		if !errors.Is(err, ErrLocalOwnedBackupConflict) {
			t.Fatal("LOCAL_OWNED_BACKUP_PENDING_ACCEPTED")
		}
		journal, err = vaultfilejournal.OpenExisting(manifest.Journal)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_PENDING_REOPEN_FAILED")
		}
		after, afterPrepared, err := journal.LoadOwnedFirstPending()
		closeErr = journal.Close()
		if err != nil || closeErr != nil ||
			!sameLocalOwnedFirstState(pending, after) ||
			!sameLocalOwnedFirstPrepared(prepared, afterPrepared) {
			t.Fatal("LOCAL_OWNED_BACKUP_PENDING_NOT_RETAINED")
		}
		clear(after.BaseBytes)
		clear(after.WorkingBytes)
		clear(afterPrepared.Proposal.Bytes)
	})

	t.Run("selectors", func(t *testing.T) {
		f3 := newLocalGenesisTwoVaultFixture(t)
		manifestA3 := localBackupManifest(t, f3.firstConfig)
		manifestB3 := localBackupManifest(t, f3.secondConfig)
		companionB3 := localBackupCompanion(t, f3.secondConfig, manifestB3)
		secondBefore3 := localFirstSecondFingerprint(t, f3)

		if _, err := CaptureLocalOwnedBackupSource(context.Background(), f3.session, f3.firstConfig,
			manifestA3.BackendRoot, manifestA3.VaultID, manifestB3.Journal,
			[]byte(f3.f.password), f3.f.key); !errors.Is(err, ErrLocalOwnedBackupReview) {
			t.Fatal("LOCAL_OWNED_BACKUP_WRONG_JOURNAL_ACCEPTED")
		}
		if _, err := CaptureLocalOwnedBackupSource(context.Background(), f3.session, f3.secondConfig,
			manifestA3.BackendRoot, manifestA3.VaultID, manifestA3.Journal,
			[]byte(f3.f.password), f3.f.key); !errors.Is(err, ErrLocalOwnedBackupReview) {
			t.Fatal("LOCAL_OWNED_BACKUP_WRONG_VAULT_ACCEPTED")
		}

		foreign := filepath.Join(t.TempDir(), "foreign-account.ll")
		if err := personal.Create(foreign, string(f3.f.password), f3.f.key); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_FOREIGN_CREATE_FAILED")
		}
		foreignSession, err := personal.UnlockSession(foreign, []byte(f3.f.password), f3.f.key, time.Minute)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_FOREIGN_UNLOCK_FAILED")
		}
		_, err = CaptureLocalOwnedBackupSource(context.Background(), foreignSession, f3.firstConfig,
			manifestA3.BackendRoot, manifestA3.VaultID, manifestA3.Journal,
			[]byte(f3.f.password), f3.f.key)
		foreignSession.Lock()
		if !errors.Is(err, ErrLocalOwnedBackupReview) {
			t.Fatal("LOCAL_OWNED_BACKUP_WRONG_ACCOUNT_ACCEPTED")
		}

		companion := localBackupCompanion(t, f3.firstConfig, manifestA3)
		companion.Resume.Checkpoint.OwnerRootKeyID = companionB3.Resume.Checkpoint.OwnerRootKeyID
		companion.Resume.Checkpoint.OwnerRootPublicKey = companionB3.Resume.Checkpoint.OwnerRootPublicKey
		raw, err := json.Marshal(companion)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_BAD_COMPANION_ENCODE_FAILED")
		}
		path, err := CompanionPath(f3.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_BAD_COMPANION_PATH_FAILED")
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_BAD_COMPANION_WRITE_FAILED")
		}
		if _, err := CaptureLocalOwnedBackupSource(context.Background(), f3.session, f3.firstConfig,
			manifestA3.BackendRoot, manifestA3.VaultID, manifestA3.Journal,
			[]byte(f3.f.password), f3.f.key); !errors.Is(err, ErrLocalOwnedBackupReview) {
			t.Fatal("LOCAL_OWNED_BACKUP_WRONG_OWNER_ACCEPTED")
		}
		if secondBefore3 != localFirstSecondFingerprint(t, f3) {
			t.Fatal("LOCAL_OWNED_BACKUP_SECOND_CHANGED_BY_SELECTORS")
		}
	})

	type captureResult struct {
		source LocalOwnedBackupSource
		err    error
	}
	installCloseBlock := func(state *localGenesisSessionState, started, release chan struct{}) {
		state.firstCloseForTest = func() {
			close(started)
			<-release
		}
	}
	startCapture := func(f *localGenesisTwoVaultFixture, manifest Manifest, ctx context.Context) chan captureResult {
		done := make(chan captureResult, 1)
		go func() {
			source, err := CaptureLocalOwnedBackupSource(ctx, f.session, f.firstConfig,
				manifest.BackendRoot, manifest.VaultID, manifest.Journal,
				[]byte(f.f.password), f.f.key)
			done <- captureResult{source: source, err: err}
		}()
		return done
	}

	t.Run("request-lock-during-close", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.firstConfig)
		started := make(chan struct{})
		release := make(chan struct{})
		released := false
		localOwnedBackupBeforeCloseForTest = func(state *localGenesisSessionState) {
			installCloseBlock(state, started, release)
		}
		defer func() {
			localOwnedBackupBeforeCloseForTest = nil
			if !released {
				close(release)
			}
		}()
		done := startCapture(f, manifest, context.Background())
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("LOCAL_OWNED_BACKUP_CLOSE_NOT_REACHED")
		}
		lockReturned := make(chan struct{})
		go func() {
			f.session.RequestLock()
			close(lockReturned)
		}()
		select {
		case <-lockReturned:
		case <-time.After(2 * time.Second):
			t.Fatal("LOCAL_OWNED_BACKUP_REQUEST_LOCK_BLOCKED_BY_CLOSE")
		}
		close(release)
		released = true
		result := <-done
		if !errors.Is(result.err, ErrLocalOwnedBackupCanceled) ||
			result.source.Current != nil || result.source.Origin != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CLOSE_LOCK_NOT_FAIL_CLOSED")
		}
	})

	t.Run("cancel-during-close", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.firstConfig)
		started := make(chan struct{})
		release := make(chan struct{})
		released := false
		localOwnedBackupBeforeCloseForTest = func(state *localGenesisSessionState) {
			installCloseBlock(state, started, release)
		}
		defer func() {
			localOwnedBackupBeforeCloseForTest = nil
			if !released {
				close(release)
			}
		}()
		ctx, cancel := context.WithCancel(context.Background())
		done := startCapture(f, manifest, ctx)
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("LOCAL_OWNED_BACKUP_CLOSE_NOT_REACHED")
		}
		cancel()
		close(release)
		released = true
		result := <-done
		if !errors.Is(result.err, ErrLocalOwnedBackupCanceled) ||
			result.source.Current != nil || result.source.Origin != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CLOSE_CANCEL_NOT_FAIL_CLOSED")
		}
	})
}
