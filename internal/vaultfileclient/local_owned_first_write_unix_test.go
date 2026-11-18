//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

const (
	localFirstWriteTitle  = "Owned first item"
	localFirstWriteUser   = "owned-first-user"
	localFirstWriteSecret = "owned-first-secret-marker"
)

type localFirstWriteFixture struct {
	f                 *localGenesisTwoVaultFixture
	manifest          Manifest
	companion         Companion
	pin               vaultfilejournal.OwnedGenesisPin
	checkpoint        *vaultfile.PolicyCheckpoint
	target            personal.OwnedVaultFileFirstSuccessorTarget
	item              LocalGenesisFirstItem
	genesis           []byte
	bootstrapRevision vaultfilebackend.Revision
}

func newLocalFirstWriteFixture(t *testing.T) *localFirstWriteFixture {
	t.Helper()
	f := newLocalGenesisTwoVaultFixture(t)
	manifest, exists, err := ReadManifest(f.firstConfig)
	if err != nil || !exists {
		t.Fatal("LOCAL_FIRST_WRITE_MANIFEST_FAILED")
	}
	companion, exists, err := ReadCompanion(f.firstConfig, manifest)
	if err != nil || !exists || companion.Resume.Checkpoint == nil {
		t.Fatal("LOCAL_FIRST_WRITE_COMPANION_FAILED")
	}
	root, err := hex.DecodeString(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_ROOT_DECODE_FAILED")
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		t.Fatal("LOCAL_FIRST_WRITE_PIN_FAILED")
	}
	j, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_JOURNAL_OPEN_FAILED")
	}
	state, err := j.LoadState()
	closeErr := j.Close()
	if err != nil || closeErr != nil {
		t.Fatal("LOCAL_FIRST_WRITE_JOURNAL_STATE_FAILED")
	}
	defer clear(state.WorkingBytes)
	genesis := bytes.Clone(state.BaseBytes)
	clear(state.BaseBytes)
	checkpoint, err := vaultfile.VerifyGenesis(genesis, &pin.Root)
	if err != nil || checkpoint == nil {
		t.Fatal("LOCAL_FIRST_WRITE_GENESIS_VERIFY_FAILED")
	}
	t.Cleanup(func() {
		clear(genesis)
		clearLocalGenesisCheckpoint(checkpoint)
		clear(pin.Root.OwnerRootPublicKey)
	})
	fx := &localFirstWriteFixture{
		f: f, manifest: manifest, companion: companion, pin: pin,
		checkpoint: checkpoint, genesis: genesis,
		bootstrapRevision: state.RemoteRevision,
		item: LocalGenesisFirstItem{
			ID: localOwnedSuccessorID(t), Title: localFirstWriteTitle,
			Username: localFirstWriteUser, Password: localFirstWriteSecret,
		},
	}
	fx.target = personal.OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: manifest.BackendRoot, BackendName: manifest.Name,
		Pin: cloneLocalGenesisGenesisPin(pin),
	}
	return fx
}

func (fx *localFirstWriteFixture) write(ctx context.Context) (LocalOwnedFirstWriteResult, error) {
	return WriteLocalGenesisFirstItem(ctx, fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, fx.item)
}

func localFirstReadBackend(t *testing.T, manifest Manifest) ([]byte, vaultfilebackend.Revision) {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_BACKEND_OPEN_FAILED")
	}
	result, readErr := backend.Read(context.Background(), manifest.Name)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("LOCAL_FIRST_WRITE_BACKEND_READ_FAILED")
	}
	return result.Bytes, result.Revision
}

func localFirstRewriteBackend(t *testing.T, manifest Manifest, value []byte) vaultfilebackend.Revision {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_BACKEND_OPEN_FAILED")
	}
	current, err := backend.Read(context.Background(), manifest.Name)
	if err != nil {
		_ = backend.Close()
		t.Fatal("LOCAL_FIRST_WRITE_BACKEND_READ_FAILED")
	}
	clear(current.Bytes)
	if err := backend.ReplaceIfVersion(context.Background(), manifest.Name, current.Revision, value); err != nil {
		_ = backend.Close()
		t.Fatal("LOCAL_FIRST_WRITE_BACKEND_REPLACE_FAILED")
	}
	updated, err := backend.Read(context.Background(), manifest.Name)
	closeErr := backend.Close()
	if err != nil || closeErr != nil {
		t.Fatal("LOCAL_FIRST_WRITE_BACKEND_REVISION_FAILED")
	}
	clear(updated.Bytes)
	return updated.Revision
}

func localFirstReadPending(t *testing.T, journal string) (vaultfilejournal.State, vaultfilejournal.PreparedProposal) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(journal)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_PENDING_OPEN_FAILED")
	}
	state, prepared, loadErr := j.LoadOwnedFirstPending()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		t.Fatal("LOCAL_FIRST_WRITE_PENDING_LOAD_FAILED")
	}
	return state, prepared
}

func localFirstAssertPristine(t *testing.T, fx *localFirstWriteFixture) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(fx.manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_PRISTINE_OPEN_FAILED")
	}
	state, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil || closeErr != nil || state.Generation != 0 ||
		state.RemoteRevision != fx.bootstrapRevision ||
		!bytes.Equal(state.BaseBytes, fx.genesis) ||
		!bytes.Equal(state.BaseBytes, state.WorkingBytes) {
		t.Fatal("LOCAL_FIRST_WRITE_JOURNAL_NOT_PRISTINE")
	}
}

func localFirstReadRecord(t *testing.T, fx *localFirstWriteFixture) vaultfilejournal.OwnedFirstSuccessor {
	t.Helper()
	record, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_RECORD_READ_FAILED")
	}
	return record
}

func localFirstSecondFingerprint(t *testing.T, f *localGenesisTwoVaultFixture) [32]byte {
	t.Helper()
	manifest, exists, err := ReadManifest(f.secondConfig)
	if err != nil || !exists {
		t.Fatal("LOCAL_FIRST_WRITE_SECOND_MANIFEST_FAILED")
	}
	journalBytes, err := os.ReadFile(manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_SECOND_JOURNAL_READ_FAILED")
	}
	backendBytes, revision := localFirstReadBackend(t, manifest)
	defer clear(backendBytes)
	h := sha256.New()
	_, _ = h.Write(journalBytes)
	_, _ = h.Write(backendBytes)
	_, _ = h.Write([]byte(revision))
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func localFirstUnlockFresh(t *testing.T, f *localGenesisTwoVaultFixture) *personal.Session {
	t.Helper()
	f.session.Lock()
	session, err := personal.UnlockSession(f.f.proposal.PersonalFile, []byte(f.f.password), f.f.key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_FRESH_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)
	return session
}

func localFirstAssertSummary(t *testing.T, wrapper *LocalGenesisSession, summary LocalGenesisBaseline, fx *localFirstWriteFixture) {
	t.Helper()
	if summary.VaultID != fx.manifest.VaultID || len(summary.Items) != 1 ||
		summary.Items[0].Title != fx.item.Title {
		t.Fatal("LOCAL_FIRST_WRITE_SUMMARY_FAILED")
	}
	again, err := wrapper.Summary()
	if err != nil || len(again.Items) != 1 || again.Items[0].Title != fx.item.Title {
		t.Fatal("LOCAL_FIRST_WRITE_SUMMARY_REOPEN_FAILED")
	}
	query, err := wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: fx.item.Title, Limit: 2})
	if err != nil || len(query.Hits) != 1 || query.Hits[0].ID != fx.item.ID {
		t.Fatal("LOCAL_FIRST_WRITE_QUERY_FAILED")
	}
	if err := wrapper.ValidateExactQueryHit(query, fx.item.ID, fx.item.Title); err != nil {
		t.Fatal("LOCAL_FIRST_WRITE_QUERY_HIT_FAILED")
	}
}

func TestOwnedFirstWriteLocalPublishesAndReopens(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	secondBefore := localFirstSecondFingerprint(t, fx.f)

	result, err := fx.write(context.Background())
	if err != nil {
		t.Fatalf("WriteLocalGenesisFirstItem: %v", err)
	}
	if result.VaultID != fx.manifest.VaultID || result.JournalPath != fx.manifest.Journal ||
		result.OperationID == "" || result.Revision == "" {
		t.Fatal("LOCAL_FIRST_WRITE_RESULT_BINDING_FAILED")
	}
	if secondAfter := localFirstSecondFingerprint(t, fx.f); secondAfter != secondBefore {
		t.Fatal("LOCAL_FIRST_WRITE_SECOND_VAULT_CHANGED")
	}

	record := localFirstReadRecord(t, fx)
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)
	if record.GenesisRevision != fx.bootstrapRevision ||
		string(record.SuccessorRevision) != result.Revision ||
		!bytes.Equal(record.GenesisBytes, fx.genesis) {
		t.Fatal("LOCAL_FIRST_WRITE_RECORD_BINDING_FAILED")
	}
	backendBytes, backendRevision := localFirstReadBackend(t, fx.manifest)
	defer clear(backendBytes)
	if backendRevision != record.SuccessorRevision || !bytes.Equal(backendBytes, record.SuccessorBytes) {
		t.Fatal("LOCAL_FIRST_WRITE_BACKEND_RECORD_DISAGREE")
	}
	if vaultfile.VerifyContentTransition(fx.genesis, record.SuccessorBytes, fx.checkpoint) != nil {
		t.Fatal("LOCAL_FIRST_WRITE_TRANSITION_INVALID")
	}
	successor, err := vaultfile.ParseFile(record.SuccessorBytes)
	if err != nil || successor.Header.OpID != result.OperationID {
		t.Fatal("LOCAL_FIRST_WRITE_SUCCESSOR_OPERATION_FAILED")
	}
	signing, _, recipient := localClientAccountIdentity(t, fx.f.f.proposal.PersonalFile, []byte(fx.f.f.password), fx.f.f.key)
	defer clear(signing)
	policy := &successor.SignedPolicyProofs[len(successor.SignedPolicyProofs)-1].Policy
	writer, ok := localOwnedWriterDevice(policy, recipient, signing.Public().(ed25519.PublicKey))
	if !ok || writer != successor.Header.AuthorDeviceID {
		t.Fatal("LOCAL_FIRST_WRITE_ACCOUNT_WRITER_FAILED")
	}

	wrapper, summary, err := OpenLocalGenesisSessionForJournal(fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil || wrapper == nil {
		t.Fatal("LOCAL_FIRST_WRITE_REOPEN_FAILED")
	}
	defer wrapper.Close()
	localFirstAssertSummary(t, wrapper, summary, fx)
}

func TestOwnedFirstWriteLocalScopedChildRetiresOnSuccess(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	wrapper, summary, err := OpenLocalGenesisSessionForJournal(fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil || wrapper == nil || summary.VaultID != fx.manifest.VaultID || len(summary.Items) != 0 {
		t.Fatal("LOCAL_FIRST_WRITE_CHILD_OPEN_FAILED")
	}
	result, err := wrapper.WriteFirstItem(context.Background(), []byte(fx.f.f.password), fx.f.f.key, fx.item)
	if err != nil || result.OperationID == "" {
		t.Fatalf("WriteFirstItem: %v", err)
	}
	if _, err := wrapper.Summary(); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_FIRST_WRITE_STALE_CHILD_STILL_READS")
	}
	reopened, reopenedSummary, err := OpenLocalGenesisSessionForJournal(fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil || reopened == nil {
		t.Fatal("LOCAL_FIRST_WRITE_CHILD_REOPEN_FAILED")
	}
	defer reopened.Close()
	localFirstAssertSummary(t, reopened, reopenedSummary, fx)
}

func TestOwnedFirstWriteLocalRejectsBeforePublication(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := fx.write(ctx); !errors.Is(err, ErrLocalOwnedFirstWriteCanceled) {
			t.Fatal("LOCAL_FIRST_WRITE_CANCELED_ACCEPTED")
		}
		localFirstAssertPristine(t, fx)
		backendBytes, revision := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBytes)
		if !bytes.Equal(backendBytes, fx.genesis) || revision != fx.bootstrapRevision {
			t.Fatal("LOCAL_FIRST_WRITE_CANCELED_PUBLISHED")
		}
	})

	t.Run("locked-account", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		fx.f.session.Lock()
		if _, err := fx.write(context.Background()); !errors.Is(err, ErrLocalOwnedFirstWriteReview) {
			t.Fatal("LOCAL_FIRST_WRITE_LOCKED_ACCEPTED")
		}
		localFirstAssertPristine(t, fx)
	})

	t.Run("stale-backend-revision", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		updated := localFirstRewriteBackend(t, fx.manifest, fx.genesis)
		if updated == fx.bootstrapRevision {
			t.Fatal("LOCAL_FIRST_WRITE_STALE_REVISION_UNCHANGED")
		}
		if _, err := fx.write(context.Background()); !errors.Is(err, ErrLocalOwnedFirstWriteConflict) {
			t.Fatal("LOCAL_FIRST_WRITE_STALE_REVISION_ACCEPTED")
		}
		localFirstAssertPristine(t, fx)
		backendBytes, revision := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBytes)
		if !bytes.Equal(backendBytes, fx.genesis) || revision != updated {
			t.Fatal("LOCAL_FIRST_WRITE_STALE_REVISION_CLOBBERED")
		}
	})

	t.Run("advanced-owned-successor", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		settled := settleLocalOwnedSuccessor(t, fx.f, fx.f.firstConfig, fx.f.firstVaultID, "")
		if _, err := fx.write(context.Background()); !errors.Is(err, ErrLocalOwnedFirstWriteConflict) {
			t.Fatal("LOCAL_FIRST_WRITE_ADVANCED_ACCEPTED")
		}
		record := localFirstReadRecord(t, fx)
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		if record.SuccessorRevision != settled.successorRevision {
			t.Fatal("LOCAL_FIRST_WRITE_ADVANCED_CLOBBERED")
		}
	})

	t.Run("foreign-owner-root", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		secondManifest, exists, err := ReadManifest(fx.f.secondConfig)
		if err != nil || !exists {
			t.Fatal("LOCAL_FIRST_WRITE_FOREIGN_SECOND_MANIFEST_FAILED")
		}
		secondCompanion, exists, err := ReadCompanion(fx.f.secondConfig, secondManifest)
		if err != nil || !exists || secondCompanion.Resume.Checkpoint == nil {
			t.Fatal("LOCAL_FIRST_WRITE_FOREIGN_SECOND_COMPANION_FAILED")
		}
		companion := fx.companion
		checkpoint := *companion.Resume.Checkpoint
		checkpoint.OwnerRootKeyID = secondCompanion.Resume.Checkpoint.OwnerRootKeyID
		checkpoint.OwnerRootPublicKey = secondCompanion.Resume.Checkpoint.OwnerRootPublicKey
		companion.Resume.Checkpoint = &checkpoint
		raw, err := json.Marshal(companion)
		if err != nil {
			t.Fatal("LOCAL_FIRST_WRITE_FOREIGN_COMPANION_ENCODE_FAILED")
		}
		path, err := CompanionPath(fx.f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_FIRST_WRITE_FOREIGN_COMPANION_PATH_FAILED")
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal("LOCAL_FIRST_WRITE_FOREIGN_COMPANION_WRITE_FAILED")
		}
		if _, err := fx.write(context.Background()); !errors.Is(err, ErrLocalOwnedFirstWriteReview) &&
			!errors.Is(err, ErrLocalOwnedFirstWriteConflict) {
			t.Fatal("LOCAL_FIRST_WRITE_FOREIGN_OWNER_ACCEPTED")
		}
		localFirstAssertPristine(t, fx)
		backendBytes, revision := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBytes)
		if !bytes.Equal(backendBytes, fx.genesis) || revision != fx.bootstrapRevision {
			t.Fatal("LOCAL_FIRST_WRITE_FOREIGN_OWNER_PUBLISHED")
		}
	})
}

func TestOwnedFirstWriteLocalConflictPreservesPreparationAndDoesNotClobber(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	foreign := []byte("foreign writer successor")
	var foreignRevision vaultfilebackend.Revision
	var hookErr error
	localOwnedFirstWriteAfterPrepareForTest = func() {
		backend, err := vaultfilebackend.OpenExistingDir(fx.manifest.BackendRoot)
		if err != nil {
			hookErr = err
			return
		}
		current, err := backend.Read(context.Background(), fx.manifest.Name)
		if err != nil {
			hookErr = err
			_ = backend.Close()
			return
		}
		clear(current.Bytes)
		if err := backend.ReplaceIfVersion(context.Background(), fx.manifest.Name, current.Revision, foreign); err != nil {
			hookErr = err
		}
		updated, err := backend.Read(context.Background(), fx.manifest.Name)
		closeErr := backend.Close()
		if err != nil || closeErr != nil {
			hookErr = errors.Join(err, closeErr)
			return
		}
		defer clear(updated.Bytes)
		foreignRevision = updated.Revision
	}
	t.Cleanup(func() { localOwnedFirstWriteAfterPrepareForTest = nil })
	if _, err := fx.write(context.Background()); !errors.Is(err, ErrLocalOwnedFirstWriteConflict) {
		t.Fatalf("conflict write error = %v, want conflict", err)
	}
	localOwnedFirstWriteAfterPrepareForTest = nil
	if hookErr != nil {
		t.Fatalf("conflict hook: %v", hookErr)
	}
	backendBytes, backendRevision := localFirstReadBackend(t, fx.manifest)
	defer clear(backendBytes)
	if !bytes.Equal(backendBytes, foreign) || backendRevision != foreignRevision {
		t.Fatal("LOCAL_FIRST_WRITE_CONFLICT_CLOBBERED")
	}
	pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
	defer clear(pending.BaseBytes)
	defer clear(pending.WorkingBytes)
	defer clear(prepared.Proposal.Bytes)
	if pending.Generation != 1 || !bytes.Equal(pending.BaseBytes, fx.genesis) ||
		pending.RemoteRevision != fx.bootstrapRevision ||
		!bytes.Equal(prepared.Proposal.Bytes, pending.WorkingBytes) {
		t.Fatal("LOCAL_FIRST_WRITE_CONFLICT_PREPARATION_LOST")
	}
	if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
		t.Fatal("LOCAL_FIRST_WRITE_CONFLICT_ACKNOWLEDGED")
	}
	if _, err := ResumeLocalGenesisFirstItem(context.Background(), fx.f.session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key); !errors.Is(err, ErrLocalOwnedFirstWriteConflict) {
		t.Fatal("LOCAL_FIRST_WRITE_CONFLICT_RESUME_ACCEPTED")
	}
	afterBytes, afterRevision := localFirstReadBackend(t, fx.manifest)
	defer clear(afterBytes)
	if !bytes.Equal(afterBytes, foreign) || afterRevision != foreignRevision {
		t.Fatal("LOCAL_FIRST_WRITE_CONFLICT_RESUME_CLOBBERED")
	}
	pendingAgain, preparedAgain := localFirstReadPending(t, fx.manifest.Journal)
	defer clear(pendingAgain.BaseBytes)
	defer clear(pendingAgain.WorkingBytes)
	defer clear(preparedAgain.Proposal.Bytes)
	if !sameLocalOwnedFirstPrepared(prepared, preparedAgain) {
		t.Fatal("LOCAL_FIRST_WRITE_CONFLICT_PREPARATION_CHANGED")
	}
}

func TestOwnedFirstWriteLocalResumeAfterInterruptedBeforePublication(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	localOwnedFirstWriteAfterPrepareForTest = cancel
	t.Cleanup(func() { localOwnedFirstWriteAfterPrepareForTest = nil })
	if _, err := fx.write(ctx); !errors.Is(err, ErrLocalOwnedFirstWriteIndeterminate) {
		t.Fatalf("interrupted write error = %v, want indeterminate", err)
	}
	localOwnedFirstWriteAfterPrepareForTest = nil
	localFirstAssertPristineBeforePrepared(t, fx)

	before, preparedBefore := localFirstReadPending(t, fx.manifest.Journal)
	defer clear(before.BaseBytes)
	defer clear(before.WorkingBytes)
	defer clear(preparedBefore.Proposal.Bytes)
	backendBytes, backendRevision := localFirstReadBackend(t, fx.manifest)
	defer clear(backendBytes)
	if !bytes.Equal(backendBytes, fx.genesis) || backendRevision != fx.bootstrapRevision {
		t.Fatal("LOCAL_FIRST_WRITE_INTERRUPTED_BEFORE_PUBLISH")
	}
	if wrapper, _, err := OpenLocalGenesisSessionForJournal(fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key); wrapper != nil || !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_FIRST_WRITE_PENDING_READABLE_THROUGH_A1")
	}

	session := localFirstUnlockFresh(t, fx.f)
	result, err := ResumeLocalGenesisFirstItem(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil {
		t.Fatalf("ResumeLocalGenesisFirstItem: %v", err)
	}
	if result.OperationID != preparedBefore.Proposal.OperationID {
		t.Fatal("LOCAL_FIRST_WRITE_RESUME_CREATED_NEW_PROPOSAL")
	}
	record := localFirstReadRecord(t, fx)
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)
	if !bytes.Equal(record.SuccessorBytes, preparedBefore.Proposal.Bytes) {
		t.Fatal("LOCAL_FIRST_WRITE_RESUME_DUPLICATED_PROPOSAL")
	}
	afterBytes, afterRevision := localFirstReadBackend(t, fx.manifest)
	defer clear(afterBytes)
	if !bytes.Equal(afterBytes, preparedBefore.Proposal.Bytes) ||
		string(afterRevision) != result.Revision || record.SuccessorRevision != afterRevision {
		t.Fatal("LOCAL_FIRST_WRITE_RESUME_BACKEND_DISAGREE")
	}
	wrapper, summary, err := OpenLocalGenesisSessionForJournal(session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil || wrapper == nil {
		t.Fatal("LOCAL_FIRST_WRITE_RESUME_REOPEN_FAILED")
	}
	defer wrapper.Close()
	localFirstAssertSummary(t, wrapper, summary, fx)
	retired, _, retiredErr := OpenLocalGenesisSessionForJournal(fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if retired != nil {
		_ = retired.Close()
		t.Fatal("LOCAL_FIRST_WRITE_RETIRED_SESSION_REOPENED")
	}
	if !errors.Is(retiredErr, ErrLocalReview) {
		t.Fatal("LOCAL_FIRST_WRITE_RETIRED_SESSION_NOT_REJECTED")
	}
}

func TestOwnedFirstWriteLocalResumeAfterInterruptedAcknowledgement(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	localOwnedFirstWriteAfterPublishForTest = cancel
	t.Cleanup(func() { localOwnedFirstWriteAfterPublishForTest = nil })
	if _, err := fx.write(ctx); !errors.Is(err, ErrLocalOwnedFirstWriteIndeterminate) {
		t.Fatalf("interrupted ack error = %v, want indeterminate", err)
	}
	localOwnedFirstWriteAfterPublishForTest = nil
	before, preparedBefore := localFirstReadPending(t, fx.manifest.Journal)
	defer clear(before.BaseBytes)
	defer clear(before.WorkingBytes)
	defer clear(preparedBefore.Proposal.Bytes)
	backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
	defer clear(backendBefore)
	if !bytes.Equal(backendBefore, preparedBefore.Proposal.Bytes) {
		t.Fatal("LOCAL_FIRST_WRITE_INTERRUPTED_ACK_BACKEND_MISSING")
	}
	if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
		t.Fatal("LOCAL_FIRST_WRITE_INTERRUPTED_ACK_ALREADY_ACKED")
	}
	if wrapper, _, err := OpenLocalGenesisSessionForJournal(fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key); wrapper != nil || !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_FIRST_WRITE_INTERRUPTED_ACK_READABLE_THROUGH_A1")
	}

	session := localFirstUnlockFresh(t, fx.f)
	result, err := ResumeLocalGenesisFirstItem(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil {
		t.Fatalf("ResumeLocalGenesisFirstItem: %v", err)
	}
	if result.OperationID != preparedBefore.Proposal.OperationID {
		t.Fatal("LOCAL_FIRST_WRITE_ACK_RESUME_CREATED_NEW_PROPOSAL")
	}
	record := localFirstReadRecord(t, fx)
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)
	if !bytes.Equal(record.SuccessorBytes, preparedBefore.Proposal.Bytes) ||
		record.SuccessorRevision != revisionBefore {
		t.Fatal("LOCAL_FIRST_WRITE_ACK_RESUME_CHANGED_DURABLE_PROPOSAL")
	}
	backendAfter, revisionAfter := localFirstReadBackend(t, fx.manifest)
	defer clear(backendAfter)
	if !bytes.Equal(backendAfter, backendBefore) || revisionAfter != revisionBefore {
		t.Fatal("LOCAL_FIRST_WRITE_ACK_RESUME_REWROTE_BACKEND")
	}
	wrapper, summary, err := OpenLocalGenesisSessionForJournal(session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil || wrapper == nil {
		t.Fatal("LOCAL_FIRST_WRITE_ACK_RESUME_REOPEN_FAILED")
	}
	defer wrapper.Close()
	localFirstAssertSummary(t, wrapper, summary, fx)
	retired, _, retiredErr := OpenLocalGenesisSessionForJournal(fx.f.session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key)
	if retired != nil {
		_ = retired.Close()
		t.Fatal("LOCAL_FIRST_WRITE_ACK_RETIRED_SESSION_REOPENED")
	}
	if !errors.Is(retiredErr, ErrLocalReview) {
		t.Fatal("LOCAL_FIRST_WRITE_ACK_RETIRED_SESSION_NOT_REJECTED")
	}
}

func TestOwnedFirstWriteLocalResultAndErrorsRetainNoSecrets(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	result, err := fx.write(context.Background())
	if err != nil {
		t.Fatalf("WriteLocalGenesisFirstItem: %v", err)
	}
	signing, _, _ := localClientAccountIdentity(t, fx.f.f.proposal.PersonalFile, []byte(fx.f.f.password), fx.f.f.key)
	defer clear(signing)
	needles := []string{
		localFirstWriteTitle, localFirstWriteUser, localFirstWriteSecret,
		fx.companion.Resume.Checkpoint.OwnerRootPublicKey,
		hex.EncodeToString(signing.Seed()), hex.EncodeToString(signing),
	}
	rendered := fmt.Sprintf("%+v", result)
	for _, needle := range needles {
		if needle != "" && strings.Contains(rendered, needle) {
			t.Fatal("LOCAL_FIRST_WRITE_RESULT_LEAKED_SECRET")
		}
	}

	bad := newLocalFirstWriteFixture(t)
	if _, err := WriteLocalGenesisFirstItem(context.Background(), bad.f.session,
		bad.f.firstConfig, bad.manifest.BackendRoot, bad.manifest.VaultID, bad.manifest.Journal,
		[]byte("wrong-factor"), bad.f.f.key, bad.item); err == nil {
		t.Fatal("LOCAL_FIRST_WRITE_WRONG_FACTOR_ACCEPTED")
	} else {
		message := err.Error()
		for _, needle := range []string{localFirstWriteTitle, localFirstWriteUser, localFirstWriteSecret,
			bad.companion.Resume.Checkpoint.OwnerRootPublicKey} {
			if needle != "" && strings.Contains(message, needle) {
				t.Fatal("LOCAL_FIRST_WRITE_ERROR_LEAKED_SECRET")
			}
		}
	}
	localFirstAssertPristine(t, bad)
}

func localFirstAssertPristineBeforePrepared(t *testing.T, fx *localFirstWriteFixture) {
	t.Helper()
	state, prepared := localFirstReadPending(t, fx.manifest.Journal)
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	defer clear(prepared.Proposal.Bytes)
	if state.Generation != 1 || !bytes.Equal(state.BaseBytes, fx.genesis) ||
		state.RemoteRevision != fx.bootstrapRevision ||
		prepared.WorkingGeneration != 1 || prepared.Proposal.Generation != 1 ||
		!bytes.Equal(prepared.Proposal.Bytes, state.WorkingBytes) {
		t.Fatal("LOCAL_FIRST_WRITE_PREPARED_SHAPE_FAILED")
	}
}
