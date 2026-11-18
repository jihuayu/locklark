//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

const ownedSuccessorItemID = "owned-successor-item"
const ownedSuccessorTitle = "Owned successor item"

type ownedSuccessorVault struct {
	session *Session
	base    *ownedChildFixture

	password []byte
	key      []byte

	journal    string
	checkpoint vaultfile.PolicyCheckpoint
	pin        vaultfilejournal.OwnedGenesisPin
	target     OwnedVaultFileFirstSuccessorTarget

	origin            vaultfilejournal.State
	successor         []byte
	successorRevision vaultfilebackend.Revision

	backendRoot string
	backendName string
}

func ownedSuccessorLocalIdentity(t *testing.T, session *Session) (ed25519.PrivateKey, *age.X25519Identity, string) {
	t.Helper()
	var accountIdentity identity
	if err := json.Unmarshal(session.material, &accountIdentity); err != nil ||
		len(accountIdentity.Signing) != ed25519.SeedSize || accountIdentity.Device == "" {
		t.Fatal("OWNED_SUCCESSOR_LOCAL_IDENTITY_FAILED")
	}
	defer func() {
		accountIdentity.clear()
		accountIdentity.Device = ""
	}()
	localAge, err := age.ParseX25519Identity(accountIdentity.Device)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_LOCAL_AGE_FAILED")
	}
	return ed25519.NewKeyFromSeed(accountIdentity.Signing), localAge, localAge.Recipient().String()
}

func sealOwnedSuccessor(t *testing.T, genesis []byte, checkpoint vaultfile.PolicyCheckpoint, signer ed25519.PrivateKey, ageIdentity *age.X25519Identity, recipient string) []byte {
	t.Helper()
	base, err := vaultfile.ParseFile(genesis)
	if err != nil || len(base.SignedPolicyProofs) == 0 {
		t.Fatal("OWNED_SUCCESSOR_GENESIS_PARSE_FAILED")
	}
	policy := &base.SignedPolicyProofs[len(base.SignedPolicyProofs)-1].Policy
	deviceID, ok := localVaultFileWriterDevice(policy, recipient, signer.Public().(ed25519.PublicKey))
	if !ok {
		t.Fatal("OWNED_SUCCESSOR_DEVICE_BIND_FAILED")
	}
	var slot *vaultfile.DeviceSlot
	for i := range base.VUKDeviceSlots {
		if base.VUKDeviceSlots[i].DeviceID == deviceID {
			slot = &base.VUKDeviceSlots[i]
			break
		}
	}
	if slot == nil {
		t.Fatal("OWNED_SUCCESSOR_VUK_SLOT_MISSING")
	}
	vuk, err := vaultfile.OpenVUKForDevice(*slot, checkpoint.VaultID, base.Header.KeyEpoch, deviceID,
		recipient, ageIdentity)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_VUK_OPEN_FAILED")
	}
	defer clear(vuk)
	digest, err := vaultfile.FileDigest(base)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_PARENT_DIGEST_FAILED")
	}
	parent, err := hex.DecodeString(digest)
	if err != nil || len(parent) != 32 {
		t.Fatal("OWNED_SUCCESSOR_PARENT_DECODE_FAILED")
	}
	opID, err := randomID()
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_OPERATION_ID_FAILED")
	}
	draft := &vaultfile.File{
		Format: base.Format, Version: base.Version,
		SignedPolicyProofs: base.SignedPolicyProofs, Header: base.Header,
	}
	draft.Header.ContentSeq++
	draft.Header.PrevDigest = parent
	draft.Header.RevisionID = ""
	draft.Header.OpID = opID
	draft.Header.AuthorDeviceID = deviceID
	items := []vault.Item{{
		ID: ownedSuccessorItemID, Kind: "login", Title: ownedSuccessorTitle,
		Username: "successor-user", Password: "fixture-hidden",
	}}
	sealed, err := vault.SealAuthenticatedItems(draft, []byte{}, items, &checkpoint, vuk, signer)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_SEAL_FAILED")
	}
	if err := vaultfile.VerifyContentTransition(genesis, sealed, &checkpoint); err != nil {
		t.Fatal("OWNED_SUCCESSOR_TRANSITION_FAILED")
	}
	return sealed
}

func newOwnedSuccessorVault(t *testing.T, recoveryAuthor bool, journalRevisionOverride string) *ownedSuccessorVault {
	t.Helper()
	base := newOwnedChildFixture(t)
	signer, ageIdentity, recipient := ownedSuccessorLocalIdentity(t, base.session)

	vaultID, err := randomID()
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_SELECTOR_FAILED")
	}
	public, err := base.session.PrepareVaultFileOwnership(vaultID)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_OWNERSHIP_FAILED")
	}
	record := testVaultFileOwnerRecord(t, base.session, base.session.path, public.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
	genesis, checkpoint := ownedChildGenesis(t, record, signer, recipient)

	backendRoot := filepath.Join(base.dir, "successor-backend")
	backendName := "owned-successor"
	backend, err := vaultfilebackend.OpenDir(backendRoot)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_BACKEND_OPEN_FAILED")
	}
	if err := backend.CreateIfAbsent(context.Background(), backendName, genesis); err != nil {
		_ = backend.Close()
		t.Fatal("OWNED_SUCCESSOR_BACKEND_CREATE_FAILED")
	}
	originRead, err := backend.Read(context.Background(), backendName)
	closeErr := backend.Close()
	if err != nil || closeErr != nil {
		t.Fatal("OWNED_SUCCESSOR_BACKEND_READ_FAILED")
	}
	defer clear(originRead.Bytes)

	journalDir := filepath.Join(base.dir, "successor-journal")
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal("OWNED_SUCCESSOR_JOURNAL_DIR_FAILED")
	}
	journalPath := filepath.Join(journalDir, "state.journal")
	if err := vaultfilejournal.CreateNewState(journalPath, vaultfilejournal.State{
		BaseBytes:      bytes.Clone(genesis),
		WorkingBytes:   bytes.Clone(genesis),
		RemoteRevision: originRead.Revision,
		Generation:     0,
	}); err != nil {
		t.Fatal("OWNED_SUCCESSOR_JOURNAL_CREATE_FAILED")
	}

	successorSigner := signer
	successorAge := ageIdentity
	successorRecipient := recipient
	if recoveryAuthor {
		successorSigner = ed25519.NewKeyFromSeed(record.RecoverySigningSeed)
		successorAge, err = age.ParseX25519Identity(string(record.RecoveryAgeIdentity))
		if err != nil {
			t.Fatal("OWNED_SUCCESSOR_RECOVERY_AGE_FAILED")
		}
		successorRecipient = successorAge.Recipient().String()
	}
	successor := sealOwnedSuccessor(t, genesis, checkpoint, successorSigner, successorAge, successorRecipient)
	successorFile, err := vaultfile.ParseFile(successor)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_PARSE_FAILED")
	}

	backend, err = vaultfilebackend.OpenDir(backendRoot)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_BACKEND_REOPEN_FAILED")
	}
	if err := backend.ReplaceIfVersion(context.Background(), backendName, originRead.Revision, successor); err != nil {
		_ = backend.Close()
		t.Fatal("OWNED_SUCCESSOR_BACKEND_REPLACE_FAILED")
	}
	successorRead, err := backend.Read(context.Background(), backendName)
	closeErr = backend.Close()
	if err != nil || closeErr != nil {
		t.Fatal("OWNED_SUCCESSOR_BACKEND_SUCCESSOR_READ_FAILED")
	}
	defer clear(successorRead.Bytes)
	journalRevision := successorRead.Revision
	if journalRevisionOverride != "" {
		journalRevision = vaultfilebackend.Revision(journalRevisionOverride)
	}

	journal, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_JOURNAL_OPEN_FAILED")
	}
	origin, err := journal.LoadState()
	if err != nil {
		_ = journal.Close()
		t.Fatal("OWNED_SUCCESSOR_JOURNAL_STATE_FAILED")
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       origin.Generation + 1,
		OperationID:      successorFile.Header.OpID,
		ExpectedRevision: origin.RemoteRevision,
		Bytes:            successor,
	}
	pin := vaultfilejournal.OwnedGenesisPin{
		Root: vaultfile.GenesisRootPin{
			VaultID: checkpoint.VaultID, OwnerRootKeyID: checkpoint.OwnerRootKeyID,
			OwnerRootPublicKey: bytes.Clone(checkpoint.OwnerRootPublicKey),
		},
		SealedSHA256: sha256.Sum256(genesis),
		OperationID:  genesisFileOperationID(t, genesis),
	}
	prepareErr := journal.PrepareWorkingIfState(origin, proposal)
	ackErr := journal.AckOwnedFirstSuccessor(origin, pin, proposal, successor, journalRevision)
	journalCloseErr := journal.Close()
	if prepareErr != nil || ackErr != nil || journalCloseErr != nil {
		t.Fatal("OWNED_SUCCESSOR_SETTLEMENT_FAILED")
	}

	return &ownedSuccessorVault{
		session: base.session, base: base, password: base.password, key: base.key,
		journal: journalPath, checkpoint: checkpoint, pin: pin,
		target: OwnedVaultFileFirstSuccessorTarget{
			BackendRoot: backendRoot, BackendName: backendName, Pin: pin,
		},
		origin: origin, successor: bytes.Clone(successor), successorRevision: journalRevision,
		backendRoot: backendRoot, backendName: backendName,
	}
}

func genesisFileOperationID(t *testing.T, genesis []byte) string {
	t.Helper()
	file, err := vaultfile.ParseFile(genesis)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_GENESIS_OPERATION_FAILED")
	}
	return file.Header.OpID
}

func (v *ownedSuccessorVault) open(t *testing.T) (VaultFileChildToken, []VaultFileBaselineItem) {
	t.Helper()
	token, items, err := v.session.OpenOwnedFirstSuccessorVaultFileChild(
		v.journal, v.target, &v.checkpoint, v.password, v.key,
		VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil || len(items) != 1 || items[0].ID != ownedSuccessorItemID ||
		items[0].Title != ownedSuccessorTitle {
		t.Fatal("OWNED_SUCCESSOR_OPEN_FAILED")
	}
	return token, items
}

func (v *ownedSuccessorVault) rewriteBackend(t *testing.T, data []byte) vaultfilebackend.Revision {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(v.backendRoot)
	if err != nil {
		t.Fatal("OWNED_SUCCESSOR_REWRITE_OPEN_FAILED")
	}
	current, err := backend.Read(context.Background(), v.backendName)
	if err != nil {
		_ = backend.Close()
		t.Fatal("OWNED_SUCCESSOR_REWRITE_READ_FAILED")
	}
	clear(current.Bytes)
	if err := backend.ReplaceIfVersion(context.Background(), v.backendName, current.Revision, data); err != nil {
		_ = backend.Close()
		t.Fatal("OWNED_SUCCESSOR_REWRITE_REPLACE_FAILED")
	}
	updated, err := backend.Read(context.Background(), v.backendName)
	closeErr := backend.Close()
	if err != nil || closeErr != nil {
		t.Fatal("OWNED_SUCCESSOR_REWRITE_READBACK_FAILED")
	}
	defer clear(updated.Bytes)
	return updated.Revision
}

func TestOwnedFirstSuccessorReadOnlyChildAdoptsAndRevalidates(t *testing.T) {
	v := newOwnedSuccessorVault(t, false, "")
	token, _ := v.open(t)
	items, err := v.session.ReadVaultFileChild(token, VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil || len(items) != 1 || items[0].ID != ownedSuccessorItemID {
		t.Fatal("OWNED_SUCCESSOR_READ_FAILED")
	}
	if err := v.session.RevalidateVaultFileChildOwnership(token); err != nil {
		t.Fatal("OWNED_SUCCESSOR_REVALIDATE_FAILED")
	}
	if err := v.session.LockVaultFileChild(token); err != nil {
		t.Fatal("OWNED_SUCCESSOR_LOCK_FAILED")
	}
}

func TestOwnedFirstSuccessorReadOnlyChildRejectsRevisionAndByteMismatch(t *testing.T) {
	t.Run("journal-revision-only", func(t *testing.T) {
		v := newOwnedSuccessorVault(t, false, "journal-only-revision")
		if _, _, err := v.session.OpenOwnedFirstSuccessorVaultFileChild(
			v.journal, v.target, &v.checkpoint, v.password, v.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineJournal) {
			t.Fatal("OWNED_SUCCESSOR_JOURNAL_REVISION_MISMATCH_ACCEPTED")
		}
	})

	t.Run("backend-revision-only-after-open", func(t *testing.T) {
		v := newOwnedSuccessorVault(t, false, "")
		token, _ := v.open(t)
		newRevision := v.rewriteBackend(t, v.successor)
		if newRevision == v.successorRevision {
			t.Fatal("OWNED_SUCCESSOR_REWRITE_REVISION_UNCHANGED")
		}
		if _, err := v.session.ReadVaultFileChild(token, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineJournal) {
			t.Fatal("OWNED_SUCCESSOR_BACKEND_REVISION_MISMATCH_ACCEPTED")
		}
	})

	t.Run("backend-bytes-after-open", func(t *testing.T) {
		v := newOwnedSuccessorVault(t, false, "")
		token, _ := v.open(t)
		v.rewriteBackend(t, []byte("foreign backend bytes"))
		if _, err := v.session.ReadVaultFileChild(token, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineJournal) {
			t.Fatal("OWNED_SUCCESSOR_BACKEND_BYTES_MISMATCH_ACCEPTED")
		}
	})
}

func TestOwnedFirstSuccessorReadOnlyChildRejectsWrongSuccessorSigner(t *testing.T) {
	v := newOwnedSuccessorVault(t, true, "")
	if _, _, err := v.session.OpenOwnedFirstSuccessorVaultFileChild(
		v.journal, v.target, &v.checkpoint, v.password, v.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineVerification) {
		t.Fatal("OWNED_SUCCESSOR_WRONG_SIGNER_ACCEPTED")
	}
}

func TestOwnedFirstSuccessorReadOnlyChildRejectsLockedAccountAndMalformedJournal(t *testing.T) {
	t.Run("locked-account", func(t *testing.T) {
		v := newOwnedSuccessorVault(t, false, "")
		token, _ := v.open(t)
		v.session.Lock()
		if _, err := v.session.ReadVaultFileChild(token, VaultFileChildOptions{}); !errors.Is(err, ErrSessionLocked) {
			t.Fatal("OWNED_SUCCESSOR_LOCKED_ACCOUNT_READ_ACCEPTED")
		}
		if _, _, err := v.session.OpenOwnedFirstSuccessorVaultFileChild(
			v.journal, v.target, &v.checkpoint, v.password, v.key, VaultFileChildOptions{}); !errors.Is(err, ErrSessionLocked) {
			t.Fatal("OWNED_SUCCESSOR_LOCKED_ACCOUNT_OPEN_ACCEPTED")
		}
	})

	t.Run("malformed-journal", func(t *testing.T) {
		v := newOwnedSuccessorVault(t, false, "")
		if err := os.WriteFile(v.journal, []byte("not a journal"), 0600); err != nil {
			t.Fatal("OWNED_SUCCESSOR_JOURNAL_CORRUPT_WRITE_FAILED")
		}
		if _, _, err := v.session.OpenOwnedFirstSuccessorVaultFileChild(
			v.journal, v.target, &v.checkpoint, v.password, v.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineJournal) {
			t.Fatal("OWNED_SUCCESSOR_MALFORMED_JOURNAL_ACCEPTED")
		}
	})
}

func TestOwnedFirstSuccessorReadOnlyChildStaleObservationIsNotProjected(t *testing.T) {
	v := newOwnedSuccessorVault(t, false, "")
	token, _ := v.open(t)
	replaced := false
	vaultFileChildReadHook = func() {
		if replaced {
			return
		}
		replaced = true
		v.rewriteBackend(t, v.successor)
	}
	t.Cleanup(func() { vaultFileChildReadHook = nil })
	if items, err := v.session.ReadVaultFileChild(token, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineJournal) || len(items) != 0 {
		t.Fatal("OWNED_SUCCESSOR_STALE_OBSERVATION_PROJECTED")
	}
}

func TestOwnedFirstSuccessorReadOnlyChildRejectsBackendAdvanceAtCandidateHook(t *testing.T) {
	v := newOwnedSuccessorVault(t, false, "")
	siblingToken, _ := openOwnedChild(t, v.session, v.base.a, v.password, v.key)
	if ownedChildAt(v.session, v.base.a.journal) == nil {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_SIBLING_MISSING")
	}

	var advanced atomic.Bool
	vaultFileChildCandidateReady = func(*vaultfile.ScopedUnlock) {
		if advanced.CompareAndSwap(false, true) {
			// Same successor bytes, new opaque revision, after the earlier
			// post-decryption recheck but before registration completes.
			v.rewriteBackend(t, v.successor)
		}
	}
	t.Cleanup(func() { vaultFileChildCandidateReady = nil })
	var candidateCloses atomic.Int32
	vaultFileChildBeforeHandleClose = func() { candidateCloses.Add(1) }
	t.Cleanup(func() { vaultFileChildBeforeHandleClose = nil })

	token, items, err := v.session.OpenOwnedFirstSuccessorVaultFileChild(
		v.journal, v.target, &v.checkpoint, v.password, v.key,
		VaultFileChildOptions{IncludeItemIDs: true})
	if !errors.Is(err, ErrVaultFileBaselineJournal) || !errors.Is(err, errVaultFileChildFinalHandoff) {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_ADVANCE_ACCEPTED")
	}
	if token != (VaultFileChildToken{}) || items != nil {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_ADVANCE_DELIVERED")
	}
	if !advanced.Load() {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_HOOK_NOT_RUN")
	}
	if candidateCloses.Load() != 1 {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_HANDLE_LEAKED")
	}
	if ownedChildAt(v.session, v.journal) != nil {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_REGISTRATION_RETAINED")
	}
	if ownedChildAt(v.session, v.base.a.journal) == nil {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_SIBLING_REVOKED")
	}
	if ownedChildAllCount(v.session) != 1 {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_CHILD_LEAKED")
	}
	assertOwnedChildRead(t, v.session, siblingToken)
	if err := v.session.RevalidateVaultFileChildOwnership(siblingToken); err != nil {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_SIBLING_UNHEALTHY")
	}
	if err := v.session.LockVaultFileChild(siblingToken); err != nil {
		t.Fatal("OWNED_SUCCESSOR_CANDIDATE_SIBLING_LOCK_FAILED")
	}
}

func TestOwnedFirstSuccessorBatchPropagatesFinalHandoffFailure(t *testing.T) {
	v := newOwnedSuccessorVault(t, false, "")
	targets := []OwnedVaultFileTarget{
		{
			JournalPath: v.base.a.journal,
			Checkpoint:  *v.base.a.checkpoint,
			Options:     VaultFileChildOptions{IncludeItemIDs: true},
		},
		{
			JournalPath: v.journal,
			Checkpoint:  v.checkpoint,
			Options:     VaultFileChildOptions{IncludeItemIDs: true},
			Successor:   &v.target,
		},
	}
	var opens atomic.Int32
	vaultFileChildCandidateReady = func(*vaultfile.ScopedUnlock) {
		if opens.Add(1) == 2 {
			v.rewriteBackend(t, v.successor)
		}
	}
	t.Cleanup(func() { vaultFileChildCandidateReady = nil })
	var closes atomic.Int32
	vaultFileChildBeforeHandleClose = func() { closes.Add(1) }
	t.Cleanup(func() { vaultFileChildBeforeHandleClose = nil })

	parent, results, err := UnlockSessionWithOwnedVaultFileChildren(
		context.Background(), v.session.path, v.password, v.key, time.Minute, targets)
	if !errors.Is(err, ErrVaultFileBaselineJournal) ||
		!errors.Is(err, errVaultFileChildFinalHandoff) {
		t.Fatal("OWNED_SUCCESSOR_BATCH_HANDOFF_NOT_PROPAGATED")
	}
	if parent != nil || results != nil {
		t.Fatal("OWNED_SUCCESSOR_BATCH_HANDOFF_DELIVERED")
	}
	if closes.Load() != 2 {
		t.Fatal("OWNED_SUCCESSOR_BATCH_HANDOFF_LEAKED_CHILD")
	}
}

func TestOwnedFirstSuccessorBackendReadRequiresBytesAtSameRevision(t *testing.T) {
	expected := []byte("expected-successor-ciphertext")
	revision := vaultfilebackend.Revision("opaque-revision")
	t.Run("same-bytes-same-revision", func(t *testing.T) {
		if err := verifyOwnedVaultFileSuccessorRead(vaultfilebackend.ReadResult{
			Bytes: bytes.Clone(expected), Revision: revision,
		}, nil, nil, expected, revision); err != nil {
			t.Fatal("OWNED_SUCCESSOR_BACKEND_EXACT_READ_REJECTED")
		}
	})
	t.Run("same-revision-different-bytes", func(t *testing.T) {
		// A revision-only comparison would accept this negative case.
		if err := verifyOwnedVaultFileSuccessorRead(vaultfilebackend.ReadResult{
			Bytes: []byte("different-successor-ciphertext"), Revision: revision,
		}, nil, nil, expected, revision); !errors.Is(err, ErrVaultFileBaselineJournal) {
			t.Fatal("OWNED_SUCCESSOR_BACKEND_BYTES_AT_SAME_REVISION_ACCEPTED")
		}
	})
}
