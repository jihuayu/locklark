//go:build darwin || linux

package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

const ownedChildItemID = "owned-recovery-item"

type ownedChildVault struct {
	journal    string
	checkpoint *vaultfile.PolicyCheckpoint
}

type ownedChildFixture struct {
	dir       string
	session   *Session
	password  []byte
	key       []byte
	signer    ed25519.PrivateKey
	recipient string
	a         ownedChildVault
}

func newOwnedChildFixture(t *testing.T) *ownedChildFixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "personal.ll")
	fx := &ownedChildFixture{
		dir:      dir,
		password: []byte("owned-child-full-factor"),
		key:      bytes.Repeat([]byte{0x6d}, 16),
	}
	if err := Create(path, string(fx.password), fx.key); err != nil {
		t.Fatal("OWNED_CHILD_CREATE_FAILED")
	}
	session, err := UnlockSession(path, fx.password, fx.key, time.Minute)
	if err != nil {
		t.Fatal("OWNED_CHILD_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)
	fx.session = session
	fx.signer, fx.recipient = ownedChildLocalReader(t, session)
	t.Cleanup(func() { clear(fx.signer) })
	fx.a = fx.addVault(t, "a")
	return fx
}

func ownedChildLocalReader(t *testing.T, session *Session) (ed25519.PrivateKey, string) {
	t.Helper()
	var accountIdentity identity
	if err := json.Unmarshal(session.material, &accountIdentity); err != nil ||
		len(accountIdentity.Signing) != ed25519.SeedSize || accountIdentity.Device == "" {
		t.Fatal("OWNED_CHILD_LOCAL_IDENTITY_FAILED")
	}
	defer func() {
		accountIdentity.clear()
		accountIdentity.Device = ""
	}()
	localAge, err := age.ParseX25519Identity(accountIdentity.Device)
	if err != nil {
		t.Fatal("OWNED_CHILD_LOCAL_AGE_FAILED")
	}
	return ed25519.NewKeyFromSeed(accountIdentity.Signing), localAge.Recipient().String()
}

func (fx *ownedChildFixture) addVault(t *testing.T, name string) ownedChildVault {
	t.Helper()
	selector, err := randomID()
	if err != nil {
		t.Fatal("OWNED_CHILD_SELECTOR_FAILED")
	}
	public, err := fx.session.PrepareVaultFileOwnership(selector)
	if err != nil {
		t.Fatal("OWNED_CHILD_PREPARE_FAILED")
	}
	record := testVaultFileOwnerRecord(t, fx.session, fx.session.path, public.VaultID)
	defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
	sealed, pin := ownedChildGenesis(t, record, fx.signer, fx.recipient)
	return writeOwnedChildVault(t, fx.dir, name, sealed, pin)
}

func newForeignOwnedChildVault(t *testing.T, fx *ownedChildFixture, name, vaultID string) ownedChildVault {
	t.Helper()
	record, err := newVaultFileOwnerRecord()
	if err != nil {
		t.Fatal("OWNED_CHILD_FOREIGN_RECORD_FAILED")
	}
	record.VaultID = vaultID
	defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
	sealed, pin := ownedChildGenesis(t, record, fx.signer, fx.recipient)
	return writeOwnedChildVault(t, fx.dir, name, sealed, pin)
}

func writeOwnedChildVault(t *testing.T, dir, name string, sealed []byte, pin vaultfile.PolicyCheckpoint) ownedChildVault {
	t.Helper()
	journalDir := filepath.Join(dir, "journal-"+name)
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal("OWNED_CHILD_JOURNAL_DIR_FAILED")
	}
	journalPath := filepath.Join(journalDir, "state.journal")
	state := vaultfilejournal.State{
		BaseBytes:      bytes.Clone(sealed),
		WorkingBytes:   bytes.Clone(sealed),
		RemoteRevision: vaultfilebackend.Revision("\"rev-" + name + "\""),
		Generation:     0,
	}
	if err := vaultfilejournal.CreateNewState(journalPath, state); err != nil {
		t.Fatal("OWNED_CHILD_JOURNAL_CREATE_FAILED")
	}
	return ownedChildVault{journal: journalPath, checkpoint: &pin}
}

func ownedChildGenesis(t *testing.T, owner vaultFileOwnerRecord, localSigner ed25519.PrivateKey, localRecipient string) ([]byte, vaultfile.PolicyCheckpoint) {
	t.Helper()
	recovery, err := vaultFileOwnerPublic(owner)
	if err != nil {
		t.Fatal("OWNED_CHILD_RECOVERY_PUBLIC_FAILED")
	}
	recoverySigning, err := hex.DecodeString(recovery.RecoveryContentSigningPublicKey)
	if err != nil {
		t.Fatal("OWNED_CHILD_RECOVERY_SIGNING_FAILED")
	}
	root := ed25519.NewKeyFromSeed(owner.OwnerRootSeed)
	defer clear(root)
	policy := &vaultfile.Policy{Format: vaultfile.Format, Version: vaultfile.Version,
		VaultID: owner.VaultID, PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{KeyID: owner.OwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(root.Public().(ed25519.PublicKey)),
			Owners:    []vaultfile.Principal{{PrincipalID: "owner", Label: "Owner"}}},
		Writers: []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}, {PrincipalID: "recovery", Label: "Recovery"}},
		Owners:  []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Devices: []vaultfile.Device{
			{DeviceID: vaultFileGenesisAuthorDeviceID, PrincipalID: "owner", Label: "Personal device",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(localSigner.Public().(ed25519.PublicKey))},
				AgeEncryptionKey:  localRecipient},
			{DeviceID: owner.RecoveryDeviceID, PrincipalID: "recovery", Label: "Recovery device",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: recoverySigning},
				AgeEncryptionKey:  recovery.RecoveryAgeRecipient},
		},
	}
	sort.Slice(policy.Devices, func(i, j int) bool { return policy.Devices[i].DeviceID < policy.Devices[j].DeviceID })
	if err := vaultfile.ValidatePolicy(policy); err != nil {
		t.Fatal("OWNED_CHILD_POLICY_INVALID")
	}
	proof := signedVaultFilePolicy(t, policy, owner.OwnerRootSeed)
	digest := vaultfile.PolicyDigest(policy)
	pin := vaultfile.PolicyCheckpoint{VaultID: owner.VaultID, OwnerRootKeyID: owner.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(root.Public().(ed25519.PublicKey)), PolicySeq: 0, PolicyDigest: bytes.Clone(digest)}
	opID, err := randomID()
	if err != nil {
		t.Fatal("OWNED_CHILD_OPERATION_ID_FAILED")
	}
	draft := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version,
		Header: vaultfile.Header{VaultID: owner.VaultID, KeyEpoch: 1, ContentSeq: 0,
			OpID: opID, PolicySeq: 0, PolicyDigest: bytes.Clone(digest), AuthorDeviceID: vaultFileGenesisAuthorDeviceID},
		SignedPolicyProofs: []vaultfile.SignedPolicy{proof}}
	items := []vault.Item{{
		ID: ownedChildItemID, Kind: "login", Title: "Owned child baseline",
		Username: "owned-user", Password: "fixture-hidden",
	}}
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("OWNED_CHILD_VUK_FAILED")
	}
	defer clear(vuk)
	sealed, err := vault.SealAuthenticatedItems(draft, []byte{}, items, &pin, vuk, localSigner)
	if err != nil {
		t.Fatal("OWNED_CHILD_SEAL_FAILED")
	}
	return sealed, pin
}

func openOwnedChild(t *testing.T, s *Session, v ownedChildVault, password, key []byte) (VaultFileChildToken, []VaultFileBaselineItem) {
	t.Helper()
	token, items, err := s.OpenOwnedVaultFileChild(v.journal, v.checkpoint, password, key, VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("OWNED_CHILD_OPEN_FAILED")
	}
	if len(items) != 1 || items[0].ID != ownedChildItemID {
		t.Fatal("OWNED_CHILD_INITIAL_SUMMARY_MISMATCH")
	}
	return token, items
}

func assertOwnedChildRead(t *testing.T, s *Session, token VaultFileChildToken) {
	t.Helper()
	items, err := s.ReadVaultFileChild(token, VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil || len(items) != 1 || items[0].ID != ownedChildItemID {
		t.Fatal("OWNED_CHILD_OWN_READ_FAILED")
	}
}

func ownedChildAt(s *Session, path string) *vaultFileChild {
	s.vaultFileMu.Lock()
	defer s.vaultFileMu.Unlock()
	return s.vaultFileChildren[path]
}

func ownedChildAllCount(s *Session) int {
	s.vaultFileMu.Lock()
	defer s.vaultFileMu.Unlock()
	return len(s.vaultFileAll)
}

func assertOwnedChildRejectedNoCandidate(t *testing.T, s *Session, path string, wantAll int) {
	t.Helper()
	if ownedChildAt(s, path) != nil || ownedChildAllCount(s) != wantAll {
		t.Fatal("OWNED_CHILD_REJECTED_CANDIDATE_RESIDUE")
	}
	if !s.Unlocked() {
		t.Fatal("OWNED_CHILD_TARGET_SCOPE_LOCKED_PARENT")
	}
}

func rewriteOwnedOwnerRecords(t *testing.T, s *Session, records []vaultFileOwnerRecord) {
	t.Helper()
	sort.Slice(records, func(i, j int) bool { return records[i].VaultID < records[j].VaultID })
	db, err := existing(s.path)
	if err != nil {
		t.Fatal("OWNED_CHILD_REWRITE_DB_OPEN_FAILED")
	}
	updateErr := db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerPrepareAction, s, true)
		if err != nil {
			return err
		}
		defer auth.clear()
		b := tx.Bucket(bucket)
		if err := saveVaultFileOwners(b, auth.identity, records); err != nil {
			return err
		}
		digest, err := vaultFileOwnersDigest(records)
		if err != nil {
			return err
		}
		snapshot, err := seal(b, auth.identity, auth.snapshot.Epoch+1, auth.items)
		if err != nil {
			return err
		}
		_, err = appendLinked(b, auth.identity, auth.tip, snapshot, vaultFileOwnerPrepareAction, "", "succeeded", "", digest)
		return err
	})
	closeErr := db.Close()
	if updateErr != nil || closeErr != nil {
		t.Fatal("OWNED_CHILD_OWNER_REWRITE_FAILED")
	}
	s.mu.Lock()
	s.clearAuditCache()
	s.mu.Unlock()
}

func TestVaultFileOwnedChildOpenReadRevalidateAndLaterOwner(t *testing.T) {
	fx := newOwnedChildFixture(t)
	tokenA, _ := openOwnedChild(t, fx.session, fx.a, fx.password, fx.key)
	assertOwnedChildRead(t, fx.session, tokenA)
	if err := fx.session.RevalidateVaultFileChildOwnership(tokenA); err != nil {
		t.Fatal("OWNED_CHILD_REVALIDATE_A_FAILED")
	}

	// Preparing a second legitimate custody record after A is a global owner
	// store change, but A's target snapshot remains valid and readable.
	b := fx.addVault(t, "b")
	if err := fx.session.RevalidateVaultFileChildOwnership(tokenA); err != nil {
		t.Fatal("OWNED_CHILD_REVALIDATE_A_AFTER_B_FAILED")
	}
	assertOwnedChildRead(t, fx.session, tokenA)

	tokenB, _ := openOwnedChild(t, fx.session, b, fx.password, fx.key)
	assertOwnedChildRead(t, fx.session, tokenB)
	if err := fx.session.RevalidateVaultFileChildOwnership(tokenB); err != nil {
		t.Fatal("OWNED_CHILD_REVALIDATE_B_FAILED")
	}
	if err := fx.session.RevalidateVaultFileChildOwnership(tokenA); err != nil {
		t.Fatal("OWNED_CHILD_REVALIDATE_A_WITH_B_FAILED")
	}
	if child := ownedChildAt(fx.session, fx.a.journal); child == nil || child.owned == nil ||
		child.owned.owner.VaultID != fx.a.checkpoint.VaultID {
		t.Fatal("OWNED_CHILD_SNAPSHOT_NOT_TARGET_BOUND")
	}
}

func TestVaultFileOwnedChildRejectsUnboundCustodyBeforeRegister(t *testing.T) {
	fx := newOwnedChildFixture(t)

	t.Run("foreign-root-same-vault-id", func(t *testing.T) {
		foreign := newForeignOwnedChildVault(t, fx, "foreign-same-id", fx.a.checkpoint.VaultID)
		if _, _, err := fx.session.OpenOwnedVaultFileChild(foreign.journal, foreign.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileOwnership) {
			t.Fatal("OWNED_CHILD_FOREIGN_ROOT_ACCEPTED")
		}
		assertOwnedChildRejectedNoCandidate(t, fx.session, foreign.journal, 0)

		// The same self-consistent file is valid under the generic caller-pin
		// contract, proving the protocol fixture itself is well formed.
		token, items, err := fx.session.OpenVaultFileChild(foreign.journal, foreign.checkpoint, fx.password, fx.key, VaultFileChildOptions{IncludeItemIDs: true})
		if err != nil || len(items) != 1 || items[0].ID != ownedChildItemID {
			t.Fatal("OWNED_CHILD_GENERIC_POSITIVE_CONTROL_FAILED")
		}
		if err := fx.session.LockVaultFileChild(token); err != nil {
			t.Fatal("OWNED_CHILD_GENERIC_POSITIVE_CONTROL_LOCK_FAILED")
		}
	})

	t.Run("missing-owner", func(t *testing.T) {
		missingID, err := randomID()
		if err != nil {
			t.Fatal("OWNED_CHILD_MISSING_ID_FAILED")
		}
		foreign := newForeignOwnedChildVault(t, fx, "missing", missingID)
		if _, _, err := fx.session.OpenOwnedVaultFileChild(foreign.journal, foreign.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileOwnership) {
			t.Fatal("OWNED_CHILD_MISSING_OWNER_ACCEPTED")
		}
		assertOwnedChildRejectedNoCandidate(t, fx.session, foreign.journal, 0)
	})

	t.Run("cross-pin", func(t *testing.T) {
		b := fx.addVault(t, "b-cross-pin")
		if _, _, err := fx.session.OpenOwnedVaultFileChild(fx.a.journal, b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineVerification) {
			t.Fatal("OWNED_CHILD_CROSS_PIN_ACCEPTED")
		}
		assertOwnedChildRejectedNoCandidate(t, fx.session, fx.a.journal, 0)
	})
}

func TestVaultFileOwnedChildGenericTokenCannotRevalidate(t *testing.T) {
	fx := newOwnedChildFixture(t)
	token, items, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil || len(items) != 1 || items[0].ID != ownedChildItemID {
		t.Fatal("OWNED_CHILD_GENERIC_OPEN_FAILED")
	}
	if child := ownedChildAt(fx.session, fx.a.journal); child == nil || child.owned != nil {
		t.Fatal("OWNED_CHILD_GENERIC_MARKED_OWNED")
	}
	if err := fx.session.RevalidateVaultFileChildOwnership(token); !errors.Is(err, ErrVaultFileScopedChild) {
		t.Fatal("OWNED_CHILD_GENERIC_REVALIDATE_ACCEPTED")
	}
	assertOwnedChildRead(t, fx.session, token)
}

func TestVaultFileOwnedChildFreshFactorsDoNotExtendGlobalProof(t *testing.T) {
	fx := newOwnedChildFixture(t)
	b := fx.addVault(t, "b-old-parent")
	fx.session.mu.Lock()
	fx.session.fullUnlock = time.Time{}
	fx.session.mu.Unlock()
	tokenA, _ := openOwnedChild(t, fx.session, fx.a, fx.password, fx.key)
	fx.session.mu.Lock()
	stillZero := fx.session.fullUnlock.IsZero()
	fx.session.mu.Unlock()
	if !stillZero {
		t.Fatal("OWNED_CHILD_ZERO_PARENT_PROOF_EXTENDED")
	}
	if projections, err := fx.session.VaultFileOwnerships(); !errors.Is(err, ErrVaultFileFullFactorRequired) || len(projections) != 0 {
		t.Fatal("OWNED_CHILD_ZERO_PARENT_GLOBAL_LIST_ACCEPTED")
	}
	if err := fx.session.RevalidateVaultFileChildOwnership(tokenA); err != nil {
		t.Fatal("OWNED_CHILD_ZERO_PARENT_REVALIDATE_FAILED")
	}

	fx.session.mu.Lock()
	fx.session.fullUnlock = time.Now().Add(-passkeyTransferFullFactorWindow)
	old := fx.session.fullUnlock
	fx.session.mu.Unlock()
	tokenB, _ := openOwnedChild(t, fx.session, b, fx.password, fx.key)
	fx.session.mu.Lock()
	unchanged := fx.session.fullUnlock.Equal(old)
	fx.session.mu.Unlock()
	if !unchanged {
		t.Fatal("OWNED_CHILD_EXPIRED_PARENT_PROOF_EXTENDED")
	}
	if projections, err := fx.session.VaultFileOwnerships(); !errors.Is(err, ErrVaultFileFullFactorRequired) || len(projections) != 0 {
		t.Fatal("OWNED_CHILD_EXPIRED_PARENT_GLOBAL_LIST_ACCEPTED")
	}
	if err := fx.session.RevalidateVaultFileChildOwnership(tokenA); err != nil {
		t.Fatal("OWNED_CHILD_EXPIRED_PARENT_REVALIDATE_A_FAILED")
	}
	if err := fx.session.RevalidateVaultFileChildOwnership(tokenB); err != nil {
		t.Fatal("OWNED_CHILD_EXPIRED_PARENT_REVALIDATE_B_FAILED")
	}
}

func TestVaultFileOwnedChildCandidateFinalGateRejects(t *testing.T) {
	t.Run("owner-missing", func(t *testing.T) {
		fx := newOwnedChildFixture(t)
		b := fx.addVault(t, "b-owner-missing")
		tokenB, _ := openOwnedChild(t, fx.session, b, fx.password, fx.key)
		recordB := testVaultFileOwnerRecord(t, fx.session, fx.session.path, b.checkpoint.VaultID)
		defer clearVaultFileOwners([]vaultFileOwnerRecord{recordB})
		var candidate *vaultfile.ScopedUnlock
		vaultFileChildCandidateReady = func(handle *vaultfile.ScopedUnlock) {
			candidate = handle
			rewriteOwnedOwnerRecords(t, fx.session, []vaultFileOwnerRecord{recordB})
		}
		t.Cleanup(func() { vaultFileChildCandidateReady = nil })
		if _, _, err := fx.session.OpenOwnedVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileOwnership) {
			t.Fatal("OWNED_CHILD_FINAL_OWNER_MISSING_ACCEPTED")
		}
		if candidate == nil {
			t.Fatal("OWNED_CHILD_FINAL_CANDIDATE_NOT_REAL")
		}
		assertScopedChildHandleClosed(t, candidate)
		if ownedChildAt(fx.session, fx.a.journal) != nil {
			t.Fatal("OWNED_CHILD_FINAL_OWNER_MISSING_REGISTERED")
		}
		if !fx.session.Unlocked() {
			t.Fatal("OWNED_CHILD_FINAL_TARGET_SCOPE_LOCKED_PARENT")
		}
		assertOwnedChildRead(t, fx.session, tokenB)
		if err := fx.session.RevalidateVaultFileChildOwnership(tokenB); err != nil {
			t.Fatal("OWNED_CHILD_FINAL_TARGET_SCOPE_LOCKED_B")
		}
	})

	t.Run("slot-change", func(t *testing.T) {
		fx := newOwnedChildFixture(t)
		b := fx.addVault(t, "b-slot-change")
		_, _ = openOwnedChild(t, fx.session, b, fx.password, fx.key)
		childB := ownedChildAt(fx.session, b.journal)
		var candidate *vaultfile.ScopedUnlock
		vaultFileChildCandidateReady = func(handle *vaultfile.ScopedUnlock) {
			candidate = handle
			replaceScopedChildSlot(t, fx.session.path, []byte("not-a-slot"))
		}
		t.Cleanup(func() { vaultFileChildCandidateReady = nil })
		if _, _, err := fx.session.OpenOwnedVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrSessionLocked) {
			t.Fatal("OWNED_CHILD_FINAL_SLOT_CHANGE_ACCEPTED")
		}
		if candidate == nil {
			t.Fatal("OWNED_CHILD_FINAL_SLOT_CANDIDATE_NOT_REAL")
		}
		assertScopedChildHandleClosed(t, candidate)
		assertScopedChildHandleClosed(t, childB.handle)
		if ownedChildAllCount(fx.session) != 0 || fx.session.Unlocked() {
			t.Fatal("OWNED_CHILD_FINAL_SLOT_CHANGE_DID_NOT_DRAIN")
		}
	})

	t.Run("request-lock", func(t *testing.T) {
		fx := newOwnedChildFixture(t)
		var candidate *vaultfile.ScopedUnlock
		vaultFileChildCandidateReady = func(handle *vaultfile.ScopedUnlock) {
			candidate = handle
			fx.session.RequestLock()
		}
		t.Cleanup(func() { vaultFileChildCandidateReady = nil })
		if _, _, err := fx.session.OpenOwnedVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrSessionLocked) {
			t.Fatal("OWNED_CHILD_FINAL_REQUEST_LOCK_ACCEPTED")
		}
		if candidate == nil {
			t.Fatal("OWNED_CHILD_FINAL_REQUEST_LOCK_CANDIDATE_NOT_REAL")
		}
		assertScopedChildHandleClosed(t, candidate)
		if ownedChildAllCount(fx.session) != 0 || fx.session.Unlocked() {
			t.Fatal("OWNED_CHILD_FINAL_REQUEST_LOCK_DID_NOT_DRAIN")
		}
	})
}

func TestVaultFileOwnedChildReadAndRevalidateDetectTargetDrift(t *testing.T) {
	t.Run("read-drift", func(t *testing.T) {
		fx := newOwnedChildFixture(t)
		b := fx.addVault(t, "b-read-drift")
		tokenA, _ := openOwnedChild(t, fx.session, fx.a, fx.password, fx.key)
		tokenB, _ := openOwnedChild(t, fx.session, b, fx.password, fx.key)
		childA := ownedChildAt(fx.session, fx.a.journal)
		recordB := testVaultFileOwnerRecord(t, fx.session, fx.session.path, b.checkpoint.VaultID)
		defer clearVaultFileOwners([]vaultFileOwnerRecord{recordB})
		foreignA := newForeignOwnedChildRecord(t, fx.a.checkpoint.VaultID)
		defer clearVaultFileOwners([]vaultFileOwnerRecord{foreignA})
		rewriteOwnedOwnerRecords(t, fx.session, []vaultFileOwnerRecord{foreignA, recordB})

		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{})
		if !errors.Is(err, ErrVaultFileOwnership) || items != nil {
			t.Fatal("OWNED_CHILD_READ_DRIFT_DISCLOSED")
		}
		assertScopedChildHandleClosed(t, childA.handle)
		if !fx.session.Unlocked() {
			t.Fatal("OWNED_CHILD_READ_DRIFT_LOCKED_PARENT")
		}
		assertOwnedChildRead(t, fx.session, tokenB)
		if err := fx.session.RevalidateVaultFileChildOwnership(tokenB); err != nil {
			t.Fatal("OWNED_CHILD_READ_DRIFT_LOCKED_B")
		}
	})

	t.Run("revalidate-missing", func(t *testing.T) {
		fx := newOwnedChildFixture(t)
		b := fx.addVault(t, "b-revalidate-missing")
		tokenA, _ := openOwnedChild(t, fx.session, fx.a, fx.password, fx.key)
		tokenB, _ := openOwnedChild(t, fx.session, b, fx.password, fx.key)
		childA := ownedChildAt(fx.session, fx.a.journal)
		recordB := testVaultFileOwnerRecord(t, fx.session, fx.session.path, b.checkpoint.VaultID)
		defer clearVaultFileOwners([]vaultFileOwnerRecord{recordB})
		rewriteOwnedOwnerRecords(t, fx.session, []vaultFileOwnerRecord{recordB})

		if err := fx.session.RevalidateVaultFileChildOwnership(tokenA); !errors.Is(err, ErrVaultFileOwnership) {
			t.Fatal("OWNED_CHILD_REVALIDATE_MISSING_ACCEPTED")
		}
		assertScopedChildHandleClosed(t, childA.handle)
		if !fx.session.Unlocked() {
			t.Fatal("OWNED_CHILD_REVALIDATE_MISSING_LOCKED_PARENT")
		}
		assertOwnedChildRead(t, fx.session, tokenB)
		if err := fx.session.RevalidateVaultFileChildOwnership(tokenB); err != nil {
			t.Fatal("OWNED_CHILD_REVALIDATE_MISSING_LOCKED_B")
		}
	})
}

func newForeignOwnedChildRecord(t *testing.T, vaultID string) vaultFileOwnerRecord {
	t.Helper()
	record, err := newVaultFileOwnerRecord()
	if err != nil {
		t.Fatal("OWNED_CHILD_FOREIGN_RECORD_FAILED")
	}
	record.VaultID = vaultID
	return record
}
