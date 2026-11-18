//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

const localOwnedSuccessorTitle = "Local owned successor"

type localOwnedSuccessorFixture struct {
	f                 *localGenesisTwoVaultFixture
	config            string
	vaultID           string
	manifest          Manifest
	pin               vaultfilejournal.OwnedGenesisPin
	checkpoint        vaultfile.PolicyCheckpoint
	target            personal.OwnedVaultFileFirstSuccessorTarget
	itemID            string
	successor         []byte
	successorRevision vaultfilebackend.Revision
}

type localAccountIdentity struct {
	Device  string
	Signing []byte
}

func localClientAccountIdentity(t *testing.T, path string, password, key []byte) (ed25519.PrivateKey, *age.X25519Identity, string) {
	t.Helper()
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ACCOUNT_OPEN_FAILED")
	}
	var raw []byte
	viewErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("locklark.personal/v1"))
		if b == nil {
			return ErrLocalReview
		}
		raw = append([]byte(nil), b.Get([]byte("device-slot"))...)
		return nil
	})
	closeErr := db.Close()
	if viewErr != nil || closeErr != nil || len(raw) == 0 {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ACCOUNT_SLOT_FAILED")
	}
	defer clear(raw)
	var slot account.Slot
	if err := json.Unmarshal(raw, &slot); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ACCOUNT_SLOT_PARSE_FAILED")
	}
	opened, err := account.Unwrap(string(password), key, slot)
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ACCOUNT_UNWRAP_FAILED")
	}
	defer clear(opened)
	var identity localAccountIdentity
	if err := json.Unmarshal(opened, &identity); err != nil ||
		len(identity.Signing) != ed25519.SeedSize || identity.Device == "" {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ACCOUNT_IDENTITY_FAILED")
	}
	signing := ed25519.NewKeyFromSeed(identity.Signing)
	localAge, err := age.ParseX25519Identity(identity.Device)
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ACCOUNT_AGE_FAILED")
	}
	return signing, localAge, localAge.Recipient().String()
}

func localOwnedWriterDevice(policy *vaultfile.Policy, recipient string, signingKey ed25519.PublicKey) (string, bool) {
	if policy == nil || recipient == "" || len(signingKey) != ed25519.PublicKeySize {
		return "", false
	}
	authorized := func(principal string) bool {
		for _, members := range [][]vaultfile.Member{policy.Writers, policy.Admins, policy.Owners} {
			for _, member := range members {
				if member.PrincipalID == principal {
					return true
				}
			}
		}
		return false
	}
	var matched string
	for _, device := range policy.Devices {
		if device.AgeEncryptionKey != recipient ||
			device.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 ||
			!bytes.Equal(device.ContentSigningKey.PublicKey, signingKey) ||
			!authorized(device.PrincipalID) {
			continue
		}
		if matched != "" {
			return "", false
		}
		matched = device.DeviceID
	}
	return matched, matched != ""
}

func settleLocalOwnedSuccessor(t *testing.T, f *localGenesisTwoVaultFixture, config, vaultID, journalRevisionOverride string) *localOwnedSuccessorFixture {
	t.Helper()
	manifest, exists, err := ReadManifest(config)
	if err != nil || !exists || manifest.VaultID != vaultID {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_MANIFEST_FAILED")
	}
	companion, exists, err := ReadCompanion(config, manifest)
	if err != nil || !exists || companion.Resume.Checkpoint == nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_COMPANION_FAILED")
	}
	root, err := hex.DecodeString(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ROOT_DECODE_FAILED")
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_PIN_FAILED")
	}

	journal, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_JOURNAL_OPEN_FAILED")
	}
	origin, err := journal.LoadState()
	if err != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_JOURNAL_STATE_FAILED")
	}
	genesis := bytes.Clone(origin.BaseBytes)
	checkpoint, err := vaultfile.VerifyGenesis(genesis, &pin.Root)
	if err != nil || checkpoint == nil ||
		!localGenesisCheckpointMatchesCompanion(checkpoint, companion.Resume.Checkpoint) {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_GENESIS_VERIFY_FAILED")
	}
	base, err := vaultfile.ParseFile(genesis)
	if err != nil || len(base.SignedPolicyProofs) == 0 {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_GENESIS_PARSE_FAILED")
	}
	policy := &base.SignedPolicyProofs[len(base.SignedPolicyProofs)-1].Policy
	signing, localAge, recipient := localClientAccountIdentity(t, f.f.proposal.PersonalFile, f.f.password, f.f.key)
	defer clear(signing)
	deviceID, ok := localOwnedWriterDevice(policy, recipient, signing.Public().(ed25519.PublicKey))
	if !ok {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_DEVICE_BIND_FAILED")
	}
	var slot *vaultfile.DeviceSlot
	for i := range base.VUKDeviceSlots {
		if base.VUKDeviceSlots[i].DeviceID == deviceID {
			slot = &base.VUKDeviceSlots[i]
			break
		}
	}
	if slot == nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_VUK_SLOT_FAILED")
	}
	vuk, err := vaultfile.OpenVUKForDevice(*slot, checkpoint.VaultID, base.Header.KeyEpoch,
		deviceID, recipient, localAge)
	if err != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_VUK_OPEN_FAILED")
	}
	defer clear(vuk)
	parentDigest, err := vaultfile.FileDigest(base)
	if err != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_PARENT_DIGEST_FAILED")
	}
	parent, err := hex.DecodeString(parentDigest)
	if err != nil || len(parent) != 32 {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_PARENT_DECODE_FAILED")
	}
	opID := localOwnedSuccessorID(t)
	draft := &vaultfile.File{Format: base.Format, Version: base.Version,
		SignedPolicyProofs: base.SignedPolicyProofs, Header: base.Header}
	draft.Header.ContentSeq++
	draft.Header.PrevDigest = parent
	draft.Header.RevisionID = ""
	draft.Header.OpID = opID
	draft.Header.AuthorDeviceID = deviceID
	itemID := localOwnedSuccessorID(t)
	successor, err := vault.SealAuthenticatedItems(draft, []byte{}, []vault.Item{{
		ID: itemID, Kind: "login", Title: localOwnedSuccessorTitle,
		Username: "successor-user", Password: "fixture-hidden",
	}}, checkpoint, vuk, signing)
	if err != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_SEAL_FAILED")
	}
	if err := vaultfile.VerifyContentTransition(genesis, successor, checkpoint); err != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_TRANSITION_FAILED")
	}
	successorFile, err := vaultfile.ParseFile(successor)
	if err != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_PARSE_FAILED")
	}

	backend, err := vaultfilebackend.OpenDir(manifest.BackendRoot)
	if err != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BACKEND_OPEN_FAILED")
	}
	if err := backend.ReplaceIfVersion(context.Background(), manifest.Name, origin.RemoteRevision, successor); err != nil {
		_ = backend.Close()
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BACKEND_REPLACE_FAILED")
	}
	readback, err := backend.Read(context.Background(), manifest.Name)
	closeErr := backend.Close()
	if err != nil || closeErr != nil {
		_ = journal.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BACKEND_READBACK_FAILED")
	}
	defer clear(readback.Bytes)
	journalRevision := readback.Revision
	if journalRevisionOverride != "" {
		journalRevision = vaultfilebackend.Revision(journalRevisionOverride)
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       origin.Generation + 1,
		OperationID:      successorFile.Header.OpID,
		ExpectedRevision: origin.RemoteRevision,
		Bytes:            successor,
	}
	prepareErr := journal.PrepareWorkingIfState(origin, proposal)
	ackErr := journal.AckOwnedFirstSuccessor(origin, pin, proposal, successor, journalRevision)
	journalCloseErr := journal.Close()
	clear(origin.BaseBytes)
	clear(origin.WorkingBytes)
	if prepareErr != nil || ackErr != nil || journalCloseErr != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_SETTLEMENT_FAILED")
	}
	return &localOwnedSuccessorFixture{
		f: f, config: config, vaultID: vaultID, manifest: manifest, pin: pin,
		checkpoint: *checkpoint,
		target: personal.OwnedVaultFileFirstSuccessorTarget{
			BackendRoot: manifest.BackendRoot, BackendName: manifest.Name, Pin: pin,
		},
		itemID: itemID, successor: bytes.Clone(successor), successorRevision: journalRevision,
	}
}

func (s *localOwnedSuccessorFixture) rewriteBackend(t *testing.T, data []byte) vaultfilebackend.Revision {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(s.manifest.BackendRoot)
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_REWRITE_OPEN_FAILED")
	}
	current, err := backend.Read(context.Background(), s.manifest.Name)
	if err != nil {
		_ = backend.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_REWRITE_READ_FAILED")
	}
	clear(current.Bytes)
	if err := backend.ReplaceIfVersion(context.Background(), s.manifest.Name, current.Revision, data); err != nil {
		_ = backend.Close()
		t.Fatal("LOCAL_OWNED_SUCCESSOR_REWRITE_REPLACE_FAILED")
	}
	updated, err := backend.Read(context.Background(), s.manifest.Name)
	closeErr := backend.Close()
	if err != nil || closeErr != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_REWRITE_READBACK_FAILED")
	}
	defer clear(updated.Bytes)
	return updated.Revision
}

func assertLocalOwnedSuccessorSummary(t *testing.T, summary LocalGenesisBaseline, vaultID string) {
	t.Helper()
	if summary.VaultID != vaultID || len(summary.Items) != 1 ||
		summary.Items[0].Title != localOwnedSuccessorTitle {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_SUMMARY_FAILED")
	}
}

func TestOwnedFirstSuccessorLocalSingleSummaryQueryAndLegacySibling(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	successor := settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")

	wrapper, summary, err := OpenLocalGenesisSession(f.session, f.firstConfig,
		f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key)
	if err != nil || wrapper == nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_SINGLE_OPEN_FAILED")
	}
	assertLocalOwnedSuccessorSummary(t, summary, f.firstVaultID)
	again, err := wrapper.Summary()
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_SINGLE_SUMMARY_FAILED")
	}
	assertLocalOwnedSuccessorSummary(t, again, f.firstVaultID)
	result, err := wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: localOwnedSuccessorTitle, Limit: 4})
	if err != nil || len(result.Hits) != 1 || result.Hits[0].Title != localOwnedSuccessorTitle ||
		result.VaultID != f.firstVaultID {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_QUERY_FAILED")
	}
	if err := wrapper.ValidateExactQueryHit(result, successor.itemID, localOwnedSuccessorTitle); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_QUERY_HIT_FAILED")
	}

	legacy, legacySummary, err := OpenLocalGenesisSession(f.session, f.secondConfig,
		f.f.proposal.BackendRoot, f.secondVaultID, f.f.password, f.f.key)
	if err != nil || legacy == nil || legacySummary.VaultID != f.secondVaultID ||
		len(legacySummary.Items) != 0 {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_LEGACY_SIBLING_FAILED")
	}
	if err := wrapper.Close(); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_SINGLE_CLOSE_FAILED")
	}
	if _, err := legacy.Summary(); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_SIBLING_AFTER_CLOSE_FAILED")
	}
	if err := legacy.Close(); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_LEGACY_CLOSE_FAILED")
	}
}

func TestOwnedFirstSuccessorLocalBatchAdoptsAndPreservesLegacySibling(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")
	candidateA := localGenesisBatchCandidate(t, f, f.firstConfig, f.firstVaultID)
	candidateB := localGenesisBatchCandidate(t, f, f.secondConfig, f.secondVaultID)

	parent, results, err := openLocalGenesisBatchForTest(t, f, context.Background(),
		[]LocalGenesisBatchCandidate{candidateA, candidateB})
	if err != nil || parent == nil || len(results) != 2 {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_DELIVERY_FAILED")
	}
	defer parent.Lock()
	if results[0].Err != nil || results[0].Wrapper == nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_A_FAILED")
	}
	assertLocalOwnedSuccessorSummary(t, results[0].Baseline, f.firstVaultID)
	if results[0].Baseline.Items[0].Title != localOwnedSuccessorTitle {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_A_ITEM_FAILED")
	}
	if results[1].Err != nil || results[1].Wrapper == nil ||
		results[1].Baseline.VaultID != f.secondVaultID || len(results[1].Baseline.Items) != 0 {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_B_FAILED")
	}
	if _, err := results[0].Wrapper.QueryExactTitle(LocalGenesisExactQuery{
		Title: localOwnedSuccessorTitle, Limit: 2,
	}); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_QUERY_FAILED")
	}
	if err := results[0].Wrapper.Close(); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_A_CLOSE_FAILED")
	}
	if _, err := results[1].Wrapper.Summary(); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_B_SUMMARY_FAILED")
	}
	if err := results[1].Wrapper.Close(); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_BATCH_B_CLOSE_FAILED")
	}
}

func TestOwnedFirstSuccessorLocalRejectsRevisionBytesCompanionAndState(t *testing.T) {
	t.Run("journal-revision-only", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "journal-only-revision")
		if wrapper, _, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key); !errors.Is(err, personal.ErrVaultFileBaselineJournal) || wrapper != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_JOURNAL_REVISION_ACCEPTED")
		}
	})

	t.Run("backend-bytes", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		s := settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")
		s.rewriteBackend(t, []byte("foreign local backend bytes"))
		if wrapper, _, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key); !errors.Is(err, personal.ErrVaultFileBaselineJournal) || wrapper != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BACKEND_BYTES_ACCEPTED")
		}
	})

	t.Run("backend-revision-after-open", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		s := settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")
		wrapper, _, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key)
		if err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_REVISION_OPEN_FAILED")
		}
		defer wrapper.Close()
		newRevision := s.rewriteBackend(t, s.successor)
		if newRevision == s.successorRevision {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_REVISION_UNCHANGED")
		}
		if _, err := wrapper.Summary(); !errors.Is(err, personal.ErrVaultFileBaselineJournal) {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BACKEND_REVISION_ACCEPTED")
		}
	})

	t.Run("bad-companion-origin", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")
		manifest, _, err := ReadManifest(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BAD_COMPANION_MANIFEST_FAILED")
		}
		companion, _, err := ReadCompanion(f.firstConfig, manifest)
		if err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BAD_COMPANION_READ_FAILED")
		}
		companion.GenesisSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		path, err := CompanionPath(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BAD_COMPANION_PATH_FAILED")
		}
		raw, err := json.Marshal(companion)
		if err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BAD_COMPANION_ENCODE_FAILED")
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BAD_COMPANION_WRITE_FAILED")
		}
		if wrapper, _, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key); !errors.Is(err, ErrLocalReview) || wrapper != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_BAD_COMPANION_ACCEPTED")
		}
	})

	t.Run("locked-account", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")
		f.session.Lock()
		if wrapper, _, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key); !errors.Is(err, ErrLocalReview) || wrapper != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_LOCKED_ACCOUNT_ACCEPTED")
		}
	})

	t.Run("replaced-account", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")
		foreign := filepath.Join(f.f.root, "foreign-personal.ll")
		if err := personal.Create(foreign, string(f.f.password), f.f.key); err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_FOREIGN_ACCOUNT_FAILED")
		}
		replaceLocalGenesisFileStable(t, f.f.proposal.PersonalFile, mustReadFile(t, foreign))
		if wrapper, _, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key); wrapper != nil || err == nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_REPLACED_ACCOUNT_ACCEPTED")
		}
	})

	t.Run("malformed-journal", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		successor := settleLocalOwnedSuccessor(t, f, f.firstConfig, f.firstVaultID, "")
		if err := os.WriteFile(successor.manifest.Journal, []byte("not a journal"), 0600); err != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_MALFORMED_JOURNAL_WRITE_FAILED")
		}
		if wrapper, _, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key); !errors.Is(err, ErrLocalReview) || wrapper != nil {
			t.Fatal("LOCAL_OWNED_SUCCESSOR_MALFORMED_JOURNAL_ACCEPTED")
		}
	})
}

func localOwnedSuccessorID(t *testing.T) string {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_ID_FAILED")
	}
	return hex.EncodeToString(id[:])
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("LOCAL_OWNED_SUCCESSOR_TEST_READ_FAILED")
	}
	return raw
}
