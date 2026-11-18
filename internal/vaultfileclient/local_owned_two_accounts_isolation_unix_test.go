//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// localIsolationCreation builds one real temporary account with its own
// password and Secret Key. It mirrors the existing creation-boundary fixture
// constructor because the two accounts in this checkpoint must not share the
// fixed factors of the legacy single-account fixture. The account itself is
// still created only through personal.Create and all vault work below uses the
// existing production creation and first-write paths.
func localIsolationCreation(t *testing.T, label string, password, key []byte) *creationBoundaryFixture {
	t.Helper()
	root := t.TempDir()
	private := filepath.Join(root, "private")
	journalDir := filepath.Join(root, "journal")
	if os.Mkdir(private, 0700) != nil || os.Mkdir(journalDir, 0700) != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_PRIVATE_PARENT_FAILED")
	}
	f := &creationBoundaryFixture{
		root:     root,
		config:   filepath.Join(private, "create.json"),
		password: bytes.Clone(password),
		key:      bytes.Clone(key),
		proposal: Manifest{Version: 1, Kind: CreateKind,
			PersonalFile: filepath.Join(root, "personal.ll"),
			BackendRoot:  filepath.Join(root, "backend"),
			Name:         "owned-" + label,
			Journal:      filepath.Join(journalDir, "genesis.journal"),
			Archive:      filepath.Join(root, "published.llb")},
	}
	f.secretInput = []byte(personal.FormatSecret(f.key))
	if personal.Create(f.proposal.PersonalFile, string(f.password), f.key) != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_PERSONAL_CREATE_FAILED")
	}
	t.Cleanup(func() {
		clear(f.password)
		clear(f.key)
		clear(f.secretInput)
		clear(f.kit)
	})
	return f
}

// localIsolationVault is one production-created owned local vault belonging to
// exactly one account. The checkpoint is derived from the persisted signed
// genesis under the account's own owner-root record, and the session is the
// account session used by the production first-write helper.
type localIsolationVault struct {
	f                 *creationBoundaryFixture
	config            string
	manifest          Manifest
	companion         Companion
	pin               vaultfilejournal.OwnedGenesisPin
	checkpoint        *vaultfile.PolicyCheckpoint
	genesis           []byte
	bootstrapRevision string
	item              LocalGenesisFirstItem
	session           *personal.Session
}

func newLocalIsolationVault(t *testing.T, f *creationBoundaryFixture, title string) *localIsolationVault {
	t.Helper()
	f.publishBackup(t)
	create := f.openReady(t)
	if err := create.Complete(context.Background(), f.password, f.secretInput, f.kit); err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_CREATE_FAILED")
	}
	create.Close()

	manifest, exists, err := ReadManifest(f.config)
	if err != nil || !exists {
		t.Fatal("LOCAL_TWO_ACCOUNT_MANIFEST_FAILED")
	}
	companion, exists, err := ReadCompanion(f.config, manifest)
	if err != nil || !exists || companion.Resume.Checkpoint == nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_COMPANION_FAILED")
	}
	root, err := hex.DecodeString(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_ROOT_DECODE_FAILED")
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		t.Fatal("LOCAL_TWO_ACCOUNT_PIN_FAILED")
	}
	j, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_JOURNAL_OPEN_FAILED")
	}
	state, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil || closeErr != nil || state.Generation != 0 {
		t.Fatal("LOCAL_TWO_ACCOUNT_JOURNAL_BASELINE_FAILED")
	}
	genesis := bytes.Clone(state.BaseBytes)
	checkpoint, err := vaultfile.VerifyGenesis(genesis, &pin.Root)
	if err != nil || checkpoint == nil ||
		!localGenesisCheckpointMatchesCompanion(checkpoint, companion.Resume.Checkpoint) {
		clearLocalGenesisCheckpoint(checkpoint)
		clear(genesis)
		t.Fatal("LOCAL_TWO_ACCOUNT_GENESIS_VERIFY_FAILED")
	}
	session, err := personal.UnlockSession(manifest.PersonalFile, f.password, f.key, time.Minute)
	if err != nil {
		clearLocalGenesisCheckpoint(checkpoint)
		clear(genesis)
		t.Fatal("LOCAL_TWO_ACCOUNT_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)

	v := &localIsolationVault{
		f: f, config: f.config, manifest: manifest, companion: companion,
		pin: pin, checkpoint: checkpoint, genesis: genesis,
		bootstrapRevision: string(state.RemoteRevision),
		session:           session,
		item: LocalGenesisFirstItem{
			ID: localOwnedSuccessorID(t), Title: title,
			Username: localFirstWriteUser, Password: localFirstWriteSecret,
		},
	}
	t.Cleanup(v.clear)
	return v
}

func (v *localIsolationVault) clear() {
	if v == nil {
		return
	}
	clear(v.genesis)
	v.genesis = nil
	clearLocalGenesisCheckpoint(v.checkpoint)
	v.checkpoint = nil
	clear(v.pin.Root.OwnerRootPublicKey)
	v.pin.Root.OwnerRootPublicKey = nil
	v.item = LocalGenesisFirstItem{}
}

func (v *localIsolationVault) write(t *testing.T) LocalOwnedFirstWriteResult {
	t.Helper()
	result, err := WriteLocalGenesisFirstItem(context.Background(), v.session, v.config,
		v.manifest.BackendRoot, v.manifest.VaultID, v.manifest.Journal,
		v.f.password, v.f.key, v.item)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_WRITE_FAILED")
	}
	return result
}

// localIsolationSettled is the exact persisted successor plus the two real
// content keys this owner can derive from it. The VUK and CEK are held only to
// prove the cross-account cryptographic refusal and are cleared with the
// record bytes.
type localIsolationSettled struct {
	record vaultfilejournal.OwnedFirstSuccessor
	file   *vaultfile.File
	itemID string
	vuk    []byte
	cek    []byte
}

func (s *localIsolationSettled) clear() {
	if s == nil {
		return
	}
	clear(s.record.GenesisBytes)
	clear(s.record.SuccessorBytes)
	clear(s.vuk)
	clear(s.cek)
	*s = localIsolationSettled{}
}

// localIsolationReadSettled binds one acknowledged first write to the typed
// journal record, the actual named-backend bytes, the signed immediate
// transition and the authenticated current policy. It performs no credential
// access and returns the exact persisted successor for later owner and
// cryptographic checks.
func localIsolationReadSettled(t *testing.T, v *localIsolationVault, result LocalOwnedFirstWriteResult) *localIsolationSettled {
	t.Helper()
	if result.VaultID != v.manifest.VaultID || result.JournalPath != v.manifest.Journal ||
		result.OperationID == "" || result.Revision == "" {
		t.Fatal("LOCAL_TWO_ACCOUNT_RESULT_BINDING_FAILED")
	}
	record, err := vaultfilejournal.ReadOwnedFirstSuccessor(v.manifest.Journal, v.pin)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_RECORD_FAILED")
	}
	success := false
	defer func() {
		if !success {
			clear(record.GenesisBytes)
			clear(record.SuccessorBytes)
		}
	}()
	if string(record.GenesisRevision) != v.bootstrapRevision ||
		string(record.SuccessorRevision) != result.Revision ||
		!bytes.Equal(record.GenesisBytes, v.genesis) {
		t.Fatal("LOCAL_TWO_ACCOUNT_RECORD_BINDING_FAILED")
	}
	backendBytes, backendRevision := localFirstReadBackend(t, v.manifest)
	defer clear(backendBytes)
	if string(backendRevision) != result.Revision || !bytes.Equal(backendBytes, record.SuccessorBytes) {
		t.Fatal("LOCAL_TWO_ACCOUNT_BACKEND_RECORD_DISAGREE")
	}
	if err := vaultfile.VerifyContentTransition(record.GenesisBytes, record.SuccessorBytes, v.checkpoint); err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_TRANSITION_INVALID")
	}
	successor, err := vaultfile.ParseFile(record.SuccessorBytes)
	if err != nil || len(successor.SignedPolicyProofs) == 0 ||
		successor.Header.VaultID != v.manifest.VaultID ||
		successor.Header.OpID != result.OperationID ||
		successor.Header.ContentSeq != 1 ||
		successor.Header.AuthorDeviceID == "" ||
		vaultfile.VerifyPolicyCheckpoint(successor, v.checkpoint) != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_SUCCESSOR_BINDING_FAILED")
	}
	policy := &successor.SignedPolicyProofs[len(successor.SignedPolicyProofs)-1].Policy
	if policy.PolicySeq != successor.Header.PolicySeq ||
		policy.OwnerRoot.KeyID != v.checkpoint.OwnerRootKeyID ||
		!bytes.Equal(policy.OwnerRoot.PublicKey, v.checkpoint.OwnerRootPublicKey) ||
		!bytes.Equal(vaultfile.PolicyDigest(policy), v.checkpoint.PolicyDigest) {
		t.Fatal("LOCAL_TWO_ACCOUNT_POLICY_ROOT_FAILED")
	}
	success = true
	return &localIsolationSettled{record: record, file: successor, itemID: v.item.ID}
}

type localIsolationOwner struct {
	signing   ed25519.PrivateKey
	identity  *age.X25519Identity
	recipient string
	deviceID  string
}

func (o *localIsolationOwner) clear() {
	if o == nil {
		return
	}
	clear(o.signing)
	o.signing = nil
	o.identity = nil
	o.recipient = ""
	o.deviceID = ""
}

// newLocalIsolationOwner derives the account device from the genuine account
// slot with the existing private test comparator and binds it to the
// authenticated successor policy. No private value is returned outside this
// test process or included in an error message.
func newLocalIsolationOwner(t *testing.T, v *localIsolationVault, file *vaultfile.File) *localIsolationOwner {
	t.Helper()
	signing, identity, recipient := localClientAccountIdentity(t, v.manifest.PersonalFile,
		v.f.password, v.f.key)
	ok := false
	defer func() {
		if !ok {
			clear(signing)
		}
	}()
	if len(file.SignedPolicyProofs) == 0 {
		t.Fatal("LOCAL_TWO_ACCOUNT_OWNER_POLICY_FAILED")
	}
	policy := &file.SignedPolicyProofs[len(file.SignedPolicyProofs)-1].Policy
	deviceID, found := localOwnedWriterDevice(policy, recipient, signing.Public().(ed25519.PublicKey))
	if !found || deviceID != file.Header.AuthorDeviceID {
		t.Fatal("LOCAL_TWO_ACCOUNT_OWNER_DEVICE_FAILED")
	}
	ok = true
	return &localIsolationOwner{signing: signing, identity: identity, recipient: recipient, deviceID: deviceID}
}

// localIsolationAssertOwnItem opens the owner's own persisted successor through
// the existing authenticated item path, using only that owner's checkpoint and
// device identity.
func localIsolationAssertOwnItem(t *testing.T, v *localIsolationVault, owner *localIsolationOwner, settled *localIsolationSettled) {
	t.Helper()
	_, metadata, items, err := vault.OpenAuthenticatedItems(settled.record.SuccessorBytes,
		v.checkpoint, owner.deviceID, owner.identity)
	defer clear(metadata)
	defer func() {
		for i := range items {
			items[i] = vault.Item{}
		}
	}()
	if err != nil || len(items) != 1 ||
		items[0].ID != v.item.ID || items[0].Title != v.item.Title ||
		items[0].Username != v.item.Username || items[0].Password != v.item.Password {
		t.Fatal("LOCAL_TWO_ACCOUNT_PERSISTED_ITEM_FAILED")
	}
}

func localIsolationOpenVUK(t *testing.T, file *vaultfile.File, checkpoint *vaultfile.PolicyCheckpoint,
	deviceID, recipient string, identity *age.X25519Identity, code string) []byte {
	t.Helper()
	var slot *vaultfile.DeviceSlot
	for i := range file.VUKDeviceSlots {
		if file.VUKDeviceSlots[i].DeviceID == deviceID {
			slot = &file.VUKDeviceSlots[i]
			break
		}
	}
	if slot == nil || slot.Recipient != recipient {
		t.Fatal(code)
		return nil
	}
	vuk, err := vaultfile.OpenVUKForDevice(*slot, checkpoint.VaultID, file.Header.KeyEpoch,
		deviceID, recipient, identity)
	if err != nil || len(vuk) != vaultfile.CEKSize {
		clear(vuk)
		t.Fatal(code)
		return nil
	}
	return vuk
}

func localIsolationOpenCEK(t *testing.T, vuk []byte, file *vaultfile.File, code string) []byte {
	t.Helper()
	cek, err := vaultfile.OpenCEK(vuk, file.Header, file.CEKSlot)
	if err != nil || len(cek) != vaultfile.CEKSize {
		clear(cek)
		t.Fatal(code)
		return nil
	}
	return cek
}

// localIsolationOpenOwnCustody derives the owner's real VUK and per-snapshot
// CEK from the exact persisted successor under the owner's own checkpoints. It
// also proves the acknowledged write used a fresh CEK rather than the genesis
// snapshot's CEK under the same VUK.
func localIsolationOpenOwnCustody(t *testing.T, v *localIsolationVault, owner *localIsolationOwner, settled *localIsolationSettled) {
	t.Helper()
	vuk := localIsolationOpenVUK(t, settled.file, v.checkpoint, owner.deviceID, owner.recipient,
		owner.identity, "LOCAL_TWO_ACCOUNT_VUK_OPEN_FAILED")
	var cek []byte
	ok := false
	defer func() {
		if !ok {
			clear(vuk)
			clear(cek)
		}
	}()
	cek = localIsolationOpenCEK(t, vuk, settled.file, "LOCAL_TWO_ACCOUNT_CEK_OPEN_FAILED")
	genesisFile, err := vaultfile.ParseFile(v.genesis)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_GENESIS_PARSE_FAILED")
		return
	}
	genesisCEK := localIsolationOpenCEK(t, vuk, genesisFile, "LOCAL_TWO_ACCOUNT_GENESIS_CEK_OPEN_FAILED")
	if bytes.Equal(genesisCEK, cek) {
		clear(genesisCEK)
		t.Fatal("LOCAL_TWO_ACCOUNT_CEK_NOT_FRESH")
		return
	}
	clear(genesisCEK)
	settled.vuk = vuk
	settled.cek = cek
	ok = true
}

func localIsolationWantCode(t *testing.T, err error, code, failure string) {
	t.Helper()
	var vaultErr *vaultfile.Error
	if !errors.As(err, &vaultErr) || vaultErr.Code != code {
		t.Fatal(failure)
	}
}

// localIsolationAssertCrossAccount proves that one account's legitimate access
// cannot read another account's actual persisted successor, even though the
// target's exact checkpoint, journal path, backend name and public device ID
// are all known. The product foreign-owner check is a separate assertion; the
// direct checks then exercise the real VUK, CEK and KDBX payload envelopes.
func localIsolationAssertCrossAccount(t *testing.T,
	viewer *personal.Session, viewerVault *localIsolationVault,
	viewerOwner *localIsolationOwner, viewerSettled *localIsolationSettled,
	targetVault *localIsolationVault, targetOwner *localIsolationOwner,
	targetSettled *localIsolationSettled) {
	t.Helper()

	// The target checkpoint is the exact persisted one, and the target bytes
	// are the actual backend object, not a synthetic or intentionally stale
	// negative.
	if targetVault.checkpoint.VaultID != targetVault.manifest.VaultID ||
		!localGenesisCheckpointMatchesCompanion(targetVault.checkpoint, targetVault.companion.Resume.Checkpoint) ||
		vaultfile.VerifyPolicyCheckpoint(targetSettled.file, targetVault.checkpoint) != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_TARGET_CHECKPOINT_NOT_EXACT")
	}
	backendBytes, backendRevision := localFirstReadBackend(t, targetVault.manifest)
	defer clear(backendBytes)
	if string(backendRevision) != string(targetSettled.record.SuccessorRevision) ||
		!bytes.Equal(backendBytes, targetSettled.record.SuccessorBytes) {
		t.Fatal("LOCAL_TWO_ACCOUNT_TARGET_BYTES_NOT_ACTUAL")
	}

	handle, err := vaultfile.NewScopedUnlock(targetSettled.record.SuccessorBytes,
		targetVault.checkpoint, targetOwner.deviceID, targetOwner.identity)
	if err != nil || handle == nil {
		if handle != nil {
			_ = handle.Close()
		}
		t.Fatal("LOCAL_TWO_ACCOUNT_TARGET_VUK_POSITIVE_FAILED")
	}
	_ = handle.Close()

	// Product foreign-owner check: the viewer's account has no owner record
	// for the target VaultID, so the owned-child constructor must refuse it as
	// an ownership failure before registration.
	token, items, err := viewer.OpenOwnedVaultFileChild(targetVault.manifest.Journal,
		targetVault.checkpoint, viewerVault.f.password, viewerVault.f.key,
		personal.VaultFileChildOptions{IncludeItemIDs: true})
	if !errors.Is(err, personal.ErrVaultFileOwnership) ||
		token != (personal.VaultFileChildToken{}) || items != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_FOREIGN_OWNED_ACCEPTED")
	}

	// The generic caller-pinned child still proves the viewer's own factors and
	// must not disclose anything for the foreign target. A settled owned
	// successor journal is outside the legacy reader's shape, so the committed
	// wrapper refuses it either as a baseline-journal or as a baseline-
	// verification failure; no token or item is returned either way.
	token, items, err = viewer.OpenVaultFileChild(targetVault.manifest.Journal,
		targetVault.checkpoint, viewerVault.f.password, viewerVault.f.key,
		personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err == nil || token != (personal.VaultFileChildToken{}) || items != nil ||
		(!errors.Is(err, personal.ErrVaultFileBaselineVerification) &&
			!errors.Is(err, personal.ErrVaultFileBaselineJournal)) {
		t.Fatal("LOCAL_TWO_ACCOUNT_FOREIGN_GENERIC_ACCEPTED")
	}

	// Direct VUK refusal: the target's exact checkpoint, actual bytes and
	// public device ID are used with the viewer's genuine account identity.
	// The age envelope cannot be opened for the viewer identity.
	foreignHandle, err := vaultfile.NewScopedUnlock(targetSettled.record.SuccessorBytes,
		targetVault.checkpoint, targetOwner.deviceID, viewerOwner.identity)
	if foreignHandle != nil {
		_ = foreignHandle.Close()
		t.Fatal("LOCAL_TWO_ACCOUNT_FOREIGN_VUK_ACCEPTED")
	}
	localIsolationWantCode(t, err, vaultfile.CodeVUKEnvelopeFailed, "LOCAL_TWO_ACCOUNT_FOREIGN_VUK_ACCEPTED")

	// Direct CEK refusal: the viewer's real VUK cannot open the target's
	// actual CEK slot under the target's authenticated header.
	foreignCEK, err := vaultfile.OpenCEK(viewerSettled.vuk, targetSettled.file.Header,
		targetSettled.file.CEKSlot)
	if foreignCEK != nil {
		clear(foreignCEK)
		t.Fatal("LOCAL_TWO_ACCOUNT_FOREIGN_CEK_ACCEPTED")
	}
	localIsolationWantCode(t, err, vaultfile.CodeCEKEnvelopeFailed, "LOCAL_TWO_ACCOUNT_FOREIGN_CEK_ACCEPTED")

	// Direct payload refusal: the viewer's legitimate CEK cannot decrypt the
	// target's actual KDBX ciphertext. The target's own wrapper already proved
	// that same ciphertext is well formed under its own CEK.
	if _, err := vaultfile.OpenKDBXPayload(targetSettled.file.KDBXCiphertext, viewerSettled.cek); err == nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_FOREIGN_PAYLOAD_ACCEPTED")
	} else {
		localIsolationWantCode(t, err, vaultfile.CodeKDBXPayloadInvalid, "LOCAL_TWO_ACCOUNT_FOREIGN_PAYLOAD_ACCEPTED")
	}
}

func localIsolationAssertSummary(t *testing.T, wrapper *LocalGenesisSession, summary LocalGenesisBaseline,
	v *localIsolationVault) {
	t.Helper()
	if summary.VaultID != v.manifest.VaultID || len(summary.Items) != 1 ||
		summary.Items[0].Title != v.item.Title {
		t.Fatal("LOCAL_TWO_ACCOUNT_WRAPPER_SUMMARY_FAILED")
	}
	again, err := wrapper.Summary()
	if err != nil || again.VaultID != v.manifest.VaultID || len(again.Items) != 1 ||
		again.Items[0].Title != v.item.Title {
		t.Fatal("LOCAL_TWO_ACCOUNT_WRAPPER_SUMMARY_REOPEN_FAILED")
	}
}

func localIsolationAssertQuery(t *testing.T, wrapper *LocalGenesisSession, v *localIsolationVault,
	itemID string) {
	t.Helper()
	result, err := wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: v.item.Title, Limit: 2})
	if err != nil || len(result.Hits) != 1 || result.Truncated ||
		result.Hits[0].ID != itemID || result.Hits[0].ID != v.item.ID ||
		result.Hits[0].Title != v.item.Title ||
		result.VaultID != v.manifest.VaultID ||
		result.ConfigPath != v.config ||
		result.WorkspaceRoot != v.manifest.BackendRoot ||
		result.JournalPath != v.manifest.Journal {
		t.Fatal("LOCAL_TWO_ACCOUNT_QUERY_FAILED")
	}
	if err := wrapper.ValidateExactQueryHit(result, result.Hits[0].ID, result.Hits[0].Title); err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_QUERY_ACTIVATION_FAILED")
	}
}

func localIsolationOwnership(t *testing.T, session *personal.Session, v *localIsolationVault) []personal.VaultFileOwnershipPublic {
	t.Helper()
	owners, err := session.VaultFileOwnerships()
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_OWNERSHIP_FAILED")
	}
	if len(owners) != 1 || owners[0].VaultID != v.manifest.VaultID ||
		owners[0].OwnerRootKeyID != v.checkpoint.OwnerRootKeyID ||
		owners[0].OwnerRootPublicKey != hex.EncodeToString(v.checkpoint.OwnerRootPublicKey) ||
		owners[0].RecoveryDeviceID == "" ||
		owners[0].RecoveryAgeRecipient == "" ||
		owners[0].RecoveryContentSigningPublicKey == "" {
		t.Fatal("LOCAL_TWO_ACCOUNT_OWNERSHIP_BINDING_FAILED")
	}
	return owners
}

func localIsolationAssertNoForeignOwner(t *testing.T, owners []personal.VaultFileOwnershipPublic,
	foreignVaultID, failure string) {
	t.Helper()
	for _, owner := range owners {
		if owner.VaultID == foreignVaultID {
			t.Fatal(failure)
		}
	}
}

func localIsolationPrivateNeedles(owner *localIsolationOwner, settled *localIsolationSettled) []string {
	needles := []string{
		hex.EncodeToString(owner.signing.Seed()),
		hex.EncodeToString(owner.signing),
		base64.StdEncoding.EncodeToString(owner.signing.Seed()),
		base64.StdEncoding.EncodeToString(owner.signing),
		owner.identity.String(),
	}
	if len(settled.vuk) > 0 {
		needles = append(needles, hex.EncodeToString(settled.vuk),
			base64.StdEncoding.EncodeToString(settled.vuk))
	}
	if len(settled.cek) > 0 {
		needles = append(needles, hex.EncodeToString(settled.cek),
			base64.StdEncoding.EncodeToString(settled.cek))
	}
	return needles
}

func localIsolationAssertNoSecrets(t *testing.T, blobs [][]byte, needles []string, failure string) {
	t.Helper()
	for _, blob := range blobs {
		for _, needle := range needles {
			if needle != "" && bytes.Contains(blob, []byte(needle)) {
				t.Fatal(failure)
			}
		}
	}
}

// TestOwnedFirstWriteLocalTwoAccountsCannotDecryptEachOther is one acceptance
// checkpoint for two independent real local accounts. Each account creates and
// first-writes its own named owned vault through the production paths. The test
// then reopens each vault through a normal scoped wrapper and proves that one
// owner's legitimate checkpoint, device credentials and content keys cannot
// read the other owner's actual persisted bytes. It does not claim #123/#105
// closure or any sharing revocation.
func TestOwnedFirstWriteLocalTwoAccountsCannotDecryptEachOther(t *testing.T) {
	passwordA := []byte("two-account-isolation-factor-a")
	keyA := bytes.Repeat([]byte{0x5a}, 16)
	passwordB := []byte("two-account-isolation-factor-b")
	keyB := bytes.Repeat([]byte{0x6b}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)

	fA := localIsolationCreation(t, "a", passwordA, keyA)
	fB := localIsolationCreation(t, "b", passwordB, keyB)
	vA := newLocalIsolationVault(t, fA, localFirstWriteTitle)
	vB := newLocalIsolationVault(t, fB, localFirstWriteTitle)
	vA.item.Password = localFirstWriteSecret + "-a"
	vB.item.Password = localFirstWriteSecret + "-b"

	if vA.manifest.PersonalFile == vB.manifest.PersonalFile ||
		vA.manifest.VaultID == vB.manifest.VaultID ||
		vA.manifest.Journal == vB.manifest.Journal ||
		vA.manifest.BackendRoot == vB.manifest.BackendRoot ||
		vA.manifest.Name == vB.manifest.Name ||
		vA.config == vB.config ||
		vA.manifest.PersonalFile != fA.proposal.PersonalFile ||
		vB.manifest.PersonalFile != fB.proposal.PersonalFile ||
		bytes.Equal(passwordA, passwordB) || bytes.Equal(keyA, keyB) {
		t.Fatal("LOCAL_TWO_ACCOUNT_SCOPES_NOT_INDEPENDENT")
	}
	if bytes.Equal(vA.checkpoint.OwnerRootPublicKey, vB.checkpoint.OwnerRootPublicKey) ||
		vA.checkpoint.OwnerRootKeyID == vB.checkpoint.OwnerRootKeyID ||
		vA.checkpoint.VaultID == vB.checkpoint.VaultID ||
		bytes.Equal(vA.checkpoint.PolicyDigest, vB.checkpoint.PolicyDigest) {
		t.Fatal("LOCAL_TWO_ACCOUNT_MANAGEMENT_ROOTS_NOT_INDEPENDENT")
	}

	// Publish each vault independently through the production first-write
	// helper and prove each write leaves the other exact durable scope intact.
	beforeB := localFirstObserveScope(t, vB.manifest)
	defer beforeB.clear()
	resultA := vA.write(t)
	localFirstAssertScopeUnchanged(t, beforeB, vB.manifest, "LOCAL_TWO_ACCOUNT_B_CHANGED_BY_A_WRITE")

	afterA := localFirstObserveScope(t, vA.manifest)
	defer afterA.clear()
	resultB := vB.write(t)
	localFirstAssertScopeUnchanged(t, afterA, vA.manifest, "LOCAL_TWO_ACCOUNT_A_CHANGED_BY_B_WRITE")

	settledA := localIsolationReadSettled(t, vA, resultA)
	defer settledA.clear()
	settledB := localIsolationReadSettled(t, vB, resultB)
	defer settledB.clear()
	ownerA := newLocalIsolationOwner(t, vA, settledA.file)
	defer ownerA.clear()
	ownerB := newLocalIsolationOwner(t, vB, settledB.file)
	defer ownerB.clear()

	localIsolationAssertOwnItem(t, vA, ownerA, settledA)
	localIsolationAssertOwnItem(t, vB, ownerB, settledB)
	localIsolationOpenOwnCustody(t, vA, ownerA, settledA)
	localIsolationOpenOwnCustody(t, vB, ownerB, settledB)

	// The genesis author device ID is a fixed per-vault label, so two
	// independent vaults legitimately share it. Compare the owners' real
	// Ed25519 signing public keys instead.
	if bytes.Equal(ownerA.signing.Public().(ed25519.PublicKey), ownerB.signing.Public().(ed25519.PublicKey)) ||
		ownerA.recipient == ownerB.recipient ||
		settledA.itemID == settledB.itemID ||
		resultA.OperationID == resultB.OperationID ||
		bytes.Equal(settledA.vuk, settledB.vuk) ||
		bytes.Equal(settledA.cek, settledB.cek) {
		t.Fatal("LOCAL_TWO_ACCOUNT_KEYS_OR_IDENTITIES_NOT_DISTINCT")
	}

	// The write sessions are no longer needed. Reopen each account from its
	// persisted slot with its own factors, then open the normal scoped wrapper.
	vA.session.Lock()
	vB.session.Lock()
	freshA, err := personal.UnlockSession(vA.manifest.PersonalFile, fA.password, fA.key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_A_REOPEN_FAILED")
	}
	t.Cleanup(freshA.Lock)
	freshB, err := personal.UnlockSession(vB.manifest.PersonalFile, fB.password, fB.key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_B_REOPEN_FAILED")
	}
	t.Cleanup(freshB.Lock)

	ownersA := localIsolationOwnership(t, freshA, vA)
	ownersB := localIsolationOwnership(t, freshB, vB)
	localIsolationAssertNoForeignOwner(t, ownersA, vB.manifest.VaultID,
		"LOCAL_TWO_ACCOUNT_A_ROSTER_HAS_B")
	localIsolationAssertNoForeignOwner(t, ownersB, vA.manifest.VaultID,
		"LOCAL_TWO_ACCOUNT_B_ROSTER_HAS_A")

	wrapperA, summaryA, err := OpenLocalGenesisSessionForJournal(freshA, vA.config,
		vA.manifest.BackendRoot, vA.manifest.VaultID, vA.manifest.Journal,
		fA.password, fA.key)
	if err != nil || wrapperA == nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_A_WRAPPER_OPEN_FAILED")
	}
	defer wrapperA.Close()
	localIsolationAssertSummary(t, wrapperA, summaryA, vA)

	wrapperB, summaryB, err := OpenLocalGenesisSessionForJournal(freshB, vB.config,
		vB.manifest.BackendRoot, vB.manifest.VaultID, vB.manifest.Journal,
		fB.password, fB.key)
	if err != nil || wrapperB == nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_B_WRAPPER_OPEN_FAILED")
	}
	defer wrapperB.Close()
	localIsolationAssertSummary(t, wrapperB, summaryB, vB)

	localIsolationAssertQuery(t, wrapperA, vA, settledA.itemID)
	localIsolationAssertQuery(t, wrapperB, vB, settledB.itemID)

	// Cross-account negatives in both directions, using the exact target
	// checkpoint and actual target bytes.
	localIsolationAssertCrossAccount(t, freshA, vA, ownerA, settledA, vB, ownerB, settledB)
	localIsolationAssertCrossAccount(t, freshB, vB, ownerB, settledB, vA, ownerA, settledA)

	// The public restricted roster and the shipped vault files contain no
	// client signing seed, age secret, VUK or CEK from either account.
	manifestA := mustReadFile(t, vA.config)
	companionPathA, err := CompanionPath(vA.config)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_A_COMPANION_PATH_FAILED")
	}
	companionA := mustReadFile(t, companionPathA)
	journalA := mustReadFile(t, vA.manifest.Journal)
	backendA, _ := localFirstReadBackend(t, vA.manifest)
	manifestB := mustReadFile(t, vB.config)
	companionPathB, err := CompanionPath(vB.config)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_B_COMPANION_PATH_FAILED")
	}
	companionB := mustReadFile(t, companionPathB)
	journalB := mustReadFile(t, vB.manifest.Journal)
	backendB, _ := localFirstReadBackend(t, vB.manifest)
	rosterA, err := json.Marshal(ownersA)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_A_ROSTER_ENCODE_FAILED")
	}
	rosterB, err := json.Marshal(ownersB)
	if err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_B_ROSTER_ENCODE_FAILED")
	}
	needles := append(localIsolationPrivateNeedles(ownerA, settledA),
		localIsolationPrivateNeedles(ownerB, settledB)...)
	localIsolationAssertNoSecrets(t, [][]byte{
		manifestA, companionA, journalA, backendA,
		manifestB, companionB, journalB, backendB, rosterA, rosterB,
	}, needles, "LOCAL_TWO_ACCOUNT_PRIVATE_KEY_PERSISTED")
	clear(backendA)
	clear(backendB)

	// Retiring A's wrapper and then locking A's account leaves B's reopened
	// wrapper and exact query intact.
	if err := wrapperA.Close(); err != nil {
		t.Fatal("LOCAL_TWO_ACCOUNT_A_WRAPPER_CLOSE_FAILED")
	}
	localIsolationAssertSummary(t, wrapperB, summaryB, vB)
	localIsolationAssertQuery(t, wrapperB, vB, settledB.itemID)

	freshA.Lock()
	if freshA.Unlocked() {
		t.Fatal("LOCAL_TWO_ACCOUNT_A_DID_NOT_LOCK")
	}
	localIsolationAssertSummary(t, wrapperB, summaryB, vB)
	localIsolationAssertQuery(t, wrapperB, vB, settledB.itemID)
}
