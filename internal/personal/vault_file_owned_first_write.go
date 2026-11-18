package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// VaultFileFirstItem is the minimal unsanitized login item accepted by one
// owned first-item write. It exists only for the protected call: after
// sealing, no field is retained, returned, logged or serialized by this
// package. ID must be a caller-stable opaque selector.
type VaultFileFirstItem struct {
	ID       string
	Title    string
	Username string
	Password string
}

// VaultFileSealedFirstItem is the sealed result of one pristine first-item
// write. State is the exact pristine generation-zero journal state the bytes
// were built against. Sealed is the complete signed immediate successor.
// AuthorDeviceID and AuthorPrincipalID are public policy selectors, never
// signing keys.
type VaultFileSealedFirstItem struct {
	State             vaultfilejournal.State
	Sealed            []byte
	AuthorDeviceID    string
	AuthorPrincipalID string
}

// Clear releases the sealed byte buffers retained by v.
func (v *VaultFileSealedFirstItem) Clear() {
	if v == nil {
		return
	}
	clear(v.State.BaseBytes)
	clear(v.State.WorkingBytes)
	clear(v.Sealed)
	*v = VaultFileSealedFirstItem{}
}

// OwnedVaultFilePendingFirstWrite is one exact pending first-item publication
// recovered directly from a write-owned journal shape. Pending is the dirty
// generation-1 state, Origin is the same provenance reconstructed as the
// pristine generation-zero state AckOwnedFirstSuccessor requires, and
// Prepared is the exact durable proposal. It contains sealed bytes only and
// grants no authority after the call.
type OwnedVaultFilePendingFirstWrite struct {
	Pending           vaultfilejournal.State
	Origin            vaultfilejournal.State
	Prepared          vaultfilejournal.PreparedProposal
	AuthorDeviceID    string
	AuthorPrincipalID string
}

// Clear releases every sealed byte buffer retained by p.
func (p *OwnedVaultFilePendingFirstWrite) Clear() {
	if p == nil {
		return
	}
	clear(p.Pending.BaseBytes)
	clear(p.Pending.WorkingBytes)
	clear(p.Origin.BaseBytes)
	clear(p.Origin.WorkingBytes)
	clear(p.Prepared.Proposal.Bytes)
	*p = OwnedVaultFilePendingFirstWrite{}
}

// ownedVaultFileWriteScope is the transient full-factor, current-owner and
// account-device proof shared by the write and recovery paths. It is never
// returned to a caller. The signing seed and account material are cleared by
// clear.
type ownedVaultFileWriteScope struct {
	parentOwner    *vaultFileChildOwner
	parentMaterial []byte
	parentSlot     [32]byte
	parentPath     string
	snapshot       VaultFileOwnershipPublic
	signing        ed25519.PrivateKey
	ageIdentity    *age.X25519Identity
	recipient      string
	signerPublic   ed25519.PublicKey
}

func (s *ownedVaultFileWriteScope) clear() {
	if s == nil {
		return
	}
	clear(s.parentMaterial)
	clear(s.signing)
	s.ageIdentity = nil
	s.signerPublic = nil
	*s = ownedVaultFileWriteScope{}
}

// authenticateOwnedVaultFileWriteScope proves the explicitly supplied full
// factors open the current account slot, authenticates exactly one current
// owner record for the target VaultID, binds that record to the caller's
// companion checkpoint and derives the current account device. The account
// read transaction is closed before any journal or backend work. It does not
// register a child and does not extend any factor deadline.
func (s *Session) authenticateOwnedVaultFileWriteScope(target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint, password, key []byte) (*ownedVaultFileWriteScope, error) {
	if s == nil {
		return nil, ErrSessionLocked
	}
	if !validOwnedVaultFileFirstSuccessorTarget(target) ||
		!ownedVaultFileFirstSuccessorMatchesCheckpoint(target, checkpoint) {
		return nil, ErrVaultFileBaselineVerification
	}

	s.mu.Lock()
	if err := s.active(true); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	parentOwner := s.vaultFileOwner
	parentMaterial := bytes.Clone(s.material)
	parentSlot := s.slotDigest
	parentPath := s.path
	s.mu.Unlock()
	if parentOwner == nil || len(parentMaterial) == 0 {
		clear(parentMaterial)
		return nil, ErrSessionLocked
	}
	scope := &ownedVaultFileWriteScope{
		parentOwner:    parentOwner,
		parentMaterial: parentMaterial,
		parentSlot:     parentSlot,
		parentPath:     parentPath,
	}
	ok := false
	defer func() {
		if !ok {
			scope.clear()
		}
	}()

	factorErr := verifyVaultFileChildFactors(parentPath, parentSlot, parentMaterial, password, key)
	switch {
	case errors.Is(factorErr, errVaultFileChildWrongFactors):
		return nil, ErrVaultFileScopedFactors
	case errors.Is(factorErr, errVaultFileChildInvalidSlot):
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	case factorErr != nil:
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	}

	snapshot, ownedErr := s.authenticateVaultFileOwnedTarget(parentPath, parentMaterial, parentSlot, checkpoint.VaultID)
	switch {
	case errors.Is(ownedErr, ErrVaultFileOwnership):
		return nil, ErrVaultFileOwnership
	case errors.Is(ownedErr, errVaultFileChildInvalidSlot):
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	case ownedErr != nil:
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	}
	if !vaultFileOwnedSnapshotMatchesCheckpoint(snapshot, checkpoint) {
		return nil, ErrVaultFileOwnership
	}
	scope.snapshot = snapshot

	var accountIdentity identity
	if err := json.Unmarshal(parentMaterial, &accountIdentity); err != nil ||
		len(accountIdentity.Signing) != ed25519.SeedSize || accountIdentity.Device == "" {
		accountIdentity.clear()
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	}
	defer func() {
		accountIdentity.clear()
		accountIdentity.Device = ""
	}()
	localAge, err := age.ParseX25519Identity(accountIdentity.Device)
	if err != nil {
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	}
	signer := ed25519.NewKeyFromSeed(accountIdentity.Signing)
	scope.signing = signer
	scope.ageIdentity = localAge
	scope.recipient = localAge.Recipient().String()
	scope.signerPublic = signer.Public().(ed25519.PublicKey)

	if err := s.revalidateOwnedVaultFileWriteScope(scope); err != nil {
		return nil, err
	}
	ok = true
	return scope, nil
}

// revalidateOwnedVaultFileWriteScope rechecks the same parent identity,
// current account slot and exact target owner record without another KDF. It
// is called again at every journal handoff, before any prepared record or
// acknowledgement is released.
func (s *Session) revalidateOwnedVaultFileWriteScope(scope *ownedVaultFileWriteScope) error {
	if s == nil || scope == nil || scope.parentOwner == nil ||
		len(scope.parentMaterial) == 0 || scope.snapshot.VaultID == "" {
		return ErrSessionLocked
	}
	snapshot, err := s.authenticateVaultFileOwnedTarget(scope.parentPath, scope.parentMaterial, scope.parentSlot, scope.snapshot.VaultID)
	switch {
	case errors.Is(err, ErrVaultFileOwnership):
		return ErrVaultFileOwnership
	case errors.Is(err, errVaultFileChildInvalidSlot):
		s.lockVaultFileParent()
		return ErrSessionLocked
	case err != nil:
		s.lockVaultFileParent()
		return ErrSessionLocked
	}
	if snapshot != scope.snapshot {
		return ErrVaultFileOwnership
	}

	s.mu.Lock()
	if err := s.active(true); err != nil {
		s.mu.Unlock()
		return err
	}
	sameParent := s.vaultFileOwner == scope.parentOwner && s.path == scope.parentPath &&
		s.slotDigest == scope.parentSlot &&
		subtle.ConstantTimeCompare(s.material, scope.parentMaterial) == 1
	s.mu.Unlock()
	if !sameParent {
		s.lockVaultFileParent()
		return ErrSessionLocked
	}
	return nil
}

func ownedVaultFileDevicePrincipal(policy *vaultfile.Policy, deviceID string) (string, bool) {
	if policy == nil || deviceID == "" {
		return "", false
	}
	for _, device := range policy.Devices {
		if device.DeviceID == deviceID {
			if !vaultFileWriterPrincipal(policy, device.PrincipalID) {
				return "", false
			}
			return device.PrincipalID, true
		}
	}
	return "", false
}

func sameOwnedVaultFileState(a, b vaultfilejournal.State) bool {
	return a.Generation == b.Generation && a.RemoteRevision == b.RemoteRevision &&
		bytes.Equal(a.BaseBytes, b.BaseBytes) && bytes.Equal(a.WorkingBytes, b.WorkingBytes)
}

// SealOwnedVaultFileFirstItem is the account-bound write boundary for one
// pristine owned genesis. It re-proves full factors, the current owner record,
// the exact caller checkpoint, the expected genesis bytes and operation ID,
// the current account device's writer/principal authority, and the empty
// genesis content before sealing exactly one login item as the immediate
// signed successor. It never reads or writes a backend.
//
// The journal is opened existing-only and must have exactly the single
// generation-zero state record. A pending, advanced, replaced or otherwise
// non-pristine journal is refused. A second offline write is never allowed.
// The caller must atomically compare the returned State before preparing the
// sealed bytes.
func (s *Session) SealOwnedVaultFileFirstItem(journalPath string, target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint, expectedGenesis []byte, password, key []byte, item VaultFileFirstItem) (out VaultFileSealedFirstItem, retErr error) {
	if journalPath == "" || len(expectedGenesis) == 0 || item.ID == "" || item.Title == "" {
		return out, ErrVaultFileEditVerification
	}
	scope, err := s.authenticateOwnedVaultFileWriteScope(target, checkpoint, password, key)
	if err != nil {
		return out, err
	}
	defer scope.clear()
	defer func() {
		if retErr != nil {
			out.Clear()
		}
	}()

	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return out, ErrVaultFileBaselineJournal
	}
	defer func() {
		if j == nil {
			return
		}
		if closeErr := j.Close(); closeErr != nil && retErr == nil {
			out.Clear()
			retErr = ErrVaultFileBaselineJournal
		}
	}()
	state, err := j.LoadGenesisBaseline()
	if err != nil {
		return out, ErrVaultFileBaselineJournal
	}
	defer func() {
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
	}()
	if !bytes.Equal(state.BaseBytes, expectedGenesis) {
		return out, ErrVaultFileBaselineVerification
	}
	if sha256.Sum256(state.BaseBytes) != target.Pin.SealedSHA256 {
		return out, ErrVaultFileBaselineVerification
	}
	genesisCheckpoint, err := vaultfile.VerifyGenesis(state.BaseBytes, &target.Pin.Root)
	if err != nil || !sameVaultFilePolicyCheckpoint(genesisCheckpoint, checkpoint) {
		clearVaultFilePolicyCheckpoint(genesisCheckpoint)
		return out, ErrVaultFileBaselineVerification
	}
	clearVaultFilePolicyCheckpoint(genesisCheckpoint)

	base, err := vaultfile.ParseFile(state.BaseBytes)
	if err != nil || len(base.SignedPolicyProofs) == 0 ||
		base.Header.OpID != target.Pin.OperationID ||
		base.Header.VaultID != checkpoint.VaultID ||
		base.Header.ContentSeq != 0 {
		return out, ErrVaultFileBaselineVerification
	}
	policy := &base.SignedPolicyProofs[len(base.SignedPolicyProofs)-1].Policy
	if policy.PolicySeq != base.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(policy), base.Header.PolicyDigest) ||
		!ownedVaultFileFirstSuccessorMatchesCheckpoint(target, checkpoint) {
		return out, ErrVaultFileBaselineVerification
	}
	deviceID, writerOK := localVaultFileWriterDevice(policy, scope.recipient, scope.signerPublic)
	readerID, readerOK := localVaultFileReaderDevice(policy, scope.recipient, scope.signerPublic)
	if !writerOK || !readerOK || deviceID != readerID {
		return out, ErrVaultFileBaselineVerification
	}
	principalID, principalOK := ownedVaultFileDevicePrincipal(policy, deviceID)
	if !principalOK {
		return out, ErrVaultFileBaselineVerification
	}

	var slot *vaultfile.DeviceSlot
	for i := range base.VUKDeviceSlots {
		if base.VUKDeviceSlots[i].DeviceID == deviceID {
			slot = &base.VUKDeviceSlots[i]
			break
		}
	}
	if slot == nil {
		return out, ErrVaultFileBaselineVerification
	}
	vuk, err := vaultfile.OpenVUKForDevice(*slot, checkpoint.VaultID, base.Header.KeyEpoch,
		deviceID, scope.recipient, scope.ageIdentity)
	if err != nil {
		return out, ErrVaultFileBaselineVerification
	}
	defer clear(vuk)
	_, metadata, items, err := vault.OpenAuthenticatedItems(state.BaseBytes, checkpoint, deviceID, scope.ageIdentity)
	if err != nil {
		return out, ErrVaultFileBaselineVerification
	}
	defer clear(metadata)
	defer clearAuthenticatedItems(items)
	if len(metadata) != 0 || len(items) != 0 {
		return out, ErrVaultFileEditReview
	}

	parentDigest, err := vaultfile.FileDigest(base)
	if err != nil {
		return out, ErrVaultFileEditVerification
	}
	parent, err := hex.DecodeString(parentDigest)
	if err != nil || len(parent) != sha256.Size {
		return out, ErrVaultFileEditVerification
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return out, ErrVaultFileEditVerification
	}
	draft := &vaultfile.File{Format: base.Format, Version: base.Version,
		SignedPolicyProofs: base.SignedPolicyProofs, Header: base.Header}
	draft.Header.ContentSeq++
	draft.Header.PrevDigest = parent
	draft.Header.RevisionID = ""
	draft.Header.OpID = hex.EncodeToString(nonce[:])
	draft.Header.AuthorDeviceID = deviceID
	out.Sealed, err = vault.SealAuthenticatedItems(draft, []byte{}, []vault.Item{{
		ID: item.ID, Kind: "login", Title: item.Title,
		Username: item.Username, Password: item.Password,
	}}, checkpoint, vuk, scope.signing)
	if err != nil || vaultfile.VerifyContentTransition(state.BaseBytes, out.Sealed, checkpoint) != nil {
		return out, ErrVaultFileEditVerification
	}
	successor, err := vaultfile.ParseFile(out.Sealed)
	if err != nil || successor.Header.OpID != draft.Header.OpID ||
		successor.Header.AuthorDeviceID != deviceID {
		return out, ErrVaultFileEditVerification
	}

	current, err := j.LoadGenesisBaseline()
	if err != nil || !sameOwnedVaultFileState(current, state) {
		clear(current.BaseBytes)
		clear(current.WorkingBytes)
		return out, ErrVaultFileBaselineJournal
	}
	clear(current.BaseBytes)
	clear(current.WorkingBytes)
	if err := s.revalidateOwnedVaultFileWriteScope(scope); err != nil {
		return out, err
	}
	if err := j.Close(); err != nil {
		j = nil
		return out, ErrVaultFileBaselineJournal
	}
	j = nil
	if err := s.active(false); err != nil {
		return out, err
	}

	out.State = vaultfilejournal.State{
		BaseBytes:      bytes.Clone(state.BaseBytes),
		RemoteRevision: state.RemoteRevision,
		WorkingBytes:   bytes.Clone(state.BaseBytes),
		Generation:     0,
	}
	out.AuthorDeviceID = deviceID
	out.AuthorPrincipalID = principalID
	return out, nil
}

// RecoverOwnedVaultFileFirstWrite is the narrow write-owned recovery boundary.
// It re-proves the explicit full factors, current parent account, exactly one
// current owner record and the named local target, then reads only the exact
// pending generation-1 state plus prepared proposal from the journal. The
// genesis is authenticated under the original pin/checkpoint, the immediate
// transition is verified from the exact genesis bytes, and the successor must
// be authored by the current account device with writer authority.
//
// It never accepts caller-supplied ciphertext or a caller-supplied proposal
// version, never creates a new item or nonce, never reads or writes the
// backend, and never acknowledges anything. Any non-exact pending shape is a
// bounded journal error and is left intact.
func (s *Session) RecoverOwnedVaultFileFirstWrite(journalPath string, target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint, password, key []byte) (out OwnedVaultFilePendingFirstWrite, retErr error) {
	if journalPath == "" {
		return out, ErrVaultFileBaselineJournal
	}
	scope, err := s.authenticateOwnedVaultFileWriteScope(target, checkpoint, password, key)
	if err != nil {
		return out, err
	}
	defer scope.clear()
	defer func() {
		if retErr != nil {
			out.Clear()
		}
	}()

	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return out, ErrVaultFileBaselineJournal
	}
	pending, prepared, loadErr := j.LoadOwnedFirstPending()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineJournal
	}

	if sha256.Sum256(pending.BaseBytes) != target.Pin.SealedSHA256 {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}
	genesisCheckpoint, err := vaultfile.VerifyGenesis(pending.BaseBytes, &target.Pin.Root)
	if err != nil || !sameVaultFilePolicyCheckpoint(genesisCheckpoint, checkpoint) {
		clearVaultFilePolicyCheckpoint(genesisCheckpoint)
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}
	clearVaultFilePolicyCheckpoint(genesisCheckpoint)
	base, err := vaultfile.ParseFile(pending.BaseBytes)
	if err != nil || len(base.SignedPolicyProofs) == 0 ||
		base.Header.OpID != target.Pin.OperationID ||
		base.Header.VaultID != checkpoint.VaultID ||
		base.Header.ContentSeq != 0 {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}
	policy := &base.SignedPolicyProofs[len(base.SignedPolicyProofs)-1].Policy
	if policy.PolicySeq != base.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(policy), base.Header.PolicyDigest) {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}
	deviceID, writerOK := localVaultFileWriterDevice(policy, scope.recipient, scope.signerPublic)
	readerID, readerOK := localVaultFileReaderDevice(policy, scope.recipient, scope.signerPublic)
	if !writerOK || !readerOK || deviceID != readerID {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}
	principalID, principalOK := ownedVaultFileDevicePrincipal(policy, deviceID)
	if !principalOK {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}

	if vaultfile.VerifyContentTransition(pending.BaseBytes, prepared.Proposal.Bytes, checkpoint) != nil {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}
	successor, err := vaultfile.ParseFile(prepared.Proposal.Bytes)
	if err != nil || successor.Header.OpID != prepared.Proposal.OperationID ||
		successor.Header.AuthorDeviceID != deviceID ||
		successor.Header.VaultID != checkpoint.VaultID ||
		successor.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(successor.Header.PolicyDigest, checkpoint.PolicyDigest) ||
		successor.Header.ContentSeq != 1 {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, ErrVaultFileBaselineVerification
	}

	if err := s.revalidateOwnedVaultFileWriteScope(scope); err != nil {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return out, err
	}

	origin := vaultfilejournal.State{
		BaseBytes:      bytes.Clone(pending.BaseBytes),
		RemoteRevision: pending.RemoteRevision,
		WorkingBytes:   bytes.Clone(pending.BaseBytes),
		Generation:     0,
	}
	out = OwnedVaultFilePendingFirstWrite{
		Pending:           pending,
		Origin:            origin,
		Prepared:          prepared,
		AuthorDeviceID:    deviceID,
		AuthorPrincipalID: principalID,
	}
	return out, nil
}
