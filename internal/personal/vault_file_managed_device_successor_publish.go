package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/jihuayu/locklark/internal/vaultfilesync"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// This file adds the explicit, consented local publication checkpoint for one
// already prepared managed-device successor. It reuses three existing pieces
// instead of inventing a second writer:
//
//   - PrepareVaultFileManagedDeviceSuccessor owns the recovered-owner,
//     destination-device, policy and sealing proof;
//   - vaultfilejournal.RebaseAndPrepare atomically writes the exact prepared
//     operation (state, prepared proposal and immutable rebase audit) before any
//     backend mutation;
//   - vaultfilepublish.Coordinator owns the single no-create compare-and-swap,
//     the one verified readback and the durable Ack.
//
// The settled durable proof is that existing pair, not a new journal format:
// the audit record keeps the original base and the exact successor proposal,
// and the state records the exact successor revision. The original genesis,
// first-successor journal, backup artifact and source journal are untouched.
//
// The preparation step is deliberately not exposed as a caller-supplied draft.
// Publish calls it in the same Session.mu critical section as the durable
// prepare, so the acknowledged successor cannot be a caller's alternative
// ciphertext. Resume consumes only the exact prepared operation already in the
// dedicated journal; it never signs again. Reopen verifies the settled record
// and the ordinary fresh account device before creating a read-only child.

var (
	// ErrVaultFileManagedDeviceSuccessorPath reports that the caller-located
	// local journal or backend target is missing, unsupported or unreadable.
	// It is a fixed capability classification and never contains a pathname.
	ErrVaultFileManagedDeviceSuccessorPath = errors.New("vault-file managed device successor local path unavailable")
	// ErrVaultFileManagedDeviceSuccessorConflict reports that the independently
	// trusted base pin, revision or owner no longer matches the exact base, or
	// that the journal is in a different valid state. Nothing was written by
	// this call.
	ErrVaultFileManagedDeviceSuccessorConflict = errors.New("vault-file managed device successor publication conflict")
	// ErrVaultFileManagedDeviceSuccessorPending reports that an exact durable
	// prepared operation exists and must be finished by an explicit resume.
	// The prepared record is preserved.
	ErrVaultFileManagedDeviceSuccessorPending = errors.New("vault-file managed device successor publication pending")
	// ErrVaultFileManagedDeviceSuccessorUnknown reports an unobserved or
	// ambiguous backend outcome. The durable prepared record is preserved and
	// no receipt or activation is returned.
	ErrVaultFileManagedDeviceSuccessorUnknown = errors.New("vault-file managed device successor publication outcome unknown")
	// ErrVaultFileManagedDeviceSuccessorUnconfirmed reports that the operation
	// may already be durable but a post-commit cancellation, lock, freshness or
	// close check failed. Success is never inferred; the settled or prepared
	// record remains available for an explicit resume.
	ErrVaultFileManagedDeviceSuccessorUnconfirmed = errors.New("vault-file managed device successor publication unconfirmed")
	// ErrVaultFileManagedDeviceSuccessorNoOperation reports an explicit resume
	// with no durable prepared or settled managed operation to finish.
	ErrVaultFileManagedDeviceSuccessorNoOperation = errors.New("vault-file managed device successor has no durable operation")
	// ErrVaultFileManagedDeviceSuccessorReopen reports that the settled managed
	// successor, exact backend revision or ordinary destination device did not
	// match. No child or item summary is returned.
	ErrVaultFileManagedDeviceSuccessorReopen = errors.New("vault-file managed device successor reopen rejected")
)

// vaultFileManagedDeviceSuccessorAfterPrepareForTest is a private
// nil-by-default fault point after the durable prepared record exists and
// before the single CAS. Production leaves it nil.
var vaultFileManagedDeviceSuccessorAfterPrepareForTest func()

// vaultFileManagedDeviceSuccessorBackend is the narrow local capability used
// by publish, resume and reopen. It is exactly the coordinator's conditional
// surface plus Close.
type vaultFileManagedDeviceSuccessorBackend interface {
	Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error)
	ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error
	Close() error
	StableIdentity() ([sha256.Size]byte, error)
}

// openVaultFileManagedDeviceSuccessorBackend opens the caller-located existing
// local backend. It is a variable only so a test can prove an unknown write
// result and the coordinator's verified reconciliation; production always uses
// the existing-only local directory backend.
var openVaultFileManagedDeviceSuccessorBackend = func(root string) (vaultFileManagedDeviceSuccessorBackend, error) {
	return vaultfilebackend.OpenExistingDir(root)
}

// VaultFileManagedDeviceSuccessorReceipt is the narrow result of one locally
// observed publication or resume. It carries public policy/device selectors and
// hashes only; it never carries ciphertext, a key, a factor, item content or a
// pathname. Its String, GoString, MarshalJSON and Format forms are completely
// redacted, including the opaque revisions.
type VaultFileManagedDeviceSuccessorReceipt struct {
	VaultID             string
	OperationID         string
	DestinationDeviceID string
	BasePolicySeq       uint64
	NextPolicySeq       uint64
	BaseKeyEpoch        uint64
	NextKeyEpoch        uint64
	BaseContentSeq      uint64
	NextContentSeq      uint64
	BaseSHA256          [sha256.Size]byte
	SuccessorSHA256     [sha256.Size]byte
	BaseRevision        vaultfilebackend.Revision
	SuccessorRevision   vaultfilebackend.Revision
	Next                vaultfile.PolicyCheckpoint
	Signed              bool
	LocallyObserved     bool
}

const vaultFileManagedDeviceSuccessorReceiptRedacted = "[vault-file managed device successor receipt]"

func (VaultFileManagedDeviceSuccessorReceipt) String() string {
	return vaultFileManagedDeviceSuccessorReceiptRedacted
}
func (VaultFileManagedDeviceSuccessorReceipt) GoString() string {
	return vaultFileManagedDeviceSuccessorReceiptRedacted
}
func (VaultFileManagedDeviceSuccessorReceipt) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted]"`), nil
}
func (VaultFileManagedDeviceSuccessorReceipt) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, vaultFileManagedDeviceSuccessorReceiptRedacted)
}

// Clear releases the public checkpoint byte slices retained by the receipt.
func (r *VaultFileManagedDeviceSuccessorReceipt) Clear() {
	if r == nil {
		return
	}
	clearVaultFilePolicyCheckpoint(&r.Next)
	*r = VaultFileManagedDeviceSuccessorReceipt{}
}

// OwnedVaultFileManagedSuccessorTarget freezes the exact existing local journal,
// named backend object and independently trusted base pin for one settled
// managed successor. It is a selector only; the typed reader and current
// Session still establish every trust fact.
type OwnedVaultFileManagedSuccessorTarget struct {
	JournalPath  string
	BackendRoot  string
	BackendName  string
	Pin          VaultFileManagedDeviceSuccessorPin
	OperationID  string
	SuccessorRev vaultfilebackend.Revision
}

func cloneVaultFileManagedDeviceSuccessorPin(pin VaultFileManagedDeviceSuccessorPin) VaultFileManagedDeviceSuccessorPin {
	pin.Checkpoint = *cloneVaultFilePolicyCheckpoint(&pin.Checkpoint)
	return pin
}

func cloneOwnedVaultFileManagedSuccessorTarget(target OwnedVaultFileManagedSuccessorTarget) OwnedVaultFileManagedSuccessorTarget {
	target.Pin = cloneVaultFileManagedDeviceSuccessorPin(target.Pin)
	return target
}

func sameOwnedVaultFileManagedSuccessorTarget(a, b *OwnedVaultFileManagedSuccessorTarget) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.JournalPath == b.JournalPath &&
		a.BackendRoot == b.BackendRoot && a.BackendName == b.BackendName &&
		a.OperationID == b.OperationID && a.SuccessorRev == b.SuccessorRev &&
		a.Pin.KeyEpoch == b.Pin.KeyEpoch && a.Pin.ContentSeq == b.Pin.ContentSeq &&
		a.Pin.SealedSHA256 == b.Pin.SealedSHA256 &&
		a.Pin.BackendRevision == b.Pin.BackendRevision &&
		sameVaultFilePolicyCheckpoint(&a.Pin.Checkpoint, &b.Pin.Checkpoint)
}

func cloneVaultFilePolicyCheckpoint(c *vaultfile.PolicyCheckpoint) *vaultfile.PolicyCheckpoint {
	if c == nil {
		return &vaultfile.PolicyCheckpoint{}
	}
	return &vaultfile.PolicyCheckpoint{
		VaultID:            c.VaultID,
		OwnerRootKeyID:     c.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(bytes.Clone(c.OwnerRootPublicKey)),
		PolicySeq:          c.PolicySeq,
		PolicyDigest:       bytes.Clone(c.PolicyDigest),
	}
}

func (t OwnedVaultFileManagedSuccessorTarget) valid() bool {
	return t.JournalPath != "" &&
		validVaultFileGenesisPath(t.BackendRoot) &&
		vaultfilebackend.ValidName(t.BackendName) &&
		validVaultFileManagedDeviceSuccessorPin(t.Pin) &&
		len(t.OperationID) <= vaultfilejournal.MaxOperationIDBytes &&
		len(t.SuccessorRev) <= vaultfilebackend.MaxRevisionSize
}

// vaultFileManagedSuccessorBinding is the immutable read identity of one
// settled managed successor. It retains public selectors, hashes and opaque
// revisions only, never successor bytes, a VUK or account material.
type vaultFileManagedSuccessorBinding struct {
	journalPath string
	backendRoot string
	backendName string

	pin            VaultFileManagedDeviceSuccessorPin
	nextCheckpoint vaultfile.PolicyCheckpoint

	destinationDeviceID string
	destinationAge      string
	destinationSigning  ed25519.PublicKey

	operationID       string
	generation        uint64
	targetDigest      [sha256.Size]byte
	baseHash          [sha256.Size]byte
	successorHash     [sha256.Size]byte
	baseRevision      vaultfilebackend.Revision
	successorRevision vaultfilebackend.Revision
}

func (b *vaultFileManagedSuccessorBinding) clear() {
	if b == nil {
		return
	}
	clearVaultFilePolicyCheckpoint(&b.pin.Checkpoint)
	clearVaultFilePolicyCheckpoint(&b.nextCheckpoint)
	b.destinationSigning = nil
	*b = vaultFileManagedSuccessorBinding{}
}

func managedSuccessorPathError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessorPath, reason)
}

func managedSuccessorConflictError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessorConflict, reason)
}

func managedSuccessorPendingError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessorPending, reason)
}

func managedSuccessorUnknownError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessorUnknown, reason)
}

func managedSuccessorUnconfirmedError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessorUnconfirmed, reason)
}

func managedSuccessorReopenError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessorReopen, reason)
}

func managedSuccessorNoOperationError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessorNoOperation, reason)
}

func openManagedSuccessorJournal(journalPath string) (*vaultfilejournal.Journal, error) {
	if journalPath == "" {
		return nil, managedSuccessorPathError("journal")
	}
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return nil, managedSuccessorPathError("journal")
	}
	return j, nil
}

// managedSuccessorTargetDigest binds the exact established backend identity
// and the exact protected record name into one fixed, non-revealing value.
// Only the digest is persisted or compared; neither the identity bytes nor the
// name appear in an error or receipt.
func managedSuccessorTargetDigest(identity [sha256.Size]byte, name string) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark managed successor target binding v1\x00"))
	_, _ = h.Write(identity[:])
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(name)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(name))
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func managedSuccessorDestination(device VaultFileDevicePublic) (string, ed25519.PublicKey, error) {
	signing, err := hex.DecodeString(device.ContentSigningPublicKey)
	if err != nil || len(signing) != ed25519.PublicKeySize || device.AgeRecipient == "" {
		return "", nil, managedSuccessorReopenError("destination")
	}
	return device.AgeRecipient, signing, nil
}

func vaultFileSameManagedDevice(a, b vaultfile.Device) bool {
	if a.DeviceID != b.DeviceID || a.PrincipalID != b.PrincipalID || a.Label != b.Label ||
		a.AgeEncryptionKey != b.AgeEncryptionKey ||
		a.ContentSigningKey.Alg != b.ContentSigningKey.Alg ||
		!bytes.Equal(a.ContentSigningKey.PublicKey, b.ContentSigningKey.PublicKey) {
		return false
	}
	if (a.PolicySigningKey == nil) != (b.PolicySigningKey == nil) {
		return false
	}
	if a.PolicySigningKey != nil &&
		(a.PolicySigningKey.Alg != b.PolicySigningKey.Alg ||
			!bytes.Equal(a.PolicySigningKey.PublicKey, b.PolicySigningKey.PublicKey)) {
		return false
	}
	return true
}

// vaultFileManagedSuccessorAddedDevice requires the successor to be exactly
// the base authority plus one new ordinary device matching the live destination
// public identity. Every existing device and every member, role and delegation
// is unchanged. Authority is never taken from the candidate roster.
func vaultFileManagedSuccessorAddedDevice(base, next *vaultfile.Policy,
	recipient string, signing ed25519.PublicKey) (vaultfile.Device, bool) {
	if base == nil || next == nil || recipient == "" ||
		len(signing) != ed25519.PublicKeySize ||
		!sameVaultFileManagedDeviceAuthority(base, next) ||
		len(next.Devices) != len(base.Devices)+1 {
		return vaultfile.Device{}, false
	}
	for i := range base.Devices {
		found := 0
		for j := range next.Devices {
			if vaultFileSameManagedDevice(base.Devices[i], next.Devices[j]) {
				found++
			}
		}
		if found != 1 {
			return vaultfile.Device{}, false
		}
	}
	var added *vaultfile.Device
	for i := range next.Devices {
		present := false
		for j := range base.Devices {
			if next.Devices[i].DeviceID == base.Devices[j].DeviceID ||
				vaultFileSameManagedDevice(next.Devices[i], base.Devices[j]) {
				present = true
				break
			}
		}
		if present {
			continue
		}
		if added != nil {
			return vaultfile.Device{}, false
		}
		added = &next.Devices[i]
	}
	if added == nil ||
		added.AgeEncryptionKey != recipient ||
		added.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 ||
		!bytes.Equal(added.ContentSigningKey.PublicKey, signing) ||
		added.PolicySigningKey != nil ||
		!vaultFileWriterPrincipal(base, added.PrincipalID) {
		return vaultfile.Device{}, false
	}
	if id, ok := localVaultFileWriterDevice(next, recipient, signing); !ok || id != added.DeviceID {
		return vaultfile.Device{}, false
	}
	return *added, true
}

// verifyManagedSuccessorFiles authenticates the exact base under the caller pin
// and the exact managed successor against that base. The returned checkpoint is
// derived from the authenticated successor, never from an uncorroborated caller
// or candidate value.
func verifyManagedSuccessorFiles(baseBytes, successorBytes []byte,
	pin VaultFileManagedDeviceSuccessorPin, recipient string,
	signing ed25519.PublicKey) (vaultfile.PolicyCheckpoint, vaultfile.Device, string, error) {
	var empty vaultfile.PolicyCheckpoint
	if len(baseBytes) == 0 || len(successorBytes) == 0 ||
		sha256.Sum256(baseBytes) != pin.SealedSHA256 {
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("base")
	}
	baseFile, err := vaultfile.ParseFile(baseBytes)
	if err != nil || vaultfile.VerifyPolicyCheckpoint(baseFile, &pin.Checkpoint) != nil ||
		baseFile.Header.KeyEpoch != pin.KeyEpoch ||
		baseFile.Header.ContentSeq != pin.ContentSeq ||
		len(baseFile.SignedPolicyProofs) == 0 {
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("base")
	}
	basePolicy := &baseFile.SignedPolicyProofs[len(baseFile.SignedPolicyProofs)-1].Policy
	if basePolicy.PolicySeq != baseFile.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(basePolicy), baseFile.Header.PolicyDigest) {
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("base")
	}

	successorFile, err := vaultfile.ParseFile(successorBytes)
	if err != nil || successorFile.Header.VaultID != pin.Checkpoint.VaultID ||
		successorFile.Header.KeyEpoch != pin.KeyEpoch+1 ||
		successorFile.Header.ContentSeq != pin.ContentSeq+1 ||
		len(successorFile.SignedPolicyProofs) == 0 {
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("successor")
	}
	if err := vaultfile.VerifyManagedTransition(baseBytes, successorBytes, &pin.Checkpoint); err != nil {
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("transition")
	}
	next := vaultfile.PolicyCheckpoint{
		VaultID:            successorFile.Header.VaultID,
		OwnerRootKeyID:     pin.Checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(pin.Checkpoint.OwnerRootPublicKey),
		PolicySeq:          successorFile.Header.PolicySeq,
		PolicyDigest:       bytes.Clone(successorFile.Header.PolicyDigest),
	}
	if err := vaultfile.VerifyPolicyCheckpoint(successorFile, &next); err != nil {
		clearVaultFilePolicyCheckpoint(&next)
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("checkpoint")
	}
	nextPolicy := &successorFile.SignedPolicyProofs[len(successorFile.SignedPolicyProofs)-1].Policy
	if nextPolicy.PolicySeq != successorFile.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(nextPolicy), successorFile.Header.PolicyDigest) {
		clearVaultFilePolicyCheckpoint(&next)
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("checkpoint")
	}
	device, ok := vaultFileManagedSuccessorAddedDevice(basePolicy, nextPolicy, recipient, signing)
	if !ok {
		clearVaultFilePolicyCheckpoint(&next)
		return empty, vaultfile.Device{}, "", managedSuccessorConflictError("device")
	}
	return next, device, successorFile.Header.OpID, nil
}

func readManagedSuccessorBackendExactWith(ctx context.Context,
	backend vaultFileManagedDeviceSuccessorBackend, name string,
	expected []byte, expectedRevision vaultfilebackend.Revision) ([]byte, error) {
	result, err := backend.Read(ctx, name)
	if err != nil {
		clear(result.Bytes)
		return nil, managedSuccessorPathError("target")
	}
	if !bytes.Equal(result.Bytes, expected) || result.Revision != expectedRevision {
		clear(result.Bytes)
		return nil, managedSuccessorConflictError("target revision")
	}
	return result.Bytes, nil
}

// verifyManagedSuccessorTargetIdentity opens the exact local backend once,
// derives its verified stable identity, binds the exact protected name and
// compares that non-revealing digest with the durable operation binding. The
// same opened instance is returned so the caller's subsequent read or CAS uses
// the identity just checked, and a later root replacement is refused by the
// backend's own component checks.
func verifyManagedSuccessorTargetIdentity(target VaultFileManagedDeviceSuccessorTarget,
	want [sha256.Size]byte) (vaultFileManagedDeviceSuccessorBackend, error) {
	backend, err := openVaultFileManagedDeviceSuccessorBackend(target.Root)
	if err != nil {
		return nil, managedSuccessorPathError("backend")
	}
	identity, err := backend.StableIdentity()
	if err != nil {
		_ = backend.Close()
		return nil, managedSuccessorPathError("backend identity")
	}
	if managedSuccessorTargetDigest(identity, target.Name) != want {
		_ = backend.Close()
		return nil, managedSuccessorConflictError("target identity")
	}
	return backend, nil
}

type managedSuccessorJournalKind uint8

const (
	managedSuccessorJournalInvalid managedSuccessorJournalKind = iota
	managedSuccessorJournalPristine
	managedSuccessorJournalPending
	managedSuccessorJournalSettled
)

type managedSuccessorJournalState struct {
	kind     managedSuccessorJournalKind
	state    vaultfilejournal.State
	prepared vaultfilejournal.PreparedProposal
	audit    vaultfilejournal.RebaseAudit
	binding  vaultfilejournal.ManagedSuccessorBinding
}

func (s *managedSuccessorJournalState) clear() {
	if s == nil {
		return
	}
	clear(s.state.BaseBytes)
	clear(s.state.WorkingBytes)
	clear(s.prepared.Proposal.Bytes)
	clear(s.audit.OldState.BaseBytes)
	clear(s.audit.OldState.WorkingBytes)
	clear(s.audit.RemoteBase)
	clear(s.audit.Proposal.Bytes)
	*s = managedSuccessorJournalState{}
}

func sameManagedSuccessorProposal(a, b vaultfilejournal.Proposal) bool {
	return a.Generation == b.Generation && a.OperationID == b.OperationID &&
		a.ExpectedRevision == b.ExpectedRevision && bytes.Equal(a.Bytes, b.Bytes)
}

// classifyManagedSuccessorJournal reads only the dedicated managed journal. It
// distinguishes the one pristine generation-zero state, one exact prepared
// generation, and one exact settled generation. Any other shape is a conflict.
func classifyManagedSuccessorJournal(j *vaultfilejournal.Journal,
	pin VaultFileManagedDeviceSuccessorPin) (managedSuccessorJournalState, error) {
	var out managedSuccessorJournalState
	state, err := j.LoadState()
	if err != nil {
		return out, managedSuccessorConflictError("state")
	}
	out.state = state
	prepared, preparedErr := j.LoadPrepared()
	switch {
	case preparedErr == nil:
		out.prepared = prepared
	case errors.Is(preparedErr, vaultfilejournal.ErrEmpty):
	default:
		out.clear()
		return managedSuccessorJournalState{}, managedSuccessorConflictError("prepared")
	}
	audit, auditErr := j.LoadRebaseAudit(state.Generation)
	switch {
	case auditErr == nil:
		out.audit = audit
	case errors.Is(auditErr, vaultfilejournal.ErrEmpty):
	default:
		out.clear()
		return managedSuccessorJournalState{}, managedSuccessorConflictError("audit")
	}
	binding, bindingErr := j.LoadManagedSuccessorBinding()
	switch {
	case bindingErr == nil:
		out.binding = binding
	case errors.Is(bindingErr, vaultfilejournal.ErrEmpty):
	default:
		out.clear()
		return managedSuccessorJournalState{}, managedSuccessorConflictError("binding")
	}

	baseMatchesPin := len(state.BaseBytes) > 0 &&
		sha256.Sum256(state.BaseBytes) == pin.SealedSHA256 &&
		state.RemoteRevision == pin.BackendRevision

	switch {
	case state.Generation == 0:
		if !baseMatchesPin || !bytes.Equal(state.BaseBytes, state.WorkingBytes) ||
			len(state.BaseBytes) == 0 || len(state.WorkingBytes) == 0 ||
			out.prepared.Proposal.OperationID != "" || out.audit.NewGeneration != 0 ||
			bindingErr == nil {
			out.clear()
			return managedSuccessorJournalState{}, managedSuccessorConflictError("pristine state")
		}
		out.kind = managedSuccessorJournalPristine
		return out, nil

	case state.Generation == 1 && out.audit.NewGeneration == 1 &&
		out.audit.OldState.Generation == 0 &&
		bytes.Equal(out.audit.OldState.BaseBytes, out.audit.OldState.WorkingBytes) &&
		bytes.Equal(out.audit.RemoteBase, out.audit.OldState.BaseBytes) &&
		out.audit.RemoteRevision == out.audit.OldState.RemoteRevision &&
		out.audit.RemoteRevision == pin.BackendRevision &&
		sha256.Sum256(out.audit.OldState.BaseBytes) == pin.SealedSHA256 &&
		out.audit.Proposal.ExpectedRevision == pin.BackendRevision &&
		bindingErr == nil && out.binding.Generation == state.Generation &&
		out.binding.OperationID == out.audit.Proposal.OperationID:
		if preparedErr == nil {
			if out.prepared.WorkingGeneration != state.Generation ||
				out.prepared.Proposal.Generation != state.Generation ||
				out.prepared.Proposal.ExpectedRevision != state.RemoteRevision ||
				!bytes.Equal(out.prepared.Proposal.Bytes, state.WorkingBytes) ||
				!sameManagedSuccessorProposal(out.prepared.Proposal, out.audit.Proposal) ||
				!baseMatchesPin {
				out.clear()
				return managedSuccessorJournalState{}, managedSuccessorConflictError("pending state")
			}
			out.kind = managedSuccessorJournalPending
			return out, nil
		}
		if !baseMatchesPin &&
			sha256.Sum256(out.audit.OldState.BaseBytes) == pin.SealedSHA256 {
			// The settled state has advanced to the successor; the original
			// base remains in the audit record. Its revision must no longer be
			// the pinned base revision.
			baseMatchesPin = true
		}
		if !bytes.Equal(state.BaseBytes, state.WorkingBytes) ||
			!bytes.Equal(state.BaseBytes, out.audit.Proposal.Bytes) ||
			state.RemoteRevision == out.audit.OldState.RemoteRevision ||
			!baseMatchesPin ||
			out.prepared.Proposal.OperationID != "" {
			out.clear()
			return managedSuccessorJournalState{}, managedSuccessorConflictError("settled state")
		}
		out.kind = managedSuccessorJournalSettled
		return out, nil
	}
	out.clear()
	return managedSuccessorJournalState{}, managedSuccessorConflictError("journal shape")
}

func pendingManagedSuccessorFromJournal(js *managedSuccessorJournalState,
	pin VaultFileManagedDeviceSuccessorPin, recipient string,
	signing ed25519.PublicKey) (vaultfile.PolicyCheckpoint, vaultfile.Device, string, error) {
	next, device, opID, err := verifyManagedSuccessorFiles(js.state.BaseBytes,
		js.prepared.Proposal.Bytes, pin, recipient, signing)
	if err != nil {
		return vaultfile.PolicyCheckpoint{}, vaultfile.Device{}, "", err
	}
	if opID != js.prepared.Proposal.OperationID ||
		js.audit.Proposal.OperationID != js.prepared.Proposal.OperationID {
		clearVaultFilePolicyCheckpoint(&next)
		return vaultfile.PolicyCheckpoint{}, vaultfile.Device{}, "", managedSuccessorConflictError("operation")
	}
	return next, device, opID, nil
}

func settledManagedSuccessorBinding(js *managedSuccessorJournalState,
	target OwnedVaultFileManagedSuccessorTarget, recipient string,
	signing ed25519.PublicKey) (*vaultFileManagedSuccessorBinding, error) {
	if js.kind != managedSuccessorJournalSettled {
		return nil, managedSuccessorReopenError("settled record")
	}
	next, device, opID, err := verifyManagedSuccessorFiles(js.audit.OldState.BaseBytes,
		js.state.BaseBytes, target.Pin, recipient, signing)
	if err != nil {
		return nil, managedSuccessorReopenError("settled transition")
	}
	if opID != js.audit.Proposal.OperationID ||
		target.OperationID != "" && target.OperationID != opID ||
		target.SuccessorRev != "" && target.SuccessorRev != js.state.RemoteRevision {
		clearVaultFilePolicyCheckpoint(&next)
		return nil, managedSuccessorReopenError("settled operation")
	}
	binding := &vaultFileManagedSuccessorBinding{
		journalPath:         target.JournalPath,
		backendRoot:         target.BackendRoot,
		backendName:         target.BackendName,
		pin:                 cloneVaultFileManagedDeviceSuccessorPin(target.Pin),
		nextCheckpoint:      next,
		destinationDeviceID: device.DeviceID,
		destinationAge:      recipient,
		destinationSigning:  ed25519.PublicKey(bytes.Clone(signing)),
		operationID:         opID,
		generation:          js.state.Generation,
		targetDigest:        js.binding.TargetDigest,
		baseHash:            sha256.Sum256(js.audit.OldState.BaseBytes),
		successorHash:       sha256.Sum256(js.state.BaseBytes),
		baseRevision:        js.audit.OldState.RemoteRevision,
		successorRevision:   js.state.RemoteRevision,
	}
	return binding, nil
}

func loadSettledManagedSuccessor(ctx context.Context,
	target OwnedVaultFileManagedSuccessorTarget,
	recipient string, signing ed25519.PublicKey) (*vaultFileManagedSuccessorBinding, []byte, error) {
	if !target.valid() {
		return nil, nil, managedSuccessorPathError("target")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	j, err := openManagedSuccessorJournal(target.JournalPath)
	if err != nil {
		return nil, nil, err
	}
	js, classifyErr := classifyManagedSuccessorJournal(j, target.Pin)
	closeErr := j.Close()
	defer js.clear()
	if classifyErr != nil {
		return nil, nil, classifyErr
	}
	if closeErr != nil {
		return nil, nil, managedSuccessorPathError("journal close")
	}
	if js.kind != managedSuccessorJournalSettled {
		return nil, nil, managedSuccessorReopenError("not settled")
	}
	binding, err := settledManagedSuccessorBinding(&js, target, recipient, signing)
	if err != nil {
		return nil, nil, err
	}
	backend, err := verifyManagedSuccessorTargetIdentity(VaultFileManagedDeviceSuccessorTarget{
		Root: target.BackendRoot, Name: target.BackendName,
	}, js.binding.TargetDigest)
	if err != nil {
		binding.clear()
		return nil, nil, err
	}
	successor, readErr := readManagedSuccessorBackendExactWith(ctx, backend, target.BackendName,
		js.state.BaseBytes, js.state.RemoteRevision)
	backendCloseErr := backend.Close()
	if readErr != nil {
		binding.clear()
		return nil, nil, readErr
	}
	if backendCloseErr != nil {
		clear(successor)
		binding.clear()
		return nil, nil, managedSuccessorPathError("backend close")
	}
	return binding, successor, nil
}

// ownedVaultFileManagedSuccessorSelector builds the internal typed selector for
// legacy single-open callers, which supply no expected settled operation or
// revision. Batch callers pass their fully populated selector directly.
func ownedVaultFileManagedSuccessorSelector(journalPath string,
	target VaultFileManagedDeviceSuccessorTarget,
	pin VaultFileManagedDeviceSuccessorPin) OwnedVaultFileManagedSuccessorTarget {
	return OwnedVaultFileManagedSuccessorTarget{
		JournalPath: journalPath, BackendRoot: target.Root, BackendName: target.Name, Pin: pin,
	}
}

// verifyManagedSuccessorBinding re-reads the exact settled record and named
// backend object, then returns the fresh acknowledged successor bytes. It never
// returns a partial item view and never accepts a later managed head.
func verifyManagedSuccessorBinding(binding *vaultFileManagedSuccessorBinding) ([]byte, error) {
	if binding == nil || binding.journalPath == "" {
		return nil, ErrVaultFileBaselineVerification
	}
	j, err := openManagedSuccessorJournal(binding.journalPath)
	if err != nil {
		return nil, err
	}
	js, classifyErr := classifyManagedSuccessorJournal(j, binding.pin)
	closeErr := j.Close()
	defer js.clear()
	if classifyErr != nil {
		return nil, classifyErr
	}
	if closeErr != nil {
		return nil, managedSuccessorPathError("journal close")
	}
	if js.kind != managedSuccessorJournalSettled {
		return nil, managedSuccessorReopenError("not settled")
	}
	owned := OwnedVaultFileManagedSuccessorTarget{
		JournalPath: binding.journalPath, BackendRoot: binding.backendRoot,
		BackendName: binding.backendName, Pin: binding.pin,
	}
	fresh, err := settledManagedSuccessorBinding(&js, owned, binding.destinationAge, binding.destinationSigning)
	if err != nil {
		return nil, err
	}
	defer fresh.clear()
	if fresh.operationID != binding.operationID ||
		fresh.generation != binding.generation ||
		fresh.baseHash != binding.baseHash ||
		fresh.successorHash != binding.successorHash ||
		fresh.baseRevision != binding.baseRevision ||
		fresh.successorRevision != binding.successorRevision ||
		fresh.destinationDeviceID != binding.destinationDeviceID ||
		fresh.targetDigest != binding.targetDigest ||
		!sameVaultFileBackupCustodyCheckpoint(fresh.nextCheckpoint, binding.nextCheckpoint) {
		return nil, ErrVaultFileBaselineJournal
	}
	target := VaultFileManagedDeviceSuccessorTarget{
		Root: binding.backendRoot, Name: binding.backendName,
	}
	backend, err := verifyManagedSuccessorTargetIdentity(target, js.binding.TargetDigest)
	if err != nil {
		return nil, err
	}
	successor, readErr := readManagedSuccessorBackendExactWith(context.Background(), backend, target.Name,
		js.state.BaseBytes, js.state.RemoteRevision)
	backendCloseErr := backend.Close()
	if readErr != nil {
		return nil, readErr
	}
	if backendCloseErr != nil {
		clear(successor)
		return nil, managedSuccessorPathError("backend close")
	}
	return successor, nil
}

func receiptFromManagedSuccessorBinding(binding *vaultFileManagedSuccessorBinding) VaultFileManagedDeviceSuccessorReceipt {
	return VaultFileManagedDeviceSuccessorReceipt{
		VaultID:             binding.pin.Checkpoint.VaultID,
		OperationID:         binding.operationID,
		DestinationDeviceID: binding.destinationDeviceID,
		BasePolicySeq:       binding.pin.Checkpoint.PolicySeq,
		NextPolicySeq:       binding.nextCheckpoint.PolicySeq,
		BaseKeyEpoch:        binding.pin.KeyEpoch,
		NextKeyEpoch:        binding.pin.KeyEpoch + 1,
		BaseContentSeq:      binding.pin.ContentSeq,
		NextContentSeq:      binding.pin.ContentSeq + 1,
		BaseSHA256:          binding.baseHash,
		SuccessorSHA256:     binding.successorHash,
		BaseRevision:        binding.baseRevision,
		SuccessorRevision:   binding.successorRevision,
		Next:                *cloneVaultFilePolicyCheckpoint(&binding.nextCheckpoint),
		Signed:              true,
		LocallyObserved:     true,
	}
}

func managedSuccessorSessionVerifier(s *Session,
	verifier vaultfilepublish.ProposalVerifier) vaultfilepublish.ProposalVerifier {
	return func(ctx context.Context, base []byte, baseRevision vaultfilebackend.Revision,
		proposal vaultfilejournal.Proposal) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.lockRequested.Load() {
			return ErrSessionLocked
		}
		if err := s.active(false); err != nil {
			return err
		}
		if err := s.requireFreshFullFactor(); err != nil {
			return err
		}
		return verifier(ctx, base, baseRevision, proposal)
	}
}

func managedSuccessorPullVerifier(base []byte, baseRevision vaultfilebackend.Revision,
	draft []byte) vaultfilepublish.PullVerifier {
	return func(_ context.Context, data []byte, revision vaultfilebackend.Revision) error {
		if bytes.Equal(data, base) && revision == baseRevision {
			return nil
		}
		// Exact successor bytes at any genuinely new opaque revision are the
		// only other acceptable observation. The same bytes at the original
		// revision, or the original bytes at a changed revision, are refused.
		if bytes.Equal(data, draft) && revision != "" && revision != baseRevision {
			return nil
		}
		return managedSuccessorConflictError("observation")
	}
}

func managedSuccessorPublishError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrSessionLocked), errors.Is(err, ErrVaultFileFullFactorRequired):
		return err
	case errors.Is(err, vaultfilebackend.ErrNotFound),
		errors.Is(err, vaultfilebackend.ErrUnsupported),
		errors.Is(err, vaultfilepublish.ErrBackendResult):
		return managedSuccessorPathError("backend")
	case errors.Is(err, vaultfilebackend.ErrUnknown),
		errors.Is(err, vaultfilepublish.ErrUnknownWrite),
		errors.Is(err, vaultfilepublish.ErrUnknownReview):
		return managedSuccessorUnknownError("write")
	case errors.Is(err, vaultfilebackend.ErrConflict),
		errors.Is(err, vaultfilepublish.ErrConflict),
		errors.Is(err, vaultfilepublish.ErrStaleBase),
		errors.Is(err, vaultfilepublish.ErrVerification),
		errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict):
		return managedSuccessorConflictError("publish")
	case errors.Is(err, vaultfilejournal.ErrPreparedExists),
		errors.Is(err, vaultfilejournal.ErrPreparedMismatch),
		errors.Is(err, vaultfilejournal.ErrPendingRecords):
		return managedSuccessorPendingError("journal")
	default:
		return managedSuccessorUnknownError("publish")
	}
}

// PublishVaultFileManagedDeviceSuccessor is the one explicit local publish
// checkpoint for a recovered destination account's newly signed device
// successor.
//
// The caller supplies only an existing dedicated journal, the exact existing
// LOCAL backend target and the independently trusted original base pin. The
// method, under one fresh full-factor Session.mu critical section:
//
//   - reauthenticates the active destination owner store and derives the
//     ordinary new device from that same live account;
//   - prepares the draft itself through the reviewed recovered-owner path and
//     refuses any caller-supplied draft;
//   - requires the journal to be the one pristine generation-zero state whose
//     base bytes and opaque revision are exactly the pin;
//   - re-reads the target non-creating and requires exact bytes and revision;
//   - atomically writes the exact prepared operation and its immutable rebase
//     audit before any backend mutation;
//   - performs exactly one no-create ReplaceIfVersion through the existing
//     coordinator and resolves it only by one verified readback and Ack.
//
// A missing/changed target (including unchanged bytes at a changed opaque
// revision), a stale journal, a wrong owner or a wrong pin is refused before
// any journal or backend mutation. A prepared operation left by an unknown
// outcome is preserved and reported as pending/unknown; only the explicit
// Resume entry point may finish that same recorded generation and operation.
// This method never creates the backend name, retries implicitly, re-signs,
// reactivates an invitation or modifies the original backup or source journals.
func (s *Session) PublishVaultFileManagedDeviceSuccessor(ctx context.Context, journalPath string,
	target VaultFileManagedDeviceSuccessorTarget,
	expected VaultFileManagedDeviceSuccessorPin) (receipt VaultFileManagedDeviceSuccessorReceipt, retErr error) {
	if s == nil {
		return receipt, ErrSessionLocked
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if journalPath == "" || !target.valid() || !validVaultFileManagedDeviceSuccessorPin(expected) {
		return receipt, managedSuccessorConflictError("request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return receipt, err
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return receipt, ctx.Err()
	}

	// Reauthenticate the current destination owner and ordinary device before
	// the journal or backend is observed.
	owner, destination, err := s.loadVaultFileManagedDeviceSuccessorOwner(expected.Checkpoint)
	if err != nil {
		if errors.Is(err, ErrSessionLocked) {
			return receipt, ErrSessionLocked
		}
		return receipt, managedSuccessorConflictError("owner")
	}
	clearVaultFileOwners([]vaultFileOwnerRecord{owner})
	recipient, signing, err := managedSuccessorDestination(destination)
	if err != nil {
		return receipt, managedSuccessorReopenError("destination")
	}

	j, err := openManagedSuccessorJournal(journalPath)
	if err != nil {
		return receipt, err
	}
	jClosed := false
	defer func() {
		if !jClosed {
			_ = j.Close()
		}
	}()
	js, err := classifyManagedSuccessorJournal(j, expected)
	if err != nil {
		return receipt, err
	}
	defer js.clear()
	switch js.kind {
	case managedSuccessorJournalPending:
		return receipt, managedSuccessorPendingError("resume required")
	case managedSuccessorJournalSettled:
		closeErr := j.Close()
		jClosed = true
		if closeErr != nil {
			return receipt, managedSuccessorUnconfirmedError("close")
		}
		binding, successor, err := loadSettledManagedSuccessor(ctx,
			ownedVaultFileManagedSuccessorSelector(journalPath, target, expected), recipient, signing)
		if err != nil {
			return receipt, err
		}
		clear(successor)
		defer binding.clear()
		if err := s.active(false); err != nil {
			return receipt, managedSuccessorUnconfirmedError("session")
		}
		if s.requireFreshFullFactor() != nil {
			return receipt, managedSuccessorUnconfirmedError("freshness")
		}
		if err := ctx.Err(); err != nil {
			return receipt, managedSuccessorUnconfirmedError("context")
		}
		return receiptFromManagedSuccessorBinding(binding), nil
	case managedSuccessorJournalPristine:
	default:
		return receipt, managedSuccessorConflictError("journal")
	}

	// The exact opened backend instance supplies the stable identity used for
	// the durable binding, the base observation and the one CAS. Its own
	// component checks refuse a root replaced after it was established.
	backend, err := openVaultFileManagedDeviceSuccessorBackend(target.Root)
	if err != nil {
		return receipt, managedSuccessorPathError("backend")
	}
	backendClosed := false
	defer func() {
		if !backendClosed {
			_ = backend.Close()
		}
	}()
	identity, err := backend.StableIdentity()
	if err != nil {
		return receipt, managedSuccessorPathError("backend identity")
	}
	targetDigest := managedSuccessorTargetDigest(identity, target.Name)
	pulledBase, err := vaultfilepublish.ReadPulled(ctx, backend, target.Name,
		func(_ context.Context, data []byte, revision vaultfilebackend.Revision) error {
			if revision != expected.BackendRevision ||
				sha256.Sum256(data) != expected.SealedSHA256 {
				return managedSuccessorConflictError("base observation")
			}
			return nil
		})
	if err != nil {
		if ctx.Err() != nil {
			return receipt, ctx.Err()
		}
		if errors.Is(err, ErrVaultFileManagedDeviceSuccessorConflict) ||
			errors.Is(err, vaultfilepublish.ErrVerification) {
			return receipt, managedSuccessorConflictError("base observation")
		}
		return receipt, managedSuccessorPathError("target")
	}
	baseBytes := pulledBase.Bytes()
	defer clear(baseBytes)
	if !bytes.Equal(js.state.BaseBytes, baseBytes) ||
		js.state.RemoteRevision != expected.BackendRevision {
		return receipt, managedSuccessorConflictError("target pin")
	}

	draft, err := s.prepareVaultFileManagedDeviceSuccessorLocked(ctx, target, expected)
	if err != nil {
		switch {
		case errors.Is(err, ErrSessionLocked),
			errors.Is(err, ErrVaultFileFullFactorRequired),
			errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return receipt, err
		default:
			// Preparation re-observed the same target. Any disagreement is a
			// conflict or a lost path, never an implicit new operation.
			return receipt, managedSuccessorConflictError("prepare")
		}
	}
	defer draft.Clear()
	draftFile, err := vaultfile.ParseFile(draft.Draft)
	if err != nil || draftFile.Header.OpID == "" ||
		!sameVaultFileBackupCustodyCheckpoint(draft.Base.Checkpoint, expected.Checkpoint) ||
		draft.Base.KeyEpoch != expected.KeyEpoch ||
		draft.Base.ContentSeq != expected.ContentSeq ||
		draft.Base.SealedSHA256 != expected.SealedSHA256 ||
		draft.Base.BackendRevision != expected.BackendRevision {
		return receipt, managedSuccessorConflictError("draft")
	}

	if err := s.active(false); err != nil {
		return receipt, err
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}

	proposal := vaultfilejournal.Proposal{
		Generation:       js.state.Generation + 1,
		OperationID:      draftFile.Header.OpID,
		ExpectedRevision: expected.BackendRevision,
		Bytes:            bytes.Clone(draft.Draft),
	}
	defer clear(proposal.Bytes)
	operationBinding := vaultfilejournal.ManagedSuccessorBinding{
		Generation:   js.state.Generation + 1,
		OperationID:  proposal.OperationID,
		TargetDigest: targetDigest,
	}
	if err := s.active(false); err != nil {
		return receipt, err
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	if err := j.RebaseAndPrepareManagedSuccessor(js.state, js.state.BaseBytes,
		js.state.RemoteRevision, proposal, operationBinding); err != nil {
		switch {
		case errors.Is(err, vaultfilejournal.ErrStateMismatch),
			errors.Is(err, vaultfilejournal.ErrPendingRecords),
			errors.Is(err, vaultfilejournal.ErrAuditCollision):
			return receipt, managedSuccessorConflictError("journal prepare")
		default:
			return receipt, managedSuccessorUnknownError("journal prepare")
		}
	}
	if vaultFileManagedDeviceSuccessorAfterPrepareForTest != nil {
		vaultFileManagedDeviceSuccessorAfterPrepareForTest()
	}

	verifier, err := vaultfilesync.NewManagedTransitionProposalVerifier(&expected.Checkpoint)
	if err != nil {
		return receipt, managedSuccessorConflictError("verifier")
	}
	verifier = managedSuccessorSessionVerifier(s, verifier)
	pullVerifier := managedSuccessorPullVerifier(baseBytes, expected.BackendRevision, draft.Draft)
	coordinator, err := vaultfilepublish.NewCoordinator(backend, j, target.Name, verifier)
	if err != nil {
		return receipt, managedSuccessorConflictError("coordinator")
	}
	writeErr := coordinator.PrepareAndPublish(ctx, pulledBase, proposal, pullVerifier)
	backendCloseErr := backend.Close()
	backendClosed = true
	journalCloseErr := j.Close()
	jClosed = true
	if writeErr != nil {
		return receipt, managedSuccessorPublishError(writeErr)
	}
	if backendCloseErr != nil || journalCloseErr != nil {
		return receipt, managedSuccessorUnconfirmedError("close")
	}
	if err := s.active(false); err != nil {
		return receipt, managedSuccessorUnconfirmedError("session")
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, managedSuccessorUnconfirmedError("freshness")
	}
	if err := ctx.Err(); err != nil {
		return receipt, managedSuccessorUnconfirmedError("context")
	}

	binding, successor, err := loadSettledManagedSuccessor(ctx,
		ownedVaultFileManagedSuccessorSelector(journalPath, target, expected), recipient, signing)
	if err != nil {
		return receipt, managedSuccessorUnconfirmedError("readback")
	}
	clear(successor)
	defer binding.clear()
	if err := s.active(false); err != nil {
		return receipt, managedSuccessorUnconfirmedError("session")
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, managedSuccessorUnconfirmedError("freshness")
	}
	if err := ctx.Err(); err != nil {
		return receipt, managedSuccessorUnconfirmedError("context")
	}
	return receiptFromManagedSuccessorBinding(binding), nil
}

// ResumeVaultFileManagedDeviceSuccessor explicitly finishes exactly the
// durable prepared generation already present in the dedicated journal.
//
// It reauthenticates the active destination owner and ordinary device, verifies
// the exact prepared operation and immutable audit against the caller's base pin
// and the live destination, then uses the existing coordinator's ResumePrepared
// rules. If the current target is the exact original base at its original
// revision, the same operation bytes and operation ID are retried once. If it is
// the exact prepared successor at a genuinely new revision, it is verified and
// acknowledged. Any other target, including the original bytes at a changed
// revision, is a hard refusal that preserves the prepared record.
//
// A settled record is verified and returned as an idempotent receipt without a
// write. A pristine journal has no durable operation and is refused.
func (s *Session) ResumeVaultFileManagedDeviceSuccessor(ctx context.Context, journalPath string,
	target VaultFileManagedDeviceSuccessorTarget,
	expected VaultFileManagedDeviceSuccessorPin) (receipt VaultFileManagedDeviceSuccessorReceipt, retErr error) {
	if s == nil {
		return receipt, ErrSessionLocked
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if journalPath == "" || !target.valid() || !validVaultFileManagedDeviceSuccessorPin(expected) {
		return receipt, managedSuccessorConflictError("request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return receipt, err
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return receipt, ctx.Err()
	}
	owner, destination, err := s.loadVaultFileManagedDeviceSuccessorOwner(expected.Checkpoint)
	if err != nil {
		if errors.Is(err, ErrSessionLocked) {
			return receipt, ErrSessionLocked
		}
		return receipt, managedSuccessorConflictError("owner")
	}
	clearVaultFileOwners([]vaultFileOwnerRecord{owner})
	recipient, signing, err := managedSuccessorDestination(destination)
	if err != nil {
		return receipt, managedSuccessorReopenError("destination")
	}

	j, err := openManagedSuccessorJournal(journalPath)
	if err != nil {
		return receipt, err
	}
	js, classifyErr := classifyManagedSuccessorJournal(j, expected)
	if classifyErr != nil {
		_ = j.Close()
		return receipt, classifyErr
	}
	defer js.clear()
	switch js.kind {
	case managedSuccessorJournalPristine:
		_ = j.Close()
		return receipt, managedSuccessorNoOperationError("pristine")
	case managedSuccessorJournalSettled:
		if err := j.Close(); err != nil {
			return receipt, managedSuccessorUnconfirmedError("close")
		}
		binding, successor, err := loadSettledManagedSuccessor(ctx,
			ownedVaultFileManagedSuccessorSelector(journalPath, target, expected), recipient, signing)
		if err != nil {
			return receipt, err
		}
		clear(successor)
		defer binding.clear()
		if err := s.active(false); err != nil {
			return receipt, managedSuccessorUnconfirmedError("session")
		}
		if s.requireFreshFullFactor() != nil {
			return receipt, managedSuccessorUnconfirmedError("freshness")
		}
		if err := ctx.Err(); err != nil {
			return receipt, managedSuccessorUnconfirmedError("context")
		}
		return receiptFromManagedSuccessorBinding(binding), nil
	case managedSuccessorJournalPending:
	default:
		_ = j.Close()
		return receipt, managedSuccessorConflictError("journal")
	}

	next, _, operationID, err := pendingManagedSuccessorFromJournal(&js, expected, recipient, signing)
	if err != nil {
		_ = j.Close()
		return receipt, err
	}
	clearVaultFilePolicyCheckpoint(&next)
	if operationID != js.prepared.Proposal.OperationID {
		_ = j.Close()
		return receipt, managedSuccessorConflictError("operation")
	}
	if !bytes.Equal(js.prepared.Proposal.Bytes, js.state.WorkingBytes) ||
		js.prepared.Proposal.ExpectedRevision != expected.BackendRevision {
		_ = j.Close()
		return receipt, managedSuccessorConflictError("prepared pin")
	}

	verifier, err := vaultfilesync.NewManagedTransitionProposalVerifier(&expected.Checkpoint)
	if err != nil {
		_ = j.Close()
		return receipt, managedSuccessorConflictError("verifier")
	}
	verifier = managedSuccessorSessionVerifier(s, verifier)
	pullVerifier := managedSuccessorPullVerifier(js.state.BaseBytes, expected.BackendRevision,
		js.prepared.Proposal.Bytes)
	backend, err := openVaultFileManagedDeviceSuccessorBackend(target.Root)
	if err != nil {
		_ = j.Close()
		return receipt, managedSuccessorPathError("backend")
	}
	identity, err := backend.StableIdentity()
	if err != nil {
		_ = backend.Close()
		_ = j.Close()
		return receipt, managedSuccessorPathError("backend identity")
	}
	if managedSuccessorTargetDigest(identity, target.Name) != js.binding.TargetDigest {
		_ = backend.Close()
		_ = j.Close()
		// The durable prepared operation stays exactly as recorded. A copied
		// root or a different exact name with matching bytes and revision is
		// never treated as the original target.
		return receipt, managedSuccessorConflictError("target identity")
	}
	currentPulled, err := vaultfilepublish.ReadPulled(ctx, backend, target.Name, pullVerifier)
	if err != nil {
		_ = backend.Close()
		_ = j.Close()
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return receipt, err
		case errors.Is(err, vaultfilebackend.ErrNotFound), errors.Is(err, vaultfilebackend.ErrUnsupported):
			return receipt, managedSuccessorPathError("target")
		default:
			// The durable prepared record is preserved. A changed or third
			// version is not an implicit retry target.
			return receipt, managedSuccessorUnknownError("observation")
		}
	}
	coordinator, err := vaultfilepublish.NewCoordinator(backend, j, target.Name, verifier)
	if err != nil {
		_ = backend.Close()
		_ = j.Close()
		return receipt, managedSuccessorConflictError("coordinator")
	}
	writeErr := coordinator.ResumePrepared(ctx, currentPulled, pullVerifier)
	backendCloseErr := backend.Close()
	journalCloseErr := j.Close()
	if writeErr != nil {
		return receipt, managedSuccessorPublishError(writeErr)
	}
	if backendCloseErr != nil || journalCloseErr != nil {
		return receipt, managedSuccessorUnconfirmedError("close")
	}
	if err := s.active(false); err != nil {
		return receipt, managedSuccessorUnconfirmedError("session")
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, managedSuccessorUnconfirmedError("freshness")
	}
	if err := ctx.Err(); err != nil {
		return receipt, managedSuccessorUnconfirmedError("context")
	}
	binding, successor, err := loadSettledManagedSuccessor(ctx,
		ownedVaultFileManagedSuccessorSelector(journalPath, target, expected), recipient, signing)
	if err != nil {
		return receipt, managedSuccessorUnconfirmedError("readback")
	}
	clear(successor)
	defer binding.clear()
	if err := s.active(false); err != nil {
		return receipt, managedSuccessorUnconfirmedError("session")
	}
	if s.requireFreshFullFactor() != nil {
		return receipt, managedSuccessorUnconfirmedError("freshness")
	}
	if err := ctx.Err(); err != nil {
		return receipt, managedSuccessorUnconfirmedError("context")
	}
	return receiptFromManagedSuccessorBinding(binding), nil
}

// OpenVaultFileManagedDeviceSuccessorVaultFileChild is the dedicated explicit
// managed-successor reopen. It proves the explicitly supplied full factors and
// the current owner custody, reads the exact settled managed record and its
// named backend object, requires the ordinary account device to be the one new
// device in the authenticated successor, and opens only that successor under the
// derived next checkpoint as a read-only child. The generic and first-successor
// opens are unchanged; no anchor check is relaxed.
func (s *Session) OpenVaultFileManagedDeviceSuccessorVaultFileChild(journalPath string,
	target VaultFileManagedDeviceSuccessorTarget,
	expected VaultFileManagedDeviceSuccessorPin, password, key []byte,
	options VaultFileChildOptions) (VaultFileChildToken, []VaultFileBaselineItem, error) {
	if s == nil {
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	if journalPath == "" || !target.valid() || !validVaultFileManagedDeviceSuccessorPin(expected) {
		return VaultFileChildToken{}, nil, managedSuccessorReopenError("request")
	}
	owned := OwnedVaultFileManagedSuccessorTarget{
		JournalPath: journalPath, BackendRoot: target.Root, BackendName: target.Name,
		Pin: cloneVaultFileManagedDeviceSuccessorPin(expected),
	}
	defer clearVaultFilePolicyCheckpoint(&owned.Pin.Checkpoint)
	return s.openVaultFileChild(journalPath, &expected.Checkpoint, password, key, options,
		vaultFileChildOpenMode{owned: true, managed: &owned})
}
