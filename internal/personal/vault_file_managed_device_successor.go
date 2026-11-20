package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"

	"filippo.io/age"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// ErrVaultFileManagedDeviceSuccessor reports a refused managed-device
// preparation. It is deliberately distinct from ErrVaultFileOwnership so a
// caller can tell "the restored owner record is absent or wrong" from "the
// caller-pinned target/version was not the exact current base".
var ErrVaultFileManagedDeviceSuccessor = errors.New("vault-file managed device successor unavailable")

// vaultFileManagedDeviceSuccessorBeforeReleaseForTest is a private
// nil-by-default fault point. It runs after the successor has been sealed and
// verified but before the final cancellation/lock/freshness check, so tests can
// prove that a late lock or cancellation never returns the prepared draft.
// Production leaves it nil.
var vaultFileManagedDeviceSuccessorBeforeReleaseForTest func()

// VaultFileManagedDeviceSuccessorTarget is the caller's independently trusted
// locator for the existing LOCAL backend object that must already contain the
// exact current base. It is the same narrow Root/Name locator used by the
// authenticated custody restore path; it is never derived from the draft, the
// owner artifact or the destination account.
type VaultFileManagedDeviceSuccessorTarget = VaultFileBackupCustodyRestoreTarget

// VaultFileManagedDeviceSuccessorPin is the caller's independent pin for one
// existing base. Checkpoint must be the exact current policy, KeyEpoch and
// ContentSeq the exact current header values, SealedSHA256 the exact complete
// file digest and BackendRevision the backend's opaque current revision. None
// of these values may be inferred from the candidate draft.
type VaultFileManagedDeviceSuccessorPin struct {
	Checkpoint      vaultfile.PolicyCheckpoint
	KeyEpoch        uint64
	ContentSeq      uint64
	SealedSHA256    [sha256.Size]byte
	BackendRevision vaultfilebackend.Revision
}

// VaultFileManagedDeviceSuccessorPolicy is the exact public policy/version
// state of the sealed successor. It is public metadata only; it grants no
// authority after the call.
type VaultFileManagedDeviceSuccessorPolicy struct {
	Checkpoint vaultfile.PolicyCheckpoint
	KeyEpoch   uint64
	ContentSeq uint64
}

// VaultFileManagedDeviceSuccessor is one bounded, already sealed managed
// successor draft plus the exact base pin a later normal compare-and-swap must
// use. Draft is the complete encrypted file. Base is the independently
// re-verified current target, not a caller echo. Next describes the draft's
// policy and version so the caller can journal it after its own successful CAS.
// No VUK, CEK, seed, private device key or decrypted item is returned.
type VaultFileManagedDeviceSuccessor struct {
	Draft []byte
	Base  VaultFileManagedDeviceSuccessorPin
	Next  VaultFileManagedDeviceSuccessorPolicy
}

// Clear releases every retained byte slice. It is idempotent and safe on nil.
func (s *VaultFileManagedDeviceSuccessor) Clear() {
	if s == nil {
		return
	}
	clear(s.Draft)
	clearVaultFilePolicyCheckpoint(&s.Base.Checkpoint)
	clearVaultFilePolicyCheckpoint(&s.Next.Checkpoint)
	*s = VaultFileManagedDeviceSuccessor{}
}

func validVaultFileManagedDeviceSuccessorPin(pin VaultFileManagedDeviceSuccessorPin) bool {
	return validVaultFileBackupCustodyCheckpoint(pin.Checkpoint) &&
		pin.KeyEpoch != 0 &&
		len(pin.BackendRevision) > 0 &&
		len(pin.BackendRevision) <= vaultfilebackend.MaxRevisionSize
}

func vaultFileManagedDeviceSuccessorError(reason string) error {
	return fmt.Errorf("%w: %s", ErrVaultFileManagedDeviceSuccessor, reason)
}

func vaultFileManagedDeviceSuccessorCanceled(err error) error {
	return fmt.Errorf("%w: canceled: %w", ErrVaultFileManagedDeviceSuccessor, err)
}

// sameVaultFileManagedDeviceAuthority reports whether the only difference
// between the authenticated base policy and the candidate is the device roster.
// The owner root, every member/role array and every delegation must be
// byte-identical. The candidate builder never accepts a member, role, action or
// delegation argument, so this guard is a defensive invariant, not an input
// validator.
func sameVaultFileManagedDeviceAuthority(base, next *vaultfile.Policy) bool {
	if base == nil || next == nil {
		return false
	}
	return base.Format == next.Format && base.Version == next.Version &&
		base.VaultID == next.VaultID &&
		base.OwnerRoot.KeyID == next.OwnerRoot.KeyID &&
		base.OwnerRoot.Alg == next.OwnerRoot.Alg &&
		bytes.Equal(base.OwnerRoot.PublicKey, next.OwnerRoot.PublicKey) &&
		slices.Equal(base.OwnerRoot.Owners, next.OwnerRoot.Owners) &&
		slices.Equal(base.Readers, next.Readers) &&
		slices.Equal(base.Writers, next.Writers) &&
		slices.Equal(base.Admins, next.Admins) &&
		slices.Equal(base.Owners, next.Owners) &&
		slices.Equal(base.AdminDelegations, next.AdminDelegations)
}

// vaultFileManagedDeviceSuccessorDevicePresent reports whether either key role
// of the destination device already exists in the base policy. The caller's
// device is only ever added as a new device, never promoted, replaced or
// duplicated.
func vaultFileManagedDeviceSuccessorDevicePresent(policy *vaultfile.Policy, recipient string,
	signing ed25519.PublicKey) bool {
	if policy == nil || recipient == "" || len(signing) != ed25519.PublicKeySize {
		return true
	}
	for i := range policy.Devices {
		device := &policy.Devices[i]
		if device.AgeEncryptionKey == recipient ||
			bytes.Equal(device.ContentSigningKey.PublicKey, signing) {
			return true
		}
	}
	return false
}

func newVaultFileManagedDeviceID(policy *vaultfile.Policy) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id, err := randomID()
		if err != nil {
			return "", err
		}
		taken := false
		for i := range policy.Devices {
			if policy.Devices[i].DeviceID == id {
				taken = true
				break
			}
		}
		if !taken {
			return id, nil
		}
	}
	return "", invalid
}

// readVaultFileManagedDeviceSuccessorTarget performs the one non-creating read
// of the caller-located existing LOCAL object. The returned bytes are owned by
// the caller and must be cleared.
func readVaultFileManagedDeviceSuccessorTarget(ctx context.Context,
	target VaultFileManagedDeviceSuccessorTarget) ([]byte, vaultfilebackend.Revision, error) {
	backend, err := vaultfilebackend.OpenExistingDir(target.Root)
	if err != nil {
		return nil, "", err
	}
	result, readErr := backend.Read(ctx, target.Name)
	closeErr := backend.Close()
	if readErr != nil {
		clear(result.Bytes)
		return nil, "", readErr
	}
	if closeErr != nil {
		clear(result.Bytes)
		return nil, "", closeErr
	}
	if len(result.Bytes) == 0 || len(result.Bytes) > vaultfile.MaxFileBytes ||
		result.Revision.Zero() || len(result.Revision) > vaultfilebackend.MaxRevisionSize {
		clear(result.Bytes)
		return nil, "", invalid
	}
	return result.Bytes, result.Revision, nil
}

// loadVaultFileManagedDeviceSuccessorOwner authenticates the destination
// account's encrypted owner store and returns exactly the one private
// owner/recovery record for the pinned vault together with the same
// authenticated account's public ordinary-device enrollment values. The record
// is cloned and cleared by the caller. No private material leaves this method
// other than the cloned record that the owning preparation path uses in place.
func (s *Session) loadVaultFileManagedDeviceSuccessorOwner(expected vaultfile.PolicyCheckpoint) (
	owner vaultFileOwnerRecord, device VaultFileDevicePublic, err error) {
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return owner, device, err
	}
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, s, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return err
		}
		defer clearVaultFileOwners(records)
		index := -1
		for i := range records {
			if records[i].VaultID == expected.VaultID {
				index = i
				break
			}
		}
		if index < 0 {
			// A caller-supplied foreign vault/root is an ordinary refusal, not
			// evidence that this account's encrypted owner store is corrupt, so
			// it must not lock the session.
			return ErrVaultFileOwnership
		}
		public, err := vaultFileOwnerPublic(records[index])
		if err != nil {
			return err
		}
		rootPublic, err := hex.DecodeString(public.OwnerRootPublicKey)
		if err != nil || public.OwnerRootKeyID != expected.OwnerRootKeyID ||
			!bytes.Equal(rootPublic, expected.OwnerRootPublicKey) {
			return ErrVaultFileOwnership
		}
		owner = cloneVaultFileOwners([]vaultFileOwnerRecord{records[index]})[0]
		identity, err := age.ParseX25519Identity(auth.identity.Device)
		if err != nil {
			clearVaultFileOwners([]vaultFileOwnerRecord{owner})
			owner = vaultFileOwnerRecord{}
			return err
		}
		signer := ed25519.NewKeyFromSeed(auth.identity.Signing)
		defer clear(signer)
		device = VaultFileDevicePublic{
			AgeRecipient:            identity.Recipient().String(),
			ContentSigningPublicKey: hex.EncodeToString(signer.Public().(ed25519.PublicKey)),
		}
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		clearVaultFileOwners([]vaultFileOwnerRecord{owner})
		return vaultFileOwnerRecord{}, VaultFileDevicePublic{}, err
	}
	if closeErr != nil {
		clearVaultFileOwners([]vaultFileOwnerRecord{owner})
		return vaultFileOwnerRecord{}, VaultFileDevicePublic{}, closeErr
	}
	return owner, device, nil
}

// PrepareVaultFileManagedDeviceSuccessor prepares, but never publishes, one
// authenticated managed successor for the restored destination account's
// actual current ordinary device.
//
// The caller supplies only an independently trusted existing LOCAL target and
// the exact current base pin. The method authenticates the destination owner
// store under a fresh full-factor session, requires exactly the one recovered
// owner/recovery record for the pinned vault and root, reads the named protected
// object non-creating, and requires the exact pinned bytes digest and opaque
// revision. It then authenticates the base policy under the pinned checkpoint
// and requires the header's policy sequence, key epoch and content sequence to
// be exactly the pinned current values.
//
// Authority is not taken from the caller or from the base roster. The recovered
// recovery device is located in the authenticated base policy by its existing
// writer-or-stronger principal, its age recipient and content signing public
// key must equal the restored private custody, and its device ID must equal the
// owner record's recovery device ID. The destination ordinary device is read
// from the same authenticated destination identity; its age recipient and
// content signing public key are the only values placed in the new policy
// entry. That entry is added under the recovered recovery device's existing
// principal, with no policy signing key, no reader/writer/admin/owner change and
// no delegation change. A device key already present in the base policy is
// refused rather than promoted or reused.
//
// The owner root signs the immediate policy continuation and the recovered
// recovery device remains the author. The existing RotateAuthenticatedFile
// primitive performs the fresh-VUK epoch rotation and SealAuthenticatedFile
// sealing; VerifyManagedTransition then authenticates the sealed successor
// against the exact base bytes and pin. The fresh VUK is cleared immediately
// and is never returned.
//
// The returned Draft is bounded encrypted bytes only. Base is the exact
// re-verified base pin a later normal CAS must use; Next is the sealed
// successor's public policy/version metadata. This step does not publish,
// activate, register a child, create a missing target, mutate the backend or
// account, revive a pending invitation, or change configuration. A later
// management write must still perform its own freshness/policy check and CAS.
// A late lock, cancellation or fresh-factor expiry after sealing is reported
// and the draft is cleared, never returned.
func (s *Session) PrepareVaultFileManagedDeviceSuccessor(ctx context.Context,
	target VaultFileManagedDeviceSuccessorTarget,
	expected VaultFileManagedDeviceSuccessorPin) (out VaultFileManagedDeviceSuccessor, retErr error) {
	if s == nil {
		return out, ErrSessionLocked
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prepareVaultFileManagedDeviceSuccessorLocked(ctx, target, expected)
}

// prepareVaultFileManagedDeviceSuccessorLocked is the explicit publish path's
// in-lock preparation step. The caller holds Session.mu and has already checked
// activity and the fresh full factor. It performs exactly the same checks and
// sealing as the public Prepare entry point and never locks Session.mu itself.
func (s *Session) prepareVaultFileManagedDeviceSuccessorLocked(ctx context.Context,
	target VaultFileManagedDeviceSuccessorTarget,
	expected VaultFileManagedDeviceSuccessorPin) (out VaultFileManagedDeviceSuccessor, retErr error) {
	defer func() {
		if retErr != nil {
			out.Clear()
		}
	}()
	if s == nil {
		return out, ErrSessionLocked
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !target.valid() || !validVaultFileManagedDeviceSuccessorPin(expected) {
		return out, vaultFileManagedDeviceSuccessorError("request")
	}
	if err := s.active(true); err != nil {
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		return out, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return out, vaultFileManagedDeviceSuccessorCanceled(err)
	}

	owner, destination, err := s.loadVaultFileManagedDeviceSuccessorOwner(expected.Checkpoint)
	if err != nil {
		if errors.Is(err, ErrSessionLocked) {
			return out, ErrSessionLocked
		}
		return out, vaultFileManagedDeviceSuccessorError("owner")
	}
	defer clearVaultFileOwners([]vaultFileOwnerRecord{owner})

	if err := s.active(false); err != nil {
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		return out, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return out, vaultFileManagedDeviceSuccessorCanceled(err)
	}

	baseBytes, baseRevision, err := readVaultFileManagedDeviceSuccessorTarget(ctx, target)
	if err != nil {
		if ctx.Err() != nil {
			return out, vaultFileManagedDeviceSuccessorCanceled(ctx.Err())
		}
		return out, vaultFileManagedDeviceSuccessorError("target")
	}
	defer clear(baseBytes)
	if baseRevision != expected.BackendRevision ||
		sha256.Sum256(baseBytes) != expected.SealedSHA256 {
		return out, vaultFileManagedDeviceSuccessorError("target")
	}
	baseFile, err := vaultfile.ParseFile(baseBytes)
	if err != nil {
		return out, vaultFileManagedDeviceSuccessorError("target")
	}
	if err := vaultfile.VerifyPolicyCheckpoint(baseFile, &expected.Checkpoint); err != nil {
		return out, vaultFileManagedDeviceSuccessorError("target")
	}
	baseHeader := &baseFile.Header
	if baseHeader.KeyEpoch != expected.KeyEpoch || baseHeader.ContentSeq != expected.ContentSeq {
		return out, vaultFileManagedDeviceSuccessorError("version")
	}
	if len(baseFile.SignedPolicyProofs) == 0 {
		return out, vaultFileManagedDeviceSuccessorError("policy")
	}
	basePolicy := &baseFile.SignedPolicyProofs[len(baseFile.SignedPolicyProofs)-1].Policy
	if basePolicy.PolicySeq != baseHeader.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(basePolicy), baseHeader.PolicyDigest) {
		return out, vaultFileManagedDeviceSuccessorError("policy")
	}
	// The base pin is not echoed: it is rebuilt from the authenticated header
	// and the caller-pinned root, then required to equal the caller's exact
	// current checkpoint. A file that is merely ahead of an older pin is refused.
	out.Base = VaultFileManagedDeviceSuccessorPin{
		Checkpoint: vaultfile.PolicyCheckpoint{
			VaultID:            baseHeader.VaultID,
			OwnerRootKeyID:     expected.Checkpoint.OwnerRootKeyID,
			OwnerRootPublicKey: bytes.Clone(expected.Checkpoint.OwnerRootPublicKey),
			PolicySeq:          baseHeader.PolicySeq,
			PolicyDigest:       bytes.Clone(baseHeader.PolicyDigest),
		},
		KeyEpoch:        baseHeader.KeyEpoch,
		ContentSeq:      baseHeader.ContentSeq,
		SealedSHA256:    sha256.Sum256(baseBytes),
		BackendRevision: baseRevision,
	}
	if !sameVaultFileBackupCustodyCheckpoint(out.Base.Checkpoint, expected.Checkpoint) {
		return out, vaultFileManagedDeviceSuccessorError("checkpoint")
	}
	// The target observation can be slow. Re-check the same session and context
	// before any root/recovery signing material is used, so a lock or cancel
	// that raced the read never authorizes a successor.
	if err := s.active(false); err != nil {
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		return out, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return out, vaultFileManagedDeviceSuccessorCanceled(err)
	}

	recoveryAge, err := age.ParseX25519Identity(string(owner.RecoveryAgeIdentity))
	if err != nil {
		return out, vaultFileManagedDeviceSuccessorError("owner")
	}
	recoverySigner := ed25519.NewKeyFromSeed(owner.RecoverySigningSeed)
	defer clear(recoverySigner)
	recoverySigning := recoverySigner.Public().(ed25519.PublicKey)
	recoveryDeviceID, ok := localVaultFileWriterDevice(basePolicy,
		recoveryAge.Recipient().String(), recoverySigning)
	if !ok || recoveryDeviceID != owner.RecoveryDeviceID {
		return out, vaultFileManagedDeviceSuccessorError("owner binding")
	}
	recoveryPrincipal, ok := ownedVaultFileDevicePrincipal(basePolicy, recoveryDeviceID)
	if !ok {
		return out, vaultFileManagedDeviceSuccessorError("principal")
	}

	destinationSigning, err := hex.DecodeString(destination.ContentSigningPublicKey)
	if err != nil || len(destinationSigning) != ed25519.PublicKeySize ||
		destination.AgeRecipient == "" {
		return out, vaultFileManagedDeviceSuccessorError("device")
	}
	if vaultFileManagedDeviceSuccessorDevicePresent(basePolicy,
		destination.AgeRecipient, destinationSigning) {
		return out, vaultFileManagedDeviceSuccessorError("device")
	}
	if destination.AgeRecipient == recoveryAge.Recipient().String() ||
		bytes.Equal(destinationSigning, recoverySigning) {
		return out, vaultFileManagedDeviceSuccessorError("device")
	}

	if baseHeader.KeyEpoch == math.MaxUint64 ||
		baseHeader.ContentSeq == math.MaxUint64 ||
		baseHeader.PolicySeq == math.MaxUint64 {
		return out, vaultFileManagedDeviceSuccessorError("version")
	}
	next := *basePolicy
	next.PolicySeq = baseHeader.PolicySeq + 1
	next.PrevPolicyDigest = bytes.Clone(baseHeader.PolicyDigest)
	newDeviceID, err := newVaultFileManagedDeviceID(basePolicy)
	if err != nil {
		return out, vaultFileManagedDeviceSuccessorError("device")
	}
	next.Devices = append(append([]vaultfile.Device(nil), basePolicy.Devices...), vaultfile.Device{
		DeviceID:    newDeviceID,
		PrincipalID: recoveryPrincipal,
		Label:       "Recovered device",
		ContentSigningKey: vaultfile.PublicKey{
			Alg:       vaultfile.SigAlgEd25519,
			PublicKey: bytes.Clone(destinationSigning),
		},
		AgeEncryptionKey: destination.AgeRecipient,
	})
	sort.Slice(next.Devices, func(i, j int) bool {
		return next.Devices[i].DeviceID < next.Devices[j].DeviceID
	})
	// Every existing member, role and delegation is carried unchanged. In
	// particular, a delegation that expires exactly at this next policy
	// sequence makes ValidatePolicy refuse the candidate rather than being
	// silently removed, so this step never revives, extends or manufactures
	// authority.
	if !sameVaultFileManagedDeviceAuthority(basePolicy, &next) {
		return out, vaultFileManagedDeviceSuccessorError("authority")
	}
	if err := vaultfile.ValidatePolicy(&next); err != nil {
		return out, vaultFileManagedDeviceSuccessorError("policy")
	}
	nextDigest := vaultfile.PolicyDigest(&next)
	if len(nextDigest) != sha256.Size {
		return out, vaultFileManagedDeviceSuccessorError("policy")
	}

	document, err := vaultfile.EncodePolicyDocument(&next)
	if err != nil {
		return out, vaultFileManagedDeviceSuccessorError("policy")
	}
	rootSigner := ed25519.NewKeyFromSeed(owner.OwnerRootSeed)
	defer clear(rootSigner)
	proof := vaultfile.SignedPolicy{
		Policy:   next,
		Document: document,
		SignerID: owner.OwnerRootKeyID,
		Alg:      vaultfile.PolicySigAlgEd25519,
		Sig:      ed25519.Sign(rootSigner, append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...)),
	}
	parentDigest, err := vaultfile.FileDigest(baseFile)
	if err != nil {
		return out, vaultFileManagedDeviceSuccessorError("base digest")
	}
	prevDigest, err := hex.DecodeString(parentDigest)
	if err != nil || len(prevDigest) != sha256.Size {
		return out, vaultFileManagedDeviceSuccessorError("base digest")
	}
	operationID, err := randomID()
	if err != nil {
		return out, vaultFileManagedDeviceSuccessorError("operation")
	}
	draft := &vaultfile.File{
		Format:             baseFile.Format,
		Version:            baseFile.Version,
		SignedPolicyProofs: append(append([]vaultfile.SignedPolicy(nil), baseFile.SignedPolicyProofs...), proof),
		Header:             *baseHeader,
	}
	draft.Header.KeyEpoch = baseHeader.KeyEpoch + 1
	draft.Header.ContentSeq = baseHeader.ContentSeq + 1
	draft.Header.PolicySeq = next.PolicySeq
	draft.Header.PolicyDigest = nextDigest
	draft.Header.PrevDigest = prevDigest
	draft.Header.RevisionID = ""
	draft.Header.OpID = operationID
	draft.Header.AuthorDeviceID = recoveryDeviceID

	sealed, newVUK, err := vaultfile.RotateAuthenticatedFile(baseBytes, &expected.Checkpoint,
		recoveryDeviceID, recoveryAge, draft, recoverySigner)
	clear(newVUK)
	if err != nil {
		return out, vaultFileManagedDeviceSuccessorError("successor")
	}
	if err := vaultfile.VerifyManagedTransition(baseBytes, sealed, &expected.Checkpoint); err != nil {
		clear(sealed)
		return out, vaultFileManagedDeviceSuccessorError("transition")
	}
	sealedFile, err := vaultfile.ParseFile(sealed)
	if err != nil || len(sealedFile.SignedPolicyProofs) == 0 ||
		sealedFile.Header.KeyEpoch != draft.Header.KeyEpoch ||
		sealedFile.Header.ContentSeq != draft.Header.ContentSeq ||
		sealedFile.Header.PolicySeq != draft.Header.PolicySeq ||
		!bytes.Equal(sealedFile.Header.PolicyDigest, nextDigest) ||
		sealedFile.Header.AuthorDeviceID != recoveryDeviceID ||
		!bytes.Equal(sealedFile.Header.PrevDigest, prevDigest) {
		clear(sealed)
		return out, vaultFileManagedDeviceSuccessorError("successor")
	}
	out.Draft = sealed
	out.Next = VaultFileManagedDeviceSuccessorPolicy{
		Checkpoint: vaultfile.PolicyCheckpoint{
			VaultID:            sealedFile.Header.VaultID,
			OwnerRootKeyID:     expected.Checkpoint.OwnerRootKeyID,
			OwnerRootPublicKey: bytes.Clone(expected.Checkpoint.OwnerRootPublicKey),
			PolicySeq:          sealedFile.Header.PolicySeq,
			PolicyDigest:       bytes.Clone(sealedFile.Header.PolicyDigest),
		},
		KeyEpoch:   sealedFile.Header.KeyEpoch,
		ContentSeq: sealedFile.Header.ContentSeq,
	}

	if vaultFileManagedDeviceSuccessorBeforeReleaseForTest != nil {
		vaultFileManagedDeviceSuccessorBeforeReleaseForTest()
	}
	if err := s.active(false); err != nil {
		return out, err
	}
	if s.requireFreshFullFactor() != nil {
		return out, ErrVaultFileFullFactorRequired
	}
	if err := ctx.Err(); err != nil {
		return out, vaultFileManagedDeviceSuccessorCanceled(err)
	}
	return out, nil
}
