package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

var (
	// ErrVaultFileBackupCustody rejects a child, source, checkpoint, recovery
	// factor or artifact that does not authenticate one exact selected vault.
	ErrVaultFileBackupCustody = errors.New("vault-file backup custody rejected")
	// ErrVaultFileBackupCustodyLimit rejects an artifact, source or factor
	// outside the fixed single-vault custody bound.
	ErrVaultFileBackupCustodyLimit = errors.New("vault-file backup custody exceeds capacity")
	// ErrVaultFileBackupCustodyCanceled reports cancellation or a session/child
	// lock before a custody artifact was delivered.
	ErrVaultFileBackupCustodyCanceled = errors.New("vault-file backup custody canceled")
)

const (
	vaultFileBackupCustodyFormat       = "locklark/vault-file-backup-custody/v1"
	vaultFileBackupCustodyDomain       = "locklark/personal/vault-file-backup-custody/signature/v1\x00"
	vaultFileBackupCustodySourceDomain = "locklark/personal/vault-file-backup-custody/source/v1\x00"
	vaultFileBackupRecoveryFactorLimit = 128

	// A source is the current encrypted file plus, for a settled first
	// successor, its authenticated encrypted origin. Each is bounded by the
	// existing vault-file value limit. The JSON payload and its age envelope
	// add the fixed encoding overhead admitted below.
	maxVaultFileBackupCustodyPayload  = 96 << 20
	maxVaultFileBackupCustodyArtifact = 128 << 20
)

// VaultFileBackupCustodySource is exactly one observed source and its
// authenticated public custody identity. Every byte slice is ciphertext or
// public metadata. It never contains an owner root seed, recovery seed, age
// identity, VUK, CEK or decrypted item. The caller owns the copies and must
// Clear them when finished.
type VaultFileBackupCustodySource struct {
	VaultID         string
	Current         []byte
	Origin          []byte
	JournalRevision string
	BackendRevision string
	OriginRevision  string
	ContentSeq      uint64
	Checkpoint      vaultfile.PolicyCheckpoint
	// SourceIdentity is the canonical local identity of this exact source and
	// checkpoint. It is computed by VaultFileBackupCustodySourceIdentity, not
	// accepted from a caller as authority.
	SourceIdentity [sha256.Size]byte
}

// Clear zeroes every retained ciphertext, checkpoint byte and digest.
func (s *VaultFileBackupCustodySource) Clear() {
	if s == nil {
		return
	}
	clear(s.Current)
	clear(s.Origin)
	clear(s.Checkpoint.OwnerRootPublicKey)
	clear(s.Checkpoint.PolicyDigest)
	*s = VaultFileBackupCustodySource{}
}

// VaultFileBackupRecoveryFactor is one fresh, independent age X25519 recovery
// factor for a single-vault backup artifact. It is never part of the artifact,
// an error, a log line or ordinary formatting. Material is the explicit
// extraction path and returns a caller-owned copy. Clear is idempotent and safe
// on a nil pointer. ImportVaultFileBackupRecoveryFactor is the independent,
// canonical import path for a serialized factor.
type VaultFileBackupRecoveryFactor struct {
	material []byte
}

const vaultFileBackupRecoveryFactorRedacted = "[vault-file backup recovery factor]"

func (VaultFileBackupRecoveryFactor) String() string   { return vaultFileBackupRecoveryFactorRedacted }
func (VaultFileBackupRecoveryFactor) GoString() string { return vaultFileBackupRecoveryFactorRedacted }
func (VaultFileBackupRecoveryFactor) MarshalJSON() ([]byte, error) {
	return []byte(`"[vault-file backup recovery factor]"`), nil
}
func (VaultFileBackupRecoveryFactor) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte(vaultFileBackupRecoveryFactorRedacted))
}

// Material returns a copy of the independent recovery factor. This is the only
// plaintext extraction path; callers must clear the returned bytes.
func (f *VaultFileBackupRecoveryFactor) Material() []byte {
	if f == nil {
		return nil
	}
	return bytes.Clone(f.material)
}

// Clear zeroes the factor material.
func (f *VaultFileBackupRecoveryFactor) Clear() {
	if f == nil {
		return
	}
	clear(f.material)
	f.material = nil
}

// ImportVaultFileBackupRecoveryFactor accepts one strict, bounded, canonical
// serialized age X25519 identity. It needs no live Session, account, checkpoint
// or prior in-memory factor. Non-canonical encodings, malformed values and
// oversized input are refused without echoing the input. The returned factor
// owns an independent copy; the caller still owns and should clear the input.
func ImportVaultFileBackupRecoveryFactor(material []byte) (*VaultFileBackupRecoveryFactor, error) {
	if len(material) == 0 {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "factor")
	}
	if len(material) > vaultFileBackupRecoveryFactorLimit {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyLimit, "factor")
	}
	identity, err := age.ParseX25519Identity(string(material))
	if err != nil || identity == nil || identity.Recipient() == nil ||
		identity.String() != string(material) {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "factor import")
	}
	return &VaultFileBackupRecoveryFactor{material: bytes.Clone(material)}, nil
}

func (f *VaultFileBackupRecoveryFactor) identity() (*age.X25519Identity, error) {
	if f == nil {
		return nil, ErrVaultFileBackupCustody
	}
	material := f.Material()
	defer clear(material)
	if len(material) == 0 {
		return nil, ErrVaultFileBackupCustody
	}
	identity, err := age.ParseX25519Identity(string(material))
	if err != nil || identity == nil || identity.Recipient() == nil {
		return nil, ErrVaultFileBackupCustody
	}
	return identity, nil
}

// The sealing payload is entirely inside age ciphertext. The public header is
// repeated inside it so a successfully decrypted artifact cannot substitute a
// different vault, checkpoint, source identity or revision set.
type vaultFileBackupCustodyHeader struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	VaultID string `json:"vault_id"`
	// Checkpoint is the caller-pinned public policy state. It contains no
	// private key.
	Checkpoint      vaultfile.PolicyCheckpoint `json:"checkpoint"`
	SourceIdentity  [sha256.Size]byte          `json:"source_identity"`
	CurrentSHA256   string                     `json:"current_sha256"`
	OriginSHA256    string                     `json:"origin_sha256,omitempty"`
	JournalRevision string                     `json:"journal_revision"`
	BackendRevision string                     `json:"backend_revision"`
	OriginRevision  string                     `json:"origin_revision,omitempty"`
	ContentSeq      uint64                     `json:"content_seq"`
}

type vaultFileBackupCustodyPayload struct {
	Format  string                       `json:"format"`
	Version int                          `json:"version"`
	Header  vaultFileBackupCustodyHeader `json:"header"`
	Owner   vaultFileOwnerRecord         `json:"owner"`
	Current []byte                       `json:"current"`
	Origin  []byte                       `json:"origin,omitempty"`
}

type vaultFileBackupCustodyArtifact struct {
	Header    vaultFileBackupCustodyHeader `json:"header"`
	Data      []byte                       `json:"data"`
	Signature []byte                       `json:"signature"`
}

// vaultFileBackupCustodyChild is a short copy of the exact registered custody
// child. It contains no private material and no reusable close authority.
type vaultFileBackupCustodyChild struct {
	token      VaultFileChildToken
	checkpoint vaultfile.PolicyCheckpoint
	owned      VaultFileOwnershipPublic

	successor   *vaultFileOwnedSuccessorBinding
	backendRoot string
	backendName string

	journalGeneration uint64
	remoteRevision    string
	baseHash          [sha256.Size]byte
	workingHash       [sha256.Size]byte
	pending           bool
}

// VaultFileBackupCustodySeal is an opaque shared-state handle for one sealed
// custody result. The artifact, factor, public ownership and source identity
// live only in the bound claim's shared state; copying this value copies only a
// pointer and cannot duplicate or re-release them. Ordinary formatting and
// JSON are fully redacted for both value and pointer.
type VaultFileBackupCustodySeal struct {
	state *vaultFileBackupCustodySealState
}

type vaultFileBackupCustodySealState struct {
	claim *vaultFileReadDeliveryClaimState

	session        *Session
	token          VaultFileChildToken
	artifact       []byte
	factor         *VaultFileBackupRecoveryFactor
	ownership      VaultFileOwnershipPublic
	sourceIdentity [sha256.Size]byte
	released       bool
}

const vaultFileBackupCustodySealRedacted = "[vault-file backup custody seal]"

func (VaultFileBackupCustodySeal) String() string   { return vaultFileBackupCustodySealRedacted }
func (VaultFileBackupCustodySeal) GoString() string { return vaultFileBackupCustodySealRedacted }
func (VaultFileBackupCustodySeal) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (VaultFileBackupCustodySeal) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte(vaultFileBackupCustodySealRedacted))
}

// detachLocked moves the four outputs out of shared state exactly once. The
// caller holds the bound claim lock and must wipe the returned bytes after all
// locks are released.
func (c *vaultFileBackupCustodySealState) detachLocked() (artifact []byte,
	factor *VaultFileBackupRecoveryFactor, ownership VaultFileOwnershipPublic,
	sourceIdentity [sha256.Size]byte) {
	if c == nil || c.released {
		return nil, nil, ownership, sourceIdentity
	}
	artifact, factor = c.artifact, c.factor
	ownership, sourceIdentity = c.ownership, c.sourceIdentity
	c.artifact, c.factor = nil, nil
	c.ownership = VaultFileOwnershipPublic{}
	c.sourceIdentity = [sha256.Size]byte{}
	c.released = true
	return artifact, factor, ownership, sourceIdentity
}

// Clear detaches and wipes the seal's outputs once, after the bound claim lock
// is released. A copy or alias that clears after another alias won Take finds
// no outputs and cannot zero the winner's detached result.
func (c *VaultFileBackupCustodySeal) Clear() {
	if c == nil || c.state == nil {
		return
	}
	state := c.state
	claim := state.claim
	if claim == nil {
		return
	}
	claim.mu.Lock()
	artifact, factor, _, _ := state.detachLocked()
	claim.mu.Unlock()
	clear(artifact)
	if factor != nil {
		factor.Clear()
	}
}

// Take performs the one final RequestLock arbitration for the exact bound,
// physically closed, valid and unconsumed claim. It samples parent/child
// deadlines and context once under claim.state.mu -> Session.mu -> saveMu,
// atomically consumes the claim and detaches the four outputs, then releases
// the locks. A foreign Session/token/claim cannot release or wipe. Any refusal
// detaches and wipes these outputs after locks are released and follows the
// existing child-only or parent-drain protocol.
func (c *VaultFileBackupCustodySeal) Take(ctx context.Context, s *Session) (
	artifact []byte, factor *VaultFileBackupRecoveryFactor, ownership VaultFileOwnershipPublic,
	sourceIdentity [sha256.Size]byte, err error) {
	if c == nil || c.state == nil || ctx == nil || s == nil {
		return nil, nil, ownership, sourceIdentity, ErrVaultFileBackupCustody
	}
	state := c.state
	claim := state.claim
	if claim == nil {
		return nil, nil, ownership, sourceIdentity, ErrVaultFileBackupCustody
	}

	claim.mu.Lock()
	if state.released {
		claim.mu.Unlock()
		return nil, nil, ownership, sourceIdentity, ErrVaultFileBackupCustody
	}
	// Foreign or wrong authority must neither release nor wipe this seal.
	if claim.session != s || state.session != s || claim.token != state.token || claim.custody != state {
		claim.mu.Unlock()
		return nil, nil, ownership, sourceIdentity, ErrVaultFileBackupCustody
	}
	if !claim.sealed || claim.consumed || claim.invalid || claim.closeErr != nil {
		artifact, factor, ownership, sourceIdentity = state.detachLocked()
		claim.mu.Unlock()
		clear(artifact)
		if factor != nil {
			factor.Clear()
		}
		return nil, nil, VaultFileOwnershipPublic{}, [sha256.Size]byte{}, ErrVaultFileBackupCustody
	}

	s.mu.Lock()
	s.saveMu.Lock()
	decision := vaultFileReadDeliveryArbitrateLocked(claim, s, ctx, vaultFileReadDeliveryClaimSample())
	if decision.valid {
		artifact, factor, ownership, sourceIdentity = state.detachLocked()
	} else {
		// Detach under the same claim lock so a concurrent alias cannot win a
		// second release, then wipe outside every lock below.
		artifact, factor, ownership, sourceIdentity = state.detachLocked()
	}
	s.saveMu.Unlock()
	s.mu.Unlock()
	claim.mu.Unlock()
	if decision.valid {
		return artifact, factor, ownership, sourceIdentity, nil
	}
	clear(artifact)
	if factor != nil {
		factor.Clear()
	}
	return nil, nil, VaultFileOwnershipPublic{}, [sha256.Size]byte{}, finishVaultFileReadDeliveryDecision(s, decision)
}

// PrepareVaultFileBackupCustodyForChild seals exactly one currently registered
// custody child. The caller can only obtain that child through the explicit
// fresh-factor owned-open methods; a generic or ordinary owned read token is
// refused. Authorization is the opaque child token plus the child's custody
// marker, exact pinned checkpoint, current target ownership projection and
// current Session. The source is read here from the actual journal and named
// backend object, never accepted from the caller. The owner record is loaded
// with the same explicit password/key, not Session.fullUnlock and not a global
// freshness timer.
//
// The artifact is sealed before the caller closes the child. The caller must
// keep it private until the published exclusive close and one-shot read-delivery
// claim have both succeeded; a close, lock, idle, child expiry or cancellation
// failure must clear it. Private owner material stays in this package.
func (s *Session) PrepareVaultFileBackupCustodyForChild(ctx context.Context, token VaultFileChildToken,
	claim *VaultFileReadDeliveryClaim, expected vaultfile.PolicyCheckpoint, password, key []byte) (seal *VaultFileBackupCustodySeal, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || claim == nil || claim.state == nil || !validVaultFileBackupCustodyCheckpoint(expected) {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "request")
	}
	claim.state.mu.Lock()
	claimErr := validateVaultFileReadDeliveryCustodyBinding(claim.state, s, token)
	claim.state.mu.Unlock()
	if claimErr != nil {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "claim")
	}
	if err := ctx.Err(); err != nil {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}

	// This is the target-only ownership proof. It never re-unwraps the account
	// slot, never refreshes fullUnlock and never promotes a generic child.
	if err := s.RevalidateVaultFileChildOwnership(token); err != nil {
		return nil, mapVaultFileBackupCustodyChildError(err)
	}
	child, err := s.snapshotVaultFileBackupCustodyChild(token, expected)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}

	// The explicit factors authenticate the current account store outside every
	// Session lock. A wrong factor cannot select a different owner record.
	owner, err := loadVaultFileBackupCustodyOwnerWithFactors(s.path, expected.VaultID, password, key)
	if err != nil {
		return nil, err
	}
	defer clearVaultFileOwners([]vaultFileOwnerRecord{owner})
	projection, err := vaultFileOwnerPublic(owner)
	if err != nil || projection != child.owned {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner projection")
	}

	source, err := readVaultFileBackupCustodySource(ctx, child)
	if err != nil {
		return nil, err
	}
	defer source.Clear()

	artifact, factor, ownership, sourceIdentity, err := sealVaultFileBackupCustody(
		ctx, source, owner, expected)
	if err != nil {
		return nil, err
	}

	// The same exact child, projection, deadline and parent activity must still
	// hold after the backend reads and sealing crypto. Failure clears the
	// artifact/factor before the caller can close or deliver anything.
	if err := s.RevalidateVaultFileChildOwnership(token); err != nil {
		clear(artifact)
		factor.Clear()
		return nil, mapVaultFileBackupCustodyChildError(err)
	}
	if err := ctx.Err(); err != nil {
		clear(artifact)
		factor.Clear()
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}
	state := &vaultFileBackupCustodySealState{
		session: s, token: token, artifact: artifact, factor: factor,
		ownership: ownership, sourceIdentity: sourceIdentity,
	}
	if err := claim.bindCustody(s, token, state); err != nil {
		clear(artifact)
		if factor != nil {
			factor.Clear()
		}
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "claim")
	}
	return &VaultFileBackupCustodySeal{state: state}, nil
}

func (s *Session) snapshotVaultFileBackupCustodyChild(token VaultFileChildToken,
	expected vaultfile.PolicyCheckpoint) (vaultFileBackupCustodyChild, error) {
	var out vaultFileBackupCustodyChild
	if s == nil || !validVaultFileBackupCustodyCheckpoint(expected) {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "child")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(false); err != nil {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "session")
	}
	if s.vaultFileRevoked.Load() {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "session")
	}
	child, err := s.snapshotVaultFileChild(token)
	if err != nil || child == nil || child.owned == nil || !child.custody ||
		!validVaultFileGenesisPath(child.backendRoot) ||
		!vaultfilebackend.ValidName(child.backendName) ||
		!sameVaultFileBackupCustodyCheckpoint(child.checkpoint, expected) {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "child")
	}
	if child.successor != nil && (child.successor.backendRoot != child.backendRoot ||
		child.successor.backendName != child.backendName) {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "child binding")
	}
	child.mu.Lock()
	closed := child.closed
	used := child.custodyUsed
	fullFactorDeadline := child.fullFactorDeadline
	idleDeadline := child.idleDeadline
	child.mu.Unlock()
	now := time.Now()
	if closed || used || fullFactorDeadline.IsZero() || !now.Before(fullFactorDeadline) ||
		(!idleDeadline.IsZero() && !now.Before(idleDeadline)) {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "child deadline")
	}
	child.mu.Lock()
	if child.closed || child.custodyUsed {
		child.mu.Unlock()
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "child deadline")
	}
	child.custodyUsed = true
	child.mu.Unlock()
	out = vaultFileBackupCustodyChild{
		token:             token,
		checkpoint:        cloneVaultFileCheckpoint(&child.checkpoint),
		owned:             child.owned.owner,
		successor:         child.successor,
		backendRoot:       child.backendRoot,
		backendName:       child.backendName,
		journalGeneration: child.journalGeneration,
		remoteRevision:    child.remoteRevision,
		baseHash:          child.baseHash,
		workingHash:       child.workingHash,
		pending:           child.pending,
	}
	return out, nil
}

func readVaultFileBackupCustodySource(ctx context.Context, child vaultFileBackupCustodyChild) (VaultFileBackupCustodySource, error) {
	var source VaultFileBackupCustodySource
	if child.successor != nil {
		genesis, successor, genesisRevision, successorRevision, err :=
			readVerifiedOwnedFirstSuccessor(ctx, child.successor, &child.checkpoint)
		if err != nil {
			if ctx.Err() != nil {
				return source, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
			}
			return source, mapVaultFileBackupCustodySourceError(err)
		}
		source = VaultFileBackupCustodySource{
			VaultID:         child.checkpoint.VaultID,
			Current:         successor,
			Origin:          genesis,
			JournalRevision: string(successorRevision),
			BackendRevision: string(successorRevision),
			OriginRevision:  string(genesisRevision),
			ContentSeq:      1,
			Checkpoint:      cloneVaultFileCheckpoint(&child.checkpoint),
		}
		source.SourceIdentity = VaultFileBackupCustodySourceIdentity(source)
		return source, nil
	}

	source, err := readVaultFileBackupCustodyPristineSource(ctx, child)
	if err != nil && ctx.Err() != nil {
		source.Clear()
		return VaultFileBackupCustodySource{}, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}
	return source, err
}

func readVaultFileBackupCustodyPristineSource(ctx context.Context, child vaultFileBackupCustodyChild) (VaultFileBackupCustodySource, error) {
	var source VaultFileBackupCustodySource
	baseline := vaultFileJournalBaseline{
		generation: child.journalGeneration, remoteRevision: child.remoteRevision,
		baseHash: child.baseHash, workingHash: child.workingHash, pending: child.pending,
	}
	journal, err := vaultfilejournal.OpenExisting(child.token.path)
	if err != nil {
		return source, mapVaultFileBackupCustodySourceError(err)
	}
	if err := journalMatchesExpected(journal, baseline); err != nil {
		_ = journal.Close()
		return source, mapVaultFileBackupCustodySourceError(err)
	}
	_, base, err := loadVaultFileJournalBaseline(journal)
	if err != nil || len(base) == 0 {
		clear(base)
		_ = journal.Close()
		return source, mapVaultFileBackupCustodySourceError(err)
	}
	ok := false
	defer func() {
		if !ok {
			clear(base)
		}
	}()

	backend, err := vaultfilebackend.OpenExistingDir(child.backendRoot)
	if err != nil {
		_ = journal.Close()
		return source, mapVaultFileBackupCustodySourceError(err)
	}
	result, readErr := backend.Read(ctx, child.backendName)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil ||
		result.Revision != vaultfilebackend.Revision(child.remoteRevision) ||
		!bytes.Equal(result.Bytes, base) {
		clear(result.Bytes)
		clear(base)
		_ = journal.Close()
		return source, mapVaultFileBackupCustodySourceError(ErrVaultFileBaselineJournal)
	}
	clear(result.Bytes)
	if err := journalMatchesExpected(journal, baseline); err != nil {
		_ = journal.Close()
		return source, mapVaultFileBackupCustodySourceError(err)
	}
	if err := journal.Close(); err != nil {
		return source, mapVaultFileBackupCustodySourceError(err)
	}
	source = VaultFileBackupCustodySource{
		VaultID:         child.checkpoint.VaultID,
		Current:         base,
		JournalRevision: child.remoteRevision,
		BackendRevision: child.remoteRevision,
		ContentSeq:      0,
		Checkpoint:      cloneVaultFileCheckpoint(&child.checkpoint),
	}
	source.SourceIdentity = VaultFileBackupCustodySourceIdentity(source)
	ok = true
	return source, nil
}

func loadVaultFileBackupCustodyOwnerWithFactors(path, vaultID string, password, key []byte) (vaultFileOwnerRecord, error) {
	var out vaultFileOwnerRecord
	if path == "" || !idOK(vaultID) || len(password) == 0 || len(key) == 0 {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner request")
	}
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		return out, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner store")
	}
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, string(password), key, vaultFileOwnerListAction, nil, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return err
		}
		defer clearVaultFileOwners(records)
		found := false
		for i := range records {
			if records[i].VaultID != vaultID {
				continue
			}
			if found {
				return invalid
			}
			out = cloneVaultFileOwners(records[i : i+1])[0]
			found = true
		}
		if !found {
			return ErrVaultFileOwnership
		}
		return nil
	})
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		clearVaultFileOwners([]vaultFileOwnerRecord{out})
		return vaultFileOwnerRecord{}, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner store")
	}
	return out, nil
}

func sealVaultFileBackupCustody(ctx context.Context, source VaultFileBackupCustodySource,
	owner vaultFileOwnerRecord, expected vaultfile.PolicyCheckpoint) (artifact []byte,
	factor *VaultFileBackupRecoveryFactor, ownership VaultFileOwnershipPublic,
	sourceIdentity [sha256.Size]byte, retErr error) {
	current, err := verifyVaultFileBackupCustodySource(source, expected)
	if err != nil {
		return nil, nil, ownership, sourceIdentity, err
	}
	projection, err := vaultFileOwnerPublic(owner)
	if err != nil {
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner")
	}
	if err := bindVaultFileBackupCustodyOwner(owner, projection, expected, current); err != nil {
		return nil, nil, ownership, sourceIdentity, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "factor")
	}
	factor = &VaultFileBackupRecoveryFactor{material: []byte(identity.String())}
	if _, err := factor.identity(); err != nil {
		factor.Clear()
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "factor")
	}

	sourceIdentity = VaultFileBackupCustodySourceIdentity(source)
	source.SourceIdentity = sourceIdentity
	header := vaultFileBackupCustodyHeader{
		Format: vaultFileBackupCustodyFormat, Version: 1,
		VaultID:         source.VaultID,
		Checkpoint:      cloneVaultFileCheckpoint(&source.Checkpoint),
		SourceIdentity:  sourceIdentity,
		CurrentSHA256:   vaultFileBackupCustodyHexSHA256(source.Current),
		JournalRevision: source.JournalRevision,
		BackendRevision: source.BackendRevision,
		OriginRevision:  source.OriginRevision,
		ContentSeq:      source.ContentSeq,
	}
	if source.Origin != nil {
		header.OriginSHA256 = vaultFileBackupCustodyHexSHA256(source.Origin)
	}
	payload := vaultFileBackupCustodyPayload{
		Format: vaultFileBackupCustodyFormat, Version: 1,
		Header: header, Owner: owner, Current: source.Current, Origin: source.Origin,
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > maxVaultFileBackupCustodyPayload {
		clear(raw)
		factor.Clear()
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyLimit, "payload")
	}
	sealed, err := sealVaultFileBackupCustodyBytes(raw, identity.Recipient())
	clear(raw)
	if err != nil {
		factor.Clear()
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "seal")
	}
	signer := ed25519.NewKeyFromSeed(owner.OwnerRootSeed)
	message, err := vaultFileBackupCustodySigningMessage(header, sealed)
	if err != nil {
		clear(signer)
		clear(sealed)
		factor.Clear()
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "binding")
	}
	signature := ed25519.Sign(signer, message[:])
	clear(signer)
	artifact, err = json.Marshal(vaultFileBackupCustodyArtifact{
		Header: header, Data: sealed, Signature: signature,
	})
	clear(sealed)
	if err != nil || len(artifact) > maxVaultFileBackupCustodyArtifact {
		clear(artifact)
		factor.Clear()
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyLimit, "artifact")
	}
	if err := ctx.Err(); err != nil {
		clear(artifact)
		factor.Clear()
		return nil, nil, ownership, sourceIdentity, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}
	return artifact, factor, projection, sourceIdentity, nil
}

// OpenVaultFileBackupCustody decrypts and verifies one exact expected vault and
// caller-pinned checkpoint. It first authenticates the public header with the
// expected owner root, then removes the age layer with the independent backup
// factor, then repeats every checkpoint, policy, source identity, revision and
// single-owner-record binding inside the payload. Wrong factors, swapped or
// corrupted artifacts, a wrong checkpoint, a self-asserted scope or a changed
// source are refused before any source value is returned. Private owner seeds
// stay inside this function and are cleared.
func OpenVaultFileBackupCustody(ctx context.Context, artifact []byte, expected vaultfile.PolicyCheckpoint, factor *VaultFileBackupRecoveryFactor) (source VaultFileBackupCustodySource, ownership VaultFileOwnershipPublic, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validVaultFileBackupCustodyCheckpoint(expected) || factor == nil {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "request")
	}
	if len(artifact) == 0 || len(artifact) > maxVaultFileBackupCustodyArtifact {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyLimit, "artifact")
	}
	if err := ctx.Err(); err != nil {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}
	var envelope vaultFileBackupCustodyArtifact
	if err := decodeVaultFileBackupCustodyJSON(artifact, &envelope); err != nil {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "artifact")
	}
	if envelope.Header.Format != vaultFileBackupCustodyFormat || envelope.Header.Version != 1 ||
		envelope.Header.VaultID != expected.VaultID ||
		!sameVaultFileBackupCustodyCheckpoint(envelope.Header.Checkpoint, expected) ||
		len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Data) == 0 {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "header")
	}
	message, err := vaultFileBackupCustodySigningMessage(envelope.Header, envelope.Data)
	if err != nil || !ed25519.Verify(expected.OwnerRootPublicKey, message[:], envelope.Signature) {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "signature")
	}
	identity, err := factor.identity()
	if err != nil {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "factor")
	}
	plain, err := openVaultFileBackupCustodyBytes(envelope.Data, identity)
	if err != nil {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "decrypt")
	}
	defer clear(plain)
	var payload vaultFileBackupCustodyPayload
	if err := decodeVaultFileBackupCustodyJSON(plain, &payload); err != nil ||
		payload.Format != vaultFileBackupCustodyFormat || payload.Version != 1 {
		clearVaultFileOwners([]vaultFileOwnerRecord{payload.Owner})
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "payload")
	}
	defer clearVaultFileOwners([]vaultFileOwnerRecord{payload.Owner})
	defer func() { payload.Current = nil; payload.Origin = nil }()
	envelopeHeader, err1 := json.Marshal(envelope.Header)
	payloadHeader, err2 := json.Marshal(payload.Header)
	if err1 != nil || err2 != nil || !bytes.Equal(envelopeHeader, payloadHeader) {
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "self scope")
	}
	candidate := VaultFileBackupCustodySource{
		VaultID:         payload.Header.VaultID,
		Current:         payload.Current,
		Origin:          payload.Origin,
		JournalRevision: payload.Header.JournalRevision,
		BackendRevision: payload.Header.BackendRevision,
		OriginRevision:  payload.Header.OriginRevision,
		ContentSeq:      payload.Header.ContentSeq,
		Checkpoint:      cloneVaultFileCheckpoint(&payload.Header.Checkpoint),
	}
	current, err := verifyVaultFileBackupCustodySource(candidate, expected)
	if err != nil {
		candidate.Clear()
		return source, ownership, err
	}
	sourceIdentity := VaultFileBackupCustodySourceIdentity(candidate)
	if payload.Header.CurrentSHA256 != vaultFileBackupCustodyHexSHA256(candidate.Current) ||
		payload.Header.OriginSHA256 != vaultFileBackupCustodyHexSHA256(candidate.Origin) ||
		payload.Header.SourceIdentity != sourceIdentity {
		candidate.Clear()
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "source binding")
	}
	candidate.SourceIdentity = sourceIdentity
	projection, err := vaultFileOwnerPublic(payload.Owner)
	if err != nil {
		candidate.Clear()
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner")
	}
	if err := bindVaultFileBackupCustodyOwner(payload.Owner, projection, expected, current); err != nil {
		candidate.Clear()
		return source, ownership, err
	}
	if err := ctx.Err(); err != nil {
		candidate.Clear()
		return source, ownership, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}
	return candidate, projection, nil
}

// VaultFileBackupCustodySourceIdentity is the stable, domain-separated local
// identity of one exact source and checkpoint. It is not a signature, remote
// freshness proof or authorization to seal.
func VaultFileBackupCustodySourceIdentity(source VaultFileBackupCustodySource) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(vaultFileBackupCustodySourceDomain))
	writeVaultFileBackupCustodyString(h, source.VaultID)
	writeVaultFileBackupCustodyString(h, source.Checkpoint.VaultID)
	writeVaultFileBackupCustodyString(h, source.Checkpoint.OwnerRootKeyID)
	writeVaultFileBackupCustodyBytes(h, source.Checkpoint.OwnerRootPublicKey)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], source.Checkpoint.PolicySeq)
	_, _ = h.Write(seq[:])
	writeVaultFileBackupCustodyBytes(h, source.Checkpoint.PolicyDigest)
	writeVaultFileBackupCustodyString(h, source.JournalRevision)
	writeVaultFileBackupCustodyString(h, source.BackendRevision)
	writeVaultFileBackupCustodyString(h, source.OriginRevision)
	binary.BigEndian.PutUint64(seq[:], source.ContentSeq)
	_, _ = h.Write(seq[:])
	if source.Origin == nil {
		_, _ = h.Write([]byte{0})
	} else {
		_, _ = h.Write([]byte{1})
		writeVaultFileBackupCustodyBytes(h, source.Origin)
	}
	writeVaultFileBackupCustodyBytes(h, source.Current)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func clearVaultFileBackupCustodyCheckpoint(checkpoint *vaultfile.PolicyCheckpoint) {
	if checkpoint == nil {
		return
	}
	clear(checkpoint.OwnerRootPublicKey)
	clear(checkpoint.PolicyDigest)
}

func validVaultFileBackupCustodyCheckpoint(c vaultfile.PolicyCheckpoint) bool {
	return idOK(c.VaultID) && idOK(c.OwnerRootKeyID) &&
		len(c.OwnerRootPublicKey) == ed25519.PublicKeySize &&
		len(c.PolicyDigest) == sha256.Size
}

func sameVaultFileBackupCustodyCheckpoint(a, b vaultfile.PolicyCheckpoint) bool {
	return a.VaultID == b.VaultID && a.OwnerRootKeyID == b.OwnerRootKeyID &&
		a.PolicySeq == b.PolicySeq &&
		bytes.Equal(a.OwnerRootPublicKey, b.OwnerRootPublicKey) &&
		bytes.Equal(a.PolicyDigest, b.PolicyDigest)
}

func verifyVaultFileBackupCustodySource(source VaultFileBackupCustodySource, expected vaultfile.PolicyCheckpoint) (*vaultfile.File, error) {
	if !validVaultFileBackupCustodyCheckpoint(expected) ||
		source.VaultID == "" || source.VaultID != expected.VaultID ||
		!sameVaultFileBackupCustodyCheckpoint(source.Checkpoint, expected) {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "source scope")
	}
	if source.Checkpoint.PolicySeq != 0 ||
		len(source.Current) == 0 || len(source.Current) > vaultfile.MaxFileBytes ||
		len(source.Origin) > vaultfile.MaxFileBytes {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyLimit, "source bytes")
	}
	if source.ContentSeq > 1 || len(source.JournalRevision) == 0 ||
		source.JournalRevision != source.BackendRevision ||
		len(source.JournalRevision) > vaultfilebackend.MaxRevisionSize {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "source revision")
	}
	if source.Origin == nil {
		if source.ContentSeq != 0 || source.OriginRevision != "" {
			return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "origin shape")
		}
	} else if len(source.Origin) == 0 || source.ContentSeq != 1 || len(source.OriginRevision) == 0 ||
		len(source.OriginRevision) > vaultfilebackend.MaxRevisionSize {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "origin shape")
	}

	current, err := vaultfile.ParseFile(source.Current)
	if err != nil || !vaultFileBackupCustodySupportedContent(current, source.ContentSeq) {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "current format")
	}
	if err := vaultfile.VerifyPolicyCheckpoint(current, &expected); err != nil {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "current proof")
	}
	pin := &vaultfile.GenesisRootPin{
		VaultID: expected.VaultID, OwnerRootKeyID: expected.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(expected.OwnerRootPublicKey),
	}
	defer clear(pin.OwnerRootPublicKey)
	if source.ContentSeq == 0 {
		checkpoint, err := vaultfile.VerifyGenesis(source.Current, pin)
		if err != nil || checkpoint == nil ||
			!sameVaultFileBackupCustodyCheckpoint(*checkpoint, expected) {
			clearVaultFileBackupCustodyCheckpoint(checkpoint)
			return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "origin proof")
		}
		clearVaultFileBackupCustodyCheckpoint(checkpoint)
		return current, nil
	}
	origin, err := vaultfile.ParseFile(source.Origin)
	if err != nil || !vaultFileBackupCustodySupportedContent(origin, 0) {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "origin format")
	}
	checkpoint, err := vaultfile.VerifyGenesis(source.Origin, pin)
	if err != nil || checkpoint == nil ||
		!sameVaultFileBackupCustodyCheckpoint(*checkpoint, expected) {
		clearVaultFileBackupCustodyCheckpoint(checkpoint)
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "origin proof")
	}
	clearVaultFileBackupCustodyCheckpoint(checkpoint)
	if err := vaultfile.VerifyContentTransition(source.Origin, source.Current, &expected); err != nil {
		return nil, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "source transition")
	}
	return current, nil
}

func vaultFileBackupCustodySupportedContent(file *vaultfile.File, contentSeq uint64) bool {
	return file != nil && file.Header.KeyEpoch == 1 &&
		file.Header.PolicySeq == 0 && file.Header.ContentSeq == contentSeq &&
		len(file.SignedPolicyProofs) == 1
}

func bindVaultFileBackupCustodyOwner(owner vaultFileOwnerRecord, projection VaultFileOwnershipPublic,
	expected vaultfile.PolicyCheckpoint, current *vaultfile.File) error {
	if !validVaultFileOwners([]vaultFileOwnerRecord{owner}) ||
		owner.VaultID != expected.VaultID || projection.VaultID != expected.VaultID ||
		projection.OwnerRootKeyID != expected.OwnerRootKeyID ||
		current == nil || len(current.SignedPolicyProofs) != 1 {
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner scope")
	}
	root, err := hex.DecodeString(projection.OwnerRootPublicKey)
	if err != nil || !bytes.Equal(root, expected.OwnerRootPublicKey) {
		clear(root)
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner root")
	}
	clear(root)
	recoveryPublic, err := hex.DecodeString(projection.RecoveryContentSigningPublicKey)
	if err != nil || len(recoveryPublic) != ed25519.PublicKeySize {
		clear(recoveryPublic)
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "owner recovery")
	}
	defer clear(recoveryPublic)

	policy := &current.SignedPolicyProofs[0].Policy
	var recovery, author *vaultfile.Device
	for i := range policy.Devices {
		device := &policy.Devices[i]
		switch device.DeviceID {
		case owner.RecoveryDeviceID:
			recovery = device
		case current.Header.AuthorDeviceID:
			author = device
		}
	}
	if recovery == nil || recovery.ContentSigningKey.Alg != vaultfile.SigAlgEd25519 ||
		!bytes.Equal(recovery.ContentSigningKey.PublicKey, recoveryPublic) ||
		recovery.AgeEncryptionKey != projection.RecoveryAgeRecipient ||
		author == nil || bytes.Equal(author.ContentSigningKey.PublicKey, recoveryPublic) {
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "recovery device")
	}
	writer := false
	for _, member := range policy.Writers {
		writer = writer || member.PrincipalID == recovery.PrincipalID
	}
	if !writer {
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "recovery role")
	}
	return nil
}

func mapVaultFileBackupCustodyChildError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrSessionLocked), errors.Is(err, ErrFullFactorRequired),
		errors.Is(err, ErrVaultFileScopedChild):
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "child")
	default:
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "child")
	}
}

func mapVaultFileBackupCustodySourceError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	case errors.Is(err, ErrVaultFileBaselineVerification):
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "source proof")
	default:
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "source")
	}
}

func sealVaultFileBackupCustodyBytes(plain []byte, recipient age.Recipient) ([]byte, error) {
	if recipient == nil || len(plain) == 0 {
		return nil, ErrVaultFileBackupCustody
	}
	var out bytes.Buffer
	writer, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, ErrVaultFileBackupCustody
	}
	if _, err := writer.Write(plain); err != nil {
		_ = writer.Close()
		return nil, ErrVaultFileBackupCustody
	}
	if err := writer.Close(); err != nil {
		return nil, ErrVaultFileBackupCustody
	}
	return out.Bytes(), nil
}

func openVaultFileBackupCustodyBytes(sealed []byte, identity age.Identity) ([]byte, error) {
	if identity == nil || len(sealed) == 0 {
		return nil, ErrVaultFileBackupCustody
	}
	reader, err := age.Decrypt(bytes.NewReader(sealed), identity)
	if err != nil {
		return nil, ErrVaultFileBackupCustody
	}
	plain, err := io.ReadAll(io.LimitReader(reader, maxVaultFileBackupCustodyPayload+1))
	if err != nil || len(plain) == 0 || len(plain) > maxVaultFileBackupCustodyPayload {
		clear(plain)
		return nil, ErrVaultFileBackupCustody
	}
	return plain, nil
}

func vaultFileBackupCustodySigningMessage(header vaultFileBackupCustodyHeader, sealed []byte) ([sha256.Size]byte, error) {
	raw, err := json.Marshal(header)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(vaultFileBackupCustodyDomain))
	writeVaultFileBackupCustodyBytes(h, raw)
	writeVaultFileBackupCustodyBytes(h, sealed)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func writeVaultFileBackupCustodyString(h io.Writer, value string) {
	writeVaultFileBackupCustodyBytes(h, []byte(value))
}

func writeVaultFileBackupCustodyBytes(h io.Writer, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

func vaultFileBackupCustodyHexSHA256(value []byte) string {
	if value == nil {
		return ""
	}
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func decodeVaultFileBackupCustodyJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrVaultFileBackupCustody
	}
	return nil
}

func vaultFileBackupCustodyError(category error, reason string) error {
	return fmt.Errorf("%w: %s", category, reason)
}
