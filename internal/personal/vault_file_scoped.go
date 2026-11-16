package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

// This file is the personal-vault read-only child session layer. It composes
// the caller-pinned pkg/vaultfile.ScopedUnlock handle and the bounded
// internal/vault item-summary bridge. It deliberately does not call
// OpenVaultFileBaseline, does not re-open the account age identity per read,
// and never returns a KDBX database, a VUK, an age identity, an account factor
// or any private key outside this package.
//
// A child is one per journal path. The parent Session owns the registry, the
// parent revocation flag, a per-Session owner marker and the token generation.
// The child owns only its
// ScopedUnlock handle, its deep-copied checkpoint and a journal baseline
// (generation, remote revision, base/working byte hashes and pending state),
// plus its own full-factor and idle deadlines. It retains no caller password,
// Secret Key, account material, age identity or root private key.
//
// B1 trust boundary: the caller supplies the already-trusted checkpoint. This
// layer proves that the exact journal BaseBytes authenticates under that
// checkpoint and that the local account device can read its real item database.
// It does not discover a vault, bind a genesis/manifest/ownership locator, or
// grant discovery authority. Those bindings belong to the client layer.
//
// Revocation is layered. RequestLock takes only saveMu, sets the irreversible
// parent revocation flag and never takes the registry or a child lock, so it
// cannot wait on a child read or an IO operation. Session.lock drains the
// registry under Session.mu, releases the registry before closing any child,
// and closes every handle. A child-specific lock is a token-generation
// compare-and-remove that does not affect any sibling. Final summary
// disclosure takes the same short saveMu gate as RequestLock and checks both
// the parent revocation flag and the current registry entry.
//
// Lock order is Session.mu -> short saveMu/registry gates -> child.mu. The
// registry lock is always released before close waits on a child, and no path
// holds child.mu while taking Session.mu or saveMu.

var (
	// ErrVaultFileScopedFactors reports that the explicitly supplied full
	// factors do not open the current account slot. It does not lock the
	// session or revoke sibling children.
	ErrVaultFileScopedFactors = errors.New("vault-file scoped child factors rejected")
	// ErrVaultFileScopedChild reports that a child token is closed, superseded,
	// expired, or no longer the current child for its journal path.
	ErrVaultFileScopedChild = errors.New("vault-file scoped child is no longer available")
)

// VaultFileChildOptions selects the only optional summary field. The ID is an
// opaque item selector, not key material.
type VaultFileChildOptions struct {
	IncludeItemIDs bool
}

// vaultFileChildOwner is the per-Session identity marker carried opaquely by
// every child token. It holds no account material, path or key. The blank byte
// makes the type non-zero-sized, so two independent allocations cannot share
// an address the way distinct zero-sized allocations may. It is allocated once
// by newUnlockedSession before the Session is published and is never mutated.
type vaultFileChildOwner struct {
	_ byte
}

// VaultFileChildToken names one registered child generation. It is opaque and
// comparable. Its fields are unexported so a caller cannot construct a token
// for another path, generation or owning Session. owner binds the token to the
// exact Session that registered it, so two Sessions that share one local
// account, parent path, journal path and per-Session generation cannot accept
// each other's tokens.
type VaultFileChildToken struct {
	owner      *vaultFileChildOwner
	path       string
	generation uint64
}

// String and GoString are only redacted display forms.
func (VaultFileChildToken) String() string   { return "[vault-file child token]" }
func (VaultFileChildToken) GoString() string { return "[vault-file child token]" }

// vaultFileOwnedSnapshot is the target-only public ownership snapshot bound to
// one owned child. It never contains a private seed, age identity, account
// material or another vault's record.
type vaultFileOwnedSnapshot struct {
	owner VaultFileOwnershipPublic
}

type vaultFileChild struct {
	mu sync.Mutex

	token  VaultFileChildToken
	handle *vaultfile.ScopedUnlock

	// owned is nil for a generic caller-pinned child. It is non-nil only when
	// this child was registered through OpenOwnedVaultFileChild; the snapshot
	// is immutable and scope failures close only this child.
	owned *vaultFileOwnedSnapshot

	// checkpoint is an independent deep copy of the caller trust pin. B1
	// revalidates scope through the ScopedUnlock built from the same pin; this
	// copy is the per-library baseline the client layer will bind in B2.
	checkpoint vaultfile.PolicyCheckpoint

	// journal baseline: exact state identity, never the bytes themselves.
	journalGeneration uint64
	remoteRevision    string
	baseHash          [sha256.Size]byte
	workingHash       [sha256.Size]byte
	pending           bool

	// Both deadlines are fixed at explicit factor unlock. They are never
	// extended by child reads and never write back to Session.fullUnlock.
	fullFactorDeadline time.Time
	idleDeadline       time.Time

	// closed marks that a first close claimed the handle. closeDone closes only
	// after the real handle.Close has returned, so every later close and the
	// parent drain wait for actual VUK clearing rather than the flag.
	closed    bool
	closeDone chan struct{}
}

func cloneVaultFileCheckpoint(c *vaultfile.PolicyCheckpoint) vaultfile.PolicyCheckpoint {
	if c == nil {
		return vaultfile.PolicyCheckpoint{}
	}
	return vaultfile.PolicyCheckpoint{
		VaultID:            c.VaultID,
		OwnerRootKeyID:     c.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(bytes.Clone(c.OwnerRootPublicKey)),
		PolicySeq:          c.PolicySeq,
		PolicyDigest:       bytes.Clone(c.PolicyDigest),
	}
}

// vaultFileChildReadHook is a narrow private test seam. It receives no
// secret, factor, key or identity and is nil in production. Tests use it to
// hold a summary after real decryption and before final disclosure, so
// RequestLock can be proven non-blocking and the final gate can be proven to
// clear a losing result.
var vaultFileChildReadHook func()

// vaultFileChildBeforeHandleClose is a narrow private test seam. It runs only
// on the first closer, after closed is set and before the real handle.Close.
// It receives no secret and is nil in production. Tests claim it with an
// atomic CAS so a later sibling close returns immediately instead of joining
// the same blocking Once.
var vaultFileChildBeforeHandleClose func()

// vaultFileChildBeforeRegister is a private no-argument seam after explicit
// factor verification and before final parent/slot registration. It carries
// no secret. Tests use it to replace the account slot on disk and prove the
// final real-slot check rejects without leaving a candidate.
var vaultFileChildBeforeRegister func()

// vaultFileChildCandidateReady is a private test seam. It runs after a real
// candidate handle has decrypted the initial summary and the journal has been
// rechecked, but before the final parent/slot/ownership registration gate. It
// carries only the real handle, never key material. Tests use it to change the
// parent, slot or target ownership at the last responsible moment and prove
// the candidate is closed without disclosure. Production leaves it nil.
var vaultFileChildCandidateReady func(*vaultfile.ScopedUnlock)

// vaultFileParentCheckCloseFault is a private fault-injection seam. The real
// read transaction and account database are closed first; a non-nil error is
// then appended by the test to model a close failure. Production leaves it nil,
// so no claim is made that the filesystem itself produced the error.
var vaultFileParentCheckCloseFault func() error

// OpenVaultFileChild explicitly verifies the supplied full password and Secret
// Key against the current account slot and material, authenticates the exact
// existing journal BaseBytes under checkpoint, opens a real item summary once,
// and only then registers a child token. The initial summaries are returned for
// that successful proof; later reads use ReadVaultFileChild.
//
// Every call re-reads and unwraps the account slot. It does not reuse or
// replace a Session, and it does not accept an old Session.fullUnlock as
// factor proof. The new proof is recorded only on the child as a fixed
// passkeyTransferFullFactorWindow deadline; Session.fullUnlock is not modified.
// A wrong factor pair returns ErrVaultFileScopedFactors and leaves siblings
// untouched. A changed or unreadable account slot follows the established
// Session.lock boundary and revokes all children.
//
// The checkpoint is caller-owned trusted state and is deep-copied into the
// child. The journal is opened existing-only and held through the initial real
// summary and a final state recheck. A journal baseline drift, authentication
// failure or bounded-summary failure closes the candidate handle and registers
// nothing. A registered child is only readable through this package; no
// ScopedUnlock leaves it.
func (s *Session) OpenVaultFileChild(journalPath string, checkpoint *vaultfile.PolicyCheckpoint, password, key []byte, options VaultFileChildOptions) (VaultFileChildToken, []VaultFileBaselineItem, error) {
	return s.openVaultFileChild(journalPath, checkpoint, password, key, options, vaultFileChildOpenMode{})
}

// OpenOwnedVaultFileChild is the narrow companion-owned child constructor. It
// proves the same fresh factors and real parent authority as OpenVaultFileChild,
// then authenticates the local account state/audit and the target vault's
// unpublished owner custody before any candidate handle is created. The caller
// checkpoint is only a candidate: its VaultID, owner root key ID and owner root
// public key must match exactly one real local owner record, and only that
// authenticated record supplies root trust. The target record's public custody
// snapshot is bound to the child so later reads cannot cross the owner scope.
//
// The generic OpenVaultFileChild contract remains caller-pinned trust and is
// deliberately unchanged; an owned child adds this local-custody proof and a
// nil owned snapshot means the child is generic. No account material, owner
// seed, age identity or other vault record is retained by the child.
func (s *Session) OpenOwnedVaultFileChild(journalPath string, checkpoint *vaultfile.PolicyCheckpoint, password, key []byte, options VaultFileChildOptions) (VaultFileChildToken, []VaultFileBaselineItem, error) {
	return s.openVaultFileChild(journalPath, checkpoint, password, key, options, vaultFileChildOpenMode{owned: true})
}

type vaultFileChildOpenMode struct {
	owned bool
}

func (s *Session) openVaultFileChild(journalPath string, checkpoint *vaultfile.PolicyCheckpoint, password, key []byte, options VaultFileChildOptions, mode vaultFileChildOpenMode) (VaultFileChildToken, []VaultFileBaselineItem, error) {
	if s == nil {
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	if checkpoint == nil || journalPath == "" {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineVerification
	}

	// Snapshot the parent's authority, activity deadline and slot/material
	// identity. The expensive slot unwrap and KDF run outside Session.mu.
	s.mu.Lock()
	if err := s.active(true); err != nil {
		s.mu.Unlock()
		return VaultFileChildToken{}, nil, err
	}
	parentOwner := s.vaultFileOwner
	if parentOwner == nil {
		s.mu.Unlock()
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	parentMaterial := bytes.Clone(s.material)
	parentSlot := s.slotDigest
	parentPath := s.path
	idleDeadline, hasIdle := s.idleDeadline()
	fullFactorDeadline := time.Now().Add(passkeyTransferFullFactorWindow)
	s.mu.Unlock()
	defer clear(parentMaterial)
	if len(parentMaterial) == 0 {
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}

	// Re-enter the complete full factors and prove they open this exact
	// current account slot and material. A wrong pair is isolated to this
	// attempt; a changed slot follows the existing Session.lock boundary.
	factorErr := verifyVaultFileChildFactors(parentPath, parentSlot, parentMaterial, password, key)
	switch {
	case errors.Is(factorErr, errVaultFileChildWrongFactors):
		return VaultFileChildToken{}, nil, ErrVaultFileScopedFactors
	case errors.Is(factorErr, errVaultFileChildInvalidSlot):
		s.lockVaultFileParent()
		return VaultFileChildToken{}, nil, ErrSessionLocked
	case factorErr != nil:
		s.lockVaultFileParent()
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	if vaultFileChildBeforeRegister != nil {
		vaultFileChildBeforeRegister()
	}

	var ownedSnapshot *vaultFileOwnedSnapshot
	if mode.owned {
		snapshot, ownedErr := s.authenticateVaultFileOwnedTarget(parentPath, password, key, checkpoint.VaultID)
		switch {
		case errors.Is(ownedErr, errVaultFileChildInvalidSlot):
			s.lockVaultFileParent()
			return VaultFileChildToken{}, nil, ErrSessionLocked
		case ownedErr != nil && !errors.Is(ownedErr, ErrVaultFileOwnership):
			s.lockVaultFileParent()
			return VaultFileChildToken{}, nil, ErrSessionLocked
		case ownedErr != nil:
			return VaultFileChildToken{}, nil, ErrVaultFileOwnership
		}
		if !vaultFileOwnedSnapshotMatchesCheckpoint(snapshot, checkpoint) {
			return VaultFileChildToken{}, nil, ErrVaultFileOwnership
		}
		ownedSnapshot = &vaultFileOwnedSnapshot{owner: snapshot}
	}

	// Parse the local account identity only after the factors are proven.
	// It is transient and cleared before any child is returned.
	var accountIdentity identity
	if err := json.Unmarshal(parentMaterial, &accountIdentity); err != nil ||
		len(accountIdentity.Signing) != ed25519.SeedSize || accountIdentity.Device == "" {
		accountIdentity.clear()
		accountIdentity.Device = ""
		s.lockVaultFileParent()
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	defer func() {
		accountIdentity.clear()
		accountIdentity.Device = ""
	}()
	localAge, err := age.ParseX25519Identity(accountIdentity.Device)
	if err != nil {
		s.lockVaultFileParent()
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	signer := ed25519.NewKeyFromSeed(accountIdentity.Signing)
	defer clear(signer)

	journal, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineJournal
	}
	defer func() { _ = journal.Close() }()
	baseline, baseBytes, err := loadVaultFileJournalBaseline(journal)
	if err != nil {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineJournal
	}
	defer clear(baseBytes)
	if len(baseBytes) == 0 {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineJournal
	}

	file, err := vaultfile.ParseFile(baseBytes)
	if err != nil || vaultfile.VerifyPolicyCheckpoint(file, checkpoint) != nil ||
		file.Header.VaultID != checkpoint.VaultID || len(file.SignedPolicyProofs) == 0 {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineVerification
	}
	policy := &file.SignedPolicyProofs[len(file.SignedPolicyProofs)-1].Policy
	if policy.PolicySeq != file.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(policy), file.Header.PolicyDigest) {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineVerification
	}
	deviceID, ok := localVaultFileReaderDevice(policy, localAge.Recipient().String(), signer.Public().(ed25519.PublicKey))
	if !ok {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineVerification
	}

	handle, err := vaultfile.NewScopedUnlock(baseBytes, checkpoint, deviceID, localAge)
	if err != nil {
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineVerification
	}

	// The real summary is the registration proof. It opens the actual KDBX
	// through the handle's cached VUK and the shared item-database reader.
	initial, err := vault.ReadScopedItemSummaries(handle, baseBytes, vault.ItemSummaryOptions{IncludeID: options.IncludeItemIDs})
	if err != nil {
		_ = handle.Close()
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineVerification
	}
	initialItems := vaultFileChildItems(initial)

	// Recheck the still-locked journal after decryption. A cooperating writer
	// cannot change the state under this held lock, and a non-cooperating
	// drift is refused rather than registered.
	if err := journalMatchesExpected(journal, baseline); err != nil {
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineJournal
	}
	if err := journal.Close(); err != nil {
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, ErrVaultFileBaselineJournal
	}
	if vaultFileChildCandidateReady != nil {
		vaultFileChildCandidateReady(handle)
	}

	// Final registration holds Session.mu, then a real read-only account
	// transaction, then the short saveMu/registry gate. Holding Session.mu
	// freezes active/idle/material state, and the held read transaction stops
	// a cooperating slot writer from crossing the check into registration.
	s.mu.Lock()
	if err := s.active(false); err != nil {
		s.mu.Unlock()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, err
	}
	if s.path != parentPath || s.slotDigest != parentSlot ||
		s.vaultFileOwner != parentOwner ||
		subtle.ConstantTimeCompare(s.material, parentMaterial) != 1 {
		s.lock()
		s.mu.Unlock()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	parentCheck, err := s.openVaultFileParentCheckLocked()
	if err != nil {
		s.lock()
		s.mu.Unlock()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	if ownedSnapshot != nil {
		ownedErr := s.verifyOwnedVaultFileTargetLocked(parentCheck, ownedSnapshot.owner)
		if ownedErr != nil {
			s.mu.Unlock()
			clearVaultFileChildItems(initialItems)
			closeErr := parentCheck.close()
			_ = handle.Close()
			if closeErr != nil || errors.Is(ownedErr, errVaultFileChildInvalidSlot) {
				s.lockVaultFileParent()
				return VaultFileChildToken{}, nil, ErrSessionLocked
			}
			return VaultFileChildToken{}, nil, ErrVaultFileOwnership
		}
	}

	now := time.Now()
	s.saveMu.Lock()
	if s.vaultFileRevoked.Load() || s.lockRequested.Load() || parentCheck.idleExpired(now) {
		s.saveMu.Unlock()
		s.mu.Unlock()
		_ = parentCheck.close()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		s.lockVaultFileParent()
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	s.vaultFileMu.Lock()
	if s.vaultFileChildren == nil {
		s.vaultFileChildren = make(map[string]*vaultFileChild)
	}
	generation := s.vaultFileNext.Add(1)
	if generation == 0 {
		s.vaultFileMu.Unlock()
		s.saveMu.Unlock()
		s.mu.Unlock()
		closeErr := parentCheck.close()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		if closeErr != nil {
			s.lockVaultFileParent()
			return VaultFileChildToken{}, nil, ErrSessionLocked
		}
		return VaultFileChildToken{}, nil, ErrVaultFileScopedChild
	}
	token := VaultFileChildToken{owner: parentOwner, path: journalPath, generation: generation}
	child := &vaultFileChild{
		token:              token,
		handle:             handle,
		owned:              ownedSnapshot,
		closeDone:          make(chan struct{}),
		checkpoint:         cloneVaultFileCheckpoint(checkpoint),
		journalGeneration:  baseline.generation,
		remoteRevision:     baseline.remoteRevision,
		baseHash:           baseline.baseHash,
		workingHash:        baseline.workingHash,
		pending:            baseline.pending,
		fullFactorDeadline: fullFactorDeadline,
	}
	if hasIdle {
		child.idleDeadline = idleDeadline
	}
	if s.vaultFileAll == nil {
		s.vaultFileAll = make(map[*vaultFileChild]struct{})
	}
	old := s.vaultFileChildren[journalPath]
	s.vaultFileChildren[journalPath] = child
	s.vaultFileAll[child] = struct{}{}
	s.vaultFileMu.Unlock()
	s.saveMu.Unlock()
	s.mu.Unlock()

	// DB close is outside saveMu. Any close failure must not leave the new
	// candidate registered or return a plaintext summary.
	if err := parentCheck.close(); err != nil {
		clearVaultFileChildItems(initialItems)
		s.lockVaultFileParent()
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}

	// Superseded candidates are closed, never merely dropped. This is outside
	// every gate so a late reader can finish and observe the new generation.
	if old != nil {
		s.retireVaultFileChild(old)
	}
	return token, initialItems, nil
}

// ReadVaultFileChild returns bounded item summaries from the exact existing
// journal BaseBytes of the current token. Before the child is even classified
// it rechecks current parent active state and the real account slot bytes, and
// it repeats that check under a held read-only account transaction before the
// final disclosure. It also rechecks the child deadline, the journal
// generation/revision/byte hashes and pending state before and after the real
// summary, and then passes the final disclosure through the same short saveMu
// gate as RequestLock. Parent failure drains every child and clears the
// summary; child-specific lock, supersession, journal drift or suite expiry
// invalidates only this child.
func (s *Session) ReadVaultFileChild(token VaultFileChildToken, options VaultFileChildOptions) ([]VaultFileBaselineItem, error) {
	// A foreign-owner token, a zero token or a zero Session is a child error.
	// This is decided before any parent IO or authorization side effect so a
	// different Session can never classify, read or drain this Session.
	if s == nil || token.generation == 0 || token.path == "" ||
		token.owner == nil || s.vaultFileOwner == nil || token.owner != s.vaultFileOwner {
		return nil, ErrVaultFileScopedChild
	}
	if s.vaultFileRevoked.Load() {
		return nil, ErrSessionLocked
	}

	// Parent authority and the real slot digest are checked before the child's
	// own deadline, so a failed parent drains every sibling even when this
	// particular child also happens to be expired.
	s.mu.Lock()
	if err := s.active(false); err != nil {
		s.mu.Unlock()
		return nil, ErrSessionLocked
	}
	parentCheck, err := s.openVaultFileParentCheckLocked()
	if err != nil {
		s.lock()
		s.mu.Unlock()
		return nil, ErrSessionLocked
	}
	s.mu.Unlock()
	if err := parentCheck.close(); err != nil {
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	}

	child, err := s.snapshotVaultFileChild(token)
	if err != nil {
		return nil, err
	}
	if err := child.deadlineError(time.Now()); err != nil {
		s.invalidateVaultFileChild(child)
		return nil, err
	}
	handle, err := child.readHandle()
	if err != nil {
		s.invalidateVaultFileChild(child)
		return nil, err
	}

	journal, err := vaultfilejournal.OpenExisting(token.path)
	if err != nil {
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileBaselineJournal
	}
	defer func() { _ = journal.Close() }()
	if err := journalMatchesChild(journal, child); err != nil {
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileBaselineJournal
	}
	_, baseBytes, err := loadVaultFileJournalBaseline(journal)
	if err != nil {
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileBaselineJournal
	}
	defer clear(baseBytes)
	if s.vaultFileRevoked.Load() {
		s.invalidateVaultFileChild(child)
		return nil, ErrSessionLocked
	}

	summaries, err := vault.ReadScopedItemSummaries(handle, baseBytes, vault.ItemSummaryOptions{IncludeID: options.IncludeItemIDs})
	if err != nil {
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileBaselineVerification
	}
	items := vaultFileChildItems(summaries)
	if vaultFileChildReadHook != nil {
		vaultFileChildReadHook()
	}
	if err := journalMatchesChild(journal, child); err != nil {
		_ = journal.Close()
		clearVaultFileChildItems(items)
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileBaselineJournal
	}
	if err := journal.Close(); err != nil {
		clearVaultFileChildItems(items)
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileBaselineJournal
	}

	// Final parent authority is checked again under Session.mu with a real
	// read-only account transaction held through the saveMu gate. This makes a
	// late slot replacement or lowered idle deadline win over the already
	// decrypted summary.
	s.mu.Lock()
	if err := s.active(false); err != nil {
		s.mu.Unlock()
		clearVaultFileChildItems(items)
		return nil, ErrSessionLocked
	}
	parentCheck, err = s.openVaultFileParentCheckLocked()
	if err != nil {
		s.lock()
		s.mu.Unlock()
		clearVaultFileChildItems(items)
		return nil, ErrSessionLocked
	}
	// An owned child remains owner-bound even through the generic read method.
	// The authenticated target snapshot is rechecked under the same held RO
	// transaction before disclosure; a target-only drift closes this child,
	// while an account-level authentication failure follows the parent drain.
	if child.owned != nil {
		ownedErr := s.verifyOwnedVaultFileTargetLocked(parentCheck, child.owned.owner)
		if ownedErr != nil {
			s.mu.Unlock()
			clearVaultFileChildItems(items)
			closeErr := parentCheck.close()
			s.invalidateVaultFileChild(child)
			if closeErr != nil || errors.Is(ownedErr, errVaultFileChildInvalidSlot) {
				s.lockVaultFileParent()
				return nil, ErrSessionLocked
			}
			return nil, ErrVaultFileOwnership
		}
	}
	now := time.Now()
	s.saveMu.Lock()
	revoked := s.vaultFileRevoked.Load()
	parentExpired := parentCheck.idleExpired(now)
	s.vaultFileMu.Lock()
	current := s.vaultFileChildren[token.path]
	s.vaultFileMu.Unlock()
	s.saveMu.Unlock()
	s.mu.Unlock()
	if revoked || parentExpired {
		clearVaultFileChildItems(items)
		_ = parentCheck.close()
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	}
	if current != child || child.expired(now) {
		clearVaultFileChildItems(items)
		if closeErr := parentCheck.close(); closeErr != nil {
			s.lockVaultFileParent()
			return nil, ErrSessionLocked
		}
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileScopedChild
	}
	if err := parentCheck.close(); err != nil {
		clearVaultFileChildItems(items)
		s.lockVaultFileParent()
		return nil, ErrSessionLocked
	}
	return items, nil
}

// RevalidateVaultFileChildOwnership rechecks the local owner custody bound to
// an already registered owned child. It never re-unwraps the account slot,
// never extends a factor or idle proof and never promotes a generic child: a
// generic token or a child without an owned snapshot returns
// ErrVaultFileScopedChild. The token's parent marker, generation and current
// registry entry, the child's fixed deadline, the parent active/slot state and
// the target-only authenticated owner snapshot are all checked. A missing or
// changed target record closes only that child; an account-level slot, audit or
// ownership-store failure follows the B1 parent drain.
func (s *Session) RevalidateVaultFileChildOwnership(token VaultFileChildToken) error {
	if s == nil || token.generation == 0 || token.path == "" ||
		token.owner == nil || s.vaultFileOwner == nil || token.owner != s.vaultFileOwner {
		return ErrVaultFileScopedChild
	}
	if s.vaultFileRevoked.Load() {
		return ErrSessionLocked
	}

	s.mu.Lock()
	if err := s.active(false); err != nil {
		s.mu.Unlock()
		return ErrSessionLocked
	}
	parentCheck, err := s.openVaultFileParentCheckLocked()
	if err != nil {
		s.lock()
		s.mu.Unlock()
		return ErrSessionLocked
	}
	child, err := s.snapshotVaultFileChild(token)
	if err != nil {
		s.mu.Unlock()
		if closeErr := parentCheck.close(); closeErr != nil {
			s.lockVaultFileParent()
			return ErrSessionLocked
		}
		return err
	}
	if child.owned == nil {
		s.mu.Unlock()
		if closeErr := parentCheck.close(); closeErr != nil {
			s.lockVaultFileParent()
			return ErrSessionLocked
		}
		return ErrVaultFileScopedChild
	}
	if err := child.deadlineError(time.Now()); err != nil {
		s.mu.Unlock()
		closeErr := parentCheck.close()
		s.invalidateVaultFileChild(child)
		if closeErr != nil {
			s.lockVaultFileParent()
			return ErrSessionLocked
		}
		return err
	}
	ownedErr := s.verifyOwnedVaultFileTargetLocked(parentCheck, child.owned.owner)
	if ownedErr != nil {
		s.mu.Unlock()
		closeErr := parentCheck.close()
		if errors.Is(ownedErr, errVaultFileChildInvalidSlot) || closeErr != nil {
			s.lockVaultFileParent()
			return ErrSessionLocked
		}
		s.invalidateVaultFileChild(child)
		return ErrVaultFileOwnership
	}

	now := time.Now()
	s.saveMu.Lock()
	revoked := s.vaultFileRevoked.Load()
	parentExpired := parentCheck.idleExpired(now)
	s.vaultFileMu.Lock()
	current := s.vaultFileChildren[token.path]
	s.vaultFileMu.Unlock()
	s.saveMu.Unlock()
	s.mu.Unlock()
	if revoked || parentExpired {
		_ = parentCheck.close()
		s.lockVaultFileParent()
		return ErrSessionLocked
	}
	if current != child || child.expired(now) {
		if closeErr := parentCheck.close(); closeErr != nil {
			s.lockVaultFileParent()
			return ErrSessionLocked
		}
		s.invalidateVaultFileChild(child)
		return ErrVaultFileScopedChild
	}
	if err := parentCheck.close(); err != nil {
		s.lockVaultFileParent()
		return ErrSessionLocked
	}
	return nil
}

// LockVaultFileChild revokes one token generation. It never changes the parent
// revocation flag, never locks a sibling and never waits on IO. A stale token
// (for example an old A after A was closed and reopened) is a no-op and cannot
// remove the new generation.
func (s *Session) LockVaultFileChild(token VaultFileChildToken) error {
	// A foreign-owner token is a no-op: it must not touch the victim child or
	// any sibling even when path and per-Session generation happen to match.
	if s == nil || token.generation == 0 || token.path == "" ||
		token.owner == nil || s.vaultFileOwner == nil || token.owner != s.vaultFileOwner {
		return nil
	}
	s.saveMu.Lock()
	if s.vaultFileRevoked.Load() {
		s.saveMu.Unlock()
		return nil
	}
	s.vaultFileMu.Lock()
	child := s.vaultFileChildren[token.path]
	if child == nil || child.token != token {
		s.vaultFileMu.Unlock()
		s.saveMu.Unlock()
		return nil
	}
	delete(s.vaultFileChildren, token.path)
	s.vaultFileMu.Unlock()
	s.saveMu.Unlock()
	s.retireVaultFileChild(child)
	return nil
}

func (s *Session) snapshotVaultFileChild(token VaultFileChildToken) (*vaultFileChild, error) {
	s.vaultFileMu.Lock()
	child := s.vaultFileChildren[token.path]
	s.vaultFileMu.Unlock()
	if child == nil || child.token != token {
		return nil, ErrVaultFileScopedChild
	}
	return child, nil
}

func (s *Session) invalidateVaultFileChild(child *vaultFileChild) {
	if child == nil {
		return
	}
	s.vaultFileMu.Lock()
	if s.vaultFileChildren[child.token.path] == child {
		delete(s.vaultFileChildren, child.token.path)
	}
	s.vaultFileMu.Unlock()
	s.retireVaultFileChild(child)
}

// lockVaultFileParent follows the existing Session.lock boundary after an
// invalid current account slot or material. It is never called while holding
// Session.mu.
func (s *Session) lockVaultFileParent() {
	s.mu.Lock()
	s.lock()
	s.mu.Unlock()
}

// drainVaultFileChildren is called by Session.lock while Session.mu may be
// held. It releases the registry lock before waiting on any child, and a child
// close completion never re-acquires Session.mu. The prohibition is that
// Close completion must not re-take parent.mu; it is not a claim that
// Session.mu is never held during the drain.
func (s *Session) drainVaultFileChildren() {
	s.vaultFileMu.Lock()
	children := make([]*vaultFileChild, 0, len(s.vaultFileAll))
	for child := range s.vaultFileAll {
		children = append(children, child)
	}
	s.vaultFileChildren = make(map[string]*vaultFileChild)
	s.vaultFileMu.Unlock()
	for _, child := range children {
		s.retireVaultFileChild(child)
	}
}

// retireVaultFileChild is the single completion path shared by replacement,
// LockVaultFileChild, invalidation and parent drain. The child stays in the
// all set until the real handle.Close has returned, so the parent cannot return
// while a retiring child still owns a VUK. This function never takes
// Session.mu or saveMu.
func (s *Session) retireVaultFileChild(child *vaultFileChild) {
	if child == nil {
		return
	}
	child.close()
	s.vaultFileMu.Lock()
	delete(s.vaultFileAll, child)
	s.vaultFileMu.Unlock()
}

// close revokes the handle and waits for the actual handle.Close. The first
// closer sets closed, runs the private seam and closes the handle outside
// child.mu; later closers wait on closeDone. child.mu is never held while
// waiting, so completion cleanup can never try to take Session.mu.
func (c *vaultFileChild) close() {
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	c.closed = true
	if c.closeDone == nil {
		c.closeDone = make(chan struct{})
	}
	done := c.closeDone
	handle := c.handle
	c.mu.Unlock()
	if vaultFileChildBeforeHandleClose != nil {
		vaultFileChildBeforeHandleClose()
	}
	if handle != nil {
		_ = handle.Close()
	}
	c.mu.Lock()
	close(done)
	c.mu.Unlock()
}

func (c *vaultFileChild) readHandle() (*vaultfile.ScopedUnlock, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.handle == nil {
		return nil, ErrVaultFileScopedChild
	}
	return c.handle, nil
}

func (c *vaultFileChild) expired(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return true
	}
	if !c.fullFactorDeadline.IsZero() && !now.Before(c.fullFactorDeadline) {
		return true
	}
	if !c.idleDeadline.IsZero() && !now.Before(c.idleDeadline) {
		return true
	}
	return false
}

func (c *vaultFileChild) deadlineError(now time.Time) error {
	if c.expired(now) {
		return ErrVaultFileScopedChild
	}
	return nil
}

// errVaultFileChildWrongFactors and errVaultFileChildInvalidSlot are internal
// classifications. A wrong factor pair is isolated; a changed/unreadable slot
// or material triggers the existing full Session lock.
var (
	errVaultFileChildWrongFactors = errors.New("vault-file child factors do not open the slot")
	errVaultFileChildInvalidSlot  = errors.New("vault-file child account slot is invalid")
)

func verifyVaultFileChildFactors(path string, slotDigest [32]byte, material, password, key []byte) error {
	if len(key) != 16 {
		return errVaultFileChildWrongFactors
	}
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		// The account slot cannot be read at all. This is parent failure, not
		// an isolated wrong-factor attempt, so the caller must drain.
		return errVaultFileChildInvalidSlot
	}
	viewErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return errVaultFileChildInvalidSlot
		}
		raw := b.Get(slotKey)
		if len(raw) == 0 || len(raw) > 8192 {
			return errVaultFileChildInvalidSlot
		}
		if sha256.Sum256(raw) != slotDigest {
			return errVaultFileChildInvalidSlot
		}
		var slot account.Slot
		if json.Unmarshal(raw, &slot) != nil {
			return errVaultFileChildInvalidSlot
		}
		opened, err := account.Unwrap(string(password), key, slot)
		defer clear(opened)
		if err != nil {
			return errVaultFileChildWrongFactors
		}
		if subtle.ConstantTimeCompare(opened, material) != 1 {
			return errVaultFileChildInvalidSlot
		}
		return nil
	})
	if closeErr := db.Close(); closeErr != nil {
		// A close failure makes the slot result untrustworthy even when the
		// factors looked wrong. Drain the parent; do not isolate it.
		return errVaultFileChildInvalidSlot
	}
	if viewErr != nil {
		if errors.Is(viewErr, errVaultFileChildWrongFactors) ||
			errors.Is(viewErr, errVaultFileChildInvalidSlot) {
			return viewErr
		}
		return errVaultFileChildInvalidSlot
	}
	return nil
}

// authenticateVaultFileOwnedTarget authenticates the real account state and
// audit with the same freshly supplied factors, then returns the unique public
// custody projection for vaultID. It never trusts the candidate checkpoint for
// ownership and clears every private owner record before returning.
func (s *Session) authenticateVaultFileOwnedTarget(path string, password, key []byte, vaultID string) (VaultFileOwnershipPublic, error) {
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		return VaultFileOwnershipPublic{}, errVaultFileChildInvalidSlot
	}
	var snapshot VaultFileOwnershipPublic
	viewErr := db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, string(password), key, vaultFileOwnerListAction, nil, false)
		if err != nil {
			return errVaultFileChildInvalidSlot
		}
		defer auth.clear()
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return errVaultFileChildInvalidSlot
		}
		defer clearVaultFileOwners(records)
		snapshot, err = vaultFileOwnedProjection(records, vaultID)
		return err
	})
	if closeErr := db.Close(); closeErr != nil {
		return VaultFileOwnershipPublic{}, errVaultFileChildInvalidSlot
	}
	if viewErr != nil {
		return VaultFileOwnershipPublic{}, viewErr
	}
	return snapshot, nil
}

// verifyOwnedVaultFileTargetLocked re-authenticates the current target owner
// record under the caller's already-held parent RO transaction and compares it
// with the target-only creation snapshot. The caller holds Session.mu; this
// function must be called before saveMu is taken.
func (s *Session) verifyOwnedVaultFileTargetLocked(check *vaultFileParentCheck, expected VaultFileOwnershipPublic) error {
	if check == nil || check.tx == nil || expected.VaultID == "" {
		return errVaultFileChildInvalidSlot
	}
	auth, err := authenticateStateItems(check.tx, "", nil, vaultFileOwnerListAction, s, false)
	if err != nil {
		return errVaultFileChildInvalidSlot
	}
	defer auth.clear()
	records, err := loadVaultFileOwners(check.tx.Bucket(bucket), auth.identity, auth.rows)
	if err != nil {
		return errVaultFileChildInvalidSlot
	}
	defer clearVaultFileOwners(records)
	current, err := vaultFileOwnedProjection(records, expected.VaultID)
	if err != nil {
		return err
	}
	if current != expected {
		return ErrVaultFileOwnership
	}
	return nil
}

// vaultFileOwnedProjection selects exactly one record for the target vault and
// returns only its public projection. A missing target is a target-scope
// failure; duplicate or invalid records are account-store failures.
func vaultFileOwnedProjection(records []vaultFileOwnerRecord, vaultID string) (VaultFileOwnershipPublic, error) {
	var out VaultFileOwnershipPublic
	found := false
	for _, record := range records {
		if record.VaultID != vaultID {
			continue
		}
		if found {
			return VaultFileOwnershipPublic{}, errVaultFileChildInvalidSlot
		}
		projection, err := vaultFileOwnerPublic(record)
		if err != nil {
			return VaultFileOwnershipPublic{}, errVaultFileChildInvalidSlot
		}
		out = projection
		found = true
	}
	if !found {
		return VaultFileOwnershipPublic{}, ErrVaultFileOwnership
	}
	return out, nil
}

// vaultFileOwnedSnapshotMatchesCheckpoint binds the candidate checkpoint to
// the authenticated target owner record. The candidate still supplies the
// policy pin; only its vault ID and root identity are checked against local
// custody here.
func vaultFileOwnedSnapshotMatchesCheckpoint(snapshot VaultFileOwnershipPublic, checkpoint *vaultfile.PolicyCheckpoint) bool {
	if checkpoint == nil || snapshot.VaultID != checkpoint.VaultID ||
		snapshot.OwnerRootKeyID != checkpoint.OwnerRootKeyID {
		return false
	}
	root, err := hex.DecodeString(snapshot.OwnerRootPublicKey)
	if err != nil {
		return false
	}
	defer clear(root)
	return bytes.Equal(root, checkpoint.OwnerRootPublicKey)
}

// vaultFileParentCheck holds a real read-only account transaction open so a
// cooperating writer cannot replace the slot between the digest check and the
// short saveMu gate. It is created only while Session.mu is held (Session.mu ->
// RO account DB); it is closed only after saveMu and Session.mu are released.
type vaultFileParentCheck struct {
	db           *bolt.DB
	tx           *bolt.Tx
	idleDeadline time.Time
	hasIdle      bool
}

// openVaultFileParentCheckLocked reads the current slot bytes under an open
// read transaction. The caller holds Session.mu and has already checked
// active(false). The returned transaction must be closed outside saveMu.
func (s *Session) openVaultFileParentCheckLocked() (*vaultFileParentCheck, error) {
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return nil, ErrSessionLocked
	}
	tx, err := db.Begin(false)
	if err != nil {
		_ = db.Close()
		return nil, ErrSessionLocked
	}
	b := tx.Bucket(bucket)
	if b == nil {
		_ = tx.Rollback()
		_ = db.Close()
		return nil, ErrSessionLocked
	}
	raw := b.Get(slotKey)
	if len(raw) == 0 || len(raw) > 8192 || sha256.Sum256(raw) != s.slotDigest {
		_ = tx.Rollback()
		_ = db.Close()
		return nil, ErrSessionLocked
	}
	idleDeadline, hasIdle := s.idleDeadline()
	return &vaultFileParentCheck{db: db, tx: tx, idleDeadline: idleDeadline, hasIdle: hasIdle}, nil
}

// close releases the read transaction and account database. It must be called
// with saveMu and Session.mu released. A real close error (or the private
// test-injected close fault) is returned; callers then take the parent lock
// boundary so no candidate or summary survives.
func (c *vaultFileParentCheck) close() error {
	if c == nil {
		return nil
	}
	var err error
	if c.tx != nil {
		err = c.tx.Rollback()
		c.tx = nil
	}
	if c.db != nil {
		if closeErr := c.db.Close(); err == nil {
			err = closeErr
		}
		c.db = nil
	}
	if vaultFileParentCheckCloseFault != nil {
		if fault := vaultFileParentCheckCloseFault(); fault != nil {
			err = fault
		}
	}
	return err
}

func (c *vaultFileParentCheck) idleExpired(now time.Time) bool {
	return c != nil && c.hasIdle && !now.Before(c.idleDeadline)
}

type vaultFileJournalBaseline struct {
	generation     uint64
	remoteRevision string
	baseHash       [sha256.Size]byte
	workingHash    [sha256.Size]byte
	pending        bool
}

func loadVaultFileJournalBaseline(j *vaultfilejournal.Journal) (vaultFileJournalBaseline, []byte, error) {
	var baseline vaultFileJournalBaseline
	state, err := j.LoadState()
	if err != nil {
		return baseline, nil, err
	}
	defer func() {
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
	}()
	if len(state.BaseBytes) == 0 || len(state.WorkingBytes) == 0 || state.RemoteRevision == "" {
		return baseline, nil, vaultfilejournal.ErrInvalid
	}
	baseline.generation = state.Generation
	baseline.remoteRevision = string(state.RemoteRevision)
	baseline.baseHash = sha256.Sum256(state.BaseBytes)
	baseline.workingHash = sha256.Sum256(state.WorkingBytes)
	baseline.pending, err = vaultFileJournalPending(j)
	if err != nil {
		return baseline, nil, err
	}
	return baseline, bytes.Clone(state.BaseBytes), nil
}

func vaultFileJournalPending(j *vaultfilejournal.Journal) (bool, error) {
	prepared, err := j.LoadPrepared()
	if err == nil {
		clear(prepared.Proposal.Bytes)
		return true, nil
	}
	if !errors.Is(err, vaultfilejournal.ErrEmpty) {
		return false, err
	}
	proposal, err := j.Load()
	if err == nil {
		clear(proposal.Bytes)
		return true, nil
	}
	if !errors.Is(err, vaultfilejournal.ErrEmpty) {
		return false, err
	}
	return false, nil
}

func journalMatchesChild(j *vaultfilejournal.Journal, child *vaultFileChild) error {
	return journalMatchesExpected(j, vaultFileJournalBaseline{
		generation:     child.journalGeneration,
		remoteRevision: child.remoteRevision,
		baseHash:       child.baseHash,
		workingHash:    child.workingHash,
		pending:        child.pending,
	})
}

func journalMatchesExpected(j *vaultfilejournal.Journal, expected vaultFileJournalBaseline) error {
	baseline, base, err := loadVaultFileJournalBaseline(j)
	if err != nil {
		return err
	}
	clear(base)
	if baseline.generation != expected.generation ||
		baseline.remoteRevision != expected.remoteRevision ||
		baseline.baseHash != expected.baseHash ||
		baseline.workingHash != expected.workingHash ||
		baseline.pending != expected.pending {
		return ErrVaultFileBaselineJournal
	}
	return nil
}

func vaultFileChildItems(items []vault.ItemSummary) []VaultFileBaselineItem {
	out := make([]VaultFileBaselineItem, len(items))
	for i := range items {
		out[i] = VaultFileBaselineItem{ID: items[i].ID, Title: items[i].Title, Category: items[i].Category}
	}
	for i := range items {
		items[i] = vault.ItemSummary{}
	}
	return out
}

func clearVaultFileChildItems(items []VaultFileBaselineItem) {
	for i := range items {
		items[i] = VaultFileBaselineItem{}
	}
}
