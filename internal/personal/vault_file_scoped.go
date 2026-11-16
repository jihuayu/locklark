package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
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
// parent revocation flag and the token generation. The child owns only its
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

// VaultFileChildToken names one registered child generation. It is opaque and
// comparable. Its fields are unexported so a caller cannot construct a token
// for another path or generation.
type VaultFileChildToken struct {
	path       string
	generation uint64
}

// String and GoString are only redacted display forms.
func (VaultFileChildToken) String() string   { return "[vault-file child token]" }
func (VaultFileChildToken) GoString() string { return "[vault-file child token]" }

type vaultFileChild struct {
	mu sync.Mutex

	token  VaultFileChildToken
	handle *vaultfile.ScopedUnlock

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

	closed bool
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
		return VaultFileChildToken{}, nil, ErrSessionLocked
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

	// Final parent check and registration share the same short saveMu gate
	// as RequestLock. No child lock is held and no IO occurs in this gate.
	s.mu.Lock()
	if err := s.active(false); err != nil {
		s.mu.Unlock()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, err
	}
	if s.path != parentPath || s.slotDigest != parentSlot ||
		subtle.ConstantTimeCompare(s.material, parentMaterial) != 1 {
		s.lock()
		s.mu.Unlock()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, ErrSessionLocked
	}
	s.saveMu.Lock()
	if s.vaultFileRevoked.Load() || s.lockRequested.Load() {
		s.saveMu.Unlock()
		s.mu.Unlock()
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
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
		_ = handle.Close()
		clearVaultFileChildItems(initialItems)
		return VaultFileChildToken{}, nil, ErrVaultFileScopedChild
	}
	token := VaultFileChildToken{path: journalPath, generation: generation}
	child := &vaultFileChild{
		token:              token,
		handle:             handle,
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
	old := s.vaultFileChildren[journalPath]
	s.vaultFileChildren[journalPath] = child
	s.vaultFileMu.Unlock()
	s.saveMu.Unlock()
	s.mu.Unlock()

	// Superseded candidates are closed, never merely dropped. This is outside
	// every gate so a late reader can finish and observe the new generation.
	if old != nil {
		old.close()
	}
	return token, initialItems, nil
}

// ReadVaultFileChild returns bounded item summaries from the exact existing
// journal BaseBytes of the current token. It rechecks the parent revocation
// flag, the child deadline, the journal generation/revision/byte hashes and
// pending state before and after the real summary, and then passes the final
// disclosure through the same short saveMu gate as RequestLock. A revocation
// that wins there clears the summaries and returns an error. A child-specific
// lock, supersession or suite expiry invalidates only this child.
func (s *Session) ReadVaultFileChild(token VaultFileChildToken, options VaultFileChildOptions) ([]VaultFileBaselineItem, error) {
	if s == nil || token.generation == 0 || token.path == "" {
		return nil, ErrVaultFileScopedChild
	}
	if s.vaultFileRevoked.Load() {
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

	now := time.Now()
	s.saveMu.Lock()
	revoked := s.vaultFileRevoked.Load()
	s.vaultFileMu.Lock()
	current := s.vaultFileChildren[token.path]
	s.vaultFileMu.Unlock()
	expired := child.expired(now)
	s.saveMu.Unlock()
	if revoked {
		clearVaultFileChildItems(items)
		s.invalidateVaultFileChild(child)
		return nil, ErrSessionLocked
	}
	if current != child || expired {
		clearVaultFileChildItems(items)
		s.invalidateVaultFileChild(child)
		return nil, ErrVaultFileScopedChild
	}
	return items, nil
}

// LockVaultFileChild revokes one token generation. It never changes the parent
// revocation flag, never locks a sibling and never waits on IO. A stale token
// (for example an old A after A was closed and reopened) is a no-op and cannot
// remove the new generation.
func (s *Session) LockVaultFileChild(token VaultFileChildToken) error {
	if s == nil || token.generation == 0 || token.path == "" {
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
	child.close()
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
	child.close()
}

// lockVaultFileParent follows the existing Session.lock boundary after an
// invalid current account slot or material. It is never called while holding
// Session.mu.
func (s *Session) lockVaultFileParent() {
	s.mu.Lock()
	s.lock()
	s.mu.Unlock()
}

// drainVaultFileChildren is called only by Session.lock, after cancelBrowserSave
// has released saveMu. It releases the registry lock before closing any child,
// so no registry or Session.mu lock is held while waiting on a child.
func (s *Session) drainVaultFileChildren() {
	s.vaultFileMu.Lock()
	children := make([]*vaultFileChild, 0, len(s.vaultFileChildren))
	for _, child := range s.vaultFileChildren {
		children = append(children, child)
	}
	s.vaultFileChildren = make(map[string]*vaultFileChild)
	s.vaultFileMu.Unlock()
	for _, child := range children {
		child.close()
	}
}

func (c *vaultFileChild) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	handle := c.handle
	c.mu.Unlock()
	if handle != nil {
		_ = handle.Close()
	}
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
		return err
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
	closeErr := db.Close()
	if viewErr != nil {
		return viewErr
	}
	return closeErr
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
