package vaultfileclient

import (
	"fmt"
	"sync"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// localGenesisSessionState is the narrow, opaque state behind one owned
// vault-file child. It retains only the exact parent Session, the opaque child
// token and a frozen public locator made of the strict create manifest and its
// companion. It never retains a password, Secret Key, recovery kit, account
// identity, age identity, owner seed, VUK, ScopedUnlock handle or database.
//
// The companion checkpoint is a candidate selector only. Opening delegates
// target-custody authentication to personal.Session.OpenOwnedVaultFileChild;
// this layer never enumerates global owner records and therefore never asks the
// parent for a quick/stale global ownership proof. Each Summary is bracketed by
// a strict locator/journal re-read and by the narrow owned-child ownership
// revalidation. The initial summary is not returned until that posterior work
// has completed.
//
// Failure is terminal for the wrapper: every failed or late candidate is
// handed to personal.Session.LockVaultFileChild and the wrapper never revives.
// Close is idempotent and waits for that real child close. Closing one wrapper
// does not lock the parent Session or any sibling child.
type localGenesisSessionState struct {
	mu sync.Mutex

	parent *personal.Session

	configPath     string
	manifest       Manifest
	manifestSHA256 string
	companion      Companion
	revision       string
	successor      *localGenesisSuccessorLocator

	token personal.VaultFileChildToken

	closed    bool
	closeErr  error
	closeDone chan struct{}

	// firstCloseForTest is nil in production and installed only before
	// concurrent work starts. The first closer runs it after closed is set and
	// mu is released, immediately before parent.LockVaultFileChild. It receives
	// no factor, key, token, handle or capability.
	firstCloseForTest func()
}

// LocalGenesisSession is a lightweight public handle. It contains only one
// private state pointer, so copying the handle or dereferencing it for
// formatting cannot copy a mutex, token or independently revivable state. A
// value copy shares the exact same terminal flag and child-close barrier.
type LocalGenesisSession struct {
	state *localGenesisSessionState
}

// These parameterless private seams are nil in production. They let tests
// interleave a real parent lock or wrapper close at the two responsible
// boundaries without receiving a factor, key, token or handle.
var (
	localGenesisCandidateReadyForTest func()
	localGenesisSummaryReadyForTest   func()
)

// OpenLocalGenesisSession re-reads the exact strict manifest and companion,
// authenticates the real pristine journal or settled owned first successor and
// candidate checkpoint, and asks the parent Session for one owned child with
// this call's explicit full factors. Only after the owned child has been read,
// its locator re-read and its target-only ownership revalidated does it release
// the initial bounded summary. Any failure closes the candidate token before
// returning.
//
// This legacy variant pins whatever journal the captured manifest names. New
// scheduling callers must use OpenLocalGenesisSessionForJournal.
func OpenLocalGenesisSession(s *personal.Session, configPath, workspaceRoot, vaultID string, password, key []byte) (*LocalGenesisSession, LocalGenesisBaseline, error) {
	return openLocalGenesisSession(s, configPath, workspaceRoot, vaultID, "", password, key)
}

// OpenLocalGenesisSessionForJournal is the narrow pinned constructor used by
// scheduling callers. The expected journal must be a valid path. After this
// constructor captures the real manifest, it compares that captured
// manifest.Journal with expectedJournal before owned-child unlock or any
// registration. The comparison source is the captured manifest itself, not a
// caller preflight, and later Summary revalidation keeps the frozen path bound.
func OpenLocalGenesisSessionForJournal(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte) (*LocalGenesisSession, LocalGenesisBaseline, error) {
	if !teamfiles.ValidPath(expectedJournal) {
		return nil, LocalGenesisBaseline{}, ErrLocalReview
	}
	return openLocalGenesisSession(s, configPath, workspaceRoot, vaultID, expectedJournal, password, key)
}

// OpenLocalGenesisSessionForJournalExclusive is the bounded aggregate-query
// variant. It performs the same pinned locator/journal/factor/ownership work,
// but fails closed with ErrLocalReview rather than replacing any child already
// registered for the target journal path. It never closes that existing child.
func OpenLocalGenesisSessionForJournalExclusive(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte) (*LocalGenesisSession, LocalGenesisBaseline, error) {
	if !teamfiles.ValidPath(expectedJournal) {
		return nil, LocalGenesisBaseline{}, ErrLocalReview
	}
	return openLocalGenesisSessionMode(s, configPath, workspaceRoot, vaultID, expectedJournal, password, key, false, true)
}

func openLocalGenesisSession(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte) (*LocalGenesisSession, LocalGenesisBaseline, error) {
	return openLocalGenesisSessionMode(s, configPath, workspaceRoot, vaultID, expectedJournal, password, key, false, false)
}

func openLocalGenesisSessionForCustody(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte) (*LocalGenesisSession, LocalGenesisBaseline, error) {
	return openLocalGenesisSessionMode(s, configPath, workspaceRoot, vaultID, expectedJournal, password, key, true, false)
}

func openLocalGenesisSessionMode(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte, custody, exclusive bool) (*LocalGenesisSession, LocalGenesisBaseline, error) {
	empty := LocalGenesisBaseline{}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" || vaultID == "" {
		return nil, empty, ErrLocalReview
	}
	manifest, digest, companion, err := readLocalGenesisLocator(s, configPath, workspaceRoot, vaultID)
	if err != nil {
		return nil, empty, err
	}
	if expectedJournal != "" && manifest.Journal != expectedJournal {
		return nil, empty, ErrLocalReview
	}
	verified, err := verifyLocalGenesisCompanion(manifest, companion)
	if err != nil {
		return nil, empty, err
	}
	defer clearLocalGenesisVerified(&verified)
	var token personal.VaultFileChildToken
	var initial []personal.VaultFileBaselineItem
	options := personal.VaultFileChildOptions{RefuseExistingChild: exclusive}
	if verified.successor != nil {
		target := personal.OwnedVaultFileFirstSuccessorTarget{
			BackendRoot: verified.successor.backendRoot,
			BackendName: verified.successor.backendName,
			Pin:         cloneLocalGenesisGenesisPin(verified.successor.pin),
		}
		if custody {
			token, initial, err = s.OpenOwnedFirstSuccessorVaultFileChildForCustody(
				manifest.Journal, target, verified.checkpoint, password, key, options)
		} else {
			token, initial, err = s.OpenOwnedFirstSuccessorVaultFileChild(
				manifest.Journal, target, verified.checkpoint, password, key, options)
		}
		clear(target.Pin.Root.OwnerRootPublicKey)
	} else {
		if custody {
			token, initial, err = s.OpenOwnedVaultFileChildForCustody(manifest.Journal,
				manifest.BackendRoot, manifest.Name, verified.checkpoint, password, key, options)
		} else {
			token, initial, err = s.OpenOwnedVaultFileChild(manifest.Journal, verified.checkpoint, password, key, options)
		}
	}
	if err != nil {
		return nil, empty, err
	}

	session := &LocalGenesisSession{state: &localGenesisSessionState{
		parent:         s,
		configPath:     configPath,
		manifest:       manifest,
		manifestSHA256: digest,
		companion:      cloneLocalGenesisCompanion(companion),
		revision:       verified.revision,
		successor:      cloneLocalGenesisSuccessor(verified.successor),
		token:          token,
		closeDone:      make(chan struct{}),
	}}
	summary, err := session.state.initialSummary(initial)
	if err != nil {
		// The initial proof is never delivered on a failed posterior. close
		// waits for the real child close and leaves siblings and the parent
		// untouched.
		_ = session.state.close()
		return nil, empty, err
	}
	return session, summary, nil
}

// Summary returns one bounded item projection only when the frozen locator and
// journal still match, the owned child still reads the same state, and the
// narrow target-only ownership revalidation succeeds. Every failure is terminal
// for this wrapper and closes only this child.
func (l *LocalGenesisSession) Summary() (LocalGenesisBaseline, error) {
	if l == nil || l.state == nil {
		return LocalGenesisBaseline{}, ErrLocalReview
	}
	return l.state.summary()
}

func (s *localGenesisSessionState) summary() (LocalGenesisBaseline, error) {
	empty := LocalGenesisBaseline{}
	s.mu.Lock()
	closed := s.closed
	token := s.token
	s.mu.Unlock()
	if closed || s.parent == nil {
		return empty, ErrLocalReview
	}

	if err := s.revalidateLocator(); err != nil {
		_ = s.close()
		return empty, err
	}
	items, err := s.parent.ReadVaultFileChild(token, personal.VaultFileChildOptions{})
	if err != nil {
		_ = s.close()
		return empty, err
	}

	if localGenesisSummaryReadyForTest != nil {
		localGenesisSummaryReadyForTest()
	}

	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, err
	}
	if err := s.parent.RevalidateVaultFileChildOwnership(token); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, err
	}
	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, err
	}

	s.mu.Lock()
	open := !s.closed && s.token == token
	s.mu.Unlock()
	if !open {
		clearLocalGenesisItems(items)
		return empty, ErrLocalReview
	}
	return LocalGenesisBaseline{VaultID: s.manifest.VaultID, Items: items}, nil
}

// Close is idempotent. It marks this wrapper terminal before waiting for the
// exact child generation's real close completion. It never locks the parent or
// a sibling, and a concurrent closer joins the same completion.
func (l *LocalGenesisSession) Close() error {
	if l == nil || l.state == nil {
		return nil
	}
	return l.state.close()
}

// String, GoString, MarshalJSON and Format are fixed redactions for both the
// pointer and the dereferenced value. Format also covers a nil *Session: it
// ignores the receiver and never dereferences the private state.
func (LocalGenesisSession) String() string   { return "[local genesis session]" }
func (LocalGenesisSession) GoString() string { return "[local genesis session]" }
func (LocalGenesisSession) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalGenesisSession) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local genesis session]"))
}

func (s *localGenesisSessionState) initialSummary(initial []personal.VaultFileBaselineItem) (LocalGenesisBaseline, error) {
	empty := LocalGenesisBaseline{}
	// The constructor's first proof is intentionally discarded: the delivered
	// projection must come from a real post-open read.
	clearLocalGenesisItems(initial)
	if localGenesisCandidateReadyForTest != nil {
		localGenesisCandidateReadyForTest()
	}
	if err := s.revalidateLocator(); err != nil {
		return empty, err
	}
	items, err := s.parent.ReadVaultFileChild(s.token, personal.VaultFileChildOptions{})
	if err != nil {
		return empty, err
	}
	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		return empty, err
	}
	if err := s.parent.RevalidateVaultFileChildOwnership(s.token); err != nil {
		clearLocalGenesisItems(items)
		return empty, err
	}
	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		return empty, err
	}
	return LocalGenesisBaseline{VaultID: s.manifest.VaultID, Items: items}, nil
}

func (s *localGenesisSessionState) revalidateLocator() error {
	if s == nil || s.parent == nil {
		return ErrLocalReview
	}
	if !s.parent.Unlocked() {
		return personal.ErrSessionLocked
	}
	manifest, digest, companion, err := readLocalGenesisLocator(s.parent, s.configPath, s.manifest.BackendRoot, s.manifest.VaultID)
	if err != nil {
		return err
	}
	if manifest != s.manifest || digest != s.manifestSHA256 || !SameCompanion(companion, s.companion) {
		return ErrLocalReview
	}
	// Repeat the complete field comparison explicitly. SameCompanion covers
	// the same values, but this makes every frozen binding visible at the
	// recheck boundary.
	if companion.ManifestSHA256 != s.manifestSHA256 ||
		companion.GenesisSHA256 != s.companion.GenesisSHA256 ||
		companion.OperationID != s.companion.OperationID ||
		!sameLocalGenesisCheckpoint(companion.Resume.Checkpoint, s.companion.Resume.Checkpoint) {
		return ErrLocalReview
	}
	if companion.Resume.BackendRoot != s.manifest.BackendRoot ||
		companion.Resume.Name != s.manifest.Name ||
		companion.Resume.Journal != s.manifest.Journal ||
		companion.Resume.PersonalFile != s.manifest.PersonalFile {
		return ErrLocalReview
	}
	verified, err := verifyLocalGenesisCompanion(manifest, companion)
	if err != nil {
		return err
	}
	defer clearLocalGenesisVerified(&verified)
	if verified.revision != s.revision || !sameLocalGenesisSuccessor(verified.successor, s.successor) {
		return ErrLocalReview
	}
	return nil
}

func (s *localGenesisSessionState) close() error {
	return s.closeWith(nil)
}

// closeWith is the single completion path. A claimed close retires exactly the
// claimed child and returns the real close error; the ordinary close keeps the
// existing token-only behavior for every prior call site.
func (s *localGenesisSessionState) closeWith(claim *personal.VaultFileReadDeliveryClaim) error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		if done != nil {
			<-done
		}
		s.mu.Lock()
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closed = true
	done := s.closeDone
	if done == nil {
		done = make(chan struct{})
		s.closeDone = done
	}
	token := s.token
	parent := s.parent
	firstClose := s.firstCloseForTest
	s.mu.Unlock()

	if firstClose != nil {
		firstClose()
	}

	var err error
	if parent != nil {
		if claim != nil {
			err = claim.CloseChild(parent)
		} else {
			err = parent.LockVaultFileChild(token)
		}
	}
	s.mu.Lock()
	s.closeErr = err
	s.mu.Unlock()
	close(done)
	return err
}

func readLocalGenesisLocator(s *personal.Session, configPath, workspaceRoot, vaultID string) (Manifest, string, Companion, error) {
	var zeroManifest Manifest
	var zeroCompanion Companion
	if s == nil || !s.Unlocked() {
		return zeroManifest, "", zeroCompanion, ErrLocalReview
	}
	return readLocalGenesisLocatorForAccount(s.VaultPath(), configPath, workspaceRoot, vaultID, "")
}

// readLocalGenesisLocatorForAccount is the pre-authentication locator shape
// bound to one explicit account path. The batch adapter uses it before the
// single account KDF; the existing Session-based constructor keeps the same
// behavior by passing its VaultPath and no expected journal.
func readLocalGenesisLocatorForAccount(accountPath, configPath, workspaceRoot, vaultID, expectedJournal string) (Manifest, string, Companion, error) {
	var zeroManifest Manifest
	var zeroCompanion Companion
	if accountPath == "" || configPath == "" || workspaceRoot == "" || vaultID == "" {
		return zeroManifest, "", zeroCompanion, ErrLocalReview
	}
	manifest, exists, err := ReadManifest(configPath)
	if err != nil || !exists || manifest.VaultID != vaultID ||
		manifest.PersonalFile != accountPath || manifest.BackendRoot != workspaceRoot {
		return zeroManifest, "", zeroCompanion, ErrLocalReview
	}
	if expectedJournal != "" && manifest.Journal != expectedJournal {
		return zeroManifest, "", zeroCompanion, ErrLocalReview
	}
	digest, err := ReadManifestDigest(configPath, manifest)
	if err != nil {
		return zeroManifest, "", zeroCompanion, ErrLocalReview
	}
	companion, exists, err := ReadCompanion(configPath, manifest)
	if err != nil || !exists || companion.ManifestSHA256 != digest || companion.Resume.Checkpoint == nil {
		return zeroManifest, "", zeroCompanion, ErrLocalReview
	}
	return manifest, digest, companion, nil
}

func verifyLocalGenesisCompanion(manifest Manifest, companion Companion) (localGenesisVerifiedState, error) {
	empty := localGenesisVerifiedState{}
	if companion.Resume.Checkpoint == nil {
		return empty, ErrLocalReview
	}
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		return empty, ErrLocalReview
	}
	defer clear(root)

	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		return empty, ErrLocalReview
	}
	record, successorErr := vaultfilejournal.ReadOwnedFirstSuccessor(manifest.Journal, pin)
	if successorErr == nil {
		checkpoint, err := verifyLocalGenesisSuccessor(manifest, companion, pin, record)
		successorRevision := string(record.SuccessorRevision)
		clear(record.GenesisBytes)
		clear(record.SuccessorBytes)
		if err != nil {
			return empty, ErrLocalReview
		}
		return localGenesisVerifiedState{
			checkpoint: checkpoint,
			revision:   successorRevision,
			successor: &localGenesisSuccessorLocator{
				pin:               cloneLocalGenesisGenesisPin(pin),
				backendRoot:       manifest.BackendRoot,
				backendName:       manifest.Name,
				successorRevision: successorRevision,
			},
		}, nil
	}
	clear(record.GenesisBytes)
	clear(record.SuccessorBytes)

	// This fallback is the unchanged pristine generation-zero path. A rejected
	// or malformed settled v2 record cannot be opened by the legacy
	// OpenExisting/LoadGenesisBaseline path, so it still fails closed here.
	checkpoint, revision, err := verifyLocalGenesisState(manifest.Journal, manifest.VaultID, companion, root)
	if err != nil || checkpoint == nil || revision == "" {
		clearLocalGenesisCheckpoint(checkpoint)
		return empty, ErrLocalReview
	}
	return localGenesisVerifiedState{checkpoint: checkpoint, revision: revision}, nil
}

func clearLocalGenesisCheckpoint(checkpoint *vaultfile.PolicyCheckpoint) {
	if checkpoint == nil {
		return
	}
	clear(checkpoint.OwnerRootPublicKey)
	clear(checkpoint.PolicyDigest)
}

func clearLocalGenesisItems(items []personal.VaultFileBaselineItem) {
	for i := range items {
		items[i] = personal.VaultFileBaselineItem{}
	}
}

func cloneLocalGenesisCompanion(companion Companion) Companion {
	out := companion
	if companion.Resume.Checkpoint == nil {
		return out
	}
	checkpoint := *companion.Resume.Checkpoint
	if companion.Resume.Checkpoint.PolicySeq != nil {
		seq := *companion.Resume.Checkpoint.PolicySeq
		checkpoint.PolicySeq = &seq
	}
	out.Resume.Checkpoint = &checkpoint
	return out
}

func sameLocalGenesisCheckpoint(a, b *CheckpointConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.VaultID != b.VaultID || a.OwnerRootKeyID != b.OwnerRootKeyID ||
		a.OwnerRootPublicKey != b.OwnerRootPublicKey || a.PolicyDigest != b.PolicyDigest {
		return false
	}
	if (a.PolicySeq == nil) != (b.PolicySeq == nil) {
		return false
	}
	return a.PolicySeq == nil || *a.PolicySeq == *b.PolicySeq
}
