package vaultfileclient

import (
	"sync"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// LocalGenesisSession is the narrow, opaque client wrapper around one owned
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
type LocalGenesisSession struct {
	mu sync.Mutex

	parent *personal.Session

	configPath     string
	manifest       Manifest
	manifestSHA256 string
	companion      Companion
	revision       string

	token personal.VaultFileChildToken

	closed    bool
	closeErr  error
	closeDone chan struct{}
}

// These parameterless private seams are nil in production. They let tests
// interleave a real parent lock or wrapper close at the two responsible
// boundaries without receiving a factor, key, token or handle.
var (
	localGenesisCandidateReadyForTest func()
	localGenesisSummaryReadyForTest   func()
)

// OpenLocalGenesisSession re-reads the exact strict manifest and companion,
// authenticates the real generation-zero journal and candidate checkpoint, and
// asks the parent Session for one owned child with this call's explicit full
// factors. Only after the owned child has been read, its locator re-read and
// its target-only ownership revalidated does it release the initial bounded
// summary. Any failure closes the candidate token before returning.
func OpenLocalGenesisSession(s *personal.Session, configPath, workspaceRoot, vaultID string, password, key []byte) (*LocalGenesisSession, LocalGenesisBaseline, error) {
	empty := LocalGenesisBaseline{}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" || vaultID == "" {
		return nil, empty, ErrLocalReview
	}
	manifest, digest, companion, err := readLocalGenesisLocator(s, configPath, workspaceRoot, vaultID)
	if err != nil {
		return nil, empty, err
	}
	checkpoint, revision, err := verifyLocalGenesisCompanion(manifest, companion)
	if err != nil {
		return nil, empty, err
	}
	token, initial, err := s.OpenOwnedVaultFileChild(manifest.Journal, checkpoint, password, key, personal.VaultFileChildOptions{})
	clearLocalGenesisCheckpoint(checkpoint)
	if err != nil {
		return nil, empty, err
	}

	session := &LocalGenesisSession{
		parent:         s,
		configPath:     configPath,
		manifest:       manifest,
		manifestSHA256: digest,
		companion:      cloneLocalGenesisCompanion(companion),
		revision:       revision,
		token:          token,
		closeDone:      make(chan struct{}),
	}
	summary, err := session.initialSummary(initial)
	if err != nil {
		// The initial proof is never delivered on a failed posterior. close
		// waits for the real child close and leaves siblings and the parent
		// untouched.
		_ = session.close()
		return nil, empty, err
	}
	return session, summary, nil
}

// Summary returns one bounded item projection only when the frozen locator and
// generation-zero journal still match, the owned child still reads the same
// state, and the narrow target-only ownership revalidation succeeds. Every
// failure is terminal for this wrapper and closes only this child.
func (l *LocalGenesisSession) Summary() (LocalGenesisBaseline, error) {
	empty := LocalGenesisBaseline{}
	if l == nil {
		return empty, ErrLocalReview
	}
	l.mu.Lock()
	closed := l.closed
	token := l.token
	l.mu.Unlock()
	if closed || l.parent == nil {
		return empty, ErrLocalReview
	}

	if err := l.revalidateLocator(); err != nil {
		_ = l.close()
		return empty, err
	}
	items, err := l.parent.ReadVaultFileChild(token, personal.VaultFileChildOptions{})
	if err != nil {
		_ = l.close()
		return empty, err
	}

	if localGenesisSummaryReadyForTest != nil {
		localGenesisSummaryReadyForTest()
	}

	if err := l.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = l.close()
		return empty, err
	}
	if err := l.parent.RevalidateVaultFileChildOwnership(token); err != nil {
		clearLocalGenesisItems(items)
		_ = l.close()
		return empty, err
	}
	if err := l.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = l.close()
		return empty, err
	}

	l.mu.Lock()
	open := !l.closed && l.token == token
	l.mu.Unlock()
	if !open {
		clearLocalGenesisItems(items)
		return empty, ErrLocalReview
	}
	return LocalGenesisBaseline{VaultID: l.manifest.VaultID, Items: items}, nil
}

// Close is idempotent. It marks this wrapper terminal before waiting for the
// exact child generation's real close completion. It never locks the parent or
// a sibling, and a concurrent closer joins the same completion.
func (l *LocalGenesisSession) Close() error {
	if l == nil {
		return nil
	}
	return l.close()
}

// String, GoString and MarshalJSON are fixed redactions. They never show a
// frozen path, journal, VaultID, checkpoint or token.
func (*LocalGenesisSession) String() string   { return "[local genesis session]" }
func (*LocalGenesisSession) GoString() string { return "[local genesis session]" }
func (*LocalGenesisSession) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

func (l *LocalGenesisSession) initialSummary(initial []personal.VaultFileBaselineItem) (LocalGenesisBaseline, error) {
	empty := LocalGenesisBaseline{}
	// The constructor's first proof is intentionally discarded: the delivered
	// projection must come from a real post-open read.
	clearLocalGenesisItems(initial)
	if localGenesisCandidateReadyForTest != nil {
		localGenesisCandidateReadyForTest()
	}
	if err := l.revalidateLocator(); err != nil {
		return empty, err
	}
	items, err := l.parent.ReadVaultFileChild(l.token, personal.VaultFileChildOptions{})
	if err != nil {
		return empty, err
	}
	if err := l.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		return empty, err
	}
	if err := l.parent.RevalidateVaultFileChildOwnership(l.token); err != nil {
		clearLocalGenesisItems(items)
		return empty, err
	}
	if err := l.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		return empty, err
	}
	return LocalGenesisBaseline{VaultID: l.manifest.VaultID, Items: items}, nil
}

func (l *LocalGenesisSession) revalidateLocator() error {
	if l == nil || l.parent == nil {
		return ErrLocalReview
	}
	if !l.parent.Unlocked() {
		return personal.ErrSessionLocked
	}
	manifest, digest, companion, err := readLocalGenesisLocator(l.parent, l.configPath, l.manifest.BackendRoot, l.manifest.VaultID)
	if err != nil {
		return err
	}
	if manifest != l.manifest || digest != l.manifestSHA256 || !SameCompanion(companion, l.companion) {
		return ErrLocalReview
	}
	// Repeat the complete field comparison explicitly. SameCompanion covers
	// the same values, but this makes every frozen binding visible at the
	// recheck boundary.
	if companion.ManifestSHA256 != l.manifestSHA256 ||
		companion.GenesisSHA256 != l.companion.GenesisSHA256 ||
		companion.OperationID != l.companion.OperationID ||
		!sameLocalGenesisCheckpoint(companion.Resume.Checkpoint, l.companion.Resume.Checkpoint) {
		return ErrLocalReview
	}
	if companion.Resume.BackendRoot != l.manifest.BackendRoot ||
		companion.Resume.Name != l.manifest.Name ||
		companion.Resume.Journal != l.manifest.Journal ||
		companion.Resume.PersonalFile != l.manifest.PersonalFile {
		return ErrLocalReview
	}
	checkpoint, revision, err := verifyLocalGenesisCompanion(manifest, companion)
	if err != nil {
		return err
	}
	clearLocalGenesisCheckpoint(checkpoint)
	if revision != l.revision {
		return ErrLocalReview
	}
	return nil
}

func (l *LocalGenesisSession) close() error {
	l.mu.Lock()
	if l.closed {
		done := l.closeDone
		l.mu.Unlock()
		if done != nil {
			<-done
		}
		l.mu.Lock()
		err := l.closeErr
		l.mu.Unlock()
		return err
	}
	l.closed = true
	done := l.closeDone
	if done == nil {
		done = make(chan struct{})
		l.closeDone = done
	}
	token := l.token
	parent := l.parent
	l.mu.Unlock()

	var err error
	if parent != nil {
		err = parent.LockVaultFileChild(token)
	}
	l.mu.Lock()
	l.closeErr = err
	l.mu.Unlock()
	close(done)
	return err
}

func readLocalGenesisLocator(s *personal.Session, configPath, workspaceRoot, vaultID string) (Manifest, string, Companion, error) {
	var zeroManifest Manifest
	var zeroCompanion Companion
	if s == nil || !s.Unlocked() {
		return zeroManifest, "", zeroCompanion, ErrLocalReview
	}
	manifest, exists, err := ReadManifest(configPath)
	if err != nil || !exists || manifest.VaultID != vaultID ||
		manifest.PersonalFile != s.VaultPath() || manifest.BackendRoot != workspaceRoot {
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

func verifyLocalGenesisCompanion(manifest Manifest, companion Companion) (*vaultfile.PolicyCheckpoint, string, error) {
	if companion.Resume.Checkpoint == nil {
		return nil, "", ErrLocalReview
	}
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		return nil, "", ErrLocalReview
	}
	defer clear(root)
	checkpoint, revision, err := verifyLocalGenesisState(manifest.Journal, manifest.VaultID, companion, root)
	if err != nil || checkpoint == nil || revision == "" {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, "", ErrLocalReview
	}
	return checkpoint, revision, nil
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
