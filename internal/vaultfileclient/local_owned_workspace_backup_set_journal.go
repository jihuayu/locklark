package vaultfileclient

import (
	"context"
	"errors"
	"sort"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// This file retains the exact settled journals whose states the fenced final
// preflight authenticates. The provider fence alone does not stop a normal
// writer from committing PrepareWorkingIfState to a journal and only then
// waiting for the provider CAS. Holding each journal's existing bbolt lock from
// the fenced reads through aggregate construction closes that overlap without a
// new journal format, a writer-protocol change or a nested reacquire.

// localOwnedWorkspaceJournalSet is one bounded, stable-order retention of the
// exact distinct journal paths bound by the authenticated source proof.
type localOwnedWorkspaceJournalSet struct {
	byPath   map[string]*vaultfilejournal.Journal
	order    []string
	acquired []*vaultfilejournal.Journal
}

// withLocalOwnedWorkspaceJournals is the single lexical owner of the acquired
// journal handles. It first re-reads the strict manifests and companions and
// binds their manifest digests to the already accepted proof, then opens the
// exact distinct paths in sorted order with the existing settled-shape reader.
// Each handle is registered before its later identity validation. The deferred
// close always runs, including on panic, closes every acquired handle in reverse
// order, and turns a close failure after callback success into a conflict; no
// handle escapes the callback.
func withLocalOwnedWorkspaceJournals(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string, proof LocalOwnedWorkspacePreflight,
	fn func(*localOwnedWorkspaceJournalSet) error) (retErr error) {
	paths, err := localOwnedWorkspaceJournalLocators(ctx, s, profileDir, backendRoot, proof)
	if err != nil {
		return err
	}
	set := &localOwnedWorkspaceJournalSet{
		byPath: make(map[string]*vaultfilejournal.Journal, len(paths)),
		order:  paths,
	}
	defer func() {
		if closeErr := set.closeReverse(); closeErr != nil && retErr == nil {
			retErr = localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal close")
		}
	}()
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return localOwnedWorkspaceCanceled(err, "context")
		}
		journal, err := vaultfilejournal.OpenExistingSettledShape(path)
		if err != nil {
			return localOwnedWorkspaceMapJournalOpenError(err)
		}
		// Register before validation so every error, panic or close failure
		// through this point still releases this descriptor.
		set.byPath[path] = journal
		set.acquired = append(set.acquired, journal)
		if err := journal.RevalidateExistingPath(); err != nil {
			return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal replaced")
		}
	}
	return fn(set)
}

// localOwnedWorkspaceJournalLocators validates the exact distinct journal
// paths against the trusted source proof without opening a journal. The
// manifest digest is the authenticated binding of the path; the companion must
// name the same journal and source. Duplicate paths and any manifest/account or
// profile-scope drift are refused before a journal lock is taken.
func localOwnedWorkspaceJournalLocators(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string,
	proof LocalOwnedWorkspacePreflight) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, localOwnedWorkspaceCanceled(err, "context")
	}
	if s == nil || !s.Unlocked() {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	accountPath := s.VaultPath()
	if accountPath == "" {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	if !localOwnedWorkspaceValidPath(accountPath) {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "account")
	}
	configs, _, err := localOwnedWorkspaceProfileConfigs(profileDir)
	if err != nil {
		return nil, localOwnedWorkspaceMapReview(err, "journal locator")
	}
	if len(configs) != len(proof.Vaults) {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal set")
	}
	proofByID := make(map[string]LocalOwnedWorkspaceVault, len(proof.Vaults))
	for _, vault := range proof.Vaults {
		proofByID[vault.VaultID] = vault
	}
	seenPath := make(map[string]string, len(configs))
	paths := make([]string, 0, len(configs))
	for _, config := range configs {
		if err := ctx.Err(); err != nil {
			return nil, localOwnedWorkspaceCanceled(err, "context")
		}
		manifest, exists, err := ReadManifest(config)
		if err != nil || !exists {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "journal manifest")
		}
		if manifest.PersonalFile != accountPath || manifest.BackendRoot != backendRoot {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "journal source")
		}
		entry, ok := proofByID[manifest.VaultID]
		if !ok {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "journal vault")
		}
		digestValue, err := ReadManifestDigest(config, manifest)
		if err != nil {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "journal manifest")
		}
		digest, ok := localOwnedWorkspaceDigest(digestValue)
		if !ok || digest != entry.ManifestSHA256 {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "manifest drift")
		}
		companion, exists, err := ReadCompanion(config, manifest)
		if err != nil || !exists || companion.ManifestSHA256 != digestValue ||
			companion.Resume.Checkpoint == nil ||
			companion.Resume.BackendRoot != backendRoot ||
			companion.Resume.PersonalFile != accountPath ||
			companion.Resume.Name != manifest.Name ||
			companion.Resume.Journal != manifest.Journal {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "journal companion")
		}
		path := manifest.Journal
		if !teamfiles.ValidPath(path) {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "journal path")
		}
		if _, duplicate := seenPath[path]; duplicate {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate journal")
		}
		seenPath[path] = manifest.VaultID
		paths = append(paths, path)
	}
	if len(paths) != len(proof.Vaults) {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal set")
	}
	sort.Strings(paths)
	return paths, nil
}

// lookup returns only an already-retained journal for the exact manifest path.
// It never opens or locks a journal. A missing path is scope drift and a path
// no longer naming the retained inode is a replacement.
func (s *localOwnedWorkspaceJournalSet) lookup(ctx context.Context,
	path string) (*vaultfilejournal.Journal, error) {
	if err := ctx.Err(); err != nil {
		return nil, localOwnedWorkspaceCanceled(err, "context")
	}
	if s == nil {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal scope")
	}
	journal, ok := s.byPath[path]
	if !ok || journal == nil {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal scope")
	}
	if err := journal.RevalidateExistingPath(); err != nil {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal replaced")
	}
	return journal, nil
}

// revalidate checks every retained path still names its locked inode. It is
// called at the last delivery gate, after artifact/account checks and
// immediately before aggregate construction.
func (s *localOwnedWorkspaceJournalSet) revalidate() error {
	if s == nil {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal scope")
	}
	for _, path := range s.order {
		journal := s.byPath[path]
		if journal == nil {
			return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal set")
		}
		if err := journal.RevalidateExistingPath(); err != nil {
			return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal replaced")
		}
	}
	return nil
}

// closeReverse releases every acquired journal lock exactly once in reverse
// acquisition order. It continues after an individual close error and returns
// all of them joined. It is called only by the lexical owner's defer, so no
// journal handle survives the scoped callback.
func (s *localOwnedWorkspaceJournalSet) closeReverse() error {
	if s == nil {
		return nil
	}
	var errs []error
	for index := len(s.acquired) - 1; index >= 0; index-- {
		journal := s.acquired[index]
		if journal == nil {
			continue
		}
		s.acquired[index] = nil
		if err := journal.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for path := range s.byPath {
		s.byPath[path] = nil
	}
	return errors.Join(errs...)
}

func localOwnedWorkspaceMapJournalOpenError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return localOwnedWorkspaceCanceled(err, "journal")
	case errors.Is(err, vaultfilejournal.ErrUnsupported):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceUnsupported, "journal")
	case errors.Is(err, vaultfilejournal.ErrLocked),
		errors.Is(err, vaultfilejournal.ErrPendingRecords),
		errors.Is(err, vaultfilejournal.ErrPendingGenesisIntent):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal busy")
	case errors.Is(err, vaultfilejournal.ErrCorrupt),
		errors.Is(err, vaultfilejournal.ErrInvalid),
		errors.Is(err, vaultfilejournal.ErrEmpty):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceUnsupported, "journal")
	default:
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "journal")
	}
}

// readLocalOwnedBackupSnapshotFromJournal is the same established pristine or
// settled owned-first-successor snapshot reader, but it uses the one retained
// journal handle for both typed shapes and never opens the path again.
func readLocalOwnedBackupSnapshotFromJournal(journal *vaultfilejournal.Journal,
	manifest Manifest, companion Companion) (*localOwnedBackupSnapshot, error) {
	if journal == nil || companion.Resume.Checkpoint == nil {
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "checkpoint")
	}
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "owner")
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		return nil, localOwnedBackupError(ErrLocalOwnedBackupReview, "pin")
	}

	record, successorErr := journal.LoadOwnedFirstSuccessor(pin)
	if successorErr == nil {
		snapshot, err := localOwnedBackupSettledSnapshot(manifest, companion, pin, record)
		if err == nil {
			// The snapshot now owns both encrypted endpoints.
			record.GenesisBytes = nil
			record.SuccessorBytes = nil
		}
		clear(record.GenesisBytes)
		clear(record.SuccessorBytes)
		return snapshot, err
	}
	clear(record.GenesisBytes)
	clear(record.SuccessorBytes)

	state, loadErr := journal.LoadGenesisBaseline()
	if loadErr == nil {
		snapshot, err := localOwnedBackupPristineSnapshotFromState(manifest, companion, pin, root, state)
		if err == nil {
			state.BaseBytes = nil
		}
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		return snapshot, err
	}
	clear(state.BaseBytes)
	clear(state.WorkingBytes)
	return nil, classifyLocalOwnedBackupSnapshotFailure(successorErr, nil, loadErr, nil)
}

// verifyLocalGenesisCompanionFromJournal is the same strict companion/journal
// verifier used by the source preflight, but it reads the retained handle
// instead of reopening the journal path.
func verifyLocalGenesisCompanionFromJournal(journal *vaultfilejournal.Journal,
	manifest Manifest, companion Companion) (localGenesisVerifiedState, error) {
	empty := localGenesisVerifiedState{}
	if journal == nil || companion.Resume.Checkpoint == nil {
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
	record, successorErr := journal.LoadOwnedFirstSuccessor(pin)
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

	state, loadErr := journal.LoadGenesisBaseline()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil {
		return empty, ErrLocalReview
	}
	checkpoint, revision, err := verifyLocalGenesisBaselineState(manifest.VaultID, companion, root, state)
	if err != nil || checkpoint == nil || revision == "" {
		clearLocalGenesisCheckpoint(checkpoint)
		return empty, ErrLocalReview
	}
	return localGenesisVerifiedState{checkpoint: checkpoint, revision: revision}, nil
}

// localOwnedWorkspaceReadVaultJournalState selects the ordinary open/read path
// or the retained-handle path while preserving the existing backup/review error
// classification.
func localOwnedWorkspaceReadVaultJournalState(ctx context.Context,
	scope localOwnedWorkspaceSourceScope, manifest Manifest,
	companion Companion) (*localOwnedBackupSnapshot, localGenesisVerifiedState, error) {
	empty := localGenesisVerifiedState{}
	if scope.journals != nil {
		journal, err := scope.journals.lookup(ctx, manifest.Journal)
		if err != nil {
			return nil, empty, err
		}
		snapshot, err := readLocalOwnedBackupSnapshotFromJournal(journal, manifest, companion)
		if err != nil {
			return nil, empty, localOwnedWorkspaceMapBackup(err)
		}
		verified, err := verifyLocalGenesisCompanionFromJournal(journal, manifest, companion)
		if err != nil {
			snapshot.clear()
			clearLocalGenesisVerified(&verified)
			return nil, empty, localOwnedWorkspaceMapReview(err, "journal")
		}
		return snapshot, verified, nil
	}
	snapshot, err := readLocalOwnedBackupSnapshot(manifest, companion)
	if err != nil {
		return nil, empty, localOwnedWorkspaceMapBackup(err)
	}
	verified, err := verifyLocalGenesisCompanion(manifest, companion)
	if err != nil {
		snapshot.clear()
		clearLocalGenesisVerified(&verified)
		return nil, empty, localOwnedWorkspaceMapReview(err, "journal")
	}
	return snapshot, verified, nil
}
