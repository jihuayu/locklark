package vaultfileclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

var (
	// ErrLocalOwnedWorkspaceReviewRequired rejects an unproven or ambiguous
	// source scope. It is the defined review-required outcome for a foreign,
	// missing, duplicate, malformed, unsafe or otherwise unsupported local
	// workspace that this preflight cannot honestly represent.
	ErrLocalOwnedWorkspaceReviewRequired = errors.New("LOCAL_OWNED_WORKSPACE_REVIEW_REQUIRED")
	// ErrLocalOwnedWorkspaceConflict reports a pending, missing, replaced or
	// drifted journal/backend observation. Original source bytes are retained.
	ErrLocalOwnedWorkspaceConflict = errors.New("LOCAL_OWNED_WORKSPACE_CONFLICT")
	// ErrLocalOwnedWorkspaceUnsupported reports a source format newer than the
	// current pristine/first-successor producer formats.
	ErrLocalOwnedWorkspaceUnsupported = errors.New("LOCAL_OWNED_WORKSPACE_UNSUPPORTED")
	// ErrLocalOwnedWorkspaceCanceled reports cancellation, a conclusively
	// locked Session at entry, or lock/session replacement observed while the
	// read-only preflight was in flight.
	ErrLocalOwnedWorkspaceCanceled = errors.New("LOCAL_OWNED_WORKSPACE_CANCELED")
)

// LocalOwnedWorkspaceState names the only successful preflight outcome. It is
// deliberately not a migration-complete value: workspace/device stop-writes
// proof, full backup-set verification and cutover remain outstanding.
type LocalOwnedWorkspaceState string

const (
	// LocalOwnedWorkspaceStateKnownInventoryReady means exactly the observed
	// account-owned local set was verified for a later pinned read. It never
	// means that the workspace is stopped, backed up or cut over.
	LocalOwnedWorkspaceStateKnownInventoryReady LocalOwnedWorkspaceState = "KNOWN_LOCAL_INVENTORY_READY_FOR_REVIEW"
)

const (
	// maxLocalOwnedWorkspaceEntries uses the existing desktop profile-list
	// bound. The personal owned-owner cap is smaller, so this is a conservative
	// outer limit for both the profile entries and the public roster.
	maxLocalOwnedWorkspaceEntries = 128
)

// LocalOwnedWorkspaceVault is the bounded, digest-only proof for exactly one
// verified owned vault. It contains no path, owner key, checkpoint byte,
// ciphertext, item or factor. ManifestSHA256 and IdentityDigest pin the exact
// source for a later read; the opaque revisions are the observed backend and
// journal identities.
type LocalOwnedWorkspaceVault struct {
	VaultID          string
	ManifestSHA256   [sha256.Size]byte
	CurrentSHA256    [sha256.Size]byte
	OriginSHA256     [sha256.Size]byte
	CheckpointDigest [sha256.Size]byte
	IdentityDigest   [sha256.Size]byte
	JournalRevision  vaultfilebackend.Revision
	BackendRevision  vaultfilebackend.Revision
	OriginRevision   vaultfilebackend.Revision
	ContentSeq       uint64
}

// String, GoString, MarshalJSON and Format are fixed redactions so a proof is
// never copied into a public log with a vault ID, revision or digest.
func (LocalOwnedWorkspaceVault) String() string   { return "[local owned workspace vault]" }
func (LocalOwnedWorkspaceVault) GoString() string { return "[local owned workspace vault]" }
func (LocalOwnedWorkspaceVault) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedWorkspaceVault) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local owned workspace vault]"))
}

// LocalOwnedWorkspacePreflight is the read-only checkpoint for exactly one
// protected profile directory, one explicit local backend root and the exact
// active account Session. The digest fields bind the account path, source
// paths, public owner roster and checked vault set without disclosing them.
// Vaults is a private copy in VaultID order.
//
// Even on success, StopWritesProofOutstanding, FullBackupOutstanding and
// CutoverOutstanding are true, and UnknownOfflineDraftsPossible is true. No
// field asserts that remote, shared or member-device writers stopped.
type LocalOwnedWorkspacePreflight struct {
	AccountDigest [sha256.Size]byte
	ProfileDigest [sha256.Size]byte
	BackendDigest [sha256.Size]byte
	RosterDigest  [sha256.Size]byte
	// KnownSetDigest binds the scoped account, profile, backend and roster,
	// the exact checked vault set and the outstanding-only state below.
	KnownSetDigest [sha256.Size]byte
	Vaults         []LocalOwnedWorkspaceVault
	State          LocalOwnedWorkspaceState

	StopWritesProofOutstanding   bool
	FullBackupOutstanding        bool
	CutoverOutstanding           bool
	UnknownOfflineDraftsPossible bool
}

func (LocalOwnedWorkspacePreflight) String() string   { return "[local owned workspace preflight]" }
func (LocalOwnedWorkspacePreflight) GoString() string { return "[local owned workspace preflight]" }
func (LocalOwnedWorkspacePreflight) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedWorkspacePreflight) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local owned workspace preflight]"))
}

// localOwnedWorkspaceSourceScope selects how the preflight reaches the named
// backend object. The default scope opens the existing local Dir for the exact
// manifest-named object. The maintenance-fence entry supplies a reader backed
// only by the already-held ProtectedReadView and disables the separate Dir open,
// so it cannot acquire a nested provider lock.
type localOwnedWorkspaceSourceScope struct {
	readTarget           func(context.Context, Manifest, []byte, vaultfilebackend.Revision) (vaultfilebackend.Revision, error)
	requireBackendExists bool
	// expectedProfileBinding/expectedBackendBinding are set only by the
	// maintenance-fence entry. They carry the exact directory identities
	// captured before the expensive preparation into the fenced preflight. A
	// same-path replacement with otherwise matching bytes is a conflict, not a
	// new authoritative identity.
	expectedProfileBinding *localOwnedWorkspaceDirectoryBinding
	expectedBackendBinding *localOwnedWorkspaceDirectoryBinding
	// journals is set only by the maintenance-fence entry. It supplies the
	// already-locked, stable-order journal handles the final preflight must use;
	// the fenced path never reopens a journal by path.
	journals *localOwnedWorkspaceJournalSet
}

func localOwnedWorkspaceDefaultSourceScope() localOwnedWorkspaceSourceScope {
	return localOwnedWorkspaceSourceScope{
		readTarget: func(ctx context.Context, manifest Manifest, expected []byte,
			wantRevision vaultfilebackend.Revision) (vaultfilebackend.Revision, error) {
			pulled, err := readLocalOwnedBackupTarget(ctx, manifest, expected, wantRevision)
			if err != nil {
				return "", err
			}
			return pulled.Revision(), nil
		},
		requireBackendExists: true,
	}
}

// PreflightLocalOwnedWorkspaceSource performs one bounded, read-only preflight
// of the currently supported account-owned local source. The caller supplies
// the exact protected profile directory, one explicit local backend root and a
// freshly full-factor-unlocked Session whose VaultPath is the one account.
//
// For every public owner returned by Session.VaultFileOwnerships, the strict
// profile manifest must be the only one for that owner, its companion and
// owner checkpoint must match, its journal must be the settled pristine or
// first-successor state, and the real named local backend object must equal the
// settled bytes at exactly the recorded opaque revision. The observed profile
// configuration set must account for every roster owner and no other owner.
// Missing, duplicate, foreign, malformed, unsafe, nested, unrecognized, shared
// or unsupported scopes are a defined ErrLocalOwnedWorkspaceReviewRequired (or
// a more specific conflict/unsupported/canceled category).
//
// The function never opens a child, stages a write, adopts a draft, creates a
// database or touches an existing live child. It re-reads the roster, account
// path, path identities and the complete source set before returning a proof.
// The success value is only a known local inventory ready for further review.
// It makes no claim about a different profile/workspace, shared team scope,
// member device, offline draft or remote writer; those remain review-required
// for any later migration step.
func PreflightLocalOwnedWorkspaceSource(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string) (proof LocalOwnedWorkspacePreflight, retErr error) {
	return preflightLocalOwnedWorkspaceSource(ctx, s, profileDir, backendRoot,
		localOwnedWorkspaceDefaultSourceScope())
}

func preflightLocalOwnedWorkspaceSource(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string,
	scope localOwnedWorkspaceSourceScope) (proof LocalOwnedWorkspacePreflight, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "request")
	}
	// A non-nil Session that is already conclusively locked (explicit lock,
	// idle expiry or cleared material) is the promised canceled outcome, not a
	// malformed request. A nil Session, or one whose exact account/path scope
	// cannot be validated below, remains review-required.
	if !s.Unlocked() {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	if !localOwnedWorkspaceValidPath(profileDir) ||
		!localOwnedWorkspaceValidPath(backendRoot) ||
		localOwnedWorkspaceNested(profileDir, backendRoot) {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "request")
	}
	if err := ctx.Err(); err != nil {
		return proof, localOwnedWorkspaceCanceled(err, "context")
	}

	accountPath := s.VaultPath()
	// VaultPath returns "" exactly when its owning active(false) check observed
	// an explicit Lock/RequestLock or an idle expiry. The entry check above saw
	// the session unlocked, so an empty capture is a session that newly locked
	// during initial capture: the promised canceled outcome, not a malformed
	// account scope. A non-empty path that fails validation is still a genuine
	// malformed active account and remains review-required.
	if accountPath == "" {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	if !localOwnedWorkspaceValidPath(accountPath) {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "account")
	}
	profileBinding, err := localOwnedWorkspaceDirectory(profileDir, true)
	if err != nil {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "profile")
	}
	backendBinding, err := localOwnedWorkspaceDirectory(backendRoot, false)
	if err != nil {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "backend")
	}
	// A fenced caller supplies the exact identities captured before expensive
	// preparation. Requiring the freshly captured leaf and resolved target to
	// equal those values prevents a same-path replacement with byte-identical
	// configs/journals from becoming authoritative inside the fence. The
	// retained expected value, not the replacement, is then used by every later
	// StillBound check in this preflight.
	if scope.expectedProfileBinding != nil {
		if !sameLocalOwnedWorkspaceDirectoryBinding(*scope.expectedProfileBinding, profileBinding) {
			return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "profile replaced")
		}
		profileBinding = *scope.expectedProfileBinding
	}
	if scope.expectedBackendBinding != nil {
		if !sameLocalOwnedWorkspaceDirectoryBinding(*scope.expectedBackendBinding, backendBinding) {
			return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "backend replaced")
		}
		backendBinding = *scope.expectedBackendBinding
	}
	// Lexical separation is not enough when an already existing ancestor is a
	// symlink. Bind both real directories now and reject a resolved target that
	// is the same directory or nested either way.
	if localOwnedWorkspaceNested(profileBinding.resolved, backendBinding.resolved) ||
		os.SameFile(profileBinding.info, backendBinding.info) {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "resolved scopes")
	}
	if scope.requireBackendExists {
		if err := localOwnedWorkspaceBackendExisting(backendRoot); err != nil {
			return proof, localOwnedWorkspaceMapReview(err, "backend")
		}
	}

	firstRoster, firstVaults, err := localOwnedWorkspaceReadSet(ctx, s, accountPath, profileDir, backendRoot, scope)
	if err != nil {
		return proof, err
	}
	if err := localOwnedWorkspaceStillBound(ctx, s, accountPath, profileDir, backendRoot,
		profileBinding, backendBinding, scope); err != nil {
		return proof, err
	}

	secondRoster, secondVaults, err := localOwnedWorkspaceReadSet(ctx, s, accountPath, profileDir, backendRoot, scope)
	if err != nil {
		return proof, err
	}
	if !sameLocalOwnedWorkspaceRoster(firstRoster, secondRoster) ||
		!sameLocalOwnedWorkspaceVaults(firstVaults, secondVaults) {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "source drift")
	}

	finalRoster, err := localOwnedWorkspaceReadRoster(ctx, s, accountPath)
	if err != nil {
		return proof, err
	}
	if !sameLocalOwnedWorkspaceRoster(secondRoster, finalRoster) {
		return proof, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "roster drift")
	}
	if err := localOwnedWorkspaceStillBound(ctx, s, accountPath, profileDir, backendRoot,
		profileBinding, backendBinding, scope); err != nil {
		return proof, err
	}

	proof = LocalOwnedWorkspacePreflight{
		AccountDigest:                localOwnedWorkspacePathDigest("account", accountPath),
		ProfileDigest:                localOwnedWorkspacePathDigest("profile", profileDir),
		BackendDigest:                localOwnedWorkspacePathDigest("backend", backendRoot),
		RosterDigest:                 localOwnedWorkspaceRosterDigest(secondRoster),
		Vaults:                       append([]LocalOwnedWorkspaceVault(nil), secondVaults...),
		State:                        LocalOwnedWorkspaceStateKnownInventoryReady,
		StopWritesProofOutstanding:   true,
		FullBackupOutstanding:        true,
		CutoverOutstanding:           true,
		UnknownOfflineDraftsPossible: true,
	}
	proof.KnownSetDigest = localOwnedWorkspaceSetDigest(proof)
	return proof, nil
}

func localOwnedWorkspaceReadSet(ctx context.Context, s *personal.Session, accountPath,
	profileDir, backendRoot string,
	scope localOwnedWorkspaceSourceScope) ([]personal.VaultFileOwnershipPublic,
	[]LocalOwnedWorkspaceVault, error) {
	roster, err := localOwnedWorkspaceReadRoster(ctx, s, accountPath)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, localOwnedWorkspaceCanceled(err, "context")
	}

	configs, entryPaths, err := localOwnedWorkspaceProfileConfigs(profileDir)
	if err != nil {
		return nil, nil, err
	}

	owners := make(map[string]personal.VaultFileOwnershipPublic, len(roster))
	seenOwnerKey := make(map[string]bool, len(roster))
	seenOwnerRoot := make(map[string]bool, len(roster))
	for _, owner := range roster {
		owners[owner.VaultID] = owner
		if seenOwnerKey[owner.OwnerRootKeyID] || seenOwnerRoot[owner.OwnerRootPublicKey] {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "shared owner")
		}
		seenOwnerKey[owner.OwnerRootKeyID] = true
		seenOwnerRoot[owner.OwnerRootPublicKey] = true
	}

	// Every .json entry is parsed before the set cardinality is compared, so an
	// extra malformed or foreign config is a manifest/source refusal rather
	// than a silent count mismatch.
	manifests := make([]Manifest, 0, len(configs))
	seenVault := make(map[string]string, len(configs))
	seenName := make(map[string]string, len(configs))
	seenJournal := make(map[string]string, len(configs))
	seenArchive := make(map[string]string, len(configs))
	for _, config := range configs {
		if err := ctx.Err(); err != nil {
			return nil, nil, localOwnedWorkspaceCanceled(err, "context")
		}
		manifest, exists, err := ReadManifest(config)
		if err != nil || !exists {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "manifest")
		}
		if manifest.PersonalFile != accountPath || manifest.BackendRoot != backendRoot {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "source")
		}
		owner, ok := owners[manifest.VaultID]
		if !ok {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "foreign vault")
		}
		if manifest.VaultID != owner.VaultID {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "owner")
		}
		if _, duplicate := seenVault[manifest.VaultID]; duplicate {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate vault")
		}
		if _, duplicate := seenName[manifest.Name]; duplicate {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate backend name")
		}
		if _, duplicate := seenJournal[manifest.Journal]; duplicate {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate journal")
		}
		if _, duplicate := seenArchive[manifest.Archive]; duplicate {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate archive")
		}
		seenVault[manifest.VaultID] = config
		seenName[manifest.Name] = config
		seenJournal[manifest.Journal] = config
		seenArchive[manifest.Archive] = config
		manifests = append(manifests, manifest)
	}
	if len(configs) != len(roster) || len(manifests) != len(roster) {
		return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "config set")
	}

	// Only the exact parsed manifests, their exact companion sidecars and the
	// exact journal/archive children named by those validated manifests may
	// occupy the protected profile directory. There is no directory, prefix,
	// suffix or arbitrary-file allowance.
	companions := make([]string, len(configs))
	allowed := make(map[string]bool, len(configs)*4)
	for index, config := range configs {
		companion, err := CompanionPath(config)
		if err != nil {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "companion path")
		}
		companions[index] = companion
		allowed[config] = true
		allowed[companion] = true
		if filepath.Dir(manifests[index].Journal) == profileDir {
			allowed[manifests[index].Journal] = true
		}
		if filepath.Dir(manifests[index].Archive) == profileDir {
			allowed[manifests[index].Archive] = true
		}
	}
	for _, path := range entryPaths {
		if !allowed[path] {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "profile entry")
		}
	}

	// Detect aliases, hard links and case-insensitive path collisions across
	// the whole working set, not just within each strict manifest.
	paths := make([]string, 0, 2+len(configs)*4)
	paths = append(paths, profileDir, backendRoot)
	for index, config := range configs {
		paths = append(paths, config, companions[index], manifests[index].Journal, manifests[index].Archive)
	}
	if !teamfiles.Distinct(paths...) {
		return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "ambiguous paths")
	}

	vaults := make([]LocalOwnedWorkspaceVault, 0, len(roster))
	for index, config := range configs {
		if err := ctx.Err(); err != nil {
			return nil, nil, localOwnedWorkspaceCanceled(err, "context")
		}
		entry, err := localOwnedWorkspaceReadVault(ctx, accountPath, backendRoot,
			owners[manifests[index].VaultID], config, manifests[index], scope)
		if err != nil {
			return nil, nil, err
		}
		vaults = append(vaults, entry)
	}
	if len(vaults) != len(roster) {
		return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "partial set")
	}
	for _, owner := range roster {
		if _, ok := seenVault[owner.VaultID]; !ok {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "missing vault")
		}
	}

	sort.Slice(vaults, func(i, j int) bool { return vaults[i].VaultID < vaults[j].VaultID })
	confirmed, err := localOwnedWorkspaceReadRoster(ctx, s, accountPath)
	if err != nil {
		return nil, nil, err
	}
	if !sameLocalOwnedWorkspaceRoster(roster, confirmed) {
		return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "roster drift")
	}
	return roster, vaults, nil
}

func localOwnedWorkspaceReadVault(ctx context.Context, accountPath, backendRoot string,
	owner personal.VaultFileOwnershipPublic, config string, manifest Manifest,
	scope localOwnedWorkspaceSourceScope) (entry LocalOwnedWorkspaceVault, retErr error) {
	if err := ctx.Err(); err != nil {
		return entry, localOwnedWorkspaceCanceled(err, "context")
	}
	if manifest.VaultID != owner.VaultID || manifest.PersonalFile != accountPath ||
		manifest.BackendRoot != backendRoot {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "locator")
	}
	manifestDigest, err := ReadManifestDigest(config, manifest)
	if err != nil {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "manifest digest")
	}
	manifestSHA256, ok := localOwnedWorkspaceDigest(manifestDigest)
	if !ok {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "manifest digest")
	}
	companion, exists, err := ReadCompanion(config, manifest)
	if err != nil || !exists || companion.ManifestSHA256 != manifestDigest ||
		companion.Resume.Checkpoint == nil || companion.Resume.BackendRoot != backendRoot ||
		companion.Resume.PersonalFile != accountPath || companion.Resume.Name != manifest.Name ||
		companion.Resume.Journal != manifest.Journal {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "companion")
	}
	checkpoint := companion.Resume.Checkpoint
	if checkpoint.VaultID != manifest.VaultID || checkpoint.OwnerRootKeyID != owner.OwnerRootKeyID ||
		checkpoint.OwnerRootPublicKey != owner.OwnerRootPublicKey {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "owner")
	}
	root, ok := DecodeHex(owner.OwnerRootPublicKey)
	if !ok || len(root) != ed25519.PublicKeySize {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "owner root")
	}
	clear(root)
	if err := ctx.Err(); err != nil {
		return entry, localOwnedWorkspaceCanceled(err, "context")
	}

	// The established snapshot reader owns the pending/missing/corrupt
	// classification. Run it before the duplicate companion verifier so a
	// pending journal is reported as a conflict, not a generic review. The
	// maintenance-fence scope supplies the already-locked journal handle, so
	// this read does not reopen the path.
	snapshot, verified, err := localOwnedWorkspaceReadVaultJournalState(ctx, scope, manifest, companion)
	if err != nil {
		return entry, err
	}
	defer snapshot.clear()
	defer clearLocalGenesisVerified(&verified)
	if verified.checkpoint == nil || snapshot.checkpoint == nil ||
		localOwnedBackupCheckpointDigest(*verified.checkpoint) != localOwnedBackupCheckpointDigest(*snapshot.checkpoint) {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "checkpoint")
	}
	if err := snapshot.bind(verified.successor, verified.revision); err != nil {
		return entry, localOwnedWorkspaceMapBackup(err)
	}
	if err := ctx.Err(); err != nil {
		return entry, localOwnedWorkspaceCanceled(err, "context")
	}

	backendRevision, err := scope.readTarget(ctx, manifest, snapshot.current, snapshot.journalRevision)
	if err != nil {
		return entry, localOwnedWorkspaceMapBackup(err)
	}
	if backendRevision != snapshot.journalRevision {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "backend revision")
	}

	currentSHA256 := sha256.Sum256(snapshot.current)
	var originSHA256 [sha256.Size]byte
	if snapshot.origin != nil {
		originSHA256 = sha256.Sum256(snapshot.origin)
	}
	source := LocalOwnedBackupSource{
		VaultID:         manifest.VaultID,
		Current:         snapshot.current,
		Origin:          snapshot.origin,
		JournalRevision: snapshot.journalRevision,
		BackendRevision: backendRevision,
		OriginRevision:  snapshot.originRevision,
		ContentSeq:      snapshot.contentSeq,
		Checkpoint:      *snapshot.checkpoint,
	}
	source.CheckpointDigest = localOwnedBackupCheckpointDigest(source.Checkpoint)
	source.IdentityDigest = localOwnedBackupIdentityDigest(source)
	entry = LocalOwnedWorkspaceVault{
		VaultID:          source.VaultID,
		ManifestSHA256:   manifestSHA256,
		CurrentSHA256:    currentSHA256,
		OriginSHA256:     originSHA256,
		CheckpointDigest: source.CheckpointDigest,
		IdentityDigest:   source.IdentityDigest,
		JournalRevision:  source.JournalRevision,
		BackendRevision:  source.BackendRevision,
		OriginRevision:   source.OriginRevision,
		ContentSeq:       source.ContentSeq,
	}
	source.Clear()
	if err := ctx.Err(); err != nil {
		return LocalOwnedWorkspaceVault{}, localOwnedWorkspaceCanceled(err, "context")
	}
	return entry, nil
}

func localOwnedWorkspaceReadRoster(ctx context.Context, s *personal.Session,
	accountPath string) ([]personal.VaultFileOwnershipPublic, error) {
	if err := ctx.Err(); err != nil {
		return nil, localOwnedWorkspaceCanceled(err, "context")
	}
	if s == nil || !s.Unlocked() || s.VaultPath() != accountPath {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	owners, err := s.VaultFileOwnerships()
	if err != nil {
		switch {
		case errors.Is(err, personal.ErrSessionLocked):
			return nil, fmt.Errorf("%w: %w", ErrLocalOwnedWorkspaceCanceled, personal.ErrSessionLocked)
		default:
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "roster")
		}
	}
	if len(owners) > maxLocalOwnedWorkspaceEntries {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "roster size")
	}
	seenVault := make(map[string]bool, len(owners))
	seenKey := make(map[string]bool, len(owners))
	seenRoot := make(map[string]bool, len(owners))
	for _, owner := range owners {
		if !ValidID(owner.VaultID) || !ValidID(owner.OwnerRootKeyID) ||
			seenVault[owner.VaultID] || seenKey[owner.OwnerRootKeyID] || seenRoot[owner.OwnerRootPublicKey] {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "roster")
		}
		root, ok := DecodeHex(owner.OwnerRootPublicKey)
		if !ok || len(root) != ed25519.PublicKeySize {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "roster root")
		}
		clear(root)
		seenVault[owner.VaultID] = true
		seenKey[owner.OwnerRootKeyID] = true
		seenRoot[owner.OwnerRootPublicKey] = true
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].VaultID < owners[j].VaultID })
	return owners, nil
}

// localOwnedWorkspaceProfileConfigs enumerates only direct regular children.
// It returns every exact entry path so the caller can refuse anything that a
// validated manifest does not name. Nested directories, symlinks, special files
// and unsupported names are refused without traversal.
func localOwnedWorkspaceProfileConfigs(profileDir string) ([]string, []string, error) {
	entries, err := os.ReadDir(profileDir)
	if err != nil || len(entries) > maxLocalOwnedWorkspaceEntries {
		return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "profile entries")
	}
	configs := make([]string, 0, len(entries))
	entryPaths := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "profile entry")
		}
		path := filepath.Join(profileDir, entry.Name())
		if !localOwnedWorkspaceValidPath(path) || filepath.Dir(path) != profileDir {
			return nil, nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "config path")
		}
		entryPaths = append(entryPaths, path)
		// The production manifest name ends in exactly lowercase ".json". A
		// differently spelled but otherwise valid manifest must not be skipped
		// and then accepted as an unknown extra child.
		if strings.HasSuffix(entry.Name(), ".json") {
			configs = append(configs, path)
		}
	}
	sort.Strings(configs)
	return configs, entryPaths, nil
}

func localOwnedWorkspaceStillBound(ctx context.Context, s *personal.Session, accountPath,
	profileDir, backendRoot string, profileBinding, backendBinding localOwnedWorkspaceDirectoryBinding,
	scope localOwnedWorkspaceSourceScope) error {
	if err := ctx.Err(); err != nil {
		return localOwnedWorkspaceCanceled(err, "context")
	}
	if s == nil || !s.Unlocked() || s.VaultPath() != accountPath {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	profileNow, err := localOwnedWorkspaceDirectory(profileDir, true)
	if err != nil {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "profile")
	}
	backendNow, err := localOwnedWorkspaceDirectory(backendRoot, false)
	if err != nil {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "backend")
	}
	// Compare both the exact lexical leaf identity and the resolved target
	// captured before the read. A retargeted ancestor symlink or a replaced
	// directory must not be mistaken for the original scope.
	if !os.SameFile(profileBinding.info, profileNow.info) ||
		!os.SameFile(backendBinding.info, backendNow.info) ||
		profileBinding.resolved != profileNow.resolved ||
		backendBinding.resolved != backendNow.resolved {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "path replaced")
	}
	if localOwnedWorkspaceNested(profileDir, backendRoot) ||
		localOwnedWorkspaceNested(profileNow.resolved, backendNow.resolved) ||
		os.SameFile(profileNow.info, backendNow.info) {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "path replaced")
	}
	if scope.requireBackendExists {
		if err := localOwnedWorkspaceBackendExisting(backendRoot); err != nil {
			return localOwnedWorkspaceMapReview(err, "backend")
		}
	}
	return nil
}

type localOwnedWorkspaceDirectoryBinding struct {
	info     os.FileInfo
	resolved string
}

// sameLocalOwnedWorkspaceDirectoryBinding requires both the exact leaf
// identity and the resolved target to match. A same-path replacement with the
// same permissions and contents still has a different identity, so it cannot
// silently become the directory the caller bound earlier.
func sameLocalOwnedWorkspaceDirectoryBinding(a, b localOwnedWorkspaceDirectoryBinding) bool {
	return a.resolved == b.resolved && os.SameFile(a.info, b.info)
}

// localOwnedWorkspaceDirectory captures the exact caller path's real leaf and
// its resolved existing-ancestor target. profile must additionally satisfy the
// existing private-parent rule. The leaf itself must not be a symlink.
func localOwnedWorkspaceDirectory(path string, private bool) (localOwnedWorkspaceDirectoryBinding, error) {
	var binding localOwnedWorkspaceDirectoryBinding
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return binding, ErrLocalReview
	}
	if private && teamfiles.ValidatePrivateParent(path) != nil {
		return binding, ErrLocalReview
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == "" || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return binding, ErrLocalReview
	}
	resolvedInfo, err := os.Lstat(resolved)
	if err != nil || resolvedInfo.Mode()&os.ModeSymlink != 0 || !resolvedInfo.IsDir() ||
		!os.SameFile(info, resolvedInfo) {
		return binding, ErrLocalReview
	}
	binding.info = info
	binding.resolved = resolved
	return binding, nil
}

func localOwnedWorkspaceBackendExisting(root string) error {
	backend, err := vaultfilebackend.OpenExistingDir(root)
	if err != nil {
		return err
	}
	return backend.Close()
}

func localOwnedWorkspaceValidPath(path string) bool {
	return teamfiles.ValidPath(path)
}

func localOwnedWorkspaceNested(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	sep := string(os.PathSeparator)
	return a == b || strings.HasPrefix(a, b+sep) || strings.HasPrefix(b, a+sep)
}

func localOwnedWorkspaceDigest(value string) ([sha256.Size]byte, bool) {
	var out [sha256.Size]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != value {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

func sameLocalOwnedWorkspaceRoster(a, b []personal.VaultFileOwnershipPublic) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func sameLocalOwnedWorkspaceVaults(a, b []LocalOwnedWorkspaceVault) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func localOwnedWorkspacePathDigest(label, path string) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark/vaultfileclient/owned-workspace/path/v1\x00"))
	writeLocalOwnedBackupString(h, label)
	writeLocalOwnedBackupString(h, path)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func localOwnedWorkspaceRosterDigest(roster []personal.VaultFileOwnershipPublic) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark/vaultfileclient/owned-workspace/roster/v1\x00"))
	var count [8]byte
	writeLocalOwnedWorkspaceUint64(h, count, uint64(len(roster)))
	for _, owner := range roster {
		writeLocalOwnedBackupString(h, owner.VaultID)
		writeLocalOwnedBackupString(h, owner.OwnerRootKeyID)
		writeLocalOwnedBackupString(h, owner.OwnerRootPublicKey)
		writeLocalOwnedBackupString(h, owner.RecoveryDeviceID)
		writeLocalOwnedBackupString(h, owner.RecoveryAgeRecipient)
		writeLocalOwnedBackupString(h, owner.RecoveryContentSigningPublicKey)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func localOwnedWorkspaceSetDigest(proof LocalOwnedWorkspacePreflight) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark/vaultfileclient/owned-workspace/set/v1\x00"))
	_, _ = h.Write(proof.AccountDigest[:])
	_, _ = h.Write(proof.ProfileDigest[:])
	_, _ = h.Write(proof.BackendDigest[:])
	_, _ = h.Write(proof.RosterDigest[:])
	writeLocalOwnedBackupString(h, string(proof.State))
	flags := []byte{0, 0, 0, 0}
	if proof.StopWritesProofOutstanding {
		flags[0] = 1
	}
	if proof.FullBackupOutstanding {
		flags[1] = 1
	}
	if proof.CutoverOutstanding {
		flags[2] = 1
	}
	if proof.UnknownOfflineDraftsPossible {
		flags[3] = 1
	}
	_, _ = h.Write(flags)
	var count [8]byte
	writeLocalOwnedWorkspaceUint64(h, count, uint64(len(proof.Vaults)))
	for _, vault := range proof.Vaults {
		writeLocalOwnedBackupString(h, vault.VaultID)
		_, _ = h.Write(vault.ManifestSHA256[:])
		_, _ = h.Write(vault.CurrentSHA256[:])
		_, _ = h.Write(vault.OriginSHA256[:])
		_, _ = h.Write(vault.CheckpointDigest[:])
		_, _ = h.Write(vault.IdentityDigest[:])
		writeLocalOwnedBackupString(h, string(vault.JournalRevision))
		writeLocalOwnedBackupString(h, string(vault.BackendRevision))
		writeLocalOwnedBackupString(h, string(vault.OriginRevision))
		writeLocalOwnedWorkspaceUint64(h, count, vault.ContentSeq)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeLocalOwnedWorkspaceUint64(h hash.Hash, buf [8]byte, value uint64) {
	buf[0] = byte(value >> 56)
	buf[1] = byte(value >> 48)
	buf[2] = byte(value >> 40)
	buf[3] = byte(value >> 32)
	buf[4] = byte(value >> 24)
	buf[5] = byte(value >> 16)
	buf[6] = byte(value >> 8)
	buf[7] = byte(value)
	_, _ = h.Write(buf[:])
}

func localOwnedWorkspaceMapReview(err error, reason string) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrLocalOwnedWorkspaceCanceled, err)
	case errors.Is(err, vaultfilebackend.ErrUnsupported):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceUnsupported, reason)
	default:
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, reason)
	}
}

func localOwnedWorkspaceMapBackup(err error) error {
	switch {
	case errors.Is(err, ErrLocalOwnedBackupCanceled):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "source")
	case errors.Is(err, ErrLocalOwnedBackupConflict):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "source")
	case errors.Is(err, ErrLocalOwnedBackupUnsupported):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceUnsupported, "source")
	default:
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "source")
	}
}

func localOwnedWorkspaceCanceled(err error, reason string) error {
	return fmt.Errorf("%w: %s: %w", ErrLocalOwnedWorkspaceCanceled, reason, err)
}

func localOwnedWorkspaceError(category error, reason string) error {
	return fmt.Errorf("%w: %s", category, reason)
}
