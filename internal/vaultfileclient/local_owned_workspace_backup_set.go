package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

// This file is the read-only workspace-level backup-set checkpoint. It couples
// the accepted owned-workspace source preflight to the accepted per-artifact
// custody opener and exact target reader. It never creates a backup, writes a
// source/backend/artifact, activates a profile, adopts a child, transitions
// policy, calls a remote provider or installs a restore. A successful value
// covers only the currently observed, supported, account-owned local set. It is
// not a stop-writers proof, offline-draft proof, complete-workspace backup or
// cutover authorization.

// LocalOwnedWorkspaceBackupSetState names the only successful aggregate
// outcome. It intentionally describes only the currently observed set.
type LocalOwnedWorkspaceBackupSetState string

const (
	// LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified means every
	// vault in the exact roster observed by this call had exactly one matching
	// authentic portable custody artifact. It makes no claim about unknown
	// offline profiles, new-profile import, remote/shared writers or cutover.
	LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified LocalOwnedWorkspaceBackupSetState = "ALL_CURRENTLY_OBSERVED_SUPPORTED_OWNED_LOCAL_VAULTS_HAVE_MATCHING_PORTABLE_CUSTODY_ARTIFACTS"
)

// LocalOwnedWorkspaceBackupArtifact is one independently held custody artifact
// input. Pin is the trusted save/reopen pin with Path updated to the relocated
// private file; Factor is the separately held recovery factor. The artifact and
// factor are not authority for the workspace scope: the operation recomputes the
// live Session/workspace proof and the canonical manifest/checkpoint binding.
//
// String, GoString, MarshalJSON and Format are fixed redactions because the
// value retains a factor pointer and a private file path.
type LocalOwnedWorkspaceBackupArtifact struct {
	Pin    LocalOwnedBackupCustodyFile
	Factor *personal.VaultFileBackupRecoveryFactor
}

func (LocalOwnedWorkspaceBackupArtifact) String() string {
	return "[local owned workspace backup artifact]"
}
func (LocalOwnedWorkspaceBackupArtifact) GoString() string {
	return "[local owned workspace backup artifact]"
}
func (LocalOwnedWorkspaceBackupArtifact) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedWorkspaceBackupArtifact) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local owned workspace backup artifact]"))
}

// LocalOwnedWorkspaceBackupVault is the closed, digest-only observation for one
// observed vault and its admitted artifact. ManifestSHA256 and the checkpoint /
// source identities are the exact independently observed source bindings;
// ArtifactSHA256 and SourceIdentity are the exact admitted artifact bindings.
// It contains no path, factor, checkpoint byte, ciphertext or item.
type LocalOwnedWorkspaceBackupVault struct {
	VaultID          string
	ManifestSHA256   [sha256.Size]byte
	CurrentSHA256    [sha256.Size]byte
	OriginSHA256     [sha256.Size]byte
	CheckpointDigest [sha256.Size]byte
	// IdentityDigest is the exact local source identity recomputed from the
	// authenticated artifact bytes and matched to the workspace preflight.
	IdentityDigest [sha256.Size]byte
	// SourceIdentity is the independently pinned custody source identity from
	// the trusted artifact pin and the authenticated artifact.
	SourceIdentity  [sha256.Size]byte
	ArtifactSize    int64
	ArtifactSHA256  [sha256.Size]byte
	JournalRevision vaultfilebackend.Revision
	BackendRevision vaultfilebackend.Revision
	OriginRevision  vaultfilebackend.Revision
	ContentSeq      uint64
}

func (LocalOwnedWorkspaceBackupVault) String() string {
	return "[local owned workspace backup vault]"
}
func (LocalOwnedWorkspaceBackupVault) GoString() string {
	return "[local owned workspace backup vault]"
}
func (LocalOwnedWorkspaceBackupVault) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedWorkspaceBackupVault) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local owned workspace backup vault]"))
}

// LocalOwnedWorkspaceBackupSet is the closed read-only aggregate. It binds the
// exact live source proof (account/profile/backend/roster/known set) to the
// admitted per-vault artifact digests. Vaults is a private copy in VaultID
// order. Even on success, stop-writers proof, unknown offline drafts, new-profile
// import, cutover and complete-workspace verification remain outstanding.
type LocalOwnedWorkspaceBackupSet struct {
	AccountDigest   [sha256.Size]byte
	ProfileDigest   [sha256.Size]byte
	BackendDigest   [sha256.Size]byte
	RosterDigest    [sha256.Size]byte
	KnownSetDigest  [sha256.Size]byte
	BackupSetDigest [sha256.Size]byte
	Vaults          []LocalOwnedWorkspaceBackupVault
	State           LocalOwnedWorkspaceBackupSetState

	StopWritesProofOutstanding   bool
	UnknownOfflineDraftsPossible bool
	NewProfileImportOutstanding  bool
	CutoverOutstanding           bool
	CompleteWorkspaceOutstanding bool
}

func (LocalOwnedWorkspaceBackupSet) String() string {
	return "[local owned workspace backup set]"
}
func (LocalOwnedWorkspaceBackupSet) GoString() string {
	return "[local owned workspace backup set]"
}
func (LocalOwnedWorkspaceBackupSet) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (*LocalOwnedWorkspaceBackupSet) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[local owned workspace backup set]"))
}

// localOwnedWorkspaceBackupSetBeforeFinalProofForTest is nil in production. A
// test may make one real source change after all artifact reads and before the
// final source-set gate. It cannot inject success.
var localOwnedWorkspaceBackupSetBeforeFinalProofForTest func()

// localOwnedWorkspaceBackupSetBeforeDeliveryForTest is nil in production. A
// test may remove or replace one already-verified custody file, or replace a
// captured source directory, after the final source-set gate and before the
// delivery recheck/gate. It cannot inject success.
var localOwnedWorkspaceBackupSetBeforeDeliveryForTest func()

// localOwnedWorkspaceBackupArtifactRequest is one private value snapshot of a
// caller-supplied artifact request. The complete pin is copied by value,
// including every scalar, text revision and digest field. Factor is the same
// separately held pointer, never a copy of its recovery material. After the
// capture below, no stage reads the original caller slice or pin again.
//
// The Go input contract does not support concurrent mutation of the caller
// slice, or of a pin value, while the initial copy is in progress. Once the
// bounded copy is complete every later stage, including the final delivery
// recheck, is private to this call.
type localOwnedWorkspaceBackupArtifactRequest struct {
	pin    LocalOwnedBackupCustodyFile
	factor *personal.VaultFileBackupRecoveryFactor
}

// captureLocalOwnedWorkspaceBackupArtifactRequests copies the complete caller
// request once. It applies the existing workspace/roster entry bound before
// making the snapshot allocation, preserves the empty list, and never copies
// factor material. A later caller change cannot alter indexing, authentication
// or the delivery recheck because only this private copy is used.
func captureLocalOwnedWorkspaceBackupArtifactRequests(ctx context.Context,
	artifacts []LocalOwnedWorkspaceBackupArtifact) ([]localOwnedWorkspaceBackupArtifactRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, localOwnedWorkspaceCanceled(err, "context")
	}
	if len(artifacts) > maxLocalOwnedWorkspaceEntries {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact set")
	}
	if len(artifacts) == 0 {
		return nil, nil
	}
	captured := make([]localOwnedWorkspaceBackupArtifactRequest, len(artifacts))
	for position := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, localOwnedWorkspaceCanceled(err, "context")
		}
		captured[position] = localOwnedWorkspaceBackupArtifactRequest{
			pin:    artifacts[position].Pin,
			factor: artifacts[position].Factor,
		}
	}
	return captured, nil
}

// VerifyLocalOwnedWorkspaceBackupSet performs one explicit bounded, read-only
// verification of the exact currently observed account-owned local workspace
// backup set.
//
// The caller supplies the live full-factor-unlocked Session, the one protected
// profile directory, the one existing local backend root and exactly one
// artifact input per expected vault. The complete artifact list is copied once,
// up front, into a private value snapshot bounded by the existing
// workspace/roster entry limit. Concurrent mutation during that initial copy is
// unsupported; after capture, indexing, authentication and the delivery recheck
// use only the private copy and never re-read the caller slice. The operation
// itself calls PreflightLocalOwnedWorkspaceSource, so a caller-provided
// preflight is never authority. It then independently re-reads each strict
// manifest and companion to bind the canonical VaultID, backend root, object
// name and expected policy checkpoint to the proof's manifest digest and
// checkpoint digest. A caller cannot suggest the root, name or checkpoint.
//
// Before any artifact is opened, the artifact pins must cover the proof roster
// exactly 1:1 with unique VaultID, private relocated path, source identity,
// artifact digest and size. Each artifact is then opened one at a time with the
// existing secure custody-file opener and the separately held factor. The opener
// re-authenticates the artifact against the exact pin and the checkpoint read
// from the strict observed companion. The authenticated current bytes and opaque
// revision are then read from the canonical manifest-named local backend object
// with the accepted checked direct-read pattern. That read retains no pulled
// value and clears its one fresh buffer before returning. The operation requires
// exact equality of VaultID, current/origin SHA-256, local source identity,
// custody source identity, checkpoint digest, every opaque revision and content
// sequence, and recomputes the local source identity from the opened artifact.
//
// After the per-vault reads, the complete source preflight is run again. Any
// observed source roster, manifest, companion, journal, backend, source path or
// revision drift fails the whole call. The exact same pinned custody files are
// then re-read at their original validated private paths and must retain the
// pinned size and SHA-256; a missing, replaced or non-private file fails the
// whole call. This recheck does not decrypt again: the earlier opener already
// authenticated those exact bytes, and a second decrypt is unnecessary when the
// ciphertext matches the immutable pin. An active-session and context check is
// made immediately before the aggregate is returned. On any failure the zero
// aggregate is returned. Success means only that all currently observed
// supported owned local vaults had matching portable custody artifacts. It does
// not prove that writers stopped, offline drafts are absent, a new profile can
// be imported, cutover is authorized or the whole workspace is backed up.
func VerifyLocalOwnedWorkspaceBackupSet(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string,
	artifacts []LocalOwnedWorkspaceBackupArtifact) (set LocalOwnedWorkspaceBackupSet, retErr error) {
	empty := LocalOwnedWorkspaceBackupSet{}
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || !localOwnedWorkspaceValidPath(profileDir) ||
		!localOwnedWorkspaceValidPath(backendRoot) ||
		localOwnedWorkspaceNested(profileDir, backendRoot) {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "request")
	}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedWorkspaceCanceled(err, "context")
	}

	first, err := PreflightLocalOwnedWorkspaceSource(ctx, s, profileDir, backendRoot)
	if err != nil {
		return empty, err
	}
	if first.State != LocalOwnedWorkspaceStateKnownInventoryReady {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "source set")
	}
	request, err := captureLocalOwnedWorkspaceBackupArtifactRequests(ctx, artifacts)
	if err != nil {
		return empty, err
	}
	prep, err := localOwnedWorkspaceBackupPrepare(ctx, s, profileDir, backendRoot, first, request)
	if err != nil {
		return empty, err
	}
	return localOwnedWorkspaceBackupFinalize(ctx, s, profileDir, backendRoot, request, prep,
		localOwnedWorkspaceBackupSetBeforeFinalProofForTest,
		localOwnedWorkspaceBackupSetBeforeDeliveryForTest,
		nil,
		func(ctx context.Context) (LocalOwnedWorkspacePreflight, error) {
			return PreflightLocalOwnedWorkspaceSource(ctx, s, profileDir, backendRoot)
		})
}

// localOwnedWorkspaceBackupPreparation is the expensive, artifact-authenticated
// part of a backup-set verification. Its proof is the exact source observation
// the remaining final validation and delivery must match.
type localOwnedWorkspaceBackupPreparation struct {
	proof  LocalOwnedWorkspacePreflight
	vaults []LocalOwnedWorkspaceBackupVault
}

// localOwnedWorkspaceBackupPrepare authenticates the artifact set and its exact
// source bindings without making the final delivery decision. It is the same
// work VerifyLocalOwnedWorkspaceBackupSet performs before its final source
// gate, reused by the maintenance-fence entry outside the provider lock.
func localOwnedWorkspaceBackupPrepare(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string, first LocalOwnedWorkspacePreflight,
	request []localOwnedWorkspaceBackupArtifactRequest) (prep localOwnedWorkspaceBackupPreparation, retErr error) {
	if len(request) != len(first.Vaults) {
		return prep, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact set")
	}
	index, err := localOwnedWorkspaceBackupArtifactIndex(ctx, first, request)
	if err != nil {
		return prep, err
	}
	bindings, err := localOwnedWorkspaceBackupBindings(ctx, s, profileDir, backendRoot, first)
	if err != nil {
		return prep, err
	}
	defer clearLocalOwnedWorkspaceBackupBindings(bindings)

	vaults := make([]LocalOwnedWorkspaceBackupVault, 0, len(first.Vaults))
	for _, proofVault := range first.Vaults {
		if err := ctx.Err(); err != nil {
			return prep, localOwnedWorkspaceCanceled(err, "context")
		}
		binding, ok := bindings[proofVault.VaultID]
		if !ok {
			return prep, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact binding")
		}
		entry, err := localOwnedWorkspaceBackupVault(ctx, proofVault, binding,
			request[index[proofVault.VaultID]])
		if err != nil {
			return prep, err
		}
		vaults = append(vaults, entry)
	}
	if err := ctx.Err(); err != nil {
		return prep, localOwnedWorkspaceCanceled(err, "context")
	}
	prep.proof = first
	prep.vaults = vaults
	return prep, nil
}

// localOwnedWorkspaceBackupFinalize performs the final source gate, artifact
// recheck and delivery decision. finalProof is the only source observation
// used here; the maintenance-fence entry supplies a view-backed proof so the
// whole gate runs under the already-held provider lock. On any failure the zero
// aggregate is returned and no partial proof escapes.
func localOwnedWorkspaceBackupFinalize(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string, request []localOwnedWorkspaceBackupArtifactRequest,
	prep localOwnedWorkspaceBackupPreparation,
	beforeFinalProof, beforeDelivery func(), finalGate func() error,
	finalProof func(context.Context) (LocalOwnedWorkspacePreflight, error)) (set LocalOwnedWorkspaceBackupSet, retErr error) {
	empty := LocalOwnedWorkspaceBackupSet{}
	if err := ctx.Err(); err != nil {
		return empty, localOwnedWorkspaceCanceled(err, "context")
	}
	if beforeFinalProof != nil {
		beforeFinalProof()
	}
	final, err := finalProof(ctx)
	if err != nil {
		return empty, err
	}
	if !sameLocalOwnedWorkspaceBackupProof(prep.proof, final) {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "source drift")
	}

	if beforeDelivery != nil {
		beforeDelivery()
	}
	if err := recheckLocalOwnedWorkspaceBackupArtifacts(ctx, s, request); err != nil {
		return empty, err
	}
	// The final source proof and the artifact recheck above are real observed
	// boundaries, but neither is an atomic writer freeze. Check the live session
	// and context once more immediately before the point-in-time aggregate is
	// granted; a lock or cancellation during the added work still yields empty.
	if err := ctx.Err(); err != nil {
		return empty, localOwnedWorkspaceCanceled(err, "context")
	}
	if s == nil || !s.Unlocked() {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	accountPath := s.VaultPath()
	if accountPath == "" {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	if localOwnedWorkspacePathDigest("account", accountPath) != prep.proof.AccountDigest {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "active scope")
	}
	// finalGate is the fenced caller's last identity check. It runs after the
	// final artifact and account rechecks and immediately before the aggregate
	// is built, so a same-path directory replacement during those rechecks
	// yields the zero aggregate instead of authoritative new identities.
	if finalGate != nil {
		if err := finalGate(); err != nil {
			return empty, err
		}
		// The gate itself can take a bounded but real amount of time. Recheck
		// cancellation, the live session and the exact account path after it so
		// a late lock or context loss still yields no result.
		if err := ctx.Err(); err != nil {
			return empty, localOwnedWorkspaceCanceled(err, "context")
		}
		if s == nil || !s.Unlocked() {
			return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
		}
		accountPath = s.VaultPath()
		if accountPath == "" {
			return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
		}
		if localOwnedWorkspacePathDigest("account", accountPath) != prep.proof.AccountDigest {
			return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "active scope")
		}
	}
	return localOwnedWorkspaceBackupSetFrom(prep.proof, prep.vaults), nil
}

func localOwnedWorkspaceBackupSetFrom(first LocalOwnedWorkspacePreflight,
	vaults []LocalOwnedWorkspaceBackupVault) LocalOwnedWorkspaceBackupSet {
	set := LocalOwnedWorkspaceBackupSet{
		AccountDigest:                first.AccountDigest,
		ProfileDigest:                first.ProfileDigest,
		BackendDigest:                first.BackendDigest,
		RosterDigest:                 first.RosterDigest,
		KnownSetDigest:               first.KnownSetDigest,
		Vaults:                       append([]LocalOwnedWorkspaceBackupVault(nil), vaults...),
		State:                        LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified,
		StopWritesProofOutstanding:   true,
		UnknownOfflineDraftsPossible: true,
		NewProfileImportOutstanding:  true,
		CutoverOutstanding:           true,
		CompleteWorkspaceOutstanding: true,
	}
	set.BackupSetDigest = localOwnedWorkspaceBackupSetDigest(set)
	return set
}

// localOwnedWorkspaceBackupArtifactIndex validates the 1:1 coverage and all
// light path/private-file preconditions from the private snapshot before any
// artifact bytes are read.
func localOwnedWorkspaceBackupArtifactIndex(ctx context.Context,
	proof LocalOwnedWorkspacePreflight,
	artifacts []localOwnedWorkspaceBackupArtifactRequest) (map[string]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, localOwnedWorkspaceCanceled(err, "context")
	}
	byID := make(map[string]LocalOwnedWorkspaceVault, len(proof.Vaults))
	for _, vault := range proof.Vaults {
		byID[vault.VaultID] = vault
	}
	index := make(map[string]int, len(artifacts))
	seenPath := make(map[string]bool, len(artifacts))
	seenDigest := make(map[[sha256.Size]byte]bool, len(artifacts))
	seenIdentity := make(map[[sha256.Size]byte]bool, len(artifacts))
	for position, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, localOwnedWorkspaceCanceled(err, "context")
		}
		pin := artifact.pin
		if !pin.valid() || artifact.factor == nil {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact request")
		}
		if pin.ArtifactSize > localOwnedBackupCustodyFileLimit {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceUnsupported, "artifact size")
		}
		if _, ok := byID[pin.VaultID]; !ok {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact scope")
		}
		if _, duplicate := index[pin.VaultID]; duplicate {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate artifact")
		}
		if !teamfiles.ValidPath(pin.Path) {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact path")
		}
		if seenPath[pin.Path] {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate artifact path")
		}
		if seenDigest[pin.ArtifactSHA256] {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate artifact digest")
		}
		if seenIdentity[pin.SourceIdentity] {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "duplicate source identity")
		}
		if err := localOwnedWorkspaceBackupArtifactPath(pin.Path); err != nil {
			return nil, err
		}
		index[pin.VaultID] = position
		seenPath[pin.Path] = true
		seenDigest[pin.ArtifactSHA256] = true
		seenIdentity[pin.SourceIdentity] = true
	}
	if len(index) != len(byID) {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact set")
	}
	for vaultID := range byID {
		if _, ok := index[vaultID]; !ok {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact set")
		}
	}
	return index, nil
}

func localOwnedWorkspaceBackupArtifactPath(path string) error {
	if !teamfiles.ValidPath(path) {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact path")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "artifact absent")
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact path")
	}
	if teamfiles.ValidatePrivateFile(path) != nil ||
		teamfiles.ValidatePrivateParent(filepath.Dir(path)) != nil {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact path")
	}
	return nil
}

// recheckLocalOwnedWorkspaceBackupArtifacts re-reads the exact same authenticated
// custody paths at delivery without decrypting again. A custody file can be
// removed or replaced after its first opener returned but before the aggregate
// is granted. The private value snapshot taken once at entry is the only
// authority here, so a caller slice or pin switch cannot substitute a different
// readable file. Each snapshot path must still pass the existing
// no-follow/private-file convention and contain exactly the pinned size and
// SHA-256 ciphertext. Bytes are always cleared. Missing, changed, canceled or
// locked work returns an error so the caller retains the zero aggregate.
func recheckLocalOwnedWorkspaceBackupArtifacts(ctx context.Context, s *personal.Session,
	artifacts []localOwnedWorkspaceBackupArtifactRequest) error {
	if err := ctx.Err(); err != nil {
		return localOwnedWorkspaceCanceled(err, "context")
	}
	if s == nil || !s.Unlocked() {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return localOwnedWorkspaceCanceled(err, "context")
		}
		if !s.Unlocked() {
			return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
		}
		pin := artifact.pin
		if !pin.valid() || artifact.factor == nil {
			return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact request")
		}
		if err := localOwnedWorkspaceBackupArtifactPath(pin.Path); err != nil {
			return err
		}
		data, err := teamfiles.ReadLimited(ctx, pin.Path, localOwnedBackupCustodyFileLimit, true)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
				ctx.Err() != nil {
				cause := ctx.Err()
				if cause == nil {
					cause = err
				}
				return localOwnedWorkspaceCanceled(cause, "context")
			}
			return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "artifact")
		}
		if int64(len(data)) != pin.ArtifactSize || sha256.Sum256(data) != pin.ArtifactSHA256 {
			clear(data)
			return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "artifact changed")
		}
		clear(data)
	}
	if err := ctx.Err(); err != nil {
		return localOwnedWorkspaceCanceled(err, "context")
	}
	if !s.Unlocked() {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	return nil
}

// readLocalOwnedWorkspaceBackupTarget applies the accepted single-vault
// restore-preflight checked direct-read pattern to the canonical
// manifest-named local object. It keeps the existing read-only Dir, exact
// bytes/revision, size contract, cancellation and close semantics. Unlike the
// producer ReadPulled helper, it retains no pulled value: the one fresh read
// buffer is cleared on every return path after its digest is computed.
func readLocalOwnedWorkspaceBackupTarget(ctx context.Context, manifest Manifest,
	expected []byte, wantRevision vaultfilebackend.Revision,
) (actualRevision vaultfilebackend.Revision, digest [sha256.Size]byte, retErr error) {
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		return "", digest, mapLocalOwnedBackupTargetError(err)
	}
	read, readErr := backend.Read(ctx, manifest.Name)
	defer clear(read.Bytes)
	closeErr := backend.Close()
	if readErr != nil {
		return "", digest, mapLocalOwnedBackupTargetError(readErr)
	}
	if closeErr != nil {
		return "", digest, mapLocalOwnedBackupTargetError(closeErr)
	}
	return validateLocalOwnedWorkspaceBackupTargetRead(read, expected, wantRevision)
}

// validateLocalOwnedWorkspaceBackupTargetRead applies the same exact
// bytes/revision, size and error mapping to a result read either through a fresh
// existing-only Dir or through the already-held protected view.
func validateLocalOwnedWorkspaceBackupTargetRead(read vaultfilebackend.ReadResult,
	expected []byte, wantRevision vaultfilebackend.Revision,
) (revision vaultfilebackend.Revision, digest [sha256.Size]byte, retErr error) {
	if len(read.Bytes) == 0 || len(read.Bytes) > vaultfilepublish.MaxPulledBytes ||
		len(read.Revision) == 0 || len(read.Revision) > vaultfilepublish.MaxPulledRevisionSize {
		return "", digest, mapLocalOwnedBackupTargetError(
			fmt.Errorf("%w: target result", vaultfilepublish.ErrBackendResult))
	}
	if read.Revision != wantRevision || !bytes.Equal(read.Bytes, expected) {
		return "", digest, mapLocalOwnedBackupTargetError(errLocalOwnedBackupTargetMismatch)
	}
	digest = sha256.Sum256(read.Bytes)
	return read.Revision, digest, nil
}

// localOwnedWorkspaceBackupBinding is the private canonical source binding for
// one proof vault. The checkpoint bytes are cloned from the strict observed
// companion, never from the artifact or a caller suggestion.
type localOwnedWorkspaceBackupBinding struct {
	manifest       Manifest
	manifestSHA256 [sha256.Size]byte
	checkpoint     vaultfile.PolicyCheckpoint
}

func (b *localOwnedWorkspaceBackupBinding) clear() {
	if b == nil {
		return
	}
	clear(b.checkpoint.OwnerRootPublicKey)
	clear(b.checkpoint.PolicyDigest)
	*b = localOwnedWorkspaceBackupBinding{}
}

func clearLocalOwnedWorkspaceBackupBindings(bindings map[string]*localOwnedWorkspaceBackupBinding) {
	for _, binding := range bindings {
		binding.clear()
	}
}

// localOwnedWorkspaceBackupBindings independently observes the strict profile
// manifests/companions again and requires their canonical VaultID, root, name,
// manifest digest and checkpoint digest to equal the accepted live proof. This
// is the owning accessor that avoids treating a caller-selected name or root as
// authority.
func localOwnedWorkspaceBackupBindings(ctx context.Context, s *personal.Session,
	profileDir, backendRoot string,
	proof LocalOwnedWorkspacePreflight) (bindings map[string]*localOwnedWorkspaceBackupBinding, retErr error) {
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
	if localOwnedWorkspacePathDigest("account", accountPath) != proof.AccountDigest ||
		localOwnedWorkspacePathDigest("profile", profileDir) != proof.ProfileDigest ||
		localOwnedWorkspacePathDigest("backend", backendRoot) != proof.BackendDigest {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "binding scope")
	}
	roster, err := localOwnedWorkspaceReadRoster(ctx, s, accountPath)
	if err != nil {
		return nil, err
	}
	if localOwnedWorkspaceRosterDigest(roster) != proof.RosterDigest {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "roster drift")
	}

	configs, _, err := localOwnedWorkspaceProfileConfigs(profileDir)
	if err != nil {
		return nil, localOwnedWorkspaceMapReview(err, "binding")
	}
	if len(configs) != len(proof.Vaults) {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "binding set")
	}
	proofByID := make(map[string]LocalOwnedWorkspaceVault, len(proof.Vaults))
	for _, vault := range proof.Vaults {
		proofByID[vault.VaultID] = vault
	}
	bindings = make(map[string]*localOwnedWorkspaceBackupBinding, len(configs))
	defer func() {
		if retErr != nil {
			clearLocalOwnedWorkspaceBackupBindings(bindings)
			bindings = nil
		}
	}()
	for _, config := range configs {
		if err := ctx.Err(); err != nil {
			return nil, localOwnedWorkspaceCanceled(err, "context")
		}
		manifest, exists, err := ReadManifest(config)
		if err != nil || !exists {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding manifest")
		}
		if manifest.PersonalFile != accountPath || manifest.BackendRoot != backendRoot {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding source")
		}
		entry, ok := proofByID[manifest.VaultID]
		if !ok {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding vault")
		}
		digestValue, err := ReadManifestDigest(config, manifest)
		if err != nil {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding manifest")
		}
		digest, ok := localOwnedWorkspaceDigest(digestValue)
		if !ok || digest != entry.ManifestSHA256 {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "manifest digest")
		}
		companion, exists, err := ReadCompanion(config, manifest)
		if err != nil || !exists || companion.Resume.Checkpoint == nil {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding companion")
		}
		if companion.Resume.BackendRoot != backendRoot ||
			companion.Resume.PersonalFile != accountPath ||
			companion.Resume.Name != manifest.Name ||
			companion.Resume.Journal != manifest.Journal {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding companion")
		}
		// Reuse the existing strict companion/journal verifier so the expected
		// checkpoint bytes and journal revision come from the observed source,
		// never from the artifact or a caller suggestion.
		verified, err := verifyLocalGenesisCompanion(manifest, companion)
		if err != nil || verified.checkpoint == nil ||
			verified.revision != string(entry.JournalRevision) {
			clearLocalGenesisVerified(&verified)
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding journal")
		}
		checkpoint := cloneLocalOwnedBackupCustodyCheckpoint(*verified.checkpoint)
		clearLocalGenesisVerified(&verified)
		if !localOwnedBackupCustodyFileCheckpointValid(checkpoint) ||
			checkpoint.VaultID != entry.VaultID ||
			localOwnedBackupCheckpointDigest(checkpoint) != entry.CheckpointDigest {
			clear(checkpoint.OwnerRootPublicKey)
			clear(checkpoint.PolicyDigest)
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding checkpoint")
		}
		if _, duplicate := bindings[manifest.VaultID]; duplicate {
			clear(checkpoint.OwnerRootPublicKey)
			clear(checkpoint.PolicyDigest)
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "binding duplicate")
		}
		bindings[manifest.VaultID] = &localOwnedWorkspaceBackupBinding{
			manifest:       manifest,
			manifestSHA256: digest,
			checkpoint:     checkpoint,
		}
	}
	if len(bindings) != len(proof.Vaults) {
		return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "binding set")
	}
	for vaultID := range proofByID {
		if _, ok := bindings[vaultID]; !ok {
			return nil, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "binding set")
		}
	}
	return bindings, nil
}

// localOwnedWorkspaceBackupVault verifies exactly one artifact against the live
// proof and the canonical manifest binding, then reads the exact named backend
// object. It retains only digests.
func localOwnedWorkspaceBackupVault(ctx context.Context,
	proofVault LocalOwnedWorkspaceVault,
	binding *localOwnedWorkspaceBackupBinding,
	artifact localOwnedWorkspaceBackupArtifactRequest) (entry LocalOwnedWorkspaceBackupVault, retErr error) {
	pin := artifact.pin
	if !pin.valid() || artifact.factor == nil {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact request")
	}
	if pin.VaultID != proofVault.VaultID ||
		pin.CheckpointDigest != proofVault.CheckpointDigest ||
		pin.JournalRevision != string(proofVault.JournalRevision) ||
		pin.BackendRevision != string(proofVault.BackendRevision) ||
		pin.OriginRevision != string(proofVault.OriginRevision) ||
		pin.ContentSeq != proofVault.ContentSeq {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact binding")
	}
	if binding == nil || binding.manifest.VaultID != proofVault.VaultID ||
		binding.manifestSHA256 != proofVault.ManifestSHA256 ||
		!localOwnedBackupCustodyFileCheckpointValid(binding.checkpoint) ||
		binding.checkpoint.VaultID != proofVault.VaultID ||
		localOwnedBackupCheckpointDigest(binding.checkpoint) != proofVault.CheckpointDigest {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "manifest binding")
	}
	if err := ctx.Err(); err != nil {
		return entry, localOwnedWorkspaceCanceled(err, "context")
	}

	opened, actual, err := OpenLocalOwnedBackupCustodyFile(ctx, pin.Path, pin,
		binding.checkpoint, artifact.factor)
	if err != nil {
		return entry, localOwnedWorkspaceMapBackup(err)
	}
	defer opened.Clear()
	if actual != pin {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact binding")
	}
	source := opened.Source
	currentSHA256 := sha256.Sum256(source.Current)
	var originSHA256 [sha256.Size]byte
	if source.Origin != nil {
		originSHA256 = sha256.Sum256(source.Origin)
	}
	if source.VaultID != proofVault.VaultID ||
		currentSHA256 != proofVault.CurrentSHA256 ||
		originSHA256 != proofVault.OriginSHA256 ||
		source.CheckpointDigest != proofVault.CheckpointDigest ||
		source.IdentityDigest != proofVault.IdentityDigest ||
		source.JournalRevision != proofVault.JournalRevision ||
		source.BackendRevision != proofVault.BackendRevision ||
		source.OriginRevision != proofVault.OriginRevision ||
		source.ContentSeq != proofVault.ContentSeq {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact source")
	}
	if opened.SourceIdentity != pin.SourceIdentity {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact identity")
	}
	if !sameLocalOwnedBackupCustodyCheckpoint(source.Checkpoint, binding.checkpoint) {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "artifact checkpoint")
	}
	if source.JournalRevision != source.BackendRevision {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "artifact revision")
	}

	targetRevision, targetSHA256, err := readLocalOwnedWorkspaceBackupTarget(
		ctx, binding.manifest, source.Current, source.BackendRevision)
	if err != nil {
		return entry, localOwnedWorkspaceMapBackup(err)
	}
	if targetRevision != proofVault.BackendRevision ||
		targetSHA256 != proofVault.CurrentSHA256 {
		return entry, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "backend bytes")
	}
	if err := ctx.Err(); err != nil {
		return entry, localOwnedWorkspaceCanceled(err, "context")
	}

	return LocalOwnedWorkspaceBackupVault{
		VaultID:          source.VaultID,
		ManifestSHA256:   binding.manifestSHA256,
		CurrentSHA256:    currentSHA256,
		OriginSHA256:     originSHA256,
		CheckpointDigest: source.CheckpointDigest,
		IdentityDigest:   source.IdentityDigest,
		SourceIdentity:   opened.SourceIdentity,
		ArtifactSize:     actual.ArtifactSize,
		ArtifactSHA256:   actual.ArtifactSHA256,
		JournalRevision:  source.JournalRevision,
		BackendRevision:  source.BackendRevision,
		OriginRevision:   source.OriginRevision,
		ContentSeq:       source.ContentSeq,
	}, nil
}

func sameLocalOwnedWorkspaceBackupProof(a, b LocalOwnedWorkspacePreflight) bool {
	return a.AccountDigest == b.AccountDigest &&
		a.ProfileDigest == b.ProfileDigest &&
		a.BackendDigest == b.BackendDigest &&
		a.RosterDigest == b.RosterDigest &&
		a.KnownSetDigest == b.KnownSetDigest &&
		a.State == b.State &&
		a.StopWritesProofOutstanding == b.StopWritesProofOutstanding &&
		a.FullBackupOutstanding == b.FullBackupOutstanding &&
		a.CutoverOutstanding == b.CutoverOutstanding &&
		a.UnknownOfflineDraftsPossible == b.UnknownOfflineDraftsPossible &&
		sameLocalOwnedWorkspaceVaults(a.Vaults, b.Vaults)
}

func localOwnedWorkspaceBackupSetDigest(set LocalOwnedWorkspaceBackupSet) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark/vaultfileclient/owned-workspace/backup-set/v1\x00"))
	_, _ = h.Write(set.AccountDigest[:])
	_, _ = h.Write(set.ProfileDigest[:])
	_, _ = h.Write(set.BackendDigest[:])
	_, _ = h.Write(set.RosterDigest[:])
	_, _ = h.Write(set.KnownSetDigest[:])
	writeLocalOwnedBackupString(h, string(set.State))
	flags := []byte{0, 0, 0, 0, 0}
	if set.StopWritesProofOutstanding {
		flags[0] = 1
	}
	if set.UnknownOfflineDraftsPossible {
		flags[1] = 1
	}
	if set.NewProfileImportOutstanding {
		flags[2] = 1
	}
	if set.CutoverOutstanding {
		flags[3] = 1
	}
	if set.CompleteWorkspaceOutstanding {
		flags[4] = 1
	}
	_, _ = h.Write(flags)
	var counter [8]byte
	writeLocalOwnedWorkspaceUint64(h, counter, uint64(len(set.Vaults)))
	for _, vault := range set.Vaults {
		writeLocalOwnedBackupString(h, vault.VaultID)
		_, _ = h.Write(vault.ManifestSHA256[:])
		_, _ = h.Write(vault.CurrentSHA256[:])
		_, _ = h.Write(vault.OriginSHA256[:])
		_, _ = h.Write(vault.CheckpointDigest[:])
		_, _ = h.Write(vault.IdentityDigest[:])
		_, _ = h.Write(vault.SourceIdentity[:])
		writeLocalOwnedWorkspaceUint64(h, counter, uint64(vault.ArtifactSize))
		_, _ = h.Write(vault.ArtifactSHA256[:])
		writeLocalOwnedBackupString(h, string(vault.JournalRevision))
		writeLocalOwnedBackupString(h, string(vault.BackendRevision))
		writeLocalOwnedBackupString(h, string(vault.OriginRevision))
		writeLocalOwnedWorkspaceUint64(h, counter, vault.ContentSeq)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
