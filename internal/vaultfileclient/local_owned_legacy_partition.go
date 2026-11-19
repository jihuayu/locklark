package vaultfileclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
)

const (
	// localOwnedLegacyPartitionSidecarSuffix names the one fixed sidecar that
	// may persist for a staged migration. The path is derived only from the
	// verified journal path; callers never choose it.
	localOwnedLegacyPartitionSidecarSuffix = ".legacy-partition-stage"
	// localOwnedLegacyPartitionMaxArchive bounds both the caller-supplied raw
	// archive and the sealed candidate read back from the sidecar.
	localOwnedLegacyPartitionMaxArchive = 16 << 20
)

var (
	// ErrLocalOwnedLegacyPartitionReview rejects an invalid request or an
	// unauthenticated account/manifest/journal/source shape before a sidecar is
	// written.
	ErrLocalOwnedLegacyPartitionReview = ErrLocalOwnedFirstWriteReview
	// ErrLocalOwnedLegacyPartitionConflict reports a stale locator, an existing
	// sidecar, a changed archive digest or a backend/journal mismatch.
	ErrLocalOwnedLegacyPartitionConflict = ErrLocalOwnedFirstWriteConflict
	// ErrLocalOwnedLegacyPartitionUnknown reports that teamfiles.WriteNew could
	// not establish whether the sidecar reached its final path. Any committed
	// bytes are left in place and the returned result pins the intended path and
	// digest; callers must not retry by replacing the sidecar.
	ErrLocalOwnedLegacyPartitionUnknown = ErrLocalOwnedFirstWriteIndeterminate
	// ErrLocalOwnedLegacyPartitionCanceled reports cancellation before a sidecar
	// was written, or after a committed write whose final scope check was
	// interrupted. In the latter case the result still pins the sidecar.
	ErrLocalOwnedLegacyPartitionCanceled = ErrLocalOwnedFirstWriteCanceled
	// ErrLocalOwnedLegacyPartitionUnsupported reports an unsupported backend
	// observed by the personal verification path.
	ErrLocalOwnedLegacyPartitionUnsupported = ErrLocalOwnedFirstWriteUnsupported
)

// localOwnedLegacyPartitionAfterWriteForTest is nil in production. Tests use it
// to interleave a cancellation or a locator change immediately after the one
// real sidecar write and before the final scope recheck. It receives no key,
// factor, ciphertext or account material.
var localOwnedLegacyPartitionAfterWriteForTest func()

// LocalOwnedLegacyPartitionStageResult is the bounded result of staging one
// legacy-partition migration. It contains the fixed sidecar location and the
// hashes needed to verify it later, but no source items, sealed bytes, recovery
// factors, keys or account material.
type LocalOwnedLegacyPartitionStageResult struct {
	VaultID             string
	JournalPath         string
	SidecarPath         string
	CandidateSHA256     [sha256.Size]byte
	SourceArchiveSHA256 [sha256.Size]byte
}

// StageLocalOwnedLegacyPartition authenticates the destination account and its
// pristine owned genesis exactly as WriteLocalGenesisFirstItem does, requires
// the caller's raw bounded legacy archive to match an independent nonzero
// digest, and asks the personal session to select and sign exactly one verified
// source partition. Only the resulting sealed successor bytes are written, once
// and without replacement, to a fixed private sidecar derived from the verified
// journal.
//
// It reads the manifest, companion, journal and named live backend baseline but
// never publishes a backend object, prepares a normal journal proposal or
// changes the journal, backend, archive or personal store. The sidecar is
// validated as a canonical, private, distinct path outside provider data. A
// successful return means the sidecar write completed and the locator, journal
// baseline and account scope were rechecked afterward; the caller may retain
// the returned hashes for a later VerifyStagedLocalOwnedLegacyPartition call.
//
// If this invocation may have committed the sidecar and a later check fails or
// is canceled, the returned result still pins the fixed sidecar path and safe
// digests together with a non-nil error. That result is a recovery pin for a
// fresh Verify, not proof that the stage is usable; the sidecar is never
// replaced or removed here. A definite prewrite or no-effect failure returns an
// empty result.
func StageLocalOwnedLegacyPartition(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte, source personal.LegacyVaultPartitionSource, expectedSourceArchiveSHA256 [sha256.Size]byte) (LocalOwnedLegacyPartitionStageResult, error) {
	empty := LocalOwnedLegacyPartitionStageResult{}
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" ||
		vaultID == "" || !teamfiles.ValidPath(expectedJournal) ||
		len(source.Archive) == 0 || len(source.Archive) > localOwnedLegacyPartitionMaxArchive ||
		source.VaultID == "" || source.RecoveryKit == "" ||
		expectedSourceArchiveSHA256 == ([sha256.Size]byte{}) {
		return empty, fmt.Errorf("%w: invalid request", ErrLocalOwnedLegacyPartitionReview)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	sourceDigest := sha256.Sum256(source.Archive)
	if sourceDigest != expectedSourceArchiveSHA256 {
		return empty, fmt.Errorf("%w: source archive digest", ErrLocalOwnedLegacyPartitionConflict)
	}

	pristine, err := readLocalGenesisPristine(s, configPath, workspaceRoot, vaultID, expectedJournal)
	if err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	defer pristine.clear()
	if err := pristine.confirm(s); err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	sidecar, err := localOwnedLegacyPartitionSidecarPath(pristine)
	if err != nil {
		return empty, err
	}
	if err := teamfiles.CheckNew(sidecar); err != nil {
		return empty, fmt.Errorf("%w: sidecar already present", ErrLocalOwnedLegacyPartitionConflict)
	}

	sealed, err := s.SealOwnedVaultFileFirstItemsFromLegacyPartition(personal.OwnedVaultFileLegacyPartitionRequest{
		JournalPath:     pristine.manifest.Journal,
		Target:          pristine.target(),
		Checkpoint:      pristine.checkpoint,
		ExpectedGenesis: pristine.state.BaseBytes,
		Password:        password,
		Key:             key,
		Source:          source,
	})
	if err != nil {
		return empty, mapLocalOwnedLegacyPartitionPersonal(err)
	}
	defer sealed.Clear()
	if sealed.SourceArchiveSHA256 != expectedSourceArchiveSHA256 ||
		len(sealed.Sealed) == 0 || len(sealed.Sealed) > localOwnedLegacyPartitionMaxArchive {
		return empty, fmt.Errorf("%w: sealed source binding", ErrLocalOwnedLegacyPartitionConflict)
	}
	candidateDigest := sha256.Sum256(sealed.Sealed)
	recoverable := LocalOwnedLegacyPartitionStageResult{
		VaultID:             pristine.manifest.VaultID,
		JournalPath:         pristine.manifest.Journal,
		SidecarPath:         sidecar,
		CandidateSHA256:     candidateDigest,
		SourceArchiveSHA256: sourceDigest,
	}

	// The personal seal already re-read the named live backend and revalidated
	// the account scope. Recheck the locator and generation-zero journal before
	// the one sidecar write so a changed manifest/companion/journal fails closed.
	if err := pristine.confirm(s); err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	if err := teamfiles.WriteNew(sidecar, sealed.Sealed); err != nil {
		if errors.Is(err, teamfiles.ErrPublicationUnknown) {
			// The sidecar may already be final. Pin the exact intended bytes so a
			// later Verify can decide, but never report this as a completed stage.
			return recoverable, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionUnknown, err)
		}
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	if localOwnedLegacyPartitionAfterWriteForTest != nil {
		localOwnedLegacyPartitionAfterWriteForTest()
	}

	// A sidecar may persist even if this final scope recheck fails. It is never
	// overwritten or removed here; verification must re-authenticate everything.
	if err := pristine.confirm(s); err != nil {
		return recoverable, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	if err := ctx.Err(); err != nil {
		return recoverable, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	return recoverable, nil
}

// VerifyStagedLocalOwnedLegacyPartition reopens the real account and re-resolves
// the same verified locator, then reads the fixed sidecar as a bounded private
// file. It accepts only bytes whose digest matches the independently supplied
// nonzero candidate hash and only a raw source archive whose independently
// supplied nonzero digest matches. No metadata or provenance is trusted from
// the sidecar itself.
//
// The actual personal verification authenticates the original selected source
// partition with the original recovery factors, requires the exact pristine
// genesis and live backend bytes/revision, and proves that the sidecar bytes are
// the complete immediate signed transition with preserved item IDs. A changed
// backend revision or bytes, a wrong account, a wrong digest, a different
// ciphertext or a different partition fails closed. The archive, backend,
// journal and sidecar are not written.
func VerifyStagedLocalOwnedLegacyPartition(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte, source personal.LegacyVaultPartitionSource, expectedSourceArchiveSHA256, expectedCandidateSHA256 [sha256.Size]byte) (personal.VaultFileVerifiedLegacyPartition, error) {
	empty := personal.VaultFileVerifiedLegacyPartition{}
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" ||
		vaultID == "" || !teamfiles.ValidPath(expectedJournal) ||
		len(source.Archive) == 0 || len(source.Archive) > localOwnedLegacyPartitionMaxArchive ||
		source.VaultID == "" || source.RecoveryKit == "" ||
		expectedSourceArchiveSHA256 == ([sha256.Size]byte{}) ||
		expectedCandidateSHA256 == ([sha256.Size]byte{}) {
		return empty, fmt.Errorf("%w: invalid request", ErrLocalOwnedLegacyPartitionReview)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	sourceDigest := sha256.Sum256(source.Archive)
	if sourceDigest != expectedSourceArchiveSHA256 {
		return empty, fmt.Errorf("%w: source archive digest", ErrLocalOwnedLegacyPartitionConflict)
	}

	pristine, err := readLocalGenesisPristine(s, configPath, workspaceRoot, vaultID, expectedJournal)
	if err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	defer pristine.clear()
	if err := pristine.confirm(s); err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	sidecar, err := localOwnedLegacyPartitionSidecarPath(pristine)
	if err != nil {
		return empty, err
	}
	candidate, err := teamfiles.Read(sidecar, localOwnedLegacyPartitionMaxArchive, true)
	if err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	}
	defer clear(candidate)
	if sha256.Sum256(candidate) != expectedCandidateSHA256 {
		return empty, fmt.Errorf("%w: candidate digest", ErrLocalOwnedLegacyPartitionConflict)
	}
	if err := pristine.confirm(s); err != nil {
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}

	verified, err := s.VerifyOwnedVaultFileLegacyPartition(personal.OwnedVaultFileLegacyPartitionVerificationRequest{
		OwnedVaultFileLegacyPartitionRequest: personal.OwnedVaultFileLegacyPartitionRequest{
			JournalPath:     pristine.manifest.Journal,
			Target:          pristine.target(),
			Checkpoint:      pristine.checkpoint,
			ExpectedGenesis: pristine.state.BaseBytes,
			Password:        password,
			Key:             key,
			Source:          source,
		},
		Candidate:                   candidate,
		ExpectedSourceArchiveSHA256: expectedSourceArchiveSHA256,
	})
	if err != nil {
		return empty, mapLocalOwnedLegacyPartitionPersonal(err)
	}
	if err := pristine.confirm(s); err != nil {
		verified.Clear()
		return empty, mapLocalOwnedLegacyPartitionPreflight(err)
	}
	if err := ctx.Err(); err != nil {
		verified.Clear()
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionCanceled, err)
	}
	return verified, nil
}

// localOwnedLegacyPartitionSidecarPath derives the one fixed sidecar from the
// verified journal and enforces the private/canonical/distinct/provider
// separation rules before a caller may inspect or write it.
func localOwnedLegacyPartitionSidecarPath(pristine *localGenesisPristine) (string, error) {
	if pristine == nil || !teamfiles.ValidPath(pristine.manifest.Journal) {
		return "", fmt.Errorf("%w: sidecar journal", ErrLocalOwnedLegacyPartitionReview)
	}
	sidecar := pristine.manifest.Journal + localOwnedLegacyPartitionSidecarSuffix
	if !teamfiles.ValidPath(sidecar) || sidecar == pristine.manifest.Journal ||
		teamfiles.ValidatePrivateParent(filepath.Dir(sidecar)) != nil {
		return "", fmt.Errorf("%w: sidecar path", ErrLocalOwnedLegacyPartitionReview)
	}
	if !teamfiles.Distinct(sidecar, pristine.configPath, pristine.manifest.PersonalFile,
		pristine.manifest.Journal, pristine.manifest.Archive, pristine.manifest.BackendRoot) {
		return "", fmt.Errorf("%w: sidecar collision", ErrLocalOwnedLegacyPartitionReview)
	}
	if localOwnedLegacyPartitionWithin(sidecar, pristine.manifest.BackendRoot) {
		return "", fmt.Errorf("%w: sidecar inside provider data", ErrLocalOwnedLegacyPartitionReview)
	}
	return sidecar, nil
}

// localOwnedLegacyPartitionWithin reports whether path is the provider data
// root or one of its descendants. Resolved directories are compared so a symlink
// cannot place the sidecar inside provider data; any resolution failure is
// treated as inside and therefore refused.
func localOwnedLegacyPartitionWithin(path, root string) bool {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return true
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(resolvedRoot, filepath.Join(parent, filepath.Base(path)))
	if err != nil {
		return true
	}
	return rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func mapLocalOwnedLegacyPartitionPreflight(err error) error {
	switch {
	case errors.Is(err, errLocalOwnedFirstJournal), errors.Is(err, errLocalOwnedFirstStale):
		return fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	default:
		return fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionReview, err)
	}
}

func mapLocalOwnedLegacyPartitionPersonal(err error) error {
	switch {
	case errors.Is(err, personal.ErrVaultFileBaselineJournal),
		errors.Is(err, personal.ErrLegacyVaultPartitionSelector),
		errors.Is(err, personal.ErrLegacyVaultPartitionPayload):
		return fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionConflict, err)
	case errors.Is(err, personal.ErrVaultFileScopedFactors),
		errors.Is(err, personal.ErrVaultFileOwnership),
		errors.Is(err, personal.ErrVaultFileBaselineVerification),
		errors.Is(err, personal.ErrVaultFileEditReview),
		errors.Is(err, personal.ErrVaultFileEditVerification),
		errors.Is(err, personal.ErrVaultFileFullFactorRequired),
		errors.Is(err, personal.ErrSessionLocked):
		return fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionReview, err)
	default:
		return fmt.Errorf("%w: %w", ErrLocalOwnedLegacyPartitionReview, err)
	}
}
