package vaultfileclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// This file is the explicit source-maintenance tether for the accepted local
// backup-set verification. It adds no writer, journal policy, remote provider,
// import or cutover path. The final source/journal validation and the aggregate
// delivery run inside one established Dir.WithProtectedRead scope; the returned
// value is still only the point-in-time observation and never a freeze proof.

// localOwnedWorkspaceBackupSetBeforeFenceForTest is nil in production. A test
// may replace a profile/backend root after the expensive preparation and before
// the one provider Dir is opened. It cannot inject success.
var localOwnedWorkspaceBackupSetBeforeFenceForTest func()

// localOwnedWorkspaceBackupSetUnderFenceForTest is nil in production. A test
// may pause after the provider writer lock is held and before final source
// validation, for example to prove that an independent cooperating writer is
// blocked until release. It cannot inject success.
var localOwnedWorkspaceBackupSetUnderFenceForTest func()

// VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence performs the same
// exact backup-set verification as VerifyLocalOwnedWorkspaceBackupSet, but the
// final source/journal validation and the aggregate delivery are made while the
// one real cooperating writer lock for the established local backend root is
// held by Dir.WithProtectedRead.
//
// The expensive work is deliberately outside that lock: the first source
// preflight, the caller-artifact snapshot, the existing authenticated custody
// opener and its exact source/artifact comparisons all run first. The function
// then revalidates the exact protected profile and backend directory identities
// captured at entry, opens the backend once with OpenExistingDir, and enters the
// protected-read scope. The captured profile identity is carried into the
// view-backed final preflight and into a last delivery gate after the final
// artifact/account rechecks; the fenced preflight uses that retained identity,
// not a freshly captured same-path replacement, for its StillBound checks.
// Inside the scope every named backend read uses only the already-held
// ProtectedReadView; no second Dir is opened and no nested provider lock is
// acquired. The exact distinct settled journals are opened/retained in stable
// sorted order and their existing exclusive locks are held from the fenced
// source reads through the artifact/account/profile checks and aggregate
// construction. A normal writer therefore cannot commit its journal
// PrepareWorkingIfState after the last read and then wait for the provider CAS.
// The final view-backed source proof must equal the first proof exactly, and the
// original artifact pins are re-read unchanged before the aggregate is built.
// Any view/callback error, late cancellation, session lock, close, path
// replacement or source drift returns the zero aggregate.
//
// Deterministic identity boundary: a same-path replacement is refused before
// the provider open, immediately inside the fence, on every fenced StillBound
// check, and at the last delivery gate. A same-UID process that replaces the
// profile path after that gate but before this call returns is outside the
// existing static filesystem threat model; the provider lock protects the
// backend and its lock inode, not an arbitrary profile directory rewrite.
//
// Lock order. A normal cooperating owned write opens the journal first and then
// acquires the provider writer lock for its CAS (journal -> provider). This
// entry holds the provider lock while the view-backed source proof opens the
// strict journals through the existing bounded OpenExisting path. That is the
// reverse order, so each journal acquisition is bounded by the journal package's
// short lock timeout; a journal already held by a cooperating writer is reported
// as a busy/conflict category and the provider scope is released instead of
// waiting indefinitely. No writer that already holds a journal is deadlocked.
// Session reads are ordinary bounded in-process calls taken under the provider
// lock and never re-enter the provider.
//
// The callback is synchronous and read-only. It does not expose the view, a
// stop-writes token or a lock handle. After this function returns, no writer
// lock is held and the result is only the observed point-in-time set; it is not
// a workspace/offline-writer shutdown, complete-workspace backup, new-profile
// import, remote freeze or cutover authorization.
func VerifyLocalOwnedWorkspaceBackupSetUnderMaintenanceFence(ctx context.Context, s *personal.Session,
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

	// Bind the exact protected profile and established backend directory
	// identities before the expensive preparation. The same bindings are
	// rechecked before and after the one provider open, so a root replaced
	// after the authenticated inputs were prepared cannot become the fence.
	profileBinding, err := localOwnedWorkspaceDirectory(profileDir, true)
	if err != nil {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "profile")
	}
	backendBinding, err := localOwnedWorkspaceDirectory(backendRoot, false)
	if err != nil {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "backend")
	}
	if localOwnedWorkspaceNested(profileBinding.resolved, backendBinding.resolved) ||
		os.SameFile(profileBinding.info, backendBinding.info) {
		return empty, localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, "resolved scopes")
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

	if localOwnedWorkspaceBackupSetBeforeFenceForTest != nil {
		localOwnedWorkspaceBackupSetBeforeFenceForTest()
	}
	if err := localOwnedWorkspaceConfirmDirectory(profileDir, true, profileBinding); err != nil {
		return empty, err
	}
	if err := localOwnedWorkspaceConfirmDirectory(backendRoot, false, backendBinding); err != nil {
		return empty, err
	}

	backend, err := vaultfilebackend.OpenExistingDir(backendRoot)
	if err != nil {
		return empty, localOwnedWorkspaceMapFenceError(err, "backend")
	}
	// The provider open independently captured the namespace and lock inode.
	// Confirm the path still names the directory bound before preparation; a
	// replacement after this point is refused by WithProtectedRead itself.
	if err := localOwnedWorkspaceConfirmDirectory(backendRoot, false, backendBinding); err != nil {
		_ = backend.Close()
		return empty, err
	}

	var fenced LocalOwnedWorkspaceBackupSet
	fenceErr := backend.WithProtectedRead(ctx, func(view *vaultfilebackend.ProtectedReadView) error {
		var got LocalOwnedWorkspaceBackupSet
		if err := withLocalOwnedWorkspaceJournals(ctx, s, profileDir, backendRoot, prep.proof,
			func(journals *localOwnedWorkspaceJournalSet) error {
				if localOwnedWorkspaceBackupSetUnderFenceForTest != nil {
					localOwnedWorkspaceBackupSetUnderFenceForTest()
				}
				built, err := localOwnedWorkspaceBackupFinalize(ctx, s, profileDir, backendRoot, request, prep,
					nil, localOwnedWorkspaceBackupSetBeforeDeliveryForTest,
					func() error {
						if err := localOwnedWorkspaceConfirmDirectory(profileDir, true, profileBinding); err != nil {
							return err
						}
						if err := journals.revalidate(); err != nil {
							return err
						}
						return localOwnedWorkspaceConfirmDirectory(backendRoot, false, backendBinding)
					},
					func(ctx context.Context) (LocalOwnedWorkspacePreflight, error) {
						return preflightLocalOwnedWorkspaceSource(ctx, s, profileDir, backendRoot,
							localOwnedWorkspaceSourceScope{
								readTarget: func(ctx context.Context, manifest Manifest, expected []byte,
									wantRevision vaultfilebackend.Revision) (vaultfilebackend.Revision, error) {
									revision, _, err := readLocalOwnedWorkspaceBackupTargetView(
										ctx, view, manifest, expected, wantRevision)
									return revision, err
								},
								requireBackendExists:   false,
								expectedProfileBinding: &profileBinding,
								expectedBackendBinding: &backendBinding,
								journals:               journals,
							})
					})
				if err != nil {
					return err
				}
				// Account/context state is checked while every journal lock is
				// still held; the scoped owner releases them after this returns.
				if err := localOwnedWorkspaceActiveAccountStillBound(ctx, s, prep.proof.AccountDigest); err != nil {
					return err
				}
				got = built
				return nil
			}); err != nil {
			return err
		}
		// The scoped owner has closed every acquired journal, including on a
		// close failure. Check once more before exposing the aggregate.
		if err := localOwnedWorkspaceActiveAccountStillBound(ctx, s, prep.proof.AccountDigest); err != nil {
			return err
		}
		fenced = got
		return nil
	})
	closeErr := backend.Close()
	if fenceErr != nil {
		fenced = LocalOwnedWorkspaceBackupSet{}
		return empty, localOwnedWorkspaceMapFenceError(fenceErr, "fence")
	}
	if closeErr != nil {
		fenced = LocalOwnedWorkspaceBackupSet{}
		return empty, localOwnedWorkspaceMapFenceError(closeErr, "backend")
	}
	return fenced, nil
}

// localOwnedWorkspaceConfirmDirectory requires path to still be the exact
// directory bound earlier: same lexical leaf identity and same resolved target.
// It opens nothing and acquires no provider lock.
func localOwnedWorkspaceConfirmDirectory(path string, private bool,
	want localOwnedWorkspaceDirectoryBinding) error {
	got, err := localOwnedWorkspaceDirectory(path, private)
	if err != nil || !sameLocalOwnedWorkspaceDirectoryBinding(want, got) {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "path replaced")
	}
	return nil
}

// localOwnedWorkspaceActiveAccountStillBound rechecks the late context, live
// session and exact account path without touching the provider or a journal.
func localOwnedWorkspaceActiveAccountStillBound(ctx context.Context, s *personal.Session,
	accountDigest [sha256.Size]byte) error {
	if err := ctx.Err(); err != nil {
		return localOwnedWorkspaceCanceled(err, "context")
	}
	if s == nil || !s.Unlocked() {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	accountPath := s.VaultPath()
	if accountPath == "" {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceCanceled, "session")
	}
	if localOwnedWorkspacePathDigest("account", accountPath) != accountDigest {
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "active scope")
	}
	return nil
}

// readLocalOwnedWorkspaceBackupTargetView applies the accepted checked direct
// read to the already-held view. It never opens or reads a Dir through another
// handle, and it clears the one fresh read buffer on every return path.
func readLocalOwnedWorkspaceBackupTargetView(ctx context.Context,
	view *vaultfilebackend.ProtectedReadView, manifest Manifest,
	expected []byte, wantRevision vaultfilebackend.Revision,
) (revision vaultfilebackend.Revision, digest [sha256.Size]byte, retErr error) {
	if view == nil {
		return "", digest, mapLocalOwnedBackupTargetError(vaultfilebackend.ErrDenied)
	}
	read, err := view.Read(ctx, manifest.Name)
	defer clear(read.Bytes)
	if err != nil {
		return "", digest, mapLocalOwnedBackupTargetError(err)
	}
	return validateLocalOwnedWorkspaceBackupTargetRead(read, expected, wantRevision)
}

// localOwnedWorkspaceMapFenceError classifies provider scope failures without
// exposing a path or record. A provider busy outcome is a conflict, not an
// indefinite wait. Errors already classified by this package pass through.
func localOwnedWorkspaceMapFenceError(err error, reason string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired),
		errors.Is(err, ErrLocalOwnedWorkspaceConflict),
		errors.Is(err, ErrLocalOwnedWorkspaceUnsupported),
		errors.Is(err, ErrLocalOwnedWorkspaceCanceled):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return localOwnedWorkspaceCanceled(err, reason)
	case errors.Is(err, vaultfilebackend.ErrConflict):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, "busy")
	case errors.Is(err, vaultfilebackend.ErrUnsupported):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceUnsupported, reason)
	case errors.Is(err, vaultfilebackend.ErrDenied):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, reason)
	case errors.Is(err, vaultfilebackend.ErrNotFound),
		errors.Is(err, vaultfilebackend.ErrCorrupt),
		errors.Is(err, vaultfilebackend.ErrUnknown):
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceConflict, reason)
	default:
		return localOwnedWorkspaceError(ErrLocalOwnedWorkspaceReviewRequired, reason)
	}
}
