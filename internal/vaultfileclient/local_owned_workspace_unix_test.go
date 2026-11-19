//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// localWorkspaceLockingContext is a test-only delegating context. Its first Err
// observation performs one real Session lock and then reports the embedded
// context's original state. That places the lock after the preflight's entry
// Unlocked check and before its VaultPath capture without a production hook or
// a timing-dependent sleep.
type localWorkspaceLockingContext struct {
	context.Context
	once sync.Once
	lock func()
}

func (c *localWorkspaceLockingContext) Err() error {
	c.once.Do(c.lock)
	return c.Context.Err()
}

type localWorkspaceDurable struct {
	manifest  []byte
	companion []byte
	journal   []byte
	backend   []byte
	revision  vaultfilebackend.Revision
}

func (d *localWorkspaceDurable) clear() {
	if d == nil {
		return
	}
	clear(d.manifest)
	clear(d.companion)
	clear(d.journal)
	clear(d.backend)
	d.revision = ""
}

func (d localWorkspaceDurable) assertSame(t *testing.T, other localWorkspaceDurable, code string) {
	t.Helper()
	if d.revision != other.revision || !bytes.Equal(d.manifest, other.manifest) ||
		!bytes.Equal(d.companion, other.companion) || !bytes.Equal(d.journal, other.journal) ||
		!bytes.Equal(d.backend, other.backend) {
		t.Fatal(code)
	}
}

func localWorkspaceObserve(t *testing.T, config string, manifest Manifest) localWorkspaceDurable {
	t.Helper()
	companionPath, err := CompanionPath(config)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_COMPANION_PATH_FAILED")
	}
	manifestBytes, err := os.ReadFile(config)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_MANIFEST_READ_FAILED")
	}
	companionBytes, err := os.ReadFile(companionPath)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_COMPANION_READ_FAILED")
	}
	journalBytes, err := os.ReadFile(manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_JOURNAL_READ_FAILED")
	}
	backendBytes, revision := localFirstReadBackend(t, manifest)
	return localWorkspaceDurable{
		manifest: manifestBytes, companion: companionBytes,
		journal: journalBytes, backend: backendBytes, revision: revision,
	}
}

func localWorkspaceRoots(f *localGenesisTwoVaultFixture) (profileDir, backendRoot string) {
	return filepath.Dir(f.firstConfig), f.f.proposal.BackendRoot
}

func localWorkspaceAssertRedacted(t *testing.T, proof LocalOwnedWorkspacePreflight) {
	t.Helper()
	for _, formatted := range []string{
		fmt.Sprintf("%v", proof), fmt.Sprintf("%+v", proof), fmt.Sprintf("%#v", proof),
		fmt.Sprintf("%v", &proof), fmt.Sprintf("%+v", &proof), fmt.Sprintf("%#v", &proof),
		fmt.Sprintf("%v", LocalOwnedWorkspacePreflight{}),
		fmt.Sprintf("%v", (*LocalOwnedWorkspacePreflight)(nil)),
	} {
		if formatted != "[local owned workspace preflight]" {
			t.Fatal("LOCAL_WORKSPACE_PROOF_FORMAT_NOT_REDACTED")
		}
	}
	raw, err := json.Marshal(proof)
	if err != nil || string(raw) != "{}" {
		t.Fatal("LOCAL_WORKSPACE_PROOF_JSON_EXPOSED_PRIVATE_FIELDS")
	}
	for _, vault := range proof.Vaults {
		for _, formatted := range []string{
			fmt.Sprintf("%v", vault), fmt.Sprintf("%+v", vault), fmt.Sprintf("%#v", vault),
			fmt.Sprintf("%v", &vault),
		} {
			if formatted != "[local owned workspace vault]" {
				t.Fatal("LOCAL_WORKSPACE_VAULT_FORMAT_NOT_REDACTED")
			}
		}
		raw, err := json.Marshal(vault)
		if err != nil || string(raw) != "{}" {
			t.Fatal("LOCAL_WORKSPACE_VAULT_JSON_EXPOSED_PRIVATE_FIELDS")
		}
	}
}

func localWorkspaceAssertRefusalRedacted(t *testing.T, err error, profileDir, backendRoot string, vaultIDs ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("LOCAL_WORKSPACE_REFUSAL_MISSING")
	}
	message := err.Error()
	if strings.Contains(message, profileDir) || strings.Contains(message, backendRoot) {
		t.Fatal("LOCAL_WORKSPACE_REFUSAL_EXPOSED_PATH")
	}
	for _, vaultID := range vaultIDs {
		if vaultID != "" && strings.Contains(message, vaultID) {
			t.Fatal("LOCAL_WORKSPACE_REFUSAL_EXPOSED_VAULT_ID")
		}
	}
}

func localWorkspaceAssertInitialCaptureCanceled(t *testing.T, f *localGenesisTwoVaultFixture, lock func()) {
	t.Helper()
	profileDir, backendRoot := localWorkspaceRoots(f)
	ctx := &localWorkspaceLockingContext{Context: context.Background(), lock: lock}
	proof, err := PreflightLocalOwnedWorkspaceSource(ctx, f.session, profileDir, backendRoot)
	if ctx.Err() != nil {
		t.Fatal("LOCAL_WORKSPACE_INITIAL_CAPTURE_LOCK_CONTEXT_CHANGED")
	}
	if !errors.Is(err, ErrLocalOwnedWorkspaceCanceled) {
		t.Fatal("LOCAL_WORKSPACE_INITIAL_CAPTURE_LOCK_NOT_CANCELED")
	}
	if errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
		t.Fatal("LOCAL_WORKSPACE_INITIAL_CAPTURE_LOCK_REVIEWED")
	}
	if !reflect.DeepEqual(proof, LocalOwnedWorkspacePreflight{}) {
		t.Fatal("LOCAL_WORKSPACE_INITIAL_CAPTURE_LOCK_PROOF_NOT_EMPTY")
	}
	localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
		f.firstVaultID, f.secondVaultID)
}

func TestLocalOwnedWorkspacePreflightPristineAndSettled(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	manifestA := localBackupManifest(t, f.firstConfig)
	manifestB := localBackupManifest(t, f.secondConfig)

	// A stays pristine; B receives one real settled first successor.
	fxB := newLocalFirstWriteFixtureFor(t, f, f.secondConfig, f.secondVaultID)
	settled, err := fxB.write(context.Background())
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_SETTLED_WRITE_FAILED")
	}

	// Keep one real sibling owned child live across the read-only preflight.
	sibling, siblingSummary := f.open(t, f.firstConfig, f.firstVaultID)
	defer sibling.Close()
	assertLocalGenesisSummary(t, siblingSummary, f.firstVaultID)

	beforeA := localWorkspaceObserve(t, f.firstConfig, manifestA)
	defer beforeA.clear()
	beforeB := localWorkspaceObserve(t, f.secondConfig, manifestB)
	defer beforeB.clear()

	owners, err := f.session.VaultFileOwnerships()
	if err != nil || len(owners) != 2 {
		t.Fatal("LOCAL_WORKSPACE_ROSTER_FAILED")
	}
	profileDir, backendRoot := localWorkspaceRoots(f)
	proof, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_PREFLIGHT_FAILED")
	}

	if proof.State != LocalOwnedWorkspaceStateKnownInventoryReady ||
		!proof.StopWritesProofOutstanding || !proof.FullBackupOutstanding ||
		!proof.CutoverOutstanding || !proof.UnknownOfflineDraftsPossible {
		t.Fatal("LOCAL_WORKSPACE_OUTCOME_OVERCLAIMED")
	}
	if proof.AccountDigest != localOwnedWorkspacePathDigest("account", f.session.VaultPath()) ||
		proof.ProfileDigest != localOwnedWorkspacePathDigest("profile", profileDir) ||
		proof.BackendDigest != localOwnedWorkspacePathDigest("backend", backendRoot) ||
		proof.RosterDigest != localOwnedWorkspaceRosterDigest(owners) ||
		proof.KnownSetDigest != localOwnedWorkspaceSetDigest(proof) {
		t.Fatal("LOCAL_WORKSPACE_DIGEST_BINDING_FAILED")
	}
	if len(proof.Vaults) != 2 ||
		proof.Vaults[0].VaultID >= proof.Vaults[1].VaultID {
		t.Fatal("LOCAL_WORKSPACE_KNOWN_SET_SHAPE_FAILED")
	}
	byID := map[string]LocalOwnedWorkspaceVault{}
	for _, vault := range proof.Vaults {
		byID[vault.VaultID] = vault
	}
	if len(byID) != 2 || byID[manifestA.VaultID].VaultID == "" || byID[manifestB.VaultID].VaultID == "" {
		t.Fatal("LOCAL_WORKSPACE_KNOWN_SET_OWNER_MISMATCH")
	}

	backendABytes, backendARevision := localFirstReadBackend(t, manifestA)
	defer clear(backendABytes)
	manifestABytes, err := os.ReadFile(f.firstConfig)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_MANIFEST_A_READ_FAILED")
	}
	entryA := byID[manifestA.VaultID]
	if entryA.ContentSeq != 0 || entryA.OriginRevision != "" ||
		entryA.OriginSHA256 != ([sha256.Size]byte{}) ||
		entryA.JournalRevision != entryA.BackendRevision ||
		entryA.BackendRevision != backendARevision ||
		entryA.CurrentSHA256 != sha256.Sum256(backendABytes) ||
		entryA.ManifestSHA256 != sha256.Sum256(manifestABytes) ||
		entryA.CheckpointDigest == ([sha256.Size]byte{}) ||
		entryA.IdentityDigest == ([sha256.Size]byte{}) {
		t.Fatal("LOCAL_WORKSPACE_PRISTINE_BINDING_FAILED")
	}

	record := localBackupSuccessorRecord(t, manifestB, localBackupPin(t, manifestB, localBackupCompanion(t, f.secondConfig, manifestB)))
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)
	backendBBytes, backendBRevision := localFirstReadBackend(t, manifestB)
	defer clear(backendBBytes)
	entryB := byID[manifestB.VaultID]
	if entryB.ContentSeq != 1 || entryB.OriginRevision == "" ||
		entryB.JournalRevision != entryB.BackendRevision ||
		entryB.BackendRevision != vaultfilebackend.Revision(settled.Revision) ||
		entryB.BackendRevision != backendBRevision ||
		entryB.CurrentSHA256 != sha256.Sum256(backendBBytes) ||
		entryB.OriginSHA256 != sha256.Sum256(record.GenesisBytes) ||
		entryB.CurrentSHA256 != sha256.Sum256(record.SuccessorBytes) ||
		entryB.CheckpointDigest == ([sha256.Size]byte{}) ||
		entryB.IdentityDigest == ([sha256.Size]byte{}) ||
		entryB.IdentityDigest == entryA.IdentityDigest {
		t.Fatal("LOCAL_WORKSPACE_SETTLED_BINDING_FAILED")
	}

	// The same value is blindly formattable without exposing any path or ID.
	localWorkspaceAssertRedacted(t, proof)

	// The read-only preflight neither changes durable source bytes nor replaces
	// the live sibling child.
	afterA := localWorkspaceObserve(t, f.firstConfig, manifestA)
	defer afterA.clear()
	beforeA.assertSame(t, afterA, "LOCAL_WORKSPACE_PRISTINE_SOURCE_CHANGED")
	afterB := localWorkspaceObserve(t, f.secondConfig, manifestB)
	defer afterB.clear()
	beforeB.assertSame(t, afterB, "LOCAL_WORKSPACE_SETTLED_SOURCE_CHANGED")
	if _, err := sibling.Summary(); err != nil {
		t.Fatal("LOCAL_WORKSPACE_LIVE_CHILD_REPLACED")
	}
}

func TestLocalOwnedWorkspacePreflightRefusals(t *testing.T) {
	t.Run("missing configured vault", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.firstConfig)
		before := localWorkspaceObserve(t, f.firstConfig, manifest)
		defer before.clear()
		profileDir, backendRoot := localWorkspaceRoots(f)
		if err := os.Remove(f.secondConfig); err != nil {
			t.Fatal("LOCAL_WORKSPACE_MISSING_REMOVE_FAILED")
		}
		companionPath, err := CompanionPath(f.secondConfig)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_MISSING_COMPANION_PATH_FAILED")
		}
		if err := os.Remove(companionPath); err != nil {
			t.Fatal("LOCAL_WORKSPACE_MISSING_COMPANION_REMOVE_FAILED")
		}
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_MISSING_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			f.firstVaultID, f.secondVaultID)
		after := localWorkspaceObserve(t, f.firstConfig, manifest)
		defer after.clear()
		before.assertSame(t, after, "LOCAL_WORKSPACE_MISSING_CHANGED_SOURCE")
	})

	t.Run("duplicate configured vault", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.firstConfig)
		profileDir, backendRoot := localWorkspaceRoots(f)
		duplicate := filepath.Join(profileDir, "duplicate.json")
		source, err := os.ReadFile(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_DUPLICATE_MANIFEST_READ_FAILED")
		}
		if err := os.WriteFile(duplicate, source, 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_DUPLICATE_MANIFEST_WRITE_FAILED")
		}
		companionPath, err := CompanionPath(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_DUPLICATE_COMPANION_PATH_FAILED")
		}
		companionBytes, err := os.ReadFile(companionPath)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_DUPLICATE_COMPANION_READ_FAILED")
		}
		duplicateCompanion, err := CompanionPath(duplicate)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_DUPLICATE_COMPANION_PATH_FAILED")
		}
		if err := os.WriteFile(duplicateCompanion, companionBytes, 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_DUPLICATE_COMPANION_WRITE_FAILED")
		}
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_DUPLICATE_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			manifest.VaultID, f.secondVaultID)
	})

	t.Run("foreign account config", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.secondConfig)
		profileDir, backendRoot := localWorkspaceRoots(f)
		foreign := filepath.Join(t.TempDir(), "foreign-personal.ll")
		if err := os.WriteFile(foreign, []byte("foreign private placeholder"), 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_FOREIGN_FILE_FAILED")
		}
		foreignManifest := manifest
		foreignManifest.PersonalFile = foreign
		raw, err := json.Marshal(foreignManifest)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_FOREIGN_ENCODE_FAILED")
		}
		if err := os.WriteFile(f.secondConfig, raw, 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_FOREIGN_WRITE_FAILED")
		}
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_FOREIGN_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			foreign, manifest.VaultID, f.firstVaultID)
	})

	t.Run("stale owner binding", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.firstConfig)
		companion := localBackupCompanion(t, f.firstConfig, manifest)
		companion.Resume.Checkpoint.OwnerRootKeyID = "00000000000000000000000000000000"
		raw, err := json.Marshal(companion)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_STALE_ENCODE_FAILED")
		}
		companionPath, err := CompanionPath(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_STALE_COMPANION_PATH_FAILED")
		}
		if err := os.WriteFile(companionPath, raw, 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_STALE_WRITE_FAILED")
		}
		profileDir, backendRoot := localWorkspaceRoots(f)
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_STALE_BINDING_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			manifest.VaultID, f.secondVaultID)
		after, err := os.ReadFile(companionPath)
		if err != nil || !bytes.Equal(after, raw) {
			t.Fatal("LOCAL_WORKSPACE_STALE_CHANGED_BINDING")
		}
	})

	t.Run("extra malformed json", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		if err := os.WriteFile(filepath.Join(profileDir, "broken.json"), []byte("{"), 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_MALFORMED_WRITE_FAILED")
		}
		_, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_MALFORMED_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			f.firstVaultID, f.secondVaultID)
	})

	t.Run("alternate manifest suffix", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.firstConfig)
		profileDir, backendRoot := localWorkspaceRoots(f)
		source, err := os.ReadFile(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_ALTERNATE_MANIFEST_READ_FAILED")
		}
		alternate := filepath.Join(profileDir, "alternate.JSON")
		if err := os.WriteFile(alternate, source, 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_ALTERNATE_MANIFEST_WRITE_FAILED")
		}
		companionPath, err := CompanionPath(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_ALTERNATE_COMPANION_PATH_FAILED")
		}
		companionBytes, err := os.ReadFile(companionPath)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_ALTERNATE_COMPANION_READ_FAILED")
		}
		alternateCompanion, err := CompanionPath(alternate)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_ALTERNATE_COMPANION_PATH_FAILED")
		}
		if err := os.WriteFile(alternateCompanion, companionBytes, 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_ALTERNATE_COMPANION_WRITE_FAILED")
		}
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_ALTERNATE_MANIFEST_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			manifest.VaultID, f.secondVaultID)
	})

	t.Run("nested directory entry", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		if err := os.Mkdir(filepath.Join(profileDir, "nested"), 0700); err != nil {
			t.Fatal("LOCAL_WORKSPACE_NESTED_DIRECTORY_CREATE_FAILED")
		}
		_, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_NESTED_DIRECTORY_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			f.firstVaultID, f.secondVaultID)
	})

	t.Run("orphan companion sidecar", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		companionPath, err := CompanionPath(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_ORPHAN_COMPANION_PATH_FAILED")
		}
		companionBytes, err := os.ReadFile(companionPath)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_ORPHAN_COMPANION_READ_FAILED")
		}
		orphan := filepath.Join(profileDir, "orphan.json.baseline")
		if err := os.WriteFile(orphan, companionBytes, 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_ORPHAN_COMPANION_WRITE_FAILED")
		}
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_ORPHAN_COMPANION_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			f.firstVaultID, f.secondVaultID)
	})

	t.Run("orphan journal sidecar", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		orphan := filepath.Join(profileDir, "orphan.journal")
		if err := os.WriteFile(orphan, []byte("unrecognized journal sidecar"), 0600); err != nil {
			t.Fatal("LOCAL_WORKSPACE_ORPHAN_JOURNAL_WRITE_FAILED")
		}
		_, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_ORPHAN_JOURNAL_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			f.firstVaultID, f.secondVaultID)
	})

	t.Run("unsafe profile parent", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		if err := os.Chmod(profileDir, 0755); err != nil {
			t.Fatal("LOCAL_WORKSPACE_UNSAFE_CHMOD_FAILED")
		}
		defer func() { _ = os.Chmod(profileDir, 0700) }()
		_, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_UNSAFE_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot)
	})

	t.Run("pending journal", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		manifest := localBackupManifest(t, f.firstConfig)
		state := localBackupPristineState(t, manifest)
		defer clear(state.BaseBytes)
		defer clear(state.WorkingBytes)
		journal, err := vaultfilejournal.OpenExisting(manifest.Journal)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_PENDING_OPEN_FAILED")
		}
		proposal := vaultfilejournal.Proposal{
			Generation: 1, OperationID: "workspace-pending-op",
			ExpectedRevision: state.RemoteRevision,
			Bytes:            []byte("authenticated pending successor placeholder"),
		}
		if err := journal.PrepareWorkingIfState(state, proposal); err != nil {
			_ = journal.Close()
			t.Fatal("LOCAL_WORKSPACE_PENDING_PREPARE_FAILED")
		}
		if err := journal.Close(); err != nil {
			t.Fatal("LOCAL_WORKSPACE_PENDING_CLOSE_FAILED")
		}
		before := localFirstObserveScope(t, manifest)
		defer before.clear()
		profileDir, backendRoot := localWorkspaceRoots(f)
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceConflict) {
			t.Fatal("LOCAL_WORKSPACE_PENDING_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot, manifest.VaultID)
		after := localFirstObserveScope(t, manifest)
		defer after.clear()
		before.assertSame(t, after, "LOCAL_WORKSPACE_PENDING_CHANGED_SOURCE")
	})

	t.Run("settled content drift", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		fx := newLocalFirstWriteFixtureFor(t, f, f.secondConfig, f.secondVaultID)
		if _, err := fx.write(context.Background()); err != nil {
			t.Fatal("LOCAL_WORKSPACE_DRIFT_WRITE_FAILED")
		}
		journalBefore, err := os.ReadFile(fx.manifest.Journal)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_DRIFT_JOURNAL_READ_FAILED")
		}
		defer clear(journalBefore)
		drifted := []byte("not the settled owned successor")
		driftedRevision := localFirstRewriteBackend(t, fx.manifest, drifted)
		profileDir, backendRoot := localWorkspaceRoots(f)
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceConflict) {
			t.Fatal("LOCAL_WORKSPACE_CONTENT_DRIFT_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot, fx.manifest.VaultID)
		journalAfter, err := os.ReadFile(fx.manifest.Journal)
		if err != nil || !bytes.Equal(journalBefore, journalAfter) {
			t.Fatal("LOCAL_WORKSPACE_DRIFT_CHANGED_JOURNAL")
		}
		backendAfter, revisionAfter := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfter)
		if !bytes.Equal(backendAfter, drifted) || revisionAfter != driftedRevision {
			t.Fatal("LOCAL_WORKSPACE_DRIFT_CHANGED_BACKEND")
		}
	})

	t.Run("settled revision drift", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		fx := newLocalFirstWriteFixtureFor(t, f, f.secondConfig, f.secondVaultID)
		if _, err := fx.write(context.Background()); err != nil {
			t.Fatal("LOCAL_WORKSPACE_REVISION_WRITE_FAILED")
		}
		current, currentRevision := localFirstReadBackend(t, fx.manifest)
		defer clear(current)
		driftedRevision := localFirstRewriteBackend(t, fx.manifest, current)
		if driftedRevision == currentRevision {
			t.Fatal("LOCAL_WORKSPACE_REVISION_DRIFT_NOT_REAL")
		}
		profileDir, backendRoot := localWorkspaceRoots(f)
		_, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceConflict) {
			t.Fatal("LOCAL_WORKSPACE_REVISION_DRIFT_ACCEPTED")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot, fx.manifest.VaultID)
		backendAfter, revisionAfter := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfter)
		if !bytes.Equal(backendAfter, current) || revisionAfter != driftedRevision {
			t.Fatal("LOCAL_WORKSPACE_REVISION_DRIFT_CHANGED_BACKEND")
		}
	})

	t.Run("resolved ancestor nesting", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		// Positive control: the untouched fixture is a valid, unrelated pair.
		if _, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot); err != nil {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_BASELINE_FAILED")
		}

		// Add a real 0700 backend leaf beneath the private profile after the
		// positive control. The leaf must be a real directory, not a symlink.
		nestedLeaf := filepath.Join(profileDir, "nested-backend")
		if err := os.Mkdir(nestedLeaf, 0700); err != nil {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_NESTED_CREATE_FAILED")
		}
		nestedInfo, err := os.Lstat(nestedLeaf)
		if err != nil || nestedInfo.Mode()&os.ModeSymlink != 0 || !nestedInfo.IsDir() {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_NESTED_NOT_REAL_DIRECTORY")
		}

		// Present that real leaf through a symlinked ancestor at a lexically
		// unrelated private fixture location. This does not depend on the
		// ambient umask or on a temp parent being private.
		presentedParent := filepath.Join(t.TempDir(), "presented")
		if err := os.Mkdir(presentedParent, 0700); err != nil {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_PRESENTED_CREATE_FAILED")
		}
		link := filepath.Join(presentedParent, "profile-link")
		if err := os.Symlink(profileDir, link); err != nil {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_LINK_FAILED")
		}
		presentedBackend := filepath.Join(link, filepath.Base(nestedLeaf))

		// Both owning-directory helpers must accept the proposed paths, and the
		// resolved real paths must be strictly nested while the lexical paths
		// are unrelated. Only resolved-scope validation can refuse this pair.
		profileBinding, err := localOwnedWorkspaceDirectory(profileDir, true)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_PROFILE_HELPER_REFUSED")
		}
		backendBinding, err := localOwnedWorkspaceDirectory(presentedBackend, false)
		if err != nil {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_BACKEND_HELPER_REFUSED")
		}
		if localOwnedWorkspaceNested(profileDir, presentedBackend) {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_CASE_LEXICALLY_NESTED")
		}
		if !strings.HasPrefix(backendBinding.resolved,
			profileBinding.resolved+string(os.PathSeparator)) {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_CASE_NOT_NESTED")
		}
		_, err = PreflightLocalOwnedWorkspaceSource(context.Background(), f.session,
			profileDir, presentedBackend)
		if !errors.Is(err, ErrLocalOwnedWorkspaceReviewRequired) {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_NESTING_ACCEPTED")
		}
		if !strings.Contains(err.Error(), "resolved scopes") {
			t.Fatal("LOCAL_WORKSPACE_RESOLVED_NESTING_WRONG_BOUNDARY")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, presentedBackend,
			f.firstVaultID, f.secondVaultID)
	})

	t.Run("locked session entry", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		f.session.Lock()
		proof, err := PreflightLocalOwnedWorkspaceSource(context.Background(), f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceCanceled) {
			t.Fatal("LOCAL_WORKSPACE_LOCKED_SESSION_ACCEPTED")
		}
		if !reflect.DeepEqual(proof, LocalOwnedWorkspacePreflight{}) {
			t.Fatal("LOCAL_WORKSPACE_LOCKED_SESSION_PROOF_NOT_EMPTY")
		}
		localWorkspaceAssertRefusalRedacted(t, err, profileDir, backendRoot,
			f.firstVaultID, f.secondVaultID)
	})

	t.Run("lock during initial capture", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		localWorkspaceAssertInitialCaptureCanceled(t, f, f.session.Lock)
	})

	t.Run("request lock during initial capture", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		localWorkspaceAssertInitialCaptureCanceled(t, f, f.session.RequestLock)
	})

	t.Run("canceled context", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		profileDir, backendRoot := localWorkspaceRoots(f)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := PreflightLocalOwnedWorkspaceSource(ctx, f.session, profileDir, backendRoot)
		if !errors.Is(err, ErrLocalOwnedWorkspaceCanceled) {
			t.Fatal("LOCAL_WORKSPACE_CANCEL_ACCEPTED")
		}
	})
}
