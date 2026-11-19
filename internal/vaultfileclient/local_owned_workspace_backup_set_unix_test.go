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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	localWorkspaceBackupSetRedacted      = "[local owned workspace backup set]"
	localWorkspaceBackupVaultRedacted    = "[local owned workspace backup vault]"
	localWorkspaceBackupArtifactRedacted = "[local owned workspace backup artifact]"
)

type localWorkspaceBackupSetTestEntry struct {
	config   string
	vaultID  string
	manifest Manifest
	expected vaultfile.PolicyCheckpoint
	pin      LocalOwnedBackupCustodyFile
	factor   *personal.VaultFileBackupRecoveryFactor
	material []byte
}

type localWorkspaceBackupSetTestFixture struct {
	f           *localGenesisTwoVaultFixture
	profileDir  string
	backendRoot string
	stagingDir  string
	finalDir    string
	entries     []*localWorkspaceBackupSetTestEntry
	artifacts   []LocalOwnedWorkspaceBackupArtifact
}

func newLocalWorkspaceBackupSetTestFixture(t *testing.T, settleSecond bool) *localWorkspaceBackupSetTestFixture {
	t.Helper()
	f := newLocalGenesisTwoVaultFixture(t)
	if settleSecond {
		write := newLocalFirstWriteFixtureFor(t, f, f.secondConfig, f.secondVaultID)
		if _, err := write.write(context.Background()); err != nil {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_SETTLED_WRITE_FAILED")
		}
	}
	profileDir, backendRoot := localWorkspaceRoots(f)
	stagingDir := filepath.Join(f.f.root, "backup-set-staging")
	finalDir := filepath.Join(f.f.root, "backup-set-final")
	if err := os.Mkdir(stagingDir, 0700); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_STAGING_DIR_FAILED")
	}
	if err := os.Mkdir(finalDir, 0700); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FINAL_DIR_FAILED")
	}
	fx := &localWorkspaceBackupSetTestFixture{
		f: f, profileDir: profileDir, backendRoot: backendRoot,
		stagingDir: stagingDir, finalDir: finalDir,
	}
	t.Cleanup(fx.clear)
	specs := []struct{ config, vaultID, label string }{
		{f.firstConfig, f.firstVaultID, "vault-a"},
		{f.secondConfig, f.secondVaultID, "vault-b"},
	}
	for _, spec := range specs {
		entry := fx.prepare(t, spec.config, spec.vaultID, spec.label)
		fx.entries = append(fx.entries, entry)
		fx.artifacts = append(fx.artifacts, LocalOwnedWorkspaceBackupArtifact{
			Pin: entry.pin, Factor: entry.factor,
		})
	}
	if fx.entries[0].pin.VaultID == fx.entries[1].pin.VaultID {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_VAULTS_NOT_DISTINCT")
	}
	if bytes.Equal(fx.entries[0].material, fx.entries[1].material) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FACTORS_NOT_INDEPENDENT")
	}
	return fx
}

func (fx *localWorkspaceBackupSetTestFixture) prepare(t *testing.T, config, vaultID, label string) *localWorkspaceBackupSetTestEntry {
	t.Helper()
	manifest := localBackupManifest(t, config)
	companion := localBackupCompanion(t, config, manifest)
	expected := localWorkspaceBackupSetExpectedCheckpoint(t, manifest, companion)
	custody, factor, err := PrepareLocalOwnedBackupCustody(context.Background(), fx.f.session,
		config, manifest.BackendRoot, manifest.VaultID, manifest.Journal, expected,
		[]byte(fx.f.f.password), fx.f.f.key)
	if err != nil || len(custody.Artifact) == 0 || factor == nil {
		clear(expected.OwnerRootPublicKey)
		clear(expected.PolicyDigest)
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PREPARE_FAILED")
	}
	material := factor.Material()
	factor.Clear()
	imported, err := ImportLocalOwnedBackupRecoveryFactor(material)
	if err != nil || imported == nil {
		clear(material)
		clear(expected.OwnerRootPublicKey)
		clear(expected.PolicyDigest)
		custody.Clear()
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FACTOR_IMPORT_FAILED")
	}
	stagingPath := filepath.Join(fx.stagingDir, label+".custody")
	pin, err := SaveLocalOwnedBackupCustodyFile(context.Background(), stagingPath,
		custody.Artifact, expected, imported)
	custody.Clear()
	if err != nil {
		clear(material)
		clear(expected.OwnerRootPublicKey)
		clear(expected.PolicyDigest)
		imported.Clear()
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_SAVE_FAILED")
	}
	if bytes.Contains(mustReadFile(t, stagingPath), material) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FACTOR_LEAKED_INTO_ARTIFACT")
	}
	finalPath := filepath.Join(fx.finalDir, label+".custody")
	if err := os.Rename(stagingPath, finalPath); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_RELOCATE_FAILED")
	}
	pin.Path = finalPath
	return &localWorkspaceBackupSetTestEntry{
		config: config, vaultID: vaultID, manifest: manifest, expected: expected,
		pin: pin, factor: imported, material: material,
	}
}

func (fx *localWorkspaceBackupSetTestFixture) clear() {
	if fx == nil {
		return
	}
	for _, entry := range fx.entries {
		clear(entry.expected.OwnerRootPublicKey)
		clear(entry.expected.PolicyDigest)
		clear(entry.material)
		entry.factor.Clear()
	}
	*fx = localWorkspaceBackupSetTestFixture{}
}

func localWorkspaceBackupSetExpectedCheckpoint(t *testing.T, manifest Manifest,
	companion Companion) vaultfile.PolicyCheckpoint {
	t.Helper()
	verified, err := verifyLocalGenesisCompanion(manifest, companion)
	if err != nil || verified.checkpoint == nil {
		clearLocalGenesisVerified(&verified)
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EXPECTED_CHECKPOINT_FAILED")
	}
	checkpoint := localCustodyCheckpoint(verified.checkpoint)
	clearLocalGenesisVerified(&verified)
	return checkpoint
}

type localWorkspaceBackupSetTestEvidence struct {
	source       []localWorkspaceDurable
	artifacts    [][]byte
	finalEntries []string
}

func localWorkspaceBackupSetTestCapture(t *testing.T, fx *localWorkspaceBackupSetTestFixture) *localWorkspaceBackupSetTestEvidence {
	t.Helper()
	ev := &localWorkspaceBackupSetTestEvidence{}
	for _, entry := range fx.entries {
		ev.source = append(ev.source, localWorkspaceObserve(t, entry.config, entry.manifest))
		ev.artifacts = append(ev.artifacts, mustReadFile(t, entry.pin.Path))
	}
	entries, err := os.ReadDir(fx.finalDir)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FINAL_DIR_READ_FAILED")
	}
	for _, entry := range entries {
		ev.finalEntries = append(ev.finalEntries, entry.Name())
	}
	slices.Sort(ev.finalEntries)
	t.Cleanup(ev.clear)
	return ev
}

func (ev *localWorkspaceBackupSetTestEvidence) clear() {
	if ev == nil {
		return
	}
	for index := range ev.source {
		ev.source[index].clear()
	}
	for index := range ev.artifacts {
		clear(ev.artifacts[index])
	}
	*ev = localWorkspaceBackupSetTestEvidence{}
}

func (ev *localWorkspaceBackupSetTestEvidence) assertSourceSame(t *testing.T, fx *localWorkspaceBackupSetTestFixture, code string) {
	t.Helper()
	for index, entry := range fx.entries {
		now := localWorkspaceObserve(t, entry.config, entry.manifest)
		ev.source[index].assertSame(t, now, code)
		now.clear()
	}
}

func (ev *localWorkspaceBackupSetTestEvidence) assertArtifactsSame(t *testing.T, fx *localWorkspaceBackupSetTestFixture, code string) {
	t.Helper()
	for index, entry := range fx.entries {
		now := mustReadFile(t, entry.pin.Path)
		if !bytes.Equal(now, ev.artifacts[index]) {
			clear(now)
			t.Fatal(code)
		}
		clear(now)
	}
	entries, err := os.ReadDir(fx.finalDir)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FINAL_DIR_READ_FAILED")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, ev.finalEntries) {
		t.Fatal(code)
	}
	staged, err := os.ReadDir(fx.stagingDir)
	if err != nil || len(staged) != 0 {
		t.Fatal(code)
	}
}

func localWorkspaceBackupSetRefuse(t *testing.T, code string, category error,
	set LocalOwnedWorkspaceBackupSet, err error) {
	t.Helper()
	if !errors.Is(err, category) || !reflect.DeepEqual(set, LocalOwnedWorkspaceBackupSet{}) {
		t.Fatal(code)
	}
}

func localWorkspaceBackupSetAssertRedacted(t *testing.T, set LocalOwnedWorkspaceBackupSet,
	fx *localWorkspaceBackupSetTestFixture) {
	t.Helper()
	for _, formatted := range []string{
		fmt.Sprintf("%v", set), fmt.Sprintf("%+v", set), fmt.Sprintf("%#v", set),
		fmt.Sprintf("%v", &set), fmt.Sprintf("%+v", &set), fmt.Sprintf("%#v", &set),
		fmt.Sprintf("%v", LocalOwnedWorkspaceBackupSet{}),
		fmt.Sprintf("%v", (*LocalOwnedWorkspaceBackupSet)(nil)),
	} {
		if formatted != localWorkspaceBackupSetRedacted {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FORMAT_NOT_REDACTED")
		}
	}
	raw, err := json.Marshal(set)
	if err != nil || string(raw) != "{}" {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_JSON_EXPOSED")
	}
	raw, err = json.Marshal(set.Vaults)
	if err != nil || string(raw) != "[{},{}]" {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_VAULTS_JSON_EXPOSED")
	}
	for _, vault := range set.Vaults {
		for _, formatted := range []string{
			fmt.Sprintf("%v", vault), fmt.Sprintf("%+v", vault), fmt.Sprintf("%#v", vault),
			fmt.Sprintf("%v", &vault), fmt.Sprintf("%+v", &vault), fmt.Sprintf("%#v", &vault),
			fmt.Sprintf("%v", LocalOwnedWorkspaceBackupVault{}),
			fmt.Sprintf("%v", (*LocalOwnedWorkspaceBackupVault)(nil)),
		} {
			if formatted != localWorkspaceBackupVaultRedacted {
				t.Fatal("LOCAL_WORKSPACE_BACKUP_VAULT_FORMAT_NOT_REDACTED")
			}
		}
		raw, err := json.Marshal(vault)
		if err != nil || string(raw) != "{}" {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_VAULT_JSON_EXPOSED")
		}
	}
	for _, artifact := range fx.artifacts {
		for _, formatted := range []string{
			fmt.Sprintf("%v", artifact), fmt.Sprintf("%+v", artifact), fmt.Sprintf("%#v", artifact),
			fmt.Sprintf("%v", &artifact), fmt.Sprintf("%+v", &artifact), fmt.Sprintf("%#v", &artifact),
			fmt.Sprintf("%v", LocalOwnedWorkspaceBackupArtifact{}),
			fmt.Sprintf("%v", (*LocalOwnedWorkspaceBackupArtifact)(nil)),
		} {
			if formatted != localWorkspaceBackupArtifactRedacted {
				t.Fatal("LOCAL_WORKSPACE_BACKUP_ARTIFACT_FORMAT_NOT_REDACTED")
			}
		}
		raw, err := json.Marshal(artifact)
		if err != nil || string(raw) != "{}" {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_ARTIFACT_JSON_EXPOSED")
		}
	}
	combined := fmt.Sprintf("%v|%+v|%#v", set, set, set)
	for _, entry := range fx.entries {
		for _, private := range []string{
			entry.pin.Path, entry.vaultID, string(entry.material), fx.profileDir,
			fx.backendRoot, string(entry.pin.JournalRevision),
			string(entry.pin.BackendRevision), string(entry.pin.OriginRevision),
			localFirstWriteSecret,
		} {
			if private != "" && strings.Contains(combined, private) {
				t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_SAFE_FORMAT_LEAKED")
			}
		}
	}
}

func localWorkspaceBackupSetReopen(t *testing.T, fx *localWorkspaceBackupSetTestFixture) {
	t.Helper()
	for round := 0; round < 2; round++ {
		for _, entry := range fx.entries {
			opened, actual, err := OpenLocalOwnedBackupCustodyFile(context.Background(),
				entry.pin.Path, entry.pin, entry.expected, entry.factor)
			if err != nil || actual != entry.pin ||
				opened.Source.VaultID != entry.vaultID ||
				opened.SourceIdentity != entry.pin.SourceIdentity {
				opened.Clear()
				t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_DURABLE_REOPEN_FAILED")
			}
			opened.Clear()
		}
	}
}

func TestLocalOwnedWorkspaceBackupSetVerifiesObservedTwoVaults(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, true)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	if bytes.Equal(ev.artifacts[0], ev.artifacts[1]) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_ARTIFACTS_NOT_INDEPENDENT")
	}
	localWorkspaceBackupSetReopen(t, fx)

	sibling, summary := fx.f.open(t, fx.f.firstConfig, fx.f.firstVaultID)
	defer sibling.Close()
	assertLocalGenesisSummary(t, summary, fx.f.firstVaultID)

	set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
		fx.profileDir, fx.backendRoot, fx.artifacts)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_VERIFY_FAILED")
	}
	if set.State != LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified ||
		!set.StopWritesProofOutstanding || !set.UnknownOfflineDraftsPossible ||
		!set.NewProfileImportOutstanding || !set.CutoverOutstanding ||
		!set.CompleteWorkspaceOutstanding {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_OUTCOME_OVERCLAIMED")
	}
	if len(set.Vaults) != 2 || set.Vaults[0].VaultID >= set.Vaults[1].VaultID {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_SHAPE_FAILED")
	}
	proof, err := PreflightLocalOwnedWorkspaceSource(context.Background(), fx.f.session,
		fx.profileDir, fx.backendRoot)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_SOURCE_PROOF_FAILED")
	}
	if set.AccountDigest != proof.AccountDigest || set.ProfileDigest != proof.ProfileDigest ||
		set.BackendDigest != proof.BackendDigest || set.RosterDigest != proof.RosterDigest ||
		set.KnownSetDigest != proof.KnownSetDigest ||
		set.BackupSetDigest != localOwnedWorkspaceBackupSetDigest(set) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_DIGEST_BINDING_FAILED")
	}
	byID := make(map[string]LocalOwnedWorkspaceBackupVault, len(set.Vaults))
	for _, vault := range set.Vaults {
		byID[vault.VaultID] = vault
	}
	proofByID := make(map[string]LocalOwnedWorkspaceVault, len(proof.Vaults))
	for _, vault := range proof.Vaults {
		proofByID[vault.VaultID] = vault
	}
	for _, entry := range fx.entries {
		vault, ok := byID[entry.vaultID]
		if !ok {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_VAULT_MISSING")
		}
		want, ok := proofByID[entry.vaultID]
		if !ok {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROOF_MISSING")
		}
		if vault.ManifestSHA256 != want.ManifestSHA256 ||
			vault.CurrentSHA256 != want.CurrentSHA256 ||
			vault.OriginSHA256 != want.OriginSHA256 ||
			vault.CheckpointDigest != want.CheckpointDigest ||
			vault.IdentityDigest != want.IdentityDigest ||
			vault.JournalRevision != want.JournalRevision ||
			vault.BackendRevision != want.BackendRevision ||
			vault.OriginRevision != want.OriginRevision ||
			vault.ContentSeq != want.ContentSeq {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_SOURCE_BINDING_FAILED")
		}
		if vault.ArtifactSHA256 != entry.pin.ArtifactSHA256 ||
			vault.ArtifactSize != entry.pin.ArtifactSize ||
			vault.SourceIdentity != entry.pin.SourceIdentity ||
			vault.CheckpointDigest != entry.pin.CheckpointDigest ||
			vault.JournalRevision != vaultfilebackend.Revision(entry.pin.JournalRevision) ||
			vault.BackendRevision != vaultfilebackend.Revision(entry.pin.BackendRevision) ||
			vault.OriginRevision != vaultfilebackend.Revision(entry.pin.OriginRevision) ||
			vault.ContentSeq != entry.pin.ContentSeq {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_ARTIFACT_BINDING_FAILED")
		}
		target, revision := localFirstReadBackend(t, entry.manifest)
		if revision != vault.BackendRevision || sha256.Sum256(target) != vault.CurrentSHA256 {
			clear(target)
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_BACKEND_BINDING_FAILED")
		}
		clear(target)
	}
	if len(byID) != 2 {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EXTRA_VAULT")
	}
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_ACTIVATED_SESSION")
	}
	if _, err := sibling.Summary(); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_CLOSED_SIBLING")
	}
	ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_CHANGED_SOURCE")
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_CHANGED_ARTIFACTS")
	localWorkspaceBackupSetAssertRedacted(t, set, fx)
}

func TestLocalOwnedWorkspaceBackupSetRefusesArtifactInputs(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, true)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	sibling, summary := fx.f.open(t, fx.f.firstConfig, fx.f.firstVaultID)
	defer sibling.Close()
	assertLocalGenesisSummary(t, summary, fx.f.firstVaultID)

	probeDir := filepath.Join(fx.f.f.root, "backup-set-probes")
	if err := os.Mkdir(probeDir, 0700); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROBE_DIR_FAILED")
	}
	probeCopy := filepath.Join(probeDir, "copy.custody")
	if err := os.WriteFile(probeCopy, mustReadFile(t, fx.entries[0].pin.Path), 0600); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROBE_COPY_FAILED")
	}
	probeLink := filepath.Join(probeDir, "link.custody")
	if err := os.Symlink(fx.entries[0].pin.Path, probeLink); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROBE_LINK_FAILED")
	}
	probeDirPath := filepath.Join(probeDir, "directory")
	if err := os.Mkdir(probeDirPath, 0700); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROBE_DIRECTORY_FAILED")
	}
	probeNonPrivate := filepath.Join(probeDir, "non-private.custody")
	if err := os.WriteFile(probeNonPrivate, mustReadFile(t, fx.entries[1].pin.Path), 0600); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROBE_NON_PRIVATE_FAILED")
	}
	if err := os.Chmod(probeNonPrivate, 0644); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROBE_CHMOD_FAILED")
	}
	tampered := mustReadFile(t, fx.entries[0].pin.Path)
	tamperedPath := filepath.Join(probeDir, "tampered.custody")
	tampered[len(tampered)/2] ^= 0x40
	if err := os.WriteFile(tamperedPath, tampered, 0600); err != nil {
		clear(tampered)
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_PROBE_TAMPERED_FAILED")
	}
	clear(tampered)
	absentPath := filepath.Join(probeDir, "absent.custody")

	copyArtifacts := func() []LocalOwnedWorkspaceBackupArtifact {
		return append([]LocalOwnedWorkspaceBackupArtifact(nil), fx.artifacts...)
	}
	cases := []struct {
		name     string
		code     string
		category error
		build    func() []LocalOwnedWorkspaceBackupArtifact
	}{
		{"missing", "LOCAL_WORKSPACE_BACKUP_SET_MISSING_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact { return copyArtifacts()[:1] }},
		{"extra foreign vault", "LOCAL_WORKSPACE_BACKUP_SET_EXTRA_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				extra := copyArtifacts()[0]
				extra.Pin.VaultID = "0011223344556677"
				extra.Pin.Path = probeCopy
				return append(copyArtifacts(), extra)
			}},
		{"duplicate artifact", "LOCAL_WORKSPACE_BACKUP_SET_DUPLICATE_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				return append(artifacts, artifacts[0])
			}},
		{"duplicate path", "LOCAL_WORKSPACE_BACKUP_SET_DUPLICATE_PATH_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[1].Pin.Path = artifacts[0].Pin.Path
				return artifacts
			}},
		{"reused digest", "LOCAL_WORKSPACE_BACKUP_SET_REUSED_DIGEST_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[1].Pin.ArtifactSHA256 = artifacts[0].Pin.ArtifactSHA256
				return artifacts
			}},
		{"swapped factors", "LOCAL_WORKSPACE_BACKUP_SET_SWAPPED_FACTORS_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Factor, artifacts[1].Factor = artifacts[1].Factor, artifacts[0].Factor
				return artifacts
			}},
		{"wrong factor", "LOCAL_WORKSPACE_BACKUP_SET_WRONG_FACTOR_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Factor = artifacts[1].Factor
				return artifacts
			}},
		{"relative path", "LOCAL_WORKSPACE_BACKUP_SET_RELATIVE_PATH_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Pin.Path = "relative.custody"
				return artifacts
			}},
		{"empty path", "LOCAL_WORKSPACE_BACKUP_SET_EMPTY_PATH_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Pin.Path = ""
				return artifacts
			}},
		{"symlink path", "LOCAL_WORKSPACE_BACKUP_SET_SYMLINK_PATH_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Pin.Path = probeLink
				return artifacts
			}},
		{"directory path", "LOCAL_WORKSPACE_BACKUP_SET_DIRECTORY_PATH_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Pin.Path = probeDirPath
				return artifacts
			}},
		{"non-private path", "LOCAL_WORKSPACE_BACKUP_SET_NON_PRIVATE_ACCEPTED", ErrLocalOwnedWorkspaceReviewRequired,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Pin.Path = probeNonPrivate
				return artifacts
			}},
		{"absent artifact", "LOCAL_WORKSPACE_BACKUP_SET_ABSENT_ACCEPTED", ErrLocalOwnedWorkspaceConflict,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Pin.Path = absentPath
				return artifacts
			}},
		{"tampered artifact", "LOCAL_WORKSPACE_BACKUP_SET_TAMPERED_ACCEPTED", ErrLocalOwnedWorkspaceConflict,
			func() []LocalOwnedWorkspaceBackupArtifact {
				artifacts := copyArtifacts()
				artifacts[0].Pin.Path = tamperedPath
				return artifacts
			}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
				fx.profileDir, fx.backendRoot, test.build())
			localWorkspaceBackupSetRefuse(t, test.code, test.category, set, err)
			ev.assertSourceSame(t, fx, test.code)
			ev.assertArtifactsSame(t, fx, test.code)
			if _, err := sibling.Summary(); err != nil {
				t.Fatal(test.code)
			}
			if !fx.f.session.Unlocked() {
				t.Fatal(test.code)
			}
		})
	}
}

func TestLocalOwnedWorkspaceBackupSetRefusesStaleSignedArtifact(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, false)
	// The stale artifact is authentic under its own old pin and factor.
	localWorkspaceBackupSetReopen(t, fx)

	write := newLocalFirstWriteFixtureFor(t, fx.f, fx.f.firstConfig, fx.f.firstVaultID)
	if _, err := write.write(context.Background()); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_STALE_WRITE_FAILED")
	}
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
		fx.profileDir, fx.backendRoot, fx.artifacts)
	localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_STALE_ACCEPTED",
		ErrLocalOwnedWorkspaceReviewRequired, set, err)
	ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_STALE_CHANGED_SOURCE")
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_STALE_CHANGED_ARTIFACTS")
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_STALE_ACTIVATED_SESSION")
	}
	// Reopen the stale artifact again after the source advanced: it remains a
	// correctly signed artifact, just no longer the current source.
	localWorkspaceBackupSetReopen(t, fx)
}

func TestLocalOwnedWorkspaceBackupSetRefusesSameBytesNewRevision(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, true)
	entry := fx.entries[0]
	target, revision := localFirstReadBackend(t, entry.manifest)
	targetSHA256 := sha256.Sum256(target)
	newRevision := localFirstRewriteBackend(t, entry.manifest, target)
	if newRevision == revision {
		clear(target)
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_SAME_BYTES_REVISION_NOT_NEW")
	}
	clear(target)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
		fx.profileDir, fx.backendRoot, fx.artifacts)
	localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_NEWER_SAME_BYTES_ACCEPTED",
		ErrLocalOwnedWorkspaceConflict, set, err)
	ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_NEWER_SAME_BYTES_CHANGED_SOURCE")
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_NEWER_SAME_BYTES_CHANGED_ARTIFACTS")
	after, afterRevision := localFirstReadBackend(t, entry.manifest)
	defer clear(after)
	if afterRevision != newRevision || sha256.Sum256(after) != targetSHA256 {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_NEWER_SAME_BYTES_TARGET_MUTATED")
	}
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_NEWER_SAME_BYTES_ACTIVATED_SESSION")
	}
}

func TestLocalOwnedWorkspaceBackupSetRefusesFinalSourceDrift(t *testing.T) {
	fx := newLocalWorkspaceBackupSetTestFixture(t, true)
	ev := localWorkspaceBackupSetTestCapture(t, fx)
	entry := fx.entries[0]
	beforeBytes, beforeRevision := localFirstReadBackend(t, entry.manifest)
	defer clear(beforeBytes)

	localOwnedWorkspaceBackupSetBeforeFinalProofForTest = func() {
		target, _ := localFirstReadBackend(t, entry.manifest)
		localFirstRewriteBackend(t, entry.manifest, target)
		clear(target)
	}
	defer func() { localOwnedWorkspaceBackupSetBeforeFinalProofForTest = nil }()

	set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
		fx.profileDir, fx.backendRoot, fx.artifacts)
	localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FINAL_DRIFT_ACCEPTED",
		ErrLocalOwnedWorkspaceConflict, set, err)
	ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FINAL_DRIFT_CHANGED_ARTIFACTS")
	afterBytes, afterRevision := localFirstReadBackend(t, entry.manifest)
	defer clear(afterBytes)
	if afterRevision == beforeRevision || !bytes.Equal(afterBytes, beforeBytes) {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FINAL_DRIFT_NOT_OBSERVED")
	}
	if !fx.f.session.Unlocked() {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_FINAL_DRIFT_ACTIVATED_SESSION")
	}
}

func TestLocalOwnedWorkspaceBackupSetRefusesArtifactChangeBeforeDelivery(t *testing.T) {
	tests := []struct {
		name   string
		code   string
		mutate func(path string, original []byte) error
	}{
		{
			name: "removed",
			code: "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_REMOVED_ACCEPTED",
			mutate: func(path string, _ []byte) error {
				return os.Remove(path)
			},
		},
		{
			name: "replaced",
			code: "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_REPLACED_ACCEPTED",
			mutate: func(path string, original []byte) error {
				replacement := append([]byte(nil), original...)
				defer clear(replacement)
				replacement[len(replacement)/2] ^= 0x40
				return os.WriteFile(path, replacement, 0600)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fx := newLocalWorkspaceBackupSetTestFixture(t, true)
			ev := localWorkspaceBackupSetTestCapture(t, fx)
			entry := fx.entries[0]
			original := mustReadFile(t, entry.pin.Path)
			defer clear(original)
			restore := func() {
				if err := os.WriteFile(entry.pin.Path, original, 0600); err != nil {
					t.Error("LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_RESTORE_FAILED")
				}
			}
			defer restore()
			var mutateErr error
			localOwnedWorkspaceBackupSetBeforeDeliveryForTest = func() {
				mutateErr = test.mutate(entry.pin.Path, original)
			}
			defer func() { localOwnedWorkspaceBackupSetBeforeDeliveryForTest = nil }()

			set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
				fx.profileDir, fx.backendRoot, fx.artifacts)
			if mutateErr != nil {
				t.Fatal(test.code)
			}
			localWorkspaceBackupSetRefuse(t, test.code, ErrLocalOwnedWorkspaceConflict, set, err)
			// Restore before proving both the source set and every unrelated
			// custody artifact are exactly what they were before the call.
			restore()
			ev.assertSourceSame(t, fx, test.code)
			ev.assertArtifactsSame(t, fx, test.code)
			if !fx.f.session.Unlocked() {
				t.Fatal(test.code)
			}
		})
	}
}

func TestLocalOwnedWorkspaceBackupSetRefusesSwitchedCallerPinBeforeDelivery(t *testing.T) {
	tests := []struct {
		name          string
		code          string
		mutate        func(originalPath, alternatePath string, original []byte) error
		assertInvalid func(t *testing.T, code, path string, pin LocalOwnedBackupCustodyFile)
	}{
		{
			name: "removed",
			code: "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_SWITCHED_REMOVED_ACCEPTED",
			mutate: func(originalPath, alternatePath string, original []byte) error {
				if err := os.WriteFile(alternatePath, original, 0600); err != nil {
					return err
				}
				return os.Remove(originalPath)
			},
			assertInvalid: func(t *testing.T, code, path string, _ LocalOwnedBackupCustodyFile) {
				t.Helper()
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal(code)
				}
			},
		},
		{
			name: "replaced",
			code: "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_SWITCHED_REPLACED_ACCEPTED",
			mutate: func(originalPath, alternatePath string, original []byte) error {
				if err := os.WriteFile(alternatePath, original, 0600); err != nil {
					return err
				}
				replacement := append([]byte(nil), original...)
				defer clear(replacement)
				replacement[len(replacement)/2] ^= 0x40
				return os.WriteFile(originalPath, replacement, 0600)
			},
			assertInvalid: func(t *testing.T, code, path string, pin LocalOwnedBackupCustodyFile) {
				t.Helper()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(code)
				}
				defer clear(data)
				if int64(len(data)) == pin.ArtifactSize && sha256.Sum256(data) == pin.ArtifactSHA256 {
					t.Fatal(code)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fx := newLocalWorkspaceBackupSetTestFixture(t, true)
			ev := localWorkspaceBackupSetTestCapture(t, fx)
			entry := fx.entries[0]
			unrelated := fx.entries[1]
			original := mustReadFile(t, entry.pin.Path)
			defer clear(original)
			alternateDir := filepath.Join(fx.f.f.root, "backup-set-delivery-switch")
			if err := os.Mkdir(alternateDir, 0700); err != nil {
				t.Fatal(test.code)
			}
			alternatePath := filepath.Join(alternateDir, "matching.custody")
			alternatePin := entry.pin
			alternatePin.Path = alternatePath
			restore := func() {
				if err := os.WriteFile(entry.pin.Path, original, 0600); err != nil {
					t.Error(test.code)
				}
			}
			defer restore()
			var mutateErr error
			localOwnedWorkspaceBackupSetBeforeDeliveryForTest = func() {
				if err := test.mutate(entry.pin.Path, alternatePath, original); err != nil {
					mutateErr = err
					return
				}
				// The original artifact was already authenticated. Switch the
				// caller-owned slice to a different readable file and pin that
				// carries the same size and digest. The private snapshot must
				// still recheck the originally pinned path and refuse delivery.
				fx.artifacts[0] = LocalOwnedWorkspaceBackupArtifact{
					Pin: alternatePin, Factor: entry.factor,
				}
			}
			defer func() { localOwnedWorkspaceBackupSetBeforeDeliveryForTest = nil }()

			set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
				fx.profileDir, fx.backendRoot, fx.artifacts)
			if mutateErr != nil {
				t.Fatal(test.code)
			}
			localWorkspaceBackupSetRefuse(t, test.code, ErrLocalOwnedWorkspaceConflict, set, err)
			// No proof may fall back to the switched readable pin when the
			// original pinned path is absent or no longer the pinned bytes.
			test.assertInvalid(t, test.code, entry.pin.Path, entry.pin)
			switched, readErr := os.ReadFile(alternatePath)
			if readErr != nil || int64(len(switched)) != alternatePin.ArtifactSize ||
				sha256.Sum256(switched) != alternatePin.ArtifactSHA256 {
				clear(switched)
				t.Fatal(test.code)
			}
			clear(switched)
			unrelatedNow := mustReadFile(t, unrelated.pin.Path)
			if !bytes.Equal(unrelatedNow, ev.artifacts[1]) {
				clear(unrelatedNow)
				t.Fatal(test.code)
			}
			clear(unrelatedNow)
			ev.assertSourceSame(t, fx, test.code)
			restore()
			ev.assertArtifactsSame(t, fx, test.code)
			if !fx.f.session.Unlocked() {
				t.Fatal(test.code)
			}
		})
	}
}

func TestLocalOwnedWorkspaceBackupSetRefusesCancelAndLock(t *testing.T) {
	t.Run("canceled context", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		set, err := VerifyLocalOwnedWorkspaceBackupSet(canceled, fx.f.session,
			fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_CANCEL_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_CANCEL_CHANGED_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_CANCEL_CHANGED_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_CANCEL_ACTIVATED_SESSION")
		}
	})

	t.Run("request lock at entry", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		fx.f.session.RequestLock()
		set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
			fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_REQUEST_LOCK_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_REQUEST_LOCK_CHANGED_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_REQUEST_LOCK_CHANGED_ARTIFACTS")
	})

	t.Run("request lock before final gate", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		localOwnedWorkspaceBackupSetBeforeFinalProofForTest = fx.f.session.RequestLock
		defer func() { localOwnedWorkspaceBackupSetBeforeFinalProofForTest = nil }()
		set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
			fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_FINAL_LOCK_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_FINAL_LOCK_CHANGED_ARTIFACTS")
	})

	t.Run("cancel before delivery recheck", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		ctx, cancel := context.WithCancel(context.Background())
		localOwnedWorkspaceBackupSetBeforeDeliveryForTest = cancel
		defer func() { localOwnedWorkspaceBackupSetBeforeDeliveryForTest = nil }()
		set, err := VerifyLocalOwnedWorkspaceBackupSet(ctx, fx.f.session,
			fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_CANCEL_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_CANCEL_CHANGED_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_CANCEL_CHANGED_ARTIFACTS")
		if !fx.f.session.Unlocked() {
			t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_CANCEL_ACTIVATED_SESSION")
		}
	})

	t.Run("request lock before delivery recheck", func(t *testing.T) {
		fx := newLocalWorkspaceBackupSetTestFixture(t, true)
		ev := localWorkspaceBackupSetTestCapture(t, fx)
		localOwnedWorkspaceBackupSetBeforeDeliveryForTest = fx.f.session.RequestLock
		defer func() { localOwnedWorkspaceBackupSetBeforeDeliveryForTest = nil }()
		set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), fx.f.session,
			fx.profileDir, fx.backendRoot, fx.artifacts)
		localWorkspaceBackupSetRefuse(t, "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_LOCK_ACCEPTED",
			ErrLocalOwnedWorkspaceCanceled, set, err)
		ev.assertSourceSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_LOCK_CHANGED_SOURCE")
		ev.assertArtifactsSame(t, fx, "LOCAL_WORKSPACE_BACKUP_SET_DELIVERY_LOCK_CHANGED_ARTIFACTS")
	})
}

func TestLocalOwnedWorkspaceBackupSetAllowsEmptyObservedSet(t *testing.T) {
	root := t.TempDir()
	profileDir := filepath.Join(root, "private")
	backendRoot := filepath.Join(root, "backend")
	if err := os.Mkdir(profileDir, 0700); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EMPTY_PROFILE_FAILED")
	}
	backend, err := vaultfilebackend.OpenDir(backendRoot)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EMPTY_BACKEND_FAILED")
	}
	if err := backend.Close(); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EMPTY_BACKEND_CLOSE_FAILED")
	}
	personalPath := filepath.Join(root, "personal.ll")
	password := []byte("local-workspace-backup-set-empty")
	key := bytes.Repeat([]byte{0x51}, 16)
	defer clear(password)
	defer clear(key)
	if err := personal.Create(personalPath, string(password), key); err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EMPTY_PERSONAL_FAILED")
	}
	session, err := personal.UnlockSession(personalPath, password, key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EMPTY_UNLOCK_FAILED")
	}
	defer session.Lock()

	set, err := VerifyLocalOwnedWorkspaceBackupSet(context.Background(), session,
		profileDir, backendRoot, nil)
	if err != nil {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EMPTY_REJECTED")
	}
	if set.State != LocalOwnedWorkspaceBackupSetStateObservedVaultsCustodyVerified ||
		len(set.Vaults) != 0 ||
		set.BackupSetDigest != localOwnedWorkspaceBackupSetDigest(set) ||
		!set.StopWritesProofOutstanding || !set.UnknownOfflineDraftsPossible ||
		!set.NewProfileImportOutstanding || !set.CutoverOutstanding ||
		!set.CompleteWorkspaceOutstanding {
		t.Fatal("LOCAL_WORKSPACE_BACKUP_SET_EMPTY_OVERCLAIMED")
	}
}
