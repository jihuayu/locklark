//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

type publishedLocalFixture struct {
	fixture      fixture
	root         string
	workspace    string
	profileDir   string
	backendRoot  string
	config       string
	companion    string
	journal      string
	archive      string
	kit          []byte
	personalPath string
}

// newPublishedLocalFixture builds one controlled local profile with the real
// product creation path only. The observer under test is never used to create.
func newPublishedLocalFixture(t *testing.T) *publishedLocalFixture {
	t.Helper()
	root := t.TempDir()
	fixtureDir := filepath.Join(root, "fixture")
	if err := setup(fixtureDir); err != nil {
		t.Fatal("OBSERVER_FIXTURE_SETUP_FAILED")
	}
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "fixture.json"))
	if err != nil {
		t.Fatal("OBSERVER_FIXTURE_READ_FAILED")
	}
	var f fixture
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("OBSERVER_FIXTURE_PARSE_FAILED")
	}
	clear(raw)

	settingsDir := filepath.Join(root, "settings")
	if err := os.Mkdir(settingsDir, 0700); err != nil {
		t.Fatal("OBSERVER_FIXTURE_SETTINGS_FAILED")
	}
	workspace := filepath.Join(settingsDir, "vaultfile-workspace")
	profileDir := localProfileDir(workspace, f.Path)
	backendRoot := localBackendRoot(workspace)
	for _, dir := range []string{workspace, filepath.Join(workspace, "profiles"), profileDir, backendRoot} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal("OBSERVER_FIXTURE_WORKSPACE_FAILED")
		}
	}

	var selectorRaw [16]byte
	if _, err := rand.Read(selectorRaw[:]); err != nil {
		t.Fatal("OBSERVER_FIXTURE_SELECTOR_FAILED")
	}
	selector := hex.EncodeToString(selectorRaw[:])
	p := &publishedLocalFixture{
		fixture: f, root: root, workspace: workspace, profileDir: profileDir,
		backendRoot: backendRoot, personalPath: f.Path,
		config:    filepath.Join(profileDir, selector+".json"),
		companion: filepath.Join(profileDir, selector+".json.baseline"),
		journal:   filepath.Join(profileDir, selector+".journal"),
		archive:   filepath.Join(profileDir, selector+".llb"),
	}
	proposal := vaultfileclient.Manifest{
		Version: 1, Kind: vaultfileclient.CreateKind,
		PersonalFile: f.Path, BackendRoot: backendRoot, Name: selector + ".llv",
		Journal: p.journal, Archive: p.archive,
	}
	key, err := personal.ParseSecret(f.Secret)
	if err != nil {
		t.Fatal("OBSERVER_FIXTURE_KEY_FAILED")
	}
	t.Cleanup(func() { clear(key) })
	password, secret := []byte(f.Password), []byte(f.Secret)
	defer clear(password)
	defer clear(secret)

	creation, err := vaultfileclient.OpenCreation(p.config, &proposal, password, secret)
	if err != nil {
		t.Fatal("OBSERVER_FIXTURE_CREATE_OPEN_FAILED")
	}
	backupRequired, err := creation.Prepare(context.Background())
	creation.Close()
	if err != nil || !backupRequired {
		t.Fatal("OBSERVER_FIXTURE_CREATE_PREPARE_FAILED")
	}
	backup, err := personal.PrepareBackup(f.Path, p.archive, f.Password, key)
	if err != nil {
		t.Fatal("OBSERVER_FIXTURE_BACKUP_PREPARE_FAILED")
	}
	if err := backup.Publish(); err != nil {
		backup.Close()
		t.Fatal("OBSERVER_FIXTURE_BACKUP_PUBLISH_FAILED")
	}
	p.kit = []byte(backup.Material())
	backup.Close()
	t.Cleanup(func() { clear(p.kit) })
	if len(p.kit) == 0 {
		t.Fatal("OBSERVER_FIXTURE_KIT_CONFIRM_FAILED")
	}

	creation, err = vaultfileclient.OpenCreation(p.config, nil, password, secret)
	if err != nil {
		t.Fatal("OBSERVER_FIXTURE_RESUME_OPEN_FAILED")
	}
	defer creation.Close()
	backupRequired, err = creation.Prepare(context.Background())
	if err != nil || backupRequired {
		t.Fatal("OBSERVER_FIXTURE_RESUME_PREPARE_FAILED")
	}
	if err := creation.Complete(context.Background(), password, secret, p.kit); err != nil {
		t.Fatal("OBSERVER_FIXTURE_COMPLETE_FAILED")
	}
	if err := creation.Verify(context.Background(), password, secret, p.kit); err != nil {
		t.Fatal("OBSERVER_FIXTURE_VERIFY_FAILED")
	}
	return p
}

type persistentState struct {
	mode   os.FileMode
	size   int64
	digest [32]byte
}

func snapshotPersistent(t *testing.T, root string) map[string]persistentState {
	t.Helper()
	states := map[string]persistentState{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		state := persistentState{mode: info.Mode(), size: info.Size()}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			state.size = int64(len(raw))
			state.digest = sha256.Sum256(raw)
		}
		states[rel] = state
		return nil
	})
	if err != nil {
		t.Fatal("OBSERVER_SNAPSHOT_FAILED")
	}
	return states
}

func allProjectionTrue(report localProjection) bool {
	return report.ManifestCount == 1 && report.ManifestPersonal && report.ManifestBackend &&
		report.CompanionPresent && report.ManifestDigest && report.JournalPresent &&
		report.ArchivePresent && report.PrivateModes && report.BackendHashMatches && report.FactorsAbsent
}

func assertNotAllTrue(t *testing.T, report localProjection) {
	t.Helper()
	if allProjectionTrue(report) {
		t.Fatal("OBSERVER_NEGATIVE_ACCEPTED")
	}
}

func assertLimitedReport(t *testing.T, report localProjection, p *publishedLocalFixture) {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(report); err != nil {
		t.Fatal("OBSERVER_REPORT_ENCODE_FAILED")
	}
	assertLimitedBytes(t, buf.Bytes(), p)
}

func assertLimitedBytes(t *testing.T, out []byte, p *publishedLocalFixture) {
	t.Helper()
	if len(out) > 4096 {
		t.Fatal("OBSERVER_REPORT_NOT_BOUNDED")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(out, &fields) != nil || len(fields) != 10 {
		t.Fatal("OBSERVER_REPORT_KEYS_INVALID")
	}
	for _, key := range []string{"manifest_count", "manifest_personal", "manifest_backend", "companion_present",
		"manifest_digest", "journal_present", "archive_present", "private_modes", "backend_hash_matches", "factors_absent"} {
		raw, ok := fields[key]
		if !ok {
			t.Fatal("OBSERVER_REPORT_KEY_MISSING")
		}
		if key == "manifest_count" {
			var count int
			if json.Unmarshal(raw, &count) != nil || count != 1 {
				t.Fatal("OBSERVER_REPORT_COUNT_INVALID")
			}
			continue
		}
		var value bool
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("OBSERVER_REPORT_BOOL_INVALID")
		}
	}
	for _, secret := range [][]byte{[]byte(p.fixture.Password), []byte(p.fixture.Secret), []byte(p.fixture.OTPSeed),
		[]byte(p.fixture.ProviderCanary), p.kit, []byte(p.personalPath), []byte(p.config)} {
		if len(secret) > 0 && bytes.Contains(out, secret) {
			t.Fatal("OBSERVER_REPORT_LEAKED_LOCAL_VALUE")
		}
	}
}

func captureRun(t *testing.T, args []string) []byte {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("OBSERVER_CLI_PIPE_FAILED")
	}
	old := os.Stdout
	os.Stdout = writer
	runErr := run(args)
	os.Stdout = old
	writer.Close()
	raw, readErr := io.ReadAll(io.LimitReader(reader, 8192))
	reader.Close()
	if runErr != nil || readErr != nil {
		t.Fatal("OBSERVER_CLI_READ_FAILED")
	}
	return raw
}

func TestLocalVaultFileReadObserverPositive(t *testing.T) {
	p := newPublishedLocalFixture(t)
	fixturePath := filepath.Join(filepath.Dir(p.personalPath), "fixture.json")

	before := snapshotPersistent(t, p.root)
	report, err := verifyLocalWorkspace(p.fixture, p.workspace)
	if err != nil {
		t.Fatal("OBSERVER_POSITIVE_READ_FAILED")
	}
	after := snapshotPersistent(t, p.root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OBSERVER_POSITIVE_MUTATED_PERSISTENT_FILES")
	}
	if !allProjectionTrue(report) {
		t.Fatal("OBSERVER_POSITIVE_NOT_ALL_TRUE")
	}
	assertLimitedReport(t, report, p)

	beforeCLI := snapshotPersistent(t, p.root)
	cliRaw := captureRun(t, []string{"-fixture", fixturePath, "-verify-local", p.workspace})
	afterCLI := snapshotPersistent(t, p.root)
	if !reflect.DeepEqual(beforeCLI, afterCLI) {
		t.Fatal("OBSERVER_CLI_MUTATED_PERSISTENT_FILES")
	}
	var cliReport localProjection
	if json.Unmarshal(cliRaw, &cliReport) != nil || !allProjectionTrue(cliReport) {
		t.Fatal("OBSERVER_CLI_NOT_ALL_TRUE")
	}
	assertLimitedBytes(t, cliRaw, p)
}

func TestLocalVaultFileReadObserverCorruptCompanion(t *testing.T) {
	p := newPublishedLocalFixture(t)
	if err := os.WriteFile(p.companion, []byte("{}\n"), 0600); err != nil {
		t.Fatal("OBSERVER_CORRUPT_COMPANION_SETUP_FAILED")
	}
	before := snapshotPersistent(t, p.root)
	report, err := verifyLocalWorkspace(p.fixture, p.workspace)
	if err != nil {
		t.Fatal("OBSERVER_CORRUPT_COMPANION_READ_FAILED")
	}
	after := snapshotPersistent(t, p.root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OBSERVER_CORRUPT_COMPANION_MUTATED_PERSISTENT_FILES")
	}
	if report.ManifestCount != 1 || report.CompanionPresent || report.ManifestDigest {
		t.Fatal("OBSERVER_CORRUPT_COMPANION_ACCEPTED")
	}
	assertNotAllTrue(t, report)
}

func TestLocalVaultFileReadObserverMissingObject(t *testing.T) {
	p := newPublishedLocalFixture(t)
	dataDir := filepath.Join(p.backendRoot, "vaultfile-backend", "v1", "data")
	objects, err := os.ReadDir(dataDir)
	if err != nil || len(objects) != 1 {
		t.Fatal("OBSERVER_MISSING_OBJECT_SETUP_FAILED")
	}
	if err := os.Remove(filepath.Join(dataDir, objects[0].Name())); err != nil {
		t.Fatal("OBSERVER_MISSING_OBJECT_REMOVE_FAILED")
	}
	before := snapshotPersistent(t, p.root)
	report, err := verifyLocalWorkspace(p.fixture, p.workspace)
	if err != nil {
		t.Fatal("OBSERVER_MISSING_OBJECT_READ_FAILED")
	}
	after := snapshotPersistent(t, p.root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OBSERVER_MISSING_OBJECT_MUTATED_PERSISTENT_FILES")
	}
	if report.BackendHashMatches {
		t.Fatal("OBSERVER_MISSING_OBJECT_ACCEPTED")
	}
	assertNotAllTrue(t, report)
}

func TestLocalVaultFileReadObserverUnknownProfileEntry(t *testing.T) {
	p := newPublishedLocalFixture(t)
	extra := filepath.Join(p.profileDir, "extra.txt")
	if err := os.WriteFile(extra, []byte(p.fixture.Secret), 0600); err != nil {
		t.Fatal("OBSERVER_UNKNOWN_PROFILE_SETUP_FAILED")
	}
	if err := os.Chmod(extra, 0600); err != nil {
		t.Fatal("OBSERVER_UNKNOWN_PROFILE_MODE_FAILED")
	}
	before := snapshotPersistent(t, p.root)
	report, err := verifyLocalWorkspace(p.fixture, p.workspace)
	if err == nil {
		t.Fatal("OBSERVER_UNKNOWN_PROFILE_ENTRY_ACCEPTED")
	}
	if allProjectionTrue(report) {
		t.Fatal("OBSERVER_UNKNOWN_PROFILE_ALL_TRUE")
	}
	after := snapshotPersistent(t, p.root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OBSERVER_UNKNOWN_PROFILE_MUTATED_PERSISTENT_FILES")
	}
}

func TestLocalVaultFileReadObserverBackendTmpEntry(t *testing.T) {
	p := newPublishedLocalFixture(t)
	extra := filepath.Join(p.backendRoot, "vaultfile-backend", "v1", "tmp", "x")
	if err := os.WriteFile(extra, []byte(p.fixture.Secret), 0644); err != nil {
		t.Fatal("OBSERVER_BACKEND_TMP_SETUP_FAILED")
	}
	if err := os.Chmod(extra, 0644); err != nil {
		t.Fatal("OBSERVER_BACKEND_TMP_MODE_FAILED")
	}
	before := snapshotPersistent(t, p.root)
	report, err := verifyLocalWorkspace(p.fixture, p.workspace)
	if err == nil {
		t.Fatal("OBSERVER_BACKEND_TMP_ENTRY_ACCEPTED")
	}
	if allProjectionTrue(report) {
		t.Fatal("OBSERVER_BACKEND_TMP_ALL_TRUE")
	}
	after := snapshotPersistent(t, p.root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OBSERVER_BACKEND_TMP_MUTATED_PERSISTENT_FILES")
	}
}

func TestLocalVaultFileReadObserverForeignBinding(t *testing.T) {
	p := newPublishedLocalFixture(t)
	foreign := filepath.Join(p.root, "foreign.ll")
	if err := os.WriteFile(foreign, []byte("foreign personal file"), 0600); err != nil {
		t.Fatal("OBSERVER_FOREIGN_BINDING_SETUP_FAILED")
	}
	manifest, exists, err := vaultfileclient.ReadManifest(p.config)
	if err != nil || !exists {
		t.Fatal("OBSERVER_FOREIGN_BINDING_MANIFEST_FAILED")
	}
	manifest.PersonalFile = foreign
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal("OBSERVER_FOREIGN_BINDING_ENCODE_FAILED")
	}
	if err := os.WriteFile(p.config, raw, 0600); err != nil {
		t.Fatal("OBSERVER_FOREIGN_BINDING_WRITE_FAILED")
	}
	before := snapshotPersistent(t, p.root)
	report, err := verifyLocalWorkspace(p.fixture, p.workspace)
	if err != nil {
		t.Fatal("OBSERVER_FOREIGN_BINDING_READ_FAILED")
	}
	after := snapshotPersistent(t, p.root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OBSERVER_FOREIGN_BINDING_MUTATED_PERSISTENT_FILES")
	}
	if report.ManifestPersonal || report.CompanionPresent || report.ManifestDigest {
		t.Fatal("OBSERVER_FOREIGN_BINDING_ACCEPTED")
	}
	assertNotAllTrue(t, report)
}

func TestLocalVaultFileReadObserverOperationExclusion(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		{"-fixture", filepath.Join(dir, "fixture.json"), "-verify-local", filepath.Join(dir, "workspace"), "-private-pipe"},
		{"-out", filepath.Join(dir, "out"), "-verify-local", filepath.Join(dir, "workspace")},
	}
	for _, args := range cases {
		if err := run(args); err == nil {
			t.Fatal("OBSERVER_OPERATION_CONFLICT_ACCEPTED")
		}
	}
}
