//go:build darwin || linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

const fixtureCompleteFailurePrefix = "OBSERVER_FIXTURE_COMPLETE_FAILED"

type fixtureFailureClass string

const (
	fixtureFailureVerifyRejected fixtureFailureClass = "VERIFY_REJECTED"
	fixtureFailureLocalReview    fixtureFailureClass = "LOCAL_REVIEW"
	fixtureFailureUnknownReview  fixtureFailureClass = "UNKNOWN_REVIEW"
	fixtureFailureCancelled      fixtureFailureClass = "CANCELLED"
	fixtureFailureUnsupported    fixtureFailureClass = "UNSUPPORTED"
	fixtureFailureBackend        fixtureFailureClass = "BACKEND"
	fixtureFailureOther          fixtureFailureClass = "OTHER"
)

// classifyFixtureSetupFailure is test-only and reports only a fixed enum. The
// production Complete path already folds lower-level causes through
// mapCreateGenesisError, so this classification cannot recover the original
// cause. It deliberately never inspects or formats the error text.
func classifyFixtureSetupFailure(err error) fixtureFailureClass {
	switch {
	case errors.Is(err, vaultfileclient.ErrCreateVerification):
		return fixtureFailureVerifyRejected
	case errors.Is(err, vaultfileclient.ErrLocalReview):
		return fixtureFailureLocalReview
	case errors.Is(err, vaultfileclient.ErrCreateUnknown):
		return fixtureFailureUnknownReview
	case errors.Is(err, vaultfileclient.ErrCreateCancelled):
		return fixtureFailureCancelled
	case errors.Is(err, vaultfileclient.ErrCreateUnsupported):
		return fixtureFailureUnsupported
	case errors.Is(err, vaultfileclient.ErrBackend):
		return fixtureFailureBackend
	default:
		return fixtureFailureOther
	}
}

func fixtureCompleteFailureMessage(err error) string {
	return fixtureCompleteFailurePrefix + ": " + string(classifyFixtureSetupFailure(err))
}

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
	if _, _, err := prepareLocalWorkspaceDirs(workspace, f.Path); err != nil {
		t.Fatal("FIXTURE_WORKSPACE_FAILED")
	}
	return createPublishedVault(t, f, root, workspace, localBackendRoot(workspace))
}

// createPublishedVault runs the real product creation flow for one new selector
// in an existing fixture/workspace/backend. It never copies another vault's
// ciphertext or fabricates a manifest/companion pair.
func createPublishedVault(t *testing.T, f fixture, root, workspace, backendRoot string) *publishedLocalFixture {
	t.Helper()
	created, _, err := createPublishedLocalVault(f, workspace, backendRoot)
	if err != nil {
		t.Fatal(fixtureCompleteFailureMessage(err))
	}
	p := &publishedLocalFixture{
		fixture: f, root: root, workspace: workspace, profileDir: created.profileDir,
		backendRoot: created.backendRoot, config: created.config, companion: created.companion,
		journal: created.journal, archive: created.archive, kit: created.kit, personalPath: f.Path,
	}
	t.Cleanup(func() { clear(p.kit) })
	return p
}

func newPublishedLocalPair(t *testing.T) (*publishedLocalFixture, *publishedLocalFixture) {
	t.Helper()
	first := newPublishedLocalFixture(t)
	second := createPublishedVault(t, first.fixture, first.root, first.workspace, first.backendRoot)
	return first, second
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

func allPairProjectionTrue(report localProjection) bool {
	return localPairProjectionComplete(report)
}

func assertPairLimitedReport(t *testing.T, report localProjection, fixtures ...*publishedLocalFixture) {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(report); err != nil {
		t.Fatal("OBSERVER_PAIR_REPORT_ENCODE_FAILED")
	}
	assertPairLimitedBytes(t, buf.Bytes(), fixtures...)
}

func assertPairLimitedBytes(t *testing.T, out []byte, fixtures ...*publishedLocalFixture) {
	t.Helper()
	if len(out) > 4096 {
		t.Fatal("OBSERVER_PAIR_REPORT_NOT_BOUNDED")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(out, &fields) != nil || len(fields) != 10 {
		t.Fatal("OBSERVER_PAIR_REPORT_KEYS_INVALID")
	}
	for _, key := range []string{"manifest_count", "manifest_personal", "manifest_backend", "companion_present",
		"manifest_digest", "journal_present", "archive_present", "private_modes", "backend_hash_matches", "factors_absent"} {
		raw, ok := fields[key]
		if !ok {
			t.Fatal("OBSERVER_PAIR_REPORT_KEY_MISSING")
		}
		if key == "manifest_count" {
			var count int
			if json.Unmarshal(raw, &count) != nil || count != 2 {
				t.Fatal("OBSERVER_PAIR_REPORT_COUNT_INVALID")
			}
			continue
		}
		var value bool
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("OBSERVER_PAIR_REPORT_BOOL_INVALID")
		}
	}
	for _, p := range fixtures {
		for _, secret := range [][]byte{[]byte(p.fixture.Password), []byte(p.fixture.Secret), []byte(p.fixture.OTPSeed),
			[]byte(p.fixture.ProviderCanary), p.kit, []byte(p.personalPath), []byte(p.config),
			[]byte(p.companion), []byte(p.journal), []byte(p.archive), []byte(strings.TrimSuffix(filepath.Base(p.config), ".json"))} {
			if len(secret) > 0 && bytes.Contains(out, secret) {
				t.Fatal("OBSERVER_PAIR_REPORT_LEAKED_LOCAL_VALUE")
			}
		}
		manifest, exists, err := vaultfileclient.ReadManifest(p.config)
		if err != nil || !exists {
			t.Fatal("OBSERVER_PAIR_REPORT_MANIFEST_FAILED")
		}
		for _, secret := range [][]byte{[]byte(manifest.VaultID), []byte(manifest.Name)} {
			if len(secret) > 0 && bytes.Contains(out, secret) {
				t.Fatal("OBSERVER_PAIR_REPORT_LEAKED_IDENTITY")
			}
		}
	}
}

func TestLocalVaultPairReadObserverPositive(t *testing.T) {
	first, second := newPublishedLocalPair(t)
	fixturePath := filepath.Join(filepath.Dir(first.personalPath), "fixture.json")

	before := snapshotPersistent(t, first.root)
	report, err := verifyLocalPairWorkspace(first.fixture, first.workspace)
	if err != nil {
		t.Fatal("OBSERVER_PAIR_POSITIVE_READ_FAILED")
	}
	after := snapshotPersistent(t, first.root)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OBSERVER_PAIR_POSITIVE_MUTATED_PERSISTENT_FILES")
	}
	if !allPairProjectionTrue(report) {
		t.Fatal("OBSERVER_PAIR_POSITIVE_NOT_ALL_TRUE")
	}
	assertPairLimitedReport(t, report, first, second)

	beforeCLI := snapshotPersistent(t, first.root)
	cliRaw := captureRun(t, []string{"-fixture", fixturePath, "-verify-local-pair", first.workspace})
	afterCLI := snapshotPersistent(t, first.root)
	if !reflect.DeepEqual(beforeCLI, afterCLI) {
		t.Fatal("OBSERVER_PAIR_CLI_MUTATED_PERSISTENT_FILES")
	}
	var cliReport localProjection
	if json.Unmarshal(cliRaw, &cliReport) != nil || !allPairProjectionTrue(cliReport) {
		t.Fatal("OBSERVER_PAIR_CLI_NOT_ALL_TRUE")
	}
	assertPairLimitedBytes(t, cliRaw, first, second)
}

func TestPrepareInitialPairProducer(t *testing.T) {
	root := t.TempDir()
	fixtureDir := filepath.Join(root, "vault")
	settingsDir := filepath.Join(root, "settings")
	if err := os.Mkdir(settingsDir, 0700); err != nil {
		t.Fatal("PAIR_FIXTURE_SETTINGS_FAILED")
	}
	workspace := filepath.Join(settingsDir, "vaultfile-workspace")
	f, err := createInitialPairFixture(fixtureDir, workspace)
	if err != nil {
		stage := "untyped"
		substage := "none"
		class := "OTHER"
		target := 0
		evidence := pairObserverEvidence{}
		var pairErr *initialPairError
		if errors.As(err, &pairErr) {
			stage = string(pairErr.stage)
			substage = string(pairErr.substage)
			class = string(pairErr.class)
			target = pairErr.target
			evidence = pairErr.observer
		}
		t.Fatalf("PAIR_FIXTURE_PREPARE_FAILED stage=%s target=%d substage=%s class=%s manifest_count=%d personal=%t backend=%t companion=%t digest=%t journal=%t archive=%t modes=%t hash=%t factors=%t",
			stage, target, substage, class, evidence.ManifestCount, evidence.ManifestPersonal,
			evidence.ManifestBackend, evidence.CompanionPresent, evidence.ManifestDigest,
			evidence.JournalPresent, evidence.ArchivePresent, evidence.PrivateModes,
			evidence.BackendHashMatches, evidence.FactorsAbsent)
	}
	defer clearFixture(&f)
	report, err := verifyLocalPairWorkspace(f, workspace)
	if err != nil || !localPairProjectionComplete(report) {
		t.Fatalf("PAIR_FIXTURE_OBSERVER_FAILED error=%t manifest_count=%d personal=%t backend=%t companion=%t digest=%t journal=%t archive=%t modes=%t hash=%t factors=%t",
			err != nil, report.ManifestCount, report.ManifestPersonal, report.ManifestBackend,
			report.CompanionPresent, report.ManifestDigest, report.JournalPresent, report.ArchivePresent,
			report.PrivateModes, report.BackendHashMatches, report.FactorsAbsent)
	}
	fixtureInfo, err := os.Stat(filepath.Join(fixtureDir, "fixture.json"))
	if err != nil || !fixtureInfo.Mode().IsRegular() || fixtureInfo.Mode().Perm() != 0600 ||
		fixtureInfo.Size() <= 64<<10 || len(f.ProviderValue) < 48<<10 {
		t.Fatal("PAIR_FIXTURE_METADATA_RETENTION_FAILED")
	}
	singleOnPair, err := verifyLocalWorkspace(f, workspace)
	if err != nil || singleOnPair.ManifestCount != 2 || allProjectionTrue(singleOnPair) {
		t.Fatal("PAIR_FIXTURE_OBSERVER_STRICT_COUNT_FAILED")
	}

	profileDir := localProfileDir(workspace, f.Path)
	entries, err := readBoundedDir(profileDir, 128)
	if err != nil {
		t.Fatal("PAIR_FIXTURE_PROFILE_FAILED")
	}
	ids := map[string]bool{}
	journals := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") ||
			strings.HasSuffix(entry.Name(), ".json.baseline") {
			continue
		}
		manifest, exists, err := vaultfileclient.ReadManifest(filepath.Join(profileDir, entry.Name()))
		if err != nil || !exists {
			t.Fatal("PAIR_FIXTURE_MANIFEST_FAILED")
		}
		if manifest.PersonalFile != f.Path || manifest.BackendRoot != localBackendRoot(workspace) {
			t.Fatal("PAIR_FIXTURE_BINDING_FAILED")
		}
		ids[manifest.VaultID] = true
		journals[manifest.Journal] = true
	}
	if len(ids) != 2 || len(journals) != 2 {
		t.Fatal("PAIR_FIXTURE_IDENTITIES_FAILED")
	}
}

func TestLocalVaultObserverModesRequireExactCount(t *testing.T) {
	single := newPublishedLocalFixture(t)
	pairFirst, _ := newPublishedLocalPair(t)

	pairOnSingle, err := verifyLocalPairWorkspace(single.fixture, single.workspace)
	if err != nil {
		t.Fatal("OBSERVER_PAIR_ON_SINGLE_ERROR")
	}
	if pairOnSingle.ManifestCount != 1 || allPairProjectionTrue(pairOnSingle) {
		t.Fatal("OBSERVER_PAIR_ON_SINGLE_ACCEPTED")
	}
	singleOnPair, err := verifyLocalWorkspace(pairFirst.fixture, pairFirst.workspace)
	if err != nil {
		t.Fatal("OBSERVER_SINGLE_ON_PAIR_ERROR")
	}
	if singleOnPair.ManifestCount != 2 || allProjectionTrue(singleOnPair) {
		t.Fatal("OBSERVER_SINGLE_ON_PAIR_ACCEPTED")
	}
}

// TestLocalVaultPairReadObserverRejectsMutations reuses one real pair and
// restores each static change before the next case. No case may reach the
// all-true pair projection, and structural cases must return an error.
func TestLocalVaultPairReadObserverRejectsMutations(t *testing.T) {
	first, second := newPublishedLocalPair(t)
	readRaw := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("OBSERVER_PAIR_MUTATION_READ_FAILED")
		}
		return raw
	}
	restore := func(t *testing.T, path string, raw []byte) func() {
		t.Helper()
		return func() {
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal("OBSERVER_PAIR_MUTATION_RESTORE_FAILED")
			}
		}
	}
	firstManifest, firstExists, err := vaultfileclient.ReadManifest(first.config)
	if err != nil || !firstExists {
		t.Fatal("OBSERVER_PAIR_MUTATION_FIRST_MANIFEST_FAILED")
	}
	secondManifest, secondExists, err := vaultfileclient.ReadManifest(second.config)
	if err != nil || !secondExists {
		t.Fatal("OBSERVER_PAIR_MUTATION_SECOND_MANIFEST_FAILED")
	}
	namespaceDir := filepath.Join(first.backendRoot, "vaultfile-backend")
	versionDir := filepath.Join(namespaceDir, "v1")
	dataDir := filepath.Join(versionDir, "data")

	cases := []struct {
		name    string
		wantErr bool
		mutate  func(t *testing.T) func()
	}{
		{
			name: "third manifest", wantErr: false,
			mutate: func(t *testing.T) func() {
				base := "observer-third"
				third := vaultfileclient.Manifest{
					Version: 1, Kind: vaultfileclient.CreateKind, VaultID: strings.Repeat("a", 32),
					PersonalFile: first.personalPath, BackendRoot: first.backendRoot, Name: base + ".llv",
					Journal: filepath.Join(first.profileDir, base+".journal"),
					Archive: filepath.Join(first.profileDir, base+".llb"),
				}
				raw, err := json.Marshal(third)
				if err != nil {
					t.Fatal("OBSERVER_PAIR_THIRD_MANIFEST_ENCODE_FAILED")
				}
				path := filepath.Join(first.profileDir, base+".json")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_THIRD_MANIFEST_WRITE_FAILED")
				}
				return func() { os.Remove(path) }
			},
		},
		{
			name: "unknown profile entry", wantErr: true,
			mutate: func(t *testing.T) func() {
				path := filepath.Join(first.profileDir, "unknown.txt")
				if err := os.WriteFile(path, []byte("unknown"), 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_UNKNOWN_PROFILE_WRITE_FAILED")
				}
				return func() { os.Remove(path) }
			},
		},
		{
			name: "unknown backend root entry", wantErr: true,
			mutate: func(t *testing.T) func() {
				path := filepath.Join(first.backendRoot, "unknown")
				if err := os.WriteFile(path, []byte("unknown"), 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_BACKEND_ROOT_WRITE_FAILED")
				}
				return func() { os.Remove(path) }
			},
		},
		{
			name: "wide namespace unknown entry", wantErr: true,
			mutate: func(t *testing.T) func() {
				path := filepath.Join(namespaceDir, "unknown")
				if err := os.WriteFile(path, []byte("unknown"), 0644); err != nil {
					t.Fatal("OBSERVER_PAIR_NAMESPACE_WRITE_FAILED")
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal("OBSERVER_PAIR_NAMESPACE_MODE_FAILED")
				}
				return func() { os.Remove(path) }
			},
		},
		{
			name: "unknown version entry", wantErr: true,
			mutate: func(t *testing.T) func() {
				lock := filepath.Join(versionDir, localBackendLockName)
				original := readRaw(t, lock)
				if err := os.Remove(lock); err != nil {
					t.Fatal("OBSERVER_PAIR_VERSION_LOCK_REMOVE_FAILED")
				}
				path := filepath.Join(versionDir, "unknown")
				if err := os.WriteFile(path, []byte("unknown"), 0600); err != nil {
					os.WriteFile(lock, original, 0600)
					t.Fatal("OBSERVER_PAIR_VERSION_UNKNOWN_WRITE_FAILED")
				}
				return func() {
					os.Remove(path)
					if err := os.WriteFile(lock, original, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_VERSION_LOCK_RESTORE_FAILED")
					}
				}
			},
		},
		{
			name: "symlink backend lockfile", wantErr: true,
			mutate: func(t *testing.T) func() {
				lock := filepath.Join(versionDir, localBackendLockName)
				original := readRaw(t, lock)
				if err := os.Remove(lock); err != nil {
					t.Fatal("OBSERVER_PAIR_LOCK_REMOVE_FAILED")
				}
				if err := os.Symlink(first.journal, lock); err != nil {
					os.WriteFile(lock, original, 0600)
					t.Fatal("OBSERVER_PAIR_LOCK_SYMLINK_FAILED")
				}
				return func() {
					os.Remove(lock)
					if err := os.WriteFile(lock, original, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_LOCK_SYMLINK_RESTORE_FAILED")
					}
				}
			},
		},
		{
			name: "wide backend lockfile", wantErr: false,
			mutate: func(t *testing.T) func() {
				path := filepath.Join(versionDir, localBackendLockName)
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal("OBSERVER_PAIR_LOCKFILE_MODE_FAILED")
				}
				return func() {
					if err := os.Chmod(path, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_LOCKFILE_RESTORE_FAILED")
					}
				}
			},
		},
		{
			name: "extra backend object", wantErr: true,
			mutate: func(t *testing.T) func() {
				path := filepath.Join(dataDir, "extra-object")
				if err := os.WriteFile(path, []byte("extra"), 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_EXTRA_BACKEND_WRITE_FAILED")
				}
				return func() { os.Remove(path) }
			},
		},
		{
			name: "occupied backend tmp", wantErr: true,
			mutate: func(t *testing.T) func() {
				path := filepath.Join(first.backendRoot, "vaultfile-backend", "v1", "tmp", "occupied")
				if err := os.WriteFile(path, []byte("tmp"), 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_TMP_WRITE_FAILED")
				}
				return func() { os.Remove(path) }
			},
		},
		{
			name: "duplicate vault id", wantErr: true,
			mutate: func(t *testing.T) func() {
				original := readRaw(t, first.config)
				duplicate := firstManifest
				duplicate.VaultID = secondManifest.VaultID
				raw, err := json.Marshal(duplicate)
				if err != nil {
					t.Fatal("OBSERVER_PAIR_DUPLICATE_ID_ENCODE_FAILED")
				}
				if err := os.WriteFile(first.config, raw, 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_DUPLICATE_ID_WRITE_FAILED")
				}
				return restore(t, first.config, original)
			},
		},
		{
			name: "swapped companions", wantErr: false,
			mutate: func(t *testing.T) func() {
				firstRaw, secondRaw := readRaw(t, first.companion), readRaw(t, second.companion)
				if err := os.WriteFile(first.companion, secondRaw, 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_SWAP_COMPANION_WRITE_FAILED")
				}
				if err := os.WriteFile(second.companion, firstRaw, 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_SWAP_COMPANION_WRITE_FAILED")
				}
				return func() {
					if err := os.WriteFile(first.companion, firstRaw, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_SWAP_COMPANION_RESTORE_FAILED")
					}
					if err := os.WriteFile(second.companion, secondRaw, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_SWAP_COMPANION_RESTORE_FAILED")
					}
				}
			},
		},
		{
			name: "foreign personal binding", wantErr: false,
			mutate: func(t *testing.T) func() {
				foreign := filepath.Join(first.root, "foreign.ll")
				if err := os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_FOREIGN_WRITE_FAILED")
				}
				original := readRaw(t, first.config)
				changed := firstManifest
				changed.PersonalFile = foreign
				raw, err := json.Marshal(changed)
				if err != nil {
					t.Fatal("OBSERVER_PAIR_FOREIGN_ENCODE_FAILED")
				}
				if err := os.WriteFile(first.config, raw, 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_FOREIGN_BINDING_WRITE_FAILED")
				}
				return func() {
					restore(t, first.config, original)()
					os.Remove(foreign)
				}
			},
		},
		{
			name: "swapped backend objects", wantErr: false,
			mutate: func(t *testing.T) func() {
				firstName := sha256.Sum256([]byte(firstManifest.Name))
				secondName := sha256.Sum256([]byte(secondManifest.Name))
				firstObject := filepath.Join(dataDir, hex.EncodeToString(firstName[:]))
				secondObject := filepath.Join(dataDir, hex.EncodeToString(secondName[:]))
				firstRaw, secondRaw := readRaw(t, firstObject), readRaw(t, secondObject)
				if err := os.WriteFile(firstObject, secondRaw, 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_SWAP_BACKEND_WRITE_FAILED")
				}
				if err := os.WriteFile(secondObject, firstRaw, 0600); err != nil {
					t.Fatal("OBSERVER_PAIR_SWAP_BACKEND_WRITE_FAILED")
				}
				return func() {
					if err := os.WriteFile(firstObject, firstRaw, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_SWAP_BACKEND_RESTORE_FAILED")
					}
					if err := os.WriteFile(secondObject, secondRaw, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_SWAP_BACKEND_RESTORE_FAILED")
					}
				}
			},
		},
		{
			name: "symlink profile entry", wantErr: true,
			mutate: func(t *testing.T) func() {
				original := readRaw(t, second.journal)
				if err := os.Remove(second.journal); err != nil {
					t.Fatal("OBSERVER_PAIR_SYMLINK_REMOVE_FAILED")
				}
				if err := os.Symlink(first.journal, second.journal); err != nil {
					t.Fatal("OBSERVER_PAIR_SYMLINK_CREATE_FAILED")
				}
				return func() {
					os.Remove(second.journal)
					if err := os.WriteFile(second.journal, original, 0600); err != nil {
						t.Fatal("OBSERVER_PAIR_SYMLINK_RESTORE_FAILED")
					}
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cleanup := tc.mutate(t)
			t.Cleanup(cleanup)
			before := snapshotPersistent(t, first.root)
			report, err := verifyLocalPairWorkspace(first.fixture, first.workspace)
			after := snapshotPersistent(t, first.root)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("OBSERVER_PAIR_MUTATION_MUTATED_PERSISTENT_FILES")
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("OBSERVER_PAIR_MUTATION_ERROR_EXPECTED")
				}
				return
			}
			if err != nil {
				t.Fatal("OBSERVER_PAIR_MUTATION_UNEXPECTED_ERROR")
			}
			if allPairProjectionTrue(report) {
				t.Fatal("OBSERVER_PAIR_MUTATION_ACCEPTED")
			}
			switch tc.name {
			case "wide backend lockfile":
				if report.PrivateModes {
					t.Fatal("OBSERVER_PAIR_WIDE_LOCKFILE_ACCEPTED")
				}
			case "swapped companions":
				if report.CompanionPresent || report.ManifestDigest {
					t.Fatal("OBSERVER_PAIR_SWAP_COMPANION_ACCEPTED")
				}
			case "foreign personal binding":
				if report.ManifestPersonal {
					t.Fatal("OBSERVER_PAIR_FOREIGN_PERSONAL_ACCEPTED")
				}
			case "swapped backend objects":
				if report.BackendHashMatches {
					t.Fatal("OBSERVER_PAIR_SWAP_BACKEND_ACCEPTED")
				}
			}
		})
	}
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

func captureRunStreams(t *testing.T, args []string) ([]byte, []byte, error) {
	t.Helper()
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal("OBSERVER_HELP_STDOUT_PIPE_FAILED")
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		stdoutReader.Close()
		stdoutWriter.Close()
		t.Fatal("OBSERVER_HELP_STDERR_PIPE_FAILED")
	}
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	runErr := run(args)
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdoutWriter.Close()
	stderrWriter.Close()
	stdout, stdoutErr := io.ReadAll(io.LimitReader(stdoutReader, 8192))
	stdoutReader.Close()
	stderr, stderrErr := io.ReadAll(io.LimitReader(stderrReader, 8192))
	stderrReader.Close()
	if stdoutErr != nil || stderrErr != nil {
		t.Fatal("OBSERVER_HELP_STREAM_READ_FAILED")
	}
	return stdout, stderr, runErr
}

func TestRunHelpUsesFixedUsageAndSucceeds(t *testing.T) {
	dir := t.TempDir()
	fixtureArg := filepath.Join(dir, "missing-fixture.json")
	workspaceArg := filepath.Join(dir, "missing-workspace")
	cases := [][]string{
		{"-fixture", fixtureArg, "-h"},
		{"-fixture", fixtureArg, "-help"},
		{"-verify-local", workspaceArg, "-h"},
		{"-verify-local", workspaceArg, "-help"},
		{"-verify-local-pair", workspaceArg, "-h"},
		{"-verify-local-pair", workspaceArg, "-help"},
	}
	for _, args := range cases {
		stdout, stderr, runErr := captureRunStreams(t, args)
		if runErr != nil {
			t.Fatal("OBSERVER_HELP_NOT_SUCCESS")
		}
		if len(stderr) != 0 {
			t.Fatal("OBSERVER_HELP_STDERR_NOT_EMPTY")
		}
		if string(stdout) != usageText {
			t.Fatal("OBSERVER_HELP_USAGE_NOT_FIXED")
		}
		if bytes.Contains(stdout, []byte(fixtureArg)) || bytes.Contains(stdout, []byte(workspaceArg)) {
			t.Fatal("OBSERVER_HELP_LEAKED_INPUT")
		}
		for _, option := range []string{"-out", "-fixture", "-private-pipe", "-stale", "-hold-readonly", "-verify-local", "-verify-local-pair"} {
			if !bytes.Contains(stdout, []byte(option)) {
				t.Fatal("OBSERVER_HELP_MISSING_OPTION")
			}
		}
		for _, option := range []string{"-prepare-initial-pair", "-prepare-workspace"} {
			if !bytes.Contains(stdout, []byte(option)) {
				t.Fatal("HELP_OPTIONS_MISSING")
			}
		}

		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("OBSERVER_HELP_PERFORMED_IO")
		}
	}
}

func TestRunFlagParseErrorsUseFixedFailure(t *testing.T) {
	const synthetic = "synthetic-invalid-bool-value"
	cases := [][]string{
		{"-fixture", "unused", "-private-pipe=" + synthetic},
		{"-fixture", "unused", "-unknown-" + synthetic},
		{"-fixture", "unused", "-verify-local-pair"},
		{"-fixture", "unused", "-verify-local-pair=" + synthetic},
	}
	for _, args := range cases {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal("OBSERVER_FLAG_STDERR_PIPE_FAILED")
		}
		old := os.Stderr
		os.Stderr = writer
		runErr := run(args)
		if runErr != nil {
			fmt.Fprintln(os.Stderr, failureMessage)
		}
		os.Stderr = old
		writer.Close()
		raw, readErr := io.ReadAll(io.LimitReader(reader, 4096))
		reader.Close()
		if readErr != nil {
			t.Fatal("OBSERVER_FLAG_STDERR_READ_FAILED")
		}
		if runErr == nil {
			t.Fatal("OBSERVER_FLAG_PARSE_ERROR_ACCEPTED")
		}
		if bytes.Contains(raw, []byte(synthetic)) {
			t.Fatal("OBSERVER_FLAG_PARSE_VALUE_LEAKED")
		}
		if string(raw) != failureMessage+"\n" {
			t.Fatal("OBSERVER_FLAG_FAILURE_LINE_INVALID")
		}
	}
}

func TestFixtureCompleteFailureClassificationIsPrivate(t *testing.T) {
	const canary = "private-fixture-setup-canary"
	cases := []struct {
		name string
		err  error
		want fixtureFailureClass
	}{
		{"known", fmt.Errorf("%s: %w", canary, vaultfileclient.ErrCreateVerification), fixtureFailureVerifyRejected},
		{"unknown", fmt.Errorf("%s: %w", canary, errors.New(canary)), fixtureFailureOther},
	}
	for _, tc := range cases {
		line := fixtureCompleteFailureMessage(tc.err)
		if line != fixtureCompleteFailurePrefix+": "+string(tc.want) {
			t.Fatalf("OBSERVER_SETUP_CLASSIFICATION_INVALID_%s", tc.name)
		}
		if strings.Contains(line, canary) {
			t.Fatalf("OBSERVER_SETUP_CLASSIFICATION_LEAKED_TEXT_%s", tc.name)
		}
		if len(line) > 128 {
			t.Fatalf("OBSERVER_SETUP_CLASSIFICATION_NOT_BOUNDED_%s", tc.name)
		}
	}
}

func TestLocalVaultFileReadObserverOperationExclusion(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		{"-fixture", filepath.Join(dir, "fixture.json"), "-verify-local", filepath.Join(dir, "workspace"), "-private-pipe"},
		{"-out", filepath.Join(dir, "out"), "-verify-local", filepath.Join(dir, "workspace")},
		{"-fixture", filepath.Join(dir, "fixture.json"), "-verify-local", filepath.Join(dir, "workspace"), "-verify-local-pair", filepath.Join(dir, "workspace")},
		{"-out", filepath.Join(dir, "out"), "-verify-local-pair", filepath.Join(dir, "workspace")},
	}
	for _, args := range cases {
		if err := run(args); err == nil {
			t.Fatal("OBSERVER_OPERATION_CONFLICT_ACCEPTED")
		}
	}
}
