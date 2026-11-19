package mobilecore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	mobileOwnedLocalTitle = "Same owned local exact title"
	mobileOwnedLocalUserA = "owned-local-username-a-canary"
	mobileOwnedLocalPassA = "owned-local-password-a-canary"
	mobileOwnedLocalUserB = "owned-local-username-b-canary"
	mobileOwnedLocalPassB = "owned-local-password-b-canary"
)

type mobileOwnedLocalFixture struct {
	configA   string
	configB   string
	configC   string
	manifestA vaultfileclient.Manifest
	manifestB vaultfileclient.Manifest
	manifestC vaultfileclient.Manifest
	itemA     vaultfileclient.LocalGenesisFirstItem
	itemB     vaultfileclient.LocalGenesisFirstItem
	revisionA string
	revisionB string
	password  []byte
	key       []byte
	vault     *Vault
}

// newMobileOwnedLocalFixture provisions one real encrypted personal account
// with two independent local vault-file children (A and B), writes one real
// first successor into each through the production write path, and provisions
// a second real account with one further local child C for wrong-account
// refusal. No fake database or synthetic read path is used.
func newMobileOwnedLocalFixture(t *testing.T) *mobileOwnedLocalFixture {
	t.Helper()
	root := t.TempDir()
	password := []byte("mobile-owned-local-account-password")
	key := bytes.Repeat([]byte{0x6c}, 16)
	secretInput := []byte(personal.FormatSecret(key))
	t.Cleanup(func() {
		clear(password)
		clear(key)
		clear(secretInput)
	})

	accountPath := filepath.Join(root, "personal.ll")
	if err := personal.Create(accountPath, string(password), key); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_ACCOUNT_CREATE_FAILED")
	}
	private := filepath.Join(root, "private")
	journalDir := filepath.Join(root, "journal")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_PRIVATE_DIR_FAILED")
	}
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_JOURNAL_DIR_FAILED")
	}
	backendRoot := filepath.Join(root, "backend")
	configA := filepath.Join(private, "a.json")
	configB := filepath.Join(private, "b.json")
	manifestA := mobileOwnedCreateLocalVault(t, configA, accountPath, backendRoot,
		"owned-a", filepath.Join(journalDir, "a.journal"), filepath.Join(root, "a.llb"),
		password, secretInput, key)
	manifestB := mobileOwnedCreateLocalVault(t, configB, accountPath, backendRoot,
		"owned-b", filepath.Join(journalDir, "b.journal"), filepath.Join(root, "b.llb"),
		password, secretInput, key)

	secondRoot := filepath.Join(root, "second-account")
	if err := os.Mkdir(secondRoot, 0700); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SECOND_ROOT_FAILED")
	}
	secondAccount := filepath.Join(secondRoot, "personal.ll")
	if err := personal.Create(secondAccount, string(password), key); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SECOND_ACCOUNT_CREATE_FAILED")
	}
	secondPrivate := filepath.Join(secondRoot, "private")
	secondJournal := filepath.Join(secondRoot, "journal")
	if err := os.Mkdir(secondPrivate, 0700); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SECOND_PRIVATE_DIR_FAILED")
	}
	if err := os.Mkdir(secondJournal, 0700); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SECOND_JOURNAL_DIR_FAILED")
	}
	configC := filepath.Join(secondPrivate, "c.json")
	manifestC := mobileOwnedCreateLocalVault(t, configC, secondAccount,
		filepath.Join(secondRoot, "backend"), "owned-c",
		filepath.Join(secondJournal, "c.journal"), filepath.Join(secondRoot, "c.llb"),
		password, secretInput, key)

	parent, err := personal.UnlockSession(accountPath, password, key, time.Minute)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_PARENT_UNLOCK_FAILED")
	}
	t.Cleanup(parent.Lock)

	itemA := vaultfileclient.LocalGenesisFirstItem{
		ID: mobileOwnedLocalItemID(0x11), Title: mobileOwnedLocalTitle,
		Username: mobileOwnedLocalUserA, Password: mobileOwnedLocalPassA,
	}
	itemB := vaultfileclient.LocalGenesisFirstItem{
		ID: mobileOwnedLocalItemID(0x22), Title: mobileOwnedLocalTitle,
		Username: mobileOwnedLocalUserB, Password: mobileOwnedLocalPassB,
	}
	resultA, err := vaultfileclient.WriteLocalGenesisFirstItem(context.Background(), parent,
		configA, manifestA.BackendRoot, manifestA.VaultID, manifestA.Journal,
		bytes.Clone(password), bytes.Clone(key), itemA)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_WRITE_A_FAILED")
	}
	resultB, err := vaultfileclient.WriteLocalGenesisFirstItem(context.Background(), parent,
		configB, manifestB.BackendRoot, manifestB.VaultID, manifestB.Journal,
		bytes.Clone(password), bytes.Clone(key), itemB)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_WRITE_B_FAILED")
	}

	vault, err := Open(accountPath)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_OPEN_FAILED")
	}
	if err := vault.Unlock(bytes.Clone(password), bytes.Clone(key)); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_MOBILE_UNLOCK_FAILED")
	}
	t.Cleanup(vault.Close)

	return &mobileOwnedLocalFixture{
		configA: configA, configB: configB, configC: configC,
		manifestA: manifestA, manifestB: manifestB, manifestC: manifestC,
		itemA: itemA, itemB: itemB, revisionA: resultA.Revision,
		revisionB: resultB.Revision, password: password, key: key, vault: vault,
	}
}

func mobileOwnedCreateLocalVault(t *testing.T, config, personalFile, backendRoot, name, journal, archive string, password, secretInput, key []byte) vaultfileclient.Manifest {
	t.Helper()
	ctx := context.Background()
	proposal := vaultfileclient.Manifest{
		Version: 1, Kind: vaultfileclient.CreateKind, PersonalFile: personalFile,
		BackendRoot: backendRoot, Name: name, Journal: journal, Archive: archive,
	}
	create, err := vaultfileclient.OpenCreation(config, &proposal, password, secretInput)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_OPEN_FAILED")
	}
	backupRequired, err := create.Prepare(ctx)
	create.Close()
	if err != nil || !backupRequired {
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_PREPARE_FAILED")
	}
	backup, err := personal.PrepareBackup(personalFile, archive, string(password), key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_BACKUP_FAILED")
	}
	if err := backup.Publish(); err != nil {
		backup.Close()
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_BACKUP_PUBLISH_FAILED")
	}
	kit := []byte(backup.Material())
	backup.Close()
	defer clear(kit)

	create, err = vaultfileclient.OpenCreation(config, nil, password, secretInput)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_REOPEN_FAILED")
	}
	backupRequired, err = create.Prepare(ctx)
	if err != nil || backupRequired {
		create.Close()
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_READY_FAILED")
	}
	err = create.Complete(ctx, password, secretInput, kit)
	create.Close()
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_COMPLETE_FAILED")
	}
	manifest, exists, err := vaultfileclient.ReadManifest(config)
	if err != nil || !exists {
		t.Fatal("MOBILE_OWNED_LOCAL_CREATE_MANIFEST_FAILED")
	}
	return manifest
}

func mobileOwnedLocalItemID(fill byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{fill}, 16))
}

func mobileOwnedSearch(t *testing.T, v *Vault, workspaceRoot, config, vaultID, journal, title string, limit int, password, key []byte) (*OwnedLocalExactResult, error) {
	t.Helper()
	pw, sk := bytes.Clone(password), bytes.Clone(key)
	result, err := v.SearchOwnedLocalExact(workspaceRoot, config, vaultID, journal, title, limit, pw, sk)
	mobileOwnedAssertCleared(t, pw)
	mobileOwnedAssertCleared(t, sk)
	return result, err
}

func mobileOwnedAssertCleared(t *testing.T, value []byte) {
	t.Helper()
	for _, b := range value {
		if b != 0 {
			t.Fatal("MOBILE_OWNED_LOCAL_SEARCH_RETAINED_FACTORS")
		}
	}
}

func mobileOwnedAssertHit(t *testing.T, result *OwnedLocalExactResult, item vaultfileclient.LocalGenesisFirstItem, manifest vaultfileclient.Manifest, revision string) {
	t.Helper()
	if result == nil || result.Count() != 1 || result.Truncated ||
		result.VaultID != manifest.VaultID || result.BackendRevision != revision ||
		result.BackendRevision == "" {
		t.Fatal("MOBILE_OWNED_LOCAL_SEARCH_BINDING_FAILED")
	}
	hit, err := result.At(0)
	if err != nil || hit.ID != item.ID || hit.Title != item.Title {
		t.Fatal("MOBILE_OWNED_LOCAL_SEARCH_HIT_FAILED")
	}
	if _, err := result.At(1); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_LOCAL_SEARCH_UNBOUNDED_INDEX_ACCEPTED")
	}
}

func mobileOwnedReadBackend(t *testing.T, manifest vaultfileclient.Manifest) ([]byte, string) {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_OPEN_FAILED")
	}
	result, readErr := backend.Read(context.Background(), manifest.Name)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_READ_FAILED")
	}
	return result.Bytes, string(result.Revision)
}

func mobileOwnedRewriteBackend(t *testing.T, manifest vaultfileclient.Manifest, value []byte) string {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_OPEN_FAILED")
	}
	current, err := backend.Read(context.Background(), manifest.Name)
	if err != nil {
		_ = backend.Close()
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_READ_FAILED")
	}
	clear(current.Bytes)
	if err := backend.ReplaceIfVersion(context.Background(), manifest.Name, current.Revision, value); err != nil {
		_ = backend.Close()
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_REPLACE_FAILED")
	}
	updated, err := backend.Read(context.Background(), manifest.Name)
	closeErr := backend.Close()
	if err != nil || closeErr != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_REVISION_FAILED")
	}
	clear(updated.Bytes)
	return string(updated.Revision)
}

func mobileOwnedScopeFingerprint(t *testing.T, config string, manifest vaultfileclient.Manifest) [32]byte {
	t.Helper()
	configBytes, err := os.ReadFile(config)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SCOPE_CONFIG_READ_FAILED")
	}
	companionPath, err := vaultfileclient.CompanionPath(config)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SCOPE_COMPANION_PATH_FAILED")
	}
	companionBytes, err := os.ReadFile(companionPath)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SCOPE_COMPANION_READ_FAILED")
	}
	journalBytes, err := os.ReadFile(manifest.Journal)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SCOPE_JOURNAL_READ_FAILED")
	}
	backendBytes, revision := mobileOwnedReadBackend(t, manifest)
	defer clear(backendBytes)
	h := sha256.New()
	_, _ = h.Write(configBytes)
	_, _ = h.Write(companionBytes)
	_, _ = h.Write(journalBytes)
	_, _ = h.Write(backendBytes)
	_, _ = h.Write([]byte(revision))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestMobileOwnedLocalExactSearchReadOnlyAcrossTwoVaults(t *testing.T) {
	fx := newMobileOwnedLocalFixture(t)
	v := fx.vault
	if fx.itemA.Title != fx.itemB.Title || fx.itemA.ID == fx.itemB.ID ||
		fx.manifestA.VaultID == fx.manifestB.VaultID ||
		fx.manifestA.Journal == fx.manifestB.Journal ||
		fx.manifestA.Name == fx.manifestB.Name ||
		fx.configA == fx.configB {
		t.Fatal("MOBILE_OWNED_LOCAL_SCOPES_NOT_DISTINCT")
	}
	if fx.revisionA == "" || fx.revisionB == "" || fx.revisionA == fx.revisionB {
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_REVISIONS_NOT_DISTINCT")
	}
	backendA, revisionA := mobileOwnedReadBackend(t, fx.manifestA)
	defer clear(backendA)
	backendB, revisionB := mobileOwnedReadBackend(t, fx.manifestB)
	defer clear(backendB)
	if revisionA != fx.revisionA || revisionB != fx.revisionB {
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_REVISION_MISMATCH")
	}

	resultA, err := mobileOwnedSearch(t, v, fx.manifestA.BackendRoot, fx.configA,
		fx.manifestA.VaultID, fx.manifestA.Journal, mobileOwnedLocalTitle, 2, fx.password, fx.key)
	if err != nil {
		t.Fatalf("MOBILE_OWNED_LOCAL_SEARCH_A_FAILED: %v", err)
	}
	mobileOwnedAssertHit(t, resultA, fx.itemA, fx.manifestA, fx.revisionA)
	resultB, err := mobileOwnedSearch(t, v, fx.manifestB.BackendRoot, fx.configB,
		fx.manifestB.VaultID, fx.manifestB.Journal, mobileOwnedLocalTitle, 2, fx.password, fx.key)
	if err != nil {
		t.Fatalf("MOBILE_OWNED_LOCAL_SEARCH_B_FAILED: %v", err)
	}
	mobileOwnedAssertHit(t, resultB, fx.itemB, fx.manifestB, fx.revisionB)
	hitA, _ := resultA.At(0)
	hitB, _ := resultB.At(0)
	if hitA.ID == hitB.ID || resultA.VaultID == resultB.VaultID ||
		resultA.BackendRevision == resultB.BackendRevision {
		t.Fatal("MOBILE_OWNED_LOCAL_SEARCH_RESULTS_MERGED")
	}

	encoded, err := json.Marshal(resultA)
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_METADATA_JSON_FAILED")
	}
	for _, forbidden := range []string{
		fx.configA, fx.manifestA.Journal, fx.manifestA.BackendRoot,
		mobileOwnedLocalUserA, mobileOwnedLocalPassA,
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatal("MOBILE_OWNED_LOCAL_METADATA_EXPOSED_PRIVATE_VALUE")
		}
	}

	// Invalid receiver, path and title/limit arguments are refused and still
	// consume/clear both factor slices.
	var nilVault *Vault
	pw, sk := bytes.Clone(fx.password), bytes.Clone(fx.key)
	if _, err := nilVault.SearchOwnedLocalExact(fx.manifestA.BackendRoot, fx.configA,
		fx.manifestA.VaultID, fx.manifestA.Journal, mobileOwnedLocalTitle, 1, pw, sk); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_LOCAL_NIL_RECEIVER_ACCEPTED")
	}
	mobileOwnedAssertCleared(t, pw)
	mobileOwnedAssertCleared(t, sk)
	for _, tc := range []struct {
		root, config, journal, title string
		limit                        int
	}{
		{"relative", fx.configA, fx.manifestA.Journal, mobileOwnedLocalTitle, 1},
		{fx.manifestA.BackendRoot, fx.configA, fx.manifestA.Journal, "", 1},
		{fx.manifestA.BackendRoot, fx.configA, fx.manifestA.Journal, mobileOwnedLocalTitle, 0},
		{fx.manifestA.BackendRoot, fx.configA, fx.manifestA.Journal, mobileOwnedLocalTitle, 65},
		{fx.manifestA.BackendRoot, fx.configA, fx.manifestA.Journal,
			strings.Repeat("t", 513), 1},
	} {
		pw, sk = bytes.Clone(fx.password), bytes.Clone(fx.key)
		if _, err := v.SearchOwnedLocalExact(tc.root, tc.config, fx.manifestA.VaultID,
			tc.journal, tc.title, tc.limit, pw, sk); !errors.Is(err, errInvalid) {
			t.Fatal("MOBILE_OWNED_LOCAL_INVALID_ARGUMENT_ACCEPTED")
		}
		mobileOwnedAssertCleared(t, pw)
		mobileOwnedAssertCleared(t, sk)
	}

	// Wrong journal, wrong account and wrong factors are refused with only a
	// safe mobile category. The sibling B remains readable after each failure.
	if result, err := mobileOwnedSearch(t, v, fx.manifestA.BackendRoot, fx.configA,
		fx.manifestA.VaultID, fx.manifestB.Journal, mobileOwnedLocalTitle, 2,
		fx.password, fx.key); err == nil || result != nil || !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_LOCAL_WRONG_JOURNAL_ACCEPTED")
	}
	if result, err := mobileOwnedSearch(t, v, fx.manifestC.BackendRoot, fx.configC,
		fx.manifestC.VaultID, fx.manifestC.Journal, mobileOwnedLocalTitle, 2,
		fx.password, fx.key); err == nil || result != nil || !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_LOCAL_WRONG_ACCOUNT_ACCEPTED")
	}
	if result, err := mobileOwnedSearch(t, v, fx.manifestA.BackendRoot, fx.configA,
		fx.manifestA.VaultID, fx.manifestA.Journal, mobileOwnedLocalTitle, 2,
		[]byte("wrong-password"), fx.key); err == nil || result != nil || !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_LOCAL_WRONG_FACTORS_ACCEPTED")
	}
	if result, err := mobileOwnedSearch(t, v, fx.manifestB.BackendRoot, fx.configB,
		fx.manifestB.VaultID, fx.manifestB.Journal, mobileOwnedLocalTitle, 2,
		fx.password, fx.key); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SIBLING_LOST_AFTER_REFUSALS")
	} else {
		mobileOwnedAssertHit(t, result, fx.itemB, fx.manifestB, fx.revisionB)
	}

	// A captured view cannot start after RequestLock and a fresh parent
	// generation. Its factors are still cleared.
	stale, err := v.CaptureOperation()
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_CAPTURE_FAILED")
	}
	v.RequestLock()
	if v.IsUnlocked() {
		t.Fatal("MOBILE_OWNED_LOCAL_LOCK_WAS_LATE")
	}
	if err := v.Unlock(bytes.Clone(fx.password), bytes.Clone(fx.key)); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_REUNLOCK_FAILED")
	}
	if result, err := mobileOwnedSearch(t, stale, fx.manifestA.BackendRoot, fx.configA,
		fx.manifestA.VaultID, fx.manifestA.Journal, mobileOwnedLocalTitle, 2,
		fx.password, fx.key); err == nil || result != nil || !errors.Is(err, errCancelled) {
		t.Fatal("MOBILE_OWNED_LOCAL_STALE_VIEW_STARTED")
	}

	// A worker that already started cannot reveal metadata after RequestLock.
	// The test hook runs after the exact child close and before the final gate.
	view, err := v.CaptureOperation()
	if err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_FINISH_CAPTURE_FAILED")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	oldHook := ownedLocalBeforeGrantForTest
	ownedLocalBeforeGrantForTest = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { ownedLocalBeforeGrantForTest = oldHook })

	type searchResult struct {
		result *OwnedLocalExactResult
		err    error
		leaked bool
	}
	done := make(chan searchResult, 1)
	go func() {
		pw, sk := bytes.Clone(fx.password), bytes.Clone(fx.key)
		result, err := view.SearchOwnedLocalExact(fx.manifestA.BackendRoot, fx.configA,
			fx.manifestA.VaultID, fx.manifestA.Journal, mobileOwnedLocalTitle, 2, pw, sk)
		leaked := false
		for _, b := range append(append([]byte(nil), pw...), sk...) {
			if b != 0 {
				leaked = true
				break
			}
		}
		done <- searchResult{result: result, err: err, leaked: leaked}
	}()
	<-entered
	v.RequestLock()
	close(release)
	finished := <-done
	ownedLocalBeforeGrantForTest = oldHook
	if finished.result != nil || finished.err == nil || !errors.Is(finished.err, errLocked) {
		t.Fatal("MOBILE_OWNED_LOCAL_STALE_WORKER_REVEALED_METADATA")
	}
	if finished.leaked {
		t.Fatal("MOBILE_OWNED_LOCAL_STALE_WORKER_RETAINED_FACTORS")
	}
	if v.IsUnlocked() {
		t.Fatal("MOBILE_OWNED_LOCAL_LOCK_AFTER_FINISH_WAS_LATE")
	}
	if err := v.Unlock(bytes.Clone(fx.password), bytes.Clone(fx.key)); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_REUNLOCK_AFTER_FINISH_FAILED")
	}

	// Replace A's actual backend ciphertext at a new opaque revision. The
	// mobile query must refuse A without writing and without affecting B.
	backendBefore, revisionBefore := mobileOwnedReadBackend(t, fx.manifestA)
	defer clear(backendBefore)
	updated := mobileOwnedRewriteBackend(t, fx.manifestA, backendBefore)
	backendAfter, revisionAfter := mobileOwnedReadBackend(t, fx.manifestA)
	defer clear(backendAfter)
	if updated == revisionBefore || revisionAfter != updated ||
		!bytes.Equal(backendBefore, backendAfter) {
		t.Fatal("MOBILE_OWNED_LOCAL_BACKEND_DRIFT_NOT_REAL")
	}
	beforeA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA)
	beforeB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB)
	if result, err := mobileOwnedSearch(t, v, fx.manifestA.BackendRoot, fx.configA,
		fx.manifestA.VaultID, fx.manifestA.Journal, mobileOwnedLocalTitle, 2,
		fx.password, fx.key); err == nil || result != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_STALE_BACKEND_BYTES_ACCEPTED")
	}
	if afterA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA); afterA != beforeA {
		t.Fatal("MOBILE_OWNED_LOCAL_FAILED_QUERY_WROTE_A")
	}
	if afterB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB); afterB != beforeB {
		t.Fatal("MOBILE_OWNED_LOCAL_FAILED_QUERY_WROTE_B")
	}
	if !v.IsUnlocked() {
		t.Fatal("MOBILE_OWNED_LOCAL_PARENT_LOCKED_BY_CHILD_FAILURE")
	}
	if result, err := mobileOwnedSearch(t, v, fx.manifestB.BackendRoot, fx.configB,
		fx.manifestB.VaultID, fx.manifestB.Journal, mobileOwnedLocalTitle, 2,
		fx.password, fx.key); err != nil {
		t.Fatal("MOBILE_OWNED_LOCAL_SIBLING_LOST_AFTER_DRIFT")
	} else {
		mobileOwnedAssertHit(t, result, fx.itemB, fx.manifestB, fx.revisionB)
	}
	if rows, err := v.List("active"); err != nil || rows.Count() != 0 {
		t.Fatal("MOBILE_OWNED_LOCAL_ACCOUNT_LIST_CHANGED")
	}
}
