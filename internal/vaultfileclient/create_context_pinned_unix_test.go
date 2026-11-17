//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func pinnedDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("PINNED_DIRECTORY_READ_FAILED")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func pinnedFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("PINNED_FILE_READ_FAILED")
	}
	return raw
}

func pinnedAssertFileUnchanged(t *testing.T, path string, want []byte, label string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal(label)
	}
}

func pinnedAssertSameNames(t *testing.T, dir string, want []string, label string) {
	t.Helper()
	if got := pinnedDirNames(t, dir); !reflect.DeepEqual(got, want) {
		t.Fatal(label)
	}
}

func pinnedAssertAbsent(t *testing.T, path, label string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal(label)
	}
}

func (f *creationBoundaryFixture) reservePinnedA(t *testing.T) Manifest {
	t.Helper()
	c, err := OpenCreation(f.config, &f.proposal, f.password, f.secretInput)
	if err != nil {
		t.Fatal("PINNED_A_RESERVE_FAILED")
	}
	c.Close()
	manifest, exists, err := ReadManifest(f.config)
	if err != nil || !exists || manifest.VaultID == "" {
		t.Fatal("PINNED_A_MANIFEST_FAILED")
	}
	return manifest
}

func (f *creationBoundaryFixture) reservePinnedB(t *testing.T) ([]byte, Manifest) {
	t.Helper()
	b := f.proposal
	b.Name = "owned-pinned-b"
	b.Journal = filepath.Join(filepath.Dir(f.proposal.Journal), "pinned-b.journal")
	b.Archive = filepath.Join(f.root, "pinned-b.llb")
	b.BackendRoot = filepath.Join(f.root, "backend-pinned-b")
	b.VaultID = ""
	path := filepath.Join(filepath.Dir(f.config), "pinned-b.json")
	manifest, err := ReserveManifest(path, b)
	if err != nil {
		t.Fatal("PINNED_B_RESERVE_FAILED")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("PINNED_B_READ_FAILED")
	}
	return raw, manifest
}

func TestCreationContextForVaultRejectsInternalSnapshotMismatch(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	aManifest := f.reservePinnedA(t)
	prepared, err := OpenCreation(f.config, &f.proposal, f.password, f.secretInput)
	if err != nil {
		t.Fatal("PINNED_PREPARED_A_OPEN_FAILED")
	}
	if _, err := prepared.Prepare(context.Background()); err != nil {
		prepared.Close()
		t.Fatal("PINNED_PREPARED_A_PREPARE_FAILED")
	}
	prepared.Close()

	bRaw, bManifest := f.reservePinnedB(t)
	if bManifest.VaultID == aManifest.VaultID {
		t.Fatal("PINNED_B_ID_COLLISION")
	}
	if err := os.WriteFile(f.config, bRaw, 0600); err != nil {
		t.Fatal("PINNED_B_SWAP_FAILED")
	}
	swappedConfig := pinnedFile(t, f.config)
	personalBefore := pinnedFile(t, f.proposal.PersonalFile)
	namesBefore := pinnedDirNames(t, filepath.Dir(f.config))

	if _, err := OpenCreationForVault(f.config, &f.proposal, aManifest.VaultID, f.password, f.secretInput); !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_SNAPSHOT_MISMATCH_ACCEPTED")
	}
	pinnedAssertFileUnchanged(t, f.config, swappedConfig, "PINNED_SNAPSHOT_CONFIG_CHANGED")
	pinnedAssertFileUnchanged(t, f.proposal.PersonalFile, personalBefore, "PINNED_SNAPSHOT_PERSONAL_CHANGED")
	pinnedAssertSameNames(t, filepath.Dir(f.config), namesBefore, "PINNED_SNAPSHOT_EXTRA_MANIFEST")
	pinnedAssertAbsent(t, bManifest.Journal, "PINNED_SNAPSHOT_B_JOURNAL")
	pinnedAssertAbsent(t, bManifest.Archive, "PINNED_SNAPSHOT_B_ARCHIVE")
	pinnedAssertAbsent(t, bManifest.BackendRoot, "PINNED_SNAPSHOT_B_BACKEND")
	companion, err := CompanionPath(f.config)
	if err != nil {
		t.Fatal("PINNED_SNAPSHOT_COMPANION_PATH_FAILED")
	}
	pinnedAssertAbsent(t, companion, "PINNED_SNAPSHOT_COMPANION")
}

func TestCreationContextForVaultComparesInternalSnapshotNotRestoredPath(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	aManifest := f.reservePinnedA(t)
	aRaw := pinnedFile(t, f.config)
	bRaw, bManifest := f.reservePinnedB(t)
	if bManifest.VaultID == aManifest.VaultID {
		t.Fatal("PINNED_HOOK_B_ID_COLLISION")
	}
	if err := os.WriteFile(f.config, bRaw, 0600); err != nil {
		t.Fatal("PINNED_HOOK_B_SWAP_FAILED")
	}
	personalBefore := pinnedFile(t, f.proposal.PersonalFile)
	namesBefore := pinnedDirNames(t, filepath.Dir(f.config))
	calls := 0
	_, err := openCreationForVault(f.config, &f.proposal, aManifest.VaultID, f.password, f.secretInput, func() {
		calls++
		if writeErr := os.WriteFile(f.config, aRaw, 0600); writeErr != nil {
			t.Fatal("PINNED_HOOK_RESTORE_FAILED")
		}
	})
	if !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_HOOK_RESTORED_SNAPSHOT_ACCEPTED")
	}
	if calls != 1 {
		t.Fatal("PINNED_HOOK_CALL_COUNT")
	}
	restored, exists, readErr := ReadManifest(f.config)
	if readErr != nil || !exists || restored.VaultID != aManifest.VaultID {
		t.Fatal("PINNED_HOOK_PATH_NOT_RESTORED")
	}
	pinnedAssertFileUnchanged(t, f.proposal.PersonalFile, personalBefore, "PINNED_HOOK_PERSONAL_CHANGED")
	pinnedAssertSameNames(t, filepath.Dir(f.config), namesBefore, "PINNED_HOOK_EXTRA_MANIFEST")
	pinnedAssertAbsent(t, bManifest.Journal, "PINNED_HOOK_B_JOURNAL")
	pinnedAssertAbsent(t, bManifest.Archive, "PINNED_HOOK_B_ARCHIVE")
	pinnedAssertAbsent(t, bManifest.BackendRoot, "PINNED_HOOK_B_BACKEND")
}

func TestCreationContextForVaultExactDigestRejectsSwapBeforePrepare(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	aManifest := f.reservePinnedA(t)
	c, err := OpenCreationForVault(f.config, &f.proposal, aManifest.VaultID, f.password, f.secretInput)
	if err != nil {
		t.Fatal("PINNED_VALID_A_OPEN_FAILED")
	}
	t.Cleanup(c.Close)

	bRaw, bManifest := f.reservePinnedB(t)
	personalBefore := pinnedFile(t, f.proposal.PersonalFile)
	namesBefore := pinnedDirNames(t, filepath.Dir(f.config))
	if err := os.WriteFile(f.config, bRaw, 0600); err != nil {
		t.Fatal("PINNED_PREPARE_SWAP_FAILED")
	}
	if _, err := c.Prepare(context.Background()); !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_PREPARE_SWAP_ACCEPTED")
	}
	pinnedAssertFileUnchanged(t, f.proposal.PersonalFile, personalBefore, "PINNED_PREPARE_SWAP_PERSONAL_CHANGED")
	pinnedAssertSameNames(t, filepath.Dir(f.config), namesBefore, "PINNED_PREPARE_SWAP_EXTRA_MANIFEST")
	pinnedAssertAbsent(t, bManifest.Journal, "PINNED_PREPARE_SWAP_B_JOURNAL")
	pinnedAssertAbsent(t, bManifest.Archive, "PINNED_PREPARE_SWAP_B_ARCHIVE")
	pinnedAssertAbsent(t, bManifest.BackendRoot, "PINNED_PREPARE_SWAP_B_BACKEND")
	if _, err := c.Prepare(context.Background()); !errors.Is(err, ErrCreateCancelled) {
		t.Fatal("PINNED_PREPARE_SWAP_CONTEXT_REUSED")
	}
}

func TestCreationContextForVaultMissingManifestDoesNotReserve(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	personalBefore := pinnedFile(t, f.proposal.PersonalFile)
	namesBefore := pinnedDirNames(t, filepath.Dir(f.config))

	if _, err := OpenCreationForVault(f.config, &f.proposal, "not-a-vault-id", f.password, f.secretInput); !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_INVALID_ID_ACCEPTED")
	}
	missingID := strings.Repeat("ab", 16)
	if _, err := OpenCreationForVault(f.config, &f.proposal, missingID, f.password, f.secretInput); !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_MISSING_MANIFEST_ACCEPTED")
	}
	pinnedAssertAbsent(t, f.config, "PINNED_MISSING_MANIFEST_RESERVED")
	pinnedAssertAbsent(t, f.proposal.Journal, "PINNED_MISSING_JOURNAL")
	pinnedAssertAbsent(t, f.proposal.Archive, "PINNED_MISSING_ARCHIVE")
	pinnedAssertAbsent(t, f.proposal.BackendRoot, "PINNED_MISSING_BACKEND")
	pinnedAssertSameNames(t, filepath.Dir(f.config), namesBefore, "PINNED_MISSING_EXTRA_MANIFEST")
	pinnedAssertFileUnchanged(t, f.proposal.PersonalFile, personalBefore, "PINNED_MISSING_PERSONAL_CHANGED")
}

func TestCreationContextForVaultNormalPinnedFlow(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	f.publishBackup(t)
	aManifest, exists, err := ReadManifest(f.config)
	if err != nil || !exists || aManifest.VaultID == "" {
		t.Fatal("PINNED_NORMAL_MANIFEST_FAILED")
	}
	if _, err := OpenCreationForVault(f.config, &f.proposal, "not-a-vault-id", f.password, f.secretInput); !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_NORMAL_INVALID_ID_ACCEPTED")
	}
	wrongID := strings.Repeat("0", 32)
	if wrongID == aManifest.VaultID {
		wrongID = strings.Repeat("1", 32)
	}
	if _, err := OpenCreationForVault(f.config, &f.proposal, wrongID, f.password, f.secretInput); !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_NORMAL_WRONG_ID_ACCEPTED")
	}
	wrongTemplate := f.proposal
	wrongTemplate.Name = "owned-pinned-wrong"
	if _, err := OpenCreationForVault(f.config, &wrongTemplate, aManifest.VaultID, f.password, f.secretInput); !errors.Is(err, ErrLocalReview) {
		t.Fatal("PINNED_NORMAL_WRONG_TEMPLATE_ACCEPTED")
	}

	c, err := OpenCreationForVault(f.config, &f.proposal, aManifest.VaultID, f.password, f.secretInput)
	if err != nil {
		t.Fatal("PINNED_NORMAL_OPEN_FAILED")
	}
	backupRequired, err := c.Prepare(context.Background())
	if err != nil || backupRequired {
		c.Close()
		t.Fatal("PINNED_NORMAL_PREPARE_FAILED")
	}
	if err := c.Complete(context.Background(), f.password, f.secretInput, f.kit); err != nil {
		c.Close()
		t.Fatal("PINNED_NORMAL_COMPLETE_FAILED")
	}
	if err := c.Verify(context.Background(), f.password, f.secretInput, f.kit); err != nil {
		c.Close()
		t.Fatal("PINNED_NORMAL_VERIFY_FAILED")
	}
	c.Close()
}
