//go:build darwin || linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

func TestVaultFileCreateCompanionLiveIntentAndExclusiveRetry(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	journalDir := filepath.Join(root, "journal")
	if os.Mkdir(private, 0700) != nil || os.Mkdir(journalDir, 0700) != nil {
		t.Fatal("CREATE_COMPANION_PRIVATE_PARENT_FAILED")
	}
	password := []byte("create-companion-factor")
	key := bytes.Repeat([]byte{0x4d}, 16)
	personalPath := filepath.Join(root, "personal.ll")
	archive := filepath.Join(root, "published.llb")
	config := filepath.Join(private, "create.json")
	manifest := vaultFileCreateManifest{Version: 1, Kind: vaultFileCreateKind,
		VaultID: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", PersonalFile: personalPath,
		BackendRoot: filepath.Join(root, "backend"), Name: "owned-g",
		Journal: filepath.Join(journalDir, "genesis.journal"), Archive: archive}
	if personal.Create(personalPath, string(password), key) != nil {
		t.Fatal("CREATE_COMPANION_PERSONAL_CREATE_FAILED")
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || teamfiles.WriteNew(config, encoded) != nil {
		t.Fatal("CREATE_COMPANION_MANIFEST_CREATE_FAILED")
	}
	session, err := personal.UnlockSession(personalPath, password, key, time.Minute)
	if err != nil {
		t.Fatal("CREATE_COMPANION_FULL_UNLOCK_FAILED")
	}
	defer session.Lock()
	if _, err := session.PrepareVaultFileOwnership(manifest.VaultID); err != nil {
		t.Fatal("CREATE_COMPANION_OWNER_PREPARE_FAILED")
	}
	backup, err := personal.PrepareBackup(personalPath, archive, string(password), key)
	if err != nil || backup.Publish() != nil {
		t.Fatal("CREATE_COMPANION_BACKUP_PUBLISH_FAILED")
	}
	kit := []byte(backup.Material())
	backup.Close()
	first, err := ensureVaultFileCreateCompanion(config, manifest, session, password, key, kit)
	if err != nil || first.GenesisSHA256 == "" || first.ManifestSHA256 == "" || first.OperationID == "" {
		t.Fatal("CREATE_COMPANION_LIVE_PREPARE_FAILED")
	}
	path, err := vaultFileCreateCompanionPath(config)
	if err != nil {
		t.Fatal("CREATE_COMPANION_PATH_FAILED")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("CREATE_COMPANION_NOT_PRIVATE")
	}
	second, exists, err := readVaultFileCreateCompanion(config, manifest)
	if err != nil || !exists || !sameVaultFileCreateCompanion(first, second) {
		t.Fatal("CREATE_COMPANION_RELOAD_FAILED")
	}
	retry, err := ensureVaultFileCreateCompanion(config, manifest, session, password, key, kit)
	if err != nil || !sameVaultFileCreateCompanion(retry, first) {
		t.Fatal("CREATE_COMPANION_EXACT_RETRY_FAILED")
	}
	retriedInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, retriedInfo) {
		t.Fatal("CREATE_COMPANION_RETRY_REPLACED_INODE")
	}
	otherConfig := filepath.Join(private, "other.json")
	if teamfiles.WriteNew(otherConfig, encoded) != nil {
		t.Fatal("CREATE_COMPANION_FOREIGN_MANIFEST_FAILED")
	}
	foreignPath, err := vaultFileCreateCompanionPath(otherConfig)
	if err != nil || os.WriteFile(foreignPath, []byte("foreign"), 0600) != nil {
		t.Fatal("CREATE_COMPANION_FOREIGN_FIXTURE_FAILED")
	}
	before, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatal("CREATE_COMPANION_FOREIGN_READ_FAILED")
	}
	if _, err := ensureVaultFileCreateCompanion(otherConfig, manifest, session, password, key, kit); !errors.Is(err, errVaultFileLocalReview) {
		t.Fatal("CREATE_COMPANION_FOREIGN_ACCEPTED")
	}
	after, err := os.ReadFile(foreignPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("CREATE_COMPANION_FOREIGN_OVERWRITTEN")
	}
	if raw, err := os.ReadFile(path); err != nil {
		t.Fatal("CREATE_COMPANION_READ_FAILED")
	} else if _, _, err := decodeVaultFileResumeConfig(raw); err == nil {
		t.Fatal("CREATE_COMPANION_ACCEPTED_AS_LEGACY_CONFIG")
	}
	j, err := vaultfilejournal.OpenExistingIntent(manifest.Journal)
	if err != nil {
		t.Fatal("CREATE_CLAIMED_MISSING_INTENT_OPEN_FAILED")
	}
	intent, err := j.Load()
	if err != nil {
		t.Fatal("CREATE_CLAIMED_MISSING_INTENT_LOAD_FAILED")
	}
	defer clear(intent.SealedBytes)
	claim, claimErr := j.ClaimGenesisAttempt(intent)
	if claimErr != nil || claim != vaultfilejournal.GenesisAttemptNewlyClaimed || j.Close() != nil {
		t.Fatal("CREATE_CLAIMED_MISSING_CLAIM_FAILED")
	}
	if err := completeVaultFileCreate(config, manifest, session, password, key, kit); !errors.Is(err, errVaultFileUnknown) {
		t.Fatal("CREATE_CLAIMED_MISSING_RECREATED_OR_PASSED")
	}
	objects, err := os.ReadDir(filepath.Join(manifest.BackendRoot, "vaultfile-backend", "v1", "data"))
	if err != nil || len(objects) != 0 {
		t.Fatal("CREATE_CLAIMED_MISSING_WROTE_OBJECT")
	}
}
