//go:build darwin || linux

package vaultfileclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func TestOpenLocalGenesisBaselineTwoIndependentFilesOnePersonal(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	f.publishBackup(t)
	first := f.openReady(t)
	if first.Complete(context.Background(), f.password, f.secretInput, f.kit) != nil {
		t.Fatal("LOCAL_GENESIS_FIRST_CREATE_FAILED")
	}
	first.Close()
	firstManifest, exists, err := ReadManifest(f.config)
	if err != nil || !exists {
		t.Fatal("LOCAL_GENESIS_FIRST_SELECTOR_MISSING")
	}

	secondConfig := filepath.Join(filepath.Dir(f.config), "second.json")
	second := f.proposal
	second.Name = "other-g"
	second.Journal = filepath.Join(filepath.Dir(f.proposal.Journal), "second.journal")
	second.Archive = filepath.Join(f.root, "second.llb")
	create, err := OpenCreation(secondConfig, &second, f.password, f.secretInput)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SECOND_OPEN_FAILED")
	}
	backupRequired, err := create.Prepare(context.Background())
	create.Close()
	if err != nil || !backupRequired {
		t.Fatal("LOCAL_GENESIS_SECOND_BACKUP_REQUIRED_MISSING")
	}
	backup, err := personal.PrepareBackup(second.PersonalFile, second.Archive, string(f.password), f.key)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SECOND_BACKUP_FAILED")
	}
	kit := []byte(backup.Material())
	defer clear(kit)
	if backup.Publish() != nil {
		t.Fatal("LOCAL_GENESIS_SECOND_BACKUP_PUBLISH_FAILED")
	}
	backup.Close()
	create, err = OpenCreation(secondConfig, nil, f.password, f.secretInput)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SECOND_REOPEN_FAILED")
	}
	backupRequired, err = create.Prepare(context.Background())
	if err != nil || backupRequired || create.Complete(context.Background(), f.password, f.secretInput, kit) != nil {
		t.Fatal("LOCAL_GENESIS_SECOND_CREATE_FAILED")
	}
	create.Close()
	secondManifest, exists, err := ReadManifest(secondConfig)
	if err != nil || !exists || firstManifest.VaultID == secondManifest.VaultID || firstManifest.Name == secondManifest.Name {
		t.Fatal("LOCAL_GENESIS_FILES_NOT_INDEPENDENT")
	}
	s, err := personal.UnlockSession(f.proposal.PersonalFile, f.password, f.key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_PROFILE_UNLOCK_FAILED")
	}
	defer s.Lock()
	for _, selector := range []struct{ path, id string }{{f.config, firstManifest.VaultID}, {secondConfig, secondManifest.VaultID}} {
		opened, err := OpenLocalGenesisBaseline(s, selector.path, f.proposal.BackendRoot, selector.id)
		if err != nil || opened.VaultID != selector.id || len(opened.Items) != 0 {
			t.Fatal("LOCAL_GENESIS_BOUND_OPEN_FAILED")
		}
	}
	if _, err := OpenLocalGenesisBaseline(s, f.config, f.proposal.BackendRoot, secondManifest.VaultID); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_GENESIS_FOREIGN_SELECTOR_ACCEPTED")
	}
	if _, err := OpenLocalGenesisBaseline(s, f.config, filepath.Join(f.root, "foreign-backend"), firstManifest.VaultID); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_GENESIS_FOREIGN_WORKSPACE_ACCEPTED")
	}
	companionPath, err := CompanionPath(f.config)
	if err != nil || os.WriteFile(companionPath, []byte("{}"), 0600) != nil {
		t.Fatal("LOCAL_GENESIS_CORRUPTION_SETUP_FAILED")
	}
	if _, err := OpenLocalGenesisBaseline(s, f.config, f.proposal.BackendRoot, firstManifest.VaultID); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_GENESIS_CORRUPT_COMPANION_ACCEPTED")
	}
	if _, err := OpenLocalGenesisBaseline(s, secondConfig, f.proposal.BackendRoot, secondManifest.VaultID); err != nil {
		t.Fatal("LOCAL_GENESIS_SECOND_AFFECTED_BY_FIRST")
	}
}
