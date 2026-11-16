//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

type creationBoundaryFixture struct {
	root, config string
	proposal     Manifest
	password     []byte
	key          []byte
	secretInput  []byte
	kit          []byte
}

func newCreationBoundaryFixture(t *testing.T) *creationBoundaryFixture {
	t.Helper()
	root := t.TempDir()
	private := filepath.Join(root, "private")
	journalDir := filepath.Join(root, "journal")
	if os.Mkdir(private, 0700) != nil || os.Mkdir(journalDir, 0700) != nil {
		t.Fatal("CREATE_BOUNDARY_PRIVATE_PARENT_FAILED")
	}
	f := &creationBoundaryFixture{root: root, config: filepath.Join(private, "create.json"),
		password: []byte("create-boundary-factor"), key: bytes.Repeat([]byte{0x35}, 16)}
	f.secretInput = []byte(personal.FormatSecret(f.key))
	f.proposal = Manifest{Version: 1, Kind: CreateKind,
		PersonalFile: filepath.Join(root, "personal.ll"), BackendRoot: filepath.Join(root, "backend"),
		Name: "owned-g", Journal: filepath.Join(journalDir, "genesis.journal"),
		Archive: filepath.Join(root, "published.llb")}
	if personal.Create(f.proposal.PersonalFile, string(f.password), f.key) != nil {
		t.Fatal("CREATE_BOUNDARY_PERSONAL_CREATE_FAILED")
	}
	t.Cleanup(func() {
		clear(f.password)
		clear(f.key)
		clear(f.secretInput)
		clear(f.kit)
	})
	return f
}

func (f *creationBoundaryFixture) open(t *testing.T) *CreationContext {
	t.Helper()
	c, err := OpenCreation(f.config, &f.proposal, f.password, f.secretInput)
	if err != nil {
		t.Fatal("CREATE_BOUNDARY_OPEN_FAILED")
	}
	t.Cleanup(c.Close)
	return c
}

func (f *creationBoundaryFixture) publishBackup(t *testing.T) {
	t.Helper()
	c := f.open(t)
	backupRequired, err := c.Prepare(context.Background())
	if err != nil || !backupRequired {
		t.Fatal("CREATE_BOUNDARY_PREPARE_FAILED")
	}
	c.Close()
	backup, err := personal.PrepareBackup(f.proposal.PersonalFile, f.proposal.Archive, string(f.password), f.key)
	if err != nil || backup.Publish() != nil {
		t.Fatal("CREATE_BOUNDARY_BACKUP_FAILED")
	}
	f.kit = []byte(backup.Material())
	backup.Close()
}

func (f *creationBoundaryFixture) openReady(t *testing.T) *CreationContext {
	t.Helper()
	c := f.open(t)
	backupRequired, err := c.Prepare(context.Background())
	if err != nil || backupRequired {
		t.Fatal("CREATE_BOUNDARY_READY_FAILED")
	}
	return c
}

func TestCreationContextRejectsForeignPersonalAndManifestSwap(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	c := f.open(t)
	foreign := f.proposal
	foreign.PersonalFile = filepath.Join(f.root, "foreign.ll")
	if personal.Create(foreign.PersonalFile, string(f.password), f.key) != nil {
		t.Fatal("CREATE_BOUNDARY_FOREIGN_PERSONAL_FAILED")
	}
	if _, err := OpenCreation(f.config, &foreign, f.password, f.secretInput); !errors.Is(err, ErrLocalReview) {
		t.Fatal("CREATE_BOUNDARY_FOREIGN_PERSONAL_ACCEPTED")
	}
	if _, err := OpenCreation(f.config, nil, []byte("wrong-factor"), f.secretInput); !errors.Is(err, ErrCreateVerification) {
		t.Fatal("CREATE_BOUNDARY_WRONG_FACTOR_ACCEPTED")
	}
	raw, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal("CREATE_BOUNDARY_MANIFEST_READ_FAILED")
	}
	if os.WriteFile(f.config, append(raw, '\n'), 0600) != nil {
		t.Fatal("CREATE_BOUNDARY_MANIFEST_SWAP_FAILED")
	}
	if _, exists, err := ReadManifest(f.config); err != nil || !exists {
		t.Fatal("CREATE_BOUNDARY_MANIFEST_SWAP_NOT_STRICT")
	}
	if _, err := c.Prepare(context.Background()); !errors.Is(err, ErrLocalReview) {
		t.Fatal("CREATE_BOUNDARY_MANIFEST_SWAP_ACCEPTED")
	}
	if _, err := c.Prepare(context.Background()); !errors.Is(err, ErrCreateCancelled) {
		t.Fatal("CREATE_BOUNDARY_REVIEW_CONTEXT_REUSED")
	}
	if _, err := os.Lstat(f.proposal.Journal); !os.IsNotExist(err) {
		t.Fatal("CREATE_BOUNDARY_MANIFEST_SWAP_WROTE_INTENT")
	}
}

func TestCreationContextCancelBeforeCustody(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	c := f.open(t)
	c.Cancel()
	if _, err := c.Prepare(context.Background()); !errors.Is(err, ErrCreateCancelled) {
		t.Fatal("CREATE_BOUNDARY_CANCEL_PREPARE_ACCEPTED")
	}
	for _, path := range []string{f.proposal.Journal, f.proposal.Archive, f.proposal.BackendRoot} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("CREATE_BOUNDARY_CANCEL_WROTE_OUTPUT")
		}
	}
}

func TestCreationContextCancelAfterDurableIntentIsUnknown(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	f.publishBackup(t)
	c := f.openReady(t)
	c.afterIntentForTest = c.Cancel
	if err := c.Complete(context.Background(), f.password, f.secretInput, f.kit); !errors.Is(err, ErrCreateUnknown) {
		t.Fatal("CREATE_BOUNDARY_CANCEL_AFTER_INTENT_PASSED")
	}
	if err := c.Complete(context.Background(), f.password, f.secretInput, f.kit); !errors.Is(err, ErrCreateCancelled) {
		t.Fatal("CREATE_BOUNDARY_CANCEL_CONTEXT_REUSED")
	}
	j, err := vaultfilejournal.OpenExistingIntent(f.proposal.Journal)
	if err != nil {
		t.Fatal("CREATE_BOUNDARY_CANCEL_LOST_INTENT")
	}
	intent, loadErr := j.Load()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil || len(intent.SealedBytes) == 0 {
		t.Fatal("CREATE_BOUNDARY_CANCEL_INTENT_INVALID")
	}
	clear(intent.SealedBytes)
	path, err := CompanionPath(f.config)
	if err != nil {
		t.Fatal("CREATE_BOUNDARY_CANCEL_COMPANION_PATH_FAILED")
	}
	if _, exists, err := ReadCompanion(f.config, c.manifest); err != nil || !exists {
		t.Fatal("CREATE_BOUNDARY_CANCEL_LOST_COMPANION")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("CREATE_BOUNDARY_CANCEL_LOST_COMPANION_INODE")
	}
	if _, err := os.Lstat(f.proposal.BackendRoot); !os.IsNotExist(err) {
		t.Fatal("CREATE_BOUNDARY_CANCEL_OPENED_BACKEND")
	}
}

func TestCreationContextExpiryBeforePublicationHasNoLateSuccess(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	f.publishBackup(t)
	c := f.open(t)
	c.fullFactorDeadline = time.Now().Add(-time.Second)
	if _, err := c.Prepare(context.Background()); !errors.Is(err, ErrCreateUnknown) {
		t.Fatal("CREATE_BOUNDARY_EXPIRY_LATE_SUCCESS")
	}
	if err := c.Complete(context.Background(), f.password, f.secretInput, f.kit); !errors.Is(err, ErrCreateCancelled) {
		t.Fatal("CREATE_BOUNDARY_EXPIRY_CONTEXT_REUSED")
	}
	if _, err := os.Lstat(f.proposal.Journal); !os.IsNotExist(err) {
		t.Fatal("CREATE_BOUNDARY_EXPIRY_WROTE_INTENT")
	}
}

func TestCreationContextVerifyExactLocalBaselineAfterRestart(t *testing.T) {
	f := newCreationBoundaryFixture(t)
	f.publishBackup(t)
	c := f.openReady(t)
	if err := c.Complete(context.Background(), f.password, f.secretInput, f.kit); err != nil {
		t.Fatal("CREATE_BOUNDARY_COMPLETE_FAILED")
	}
	c.Close()
	restarted := f.openReady(t)
	if err := restarted.Verify(context.Background(), f.password, f.secretInput, f.kit); err != nil {
		t.Fatal("CREATE_BOUNDARY_RESTART_VERIFY_FAILED")
	}
	if err := restarted.Verify(context.Background(), f.password, f.secretInput, []byte("wrong-kit")); !errors.Is(err, ErrCreateVerification) {
		t.Fatal("CREATE_BOUNDARY_WRONG_KIT_VERIFIED")
	}
	if err := restarted.Verify(context.Background(), f.password, f.secretInput, f.kit); !errors.Is(err, ErrCreateCancelled) {
		t.Fatal("CREATE_BOUNDARY_FAILED_VERIFY_CONTEXT_REUSED")
	}
}
