//go:build darwin || linux

package vaultfileclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

type localGenesisTwoVaultFixture struct {
	f *creationBoundaryFixture

	firstConfig   string
	secondConfig  string
	firstVaultID  string
	secondVaultID string

	session *personal.Session
}

// newLocalGenesisTwoVaultFixture reuses the real creation boundary fixture and
// its real backup publish/complete flow. Both vaults share one personal parent
// and one generation-zero create shape, but each create obtains its own real
// owner root, so the two journals use different keys.
func newLocalGenesisTwoVaultFixture(t *testing.T) *localGenesisTwoVaultFixture {
	t.Helper()
	f := newCreationBoundaryFixture(t)
	f.publishBackup(t)

	first := f.openReady(t)
	if first.Complete(context.Background(), f.password, f.secretInput, f.kit) != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_FIRST_CREATE_FAILED")
	}
	first.Close()
	firstManifest, exists, err := ReadManifest(f.config)
	if err != nil || !exists {
		t.Fatal("LOCAL_GENESIS_SESSION_FIRST_MANIFEST_FAILED")
	}

	secondConfig := filepath.Join(filepath.Dir(f.config), "second.json")
	second := f.proposal
	second.Name = "other-g"
	second.Journal = filepath.Join(filepath.Dir(f.proposal.Journal), "second.journal")
	second.Archive = filepath.Join(f.root, "second.llb")
	create, err := OpenCreation(secondConfig, &second, f.password, f.secretInput)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_OPEN_FAILED")
	}
	backupRequired, err := create.Prepare(context.Background())
	create.Close()
	if err != nil || !backupRequired {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_BACKUP_REQUIRED_FAILED")
	}
	backup, err := personal.PrepareBackup(second.PersonalFile, second.Archive, string(f.password), f.key)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_BACKUP_FAILED")
	}
	kit := []byte(backup.Material())
	defer clear(kit)
	if backup.Publish() != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_BACKUP_PUBLISH_FAILED")
	}
	backup.Close()
	create, err = OpenCreation(secondConfig, nil, f.password, f.secretInput)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_REOPEN_FAILED")
	}
	backupRequired, err = create.Prepare(context.Background())
	if err != nil || backupRequired {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_PREPARE_FAILED")
	}
	if err := create.Complete(context.Background(), f.password, f.secretInput, kit); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_CREATE_FAILED")
	}
	create.Close()
	secondManifest, exists, err := ReadManifest(secondConfig)
	if err != nil || !exists {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_MANIFEST_FAILED")
	}
	firstCompanion, ok, err := ReadCompanion(f.config, firstManifest)
	if err != nil || !ok || firstCompanion.Resume.Checkpoint == nil {
		t.Fatal("LOCAL_GENESIS_SESSION_FIRST_COMPANION_FAILED")
	}
	secondCompanion, ok, err := ReadCompanion(secondConfig, secondManifest)
	if err != nil || !ok || secondCompanion.Resume.Checkpoint == nil {
		t.Fatal("LOCAL_GENESIS_SESSION_SECOND_COMPANION_FAILED")
	}
	if firstManifest.VaultID == secondManifest.VaultID {
		t.Fatal("LOCAL_GENESIS_SESSION_VAULT_IDS_NOT_DISTINCT")
	}
	if firstCompanion.Resume.Checkpoint.OwnerRootPublicKey == secondCompanion.Resume.Checkpoint.OwnerRootPublicKey {
		t.Fatal("LOCAL_GENESIS_SESSION_OWNER_ROOTS_NOT_DISTINCT")
	}

	session, err := personal.UnlockSession(f.proposal.PersonalFile, f.password, f.key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_PARENT_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)
	return &localGenesisTwoVaultFixture{
		f:             f,
		firstConfig:   f.config,
		secondConfig:  secondConfig,
		firstVaultID:  firstManifest.VaultID,
		secondVaultID: secondManifest.VaultID,
		session:       session,
	}
}

func (f *localGenesisTwoVaultFixture) open(t *testing.T, config, vaultID string) (*LocalGenesisSession, LocalGenesisBaseline) {
	t.Helper()
	session, summary, err := OpenLocalGenesisSession(f.session, config, f.f.proposal.BackendRoot, vaultID, f.f.password, f.f.key)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_OPEN_FAILED")
	}
	return session, summary
}

func assertLocalGenesisSummary(t *testing.T, summary LocalGenesisBaseline, vaultID string) {
	t.Helper()
	if summary.VaultID != vaultID || len(summary.Items) != 0 {
		t.Fatal("LOCAL_GENESIS_SESSION_SUMMARY_BINDING_FAILED")
	}
}

func replaceLocalGenesisFileStable(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".swap"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_REPLACE_WRITE_FAILED")
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		t.Fatal("LOCAL_GENESIS_SESSION_REPLACE_RENAME_FAILED")
	}
}

func TestLocalGenesisSessionTwoVaultsIndependentCloseAndSiblingRead(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, summaryA := f.open(t, f.firstConfig, f.firstVaultID)
	assertLocalGenesisSummary(t, summaryA, f.firstVaultID)

	// Pointer, dereferenced value, zero value and nil pointer must all have a
	// fixed safe representation. Failures never print the formatted result.
	const redacted = "[local genesis session]"
	for _, formatted := range []struct {
		name string
		got  string
	}{
		{"POINTER_V", fmt.Sprintf("%v", a)},
		{"POINTER_PLUS_V", fmt.Sprintf("%+v", a)},
		{"POINTER_SHARP_V", fmt.Sprintf("%#v", a)},
		{"VALUE_V", fmt.Sprintf("%v", *a)},
		{"VALUE_PLUS_V", fmt.Sprintf("%+v", *a)},
		{"VALUE_SHARP_V", fmt.Sprintf("%#v", *a)},
		{"ZERO_V", fmt.Sprintf("%v", LocalGenesisSession{})},
		{"ZERO_PLUS_V", fmt.Sprintf("%+v", LocalGenesisSession{})},
		{"ZERO_SHARP_V", fmt.Sprintf("%#v", LocalGenesisSession{})},
		{"NIL_V", fmt.Sprintf("%v", (*LocalGenesisSession)(nil))},
		{"NIL_PLUS_V", fmt.Sprintf("%+v", (*LocalGenesisSession)(nil))},
		{"NIL_SHARP_V", fmt.Sprintf("%#v", (*LocalGenesisSession)(nil))},
	} {
		if formatted.got != redacted {
			t.Fatalf("LOCAL_GENESIS_SESSION_FORMAT_NOT_REDACTED_%s", formatted.name)
		}
	}
	for _, encoded := range []struct {
		name  string
		value any
	}{
		{"POINTER", a},
		{"VALUE", *a},
		{"ZERO", LocalGenesisSession{}},
	} {
		raw, err := json.Marshal(encoded.value)
		if err != nil || string(raw) != "{}" {
			t.Fatalf("LOCAL_GENESIS_SESSION_JSON_EXPOSED_PRIVATE_FIELDS_%s", encoded.name)
		}
	}
	if raw, err := json.Marshal((*LocalGenesisSession)(nil)); err != nil || string(raw) != "null" {
		t.Fatal("LOCAL_GENESIS_SESSION_JSON_NIL_NOT_SAFE")
	}
	zero := LocalGenesisSession{}
	if _, err := zero.Summary(); err == nil {
		t.Fatal("LOCAL_GENESIS_SESSION_ZERO_SUMMARIZED")
	}
	if err := zero.Close(); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_ZERO_CLOSE_FAILED")
	}
	var nilSession *LocalGenesisSession
	if _, err := nilSession.Summary(); err == nil {
		t.Fatal("LOCAL_GENESIS_SESSION_NIL_SUMMARIZED")
	}
	if err := nilSession.Close(); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_NIL_CLOSE_FAILED")
	}

	b, summaryB := f.open(t, f.secondConfig, f.secondVaultID)
	assertLocalGenesisSummary(t, summaryB, f.secondVaultID)

	// A plain value copy shares the exact state and close barrier. Closing the
	// copy must close the original; it must not create a fresh usable wrapper.
	copyValue := *a
	if err := copyValue.Close(); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_CLOSE_COPY_FAILED")
	}
	if err := a.Close(); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_CLOSE_A_NOT_IDEMPOTENT")
	}
	if _, err := a.Summary(); err == nil {
		t.Fatal("LOCAL_GENESIS_SESSION_CLOSED_A_SUMMARIZED")
	}
	if _, err := copyValue.Summary(); err == nil {
		t.Fatal("LOCAL_GENESIS_SESSION_CLOSED_COPY_REVIVED")
	}
	if !f.session.Unlocked() {
		t.Fatal("LOCAL_GENESIS_SESSION_CLOSE_A_LOCKED_PARENT")
	}
	after, err := b.Summary()
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_SIBLING_UNAVAILABLE_AFTER_CLOSE_A")
	}
	assertLocalGenesisSummary(t, after, f.secondVaultID)
	if err := b.Close(); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_CLOSE_B_FAILED")
	}
}

func TestLocalGenesisSessionWrongFactorsDoNotHurtSibling(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)

	session, summary, err := OpenLocalGenesisSession(f.session, f.firstConfig,
		f.f.proposal.BackendRoot, f.firstVaultID, []byte("wrong-factor"), f.f.key)
	if !errors.Is(err, personal.ErrVaultFileScopedFactors) || session != nil || summary.Items != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_WRONG_FACTOR_ACCEPTED")
	}
	after, err := b.Summary()
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_WRONG_FACTOR_HURT_SIBLING")
	}
	assertLocalGenesisSummary(t, after, f.secondVaultID)

	a, fresh := f.open(t, f.firstConfig, f.firstVaultID)
	assertLocalGenesisSummary(t, fresh, f.firstVaultID)
	if err := a.Close(); err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_FRESH_AFTER_WRONG_FACTOR_CLOSE_FAILED")
	}
}

func TestLocalGenesisSessionRejectsForeignLocatorAndCompanion(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)

	cases := []struct {
		name    string
		config  string
		root    string
		vaultID string
	}{
		{"foreign-selector", f.firstConfig, f.f.proposal.BackendRoot, f.secondVaultID},
		{"foreign-workspace", f.firstConfig, filepath.Join(f.f.root, "foreign-backend"), f.firstVaultID},
	}
	for _, tc := range cases {
		session, summary, err := OpenLocalGenesisSession(f.session, tc.config, tc.root, tc.vaultID, f.f.password, f.f.key)
		if !errors.Is(err, ErrLocalReview) || session != nil || summary.Items != nil {
			t.Fatalf("LOCAL_GENESIS_SESSION_FOREIGN_ACCEPTED_%s", tc.name)
		}
	}

	companionPath, err := CompanionPath(f.firstConfig)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_COMPANION_PATH_FAILED")
	}
	originalCompanion, err := os.ReadFile(companionPath)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_COMPANION_READ_FAILED")
	}
	replaceLocalGenesisFileStable(t, companionPath, []byte("{}"))
	t.Cleanup(func() { _ = os.WriteFile(companionPath, originalCompanion, 0600) })
	session, summary, err := OpenLocalGenesisSession(f.session, f.firstConfig,
		f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key)
	if !errors.Is(err, ErrLocalReview) || session != nil || summary.Items != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_CORRUPT_COMPANION_ACCEPTED")
	}
	after, err := b.Summary()
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_BAD_COMPANION_HURT_SIBLING")
	}
	assertLocalGenesisSummary(t, after, f.secondVaultID)
}

func TestLocalGenesisSessionStableReplacementIsTerminal(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)

	targets := []struct {
		name string
		path string
		make func(*testing.T) []byte
	}{
		{"manifest", f.firstConfig, func(t *testing.T) []byte {
			raw, err := os.ReadFile(f.firstConfig)
			if err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_MANIFEST_READ_FAILED")
			}
			return append(raw, '\n')
		}},
		{"companion", "", func(t *testing.T) []byte {
			path, err := CompanionPath(f.secondConfig)
			if err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_SECOND_COMPANION_PATH_FAILED")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_SECOND_COMPANION_READ_FAILED")
			}
			return raw
		}},
		{"journal", "", func(t *testing.T) []byte {
			raw, err := os.ReadFile(filepath.Join(filepath.Dir(f.f.proposal.Journal), "second.journal"))
			if err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_SECOND_JOURNAL_READ_FAILED")
			}
			return raw
		}},
	}
	companionPath, err := CompanionPath(f.firstConfig)
	if err != nil {
		t.Fatal("LOCAL_GENESIS_SESSION_COMPANION_PATH_FAILED")
	}
	targets[1].path = companionPath
	targets[2].path = f.f.proposal.Journal

	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			a, summary := f.open(t, f.firstConfig, f.firstVaultID)
			assertLocalGenesisSummary(t, summary, f.firstVaultID)
			original, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_REPLACEMENT_ORIGINAL_READ_FAILED")
			}
			replaceLocalGenesisFileStable(t, tc.path, tc.make(t))
			if _, err := a.Summary(); err == nil {
				t.Fatal("LOCAL_GENESIS_SESSION_REPLACED_FILE_ACCEPTED")
			}
			if _, err := a.Summary(); err == nil {
				t.Fatal("LOCAL_GENESIS_SESSION_FAILED_WRAPPER_REVIVED")
			}
			replaceLocalGenesisFileStable(t, tc.path, original)
			if _, err := a.Summary(); err == nil {
				t.Fatal("LOCAL_GENESIS_SESSION_RESTORED_FILE_REVIVED_WRAPPER")
			}
			if err := a.Close(); err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_REPLACED_CLOSE_FAILED")
			}
			if err := a.Close(); err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_REPLACED_CLOSE_NOT_IDEMPOTENT")
			}
			if !f.session.Unlocked() {
				t.Fatal("LOCAL_GENESIS_SESSION_REPLACEMENT_LOCKED_PARENT")
			}
			after, err := b.Summary()
			if err != nil {
				t.Fatal("LOCAL_GENESIS_SESSION_REPLACEMENT_HURT_SIBLING")
			}
			assertLocalGenesisSummary(t, after, f.secondVaultID)
		})
	}
}

func TestLocalGenesisSessionPosteriorDoesNotDeliverLateSummary(t *testing.T) {
	t.Run("parent-lock-during-open", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		old := localGenesisCandidateReadyForTest
		localGenesisCandidateReadyForTest = func() { f.session.RequestLock() }
		t.Cleanup(func() { localGenesisCandidateReadyForTest = old })

		session, summary, err := OpenLocalGenesisSession(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, f.f.password, f.f.key)
		if err == nil || session != nil || summary.Items != nil {
			t.Fatal("LOCAL_GENESIS_SESSION_LATE_OPEN_SUMMARY_DELIVERED")
		}
	})

	t.Run("parent-lock-during-summary", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		a, _ := f.open(t, f.firstConfig, f.firstVaultID)
		old := localGenesisSummaryReadyForTest
		localGenesisSummaryReadyForTest = func() { f.session.RequestLock() }
		t.Cleanup(func() { localGenesisSummaryReadyForTest = old })

		summary, err := a.Summary()
		if err == nil || summary.Items != nil {
			t.Fatal("LOCAL_GENESIS_SESSION_LATE_PARENT_LOCK_SUMMARY_DELIVERED")
		}
		if err := a.Close(); err != nil {
			t.Fatal("LOCAL_GENESIS_SESSION_LATE_PARENT_LOCK_CLOSE_FAILED")
		}
	})

	t.Run("close-during-summary", func(t *testing.T) {
		f := newLocalGenesisTwoVaultFixture(t)
		a, _ := f.open(t, f.firstConfig, f.firstVaultID)
		b, _ := f.open(t, f.secondConfig, f.secondVaultID)
		old := localGenesisSummaryReadyForTest
		localGenesisSummaryReadyForTest = func() { _ = a.Close() }
		t.Cleanup(func() { localGenesisSummaryReadyForTest = old })

		summary, err := a.Summary()
		if err == nil || summary.Items != nil {
			t.Fatal("LOCAL_GENESIS_SESSION_LATE_CLOSE_SUMMARY_DELIVERED")
		}
		if _, err := a.Summary(); err == nil {
			t.Fatal("LOCAL_GENESIS_SESSION_CLOSED_IN_HOOK_REVIVED")
		}
		if !f.session.Unlocked() {
			t.Fatal("LOCAL_GENESIS_SESSION_CLOSE_HOOK_LOCKED_PARENT")
		}
		after, err := b.Summary()
		if err != nil {
			t.Fatal("LOCAL_GENESIS_SESSION_CLOSE_HOOK_HURT_SIBLING")
		}
		assertLocalGenesisSummary(t, after, f.secondVaultID)
	})
}
