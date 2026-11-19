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
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const localRestorePreflightRedacted = "[local owned backup restore admission]"

type localRestorePreflightFixture struct {
	fx       *localCustodyFileFixture
	oldPath  string
	path     string
	saved    LocalOwnedBackupCustodyFile
	pin      LocalOwnedBackupRestoreSourcePin
	expected vaultfile.PolicyCheckpoint
	locator  LocalOwnedBackupRestoreBackendLocator
}

func newLocalRestorePreflightFixture(t *testing.T, fx *localCustodyFileFixture,
	label string) *localRestorePreflightFixture {
	t.Helper()
	dir := filepath.Join(fx.v.f.root, "restore-preflight-"+label)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_DIR_FAILED")
	}
	oldPath := filepath.Join(dir, "vault.custody")
	saved, err := SaveLocalOwnedBackupCustodyFile(context.Background(), oldPath,
		fx.artifact, localCustodyCheckpoint(&fx.expected), fx.factor)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SAVE_FAILED")
	}
	f := &localRestorePreflightFixture{
		fx:       fx,
		oldPath:  oldPath,
		saved:    saved,
		pin:      NewLocalOwnedBackupRestoreSourcePin(saved),
		expected: localCustodyCheckpoint(&fx.expected),
		locator: LocalOwnedBackupRestoreBackendLocator{
			Root: fx.v.manifest.BackendRoot, Name: fx.v.manifest.Name,
		},
	}
	f.path = filepath.Join(t.TempDir(), "vault.custody")
	if err := os.Rename(oldPath, f.path); err != nil {
		f.clear()
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_TRANSFER_FAILED")
	}
	if _, err := os.Lstat(oldPath); !os.IsNotExist(err) {
		f.clear()
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_OLD_PATH_RETAINED")
	}
	t.Cleanup(f.clear)
	return f
}

func (f *localRestorePreflightFixture) clear() {
	if f == nil {
		return
	}
	clear(f.expected.OwnerRootPublicKey)
	clear(f.expected.PolicyDigest)
	*f = localRestorePreflightFixture{}
}

func localRestorePreflightRefuse(t *testing.T, code string, category error,
	admission LocalOwnedBackupRestoreAdmission, err error) {
	t.Helper()
	if !errors.Is(err, category) || admission != (LocalOwnedBackupRestoreAdmission{}) {
		t.Fatal(code)
	}
}

func localRestorePreflightSourceDigest(t *testing.T, v *localIsolationVault) [sha256.Size]byte {
	t.Helper()
	journal, err := os.ReadFile(v.manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_JOURNAL_READ_FAILED")
	}
	defer clear(journal)
	companionPath, err := CompanionPath(v.config)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_COMPANION_PATH_FAILED")
	}
	companion, err := os.ReadFile(companionPath)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_COMPANION_READ_FAILED")
	}
	defer clear(companion)
	target, revision := localFirstReadBackend(t, v.manifest)
	defer clear(target)

	h := sha256.New()
	for _, part := range [][sha256.Size]byte{
		sha256.Sum256(journal), sha256.Sum256(companion), sha256.Sum256(target),
	} {
		_, _ = h.Write(part[:])
	}
	_, _ = h.Write([]byte(revision))
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func localRestorePreflightTarget(t *testing.T, v *localIsolationVault) ([]byte, vaultfilebackend.Revision) {
	t.Helper()
	return localFirstReadBackend(t, v.manifest)
}

func TestLocalOwnedBackupRestorePreflightAdmitsTransferredExactCurrent(t *testing.T) {
	password := []byte("local-restore-preflight-exact")
	key := bytes.Repeat([]byte{0x4a}, 16)
	defer clear(password)
	defer clear(key)

	fx := newLocalCustodyFileFixture(t, "restore-preflight-exact", password, key,
		localFirstWriteSecret+"-restore-preflight")
	transfer := newLocalRestorePreflightFixture(t, fx, "exact")
	before := localRestorePreflightSourceDigest(t, fx.v)

	// The producer session is gone and the original personal database/config
	// are removed after transfer. Admission must need neither.
	fx.v.session.Lock()
	if fx.v.session.Unlocked() {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SESSION_STILL_LIVE")
	}
	if err := os.Remove(fx.v.config); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_CONFIG_REMOVE_FAILED")
	}
	if err := os.Remove(fx.v.manifest.PersonalFile); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_DATABASE_REMOVE_FAILED")
	}

	admission, err := AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_ADMISSION_FAILED")
	}
	if admission.VaultID != transfer.saved.VaultID ||
		admission.ArtifactSize != transfer.saved.ArtifactSize ||
		admission.ArtifactSHA256 != transfer.saved.ArtifactSHA256 ||
		admission.SourceIdentity != transfer.saved.SourceIdentity ||
		admission.CheckpointDigest != transfer.saved.CheckpointDigest ||
		admission.JournalRevision != transfer.saved.JournalRevision ||
		admission.BackendRevision != transfer.saved.BackendRevision ||
		admission.OriginRevision != transfer.saved.OriginRevision ||
		admission.ContentSeq != transfer.saved.ContentSeq ||
		admission.TargetRevision != transfer.saved.BackendRevision ||
		admission.TargetSHA256 != sha256.Sum256(fx.settled.record.SuccessorBytes) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_OBSERVATION_MISMATCH")
	}
	if _, err := os.Lstat(transfer.path); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_TRANSFER_MISSING")
	}
	if _, err := os.Lstat(transfer.oldPath); !os.IsNotExist(err) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_OLD_CUSTODY_PATH_RETAINED")
	}
	if after := localRestorePreflightSourceDigest(t, fx.v); after != before {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SOURCE_MUTATED")
	}
	target, revision := localRestorePreflightTarget(t, fx.v)
	defer clear(target)
	if !bytes.Equal(target, fx.settled.record.SuccessorBytes) ||
		revision != vaultfilebackend.Revision(transfer.saved.BackendRevision) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_TARGET_MUTATED")
	}

	for _, value := range []any{admission, &admission} {
		formatted := fmt.Sprintf("%v|%+v|%#v", value, value, value)
		if formatted != localRestorePreflightRedacted+"|"+
			localRestorePreflightRedacted+"|"+localRestorePreflightRedacted {
			t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_FORMAT_NOT_REDACTED")
		}
		for _, private := range []string{
			transfer.path, transfer.locator.Root, transfer.locator.Name,
			fx.v.manifest.VaultID, admission.JournalRevision,
			admission.BackendRevision, admission.OriginRevision,
			fx.v.item.Password,
		} {
			if strings.Contains(formatted, private) {
				t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SAFE_FORMAT_LEAKED")
			}
		}
	}
	encoded, err := json.Marshal(admission)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_JSON_EXPOSED_FIELDS")
	}
	var nilAdmission *LocalOwnedBackupRestoreAdmission
	if formatted := fmt.Sprintf("%v", nilAdmission); formatted != localRestorePreflightRedacted {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_NIL_FORMAT_NOT_REDACTED")
	}
}

func TestLocalOwnedBackupRestorePreflightRefusesUnscopedInputs(t *testing.T) {
	passwordA := []byte("local-restore-preflight-scope-a")
	passwordB := []byte("local-restore-preflight-scope-b")
	keyA := bytes.Repeat([]byte{0x2b}, 16)
	keyB := bytes.Repeat([]byte{0x6c}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)

	a := newLocalCustodyFileFixture(t, "restore-preflight-scope-a", passwordA, keyA,
		localFirstWriteSecret+"-restore-scope-a")
	b := newLocalCustodyFileFixture(t, "restore-preflight-scope-b", passwordB, keyB,
		localFirstWriteSecret+"-restore-scope-b")
	ta := newLocalRestorePreflightFixture(t, a, "scope-a")
	tb := newLocalRestorePreflightFixture(t, b, "scope-b")
	beforeA := localRestorePreflightSourceDigest(t, a.v)
	beforeB := localRestorePreflightSourceDigest(t, b.v)
	targetA, revisionA := localRestorePreflightTarget(t, a.v)
	defer clear(targetA)

	admission, err := AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		ta.path, ta.pin, tb.expected, a.factor, ta.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_WRONG_CHECKPOINT_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)

	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		ta.path, ta.pin, ta.expected, b.factor, ta.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_WRONG_FACTOR_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)

	wrongVault := ta.pin
	wrongVault.VaultID = tb.saved.VaultID
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		ta.path, wrongVault, ta.expected, a.factor, ta.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_WRONG_VAULT_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)

	wrongDigest := ta.pin
	wrongDigest.CheckpointDigest = tb.saved.CheckpointDigest
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		ta.path, wrongDigest, ta.expected, a.factor, ta.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_WRONG_DIGEST_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)

	wrongIdentity := ta.pin
	wrongIdentity.SourceIdentity = sha256.Sum256([]byte("foreign source identity"))
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		ta.path, wrongIdentity, ta.expected, a.factor, ta.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_WRONG_IDENTITY_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)

	raw, err := os.ReadFile(ta.path)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_TAMPER_READ_FAILED")
	}
	raw[len(raw)/2] ^= 0x40
	if err := os.WriteFile(ta.path, raw, 0600); err != nil {
		clear(raw)
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_TAMPER_WRITE_FAILED")
	}
	clear(raw)
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		ta.path, ta.pin, ta.expected, a.factor, ta.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_TAMPERED_ARTIFACT_ACCEPTED",
		ErrLocalOwnedBackupConflict, admission, err)

	if after := localRestorePreflightSourceDigest(t, a.v); after != beforeA {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SCOPE_MUTATED_A")
	}
	if after := localRestorePreflightSourceDigest(t, b.v); after != beforeB {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SCOPE_MUTATED_B")
	}
	target, revision := localRestorePreflightTarget(t, a.v)
	defer clear(target)
	if !bytes.Equal(target, targetA) || revision != revisionA {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SCOPE_TARGET_MUTATED")
	}
}

func TestLocalOwnedBackupRestorePreflightRefusesDivergedTarget(t *testing.T) {
	password := []byte("local-restore-preflight-diverged")
	key := bytes.Repeat([]byte{0x5d}, 16)
	defer clear(password)
	defer clear(key)

	fx := newLocalCustodyFileFixture(t, "restore-preflight-diverged", password, key,
		localFirstWriteSecret+"-restore-diverged")
	transfer := newLocalRestorePreflightFixture(t, fx, "diverged")

	sameBytesRevision := localFirstRewriteBackend(t, fx.v.manifest,
		fx.settled.record.SuccessorBytes)
	if sameBytesRevision == vaultfilebackend.Revision(transfer.saved.BackendRevision) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SAME_BYTES_REVISION_NOT_NEW")
	}
	admission, err := AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_NEWER_SAME_BYTES_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)
	target, revision := localRestorePreflightTarget(t, fx.v)
	if !bytes.Equal(target, fx.settled.record.SuccessorBytes) || revision != sameBytesRevision {
		clear(target)
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_SAME_BYTES_TARGET_MUTATED")
	}
	clear(target)

	differentRevision := localFirstRewriteBackend(t, fx.v.manifest,
		fx.settled.record.GenesisBytes)
	if differentRevision == sameBytesRevision {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_DIFFERENT_REVISION_NOT_NEW")
	}
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_DIFFERENT_CONTENT_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)
	target, revision = localRestorePreflightTarget(t, fx.v)
	if !bytes.Equal(target, fx.settled.record.GenesisBytes) || revision != differentRevision {
		clear(target)
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_DIFFERENT_TARGET_MUTATED")
	}
	clear(target)

	passwordB := []byte("local-restore-preflight-diverged-b")
	keyB := bytes.Repeat([]byte{0x7e}, 16)
	defer clear(passwordB)
	defer clear(keyB)
	b := newLocalCustodyFileFixture(t, "restore-preflight-diverged-b", passwordB, keyB,
		localFirstWriteSecret+"-restore-diverged-b")
	foreignRevision := localFirstRewriteBackend(t, fx.v.manifest,
		b.settled.record.SuccessorBytes)
	if foreignRevision == differentRevision {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_FOREIGN_REVISION_NOT_NEW")
	}
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_FOREIGN_POLICY_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)
	target, revision = localRestorePreflightTarget(t, fx.v)
	if !bytes.Equal(target, b.settled.record.SuccessorBytes) || revision != foreignRevision {
		clear(target)
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_FOREIGN_TARGET_MUTATED")
	}
	clear(target)
}

func TestLocalOwnedBackupRestorePreflightRefusesMissingInvalidAndCanceled(t *testing.T) {
	password := []byte("local-restore-preflight-missing")
	key := bytes.Repeat([]byte{0x3c}, 16)
	defer clear(password)
	defer clear(key)

	fx := newLocalCustodyFileFixture(t, "restore-preflight-missing", password, key,
		localFirstWriteSecret+"-restore-missing")
	transfer := newLocalRestorePreflightFixture(t, fx, "missing")
	before := localRestorePreflightSourceDigest(t, fx.v)
	target, revision := localRestorePreflightTarget(t, fx.v)
	defer clear(target)

	admission, err := AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: "relative-root", Name: transfer.locator.Name})
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_RELATIVE_ROOT_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)

	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: transfer.locator.Root, Name: ""})
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_EMPTY_NAME_ACCEPTED",
		ErrLocalOwnedBackupReview, admission, err)

	absentName := fx.v.manifest.Name + "-absent"
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: transfer.locator.Root, Name: absentName})
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_MISSING_TARGET_ACCEPTED",
		ErrLocalOwnedBackupConflict, admission, err)
	backend, err := vaultfilebackend.OpenExistingDir(transfer.locator.Root)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_MISSING_BACKEND_OPEN_FAILED")
	}
	_, readErr := backend.Read(context.Background(), absentName)
	closeErr := backend.Close()
	if !errors.Is(readErr, vaultfilebackend.ErrNotFound) || closeErr != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_MISSING_TARGET_CREATED")
	}

	missingRoot := filepath.Join(t.TempDir(), "missing-backend")
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(context.Background(),
		transfer.path, transfer.pin, transfer.expected, fx.factor,
		LocalOwnedBackupRestoreBackendLocator{Root: missingRoot, Name: transfer.locator.Name})
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_MISSING_ROOT_ACCEPTED",
		ErrLocalOwnedBackupConflict, admission, err)
	if _, err := os.Lstat(missingRoot); !os.IsNotExist(err) {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_MISSING_ROOT_CREATED")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	admission, err = AdmitTransferredLocalOwnedBackupForRestore(canceled,
		transfer.path, transfer.pin, transfer.expected, fx.factor, transfer.locator)
	localRestorePreflightRefuse(t, "LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_CANCEL_ACCEPTED",
		ErrLocalOwnedBackupCanceled, admission, err)

	if after := localRestorePreflightSourceDigest(t, fx.v); after != before {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_MISSING_SOURCE_MUTATED")
	}
	afterTarget, afterRevision := localRestorePreflightTarget(t, fx.v)
	defer clear(afterTarget)
	if !bytes.Equal(afterTarget, target) || afterRevision != revision {
		t.Fatal("LOCAL_OWNED_BACKUP_RESTORE_PREFLIGHT_MISSING_TARGET_MUTATED")
	}
}
