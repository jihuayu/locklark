//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

type localCustodyFileFixture struct {
	v        *localIsolationVault
	settled  *localIsolationSettled
	expected vaultfile.PolicyCheckpoint
	artifact []byte
	material []byte
	factor   *personal.VaultFileBackupRecoveryFactor
}

func newLocalCustodyFileFixture(t *testing.T, label string, password, key []byte,
	secret string) *localCustodyFileFixture {
	t.Helper()
	f := localIsolationCreation(t, label, password, key)
	v := newLocalIsolationVault(t, f, localFirstWriteTitle)
	v.item.Password = secret
	result := v.write(t)
	settled := localIsolationReadSettled(t, v, result)
	expected := localCustodyCheckpoint(v.checkpoint)
	custody, factor, err := PrepareLocalOwnedBackupCustody(context.Background(),
		v.session, v.config, v.manifest.BackendRoot, v.manifest.VaultID,
		v.manifest.Journal, expected, f.password, f.key)
	if err != nil || len(custody.Artifact) == 0 || factor == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_PREPARE_FAILED")
	}
	fx := &localCustodyFileFixture{
		v: v, settled: settled, expected: expected,
		artifact: bytes.Clone(custody.Artifact),
		material: factor.Material(),
	}
	custody.Clear()
	factor.Clear()
	fx.factor, err = ImportLocalOwnedBackupRecoveryFactor(fx.material)
	if err != nil || fx.factor == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_IMPORT_FAILED")
	}
	t.Cleanup(fx.clear)
	return fx
}

func (f *localCustodyFileFixture) clear() {
	if f == nil {
		return
	}
	clear(f.artifact)
	clear(f.material)
	clear(f.expected.OwnerRootPublicKey)
	clear(f.expected.PolicyDigest)
	f.factor.Clear()
	if f.settled != nil {
		f.settled.clear()
	}
	*f = localCustodyFileFixture{}
}

func localCustodyFileAssertPrivate(t *testing.T, path string, want []byte) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_NOT_PRIVATE_REGULAR")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || info.Size() != int64(len(want)) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_NOT_OWNED_SINGLE_LINK")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, want) {
		clear(raw)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_BYTES_CHANGED")
	}
	clear(raw)
}

func localCustodyFileAssertNoTemporary(t *testing.T, dir string, final string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_DIR_READ_FAILED")
	}
	seen := false
	for _, entry := range entries {
		if entry.Name() == final {
			if seen {
				t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_DUPLICATE_FINAL")
			}
			seen = true
			continue
		}
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_TEMPORARY_RETAINED")
	}
	if !seen {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_FINAL_MISSING")
	}
}

func localCustodyFileRefuse(t *testing.T, code string, fn func() error) {
	t.Helper()
	if err := fn(); !errors.Is(err, ErrLocalOwnedBackupReview) {
		t.Fatal(code)
	}
}

func TestLocalOwnedBackupCustodyFileDurableSaveAndReopen(t *testing.T) {
	passwordA := []byte("local-custody-file-a")
	keyA := bytes.Repeat([]byte{0x2e}, 16)
	passwordB := []byte("local-custody-file-b")
	keyB := bytes.Repeat([]byte{0x6f}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)

	a := newLocalCustodyFileFixture(t, "custody-file-a", passwordA, keyA,
		localFirstWriteSecret+"-file-a")
	b := newLocalCustodyFileFixture(t, "custody-file-b", passwordB, keyB,
		localFirstWriteSecret+"-file-b")
	if bytes.Equal(a.artifact, b.artifact) || bytes.Contains(a.artifact, b.material) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_SCOPES_NOT_INDEPENDENT")
	}
	expectedA := localCustodyCheckpoint(&a.expected)
	defer clear(expectedA.OwnerRootPublicKey)
	defer clear(expectedA.PolicyDigest)
	expectedB := localCustodyCheckpoint(&b.expected)
	defer clear(expectedB.OwnerRootPublicKey)
	defer clear(expectedB.PolicyDigest)

	dir := filepath.Join(a.v.f.root, "custody")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_DIR_FAILED")
	}
	path := filepath.Join(dir, "vault-a.custody")
	pin, err := SaveLocalOwnedBackupCustodyFile(context.Background(), path,
		a.artifact, expectedA, a.factor)
	if err != nil || !pin.valid() || pin.Path != path ||
		pin.VaultID != expectedA.VaultID || pin.SourceIdentity == ([sha256.Size]byte{}) ||
		pin.ArtifactSize != int64(len(a.artifact)) ||
		pin.ArtifactSHA256 != sha256.Sum256(a.artifact) ||
		pin.JournalRevision != string(a.settled.record.SuccessorRevision) ||
		pin.BackendRevision != string(a.settled.record.SuccessorRevision) ||
		pin.OriginRevision != string(a.settled.record.GenesisRevision) ||
		pin.ContentSeq != 1 {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_SAVE_FAILED")
	}
	localCustodyFileAssertPrivate(t, path, a.artifact)
	localCustodyFileAssertNoTemporary(t, dir, filepath.Base(path))
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, a.material) || bytes.Contains(raw, b.material) ||
		!bytes.Equal(raw, a.artifact) {
		clear(raw)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_FACTOR_OR_WIRE_LEAK")
	}
	clear(raw)

	opened, actual, err := OpenLocalOwnedBackupCustodyFile(context.Background(), path,
		pin, expectedA, a.factor)
	if err != nil || actual != pin {
		opened.Clear()
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_REOPEN_FAILED")
	}
	defer opened.Clear()
	localCustodyAssertSource(t, opened, expectedA,
		a.settled.record.SuccessorBytes, a.settled.record.GenesisBytes,
		string(a.settled.record.SuccessorRevision), string(a.settled.record.SuccessorRevision),
		string(a.settled.record.GenesisRevision), 1,
		pin.SourceIdentity, "LOCAL_OWNED_BACKUP_CUSTODY_FILE_SOURCE_MISMATCH")
	reopened, actualAgain, err := OpenLocalOwnedBackupCustodyFile(context.Background(), path,
		actual, expectedA, a.factor)
	if err != nil || actualAgain != pin {
		reopened.Clear()
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_REOPEN_ALIAS_FAILED")
	}
	reopened.Clear()

	// The exact same bytes cannot silently replace the published file.
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_ORIGINAL_READ_FAILED")
	}
	if _, err := SaveLocalOwnedBackupCustodyFile(context.Background(), path,
		a.artifact, expectedA, a.factor); !errors.Is(err, ErrLocalOwnedBackupConflict) {
		clear(original)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_OVERWROTE_EXISTING")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		clear(original)
		clear(after)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_OVERWRITE_CHANGED_ORIGINAL")
	}
	clear(original)
	clear(after)
	localCustodyFileAssertNoTemporary(t, dir, filepath.Base(path))
	alias := filepath.Join(dir, "alias")
	if os.Symlink(path, alias) != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_SYMLINK_FAILED")
	}
	if _, err := SaveLocalOwnedBackupCustodyFile(context.Background(), alias,
		a.artifact, expectedA, a.factor); !errors.Is(err, ErrLocalOwnedBackupConflict) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_SYMLINK_ACCEPTED")
	}
	localCustodyFileAssertPrivate(t, path, a.artifact)

	// Wrong vault, wrong factor and tampered artifact are refused before any
	// new file appears.
	wrongPath := filepath.Join(dir, "wrong.custody")
	localCustodyFileRefuse(t, "LOCAL_OWNED_BACKUP_CUSTODY_FILE_WRONG_CHECKPOINT_SAVE", func() error {
		_, err := SaveLocalOwnedBackupCustodyFile(context.Background(), wrongPath,
			a.artifact, expectedB, a.factor)
		return err
	})
	localCustodyFileRefuse(t, "LOCAL_OWNED_BACKUP_CUSTODY_FILE_WRONG_FACTOR_SAVE", func() error {
		_, err := SaveLocalOwnedBackupCustodyFile(context.Background(), wrongPath,
			a.artifact, expectedA, b.factor)
		return err
	})
	tamperedArchive := bytes.Clone(a.artifact)
	tamperedArchive[len(tamperedArchive)/2] ^= 0x40
	localCustodyFileRefuse(t, "LOCAL_OWNED_BACKUP_CUSTODY_FILE_TAMPERED_SAVE", func() error {
		_, err := SaveLocalOwnedBackupCustodyFile(context.Background(), wrongPath,
			tamperedArchive, expectedA, a.factor)
		return err
	})
	clear(tamperedArchive)
	if _, err := os.Lstat(wrongPath); !os.IsNotExist(err) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_REFUSAL_WROTE_DESTINATION")
	}
	localCustodyFileRefuse(t, "LOCAL_OWNED_BACKUP_CUSTODY_FILE_WRONG_CHECKPOINT_OPEN", func() error {
		wrongOpened, _, err := OpenLocalOwnedBackupCustodyFile(context.Background(), path,
			pin, expectedB, a.factor)
		wrongOpened.Clear()
		return err
	})
	localCustodyFileRefuse(t, "LOCAL_OWNED_BACKUP_CUSTODY_FILE_WRONG_FACTOR_OPEN", func() error {
		wrongOpened, _, err := OpenLocalOwnedBackupCustodyFile(context.Background(), path,
			pin, expectedA, b.factor)
		wrongOpened.Clear()
		return err
	})
	localCustodyFileRefuse(t, "LOCAL_OWNED_BACKUP_CUSTODY_FILE_WRONG_PIN_OPEN", func() error {
		wrongPin := pin
		wrongPin.SourceIdentity = sha256.Sum256([]byte("wrong source identity"))
		wrongOpened, _, err := OpenLocalOwnedBackupCustodyFile(context.Background(), path,
			wrongPin, expectedA, a.factor)
		wrongOpened.Clear()
		return err
	})

	// A byte change after publication is a digest refusal, not a leap to the
	// tampered source.
	tamperPath := filepath.Join(dir, "tamper.custody")
	tamperPin, err := SaveLocalOwnedBackupCustodyFile(context.Background(), tamperPath,
		a.artifact, expectedA, a.factor)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_TAMPER_SETUP_FAILED")
	}
	tamperedFile, err := os.ReadFile(tamperPath)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_TAMPER_READ_FAILED")
	}
	tamperedFile[len(tamperedFile)/2] ^= 0x20
	if err := os.WriteFile(tamperPath, tamperedFile, 0600); err != nil {
		clear(tamperedFile)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_TAMPER_WRITE_FAILED")
	}
	clear(tamperedFile)
	if tamperOpened, _, err := OpenLocalOwnedBackupCustodyFile(context.Background(), tamperPath,
		tamperPin, expectedA, a.factor); !errors.Is(err, ErrLocalOwnedBackupConflict) ||
		tamperOpened.Source.VaultID != "" {
		tamperOpened.Clear()
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_TAMPER_ACCEPTED")
	}

	// Cancellation before the irreversible publish leaves no final name and no
	// temporary or factor material.
	cancelDir := filepath.Join(a.v.f.root, "custody-cancel")
	if os.Mkdir(cancelDir, 0700) != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_CANCEL_DIR_FAILED")
	}
	cancelPath := filepath.Join(cancelDir, "canceled.custody")
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SaveLocalOwnedBackupCustodyFile(cancelCtx, cancelPath,
		a.artifact, expectedA, a.factor); !errors.Is(err, ErrLocalOwnedBackupCanceled) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_CANCEL_NOT_REFUSED")
	}
	if _, err := os.Lstat(cancelPath); !os.IsNotExist(err) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_CANCEL_WROTE_DESTINATION")
	}
	entries, err := os.ReadDir(cancelDir)
	if err != nil || len(entries) != 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_CANCEL_LEFTOVER")
	}
	if cancelOpened, _, err := OpenLocalOwnedBackupCustodyFile(cancelCtx, path,
		pin, expectedA, a.factor); !errors.Is(err, ErrLocalOwnedBackupCanceled) ||
		cancelOpened.Source.VaultID != "" {
		cancelOpened.Clear()
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_CANCEL_OPEN_NOT_REFUSED")
	}

	// A post-visibility failure is explicitly unknown, preserves the complete
	// file, and is recoverable with a fresh exact reopen without a write retry.
	unknownPath := filepath.Join(dir, "unknown.custody")
	unknownPin, err := saveLocalOwnedBackupCustodyFile(context.Background(), unknownPath,
		a.artifact, expectedA, a.factor, localCustodyFileSaveHooks{
			afterDurablePublish: func() error {
				return errors.New("injected post-visibility failure")
			},
		})
	if !errors.Is(err, ErrLocalOwnedBackupUnknown) || unknownPin.Path != unknownPath ||
		unknownPin.ArtifactSHA256 != pin.ArtifactSHA256 {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_UNKNOWN_NOT_REPORTED")
	}
	localCustodyFileAssertPrivate(t, unknownPath, a.artifact)
	if _, err := SaveLocalOwnedBackupCustodyFile(context.Background(), unknownPath,
		a.artifact, expectedA, a.factor); !errors.Is(err, ErrLocalOwnedBackupConflict) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_UNKNOWN_RETRIED_OVERWRITE")
	}
	recovered, recoveredActual, err := OpenLocalOwnedBackupCustodyFile(context.Background(),
		unknownPath, unknownPin, expectedA, a.factor)
	if err != nil || recoveredActual != unknownPin ||
		recovered.SourceIdentity != pin.SourceIdentity {
		recovered.Clear()
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_UNKNOWN_NOT_RECOVERABLE")
	}
	recovered.Clear()

	// A changed published file is not reported as success even though the
	// final name is visible; the real bytes remain for explicit inspection.
	changedPath := filepath.Join(dir, "changed.custody")
	changedPin, err := saveLocalOwnedBackupCustodyFile(context.Background(), changedPath,
		a.artifact, expectedA, a.factor, localCustodyFileSaveHooks{
			afterDurablePublish: func() error {
				return os.WriteFile(changedPath, []byte("changed after visibility"), 0600)
			},
		})
	if !errors.Is(err, ErrLocalOwnedBackupUnknown) || changedPin.Path != changedPath {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_STAGED_CHANGE_ACCEPTED")
	}
	if _, _, err := OpenLocalOwnedBackupCustodyFile(context.Background(), changedPath,
		changedPin, expectedA, a.factor); !errors.Is(err, ErrLocalOwnedBackupConflict) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_STAGED_CHANGE_REOPEN_ACCEPTED")
	}

	for _, value := range []any{pin, actual, unknownPin} {
		if formatted := fmt.Sprintf("%v", value); bytes.Contains([]byte(formatted), a.material) {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FILE_RESULT_LEAKED_FACTOR")
		}
	}
}
