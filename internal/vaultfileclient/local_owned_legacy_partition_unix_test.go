//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

type localStagedLegacyPartitionSource struct {
	archive  []byte
	password string
	key      []byte
	kit      string
	itemID   string
}

func newLocalStagedLegacyPartitionSource(t *testing.T) *localStagedLegacyPartitionSource {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "legacy-source")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_DIR_FAILED")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_DIR_MODE_FAILED")
	}
	path := filepath.Join(dir, "source.ll")
	archivePath := filepath.Join(dir, "source.llb")
	password := "staged-legacy-source-factor"
	key := bytes.Repeat([]byte{0x47}, 16)
	if err := personal.Create(path, password, key); err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_CREATE_FAILED")
	}
	session, err := personal.UnlockSession(path, []byte(password), key, time.Minute)
	if err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := session.RegisterMutation(gate); err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_GATE_FAILED")
	}
	itemID, _, err := session.AddItem(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: vault.DefaultVaultID,
		Title: "Staged legacy login", Username: "staged-legacy-user",
		Password: "staged-legacy-secret",
	}, gate)
	if err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_ITEM_FAILED")
	}
	kit, err := personal.Backup(path, archivePath, password, key)
	if err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_BACKUP_FAILED")
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal("STAGED_LEGACY_SOURCE_ARCHIVE_FAILED")
	}
	source := &localStagedLegacyPartitionSource{
		archive: archive, password: password, key: key, kit: kit, itemID: itemID,
	}
	t.Cleanup(func() {
		clear(source.archive)
		clear(source.key)
	})
	return source
}

func (s *localStagedLegacyPartitionSource) request() personal.LegacyVaultPartitionSource {
	return personal.LegacyVaultPartitionSource{
		Archive: s.archive, Password: s.password, Key: s.key,
		RecoveryKit: s.kit, VaultID: vault.DefaultVaultID,
	}
}

func TestLocalOwnedLegacyPartitionStagesAndVerifiesAcrossReopen(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	source := newLocalStagedLegacyPartitionSource(t)
	sourceDigest := sha256.Sum256(source.archive)

	journalBefore, err := os.ReadFile(fx.manifest.Journal)
	if err != nil {
		t.Fatal("STAGED_LEGACY_JOURNAL_READ_FAILED")
	}
	backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
	defer clear(backendBefore)

	result, err := StageLocalOwnedLegacyPartition(context.Background(), fx.f.session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest)
	if err != nil {
		t.Fatalf("StageLocalOwnedLegacyPartition: %v", err)
	}
	if result.VaultID != fx.manifest.VaultID || result.JournalPath != fx.manifest.Journal ||
		result.SidecarPath == "" || result.SourceArchiveSHA256 != sourceDigest ||
		result.CandidateSHA256 == ([sha256.Size]byte{}) {
		t.Fatal("STAGED_LEGACY_RESULT_BINDING_FAILED")
	}
	sidecar, err := os.ReadFile(result.SidecarPath)
	if err != nil || len(sidecar) == 0 {
		t.Fatal("STAGED_LEGACY_SIDECAR_READ_FAILED")
	}
	if sha256.Sum256(sidecar) != result.CandidateSHA256 {
		t.Fatal("STAGED_LEGACY_SIDECAR_DIGEST_MISMATCH")
	}
	journalAfterStage, err := os.ReadFile(fx.manifest.Journal)
	if err != nil || !bytes.Equal(journalAfterStage, journalBefore) {
		t.Fatal("STAGED_LEGACY_JOURNAL_CHANGED")
	}
	backendAfterStage, revisionAfterStage := localFirstReadBackend(t, fx.manifest)
	defer clear(backendAfterStage)
	if revisionAfterStage != revisionBefore || !bytes.Equal(backendAfterStage, backendBefore) {
		t.Fatal("STAGED_LEGACY_BACKEND_CHANGED")
	}
	localFirstAssertPristine(t, fx)

	// A staged sidecar is not a normal prepared proposal. The regular resume
	// path must refuse it and leave the pristine journal and live backend alone.
	if _, err := ResumeLocalGenesisFirstItem(context.Background(), fx.f.session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key); !errors.Is(err, ErrLocalOwnedFirstWriteConflict) {
		t.Fatal("STAGED_LEGACY_CREATED_REGULAR_PREPARED_PROPOSAL")
	}
	localFirstAssertPristine(t, fx)
	backendAfterResume, revisionAfterResume := localFirstReadBackend(t, fx.manifest)
	defer clear(backendAfterResume)
	if revisionAfterResume != revisionBefore || !bytes.Equal(backendAfterResume, backendBefore) {
		t.Fatal("STAGED_LEGACY_REGULAR_RESUME_WROTE_BACKEND")
	}

	// Use a genuinely reopened account and the same verified locator.
	session := localFirstUnlockFresh(t, fx.f)
	verified, err := VerifyStagedLocalOwnedLegacyPartition(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest, result.CandidateSHA256)
	if err != nil {
		t.Fatalf("VerifyStagedLocalOwnedLegacyPartition: %v", err)
	}
	defer verified.Clear()
	if verified.SourceVaultID != vault.DefaultVaultID ||
		verified.DestinationVaultID != fx.manifest.VaultID ||
		verified.SourceArchiveSHA256 != sourceDigest ||
		len(verified.ItemMapping) != 1 ||
		verified.ItemMapping[source.itemID] != source.itemID {
		t.Fatal("STAGED_LEGACY_VERIFIED_BINDING_FAILED")
	}
	sidecarAfterVerify, err := os.ReadFile(result.SidecarPath)
	if err != nil || !bytes.Equal(sidecarAfterVerify, sidecar) {
		t.Fatal("STAGED_LEGACY_VERIFY_OVERWROTE_SIDECAR")
	}
	journalAfterVerify, err := os.ReadFile(fx.manifest.Journal)
	if err != nil || !bytes.Equal(journalAfterVerify, journalBefore) {
		t.Fatal("STAGED_LEGACY_VERIFY_CHANGED_JOURNAL")
	}
	backendAfterVerify, revisionAfterVerify := localFirstReadBackend(t, fx.manifest)
	defer clear(backendAfterVerify)
	if revisionAfterVerify != revisionBefore || !bytes.Equal(backendAfterVerify, backendBefore) {
		t.Fatal("STAGED_LEGACY_VERIFY_CHANGED_BACKEND")
	}

	// Independent digests are mandatory and stale values fail closed.
	wrongSource := sourceDigest
	wrongSource[0] ^= 0xff
	if _, err := VerifyStagedLocalOwnedLegacyPartition(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), wrongSource, result.CandidateSHA256); err == nil {
		t.Fatal("STAGED_LEGACY_WRONG_SOURCE_DIGEST_ACCEPTED")
	}
	wrongCandidate := result.CandidateSHA256
	wrongCandidate[0] ^= 0xff
	if _, err := VerifyStagedLocalOwnedLegacyPartition(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest, wrongCandidate); err == nil {
		t.Fatal("STAGED_LEGACY_WRONG_CANDIDATE_DIGEST_ACCEPTED")
	}

	// A matching digest over different ciphertext must not be trusted from the
	// sidecar. Tamper deliberately after proving the successful verify above did
	// not overwrite the original bytes, then restore them for the revision test.
	tampered := bytes.Clone(sidecar)
	tampered[len(tampered)/2] ^= 0x5a
	if err := os.WriteFile(result.SidecarPath, tampered, 0600); err != nil {
		t.Fatal("STAGED_LEGACY_TAMPER_WRITE_FAILED")
	}
	tamperedDigest := sha256.Sum256(tampered)
	if _, err := VerifyStagedLocalOwnedLegacyPartition(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest, tamperedDigest); err == nil {
		t.Fatal("STAGED_LEGACY_TAMPERED_CIPHERTEXT_ACCEPTED")
	}
	clear(tampered)
	if err := os.WriteFile(result.SidecarPath, sidecar, 0600); err != nil {
		t.Fatal("STAGED_LEGACY_SIDECAR_RESTORE_FAILED")
	}
	if err := os.Chmod(result.SidecarPath, 0600); err != nil {
		t.Fatal("STAGED_LEGACY_SIDECAR_MODE_FAILED")
	}

	// The same journal bytes at a revised live backend revision are not the
	// authenticated baseline and must refuse verification.
	revised := localFirstRewriteBackend(t, fx.manifest, backendBefore)
	if revised == revisionBefore {
		t.Fatal("STAGED_LEGACY_REVISED_REVISION_UNCHANGED")
	}
	if _, err := VerifyStagedLocalOwnedLegacyPartition(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest, result.CandidateSHA256); err == nil {
		t.Fatal("STAGED_LEGACY_REVISED_BACKEND_ACCEPTED")
	}
	backendAfterRevision, revisionAfterRevision := localFirstReadBackend(t, fx.manifest)
	defer clear(backendAfterRevision)
	if revised != revisionAfterRevision || !bytes.Equal(backendAfterRevision, backendBefore) {
		t.Fatal("STAGED_LEGACY_REVISED_BACKEND_CHANGED")
	}
	journalAfterRevision, err := os.ReadFile(fx.manifest.Journal)
	if err != nil || !bytes.Equal(journalAfterRevision, journalBefore) {
		t.Fatal("STAGED_LEGACY_REVISED_VERIFY_CHANGED_JOURNAL")
	}
	sidecarAfterRevision, err := os.ReadFile(result.SidecarPath)
	if err != nil || !bytes.Equal(sidecarAfterRevision, sidecar) {
		t.Fatal("STAGED_LEGACY_REVISED_VERIFY_CHANGED_SIDECAR")
	}
}

func TestLocalOwnedLegacyPartitionReturnsRecoveryPinAfterPostWriteCancel(t *testing.T) {
	fx := newLocalFirstWriteFixture(t)
	source := newLocalStagedLegacyPartitionSource(t)
	sourceDigest := sha256.Sum256(source.archive)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	localOwnedLegacyPartitionAfterWriteForTest = cancel
	t.Cleanup(func() { localOwnedLegacyPartitionAfterWriteForTest = nil })

	result, err := StageLocalOwnedLegacyPartition(ctx, fx.f.session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest)
	localOwnedLegacyPartitionAfterWriteForTest = nil
	if err == nil || !errors.Is(err, ErrLocalOwnedLegacyPartitionCanceled) ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("post-write cancel error = %v, want canceled cause", err)
	}
	if result.VaultID != fx.manifest.VaultID || result.JournalPath != fx.manifest.Journal ||
		result.SidecarPath != fx.manifest.Journal+localOwnedLegacyPartitionSidecarSuffix ||
		result.SourceArchiveSHA256 != sourceDigest ||
		result.CandidateSHA256 == ([sha256.Size]byte{}) {
		t.Fatal("STAGED_LEGACY_POST_WRITE_PIN_FAILED")
	}
	sidecar, err := os.ReadFile(result.SidecarPath)
	if err != nil || len(sidecar) == 0 || sha256.Sum256(sidecar) != result.CandidateSHA256 {
		t.Fatal("STAGED_LEGACY_POST_WRITE_SIDECAR_FAILED")
	}
	defer clear(sidecar)
	localFirstAssertPristine(t, fx)
	backendBytes, backendRevision := localFirstReadBackend(t, fx.manifest)
	defer clear(backendBytes)
	if backendRevision != fx.bootstrapRevision || !bytes.Equal(backendBytes, fx.genesis) {
		t.Fatal("STAGED_LEGACY_POST_WRITE_BACKEND_CHANGED")
	}

	// The committed sidecar is immutable: a later Stage must refuse the
	// collision with an empty result and must not replace or remove it.
	retry, retryErr := StageLocalOwnedLegacyPartition(context.Background(), fx.f.session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest)
	if retryErr == nil || !errors.Is(retryErr, ErrLocalOwnedLegacyPartitionConflict) ||
		retry.VaultID != "" || retry.JournalPath != "" || retry.SidecarPath != "" ||
		retry.CandidateSHA256 != ([sha256.Size]byte{}) ||
		retry.SourceArchiveSHA256 != ([sha256.Size]byte{}) {
		t.Fatal("STAGED_LEGACY_POST_WRITE_COLLISION_FAILED")
	}
	afterRetry, err := os.ReadFile(result.SidecarPath)
	if err != nil || !bytes.Equal(afterRetry, sidecar) {
		t.Fatal("STAGED_LEGACY_POST_WRITE_SIDECAR_REPLACED")
	}
	clear(afterRetry)

	// A fresh real account and the same exact valid locator can verify the
	// recovered candidate only through the full independent-digest proof.
	session := localFirstUnlockFresh(t, fx.f)
	verified, err := VerifyStagedLocalOwnedLegacyPartition(context.Background(), session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, source.request(), sourceDigest, result.CandidateSHA256)
	if err != nil {
		t.Fatalf("VerifyStagedLocalOwnedLegacyPartition after recovery: %v", err)
	}
	defer verified.Clear()
	if verified.SourceVaultID != vault.DefaultVaultID ||
		verified.DestinationVaultID != fx.manifest.VaultID ||
		verified.SourceArchiveSHA256 != sourceDigest ||
		len(verified.ItemMapping) != 1 ||
		verified.ItemMapping[source.itemID] != source.itemID {
		t.Fatal("STAGED_LEGACY_POST_WRITE_VERIFY_BINDING_FAILED")
	}
	afterVerify, err := os.ReadFile(result.SidecarPath)
	if err != nil || !bytes.Equal(afterVerify, sidecar) {
		t.Fatal("STAGED_LEGACY_POST_WRITE_VERIFY_CHANGED_SIDECAR")
	}
	clear(afterVerify)
}
