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
	"syscall"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

type localStagedPublishSource struct {
	archive     []byte
	archivePath string
	vaultPath   string
	password    string
	key         []byte
	kit         string
	itemIDs     []string
	titles      []string
}

func newLocalStagedPublishSource(t *testing.T, count int) *localStagedPublishSource {
	t.Helper()
	if count <= 0 {
		t.Fatal("STAGED_PUBLISH_SOURCE_COUNT_INVALID")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "legacy-source")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("STAGED_PUBLISH_SOURCE_DIR_FAILED")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("STAGED_PUBLISH_SOURCE_DIR_MODE_FAILED")
	}
	path := filepath.Join(dir, "source.ll")
	archivePath := filepath.Join(dir, "source.llb")
	password := "staged-publish-source-factor"
	key := bytes.Repeat([]byte{0x61}, 16)
	if err := personal.Create(path, password, key); err != nil {
		t.Fatal("STAGED_PUBLISH_SOURCE_CREATE_FAILED")
	}
	session, err := personal.UnlockSession(path, []byte(password), key, time.Minute)
	if err != nil {
		t.Fatal("STAGED_PUBLISH_SOURCE_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)
	source := &localStagedPublishSource{
		archivePath: archivePath, vaultPath: path, password: password, key: key,
	}
	for i := 0; i < count; i++ {
		title := fmt.Sprintf("Staged publish item %d", i+1)
		username := fmt.Sprintf("staged-publish-user-%d", i+1)
		secret := fmt.Sprintf("staged-publish-secret-%d", i+1)
		gate := personal.NewMutationGate(time.Now().Add(time.Minute))
		if err := session.RegisterMutation(gate); err != nil {
			t.Fatal("STAGED_PUBLISH_SOURCE_GATE_FAILED")
		}
		id, _, err := session.AddItem(vault.Item{
			Kind: "login", Category: vault.CategoryLogin, VaultID: vault.DefaultVaultID,
			Title: title, Username: username, Password: secret,
		}, gate)
		if err != nil {
			t.Fatal("STAGED_PUBLISH_SOURCE_ITEM_FAILED")
		}
		source.itemIDs = append(source.itemIDs, id)
		source.titles = append(source.titles, title)
	}
	kit, err := personal.Backup(path, archivePath, password, key)
	if err != nil {
		t.Fatal("STAGED_PUBLISH_SOURCE_BACKUP_FAILED")
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal("STAGED_PUBLISH_SOURCE_ARCHIVE_FAILED")
	}
	source.archive = archive
	source.kit = kit
	t.Cleanup(func() {
		clear(source.archive)
		clear(source.key)
	})
	return source
}

func (s *localStagedPublishSource) request() personal.LegacyVaultPartitionSource {
	return personal.LegacyVaultPartitionSource{
		Archive: s.archive, Password: s.password, Key: s.key,
		RecoveryKit: s.kit, VaultID: vault.DefaultVaultID,
	}
}

func (s *localStagedPublishSource) digest() [sha256.Size]byte {
	return sha256.Sum256(s.archive)
}

func (s *localStagedPublishSource) stage(t *testing.T, fx *localFirstWriteFixture) LocalOwnedLegacyPartitionStageResult {
	t.Helper()
	result, err := StageLocalOwnedLegacyPartition(context.Background(), fx.f.session,
		fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, s.request(), s.digest())
	if err != nil {
		t.Fatalf("StageLocalOwnedLegacyPartition: %v", err)
	}
	return result
}

func (s *localStagedPublishSource) publish(ctx context.Context, session *personal.Session, fx *localFirstWriteFixture, staged LocalOwnedLegacyPartitionStageResult) (LocalOwnedFirstWriteResult, error) {
	return s.publishWithDigests(ctx, session, fx, s.digest(), staged.CandidateSHA256)
}

func (s *localStagedPublishSource) publishWithDigests(ctx context.Context, session *personal.Session, fx *localFirstWriteFixture, sourceDigest, candidateDigest [sha256.Size]byte) (LocalOwnedFirstWriteResult, error) {
	return PublishStagedLocalOwnedLegacyPartition(ctx, session, fx.f.firstConfig,
		fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
		[]byte(fx.f.f.password), fx.f.f.key, s.request(), sourceDigest, candidateDigest)
}

func (s *localStagedPublishSource) assertUnchanged(t *testing.T, archiveCopy, vaultCopy []byte) {
	t.Helper()
	if !bytes.Equal(s.archive, archiveCopy) {
		t.Fatal("STAGED_PUBLISH_SOURCE_MEMORY_CHANGED")
	}
	archiveNow, err := os.ReadFile(s.archivePath)
	if err != nil || !bytes.Equal(archiveNow, archiveCopy) {
		t.Fatal("STAGED_PUBLISH_SOURCE_ARCHIVE_CHANGED")
	}
	clear(archiveNow)
	vaultNow, err := os.ReadFile(s.vaultPath)
	if err != nil || !bytes.Equal(vaultNow, vaultCopy) {
		t.Fatal("STAGED_PUBLISH_SOURCE_VAULT_CHANGED")
	}
	clear(vaultNow)
}

func localStagedPublishReadFile(t *testing.T, path string, label string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return raw
}

func localStagedPublishAssertPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("STAGED_PUBLISH_SIDECAR_MODE_NOT_PRIVATE")
	}
}

func localStagedPublishAssertPristine(t *testing.T, fx *localFirstWriteFixture, journal, backend []byte, revision vaultfilebackend.Revision, sidecarPath string, sidecar []byte, source *localStagedPublishSource, archiveCopy, vaultCopy []byte) {
	t.Helper()
	localFirstAssertPristine(t, fx)
	journalNow := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
	defer clear(journalNow)
	if !bytes.Equal(journalNow, journal) {
		t.Fatal("STAGED_PUBLISH_JOURNAL_CHANGED")
	}
	backendNow, revisionNow := localFirstReadBackend(t, fx.manifest)
	defer clear(backendNow)
	if !bytes.Equal(backendNow, backend) || revisionNow != revision {
		t.Fatal("STAGED_PUBLISH_BACKEND_CHANGED")
	}
	sidecarNow := localStagedPublishReadFile(t, sidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
	defer clear(sidecarNow)
	if !bytes.Equal(sidecarNow, sidecar) {
		t.Fatal("STAGED_PUBLISH_SIDECAR_CHANGED")
	}
	source.assertUnchanged(t, archiveCopy, vaultCopy)
}

func localStagedPublishAssertSummary(t *testing.T, wrapper *LocalGenesisSession, summary LocalGenesisBaseline, fx *localFirstWriteFixture, source *localStagedPublishSource) {
	t.Helper()
	if summary.VaultID != fx.manifest.VaultID || len(summary.Items) != len(source.titles) {
		t.Fatal("STAGED_PUBLISH_SUMMARY_FAILED")
	}
	found := make(map[string]bool, len(summary.Items))
	for _, item := range summary.Items {
		found[item.Title] = true
	}
	for _, title := range source.titles {
		if !found[title] {
			t.Fatal("STAGED_PUBLISH_SUMMARY_ITEM_FAILED")
		}
	}
	again, err := wrapper.Summary()
	if err != nil || len(again.Items) != len(source.titles) {
		t.Fatal("STAGED_PUBLISH_SUMMARY_REOPEN_FAILED")
	}
	for i, title := range source.titles {
		query, err := wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 2})
		if err != nil || len(query.Hits) != 1 || query.Hits[0].ID != source.itemIDs[i] {
			t.Fatal("STAGED_PUBLISH_QUERY_FAILED")
		}
	}
}

func TestLocalOwnedLegacyPartitionPublishesAndReconcilesExactStage(t *testing.T) {
	t.Run("publishes-reopens-and-repeat-settled", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		journalBefore := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
		defer clear(journalBefore)
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		oldMask := syscall.Umask(0)
		staged, err := StageLocalOwnedLegacyPartition(context.Background(), fx.f.session,
			fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
			[]byte(fx.f.f.password), fx.f.f.key, source.request(), source.digest())
		syscall.Umask(oldMask)
		if err != nil {
			t.Fatalf("StageLocalOwnedLegacyPartition: %v", err)
		}
		localStagedPublishAssertPrivate(t, staged.SidecarPath)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		if sha256.Sum256(sidecarBefore) != staged.CandidateSHA256 {
			t.Fatal("STAGED_PUBLISH_SIDECAR_DIGEST_FAILED")
		}
		sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
		if err != nil || sidecarFile.Header.OpID == "" {
			t.Fatal("STAGED_PUBLISH_SIDECAR_PARSE_FAILED")
		}
		backendPending, revisionPending := localFirstReadBackend(t, fx.manifest)
		defer clear(backendPending)
		if !bytes.Equal(backendPending, backendBefore) || revisionPending != revisionBefore {
			t.Fatal("STAGED_PUBLISH_BEFORE_CAS_BACKEND_CHANGED")
		}
		sidecarPending := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarPending)
		if !bytes.Equal(sidecarPending, sidecarBefore) {
			t.Fatal("STAGED_PUBLISH_BEFORE_CAS_SIDECAR_CHANGED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)

		result, err := source.publish(context.Background(), fx.f.session, fx, staged)
		if err != nil {
			t.Fatalf("PublishStagedLocalOwnedLegacyPartition: %v", err)
		}
		if result.VaultID != fx.manifest.VaultID || result.JournalPath != fx.manifest.Journal ||
			result.OperationID != sidecarFile.Header.OpID || result.Revision == "" ||
			result.Revision == string(revisionBefore) {
			t.Fatal("STAGED_PUBLISH_RESULT_BINDING_FAILED")
		}
		record := localFirstReadRecord(t, fx)
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		if !bytes.Equal(record.GenesisBytes, backendBefore) ||
			record.GenesisRevision != revisionBefore ||
			!bytes.Equal(record.SuccessorBytes, sidecarBefore) ||
			record.SuccessorRevision != vaultfilebackend.Revision(result.Revision) ||
			record.SuccessorRevision == revisionBefore {
			t.Fatal("STAGED_PUBLISH_RECORD_BINDING_FAILED")
		}
		backendAfter, revisionAfter := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfter)
		if !bytes.Equal(backendAfter, sidecarBefore) || revisionAfter != record.SuccessorRevision {
			t.Fatal("STAGED_PUBLISH_BACKEND_BINDING_FAILED")
		}
		sidecarAfter := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		if !bytes.Equal(sidecarAfter, sidecarBefore) {
			t.Fatal("STAGED_PUBLISH_SIDECAR_REPLACED")
		}
		clear(sidecarAfter)
		source.assertUnchanged(t, archiveCopy, vaultCopy)

		session := localFirstUnlockFresh(t, fx.f)
		wrapper, summary, err := OpenLocalGenesisSessionForJournal(session, fx.f.firstConfig,
			fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
			[]byte(fx.f.f.password), fx.f.f.key)
		if err != nil || wrapper == nil {
			t.Fatalf("OpenLocalGenesisSessionForJournal: %v", err)
		}
		defer wrapper.Close()
		localStagedPublishAssertSummary(t, wrapper, summary, fx, source)

		reconciled, err := session.ReconcileOwnedVaultFileLegacyPartition(personal.OwnedVaultFileLegacyPartitionReconciliationRequest{
			OwnedVaultFileLegacyPartitionVerificationRequest: personal.OwnedVaultFileLegacyPartitionVerificationRequest{
				OwnedVaultFileLegacyPartitionRequest: personal.OwnedVaultFileLegacyPartitionRequest{
					JournalPath:     fx.manifest.Journal,
					Target:          fx.target,
					Checkpoint:      fx.checkpoint,
					ExpectedGenesis: fx.genesis,
					Password:        []byte(fx.f.f.password),
					Key:             fx.f.f.key,
					Source:          source.request(),
				},
				Candidate:                   sidecarBefore,
				ExpectedSourceArchiveSHA256: source.digest(),
			},
			ExpectedCandidateSHA256: staged.CandidateSHA256,
		})
		if err != nil || reconciled.Disposition != personal.VaultFileLegacyPartitionSettled {
			t.Fatalf("ReconcileOwnedVaultFileLegacyPartition settled: %v", err)
		}
		reconciled.Clear()

		journalSettled := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
		defer clear(journalSettled)
		backendSettled, revisionSettled := localFirstReadBackend(t, fx.manifest)
		defer clear(backendSettled)
		sidecarSettled := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarSettled)
		resultAgain, err := source.publish(context.Background(), session, fx, staged)
		if err != nil {
			t.Fatalf("repeat PublishStagedLocalOwnedLegacyPartition: %v", err)
		}
		if resultAgain != result {
			t.Fatal("STAGED_PUBLISH_REPEAT_RESULT_CHANGED")
		}
		journalAgain := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
		defer clear(journalAgain)
		backendAgain, revisionAgain := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAgain)
		sidecarAgain := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarAgain)
		if !bytes.Equal(journalAgain, journalSettled) ||
			!bytes.Equal(backendAgain, backendSettled) || revisionAgain != revisionSettled ||
			!bytes.Equal(sidecarAgain, sidecarSettled) {
			t.Fatal("STAGED_PUBLISH_REPEAT_WROTE")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("interrupt-before-cas-recovers-exact-proposal", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)
		journalBefore := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
		defer clear(journalBefore)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		localOwnedFirstWriteAfterPrepareForTest = cancel
		t.Cleanup(func() { localOwnedFirstWriteAfterPrepareForTest = nil })
		if _, err := source.publish(ctx, fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("interrupted before CAS error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPrepareForTest = nil
		pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if pending.Generation != 1 || !bytes.Equal(pending.BaseBytes, backendBefore) ||
			pending.RemoteRevision != revisionBefore ||
			!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) ||
			prepared.Proposal.OperationID == "" {
			t.Fatal("STAGED_PUBLISH_BEFORE_CAS_PREPARATION_FAILED")
		}
		backendPending, revisionPending := localFirstReadBackend(t, fx.manifest)
		defer clear(backendPending)
		if !bytes.Equal(backendPending, backendBefore) || revisionPending != revisionBefore {
			t.Fatal("STAGED_PUBLISH_BEFORE_CAS_BACKEND_CHANGED")
		}
		sidecarPending := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarPending)
		if !bytes.Equal(sidecarPending, sidecarBefore) {
			t.Fatal("STAGED_PUBLISH_BEFORE_CAS_SIDECAR_CHANGED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)

		result, err := source.publish(context.Background(), fx.f.session, fx, staged)
		if err != nil {
			t.Fatalf("recover before CAS: %v", err)
		}
		if result.OperationID != prepared.Proposal.OperationID {
			t.Fatal("STAGED_PUBLISH_BEFORE_CAS_CREATED_NEW_PROPOSAL")
		}
		record := localFirstReadRecord(t, fx)
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		if !bytes.Equal(record.GenesisBytes, backendBefore) || record.GenesisRevision != revisionBefore ||
			!bytes.Equal(record.SuccessorBytes, sidecarBefore) ||
			record.SuccessorRevision != vaultfilebackend.Revision(result.Revision) {
			t.Fatal("STAGED_PUBLISH_BEFORE_CAS_SETTLEMENT_FAILED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
		session := localFirstUnlockFresh(t, fx.f)
		wrapper, summary, err := OpenLocalGenesisSessionForJournal(session, fx.f.firstConfig,
			fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
			[]byte(fx.f.f.password), fx.f.f.key)
		if err != nil || wrapper == nil {
			t.Fatalf("reopen after before-CAS recovery: %v", err)
		}
		defer wrapper.Close()
		localStagedPublishAssertSummary(t, wrapper, summary, fx, source)
	})

	t.Run("interrupt-after-cas-acknowledges-without-second-write", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		localOwnedFirstWriteAfterPublishForTest = cancel
		t.Cleanup(func() { localOwnedFirstWriteAfterPublishForTest = nil })
		if _, err := source.publish(ctx, fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("interrupted after CAS error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPublishForTest = nil
		backendAfterFirst, revisionAfterFirst := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterFirst)
		if !bytes.Equal(backendAfterFirst, sidecarBefore) || revisionAfterFirst == revisionBefore {
			t.Fatal("STAGED_PUBLISH_AFTER_CAS_BACKEND_FAILED")
		}
		pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if !bytes.Equal(pending.BaseBytes, backendBefore) || pending.RemoteRevision != revisionBefore ||
			!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) {
			t.Fatal("STAGED_PUBLISH_AFTER_CAS_PREPARATION_FAILED")
		}
		if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
			t.Fatal("STAGED_PUBLISH_AFTER_CAS_ALREADY_ACKED")
		}
		sidecarAfterFirst := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		if !bytes.Equal(sidecarAfterFirst, sidecarBefore) {
			t.Fatal("STAGED_PUBLISH_AFTER_CAS_SIDECAR_CHANGED")
		}
		clear(sidecarAfterFirst)
		source.assertUnchanged(t, archiveCopy, vaultCopy)

		result, err := source.publish(context.Background(), fx.f.session, fx, staged)
		if err != nil {
			t.Fatalf("recover after CAS: %v", err)
		}
		if result.OperationID != prepared.Proposal.OperationID {
			t.Fatal("STAGED_PUBLISH_AFTER_CAS_CREATED_NEW_PROPOSAL")
		}
		backendAfterSecond, revisionAfterSecond := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterSecond)
		if !bytes.Equal(backendAfterSecond, backendAfterFirst) || revisionAfterSecond != revisionAfterFirst {
			t.Fatal("STAGED_PUBLISH_AFTER_CAS_REWROTE_BACKEND")
		}
		record := localFirstReadRecord(t, fx)
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		if !bytes.Equal(record.GenesisBytes, backendBefore) || record.GenesisRevision != revisionBefore ||
			!bytes.Equal(record.SuccessorBytes, sidecarBefore) ||
			record.SuccessorRevision != revisionAfterFirst ||
			record.SuccessorRevision != vaultfilebackend.Revision(result.Revision) {
			t.Fatal("STAGED_PUBLISH_AFTER_CAS_SETTLEMENT_FAILED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
		session := localFirstUnlockFresh(t, fx.f)
		wrapper, summary, err := OpenLocalGenesisSessionForJournal(session, fx.f.firstConfig,
			fx.manifest.BackendRoot, fx.manifest.VaultID, fx.manifest.Journal,
			[]byte(fx.f.f.password), fx.f.f.key)
		if err != nil || wrapper == nil {
			t.Fatalf("reopen after after-CAS recovery: %v", err)
		}
		defer wrapper.Close()
		localStagedPublishAssertSummary(t, wrapper, summary, fx, source)
	})

	t.Run("request-lock-after-prepare-before-cas-preserves-base", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
		if err != nil || sidecarFile.Header.OpID == "" {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_SIDECAR_PARSE_FAILED")
		}
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedFirstWriteAfterPrepareForTest = fx.f.session.RequestLock
		t.Cleanup(func() { localOwnedFirstWriteAfterPrepareForTest = nil })
		if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("lock after prepare error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPrepareForTest = nil

		backendPending, revisionPending := localFirstReadBackend(t, fx.manifest)
		defer clear(backendPending)
		if !bytes.Equal(backendPending, backendBefore) || revisionPending != revisionBefore {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_BACKEND_CHANGED")
		}
		sidecarPending := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarPending)
		if !bytes.Equal(sidecarPending, sidecarBefore) {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_SIDECAR_CHANGED")
		}
		pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if !bytes.Equal(pending.BaseBytes, backendBefore) || pending.RemoteRevision != revisionBefore ||
			!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) ||
			prepared.Proposal.OperationID != sidecarFile.Header.OpID {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_PENDING_CHANGED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)

		session := localFirstUnlockFresh(t, fx.f)
		result, err := source.publish(context.Background(), session, fx, staged)
		if err != nil {
			t.Fatalf("recover after prepare lock: %v", err)
		}
		if result.OperationID != sidecarFile.Header.OpID {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_OPERATION_CHANGED")
		}
		backendAfter, revisionAfter := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfter)
		if !bytes.Equal(backendAfter, sidecarBefore) || revisionAfter == revisionBefore {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_RECOVERY_FAILED")
		}
		record := localFirstReadRecord(t, fx)
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		if record.GenesisRevision != revisionBefore || record.SuccessorRevision != revisionAfter {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_RECORD_FAILED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("request-lock-after-cas-before-ack-retains-pending", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
		if err != nil || sidecarFile.Header.OpID == "" {
			t.Fatal("STAGED_PUBLISH_LOCK_CAS_SIDECAR_PARSE_FAILED")
		}
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedFirstWriteAfterPublishForTest = fx.f.session.RequestLock
		t.Cleanup(func() { localOwnedFirstWriteAfterPublishForTest = nil })
		if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("lock after CAS error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPublishForTest = nil

		backendAfterCAS, revisionAfterCAS := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterCAS)
		if !bytes.Equal(backendAfterCAS, sidecarBefore) || revisionAfterCAS == revisionBefore {
			t.Fatal("STAGED_PUBLISH_LOCK_CAS_BACKEND_FAILED")
		}
		pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if !bytes.Equal(pending.BaseBytes, backendBefore) || pending.RemoteRevision != revisionBefore ||
			!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) ||
			prepared.Proposal.OperationID != sidecarFile.Header.OpID {
			t.Fatal("STAGED_PUBLISH_LOCK_CAS_PENDING_CHANGED")
		}
		if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
			t.Fatal("STAGED_PUBLISH_LOCK_CAS_ALREADY_ACKED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)

		session := localFirstUnlockFresh(t, fx.f)
		result, err := source.publish(context.Background(), session, fx, staged)
		if err != nil {
			t.Fatalf("fresh session after CAS lock: %v", err)
		}
		if result.OperationID != sidecarFile.Header.OpID || result.Revision != string(revisionAfterCAS) {
			t.Fatal("STAGED_PUBLISH_LOCK_CAS_RESULT_CHANGED")
		}
		backendAfterAck, revisionAfterAck := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterAck)
		if !bytes.Equal(backendAfterAck, backendAfterCAS) || revisionAfterAck != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_LOCK_CAS_SECOND_WRITE")
		}
		record := localFirstReadRecord(t, fx)
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		if !bytes.Equal(record.GenesisBytes, backendBefore) || record.GenesisRevision != revisionBefore ||
			!bytes.Equal(record.SuccessorBytes, sidecarBefore) ||
			record.SuccessorRevision != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_LOCK_CAS_RECORD_FAILED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("request-lock-before-direct-applied-ack-retains-pending", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedFirstWriteAfterPublishForTest = fx.f.session.RequestLock
		t.Cleanup(func() { localOwnedFirstWriteAfterPublishForTest = nil })
		if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("applied ack setup error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPublishForTest = nil
		backendAfterCAS, revisionAfterCAS := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterCAS)
		if !bytes.Equal(backendAfterCAS, sidecarBefore) || revisionAfterCAS == revisionBefore {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_SETUP_FAILED")
		}

		session := localFirstUnlockFresh(t, fx.f)
		localOwnedFirstWriteAfterPublishForTest = session.RequestLock
		t.Cleanup(func() { localOwnedFirstWriteAfterPublishForTest = nil })
		if _, err := source.publish(context.Background(), session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("direct applied ack lock error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPublishForTest = nil
		if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_ALREADY_ACKED")
		}
		backendGuard, revisionGuard := localFirstReadBackend(t, fx.manifest)
		defer clear(backendGuard)
		if !bytes.Equal(backendGuard, backendAfterCAS) || revisionGuard != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_BACKEND_CHANGED")
		}

		second := localFirstUnlockFresh(t, fx.f)
		result, err := source.publish(context.Background(), second, fx, staged)
		if err != nil {
			t.Fatalf("fresh session after applied ack lock: %v", err)
		}
		if result.Revision != string(revisionAfterCAS) {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_RESULT_CHANGED")
		}
		backendFinal, revisionFinal := localFirstReadBackend(t, fx.manifest)
		defer clear(backendFinal)
		if !bytes.Equal(backendFinal, backendAfterCAS) || revisionFinal != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_SECOND_WRITE")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("request-lock-before-initial-prepare-claim-does-not-prepare", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		journalBefore := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
		defer clear(journalBefore)
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedLegacyPartitionPhaseHookForTest = func(step string) error {
			if step == "before-prepare" {
				fx.f.session.RequestLock()
			}
			return nil
		}
		t.Cleanup(func() { localOwnedLegacyPartitionPhaseHookForTest = nil })
		if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionCanceled) {
			t.Fatalf("lock before prepare error = %v, want canceled", err)
		}
		localOwnedLegacyPartitionPhaseHookForTest = nil

		localFirstAssertPristine(t, fx)
		journalNow := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
		defer clear(journalNow)
		if !bytes.Equal(journalNow, journalBefore) {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_JOURNAL_CHANGED")
		}
		backendNow, revisionNow := localFirstReadBackend(t, fx.manifest)
		defer clear(backendNow)
		if !bytes.Equal(backendNow, backendBefore) || revisionNow != revisionBefore {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_BACKEND_CHANGED")
		}
		sidecarNow := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarNow)
		if !bytes.Equal(sidecarNow, sidecarBefore) {
			t.Fatal("STAGED_PUBLISH_LOCK_PREPARE_SIDECAR_CHANGED")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("cancel-or-lock-before-publish-claim-preserves-base", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			action func(*personal.Session, context.CancelFunc)
		}{
			{"cancel", func(_ *personal.Session, cancel context.CancelFunc) { cancel() }},
			{"lock", func(s *personal.Session, _ context.CancelFunc) { s.RequestLock() }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fx := newLocalFirstWriteFixture(t)
				source := newLocalStagedPublishSource(t, 3)
				archiveCopy := bytes.Clone(source.archive)
				vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
				defer clear(archiveCopy)
				defer clear(vaultCopy)
				staged := source.stage(t, fx)
				sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
				defer clear(sidecarBefore)
				sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
				if err != nil || sidecarFile.Header.OpID == "" {
					t.Fatal("STAGED_PUBLISH_LOCK_PUBLISH_SIDECAR_PARSE_FAILED")
				}
				backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
				defer clear(backendBefore)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				localOwnedLegacyPartitionPhaseHookForTest = func(step string) error {
					if step == "before-publish" {
						tc.action(fx.f.session, cancel)
					}
					return nil
				}
				t.Cleanup(func() { localOwnedLegacyPartitionPhaseHookForTest = nil })
				if _, err := source.publish(ctx, fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
					t.Fatalf("%s before publish error = %v, want indeterminate", tc.name, err)
				}
				localOwnedLegacyPartitionPhaseHookForTest = nil

				backendPending, revisionPending := localFirstReadBackend(t, fx.manifest)
				defer clear(backendPending)
				if !bytes.Equal(backendPending, backendBefore) || revisionPending != revisionBefore {
					t.Fatal("STAGED_PUBLISH_LOCK_PUBLISH_BACKEND_CHANGED")
				}
				pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
				defer clear(pending.BaseBytes)
				defer clear(pending.WorkingBytes)
				defer clear(prepared.Proposal.Bytes)
				if !bytes.Equal(pending.BaseBytes, backendBefore) || pending.RemoteRevision != revisionBefore ||
					!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) ||
					prepared.Proposal.OperationID != sidecarFile.Header.OpID ||
					prepared.Proposal.ExpectedRevision != revisionBefore {
					t.Fatal("STAGED_PUBLISH_LOCK_PUBLISH_PENDING_CHANGED")
				}
				sidecarNow := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
				defer clear(sidecarNow)
				if !bytes.Equal(sidecarNow, sidecarBefore) {
					t.Fatal("STAGED_PUBLISH_LOCK_PUBLISH_SIDECAR_CHANGED")
				}
				source.assertUnchanged(t, archiveCopy, vaultCopy)

				session := localFirstUnlockFresh(t, fx.f)
				result, err := source.publish(context.Background(), session, fx, staged)
				if err != nil {
					t.Fatalf("recover after %s before publish: %v", tc.name, err)
				}
				if result.OperationID != sidecarFile.Header.OpID {
					t.Fatal("STAGED_PUBLISH_LOCK_PUBLISH_OPERATION_CHANGED")
				}
				backendAfter, revisionAfter := localFirstReadBackend(t, fx.manifest)
				defer clear(backendAfter)
				if !bytes.Equal(backendAfter, sidecarBefore) || revisionAfter == revisionBefore {
					t.Fatal("STAGED_PUBLISH_LOCK_PUBLISH_RECOVERY_FAILED")
				}
				source.assertUnchanged(t, archiveCopy, vaultCopy)
			})
		}
	})

	t.Run("request-lock-before-direct-applied-ack-claim-retains-pending", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
		if err != nil || sidecarFile.Header.OpID == "" {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_SIDECAR_PARSE_FAILED")
		}
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedFirstWriteAfterPublishForTest = fx.f.session.RequestLock
		t.Cleanup(func() { localOwnedFirstWriteAfterPublishForTest = nil })
		if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("applied ack setup error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPublishForTest = nil
		backendAfterCAS, revisionAfterCAS := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterCAS)
		if !bytes.Equal(backendAfterCAS, sidecarBefore) || revisionAfterCAS == revisionBefore {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_SETUP_FAILED")
		}

		session := localFirstUnlockFresh(t, fx.f)
		localOwnedLegacyPartitionPhaseHookForTest = func(step string) error {
			if step == "before-ack" {
				session.RequestLock()
			}
			return nil
		}
		t.Cleanup(func() { localOwnedLegacyPartitionPhaseHookForTest = nil })
		if _, err := source.publish(context.Background(), session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("direct applied ack lock error = %v, want indeterminate", err)
		}
		localOwnedLegacyPartitionPhaseHookForTest = nil
		if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_ALREADY_ACKED")
		}
		backendGuard, revisionGuard := localFirstReadBackend(t, fx.manifest)
		defer clear(backendGuard)
		if !bytes.Equal(backendGuard, backendAfterCAS) || revisionGuard != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_BACKEND_CHANGED")
		}
		pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if !bytes.Equal(pending.BaseBytes, backendBefore) || pending.RemoteRevision != revisionBefore ||
			!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) ||
			prepared.Proposal.OperationID != sidecarFile.Header.OpID {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_PENDING_CHANGED")
		}

		second := localFirstUnlockFresh(t, fx.f)
		result, err := source.publish(context.Background(), second, fx, staged)
		if err != nil {
			t.Fatalf("fresh session after applied ack lock: %v", err)
		}
		if result.OperationID != sidecarFile.Header.OpID || result.Revision != string(revisionAfterCAS) {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_RESULT_CHANGED")
		}
		backendFinal, revisionFinal := localFirstReadBackend(t, fx.manifest)
		defer clear(backendFinal)
		if !bytes.Equal(backendFinal, backendAfterCAS) || revisionFinal != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_LOCK_APPLIED_SECOND_WRITE")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("durability-proof-failure-after-cas-retains-pending", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
		if err != nil || sidecarFile.Header.OpID == "" {
			t.Fatal("STAGED_PUBLISH_DURABILITY_SIDECAR_PARSE_FAILED")
		}
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedLegacyPartitionPhaseHookForTest = func(step string) error {
			if step == "durability" {
				return errors.New("synthetic durability proof failure")
			}
			return nil
		}
		t.Cleanup(func() { localOwnedLegacyPartitionPhaseHookForTest = nil })
		if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) ||
			!errors.Is(err, vaultfilebackend.ErrDurabilityUnproven) {
			t.Fatalf("durability failure error = %v, want recoverable unknown", err)
		}
		localOwnedLegacyPartitionPhaseHookForTest = nil
		backendAfterCAS, revisionAfterCAS := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterCAS)
		if !bytes.Equal(backendAfterCAS, sidecarBefore) || revisionAfterCAS == revisionBefore {
			t.Fatal("STAGED_PUBLISH_DURABILITY_BACKEND_FAILED")
		}
		if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
			t.Fatal("STAGED_PUBLISH_DURABILITY_ALREADY_ACKED")
		}
		pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if !bytes.Equal(pending.BaseBytes, backendBefore) || pending.RemoteRevision != revisionBefore ||
			!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) ||
			prepared.Proposal.OperationID != sidecarFile.Header.OpID {
			t.Fatal("STAGED_PUBLISH_DURABILITY_PENDING_CHANGED")
		}
		reopened, err := vaultfilejournal.OpenExisting(fx.manifest.Journal)
		if err != nil {
			t.Fatal("STAGED_PUBLISH_DURABILITY_REOPEN_FAILED")
		}
		againState, againPrepared, loadErr := reopened.LoadOwnedFirstPending()
		closeErr := reopened.Close()
		defer clear(againState.BaseBytes)
		defer clear(againState.WorkingBytes)
		defer clear(againPrepared.Proposal.Bytes)
		if loadErr != nil || closeErr != nil ||
			!sameLocalOwnedFirstState(pending, againState) ||
			!sameLocalOwnedFirstPrepared(prepared, againPrepared) {
			t.Fatal("STAGED_PUBLISH_DURABILITY_REOPEN_CHANGED")
		}

		session := localFirstUnlockFresh(t, fx.f)
		result, err := source.publish(context.Background(), session, fx, staged)
		if err != nil {
			t.Fatalf("real proof after durability failure: %v", err)
		}
		if result.OperationID != sidecarFile.Header.OpID || result.Revision != string(revisionAfterCAS) {
			t.Fatal("STAGED_PUBLISH_DURABILITY_RESULT_CHANGED")
		}
		backendFinal, revisionFinal := localFirstReadBackend(t, fx.manifest)
		defer clear(backendFinal)
		if !bytes.Equal(backendFinal, backendAfterCAS) || revisionFinal != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_DURABILITY_SECOND_WRITE")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("durability-proof-failure-on-direct-applied-ack-retains-pending", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
		if err != nil || sidecarFile.Header.OpID == "" {
			t.Fatal("STAGED_PUBLISH_DURABILITY_APPLIED_SIDECAR_PARSE_FAILED")
		}
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedFirstWriteAfterPublishForTest = fx.f.session.RequestLock
		t.Cleanup(func() { localOwnedFirstWriteAfterPublishForTest = nil })
		if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("applied durability setup error = %v, want indeterminate", err)
		}
		localOwnedFirstWriteAfterPublishForTest = nil
		backendAfterCAS, revisionAfterCAS := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfterCAS)
		if !bytes.Equal(backendAfterCAS, sidecarBefore) || revisionAfterCAS == revisionBefore {
			t.Fatal("STAGED_PUBLISH_DURABILITY_APPLIED_SETUP_FAILED")
		}

		session := localFirstUnlockFresh(t, fx.f)
		localOwnedLegacyPartitionPhaseHookForTest = func(step string) error {
			if step == "durability" {
				return errors.New("synthetic durability proof failure")
			}
			return nil
		}
		t.Cleanup(func() { localOwnedLegacyPartitionPhaseHookForTest = nil })
		if _, err := source.publish(context.Background(), session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) ||
			!errors.Is(err, vaultfilebackend.ErrDurabilityUnproven) {
			t.Fatalf("applied durability failure error = %v, want recoverable unknown", err)
		}
		localOwnedLegacyPartitionPhaseHookForTest = nil
		if _, err := vaultfilejournal.ReadOwnedFirstSuccessor(fx.manifest.Journal, fx.pin); err == nil {
			t.Fatal("STAGED_PUBLISH_DURABILITY_APPLIED_ALREADY_ACKED")
		}
		pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
		defer clear(pending.BaseBytes)
		defer clear(pending.WorkingBytes)
		defer clear(prepared.Proposal.Bytes)
		if !bytes.Equal(pending.BaseBytes, backendBefore) || pending.RemoteRevision != revisionBefore ||
			!bytes.Equal(prepared.Proposal.Bytes, sidecarBefore) ||
			prepared.Proposal.OperationID != sidecarFile.Header.OpID {
			t.Fatal("STAGED_PUBLISH_DURABILITY_APPLIED_PENDING_CHANGED")
		}

		second := localFirstUnlockFresh(t, fx.f)
		result, err := source.publish(context.Background(), second, fx, staged)
		if err != nil {
			t.Fatalf("real proof on applied after durability failure: %v", err)
		}
		if result.OperationID != sidecarFile.Header.OpID || result.Revision != string(revisionAfterCAS) {
			t.Fatal("STAGED_PUBLISH_DURABILITY_APPLIED_RESULT_CHANGED")
		}
		backendFinal, revisionFinal := localFirstReadBackend(t, fx.manifest)
		defer clear(backendFinal)
		if !bytes.Equal(backendFinal, backendAfterCAS) || revisionFinal != revisionAfterCAS {
			t.Fatal("STAGED_PUBLISH_DURABILITY_APPLIED_SECOND_WRITE")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("request-lock-before-deliver-claim-withdraws-old-success", func(t *testing.T) {
		fx := newLocalFirstWriteFixture(t)
		source := newLocalStagedPublishSource(t, 3)
		archiveCopy := bytes.Clone(source.archive)
		vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
		defer clear(archiveCopy)
		defer clear(vaultCopy)
		staged := source.stage(t, fx)
		sidecarBefore := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
		defer clear(sidecarBefore)
		sidecarFile, err := vaultfile.ParseFile(sidecarBefore)
		if err != nil || sidecarFile.Header.OpID == "" {
			t.Fatal("STAGED_PUBLISH_DELIVER_SIDECAR_PARSE_FAILED")
		}
		backendBefore, revisionBefore := localFirstReadBackend(t, fx.manifest)
		defer clear(backendBefore)

		localOwnedLegacyPartitionPhaseHookForTest = func(step string) error {
			if step == "before-deliver" {
				fx.f.session.RequestLock()
			}
			return nil
		}
		t.Cleanup(func() { localOwnedLegacyPartitionPhaseHookForTest = nil })
		result, err := source.publish(context.Background(), fx.f.session, fx, staged)
		if !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
			t.Fatalf("lock before delivery error = %v, want indeterminate", err)
		}
		if result != (LocalOwnedFirstWriteResult{}) {
			t.Fatal("STAGED_PUBLISH_DELIVER_RETURNED_OLD_SUCCESS")
		}
		localOwnedLegacyPartitionPhaseHookForTest = nil

		backendAfter, revisionAfter := localFirstReadBackend(t, fx.manifest)
		defer clear(backendAfter)
		if !bytes.Equal(backendAfter, sidecarBefore) || revisionAfter == revisionBefore {
			t.Fatal("STAGED_PUBLISH_DELIVER_BACKEND_CHANGED")
		}
		record := localFirstReadRecord(t, fx)
		defer clear(record.GenesisBytes)
		defer clear(record.SuccessorBytes)
		if !bytes.Equal(record.GenesisBytes, backendBefore) || record.GenesisRevision != revisionBefore ||
			!bytes.Equal(record.SuccessorBytes, sidecarBefore) ||
			record.SuccessorRevision != revisionAfter {
			t.Fatal("STAGED_PUBLISH_DELIVER_ACKNOWLEDGED_STATE_CHANGED")
		}

		session := localFirstUnlockFresh(t, fx.f)
		reconciled, err := source.publish(context.Background(), session, fx, staged)
		if err != nil {
			t.Fatalf("fresh auth after delivery lock: %v", err)
		}
		if reconciled.OperationID != sidecarFile.Header.OpID || reconciled.Revision != string(revisionAfter) {
			t.Fatal("STAGED_PUBLISH_DELIVER_RECONCILIATION_CHANGED")
		}
		backendFinal, revisionFinal := localFirstReadBackend(t, fx.manifest)
		defer clear(backendFinal)
		if !bytes.Equal(backendFinal, backendAfter) || revisionFinal != revisionAfter {
			t.Fatal("STAGED_PUBLISH_DELIVER_SECOND_WRITE")
		}
		source.assertUnchanged(t, archiveCopy, vaultCopy)
	})

	t.Run("wrong-digests-stale-and-foreign-advance-never-overwrite", func(t *testing.T) {
		t.Run("wrong-source-digest", func(t *testing.T) {
			fx := newLocalFirstWriteFixture(t)
			source := newLocalStagedPublishSource(t, 3)
			archiveCopy := bytes.Clone(source.archive)
			vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
			defer clear(archiveCopy)
			defer clear(vaultCopy)
			staged := source.stage(t, fx)
			sidecar := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecar)
			journal := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journal)
			backend, revision := localFirstReadBackend(t, fx.manifest)
			defer clear(backend)
			wrong := source.digest()
			wrong[0] ^= 0xff
			if _, err := source.publishWithDigests(context.Background(), fx.f.session, fx,
				wrong, staged.CandidateSHA256); !errors.Is(err, ErrLocalOwnedLegacyPartitionConflict) {
				t.Fatalf("wrong source digest error = %v, want conflict", err)
			}
			localStagedPublishAssertPristine(t, fx, journal, backend, revision,
				staged.SidecarPath, sidecar, source, archiveCopy, vaultCopy)
		})

		t.Run("wrong-candidate-digest", func(t *testing.T) {
			fx := newLocalFirstWriteFixture(t)
			source := newLocalStagedPublishSource(t, 3)
			archiveCopy := bytes.Clone(source.archive)
			vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
			defer clear(archiveCopy)
			defer clear(vaultCopy)
			staged := source.stage(t, fx)
			sidecar := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecar)
			journal := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journal)
			backend, revision := localFirstReadBackend(t, fx.manifest)
			defer clear(backend)
			wrong := staged.CandidateSHA256
			wrong[0] ^= 0xff
			if _, err := source.publishWithDigests(context.Background(), fx.f.session, fx,
				source.digest(), wrong); !errors.Is(err, ErrLocalOwnedLegacyPartitionConflict) {
				t.Fatalf("wrong candidate digest error = %v, want conflict", err)
			}
			localStagedPublishAssertPristine(t, fx, journal, backend, revision,
				staged.SidecarPath, sidecar, source, archiveCopy, vaultCopy)
		})

		t.Run("stale-same-genesis-new-revision", func(t *testing.T) {
			fx := newLocalFirstWriteFixture(t)
			source := newLocalStagedPublishSource(t, 3)
			archiveCopy := bytes.Clone(source.archive)
			vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
			defer clear(archiveCopy)
			defer clear(vaultCopy)
			staged := source.stage(t, fx)
			sidecar := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecar)
			journal := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journal)
			backend, revision := localFirstReadBackend(t, fx.manifest)
			defer clear(backend)
			updated := localFirstRewriteBackend(t, fx.manifest, backend)
			if updated == revision {
				t.Fatal("STAGED_PUBLISH_STALE_REVISION_UNCHANGED")
			}
			if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionConflict) {
				t.Fatalf("stale revision error = %v, want conflict", err)
			}
			backendNow, revisionNow := localFirstReadBackend(t, fx.manifest)
			defer clear(backendNow)
			if !bytes.Equal(backendNow, backend) || revisionNow != updated {
				t.Fatal("STAGED_PUBLISH_STALE_REVISION_CLOBBERED")
			}
			journalNow := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journalNow)
			if !bytes.Equal(journalNow, journal) {
				t.Fatal("STAGED_PUBLISH_STALE_REVISION_CHANGED_JOURNAL")
			}
			sidecarNow := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecarNow)
			if !bytes.Equal(sidecarNow, sidecar) {
				t.Fatal("STAGED_PUBLISH_STALE_REVISION_CHANGED_SIDECAR")
			}
			source.assertUnchanged(t, archiveCopy, vaultCopy)
		})

		t.Run("foreign-advance", func(t *testing.T) {
			fx := newLocalFirstWriteFixture(t)
			source := newLocalStagedPublishSource(t, 3)
			archiveCopy := bytes.Clone(source.archive)
			vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
			defer clear(archiveCopy)
			defer clear(vaultCopy)
			staged := source.stage(t, fx)
			sidecar := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecar)
			journal := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journal)
			foreign := []byte("foreign local advance")
			foreignRevision := localFirstRewriteBackend(t, fx.manifest, foreign)
			if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionConflict) {
				t.Fatalf("foreign advance error = %v, want conflict", err)
			}
			backendNow, revisionNow := localFirstReadBackend(t, fx.manifest)
			defer clear(backendNow)
			if !bytes.Equal(backendNow, foreign) || revisionNow != foreignRevision {
				t.Fatal("STAGED_PUBLISH_FOREIGN_ADVANCE_CLOBBERED")
			}
			journalNow := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journalNow)
			if !bytes.Equal(journalNow, journal) {
				t.Fatal("STAGED_PUBLISH_FOREIGN_ADVANCE_CHANGED_JOURNAL")
			}
			sidecarNow := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecarNow)
			if !bytes.Equal(sidecarNow, sidecar) {
				t.Fatal("STAGED_PUBLISH_FOREIGN_ADVANCE_CHANGED_SIDECAR")
			}
			source.assertUnchanged(t, archiveCopy, vaultCopy)
		})

		t.Run("pending-foreign-advance", func(t *testing.T) {
			fx := newLocalFirstWriteFixture(t)
			source := newLocalStagedPublishSource(t, 3)
			archiveCopy := bytes.Clone(source.archive)
			vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
			defer clear(archiveCopy)
			defer clear(vaultCopy)
			staged := source.stage(t, fx)
			sidecar := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecar)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			localOwnedFirstWriteAfterPrepareForTest = cancel
			t.Cleanup(func() { localOwnedFirstWriteAfterPrepareForTest = nil })
			if _, err := source.publish(ctx, fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionUnknown) {
				t.Fatalf("pending foreign setup error = %v, want indeterminate", err)
			}
			localOwnedFirstWriteAfterPrepareForTest = nil
			pending, prepared := localFirstReadPending(t, fx.manifest.Journal)
			defer clear(pending.BaseBytes)
			defer clear(pending.WorkingBytes)
			defer clear(prepared.Proposal.Bytes)
			pendingJournal := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(pendingJournal)
			foreign := []byte("foreign pending advance")
			foreignRevision := localFirstRewriteBackend(t, fx.manifest, foreign)
			if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionConflict) {
				t.Fatalf("pending foreign advance error = %v, want conflict", err)
			}
			backendNow, revisionNow := localFirstReadBackend(t, fx.manifest)
			defer clear(backendNow)
			if !bytes.Equal(backendNow, foreign) || revisionNow != foreignRevision {
				t.Fatal("STAGED_PUBLISH_PENDING_FOREIGN_ADVANCE_CLOBBERED")
			}
			journalNow := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journalNow)
			if !bytes.Equal(journalNow, pendingJournal) {
				t.Fatal("STAGED_PUBLISH_PENDING_FOREIGN_ADVANCE_CHANGED_JOURNAL")
			}
			pendingAgain, preparedAgain := localFirstReadPending(t, fx.manifest.Journal)
			defer clear(pendingAgain.BaseBytes)
			defer clear(pendingAgain.WorkingBytes)
			defer clear(preparedAgain.Proposal.Bytes)
			if !sameLocalOwnedFirstState(pendingAgain, pending) ||
				!sameLocalOwnedFirstPrepared(preparedAgain, prepared) {
				t.Fatal("STAGED_PUBLISH_PENDING_FOREIGN_ADVANCE_CHANGED_PREPARATION")
			}
			sidecarNow := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecarNow)
			if !bytes.Equal(sidecarNow, sidecar) {
				t.Fatal("STAGED_PUBLISH_PENDING_FOREIGN_ADVANCE_CHANGED_SIDECAR")
			}
			source.assertUnchanged(t, archiveCopy, vaultCopy)
		})

		t.Run("foreign-pin", func(t *testing.T) {
			fx := newLocalFirstWriteFixture(t)
			source := newLocalStagedPublishSource(t, 3)
			archiveCopy := bytes.Clone(source.archive)
			vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
			defer clear(archiveCopy)
			defer clear(vaultCopy)
			staged := source.stage(t, fx)
			sidecar := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecar)
			journal := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journal)
			backend, revision := localFirstReadBackend(t, fx.manifest)
			defer clear(backend)
			secondManifest, exists, err := ReadManifest(fx.f.secondConfig)
			if err != nil || !exists {
				t.Fatal("STAGED_PUBLISH_FOREIGN_PIN_SECOND_MANIFEST_FAILED")
			}
			secondCompanion, exists, err := ReadCompanion(fx.f.secondConfig, secondManifest)
			if err != nil || !exists || secondCompanion.Resume.Checkpoint == nil {
				t.Fatal("STAGED_PUBLISH_FOREIGN_PIN_SECOND_COMPANION_FAILED")
			}
			companion := fx.companion
			checkpoint := *companion.Resume.Checkpoint
			checkpoint.OwnerRootKeyID = secondCompanion.Resume.Checkpoint.OwnerRootKeyID
			checkpoint.OwnerRootPublicKey = secondCompanion.Resume.Checkpoint.OwnerRootPublicKey
			companion.Resume.Checkpoint = &checkpoint
			raw, err := json.Marshal(companion)
			if err != nil {
				t.Fatal("STAGED_PUBLISH_FOREIGN_PIN_ENCODE_FAILED")
			}
			path, err := CompanionPath(fx.f.firstConfig)
			if err != nil {
				t.Fatal("STAGED_PUBLISH_FOREIGN_PIN_PATH_FAILED")
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal("STAGED_PUBLISH_FOREIGN_PIN_WRITE_FAILED")
			}
			if _, err := source.publish(context.Background(), fx.f.session, fx, staged); !errors.Is(err, ErrLocalOwnedLegacyPartitionConflict) && !errors.Is(err, ErrLocalOwnedLegacyPartitionReview) {
				t.Fatalf("foreign pin error = %v, want conflict or review", err)
			}
			localStagedPublishAssertPristine(t, fx, journal, backend, revision,
				staged.SidecarPath, sidecar, source, archiveCopy, vaultCopy)
		})

		t.Run("wrong-journal", func(t *testing.T) {
			fx := newLocalFirstWriteFixture(t)
			source := newLocalStagedPublishSource(t, 3)
			archiveCopy := bytes.Clone(source.archive)
			vaultCopy := localStagedPublishReadFile(t, source.vaultPath, "STAGED_PUBLISH_SOURCE_VAULT_READ_FAILED")
			defer clear(archiveCopy)
			defer clear(vaultCopy)
			staged := source.stage(t, fx)
			sidecar := localStagedPublishReadFile(t, staged.SidecarPath, "STAGED_PUBLISH_SIDECAR_READ_FAILED")
			defer clear(sidecar)
			journal := localStagedPublishReadFile(t, fx.manifest.Journal, "STAGED_PUBLISH_JOURNAL_READ_FAILED")
			defer clear(journal)
			backend, revision := localFirstReadBackend(t, fx.manifest)
			defer clear(backend)
			secondManifest, exists, err := ReadManifest(fx.f.secondConfig)
			if err != nil || !exists || secondManifest.Journal == fx.manifest.Journal {
				t.Fatal("STAGED_PUBLISH_WRONG_JOURNAL_SETUP_FAILED")
			}
			if _, err := PublishStagedLocalOwnedLegacyPartition(context.Background(), fx.f.session,
				fx.f.firstConfig, fx.manifest.BackendRoot, fx.manifest.VaultID, secondManifest.Journal,
				[]byte(fx.f.f.password), fx.f.f.key, source.request(), source.digest(),
				staged.CandidateSHA256); !errors.Is(err, ErrLocalOwnedLegacyPartitionConflict) {
				t.Fatalf("wrong journal error = %v, want conflict", err)
			}
			localStagedPublishAssertPristine(t, fx, journal, backend, revision,
				staged.SidecarPath, sidecar, source, archiveCopy, vaultCopy)
		})
	})
}
