//go:build darwin || linux

package personal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

func TestOwnedVaultFileLegacyPartitionReconcilesDurableOutcome(t *testing.T) {
	dir := t.TempDir()

	// A real multi-item legacy source with two declared partitions. The
	// selected partition has several represented item shapes so the candidate
	// is genuinely a multi-item transition, not a single synthetic record.
	sourcePath := filepath.Join(dir, "reconcile-source.ll")
	sourcePassword := "synthetic-reconcile-source-factor"
	sourceKey := bytes.Repeat([]byte{0x28}, 16)
	if err := Create(sourcePath, sourcePassword, sourceKey); err != nil {
		t.Fatal("RECONCILE_SOURCE_CREATE_FAILED")
	}
	sourceSession, err := UnlockSession(sourcePath, []byte(sourcePassword), sourceKey, time.Hour)
	if err != nil {
		t.Fatal("RECONCILE_SOURCE_UNLOCK_FAILED")
	}
	t.Cleanup(sourceSession.Lock)
	selected, err := sourceSession.CreateVault("Reconcile Selected", "selected reconcile partition", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("RECONCILE_SOURCE_SELECTED_FAILED")
	}
	other, err := sourceSession.CreateVault("Reconcile Other", "other reconcile partition", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("RECONCILE_SOURCE_OTHER_FAILED")
	}
	stamp := time.Unix(1_700_003_456, 0).UTC()
	trashedAt := stamp.Add(time.Hour)
	add := func(item vault.Item) string {
		t.Helper()
		id, _, err := sourceSession.AddItem(item, v2Gate(t, sourceSession))
		if err != nil {
			t.Fatalf("RECONCILE_SOURCE_ADD_FAILED: %v", err)
		}
		return id
	}
	selectedIDs := []string{
		add(vault.Item{
			Kind: "login", Category: vault.CategoryLogin, VaultID: selected.ID,
			Title: "Reconcile active login", Username: "reconcile-user", Password: "reconcile-password",
			URL: "https://reconcile.example.test/", Notes: "reconcile notes",
			Tags: []string{"reconcile", "durable"}, ImportSource: []byte("reconcile-import-provenance"),
		}),
		add(vault.Item{
			Kind: "login", Category: vault.CategoryLogin, VaultID: selected.ID,
			Title: "Reconcile trashed login", Username: "reconcile-trashed-user",
			Password: "reconcile-trashed-password", State: "trashed", PreviousState: "archived",
			TrashedAt: &trashedAt,
			History: []vault.ItemHistoryEntry{{
				Timestamp: stamp.Unix(), Action: "edit", Title: "Reconcile prior title",
			}},
		}),
		add(vault.Item{
			Kind: "document", Category: vault.CategoryDocument, VaultID: selected.ID,
			Title: "Reconcile document", Filename: "reconcile-document.bin",
			Attachment: []byte{0x50, 0x4b, 0x03, 0x04}, AttachmentProtected: true,
		}),
	}
	otherID := add(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: other.ID,
		Title: "Reconcile other login", Username: "reconcile-other-user",
		Password: "reconcile-other-password", Notes: "other partition only",
	})

	sourceArchivePath := filepath.Join(dir, "reconcile-source.llb")
	sourceKit, err := Backup(sourcePath, sourceArchivePath, sourcePassword, sourceKey)
	if err != nil {
		t.Fatal("RECONCILE_SOURCE_BACKUP_FAILED")
	}
	sourceArchive := legacyPartitionReadFile(t, sourceArchivePath)
	sourceArchiveBefore := bytes.Clone(sourceArchive)
	sourceArchiveFileBefore := legacyPartitionReadFile(t, sourceArchivePath)
	sourceDigest := sha256.Sum256(sourceArchive)

	// A real destination account with two independently published owned genesis
	// scopes. Both journals live below explicit 0700 directories so umask 022
	// cannot make them non-private.
	destPath := filepath.Join(dir, "reconcile-destination.ll")
	destPassword := "synthetic-reconcile-destination-factor"
	destKey := bytes.Repeat([]byte{0x41}, 16)
	if err := Create(destPath, destPassword, destKey); err != nil {
		t.Fatal("RECONCILE_DEST_CREATE_FAILED")
	}
	setupSession, err := UnlockSession(destPath, []byte(destPassword), destKey, time.Hour)
	if err != nil {
		t.Fatal("RECONCILE_DEST_UNLOCK_FAILED")
	}
	prepareOwner := func(label string) VaultFileOwnershipPublic {
		t.Helper()
		selector, err := randomID()
		if err != nil {
			t.Fatalf("RECONCILE_USER_%s_FAILED", label)
		}
		public, err := setupSession.PrepareVaultFileOwnership(selector)
		if err != nil {
			t.Fatalf("RECONCILE_CUSTODY_%s_FAILED", label)
		}
		return public
	}
	publicA := prepareOwner("A")
	publicB := prepareOwner("B")
	destArchivePath := filepath.Join(dir, "reconcile-destination.llb")
	destKit, err := Backup(destPath, destArchivePath, destPassword, destKey)
	if err != nil {
		t.Fatal("RECONCILE_DEST_BACKUP_FAILED")
	}
	destArchive := legacyPartitionReadFile(t, destArchivePath)
	journalDir := legacyPartitionPrivateDir(t, dir, "reconcile-journals")
	publish := func(name string, public VaultFileOwnershipPublic) legacyPartitionGenesisScope {
		t.Helper()
		intentPath := filepath.Join(journalDir, "genesis-"+name+".journal")
		if _, err := setupSession.PrepareVaultFileGenesis(VaultFileGenesisRequest{
			VaultID: public.VaultID, Name: "reconcile-" + name, IntentPath: intentPath, ArchivePath: destArchivePath,
		}, []byte(destPassword), destKey, []byte(destKit)); err != nil {
			t.Fatalf("RECONCILE_GENESIS_%s_FAILED: %v", name, err)
		}
		return legacyPartitionPublishGenesis(t, dir, name, public, intentPath)
	}
	scopeA := publish("a", publicA)
	scopeB := publish("b", publicB)
	t.Cleanup(func() {
		clearVaultFilePolicyCheckpoint(scopeA.checkpoint)
		clearVaultFilePolicyCheckpoint(scopeB.checkpoint)
	})

	seal := func(scope legacyPartitionGenesisScope, selector, label string) []byte {
		t.Helper()
		sealed, err := setupSession.SealOwnedVaultFileFirstItemsFromLegacyPartition(OwnedVaultFileLegacyPartitionRequest{
			JournalPath: scope.journalPath, Target: scope.target, Checkpoint: scope.checkpoint,
			ExpectedGenesis: scope.genesis, Password: []byte(destPassword), Key: destKey,
			Source: LegacyVaultPartitionSource{
				Archive: sourceArchive, Password: sourcePassword, Key: sourceKey,
				RecoveryKit: sourceKit, VaultID: selector,
			},
		})
		if err != nil {
			t.Fatalf("RECONCILE_SEAL_%s_FAILED: %v", label, err)
		}
		defer sealed.Clear()
		if sealed.SourceArchiveSHA256 != sourceDigest {
			t.Fatalf("RECONCILE_SEAL_%s_DIGEST_MISMATCH", label)
		}
		return bytes.Clone(sealed.Sealed)
	}
	candidateA := seal(scopeA, selected.ID, "selected")
	candidateOther := seal(scopeA, other.ID, "other_partition")
	candidateForeign := seal(scopeB, selected.ID, "foreign_scope")
	defer clear(candidateA)
	defer clear(candidateOther)
	defer clear(candidateForeign)
	if bytes.Equal(candidateA, candidateOther) || bytes.Equal(candidateA, candidateForeign) ||
		bytes.Equal(candidateOther, candidateForeign) {
		t.Fatal("RECONCILE_CANDIDATES_NOT_DISTINCT")
	}

	prepare := func(scope legacyPartitionGenesisScope, candidate []byte, label string) (vaultfilejournal.State, vaultfilejournal.Proposal) {
		t.Helper()
		journal, err := vaultfilejournal.OpenExisting(scope.journalPath)
		if err != nil {
			t.Fatalf("RECONCILE_PREPARE_%s_OPEN_FAILED", label)
		}
		origin, err := journal.LoadGenesisBaseline()
		if err != nil {
			_ = journal.Close()
			t.Fatalf("RECONCILE_PREPARE_%s_STATE_FAILED", label)
		}
		file, err := vaultfile.ParseFile(candidate)
		if err != nil {
			clear(origin.BaseBytes)
			clear(origin.WorkingBytes)
			_ = journal.Close()
			t.Fatalf("RECONCILE_PREPARE_%s_PARSE_FAILED", label)
		}
		proposal := vaultfilejournal.Proposal{
			Generation:       origin.Generation + 1,
			OperationID:      file.Header.OpID,
			ExpectedRevision: origin.RemoteRevision,
			Bytes:            candidate,
		}
		prepareErr := journal.PrepareWorkingIfState(origin, proposal)
		closeErr := journal.Close()
		if prepareErr != nil || closeErr != nil {
			clear(origin.BaseBytes)
			clear(origin.WorkingBytes)
			t.Fatalf("RECONCILE_PREPARE_%s_FAILED: prepare=%v close=%v", label, prepareErr, closeErr)
		}
		return origin, proposal
	}
	originA, proposalA := prepare(scopeA, candidateA, "a")
	originB, proposalB := prepare(scopeB, candidateForeign, "b")
	defer func() {
		clear(originA.BaseBytes)
		clear(originA.WorkingBytes)
		clear(proposalA.Bytes)
		clear(originB.BaseBytes)
		clear(originB.WorkingBytes)
		clear(proposalB.Bytes)
	}()

	// Scope B stays pending while its live backend holds the same genesis bytes
	// at a changed revision. That is not the unchanged original journal revision
	// and must never be accepted as safe for the original CAS.
	changedGenesisRevision := legacyPartitionReplaceBackend(t, scopeB, scopeB.revision, bytes.Clone(scopeB.genesis))
	if changedGenesisRevision == scopeB.revision {
		t.Fatal("RECONCILE_CHANGED_GENESIS_REVISION_UNCHANGED")
	}

	setupSession.Lock()
	openFresh := func() *Session {
		t.Helper()
		session, err := UnlockSession(destPath, []byte(destPassword), destKey, time.Hour)
		if err != nil {
			t.Fatal("RECONCILE_FRESH_UNLOCK_FAILED")
		}
		return session
	}

	request := func(scope legacyPartitionGenesisScope, candidate []byte, selector string) OwnedVaultFileLegacyPartitionReconciliationRequest {
		return OwnedVaultFileLegacyPartitionReconciliationRequest{
			OwnedVaultFileLegacyPartitionVerificationRequest: OwnedVaultFileLegacyPartitionVerificationRequest{
				OwnedVaultFileLegacyPartitionRequest: OwnedVaultFileLegacyPartitionRequest{
					JournalPath: scope.journalPath, Target: scope.target, Checkpoint: scope.checkpoint,
					ExpectedGenesis: scope.genesis, Password: []byte(destPassword), Key: destKey,
					Source: LegacyVaultPartitionSource{
						Archive: sourceArchive, Password: sourcePassword, Key: sourceKey,
						RecoveryKit: sourceKit, VaultID: selector,
					},
				},
				Candidate:                   candidate,
				ExpectedSourceArchiveSHA256: sourceDigest,
			},
			ExpectedCandidateSHA256: sha256.Sum256(candidate),
		}
	}
	requestA := request(scopeA, candidateA, selected.ID)
	requestB := request(scopeB, candidateForeign, selected.ID)

	type reconciliationSnapshot struct {
		journalA         []byte
		journalB         []byte
		personal         []byte
		backendA         []byte
		backendB         []byte
		backendARevision vaultfilebackend.Revision
		backendBRevision vaultfilebackend.Revision
	}
	takeSnapshot := func() reconciliationSnapshot {
		t.Helper()
		backendA, revisionA := legacyPartitionReadBackend(t, scopeA.backendRoot, scopeA.target.BackendName)
		backendB, revisionB := legacyPartitionReadBackend(t, scopeB.backendRoot, scopeB.target.BackendName)
		return reconciliationSnapshot{
			journalA: legacyPartitionReadFile(t, scopeA.journalPath),
			journalB: legacyPartitionReadFile(t, scopeB.journalPath),
			personal: legacyPartitionReadFile(t, destPath),
			backendA: backendA, backendB: backendB,
			backendARevision: revisionA, backendBRevision: revisionB,
		}
	}
	sameSnapshot := func(a, b reconciliationSnapshot) bool {
		return bytes.Equal(a.journalA, b.journalA) && bytes.Equal(a.journalB, b.journalB) &&
			bytes.Equal(a.personal, b.personal) && bytes.Equal(a.backendA, b.backendA) &&
			bytes.Equal(a.backendB, b.backendB) &&
			a.backendARevision == b.backendARevision && a.backendBRevision == b.backendBRevision
	}
	clearSnapshot := func(s reconciliationSnapshot) {
		clear(s.journalA)
		clear(s.journalB)
		clear(s.personal)
		clear(s.backendA)
		clear(s.backendB)
	}
	assertNoResult := func(name string, out VaultFileReconciledLegacyPartition) {
		t.Helper()
		if out.Disposition != VaultFileLegacyPartitionDispositionUnknown ||
			out.SourceVault != nil || out.SourceVaultID != "" ||
			out.SourceArchiveSHA256 != ([sha256.Size]byte{}) ||
			out.DestinationVaultID != "" || len(out.ItemMapping) != 0 {
			t.Fatalf("RECONCILE_%s_LEAKED_OUTPUT", name)
		}
	}
	expect := func(name string, session *Session, req OwnedVaultFileLegacyPartitionReconciliationRequest, want VaultFileLegacyPartitionDisposition) {
		t.Helper()
		before := takeSnapshot()
		out, err := session.ReconcileOwnedVaultFileLegacyPartition(req)
		after := takeSnapshot()
		if err != nil {
			t.Fatalf("RECONCILE_%s_FAILED: %v", name, err)
		}
		if out.Disposition != want {
			out.Clear()
			t.Fatalf("RECONCILE_%s_DISPOSITION_MISMATCH: got=%s want=%s", name, out.Disposition, want)
		}
		if out.SourceArchiveSHA256 != sourceDigest || out.SourceVaultID != selected.ID ||
			out.DestinationVaultID != scopeA.target.Pin.Root.VaultID {
			out.Clear()
			t.Fatalf("RECONCILE_%s_PROVENANCE_MISMATCH", name)
		}
		if len(out.ItemMapping) != len(selectedIDs) {
			out.Clear()
			t.Fatalf("RECONCILE_%s_MAPPING_SHAPE_MISMATCH", name)
		}
		for _, id := range selectedIDs {
			if out.ItemMapping[id] != id {
				out.Clear()
				t.Fatalf("RECONCILE_%s_MAPPING_MISMATCH", name)
			}
		}
		if out.ItemMapping[otherID] != "" {
			out.Clear()
			t.Fatalf("RECONCILE_%s_MIXED_OTHER_PARTITION", name)
		}
		out.Clear()
		if !sameSnapshot(before, after) {
			t.Fatalf("RECONCILE_%s_MUTATED", name)
		}
		clearSnapshot(before)
		clearSnapshot(after)
	}
	refuse := func(name string, session *Session, req OwnedVaultFileLegacyPartitionReconciliationRequest, want error) {
		t.Helper()
		before := takeSnapshot()
		out, err := session.ReconcileOwnedVaultFileLegacyPartition(req)
		after := takeSnapshot()
		if err == nil || want != nil && !errors.Is(err, want) {
			t.Fatalf("RECONCILE_%s_NOT_REFUSED: err=%v want=%v", name, err, want)
		}
		assertNoResult(name, out)
		if !sameSnapshot(before, after) {
			t.Fatalf("RECONCILE_%s_MUTATED", name)
		}
		clearSnapshot(before)
		clearSnapshot(after)
	}

	// Same genesis with a changed revision and an otherwise exact prepared
	// candidate is refused on the foreign scope.
	session := openFresh()
	refuse("pending_same_genesis_changed_revision", session, requestB, ErrVaultFileBaselineJournal)
	session.Lock()

	// Crash before the CAS: the prepared journal and unchanged live genesis
	// revision prove the original CAS is still safe.
	session = openFresh()
	expect("pending_safe", session, requestA, VaultFileLegacyPartitionPendingSafeForCAS)

	wrongCandidateDigest := requestA
	wrongCandidateDigest.ExpectedCandidateSHA256 = sha256.Sum256(candidateOther)
	refuse("wrong_candidate_digest", session, wrongCandidateDigest, ErrLegacyVaultPartitionPayload)

	substitutedCiphertext := requestA
	substitutedCiphertext.Candidate = candidateOther
	substitutedCiphertext.ExpectedCandidateSHA256 = sha256.Sum256(candidateOther)
	refuse("other_partition_ciphertext", session, substitutedCiphertext, ErrVaultFileBaselineJournal)

	foreignCiphertext := requestA
	foreignCiphertext.Candidate = candidateForeign
	foreignCiphertext.ExpectedCandidateSHA256 = sha256.Sum256(candidateForeign)
	refuse("foreign_scope_ciphertext", session, foreignCiphertext, ErrVaultFileBaselineJournal)

	corrupt := bytes.Clone(candidateA)
	corrupt[len(corrupt)-1] ^= 0xff
	corruptWithOwnDigest := requestA
	corruptWithOwnDigest.Candidate = corrupt
	corruptWithOwnDigest.ExpectedCandidateSHA256 = sha256.Sum256(corrupt)
	refuse("corrupt_ciphertext", session, corruptWithOwnDigest, ErrVaultFileBaselineJournal)

	tamperedWithPinnedDigest := requestA
	tamperedWithPinnedDigest.Candidate = corrupt
	refuse("tampered_ciphertext", session, tamperedWithPinnedDigest, ErrLegacyVaultPartitionPayload)
	clear(corrupt)

	wrongSourceDigest := requestA
	wrongSourceDigest.ExpectedSourceArchiveSHA256 = sha256.Sum256(destArchive)
	refuse("wrong_source_digest", session, wrongSourceDigest, ErrLegacyVaultPartitionPayload)

	substitutedSource := requestA
	substitutedSource.Source.Archive = destArchive
	substitutedSource.ExpectedSourceArchiveSHA256 = sha256.Sum256(destArchive)
	refuse("substituted_source_archive", session, substitutedSource, nil)

	wrongSelector := requestA
	wrongSelector.Source.VaultID = other.ID
	refuse("other_selector", session, wrongSelector, ErrLegacyVaultPartitionPayload)

	missingSelector := requestA
	missingSelector.Source.VaultID = "reconcile-not-a-selector"
	refuse("missing_selector", session, missingSelector, ErrLegacyVaultPartitionSelector)

	missingJournal := requestA
	missingJournal.JournalPath = filepath.Join(journalDir, "missing.journal")
	refuse("missing_journal", session, missingJournal, ErrVaultFileBaselineJournal)

	foreignJournal := requestA
	foreignJournal.JournalPath = scopeB.journalPath
	refuse("foreign_journal", session, foreignJournal, ErrVaultFileBaselineJournal)

	wrongTarget := requestA
	wrongTarget.Target = scopeB.target
	refuse("wrong_target", session, wrongTarget, ErrVaultFileBaselineVerification)

	wrongCheckpoint := requestA
	wrongCheckpoint.Checkpoint = scopeB.checkpoint
	refuse("wrong_checkpoint", session, wrongCheckpoint, ErrVaultFileBaselineVerification)

	wrongFactors := requestA
	wrongFactors.Password = []byte("synthetic-reconcile-wrong-factor")
	refuse("wrong_destination_factors", session, wrongFactors, ErrVaultFileScopedFactors)
	session.Lock()

	// Crash after the CAS but before the local acknowledgement: the journal is
	// still pending, while the backend is exactly the candidate at a coherently
	// different revision.
	appliedRevision := legacyPartitionReplaceBackend(t, scopeA, scopeA.revision, candidateA)
	if appliedRevision == scopeA.revision {
		t.Fatal("RECONCILE_APPLIED_REVISION_UNCHANGED")
	}
	session = openFresh()
	expect("applied_unacknowledged", session, requestA, VaultFileLegacyPartitionAppliedUnacknowledged)

	// A genuinely different successor advance is never mistaken for the pinned
	// candidate, even at a different revision.
	advanceRevision := legacyPartitionReplaceBackend(t, scopeA, appliedRevision, candidateOther)
	if advanceRevision == appliedRevision {
		t.Fatal("RECONCILE_ADVANCE_REVISION_UNCHANGED")
	}
	refuse("applied_different_advance", session, requestA, ErrVaultFileBaselineJournal)
	session.Lock()

	// Restoring the exact candidate at another coherent revision is again the
	// applied-but-unacknowledged outcome, and it can be settled with that exact
	// readback revision.
	appliedRevision = legacyPartitionReplaceBackend(t, scopeA, advanceRevision, candidateA)
	session = openFresh()
	expect("applied_after_restore", session, requestA, VaultFileLegacyPartitionAppliedUnacknowledged)
	session.Lock()

	journal, err := vaultfilejournal.OpenExisting(scopeA.journalPath)
	if err != nil {
		t.Fatal("RECONCILE_SETTLE_OPEN_FAILED")
	}
	ackErr := journal.AckOwnedFirstSuccessor(originA, scopeA.target.Pin, proposalA, candidateA, appliedRevision)
	closeErr := journal.Close()
	if ackErr != nil || closeErr != nil {
		t.Fatalf("RECONCILE_SETTLE_ACK_FAILED: ack=%v close=%v", ackErr, closeErr)
	}

	session = openFresh()
	expect("settled", session, requestA, VaultFileLegacyPartitionSettled)

	// The settled record pins the exact readback revision. Replacing the same
	// bytes at a different revision must not be read as the same settled live
	// state.
	mismatchedRevision := legacyPartitionReplaceBackend(t, scopeA, appliedRevision, candidateA)
	if mismatchedRevision == appliedRevision {
		t.Fatal("RECONCILE_SETTLED_REVISION_UNCHANGED")
	}
	refuse("settled_same_bytes_changed_revision", session, requestA, ErrVaultFileBaselineJournal)
	session.Lock()

	// A settled journal whose live object advanced to a different successor is
	// refused rather than reported as the pinned candidate.
	session = openFresh()
	_ = legacyPartitionReplaceBackend(t, scopeA, mismatchedRevision, candidateOther)
	refuse("settled_different_advance", session, requestA, ErrVaultFileBaselineJournal)
	session.Lock()

	if !bytes.Equal(sourceArchive, sourceArchiveBefore) ||
		!bytes.Equal(legacyPartitionReadFile(t, sourceArchivePath), sourceArchiveFileBefore) {
		t.Fatal("RECONCILE_SOURCE_ARCHIVE_CHANGED")
	}
}
