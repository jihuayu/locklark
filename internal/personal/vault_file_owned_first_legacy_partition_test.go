//go:build darwin || linux

package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

func TestOwnedVaultFileFirstItemsFromLegacyPartitionMaterializesOneVerifiedGroup(t *testing.T) {
	dir := t.TempDir()

	// A real, independent source personal vault with two declared groups. The
	// recovery archive is produced by the production backup path, not by a
	// caller-supplied item slice.
	sourcePath := filepath.Join(dir, "source.ll")
	sourcePassword := "synthetic-legacy-partition-source-factor"
	sourceKey := bytes.Repeat([]byte{0x51}, 16)
	if err := Create(sourcePath, sourcePassword, sourceKey); err != nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_CREATE_FAILED")
	}
	sourceSession, err := UnlockSession(sourcePath, []byte(sourcePassword), sourceKey, time.Hour)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_UNLOCK_FAILED")
	}
	t.Cleanup(sourceSession.Lock)
	work, err := sourceSession.CreateVault("Selected Work", "selected source group", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_GROUP_FAILED")
	}
	other, err := sourceSession.CreateVault("Unselected Group", "other source group", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_OTHER_GROUP_FAILED")
	}

	stamp := time.Unix(1_700_000_123, 0).UTC()
	auto := true
	add := func(item vault.Item) string {
		t.Helper()
		id, _, err := sourceSession.AddItem(item, v2Gate(t, sourceSession))
		if err != nil {
			t.Fatalf("LEGACY_PARTITION_SOURCE_ADD_FAILED: %v", err)
		}
		return id
	}
	activeID := add(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: work.ID,
		Title: "Selected active login", Username: "selected-user", Password: "selected-password",
		URL: "https://selected.example.test/", Notes: "selected notes",
		URLs: []vault.ItemURL{
			{Label: "primary", URL: "https://selected.example.test/", Primary: true, MatchMode: vault.URLMatchOrigin},
			{Label: "secondary", URL: "https://secondary.example.test/", MatchMode: vault.URLMatchHost},
		},
		Favorite: true, AutoSubmit: &auto, Tags: []string{"selected", "work"},
		Sections: []vault.ItemSection{{ID: "selected-section", Title: "Selected fields", Fields: []vault.CustomField{
			{ID: "selected-concealed", Label: "Concealed", Type: vault.FieldTypeConcealed, Value: "concealed-value", Protected: true},
			{ID: "selected-email", Label: "Email", Type: vault.FieldTypeEmail, Value: "field@example.test"},
		}}},
		History: []vault.ItemHistoryEntry{{
			Timestamp: stamp.Unix(), Action: "edit", Password: "prior-password", Title: "Prior title",
			Username: "prior-user", Notes: "prior notes",
			Sections: []vault.ItemSection{{ID: "prior-section", Title: "Prior", Fields: []vault.CustomField{{
				ID: "prior-field", Label: "Prior", Type: vault.FieldTypeText, Value: "prior-value",
			}}}},
		}},
		Attachments: []vault.AttachmentMeta{{
			FileName: "selected.bin", MIMEType: "application/octet-stream", Protected: true,
			Content: []byte{0x00, 0x01, 0x7f, 0xff, 0x10},
		}},
		ImportSource: []byte("selected-import-provenance"),
	})
	trashedAt := stamp.Add(time.Hour)
	trashedID := add(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: work.ID,
		Title: "Selected trashed login", Username: "trashed-user", Password: "trashed-password",
		State: "trashed", PreviousState: "archived", TrashedAt: &trashedAt,
		History:      []vault.ItemHistoryEntry{{Timestamp: stamp.Unix(), Action: "edit", Title: "Trashed prior"}},
		ImportSource: []byte("trashed-import-provenance"),
		Attachments: []vault.AttachmentMeta{{
			FileName: "trashed.bin", MIMEType: "application/octet-stream", Protected: true,
			Content: []byte{0xde, 0xad, 0xbe, 0xef},
		}},
	})
	documentID := add(vault.Item{
		Kind: "document", Category: vault.CategoryDocument, VaultID: work.ID,
		Title: "Selected document", Filename: "selected-document.bin",
		Attachment: []byte{0x50, 0x4b, 0x03, 0x04}, AttachmentProtected: true,
		ImportSource: []byte("document-import-provenance"),
	})
	cardID := add(vault.Item{
		Kind: "credit_card", Category: vault.CategoryCreditCard, VaultID: work.ID,
		Title: "Selected card",
		CreditCard: &vault.CreditCardDetails{
			CardholderName: "Synthetic Holder", Type: "visa", Number: "4111111111111111",
			Verification: "123", ExpiryDate: "2030-01", ValidFrom: "2020-01",
			PIN: "9999", IssuingBank: "Synthetic Bank",
		},
	})
	otherID := add(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: other.ID,
		Title: "Unselected login", Username: "other-user", Password: "other-password",
		ImportSource: []byte("other-import-provenance"),
	})

	sourceArchivePath := filepath.Join(dir, "source.llb")
	sourceKit, err := Backup(sourcePath, sourceArchivePath, sourcePassword, sourceKey)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_BACKUP_FAILED")
	}
	sourceArchive, err := os.ReadFile(sourceArchivePath)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_ARCHIVE_READ_FAILED")
	}
	sourceArchiveBefore := bytes.Clone(sourceArchive)
	sourceArchiveFileBefore := legacyPartitionReadFile(t, sourceArchivePath)

	sourcePayload, err := verifyRecoveryArchive(sourceArchive, sourcePassword, sourceKey, sourceKit, true)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_VERIFY_FAILED")
	}
	defer clearDecodedArchiveSensitive(sourcePayload)
	var sourceWorkMeta *vault.VaultMeta
	for i := range sourcePayload.Vaults {
		if sourcePayload.Vaults[i].ID == work.ID {
			metadata := sourcePayload.Vaults[i]
			sourceWorkMeta = &metadata
			break
		}
	}
	if sourceWorkMeta == nil {
		t.Fatal("LEGACY_PARTITION_SOURCE_METADATA_MISSING")
	}
	sourceItems := make([]vault.Item, 0, 4)
	for i := range sourcePayload.Items {
		if sourcePayload.Items[i].VaultID == work.ID {
			sourceItems = append(sourceItems, sourcePayload.Items[i])
		}
	}
	if len(sourceItems) != 4 {
		t.Fatal("LEGACY_PARTITION_SOURCE_GROUP_SHAPE_MISMATCH")
	}
	sourceIDs := map[string]bool{}
	for i := range sourceItems {
		sourceIDs[sourceItems[i].ID] = true
	}
	for _, id := range []string{activeID, trashedID, documentID, cardID} {
		if !sourceIDs[id] {
			t.Fatal("LEGACY_PARTITION_SOURCE_GROUP_ITEM_MISSING")
		}
	}
	if sourceIDs[otherID] {
		t.Fatal("LEGACY_PARTITION_SOURCE_GROUP_MIXED_OTHER_GROUP")
	}
	byID := make(map[string]vault.Item, len(sourceItems))
	for i := range sourceItems {
		byID[sourceItems[i].ID] = sourceItems[i]
	}
	if item := byID[activeID]; len(item.History) == 0 || len(item.Sections) == 0 ||
		len(item.Attachments) != 1 || len(item.Attachments[0].Content) == 0 ||
		!item.Attachments[0].Protected || len(item.ImportSource) == 0 {
		t.Fatal("LEGACY_PARTITION_SOURCE_ACTIVE_REPRESENTATION_MISSING")
	}
	if item := byID[trashedID]; item.State != "trashed" || item.PreviousState != "archived" ||
		item.TrashedAt == nil || len(item.History) == 0 || len(item.ImportSource) == 0 {
		t.Fatal("LEGACY_PARTITION_SOURCE_TRASH_REPRESENTATION_MISSING")
	}
	if item := byID[documentID]; len(item.Attachment) == 0 || !item.AttachmentProtected {
		t.Fatal("LEGACY_PARTITION_SOURCE_DOCUMENT_REPRESENTATION_MISSING")
	}
	if item := byID[cardID]; item.CreditCard == nil || item.CreditCard.Number == "" {
		t.Fatal("LEGACY_PARTITION_SOURCE_TYPED_REPRESENTATION_MISSING")
	}

	// Four real destination personal-vault custody scopes. Each genesis journal
	// is published through the production Dir backend helper, and the target
	// bytes/revision are observed from the actual backend Read that the journal
	// acknowledged rather than from a synthetic ack.
	destPath := filepath.Join(dir, "destination.ll")
	destPassword := "synthetic-legacy-partition-destination-factor"
	destKey := bytes.Repeat([]byte{0x61}, 16)
	if err := Create(destPath, destPassword, destKey); err != nil {
		t.Fatal("LEGACY_PARTITION_DEST_CREATE_FAILED")
	}
	destSession, err := UnlockSession(destPath, []byte(destPassword), destKey, time.Hour)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_DEST_UNLOCK_FAILED")
	}
	t.Cleanup(destSession.Lock)
	prepareOwner := func(label string) VaultFileOwnershipPublic {
		t.Helper()
		selector, err := randomID()
		if err != nil {
			t.Fatalf("LEGACY_PARTITION_USER_%s_FAILED", label)
		}
		public, err := destSession.PrepareVaultFileOwnership(selector)
		if err != nil {
			t.Fatalf("LEGACY_PARTITION_CUSTODY_%s_FAILED", label)
		}
		return public
	}
	publicA := prepareOwner("A")
	publicB := prepareOwner("B")
	publicC := prepareOwner("C")
	publicD := prepareOwner("D")
	destArchivePath := filepath.Join(dir, "destination.llb")
	destKit, err := Backup(destPath, destArchivePath, destPassword, destKey)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_DEST_BACKUP_FAILED")
	}
	destArchive := legacyPartitionReadFile(t, destArchivePath)
	publish := func(name string, public VaultFileOwnershipPublic) legacyPartitionGenesisScope {
		t.Helper()
		intentPath := filepath.Join(dir, "genesis-"+name+".journal")
		if _, err := destSession.PrepareVaultFileGenesis(VaultFileGenesisRequest{
			VaultID: public.VaultID, Name: "legacy-partition-" + name, IntentPath: intentPath, ArchivePath: destArchivePath,
		}, []byte(destPassword), destKey, []byte(destKit)); err != nil {
			t.Fatalf("LEGACY_PARTITION_GENESIS_%s_FAILED: %v", name, err)
		}
		return legacyPartitionPublishGenesis(t, dir, name, public, intentPath)
	}
	scopeA := publish("a", publicA)
	scopeB := publish("b", publicB)
	scopeC := publish("c", publicC)
	scopeD := publish("d", publicD)
	allScopes := []legacyPartitionGenesisScope{scopeA, scopeB, scopeC, scopeD}
	t.Cleanup(func() {
		for _, scope := range allScopes {
			clearVaultFilePolicyCheckpoint(scope.checkpoint)
		}
	})
	localAge := legacyPartitionLocalAge(t, destSession)

	journalABefore := legacyPartitionReadFile(t, scopeA.journalPath)
	journalBBefore := legacyPartitionReadFile(t, scopeB.journalPath)
	journalCBefore := legacyPartitionReadFile(t, scopeC.journalPath)
	journalDBefore := legacyPartitionReadFile(t, scopeD.journalPath)
	destBefore := legacyPartitionReadFile(t, destPath)

	requestFor := func(scope legacyPartitionGenesisScope) OwnedVaultFileLegacyPartitionRequest {
		return OwnedVaultFileLegacyPartitionRequest{
			JournalPath: scope.journalPath, Target: scope.target, Checkpoint: scope.checkpoint,
			ExpectedGenesis: scope.genesis,
			Password:        []byte(destPassword), Key: destKey,
			Source: LegacyVaultPartitionSource{
				Archive: sourceArchive, Password: sourcePassword, Key: sourceKey,
				RecoveryKit: sourceKit, VaultID: work.ID,
			},
		}
	}
	request := requestFor(scopeA)

	advancedBytes := bytes.Clone(scopeC.genesis)
	advancedRevision := legacyPartitionReplaceBackend(t, scopeC, scopeC.revision, advancedBytes)
	clear(advancedBytes)
	if advancedRevision == scopeC.revision {
		t.Fatal("LEGACY_PARTITION_ADVANCED_REVISION_UNCHANGED")
	}
	differentRevision := legacyPartitionReplaceBackend(t, scopeD, scopeD.revision, []byte("genuinely different backend bytes"))
	if differentRevision == scopeD.revision {
		t.Fatal("LEGACY_PARTITION_DIFFERENT_REVISION_UNCHANGED")
	}

	sealed, err := destSession.SealOwnedVaultFileFirstItemsFromLegacyPartition(request)
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_SEAL_FAILED: %v", err)
	}
	defer sealed.Clear()
	if sealed.SourceVaultID != work.ID || sealed.SourceVault == nil || !reflect.DeepEqual(*sealed.SourceVault, *sourceWorkMeta) {
		t.Fatal("LEGACY_PARTITION_SOURCE_PROVENANCE_MISMATCH")
	}
	if sealed.SourceArchiveSHA256 != sha256.Sum256(sourceArchive) {
		t.Fatal("LEGACY_PARTITION_SOURCE_ARCHIVE_DIGEST_MISMATCH")
	}
	if sealed.AuthorDeviceID == "" || sealed.AuthorPrincipalID == "" || sealed.State.Generation != 0 ||
		sealed.State.RemoteRevision != scopeA.revision ||
		!bytes.Equal(sealed.State.BaseBytes, scopeA.genesis) || !bytes.Equal(sealed.State.WorkingBytes, scopeA.genesis) {
		t.Fatal("LEGACY_PARTITION_SEALED_STATE_MISMATCH")
	}
	sealedFile, err := vaultfile.ParseFile(sealed.Sealed)
	if err != nil || sealedFile.Header.ContentSeq != 1 || sealedFile.Header.VaultID != publicA.VaultID ||
		bytes.Equal(sealed.Sealed, scopeA.genesis) {
		t.Fatal("LEGACY_PARTITION_SEALED_SUCCESSOR_SHAPE_MISMATCH")
	}

	_, metadata, opened, err := vault.OpenAuthenticatedItems(sealed.Sealed, scopeA.checkpoint, sealed.AuthorDeviceID, localAge)
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_DEST_OPEN_FAILED: %v", err)
	}
	defer clear(metadata)
	defer clearAuthenticatedItems(opened)
	if len(metadata) != 0 || len(opened) != len(sourceItems) {
		t.Fatal("LEGACY_PARTITION_DEST_ITEM_COUNT_MISMATCH")
	}
	for i := range opened {
		if opened[i].ID != sourceItems[i].ID {
			t.Fatal("LEGACY_PARTITION_DEST_ITEM_ID_MISMATCH")
		}
		if opened[i].ID == otherID {
			t.Fatal("LEGACY_PARTITION_DEST_MIXED_OTHER_GROUP")
		}
	}
	if !legacyPartitionItemsRepresented(sourceItems, opened) {
		t.Fatal("LEGACY_PARTITION_DEST_REPRESENTED_DATA_MISMATCH")
	}

	if _, _, cross, err := vault.OpenAuthenticatedItems(sealed.Sealed, scopeB.checkpoint, sealed.AuthorDeviceID, localAge); err == nil {
		clearAuthenticatedItems(cross)
		t.Fatal("LEGACY_PARTITION_CROSS_TARGET_OPEN_SUCCEEDED")
	}
	sourceAge := legacyPartitionLocalAge(t, sourceSession)
	if _, _, foreign, err := vault.OpenAuthenticatedItems(sealed.Sealed, scopeA.checkpoint, sealed.AuthorDeviceID, sourceAge); err == nil {
		clearAuthenticatedItems(foreign)
		t.Fatal("LEGACY_PARTITION_SOURCE_KEY_OPEN_SUCCEEDED")
	}

	refuseRequest := func(name string, bad OwnedVaultFileLegacyPartitionRequest, want error) {
		t.Helper()
		out, err := destSession.SealOwnedVaultFileFirstItemsFromLegacyPartition(bad)
		if err == nil || want != nil && !errors.Is(err, want) {
			t.Fatalf("LEGACY_PARTITION_REFUSAL_%s: err=%v want=%v", name, err, want)
		}
		if out.Sealed != nil || len(out.State.BaseBytes) != 0 || len(out.State.WorkingBytes) != 0 ||
			out.State.RemoteRevision != "" || out.State.Generation != 0 ||
			out.AuthorDeviceID != "" || out.AuthorPrincipalID != "" ||
			out.SourceVault != nil || out.SourceVaultID != "" ||
			out.SourceArchiveSHA256 != [sha256.Size]byte{} {
			t.Fatalf("LEGACY_PARTITION_REFUSAL_%s_LEAKED_OUTPUT", name)
		}
	}
	refuse := func(name string, mutate func(*OwnedVaultFileLegacyPartitionRequest), want error) {
		t.Helper()
		bad := request
		mutate(&bad)
		refuseRequest(name, bad, want)
	}
	refuse("wrong_selector", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Source.VaultID = "not-a-source-vault"
	}, ErrLegacyVaultPartitionSelector)
	refuse("display_name_selector", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Source.VaultID = work.Name
	}, ErrLegacyVaultPartitionSelector)
	refuse("wrong_archive", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Source.Archive = destArchive
	}, nil)
	refuse("tampered_archive", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Source.Archive = bytes.Clone(r.Source.Archive)
		r.Source.Archive[len(r.Source.Archive)-1] ^= 0xff
	}, nil)
	refuse("wrong_recovery_kit", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Source.RecoveryKit = destKit
	}, nil)
	refuse("wrong_source_password", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Source.Password = "wrong-source-factor"
	}, nil)
	refuse("wrong_source_key", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Source.Key = bytes.Repeat([]byte{0x72}, 16)
	}, nil)
	refuse("wrong_target", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Target = scopeB.target
	}, ErrVaultFileBaselineVerification)
	refuse("wrong_checkpoint", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Checkpoint = scopeB.checkpoint
	}, ErrVaultFileBaselineVerification)
	refuse("wrong_backend_root", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Target.BackendRoot = filepath.Join(dir, "missing-backend")
	}, ErrVaultFileBaselineJournal)
	refuse("wrong_backend_name", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Target.BackendName = "wrong-backend-name"
	}, ErrVaultFileBaselineJournal)
	refuse("wrong_backend_path", func(r *OwnedVaultFileLegacyPartitionRequest) {
		r.Target.BackendRoot = scopeC.backendRoot
	}, ErrVaultFileBaselineJournal)
	refuseRequest("advanced_backend_revision", requestFor(scopeC), ErrVaultFileBaselineJournal)
	refuseRequest("different_backend_bytes", requestFor(scopeD), ErrVaultFileBaselineJournal)

	if !bytes.Equal(sourceArchive, sourceArchiveBefore) ||
		!bytes.Equal(legacyPartitionReadFile(t, sourceArchivePath), sourceArchiveFileBefore) {
		t.Fatal("LEGACY_PARTITION_SOURCE_ARCHIVE_CHANGED")
	}
	if !bytes.Equal(legacyPartitionReadFile(t, destPath), destBefore) {
		t.Fatal("LEGACY_PARTITION_DEST_PERSONAL_CHANGED")
	}
	for _, journal := range []struct {
		name   string
		path   string
		before []byte
	}{
		{"a", scopeA.journalPath, journalABefore},
		{"b", scopeB.journalPath, journalBBefore},
		{"c", scopeC.journalPath, journalCBefore},
		{"d", scopeD.journalPath, journalDBefore},
	} {
		if !bytes.Equal(legacyPartitionReadFile(t, journal.path), journal.before) {
			t.Fatalf("LEGACY_PARTITION_DEST_JOURNAL_%s_CHANGED", journal.name)
		}
	}
	assertBackend := func(scope legacyPartitionGenesisScope, want []byte, wantRevision vaultfilebackend.Revision) {
		t.Helper()
		got, revision := legacyPartitionReadBackend(t, scope.backendRoot, scope.target.BackendName)
		defer clear(got)
		if !bytes.Equal(got, want) || revision != wantRevision {
			t.Fatalf("LEGACY_PARTITION_BACKEND_%s_MISMATCH", scope.target.BackendName)
		}
	}
	assertBackend(scopeA, scopeA.genesis, scopeA.revision)
	assertBackend(scopeB, scopeB.genesis, scopeB.revision)

	advancedBytesNow, advancedRevisionNow := legacyPartitionReadBackend(t, scopeC.backendRoot, scopeC.target.BackendName)
	if !bytes.Equal(advancedBytesNow, scopeC.genesis) || advancedRevisionNow != advancedRevision {
		clear(advancedBytesNow)
		t.Fatal("LEGACY_PARTITION_ADVANCED_BACKEND_MISMATCH")
	}
	clear(advancedBytesNow)

	differentBytesNow, differentRevisionNow := legacyPartitionReadBackend(t, scopeD.backendRoot, scopeD.target.BackendName)
	if bytes.Equal(differentBytesNow, scopeD.genesis) || differentRevisionNow != differentRevision {
		clear(differentBytesNow)
		t.Fatal("LEGACY_PARTITION_DIFFERENT_BACKEND_MISMATCH")
	}
	clear(differentBytesNow)
}

type legacyPartitionGenesisScope struct {
	target      OwnedVaultFileFirstSuccessorTarget
	checkpoint  *vaultfile.PolicyCheckpoint
	genesis     []byte
	revision    vaultfilebackend.Revision
	journalPath string
	backendRoot string
}

func legacyPartitionPublishGenesis(t *testing.T, dir, name string, ownership VaultFileOwnershipPublic, intentPath string) legacyPartitionGenesisScope {
	t.Helper()
	rootPublic, err := hex.DecodeString(ownership.OwnerRootPublicKey)
	if err != nil || len(rootPublic) != ed25519.PublicKeySize {
		t.Fatal("LEGACY_PARTITION_OWNER_ROOT_INVALID")
	}
	rootPin := &vaultfile.GenesisRootPin{
		VaultID:            ownership.VaultID,
		OwnerRootKeyID:     ownership.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(bytes.Clone(rootPublic)),
	}
	journal, err := vaultfilejournal.OpenExistingIntent(intentPath)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_INTENT_OPEN_FAILED")
	}
	intent, err := journal.Load()
	if err != nil {
		_ = journal.Close()
		t.Fatal("LEGACY_PARTITION_INTENT_LOAD_FAILED")
	}
	backendRoot := filepath.Join(dir, "backend-"+name)
	backend, err := vaultfilebackend.OpenDir(backendRoot)
	if err != nil {
		_ = journal.Close()
		t.Fatal("LEGACY_PARTITION_BACKEND_OPEN_FAILED")
	}
	publishErr := vaultfilepublish.PublishGenesisDir(context.Background(), backend, journal, rootPin)
	backendCloseErr := backend.Close()
	journalCloseErr := journal.Close()
	if publishErr != nil || backendCloseErr != nil || journalCloseErr != nil {
		t.Fatalf("LEGACY_PARTITION_GENESIS_PUBLISH_FAILED: publish=%v backend=%v journal=%v", publishErr, backendCloseErr, journalCloseErr)
	}
	data, revision := legacyPartitionReadBackend(t, backendRoot, intent.Name)
	clear(intent.SealedBytes)

	stateJournal, err := vaultfilejournal.OpenExisting(intentPath)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ACKED_JOURNAL_OPEN_FAILED")
	}
	state, stateErr := stateJournal.LoadGenesisBaseline()
	stateCloseErr := stateJournal.Close()
	if stateErr != nil || stateCloseErr != nil || state.RemoteRevision != revision || !bytes.Equal(state.BaseBytes, data) {
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		t.Fatalf("LEGACY_PARTITION_ACKED_STATE_MISMATCH: load=%v close=%v", stateErr, stateCloseErr)
	}
	clear(state.BaseBytes)
	clear(state.WorkingBytes)

	checkpoint, err := vaultfile.VerifyGenesis(data, rootPin)
	if err != nil || checkpoint == nil {
		t.Fatal("LEGACY_PARTITION_GENESIS_CHECKPOINT_FAILED")
	}
	targetPin := vaultfilejournal.OwnedGenesisPin{
		Root: vaultfile.GenesisRootPin{
			VaultID:            ownership.VaultID,
			OwnerRootKeyID:     ownership.OwnerRootKeyID,
			OwnerRootPublicKey: ed25519.PublicKey(bytes.Clone(rootPublic)),
		},
		SealedSHA256: sha256.Sum256(data),
		OperationID:  genesisFileOperationID(t, data),
	}
	return legacyPartitionGenesisScope{
		target: OwnedVaultFileFirstSuccessorTarget{
			BackendRoot: backendRoot,
			BackendName: intent.Name,
			Pin:         targetPin,
		},
		checkpoint:  checkpoint,
		genesis:     data,
		revision:    revision,
		journalPath: intentPath,
		backendRoot: backendRoot,
	}
}

func legacyPartitionReadBackend(t *testing.T, root, name string) ([]byte, vaultfilebackend.Revision) {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(root)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_BACKEND_REOPEN_FAILED")
	}
	result, readErr := backend.Read(context.Background(), name)
	closeErr := backend.Close()
	if readErr != nil || closeErr != nil || len(result.Bytes) == 0 || result.Revision == "" {
		clear(result.Bytes)
		t.Fatalf("LEGACY_PARTITION_BACKEND_READ_FAILED: read=%v close=%v", readErr, closeErr)
	}
	data := bytes.Clone(result.Bytes)
	clear(result.Bytes)
	return data, result.Revision
}

func legacyPartitionReplaceBackend(t *testing.T, scope legacyPartitionGenesisScope, expected vaultfilebackend.Revision, content []byte) vaultfilebackend.Revision {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(scope.backendRoot)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_BACKEND_REOPEN_FAILED")
	}
	replaceErr := backend.ReplaceIfVersion(context.Background(), scope.target.BackendName, expected, content)
	closeErr := backend.Close()
	if replaceErr != nil || closeErr != nil {
		t.Fatalf("LEGACY_PARTITION_BACKEND_REPLACE_FAILED: replace=%v close=%v", replaceErr, closeErr)
	}
	observed, revision := legacyPartitionReadBackend(t, scope.backendRoot, scope.target.BackendName)
	clear(observed)
	return revision
}

func legacyPartitionLocalAge(t *testing.T, session *Session) *age.X25519Identity {
	t.Helper()
	var account identity
	if err := json.Unmarshal(session.material, &account); err != nil || account.Device == "" {
		t.Fatal("LEGACY_PARTITION_LOCAL_IDENTITY_FAILED")
	}
	defer func() {
		account.clear()
		account.Device = ""
	}()
	local, err := age.ParseX25519Identity(account.Device)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_LOCAL_AGE_FAILED")
	}
	return local
}

func legacyPartitionItemsRepresented(want, got []vault.Item) bool {
	if len(want) != len(got) {
		return false
	}
	left := make([]vault.Item, len(want))
	right := make([]vault.Item, len(got))
	for i := range want {
		left[i] = legacyPartitionComparableItem(want[i])
		right[i] = legacyPartitionComparableItem(got[i])
	}
	defer clearAuthenticatedItems(left)
	defer clearAuthenticatedItems(right)
	return reflect.DeepEqual(left, right)
}

// legacyPartitionComparableItem keeps every represented field and normalizes
// only the same semantic distinctions the authenticated wire format derives:
// the effective category, the effective default vault selector, empty buffers
// and the location attached to a trash timestamp.
func legacyPartitionComparableItem(item vault.Item) vault.Item {
	out := vault.CloneItem(item)
	if out.VaultID == vault.DefaultVaultID {
		out.VaultID = ""
	}
	if out.Category == vault.CategoryLogin && out.Kind == "login" ||
		out.Category == vault.CategoryDocument && out.Kind == "document" ||
		out.Category == vault.CategorySSHKey && out.Kind == "ssh-key" {
		out.Category = ""
	}
	if len(out.Attachment) == 0 {
		out.Attachment = nil
	}
	if len(out.ImportSource) == 0 {
		out.ImportSource = nil
	}
	if len(out.SSHSeed) == 0 {
		out.SSHSeed = nil
	}
	if len(out.SSHPublicKey) == 0 {
		out.SSHPublicKey = nil
	}
	if len(out.Passkey) == 0 {
		out.Passkey = nil
	}
	if len(out.Passkeys) == 0 {
		out.Passkeys = nil
	}
	for i := range out.Attachments {
		if len(out.Attachments[i].Content) == 0 {
			out.Attachments[i].Content = nil
		}
	}
	if out.TrashedAt != nil {
		instant := out.TrashedAt.UTC()
		out.TrashedAt = &instant
	}
	return out
}

func legacyPartitionReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_READ_FAILED: %v", err)
	}
	return raw
}
