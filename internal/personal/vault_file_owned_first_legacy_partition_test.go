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
	journalDir := legacyPartitionPrivateDir(t, dir, "genesis-journals")
	publish := func(name string, public VaultFileOwnershipPublic) legacyPartitionGenesisScope {
		t.Helper()
		intentPath := filepath.Join(journalDir, "genesis-"+name+".journal")
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

func TestOwnedVaultFileLegacyPartitionsUseIndependentDataKeys(t *testing.T) {
	dir := t.TempDir()

	// One genuine, independently authenticated recovery archive with two
	// explicitly declared custom source partitions, each carrying items, plus
	// an empty implicit default partition.
	sourcePath := filepath.Join(dir, "source.ll")
	sourcePassword := "synthetic-legacy-partition-isolation-source-factor"
	sourceKey := bytes.Repeat([]byte{0x37}, 16)
	if err := Create(sourcePath, sourcePassword, sourceKey); err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_CREATE_FAILED")
	}
	sourceSession, err := UnlockSession(sourcePath, []byte(sourcePassword), sourceKey, time.Hour)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_UNLOCK_FAILED")
	}
	t.Cleanup(sourceSession.Lock)
	partitionA, err := sourceSession.CreateVault("Partition A", "first isolated source partition", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITION_A_FAILED")
	}
	partitionB, err := sourceSession.CreateVault("Partition B", "second isolated source partition", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITION_B_FAILED")
	}

	stamp := time.Unix(1_700_001_234, 0).UTC()
	trashedAt := stamp.Add(time.Hour)
	auto := true
	add := func(label string, item vault.Item) string {
		t.Helper()
		id, _, err := sourceSession.AddItem(item, v2Gate(t, sourceSession))
		if err != nil {
			t.Fatalf("LEGACY_PARTITION_ISOLATION_SOURCE_ADD_%s_FAILED: %v", label, err)
		}
		return id
	}
	aLoginID := add("A_LOGIN", vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: partitionA.ID,
		Title: "Partition A active login", Username: "partition-a-user", Password: "partition-a-password",
		URL: "https://partition-a.example.test/", Notes: "partition a notes",
		URLs: []vault.ItemURL{
			{Label: "primary", URL: "https://partition-a.example.test/", Primary: true, MatchMode: vault.URLMatchOrigin},
			{Label: "secondary", URL: "https://secondary.partition-a.example.test/", MatchMode: vault.URLMatchHost},
		},
		Favorite: true, AutoSubmit: &auto, Tags: []string{"partition-a", "isolation"},
		Sections: []vault.ItemSection{{ID: "partition-a-section", Title: "Partition A fields", Fields: []vault.CustomField{
			{ID: "partition-a-concealed", Label: "Concealed", Type: vault.FieldTypeConcealed, Value: "partition-a-concealed-value", Protected: true},
			{ID: "partition-a-email", Label: "Email", Type: vault.FieldTypeEmail, Value: "partition-a@example.test"},
		}}},
		History: []vault.ItemHistoryEntry{{
			Timestamp: stamp.Unix(), Action: "edit", Password: "partition-a-prior-password", Title: "Partition A prior title",
			Username: "partition-a-prior-user", Notes: "partition a prior notes",
			Sections: []vault.ItemSection{{ID: "partition-a-prior-section", Title: "Prior", Fields: []vault.CustomField{{
				ID: "partition-a-prior-field", Label: "Prior", Type: vault.FieldTypeText, Value: "partition-a-prior-value",
			}}}},
		}},
		Attachments: []vault.AttachmentMeta{{
			FileName: "partition-a.bin", MIMEType: "application/octet-stream", Protected: true,
			Content: []byte{0x00, 0x01, 0x7f, 0xff, 0x10},
		}},
		ImportSource: []byte("partition-a-import-provenance"),
	})
	aDocumentID := add("A_DOCUMENT", vault.Item{
		Kind: "document", Category: vault.CategoryDocument, VaultID: partitionA.ID,
		Title: "Partition A document", Filename: "partition-a-document.bin",
		Attachment: []byte{0x50, 0x4b, 0x03, 0x04}, AttachmentProtected: true,
		ImportSource: []byte("partition-a-document-import-provenance"),
	})
	aCardID := add("A_CARD", vault.Item{
		Kind: "credit_card", Category: vault.CategoryCreditCard, VaultID: partitionA.ID,
		Title: "Partition A card",
		CreditCard: &vault.CreditCardDetails{
			CardholderName: "Synthetic Partition A Holder", Type: "visa", Number: "4111111111111111",
			Verification: "123", ExpiryDate: "2030-01", ValidFrom: "2020-01",
			PIN: "9999", IssuingBank: "Synthetic Partition A Bank",
		},
	})
	bLoginID := add("B_LOGIN", vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: partitionB.ID,
		Title: "Partition B active login", Username: "partition-b-user", Password: "partition-b-password",
		URL: "https://partition-b.example.test/", Notes: "partition b notes",
		Tags: []string{"partition-b", "isolation"},
		History: []vault.ItemHistoryEntry{{
			Timestamp: stamp.Unix(), Action: "edit", Title: "Partition B prior title", Password: "partition-b-prior-password",
		}},
		Attachments: []vault.AttachmentMeta{{
			FileName: "partition-b.bin", MIMEType: "application/octet-stream", Protected: true,
			Content: []byte{0xde, 0xad, 0xbe, 0xef},
		}},
		ImportSource: []byte("partition-b-import-provenance"),
	})
	bTrashedID := add("B_TRASHED", vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: partitionB.ID,
		Title: "Partition B trashed login", Username: "partition-b-trashed-user", Password: "partition-b-trashed-password",
		State: "trashed", PreviousState: "archived", TrashedAt: &trashedAt,
		History:      []vault.ItemHistoryEntry{{Timestamp: stamp.Unix(), Action: "edit", Title: "Partition B trashed prior"}},
		ImportSource: []byte("partition-b-trashed-import-provenance"),
		Attachments: []vault.AttachmentMeta{{
			FileName: "partition-b-trashed.bin", MIMEType: "application/octet-stream", Protected: true,
			Content: []byte{0xca, 0xfe, 0xba, 0xbe},
		}},
	})

	sourceArchivePath := filepath.Join(dir, "source.llb")
	sourceKit, err := Backup(sourcePath, sourceArchivePath, sourcePassword, sourceKey)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_BACKUP_FAILED")
	}
	sourceArchive := legacyPartitionReadFile(t, sourceArchivePath)
	sourceArchiveBefore := bytes.Clone(sourceArchive)
	sourceArchiveFileBefore := legacyPartitionReadFile(t, sourceArchivePath)

	sourcePayload, err := verifyRecoveryArchive(sourceArchive, sourcePassword, sourceKey, sourceKit, true)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_VERIFY_FAILED")
	}
	defer clearDecodedArchiveSensitive(sourcePayload)
	if len(sourcePayload.Vaults) != 2 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITION_COUNT_MISMATCH")
	}
	partitionMeta := func(vaultID string) *vault.VaultMeta {
		for i := range sourcePayload.Vaults {
			if sourcePayload.Vaults[i].ID == vaultID {
				metadata := sourcePayload.Vaults[i]
				return &metadata
			}
		}
		return nil
	}
	sourceMetaA := partitionMeta(partitionA.ID)
	sourceMetaB := partitionMeta(partitionB.ID)
	if sourceMetaA == nil || sourceMetaB == nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITION_METADATA_MISSING")
	}
	sourceItemsFor := func(vaultID string) []vault.Item {
		var selected []vault.Item
		for i := range sourcePayload.Items {
			if sourcePayload.Items[i].EffectiveVaultID() == vaultID {
				selected = append(selected, sourcePayload.Items[i])
			}
		}
		return selected
	}
	sourceItemsA := sourceItemsFor(partitionA.ID)
	sourceItemsB := sourceItemsFor(partitionB.ID)
	if len(sourceItemsA) != 3 || len(sourceItemsB) != 2 ||
		len(sourceItemsA)+len(sourceItemsB) != len(sourcePayload.Items) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITION_SHAPE_MISMATCH")
	}
	sourceIDsA := map[string]bool{}
	for i := range sourceItemsA {
		sourceIDsA[sourceItemsA[i].ID] = true
	}
	sourceIDsB := map[string]bool{}
	for i := range sourceItemsB {
		sourceIDsB[sourceItemsB[i].ID] = true
	}
	for _, id := range []string{aLoginID, aDocumentID, aCardID} {
		if !sourceIDsA[id] {
			t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITION_A_ITEM_MISSING")
		}
	}
	for _, id := range []string{bLoginID, bTrashedID} {
		if !sourceIDsB[id] {
			t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITION_B_ITEM_MISSING")
		}
	}
	if sourceIDsA[bLoginID] || sourceIDsA[bTrashedID] || sourceIDsB[aLoginID] ||
		sourceIDsB[aDocumentID] || sourceIDsB[aCardID] {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PARTITIONS_NOT_DISJOINT")
	}
	byID := make(map[string]vault.Item, len(sourcePayload.Items))
	for i := range sourcePayload.Items {
		byID[sourcePayload.Items[i].ID] = sourcePayload.Items[i]
	}
	if item := byID[aLoginID]; len(item.History) == 0 || len(item.Sections) == 0 ||
		len(item.URLs) != 2 || len(item.Attachments) != 1 || len(item.Attachments[0].Content) == 0 ||
		!item.Attachments[0].Protected || len(item.ImportSource) == 0 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_A_ACTIVE_REPRESENTATION_MISSING")
	}
	if item := byID[aDocumentID]; len(item.Attachment) == 0 || !item.AttachmentProtected {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_A_DOCUMENT_REPRESENTATION_MISSING")
	}
	if item := byID[aCardID]; item.CreditCard == nil || item.CreditCard.Number == "" {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_A_TYPED_REPRESENTATION_MISSING")
	}
	if item := byID[bLoginID]; len(item.History) == 0 || len(item.Attachments) != 1 ||
		len(item.Attachments[0].Content) == 0 || len(item.ImportSource) == 0 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_B_ACTIVE_REPRESENTATION_MISSING")
	}
	if item := byID[bTrashedID]; item.State != "trashed" || item.PreviousState != "archived" ||
		item.TrashedAt == nil || len(item.History) == 0 || len(item.ImportSource) == 0 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_B_TRASH_REPRESENTATION_MISSING")
	}

	// Two independent owned destination scopes in the same real local
	// personal vault, each with its own published genesis object and observed
	// backend revision.
	destPath := filepath.Join(dir, "destination.ll")
	destPassword := "synthetic-legacy-partition-isolation-destination-factor"
	destKey := bytes.Repeat([]byte{0x47}, 16)
	if err := Create(destPath, destPassword, destKey); err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_CREATE_FAILED")
	}
	destSession, err := UnlockSession(destPath, []byte(destPassword), destKey, time.Hour)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_UNLOCK_FAILED")
	}
	t.Cleanup(destSession.Lock)
	prepareOwner := func(label string) VaultFileOwnershipPublic {
		t.Helper()
		selector, err := randomID()
		if err != nil {
			t.Fatalf("LEGACY_PARTITION_ISOLATION_USER_%s_FAILED", label)
		}
		public, err := destSession.PrepareVaultFileOwnership(selector)
		if err != nil {
			t.Fatalf("LEGACY_PARTITION_ISOLATION_CUSTODY_%s_FAILED", label)
		}
		return public
	}
	publicA := prepareOwner("A")
	publicB := prepareOwner("B")
	if publicA.VaultID == publicB.VaultID {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_VAULT_ID_NOT_DISTINCT")
	}
	destArchivePath := filepath.Join(dir, "destination.llb")
	destKit, err := Backup(destPath, destArchivePath, destPassword, destKey)
	if err != nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_BACKUP_FAILED")
	}
	journalDir := legacyPartitionPrivateDir(t, dir, "genesis-journals")
	publish := func(name string, public VaultFileOwnershipPublic) legacyPartitionGenesisScope {
		t.Helper()
		intentPath := filepath.Join(journalDir, "genesis-"+name+".journal")
		if _, err := destSession.PrepareVaultFileGenesis(VaultFileGenesisRequest{
			VaultID: public.VaultID, Name: "legacy-partition-" + name, IntentPath: intentPath, ArchivePath: destArchivePath,
		}, []byte(destPassword), destKey, []byte(destKit)); err != nil {
			t.Fatalf("LEGACY_PARTITION_ISOLATION_GENESIS_%s_FAILED: %v", name, err)
		}
		return legacyPartitionPublishGenesis(t, dir, name, public, intentPath)
	}
	scopeA := publish("a", publicA)
	scopeB := publish("b", publicB)
	t.Cleanup(func() {
		clearVaultFilePolicyCheckpoint(scopeA.checkpoint)
		clearVaultFilePolicyCheckpoint(scopeB.checkpoint)
	})
	localAge := legacyPartitionLocalAge(t, destSession)

	journalABefore := legacyPartitionReadFile(t, scopeA.journalPath)
	journalBBefore := legacyPartitionReadFile(t, scopeB.journalPath)
	destBefore := legacyPartitionReadFile(t, destPath)

	requestFor := func(scope legacyPartitionGenesisScope, vaultID string) OwnedVaultFileLegacyPartitionRequest {
		return OwnedVaultFileLegacyPartitionRequest{
			JournalPath: scope.journalPath, Target: scope.target, Checkpoint: scope.checkpoint,
			ExpectedGenesis: scope.genesis,
			Password:        []byte(destPassword), Key: destKey,
			Source: LegacyVaultPartitionSource{
				Archive: sourceArchive, Password: sourcePassword, Key: sourceKey,
				RecoveryKit: sourceKit, VaultID: vaultID,
			},
		}
	}
	sealedA, err := destSession.SealOwnedVaultFileFirstItemsFromLegacyPartition(requestFor(scopeA, partitionA.ID))
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_ISOLATION_SEAL_A_FAILED: %v", err)
	}
	defer sealedA.Clear()
	sealedB, err := destSession.SealOwnedVaultFileFirstItemsFromLegacyPartition(requestFor(scopeB, partitionB.ID))
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_ISOLATION_SEAL_B_FAILED: %v", err)
	}
	defer sealedB.Clear()

	fileA, itemsA := legacyPartitionOpenSealed(t, sealedA, scopeA, sourceArchive, partitionA.ID, sourceMetaA, sourceItemsA, localAge)
	defer clearAuthenticatedItems(itemsA)
	fileB, itemsB := legacyPartitionOpenSealed(t, sealedB, scopeB, sourceArchive, partitionB.ID, sourceMetaB, sourceItemsB, localAge)
	defer clearAuthenticatedItems(itemsB)
	if sealedA.SourceArchiveSHA256 != sealedB.SourceArchiveSHA256 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_ARCHIVE_BINDING_MISMATCH")
	}

	// The two destination identities and their real owner-management Ed25519
	// keys are distinct, and each authenticated file carries its own key.
	if fileA.Header.VaultID != publicA.VaultID || fileB.Header.VaultID != publicB.VaultID ||
		fileA.Header.VaultID == fileB.Header.VaultID {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_FILE_VAULT_ID_MISMATCH")
	}
	rootA := legacyPartitionOwnerRoot(t, publicA)
	rootB := legacyPartitionOwnerRoot(t, publicB)
	if bytes.Equal(rootA, rootB) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_OWNER_ROOT_NOT_DISTINCT")
	}
	if !bytes.Equal(rootA, scopeA.checkpoint.OwnerRootPublicKey) ||
		!bytes.Equal(rootB, scopeB.checkpoint.OwnerRootPublicKey) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_OWNER_ROOT_CHECKPOINT_MISMATCH")
	}
	if len(fileA.SignedPolicyProofs) == 0 || len(fileB.SignedPolicyProofs) == 0 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_POLICY_MISSING")
	}
	policyA := fileA.SignedPolicyProofs[len(fileA.SignedPolicyProofs)-1].Policy
	policyB := fileB.SignedPolicyProofs[len(fileB.SignedPolicyProofs)-1].Policy
	if !bytes.Equal(policyA.OwnerRoot.PublicKey, rootA) ||
		!bytes.Equal(policyB.OwnerRoot.PublicKey, rootB) ||
		policyA.OwnerRoot.Alg != vaultfile.PolicySigAlgEd25519 ||
		policyB.OwnerRoot.Alg != vaultfile.PolicySigAlgEd25519 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_OWNER_ROOT_POLICY_MISMATCH")
	}

	// The selected proof is the real genesis policy proof copied unchanged into
	// the sealed successor by the product sealing path. Its SignerID is the
	// candidate's owner-root key ID, its policy sequence and digest match the
	// candidate's checkpoint and file header, and ParseFile validated its
	// signed document as the canonical policy encoding. The successor's own
	// content signature is device-signed, so it is not used as a root signature.
	proofA, transcriptA := legacyPartitionRootSignedCandidateProof(t, fileA, scopeA.checkpoint, rootA)
	proofB, transcriptB := legacyPartitionRootSignedCandidateProof(t, fileB, scopeB.checkpoint, rootB)
	if bytes.Equal(proofA.Sig, proofB.Sig) || bytes.Equal(transcriptA, transcriptB) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_ROOT_SIGNATURE_NOT_CANDIDATE_BOUND")
	}
	if !ed25519.Verify(rootA, transcriptA, proofA.Sig) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_OWNER_A_SIGNATURE_REJECTED")
	}
	if ed25519.Verify(rootB, transcriptA, proofA.Sig) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_CROSS_OWNER_B_ACCEPTED_A")
	}
	if !ed25519.Verify(rootB, transcriptB, proofB.Sig) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_OWNER_B_SIGNATURE_REJECTED")
	}
	if ed25519.Verify(rootA, transcriptB, proofB.Sig) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_CROSS_OWNER_A_ACCEPTED_B")
	}

	// Every selected source record appears exactly once across the two sealed
	// partitions, and only under the partition that was selected.
	sourceIDs := map[string]bool{}
	for i := range sourcePayload.Items {
		sourceIDs[sourcePayload.Items[i].ID] = true
	}
	seen := map[string]bool{}
	for i := range itemsA {
		id := itemsA[i].ID
		if !sourceIDsA[id] || sourceIDsB[id] || seen[id] {
			t.Fatal("LEGACY_PARTITION_ISOLATION_PARTITION_A_COVERAGE_MISMATCH")
		}
		seen[id] = true
	}
	for i := range itemsB {
		id := itemsB[i].ID
		if !sourceIDsB[id] || sourceIDsA[id] || seen[id] {
			t.Fatal("LEGACY_PARTITION_ISOLATION_PARTITION_B_COVERAGE_MISMATCH")
		}
		seen[id] = true
	}
	if len(seen) != len(sourceIDs) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_COVERAGE_INCOMPLETE")
	}

	// Both destinations have their own VUK and CEK. The actual item payload
	// ciphertexts are distinct, and each side's real key material fails to
	// decrypt the other side's real bytes with the expected typed
	// authentication error.
	vukA := legacyPartitionOpenVUK(t, fileA, scopeA.checkpoint, sealedA.AuthorDeviceID, localAge)
	defer clear(vukA)
	vukB := legacyPartitionOpenVUK(t, fileB, scopeB.checkpoint, sealedB.AuthorDeviceID, localAge)
	defer clear(vukB)
	if len(vukA) != vaultfile.CEKSize || len(vukB) != vaultfile.CEKSize || bytes.Equal(vukA, vukB) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_VUK_NOT_DISTINCT")
	}
	crossAtoB, err := vaultfile.OpenCEK(vukA, fileB.Header, fileB.CEKSlot)
	if crossAtoB != nil || !legacyPartitionIsVaultFileError(err, vaultfile.CodeCEKEnvelopeFailed, "cek_slot") {
		clear(crossAtoB)
		t.Fatalf("LEGACY_PARTITION_ISOLATION_CROSS_VUK_A_TO_B_NOT_AUTH_FAILURE: %v", err)
	}
	crossBtoA, err := vaultfile.OpenCEK(vukB, fileA.Header, fileA.CEKSlot)
	if crossBtoA != nil || !legacyPartitionIsVaultFileError(err, vaultfile.CodeCEKEnvelopeFailed, "cek_slot") {
		clear(crossBtoA)
		t.Fatalf("LEGACY_PARTITION_ISOLATION_CROSS_VUK_B_TO_A_NOT_AUTH_FAILURE: %v", err)
	}
	cekA, err := vaultfile.OpenCEK(vukA, fileA.Header, fileA.CEKSlot)
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_ISOLATION_OWN_CEK_A_FAILED: %v", err)
	}
	defer clear(cekA)
	cekB, err := vaultfile.OpenCEK(vukB, fileB.Header, fileB.CEKSlot)
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_ISOLATION_OWN_CEK_B_FAILED: %v", err)
	}
	defer clear(cekB)
	if len(cekA) != vaultfile.CEKSize || len(cekB) != vaultfile.CEKSize || bytes.Equal(cekA, cekB) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_CEK_NOT_DISTINCT")
	}
	if len(fileA.KDBXCiphertext) == 0 || len(fileB.KDBXCiphertext) == 0 ||
		bytes.Equal(fileA.KDBXCiphertext, fileB.KDBXCiphertext) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_ITEM_CIPHERTEXT_NOT_DISTINCT")
	}
	if db, err := vaultfile.OpenKDBXPayload(fileB.KDBXCiphertext, cekA); err == nil || db != nil ||
		!legacyPartitionIsVaultFileError(err, vaultfile.CodeKDBXPayloadInvalid, "") {
		t.Fatalf("LEGACY_PARTITION_ISOLATION_CROSS_CEK_A_TO_B_NOT_AUTH_FAILURE: %v", err)
	}
	if db, err := vaultfile.OpenKDBXPayload(fileA.KDBXCiphertext, cekB); err == nil || db != nil ||
		!legacyPartitionIsVaultFileError(err, vaultfile.CodeKDBXPayloadInvalid, "") {
		t.Fatalf("LEGACY_PARTITION_ISOLATION_CROSS_CEK_B_TO_A_NOT_AUTH_FAILURE: %v", err)
	}

	// Sealing is observation-only: the source archive, the destination
	// personal store and journals, and both published genesis bytes and
	// backend revisions remain exactly as they were.
	if !bytes.Equal(sourceArchive, sourceArchiveBefore) ||
		!bytes.Equal(legacyPartitionReadFile(t, sourceArchivePath), sourceArchiveFileBefore) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_ARCHIVE_CHANGED")
	}
	if !bytes.Equal(legacyPartitionReadFile(t, destPath), destBefore) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_PERSONAL_CHANGED")
	}
	if !bytes.Equal(legacyPartitionReadFile(t, scopeA.journalPath), journalABefore) ||
		!bytes.Equal(legacyPartitionReadFile(t, scopeB.journalPath), journalBBefore) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_JOURNAL_CHANGED")
	}
	assertBackend := func(scope legacyPartitionGenesisScope) {
		t.Helper()
		got, revision := legacyPartitionReadBackend(t, scope.backendRoot, scope.target.BackendName)
		defer clear(got)
		if !bytes.Equal(got, scope.genesis) || revision != scope.revision {
			t.Fatalf("LEGACY_PARTITION_ISOLATION_BACKEND_%s_OVERWRITTEN", scope.target.BackendName)
		}
	}
	assertBackend(scopeA)
	assertBackend(scopeB)
}

func legacyPartitionOpenSealed(t *testing.T, sealed VaultFileSealedLegacyPartition, scope legacyPartitionGenesisScope, sourceArchive []byte, sourceVaultID string, sourceMeta *vault.VaultMeta, sourceItems []vault.Item, identity *age.X25519Identity) (*vaultfile.File, []vault.Item) {
	t.Helper()
	file, metadata, items, err := vault.OpenAuthenticatedItems(sealed.Sealed, scope.checkpoint, sealed.AuthorDeviceID, identity)
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_ISOLATION_OWN_OPEN_FAILED: %v", err)
	}
	if len(metadata) != 0 {
		clear(metadata)
		clearAuthenticatedItems(items)
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_METADATA_NOT_EMPTY")
	}
	clear(metadata)
	if len(items) != len(sourceItems) {
		clearAuthenticatedItems(items)
		t.Fatalf("LEGACY_PARTITION_ISOLATION_DEST_ITEM_COUNT_MISMATCH: got=%d want=%d", len(items), len(sourceItems))
	}
	for i := range items {
		if items[i].ID != sourceItems[i].ID {
			clearAuthenticatedItems(items)
			t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_ITEM_ID_MISMATCH")
		}
	}
	if !legacyPartitionItemsRepresented(sourceItems, items) {
		clearAuthenticatedItems(items)
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_REPRESENTED_DATA_MISMATCH")
	}

	// Only after the sealed bytes were independently authenticated and
	// reopened is the caller-visible output compared with real source and
	// genesis observations.
	if sealed.SourceVaultID != sourceVaultID {
		clearAuthenticatedItems(items)
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_PROVENANCE_MISMATCH")
	}
	if sourceMeta == nil {
		if sealed.SourceVault != nil {
			clearAuthenticatedItems(items)
			t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_METADATA_UNEXPECTED")
		}
	} else if sealed.SourceVault == nil || !reflect.DeepEqual(*sealed.SourceVault, *sourceMeta) {
		clearAuthenticatedItems(items)
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_METADATA_MISMATCH")
	}
	if sealed.SourceArchiveSHA256 != sha256.Sum256(sourceArchive) {
		clearAuthenticatedItems(items)
		t.Fatal("LEGACY_PARTITION_ISOLATION_SOURCE_ARCHIVE_DIGEST_MISMATCH")
	}
	if sealed.State.Generation != 0 || sealed.State.RemoteRevision != scope.revision ||
		!bytes.Equal(sealed.State.BaseBytes, scope.genesis) ||
		!bytes.Equal(sealed.State.WorkingBytes, scope.genesis) {
		clearAuthenticatedItems(items)
		t.Fatal("LEGACY_PARTITION_ISOLATION_SEALED_STATE_MISMATCH")
	}
	if file.Header.ContentSeq != 1 || file.Header.VaultID != scope.target.Pin.Root.VaultID {
		clearAuthenticatedItems(items)
		t.Fatal("LEGACY_PARTITION_ISOLATION_DEST_FILE_SHAPE_MISMATCH")
	}
	return file, items
}

func legacyPartitionOpenVUK(t *testing.T, file *vaultfile.File, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity) []byte {
	t.Helper()
	if file == nil || checkpoint == nil || identity == nil || deviceID == "" || len(file.SignedPolicyProofs) == 0 {
		t.Fatal("LEGACY_PARTITION_ISOLATION_VUK_CONTEXT_INVALID")
	}
	policy := &file.SignedPolicyProofs[len(file.SignedPolicyProofs)-1].Policy
	recipient := ""
	for i := range policy.Devices {
		if policy.Devices[i].DeviceID == deviceID {
			recipient = policy.Devices[i].AgeEncryptionKey
			break
		}
	}
	var slot *vaultfile.DeviceSlot
	for i := range file.VUKDeviceSlots {
		if file.VUKDeviceSlots[i].DeviceID == deviceID {
			slot = &file.VUKDeviceSlots[i]
			break
		}
	}
	if recipient == "" || slot == nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_VUK_SLOT_MISSING")
	}
	vuk, err := vaultfile.OpenVUKForDevice(*slot, checkpoint.VaultID, file.Header.KeyEpoch, deviceID, recipient, identity)
	if err != nil || len(vuk) != vaultfile.CEKSize {
		clear(vuk)
		t.Fatalf("LEGACY_PARTITION_ISOLATION_OWN_VUK_OPEN_FAILED: %v", err)
	}
	return vuk
}

func legacyPartitionOwnerRoot(t *testing.T, public VaultFileOwnershipPublic) ed25519.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(public.OwnerRootPublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatal("LEGACY_PARTITION_ISOLATION_OWNER_ROOT_INVALID")
	}
	return ed25519.PublicKey(raw)
}

// legacyPartitionRootSignedCandidateProof returns the owner-root-signed policy
// proof carried by candidate together with the exact v1 signing transcript.
// ParseFile already established that proof.Document is the canonical encoding
// of proof.Policy, so this returns the product-produced transcripts and
// signatures verbatim rather than re-encoding a substitute before verification.
func legacyPartitionRootSignedCandidateProof(t *testing.T, candidate *vaultfile.File, checkpoint *vaultfile.PolicyCheckpoint, ownerRoot ed25519.PublicKey) (*vaultfile.SignedPolicy, []byte) {
	t.Helper()
	if candidate == nil || checkpoint == nil || len(ownerRoot) != ed25519.PublicKeySize {
		t.Fatal("LEGACY_PARTITION_ISOLATION_CANDIDATE_PROOF_CONTEXT_INVALID")
	}
	if candidate.Header.VaultID != checkpoint.VaultID ||
		candidate.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(candidate.Header.PolicyDigest, checkpoint.PolicyDigest) ||
		!bytes.Equal(ownerRoot, checkpoint.OwnerRootPublicKey) {
		t.Fatal("LEGACY_PARTITION_ISOLATION_CANDIDATE_PROOF_CHECKPOINT_MISMATCH")
	}
	var proof *vaultfile.SignedPolicy
	for i := range candidate.SignedPolicyProofs {
		current := &candidate.SignedPolicyProofs[i]
		if current.Policy.PolicySeq != checkpoint.PolicySeq ||
			current.SignerID != checkpoint.OwnerRootKeyID ||
			current.Alg != vaultfile.PolicySigAlgEd25519 ||
			!bytes.Equal(current.Policy.OwnerRoot.PublicKey, ownerRoot) ||
			!bytes.Equal(vaultfile.PolicyDigest(&current.Policy), checkpoint.PolicyDigest) {
			continue
		}
		proof = current
		break
	}
	if proof == nil {
		t.Fatal("LEGACY_PARTITION_ISOLATION_CANDIDATE_ROOT_PROOF_MISSING")
	}
	transcript := make([]byte, 0, len(vaultfile.DomainPolicyDocumentSignature)+1+len(proof.Document))
	transcript = append(transcript, vaultfile.DomainPolicyDocumentSignature...)
	transcript = append(transcript, 0)
	transcript = append(transcript, proof.Document...)
	return proof, transcript
}

func legacyPartitionIsVaultFileError(err error, code, path string) bool {
	var target *vaultfile.Error
	return errors.As(err, &target) && target.Code == code && target.Path == path
}

type legacyPartitionGenesisScope struct {
	target      OwnedVaultFileFirstSuccessorTarget
	checkpoint  *vaultfile.PolicyCheckpoint
	genesis     []byte
	revision    vaultfilebackend.Revision
	journalPath string
	backendRoot string
}

// legacyPartitionPrivateDir creates a real private directory under the test's
// temporary root. t.TempDir's numbered leaf inherits the process umask, so a
// 0755 leaf under umask 022 would not satisfy the journal's private-parent
// check. The genesis-intent journals live below this explicitly created 0700
// directory instead.
func legacyPartitionPrivateDir(t *testing.T, parent, name string) string {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("LEGACY_PARTITION_PRIVATE_DIR_FAILED: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("LEGACY_PARTITION_PRIVATE_DIR_STAT_FAILED: %v", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("LEGACY_PARTITION_PRIVATE_DIR_MODE_MISMATCH: %v", info.Mode())
	}
	return dir
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

func TestOwnedVaultFileLegacyPartitionReconstructsVerifiedProvenance(t *testing.T) {
	dir := t.TempDir()

	// A real independent source personal vault with two declared partitions.
	// The selected partition carries every represented field the current
	// authenticated item format stores; the other partition deliberately has
	// the same item count so a count-only check would accept it.
	sourcePath := filepath.Join(dir, "verify-source.ll")
	sourcePassword := "synthetic-verify-source-factor"
	sourceKey := bytes.Repeat([]byte{0x35}, 16)
	if err := Create(sourcePath, sourcePassword, sourceKey); err != nil {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_CREATE_FAILED")
	}
	sourceSession, err := UnlockSession(sourcePath, []byte(sourcePassword), sourceKey, time.Hour)
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_UNLOCK_FAILED")
	}
	t.Cleanup(sourceSession.Lock)
	selected, err := sourceSession.CreateVault("Verified Selected", "selected source partition", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_SELECTED_FAILED")
	}
	other, err := sourceSession.CreateVault("Verified Other", "other source partition", "folder", v2Gate(t, sourceSession))
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_OTHER_FAILED")
	}

	stamp := time.Unix(1_700_002_345, 0).UTC()
	trashedAt := stamp.Add(time.Hour)
	auto := true
	add := func(item vault.Item) string {
		t.Helper()
		id, _, err := sourceSession.AddItem(item, v2Gate(t, sourceSession))
		if err != nil {
			t.Fatalf("VERIFY_PROVENANCE_SOURCE_ADD_FAILED: %v", err)
		}
		return id
	}
	selectedActiveID := add(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: selected.ID,
		Title: "Verified active login", Username: "verified-user", Password: "verified-password",
		URL: "https://verified.example.test/", Notes: "verified notes",
		URLs: []vault.ItemURL{
			{Label: "primary", URL: "https://verified.example.test/", Primary: true, MatchMode: vault.URLMatchOrigin},
			{Label: "secondary", URL: "https://secondary.verified.example.test/", MatchMode: vault.URLMatchHost},
		},
		Favorite: true, AutoSubmit: &auto, Tags: []string{"verified", "provenance"},
		Sections: []vault.ItemSection{{ID: "verified-section", Title: "Verified fields", Fields: []vault.CustomField{
			{ID: "verified-concealed", Label: "Concealed", Type: vault.FieldTypeConcealed, Value: "verified-concealed-value", Protected: true},
			{ID: "verified-email", Label: "Email", Type: vault.FieldTypeEmail, Value: "verified@example.test"},
		}}},
		History: []vault.ItemHistoryEntry{{
			Timestamp: stamp.Unix(), Action: "edit", Password: "verified-prior-password", Title: "Verified prior title",
			Username: "verified-prior-user", Notes: "verified prior notes",
			Sections: []vault.ItemSection{{ID: "verified-prior-section", Title: "Prior", Fields: []vault.CustomField{{
				ID: "verified-prior-field", Label: "Prior", Type: vault.FieldTypeText, Value: "verified-prior-value",
			}}}},
		}},
		Attachments: []vault.AttachmentMeta{{
			FileName: "verified.bin", MIMEType: "application/octet-stream", Protected: true,
			Content: []byte{0x00, 0x01, 0x7f, 0xff, 0x10},
		}},
		ImportSource: []byte("verified-import-provenance"),
	})
	selectedTrashedID := add(vault.Item{
		Kind: "login", Category: vault.CategoryLogin, VaultID: selected.ID,
		Title: "Verified trashed login", Username: "verified-trashed-user", Password: "verified-trashed-password",
		State: "trashed", PreviousState: "archived", TrashedAt: &trashedAt,
		History:      []vault.ItemHistoryEntry{{Timestamp: stamp.Unix(), Action: "edit", Title: "Verified trashed prior"}},
		ImportSource: []byte("verified-trashed-import-provenance"),
		Attachments: []vault.AttachmentMeta{{
			FileName: "verified-trashed.bin", MIMEType: "application/octet-stream", Protected: true,
			Content: []byte{0xde, 0xad, 0xbe, 0xef},
		}},
	})
	selectedDocumentID := add(vault.Item{
		Kind: "document", Category: vault.CategoryDocument, VaultID: selected.ID,
		Title: "Verified document", Filename: "verified-document.bin",
		Attachment: []byte{0x50, 0x4b, 0x03, 0x04}, AttachmentProtected: true,
		ImportSource: []byte("verified-document-import-provenance"),
	})
	selectedCardID := add(vault.Item{
		Kind: "credit_card", Category: vault.CategoryCreditCard, VaultID: selected.ID,
		Title: "Verified card",
		CreditCard: &vault.CreditCardDetails{
			CardholderName: "Synthetic Verified Holder", Type: "visa", Number: "4111111111111111",
			Verification: "123", ExpiryDate: "2030-01", ValidFrom: "2020-01",
			PIN: "9999", IssuingBank: "Synthetic Verified Bank",
		},
	})
	otherIDs := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		otherIDs = append(otherIDs, add(vault.Item{
			Kind: "login", Category: vault.CategoryLogin, VaultID: other.ID,
			Title: "Other login", Username: "other-user", Password: "other-password",
			Notes: "other partition payload only",
		}))
	}

	sourceArchivePath := filepath.Join(dir, "verify-source.llb")
	sourceKit, err := Backup(sourcePath, sourceArchivePath, sourcePassword, sourceKey)
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_BACKUP_FAILED")
	}
	sourceArchive := legacyPartitionReadFile(t, sourceArchivePath)
	sourceArchiveBefore := bytes.Clone(sourceArchive)
	sourceArchiveFileBefore := legacyPartitionReadFile(t, sourceArchivePath)

	sourcePayload, err := verifyRecoveryArchive(sourceArchive, sourcePassword, sourceKey, sourceKit, true)
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_VERIFY_FAILED")
	}
	defer clearDecodedArchiveSensitive(sourcePayload)
	var sourceMeta *vault.VaultMeta
	sourceItems := make([]vault.Item, 0, 4)
	otherItems := make([]vault.Item, 0, 4)
	for i := range sourcePayload.Items {
		switch sourcePayload.Items[i].EffectiveVaultID() {
		case selected.ID:
			sourceItems = append(sourceItems, sourcePayload.Items[i])
		case other.ID:
			otherItems = append(otherItems, sourcePayload.Items[i])
		}
	}
	for i := range sourcePayload.Vaults {
		if sourcePayload.Vaults[i].ID == selected.ID {
			metadata := sourcePayload.Vaults[i]
			sourceMeta = &metadata
			break
		}
	}
	if sourceMeta == nil || len(sourceItems) != 4 || len(otherItems) != 4 {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_SHAPE_MISMATCH")
	}
	selectedSourceIDs := map[string]bool{
		selectedActiveID: true, selectedTrashedID: true, selectedDocumentID: true, selectedCardID: true,
	}
	for i := range sourceItems {
		if !selectedSourceIDs[sourceItems[i].ID] {
			t.Fatal("VERIFY_PROVENANCE_SOURCE_SELECTED_ID_MISMATCH")
		}
	}
	for _, id := range otherIDs {
		found := false
		for i := range otherItems {
			if otherItems[i].ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("VERIFY_PROVENANCE_SOURCE_OTHER_ID_MISSING")
		}
	}
	byID := make(map[string]vault.Item, len(sourceItems))
	for i := range sourceItems {
		byID[sourceItems[i].ID] = sourceItems[i]
	}
	if item := byID[selectedActiveID]; len(item.History) == 0 || len(item.Sections) == 0 ||
		len(item.URLs) != 2 || len(item.Attachments) != 1 || len(item.Attachments[0].Content) == 0 ||
		!item.Attachments[0].Protected || len(item.ImportSource) == 0 {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_ACTIVE_REPRESENTATION_MISSING")
	}
	if item := byID[selectedTrashedID]; item.State != "trashed" || item.PreviousState != "archived" ||
		item.TrashedAt == nil || len(item.History) == 0 || len(item.ImportSource) == 0 {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_TRASH_REPRESENTATION_MISSING")
	}
	if item := byID[selectedDocumentID]; len(item.Attachment) == 0 || !item.AttachmentProtected {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_DOCUMENT_REPRESENTATION_MISSING")
	}
	if item := byID[selectedCardID]; item.CreditCard == nil || item.CreditCard.Number == "" {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_TYPED_REPRESENTATION_MISSING")
	}

	// Two real destination custody scopes with explicitly private journal
	// parents and published genesis baselines observed from the live backend.
	destPath := filepath.Join(dir, "verify-destination.ll")
	destPassword := "synthetic-verify-destination-factor"
	destKey := bytes.Repeat([]byte{0x45}, 16)
	if err := Create(destPath, destPassword, destKey); err != nil {
		t.Fatal("VERIFY_PROVENANCE_DEST_CREATE_FAILED")
	}
	destSession, err := UnlockSession(destPath, []byte(destPassword), destKey, time.Hour)
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_DEST_UNLOCK_FAILED")
	}
	t.Cleanup(destSession.Lock)
	prepareOwner := func(label string) VaultFileOwnershipPublic {
		t.Helper()
		selector, err := randomID()
		if err != nil {
			t.Fatalf("VERIFY_PROVENANCE_OWNER_%s_FAILED", label)
		}
		public, err := destSession.PrepareVaultFileOwnership(selector)
		if err != nil {
			t.Fatalf("VERIFY_PROVENANCE_CUSTODY_%s_FAILED", label)
		}
		return public
	}
	publicA := prepareOwner("A")
	publicB := prepareOwner("B")
	destArchivePath := filepath.Join(dir, "verify-destination.llb")
	destKit, err := Backup(destPath, destArchivePath, destPassword, destKey)
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_DEST_BACKUP_FAILED")
	}
	journalDir := legacyPartitionPrivateDir(t, dir, "verify-genesis-journals")
	publish := func(name string, public VaultFileOwnershipPublic) legacyPartitionGenesisScope {
		t.Helper()
		intentPath := filepath.Join(journalDir, "genesis-"+name+".journal")
		if _, err := destSession.PrepareVaultFileGenesis(VaultFileGenesisRequest{
			VaultID: public.VaultID, Name: "verified-provenance-" + name, IntentPath: intentPath, ArchivePath: destArchivePath,
		}, []byte(destPassword), destKey, []byte(destKit)); err != nil {
			t.Fatalf("VERIFY_PROVENANCE_GENESIS_%s_FAILED: %v", name, err)
		}
		return legacyPartitionPublishGenesis(t, dir, name, public, intentPath)
	}
	scopeA := publish("a", publicA)
	scopeB := publish("b", publicB)
	t.Cleanup(func() {
		clearVaultFilePolicyCheckpoint(scopeA.checkpoint)
		clearVaultFilePolicyCheckpoint(scopeB.checkpoint)
	})
	localAge := legacyPartitionLocalAge(t, destSession)

	seal := func(name string, scope legacyPartitionGenesisScope, vaultID string) VaultFileSealedLegacyPartition {
		t.Helper()
		sealed, err := destSession.SealOwnedVaultFileFirstItemsFromLegacyPartition(OwnedVaultFileLegacyPartitionRequest{
			JournalPath: scope.journalPath, Target: scope.target, Checkpoint: scope.checkpoint,
			ExpectedGenesis: scope.genesis, Password: []byte(destPassword), Key: destKey,
			Source: LegacyVaultPartitionSource{
				Archive: sourceArchive, Password: sourcePassword, Key: sourceKey,
				RecoveryKit: sourceKit, VaultID: vaultID,
			},
		})
		if err != nil {
			t.Fatalf("VERIFY_PROVENANCE_SEAL_%s_FAILED: %v", name, err)
		}
		return sealed
	}
	sealed := seal("selected", scopeA, selected.ID)
	defer sealed.Clear()
	candidate := bytes.Clone(sealed.Sealed)
	candidateBefore := bytes.Clone(candidate)
	sealedOther := seal("other_partition", scopeA, other.ID)
	defer sealedOther.Clear()
	candidateOther := bytes.Clone(sealedOther.Sealed)
	sealedForeign := seal("foreign_scope", scopeB, selected.ID)
	defer sealedForeign.Clear()
	candidateForeign := bytes.Clone(sealedForeign.Sealed)
	if bytes.Equal(candidate, candidateOther) || bytes.Equal(candidate, candidateForeign) ||
		bytes.Equal(candidateOther, candidateForeign) {
		t.Fatal("VERIFY_PROVENANCE_CANDIDATES_NOT_DISTINCT")
	}

	expectedDigest := sha256.Sum256(sourceArchive)
	request := OwnedVaultFileLegacyPartitionVerificationRequest{
		OwnedVaultFileLegacyPartitionRequest: OwnedVaultFileLegacyPartitionRequest{
			JournalPath: scopeA.journalPath, Target: scopeA.target, Checkpoint: scopeA.checkpoint,
			ExpectedGenesis: scopeA.genesis, Password: []byte(destPassword), Key: destKey,
			Source: LegacyVaultPartitionSource{
				Archive: sourceArchive, Password: sourcePassword, Key: sourceKey,
				RecoveryKit: sourceKit, VaultID: selected.ID,
			},
		},
		Candidate:                   candidate,
		ExpectedSourceArchiveSHA256: expectedDigest,
	}

	journalABefore := legacyPartitionReadFile(t, scopeA.journalPath)
	journalBBefore := legacyPartitionReadFile(t, scopeB.journalPath)
	destBefore := legacyPartitionReadFile(t, destPath)
	backendABefore, backendARevisionBefore := legacyPartitionReadBackend(t, scopeA.backendRoot, scopeA.target.BackendName)
	backendBBefore, backendBRevisionBefore := legacyPartitionReadBackend(t, scopeB.backendRoot, scopeB.target.BackendName)
	defer clear(backendABefore)
	defer clear(backendBBefore)

	verified, err := destSession.VerifyOwnedVaultFileLegacyPartition(request)
	if err != nil {
		t.Fatalf("VERIFY_PROVENANCE_RECONSTRUCT_FAILED: %v", err)
	}
	defer verified.Clear()
	if verified.SourceArchiveSHA256 != expectedDigest || verified.SourceVaultID != selected.ID ||
		verified.SourceVault == nil || !reflect.DeepEqual(*verified.SourceVault, *sourceMeta) {
		t.Fatal("VERIFY_PROVENANCE_RECONSTRUCTED_SOURCE_MISMATCH")
	}
	if verified.DestinationVaultID != scopeA.target.Pin.Root.VaultID {
		t.Fatal("VERIFY_PROVENANCE_RECONSTRUCTED_DESTINATION_MISMATCH")
	}
	if len(verified.ItemMapping) != len(sourceItems) {
		t.Fatal("VERIFY_PROVENANCE_RECONSTRUCTED_MAPPING_SHAPE_MISMATCH")
	}
	for i := range sourceItems {
		if verified.ItemMapping[sourceItems[i].ID] != sourceItems[i].ID {
			t.Fatal("VERIFY_PROVENANCE_RECONSTRUCTED_MAPPING_MISMATCH")
		}
	}

	// Reopen the exact sealed bytes independently of the verify call. Its
	// authenticated content must be the complete selected source partition.
	candidateFile, err := vaultfile.ParseFile(candidate)
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_CANDIDATE_PARSE_FAILED")
	}
	_, reopenedMeta, reopened, err := vault.OpenAuthenticatedItems(candidate, scopeA.checkpoint,
		candidateFile.Header.AuthorDeviceID, localAge)
	if err != nil {
		t.Fatal("VERIFY_PROVENANCE_CANDIDATE_REOPEN_FAILED")
	}
	defer clear(reopenedMeta)
	defer clearAuthenticatedItems(reopened)
	if len(reopenedMeta) != 0 || !legacyPartitionItemsRepresented(sourceItems, reopened) {
		t.Fatal("VERIFY_PROVENANCE_CANDIDATE_REPRESENTED_MISMATCH")
	}

	// The exact candidate bytes were not mutated by verification.
	if !bytes.Equal(candidate, candidateBefore) {
		t.Fatal("VERIFY_PROVENANCE_CANDIDATE_CHANGED")
	}

	refuse := func(name string, mutate func(*OwnedVaultFileLegacyPartitionVerificationRequest), want error) {
		t.Helper()
		bad := request
		mutate(&bad)
		out, err := destSession.VerifyOwnedVaultFileLegacyPartition(bad)
		if err == nil || want != nil && !errors.Is(err, want) {
			t.Fatalf("VERIFY_PROVENANCE_REFUSAL_%s: err=%v want=%v", name, err, want)
		}
		if out.SourceVault != nil || out.SourceVaultID != "" ||
			out.SourceArchiveSHA256 != [sha256.Size]byte{} ||
			out.DestinationVaultID != "" || len(out.ItemMapping) != 0 {
			t.Fatalf("VERIFY_PROVENANCE_REFUSAL_%s_LEAKED_OUTPUT", name)
		}
	}
	refuse("missing_candidate", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Candidate = nil
	}, ErrVaultFileBaselineVerification)
	refuse("missing_expected_digest", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.ExpectedSourceArchiveSHA256 = [sha256.Size]byte{}
	}, ErrLegacyVaultPartitionPayload)
	refuse("wrong_expected_digest", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.ExpectedSourceArchiveSHA256 = sha256.Sum256([]byte(destKit))
	}, ErrLegacyVaultPartitionPayload)
	refuse("missing_recovery_kit", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Source.RecoveryKit = ""
	}, ErrLegacyVaultPartitionPayload)
	refuse("display_name_selector", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Source.VaultID = selected.Name
	}, ErrLegacyVaultPartitionSelector)
	// other.ID is a different real partition declared by the same archive and
	// the candidate is still the selected partition's exact bytes.
	refuse("wrong_selector", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Source.VaultID = other.ID
	}, ErrLegacyVaultPartitionPayload)
	refuse("wrong_source_password", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Source.Password = "wrong-source-factor"
	}, nil)
	refuse("wrong_source_key", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Source.Key = bytes.Repeat([]byte{0x72}, 16)
	}, nil)
	refuse("wrong_dest_password", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Password = []byte("wrong-destination-factor")
	}, ErrVaultFileScopedFactors)
	refuse("wrong_dest_key", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Key = bytes.Repeat([]byte{0x73}, 16)
	}, ErrVaultFileScopedFactors)
	refuse("wrong_target", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Target = scopeB.target
	}, ErrVaultFileBaselineVerification)
	refuse("wrong_checkpoint", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Checkpoint = scopeB.checkpoint
	}, ErrVaultFileBaselineVerification)
	refuse("corrupt_candidate", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Candidate = bytes.Clone(candidate)
		r.Candidate[len(r.Candidate)-1] ^= 0xff
	}, ErrVaultFileBaselineVerification)
	refuse("other_partition_candidate", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Candidate = candidateOther
	}, ErrLegacyVaultPartitionPayload)
	refuse("foreign_scope_candidate", func(r *OwnedVaultFileLegacyPartitionVerificationRequest) {
		r.Candidate = candidateForeign
	}, ErrVaultFileBaselineVerification)

	// The verify path and all refusals were observation-only.
	if !bytes.Equal(sourceArchive, sourceArchiveBefore) ||
		!bytes.Equal(legacyPartitionReadFile(t, sourceArchivePath), sourceArchiveFileBefore) {
		t.Fatal("VERIFY_PROVENANCE_SOURCE_ARCHIVE_CHANGED")
	}
	if !bytes.Equal(legacyPartitionReadFile(t, destPath), destBefore) {
		t.Fatal("VERIFY_PROVENANCE_DEST_PERSONAL_CHANGED")
	}
	if !bytes.Equal(legacyPartitionReadFile(t, scopeA.journalPath), journalABefore) ||
		!bytes.Equal(legacyPartitionReadFile(t, scopeB.journalPath), journalBBefore) {
		t.Fatal("VERIFY_PROVENANCE_DEST_JOURNAL_CHANGED")
	}
	assertBackend := func(scope legacyPartitionGenesisScope, want []byte, wantRevision vaultfilebackend.Revision, label string) {
		t.Helper()
		got, revision := legacyPartitionReadBackend(t, scope.backendRoot, scope.target.BackendName)
		defer clear(got)
		if !bytes.Equal(got, want) || revision != wantRevision {
			t.Fatalf("VERIFY_PROVENANCE_BACKEND_%s_CHANGED", label)
		}
	}
	assertBackend(scopeA, backendABefore, backendARevisionBefore, "A")
	assertBackend(scopeB, backendBBefore, backendBRevisionBefore, "B")

	// A live genesis revision mismatch must fail closed even when the candidate
	// itself is still the exact previously sealed bytes.
	advancedRevision := legacyPartitionReplaceBackend(t, scopeA, scopeA.revision, scopeA.genesis)
	if advancedRevision == scopeA.revision {
		t.Fatal("VERIFY_PROVENANCE_ADVANCED_REVISION_UNCHANGED")
	}
	out, err := destSession.VerifyOwnedVaultFileLegacyPartition(request)
	if !errors.Is(err, ErrVaultFileBaselineJournal) {
		t.Fatalf("VERIFY_PROVENANCE_ADVANCED_REVISION_NOT_REFUSED: %v", err)
	}
	if out.SourceVault != nil || out.SourceVaultID != "" || out.SourceArchiveSHA256 != [sha256.Size]byte{} ||
		out.DestinationVaultID != "" || len(out.ItemMapping) != 0 {
		t.Fatal("VERIFY_PROVENANCE_ADVANCED_REVISION_LEAKED_OUTPUT")
	}
	advancedBytes, advancedRevisionNow := legacyPartitionReadBackend(t, scopeA.backendRoot, scopeA.target.BackendName)
	defer clear(advancedBytes)
	if !bytes.Equal(advancedBytes, scopeA.genesis) || advancedRevisionNow != advancedRevision {
		t.Fatal("VERIFY_PROVENANCE_ADVANCED_BACKEND_MUTATED")
	}
}
