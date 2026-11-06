package personal

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

const v2OTPConfig = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=3600&digits=6"

func v2Session(t *testing.T) (*Session, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "v2.ll")
	key := bytes.Repeat([]byte{41}, 16)
	if err := Create(path, "v2-fixture", key); err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Lock)
	return s, path, key
}

func v2Gate(t *testing.T, s *Session) *MutationGate {
	t.Helper()
	g := NewMutationGate(time.Now().Add(time.Minute))
	if err := s.RegisterMutation(g); err != nil {
		t.Fatal(err)
	}
	return g
}

func v2LoginItem() vault.Item {
	auto := true
	return vault.Item{
		Kind:       "login",
		Category:   vault.CategoryLogin,
		Title:      "V2 Login",
		URL:        "https://example.test/login",
		URLs:       []vault.ItemURL{{Label: "primary", URL: "https://example.test/login", Primary: true, MatchMode: vault.URLMatchOrigin}, {Label: "second", URL: "https://second.example.test/", MatchMode: vault.URLMatchNever}},
		Username:   "v2-user",
		Password:   "old-password",
		OTP:        v2OTPConfig,
		Notes:      "v2 notes",
		Favorite:   true,
		AutoSubmit: &auto,
		Tags:       []string{"work", "shared"},
		Sections: []vault.ItemSection{{ID: "section-one", Title: "Section One", Fields: []vault.CustomField{
			{ID: "secret", Label: "Secret", Type: vault.FieldTypeConcealed, Value: "concealed-value", Protected: true},
			{ID: "text", Label: "Text", Type: vault.FieldTypeText, Value: "searchable-value"},
			{ID: "totp", Label: "TOTP", Type: vault.FieldTypeTOTP, Value: v2OTPConfig, Protected: true},
			{ID: "mail", Label: "Email", Type: vault.FieldTypeEmail, Value: "field@example.test"},
		}}},
	}
}

func TestSessionV2CRUDFilterDetailHistoryAndJournal(t *testing.T) {
	s, _, _ := v2Session(t)
	vaults, err := s.ListVaults()
	if err != nil || len(vaults) != 1 || vaults[0].ID != vault.DefaultVaultID || vaults[0].Name != "Personal" {
		t.Fatalf("default vault missing: %+v %v", vaults, err)
	}
	sub, err := s.CreateVault("Credit Cards", "card vault", "card", v2Gate(t, s))
	if err != nil || !selectorID(sub.ID) || sub.Name != "Credit Cards" || sub.CreatedAt == 0 {
		t.Fatalf("sub-vault creation failed: %+v %v", sub, err)
	}
	if _, err := s.CreateVault("credit cards", "", "", v2Gate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("duplicate vault name accepted: %v", err)
	}
	vaults, err = s.ListVaults()
	if err != nil || len(vaults) != 2 {
		t.Fatalf("sub-vault listing failed: %+v %v", vaults, err)
	}

	login := v2LoginItem()
	id, rev, err := s.AddItem(login, v2Gate(t, s))
	if err != nil || !idOK(id) || !digestOK(rev) {
		t.Fatalf("v2 login add failed: %+v %v", id, rev)
	}
	cc := vault.Item{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "V2 Card", Tags: []string{"finance"}, CreditCard: &vault.CreditCardDetails{CardholderName: "Card Holder", Type: "visa", Number: "4111111111111111", Verification: "123", ExpiryDate: "2030-01", PIN: "9999"}}
	ccID, ccRev, err := s.AddItem(cc, v2Gate(t, s))
	if err != nil || ccID == "" || ccRev == "" {
		t.Fatalf("credit card add failed: %v", err)
	}
	identity := vault.Item{Kind: "identity", Category: vault.CategoryIdentity, Title: "V2 Identity", Identity: &vault.IdentityDetails{FirstName: "First", LastName: "Last", Email: "identity@example.test", Phone: "+1 555 0101"}}
	if _, _, err := s.AddItem(identity, v2Gate(t, s)); err != nil {
		t.Fatal(err)
	}
	doc := vault.Item{Kind: "document", Category: vault.CategoryDocument, Title: "V2 Document", Filename: "doc.bin", Attachment: []byte("doc bytes"), Attachments: []vault.AttachmentMeta{{FileName: "extra.txt", MIMEType: "text/plain", Content: []byte("extra bytes")}}}
	docID, _, err := s.AddItem(doc, v2Gate(t, s))
	if err != nil {
		t.Fatalf("document add failed: %v", err)
	}
	if _, _, err := s.AddItem(vault.Item{Kind: "login", Title: "  "}, v2Gate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("empty title accepted: %v", err)
	}

	all, err := s.ListByFilter(ItemFilter{State: "all"})
	if err != nil || len(all) != 4 {
		t.Fatalf("unfiltered listing = %d %v", len(all), err)
	}
	byID := map[string]ItemSummary{}
	for _, row := range all {
		byID[row.ID] = row
	}
	if row := byID[id]; row.Category != vault.CategoryLogin || row.VaultID != vault.DefaultVaultID || !row.Favorite || !row.HasOTP || row.HasPasskey || len(row.Tags) != 2 || row.PrimaryURL != "https://example.test/login" {
		t.Fatalf("login summary lost: %+v", row)
	}
	if row := byID[ccID]; row.Category != vault.CategoryCreditCard || row.Subtitle != "•••• 1111" {
		t.Fatalf("card summary lost: %+v", row)
	}
	if row := byID[docID]; row.Category != vault.CategoryDocument || row.Attachments != 2 {
		t.Fatalf("document summary lost: %+v", row)
	}
	loginRows, err := s.ListByFilter(ItemFilter{Category: vault.CategoryLogin})
	if err != nil || len(loginRows) != 1 || loginRows[0].ID != id {
		t.Fatalf("category filter failed: %+v %v", loginRows, err)
	}
	tagRows, err := s.ListByFilter(ItemFilter{Tag: "WORK"})
	if err != nil || len(tagRows) != 1 || tagRows[0].ID != id {
		t.Fatalf("tag filter failed: %+v %v", tagRows, err)
	}
	queryRows, err := s.ListByFilter(ItemFilter{Query: "searchable-value"})
	if err != nil || len(queryRows) != 1 || queryRows[0].ID != id {
		t.Fatalf("section field query failed: %+v %v", queryRows, err)
	}
	if _, err := s.ListByFilter(ItemFilter{Query: " "}); err == nil {
		t.Fatal("invalid query accepted")
	}

	masked, err := s.GetItemDetail(id, rev, false)
	if err != nil || masked.Password != "" || masked.OTP != "" || masked.Password == "old-password" {
		t.Fatalf("masked detail failed: %+v %v", masked, err)
	}
	for _, section := range masked.Sections {
		for _, field := range section.Fields {
			if (field.Type == vault.FieldTypeConcealed || field.Type == vault.FieldTypeTOTP) && field.Value != "" {
				t.Fatalf("concealed value exposed: %+v", field)
			}
		}
	}
	revealed, err := s.GetItemDetail(id, rev, true)
	if err != nil || revealed.Password != "old-password" || revealed.OTP != v2OTPConfig || len(revealed.Sections) != 1 || revealed.Sections[0].Fields[0].Value != "concealed-value" {
		t.Fatalf("revealed detail failed: %+v %v", revealed, err)
	}
	ccDetail, err := s.GetItemDetail(ccID, ccRev, false)
	if err != nil || ccDetail.CreditCard == nil || ccDetail.CreditCard.Number != "" || ccDetail.CreditCard.Verification != "" {
		t.Fatalf("card detail masked incorrectly: %+v %v", ccDetail, err)
	}
	if _, err := s.GetItemDetail(id, strings.Repeat("0", 64), true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale detail accepted: %v", err)
	}

	updated := v2LoginItem()
	updated.Password = "new-password"
	newRev, err := s.EditItem(id, rev, updated, v2Gate(t, s))
	if err != nil || newRev == rev || !digestOK(newRev) {
		t.Fatalf("edit failed: %q %v", newRev, err)
	}
	afterEdit, err := s.GetItemDetail(id, newRev, true)
	if err != nil || afterEdit.Password != "new-password" || len(afterEdit.History) != 1 || afterEdit.History[0].Password != "old-password" || afterEdit.History[0].Action != "edit" {
		t.Fatalf("auto history failed: %+v %v", afterEdit, err)
	}
	if _, err := s.EditItem(id, rev, updated, v2Gate(t, s)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit accepted: %v", err)
	}
	restored, err := s.RestoreHistory(id, newRev, 0, v2Gate(t, s))
	if err != nil {
		t.Fatalf("restore history failed: %v", err)
	}
	afterRestore, err := s.GetItemDetail(id, restored, true)
	if err != nil || afterRestore.Password != "old-password" || len(afterRestore.History) != 1 || afterRestore.History[0].Password != "new-password" {
		t.Fatalf("history restore failed: %+v %v", afterRestore, err)
	}

	favorited, err := s.SetFavorite(id, restored, false, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	tagged, err := s.SetTags(id, favorited, []string{"work", "new"}, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	detail, err := s.GetItemDetail(id, tagged, false)
	if err != nil || detail.Favorite || len(detail.Tags) != 2 || detail.Tags[1] != "new" {
		t.Fatalf("favorite/tags update failed: %+v %v", detail, err)
	}

	moved, moveRev, err := s.MoveItemVault(id, tagged, sub.ID, false, v2Gate(t, s))
	if err != nil || moved != id || moveRev == "" {
		t.Fatalf("move vault failed: %q %q %v", moved, moveRev, err)
	}
	detail, err = s.GetItemDetail(id, moveRev, false)
	if err != nil || detail.VaultID != sub.ID {
		t.Fatalf("moved vault lost: %+v %v", detail, err)
	}
	inSub, err := s.ListByFilter(ItemFilter{VaultID: sub.ID, State: "all"})
	if err != nil || len(inSub) != 1 || inSub[0].ID != id {
		t.Fatalf("vault filter failed: %+v %v", inSub, err)
	}
	copied, copyRev, err := s.MoveItemVault(id, moveRev, vault.DefaultVaultID, true, v2Gate(t, s))
	if err != nil || copied == id || copyRev == "" {
		t.Fatalf("copy vault failed: %q %q %v", copied, copyRev, err)
	}
	detail, err = s.GetItemDetail(copied, copyRev, false)
	if err != nil || detail.VaultID != vault.DefaultVaultID || detail.Title != "V2 Login" {
		t.Fatalf("copied item lost: %+v %v", detail, err)
	}
	if _, _, err := s.MoveItemVault(id, moveRev, "missing-vault", false, v2Gate(t, s)); err == nil {
		t.Fatal("unknown target vault accepted")
	}

	events, err := s.Audit()
	if err != nil || len(events) == 0 {
		t.Fatalf("journal replay failed: %v", err)
	}
	last := events[len(events)-1]
	if last.Action != "audit.list" || last.Signature == nil {
		t.Fatalf("audit tip malformed: %+v", last)
	}
	if _, err := s.GetItemDetail(id, strings.Repeat("a", 64), true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale detail accepted: %v", err)
	}
	if _, err := s.GetItemDetail(strings.Repeat("f", 32), tagged, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown item detail accepted: %v", err)
	}
	if _, err := s.GetItemDetail("not-a-personal-id", tagged, true); err == nil {
		t.Fatal("malformed ID accepted")
	}
}

func TestSessionV2AttachmentsTrashAndEmptyTrash(t *testing.T) {
	s, _, _ := v2Session(t)
	item := v2LoginItem()
	id, rev, err := s.AddItem(item, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	attID, attRev, err := s.AddAttachment(id, rev, "notes.txt", "text/plain", []byte("attachment bytes"), v2Gate(t, s))
	if err != nil || !selectorID(attID) || attRev == "" {
		t.Fatalf("attachment add failed: %q %q %v", attID, attRev, err)
	}
	meta, content, err := s.GetAttachment(id, attRev, attID)
	if err != nil || meta.FileName != "notes.txt" || meta.Size != 16 || meta.SHA256 != vault.AttachmentSHA256([]byte("attachment bytes")) || string(content) != "attachment bytes" {
		t.Fatalf("attachment read failed: %+v %q %v", meta, content, err)
	}
	if _, _, err := s.GetAttachment(id, attRev, strings.Repeat("f", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing attachment accepted: %v", err)
	}
	if _, _, err := s.AddAttachment(id, attRev, "bad/name", "", []byte("x"), v2Gate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("unsafe attachment name accepted: %v", err)
	}
	if _, _, err := s.AddAttachment(id, attRev, "large.bin", "", bytes.Repeat([]byte{1}, vault.MaxAttachmentSize+1), v2Gate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("oversized attachment accepted: %v", err)
	}
	removed, err := s.RemoveAttachment(id, attRev, attID, v2Gate(t, s))
	if err != nil || removed == attRev {
		t.Fatalf("attachment remove failed: %v", err)
	}
	detail, err := s.GetItemDetail(id, removed, false)
	if err != nil || len(detail.Attachments) != 0 {
		t.Fatalf("attachment retained after removal: %+v %v", detail, err)
	}

	// Trash two items and verify the 30-day retention filter keeps recent items.
	secondID, _, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	trashed, err := s.SetState(id, removed, "item.trash")
	if err != nil {
		t.Fatalf("trash failed: %v", err)
	}
	rows, err := s.ListByFilter(ItemFilter{State: "trashed"})
	if err != nil || len(rows) != 1 || rows[0].ID != id || rows[0].TrashedAt == nil {
		t.Fatalf("trash listing failed: %+v %v", rows, err)
	}
	retention := 30 * 24 * time.Hour
	if purged, err := s.EmptyTrash(&retention, v2Gate(t, s)); err != nil || purged != 0 {
		t.Fatalf("recent trash purged: %d %v", purged, err)
	}
	if err := s.PurgeTrashed(secondID, rows[0].Revision, v2Gate(t, s)); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrNotTrashed) {
		// secondID exists, but the supplied revision belongs to the first item.
		t.Fatalf("cross item purge did not refuse: %v", err)
	}
	if err := s.PurgeTrashed(id, trashed, v2Gate(t, s)); err != nil {
		t.Fatalf("purge trashed failed: %v", err)
	}
	if _, err := s.GetItemDetail(id, trashed, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged item still visible: %v", err)
	}
	if _, err := s.EmptyTrash(nil, v2Gate(t, s)); err != nil {
		t.Fatalf("empty trash (nothing) failed: %v", err)
	}

	// EmptyTrash(nil) purges all trashed items atomically.
	if _, err := s.SetState(secondID, rows[0].Revision, "item.trash"); err != nil {
		// The revision above belongs to the first item; refetch the current one.
		list, listErr := s.ListByFilter(ItemFilter{State: "active"})
		if listErr != nil || len(list) != 1 {
			t.Fatalf("active listing failed: %+v %v", list, listErr)
		}
		if _, err = s.SetState(secondID, list[0].Revision, "item.trash"); err != nil {
			t.Fatalf("second trash failed: %v", err)
		}
	}
	if purged, err := s.EmptyTrash(nil, v2Gate(t, s)); err != nil || purged != 1 {
		t.Fatalf("empty trash failed: %d %v", purged, err)
	}
	all, err := s.ListByFilter(ItemFilter{State: "all"})
	if err != nil || len(all) != 0 {
		t.Fatalf("purged items remain: %+v %v", all, err)
	}
	if _, err := s.Audit(); err != nil {
		t.Fatalf("journal after purge replay failed: %v", err)
	}
}

func TestSessionV2ImportArchive(t *testing.T) {
	s, _, _ := v2Session(t)
	source := filepath.Join(t.TempDir(), "full.1pux")
	raw := v2ImportArchive(t)
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := s.PlanImportV2(source)
	if err != nil || plan.Report.Profile != onepux.FullProfileV2 || plan.Status != "planned-"+onepux.FullProfileV2 {
		t.Fatalf("v2 import plan failed: %+v %v", plan, err)
	}
	if rows, _ := s.ListByFilter(ItemFilter{State: "all"}); len(rows) != 0 {
		t.Fatal("plan mutated the vault")
	}
	receipt, err := s.ImportV2(source, plan.Report.SourceDigest)
	if err != nil || receipt.Status != "imported-"+onepux.FullProfileV2 || receipt.ReportDigest != plan.ReportDigest {
		t.Fatalf("v2 import failed: %+v %v", receipt, err)
	}
	rows, err := s.ListByFilter(ItemFilter{State: "all"})
	if err != nil || len(rows) != 3 {
		t.Fatalf("imported rows: %+v %v", rows, err)
	}
	byCategory := map[vault.ItemCategory]ItemSummary{}
	for _, row := range rows {
		byCategory[row.Category] = row
	}
	if byCategory[vault.CategoryCreditCard].ID == "" || byCategory[vault.CategoryDocument].Attachments != 1 || byCategory[vault.CategoryLogin].HasOTP == false {
		t.Fatalf("imported categories lost: %+v", byCategory)
	}
	docRow := byCategory[vault.CategoryDocument]
	doc, err := s.GetItemDetail(docRow.ID, docRow.Revision, true)
	if err != nil || len(doc.Attachments) != 1 {
		t.Fatalf("imported document detail failed: %+v %v", doc, err)
	}
	meta, content, err := s.GetAttachment(docRow.ID, docRow.Revision, doc.Attachments[0].ID)
	if err != nil || meta.FileName != "report.txt" || string(content) != "hello world" {
		t.Fatalf("imported attachment failed: %+v %q %v", meta, content, err)
	}
	if _, err := s.ImportV2(source, plan.Report.SourceDigest); !errors.Is(err, ErrImportDuplicate) {
		t.Fatalf("duplicate v2 import accepted: %v", err)
	}
	// A v2 plan must not be replayable through the narrow login profile.
	legacy, err := s.PlanImport(source)
	if err == nil && legacy.Report.SourceDigest != "" && legacy.Report.SourceDigest == plan.Report.SourceDigest {
		t.Fatal("legacy and v2 import plans share a digest")
	}
	if _, err := s.Audit(); err != nil {
		t.Fatalf("journal after v2 import failed: %v", err)
	}
}

func TestSessionV2ReferencesResolveCustomSectionsAndStructuredFields(t *testing.T) {
	s, path, key := v2Session(t)
	login := v2LoginItem()
	loginID, loginRev, err := s.AddItem(login, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	cc := vault.Item{Kind: "credit_card", Category: vault.CategoryCreditCard, Title: "Reference Card", CreditCard: &vault.CreditCardDetails{CardholderName: "Card Holder", Type: "visa", Number: "4111111111111111", Verification: "123", ExpiryDate: "2030-01", PIN: "9999", IssuingBank: "Bank"}}
	ccID, ccRev, err := s.AddItem(cc, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	identity := vault.Item{Kind: "identity", Category: vault.CategoryIdentity, Title: "Reference Identity", Identity: &vault.IdentityDetails{FirstName: "First", LastName: "Last", Email: "identity@example.test", Phone: "+1 555 0101", AddressLine1: "1 Street", City: "City", State: "ST", PostalCode: "12345", Country: "US"}}
	idID, idRev, err := s.AddItem(identity, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := s.CreateVault("References", "", "", v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	_, loginRev, err = s.MoveItemVault(loginID, loginRev, sub.ID, false, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}

	index, err := References(path, "v2-fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	if index.VaultName != "Personal" || len(index.Items) != 3 {
		t.Fatalf("reference index malformed: %+v", index)
	}
	byItem := map[string]ReferenceRow{}
	for _, row := range index.Items {
		byItem[row.ID] = row
	}
	loginRefs := byItem[loginID].References
	for _, keyName := range []string{"username", "password", "otp", "notes", "section-one/secret", "section-one/totp", "section-one/text"} {
		if _, ok := loginRefs[keyName]; !ok {
			t.Fatalf("missing login reference %q in %+v", keyName, loginRefs)
		}
	}
	if _, ok := byItem[ccID].References["cc-number"]; !ok {
		t.Fatalf("credit card reference missing: %+v", byItem[ccID].References)
	}
	if _, ok := byItem[idID].References["given-name"]; !ok {
		t.Fatalf("identity reference missing: %+v", byItem[idID].References)
	}
	raw, _ := json.Marshal(index)
	for _, secret := range []string{"old-password", "concealed-value", "4111111111111111", "identity@example.test", "searchable-value"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("reference index leaked %q", secret)
		}
	}

	reveal := func(ref, revision string, otp bool) (string, error) {
		var out bytes.Buffer
		var err error
		if otp {
			_, err = RevealOTPReference(path, "v2-fixture", key, ref, revision, &out)
		} else {
			_, err = RevealReference(path, "v2-fixture", key, ref, revision, &out)
		}
		if err != nil {
			return "", err
		}
		var value string
		if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &value); err != nil {
			return "", err
		}
		return value, nil
	}
	passwordRef := loginRefs["password"]
	// The item now lives in the sub-vault; the account-level catalog still
	// resolves it, and the v2 vault ID/name is independently addressable.
	if value, err := reveal(passwordRef, loginRev, false); err != nil || value != "old-password" {
		t.Fatalf("password reference failed: %q %v", value, err)
	}
	subRef := "op://" + sub.ID + "/" + loginID + "/section-one/secret"
	if value, err := reveal(subRef, loginRev, false); err != nil || value != "concealed-value" {
		t.Fatalf("custom section reference failed: %q %v", value, err)
	}
	nameRef := "op://" + sub.Name + "/" + loginID + "/section-one/text"
	if value, err := reveal(nameRef, loginRev, false); err != nil || value != "searchable-value" {
		t.Fatalf("vault name reference failed: %q %v", value, err)
	}
	if value, err := reveal("op://"+index.VaultID+"/"+loginID+"/notes", loginRev, false); err != nil || value != "v2 notes" {
		t.Fatalf("v2 notes reference failed: %q %v", value, err)
	}
	if value, err := reveal("op://"+index.VaultID+"/"+ccID+"/cc-number", ccRev, false); err != nil || value != "4111111111111111" {
		t.Fatalf("credit card reference failed: %q %v", value, err)
	}
	if value, err := reveal("op://"+index.VaultID+"/"+ccID+"/cc-exp-year", ccRev, false); err != nil || value != "2030" {
		t.Fatalf("credit card derived reference failed: %q %v", value, err)
	}
	if value, err := reveal("op://"+index.VaultID+"/"+idID+"/given-name", idRev, false); err != nil || value != "First" {
		t.Fatalf("identity reference failed: %q %v", value, err)
	}
	if value, err := reveal("op://"+index.VaultID+"/"+loginID+"/section-one/totp", loginRev, true); err != nil || len(value) != 6 {
		t.Fatalf("custom TOTP reference failed: %q %v", value, err)
	}
	if _, err := reveal("op://"+index.VaultID+"/"+loginID+"/notes", loginRev, true); err == nil {
		t.Fatal("OTP reference accepted a text field")
	}
	if _, err := reveal("op://"+index.VaultID+"/"+loginID+"/section-one/missing", loginRev, false); !errors.Is(err, reference.ErrNotFound) {
		t.Fatalf("missing field reference accepted: %v", err)
	}
	if _, err := reveal("op://"+index.VaultID+"/"+loginID+"/password", strings.Repeat("b", 64), false); err == nil {
		t.Fatal("stale reference accepted")
	}
	if _, err := s.Audit(); err != nil {
		t.Fatalf("journal after reference operations failed: %v", err)
	}
}

func v2ImportArchive(t *testing.T) []byte {
	t.Helper()
	items := []any{
		map[string]any{"uuid": "login-1", "categoryUuid": "001", "state": "active", "favIndex": 1, "overview": map[string]any{"title": "Imported Login", "url": "https://example.test/login", "tags": []any{"imported"}}, "details": map[string]any{"notesPlain": "imported notes", "loginFields": []any{map[string]any{"designation": "username", "fieldType": "T", "value": "private-user"}, map[string]any{"designation": "password", "fieldType": "P", "value": "private-password"}}, "sections": []any{map[string]any{"name": "extra", "title": "Extra", "fields": []any{map[string]any{"id": "token", "title": "Token", "value": map[string]any{"totp": v2OTPConfig}}}}}}, "createdAt": 123, "updatedAt": 456},
		map[string]any{"uuid": "card-1", "categoryUuid": "002", "state": "active", "overview": map[string]any{"title": "Imported Card"}, "details": map[string]any{"sections": []any{map[string]any{"name": "card", "title": "Card", "fields": []any{map[string]any{"id": "ccnum", "title": "Number", "value": map[string]any{"creditCardNumber": "4111111111111111"}}, map[string]any{"id": "cardholder", "title": "Cardholder", "value": map[string]any{"string": "Card Holder"}}}}}}},
		map[string]any{"uuid": "doc-1", "categoryUuid": "114", "state": "active", "overview": map[string]any{"title": "Imported Document"}, "details": map[string]any{"documentAttributes": map[string]any{"fileName": "report.txt", "decryptedSize": 11}}, "file": map[string]any{"path": "files/report.txt"}},
	}
	data, err := json.Marshal(map[string]any{"accounts": []any{map[string]any{"attrs": map[string]any{"uuid": "a"}, "vaults": []any{map[string]any{"attrs": map[string]any{"uuid": "v"}, "items": items}}}}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for _, file := range [][2]string{
		{"export.attributes", `{"version":3,"description":"1Password Unencrypted Export","createdAt":0}`},
		{"export.data", string(data)},
		{"files/", ""},
		{"files/report.txt", "hello world"},
	} {
		header := &zip.FileHeader{Name: file[0], Method: zip.Store}
		if file[0] == "files/" {
			header.SetMode(os.ModeDir | 0700)
		}
		w, err := z.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(file[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
