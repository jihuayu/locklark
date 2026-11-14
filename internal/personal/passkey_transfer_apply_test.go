package personal

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func transferApplyPlanFixture(t *testing.T, ttl time.Duration) (source, receiver *Session, invite PasskeyTransferInvitation, export PasskeyTransferExport, plan PasskeyTransferPlan, targets []PasskeyTransferTarget, existingID, existingRevision string) {
	t.Helper()
	source, receiver, invite, _, export, targets, existingID, existingRevision = passkeyTransferPlanFixture(t, ttl)
	plan, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Groups) != 1 {
		t.Fatalf("fixture groups: %d", len(plan.Groups))
	}
	return source, receiver, invite, export, plan, targets, existingID, existingRevision
}

func transferApplyNewMapping(plan PasskeyTransferPlan, title, username string) PasskeyTransferMapping {
	return PasskeyTransferMapping{GroupID: plan.Groups[0].GroupID, NewTitle: title, NewUsername: username}
}

func transferApplyExistingMapping(plan PasskeyTransferPlan, id, revision string) PasskeyTransferMapping {
	return PasskeyTransferMapping{GroupID: plan.Groups[0].GroupID, ExistingTargetID: id, ExistingRevision: revision}
}

func transferApplyRecords(t *testing.T, s *Session, id string) [][]byte {
	t.Helper()
	items := rawItems(t, s)
	defer func() {
		for i := range items {
			items[i].ClearPasskeys()
		}
	}()
	for _, item := range items {
		if item.ID != id {
			continue
		}
		out := make([][]byte, 0, len(item.PasskeyRecords()))
		for _, raw := range item.PasskeyRecords() {
			out = append(out, bytes.Clone(raw))
		}
		return out
	}
	t.Fatalf("item %q missing", id)
	return nil
}

func transferApplyItem(t *testing.T, s *Session, id string) vault.Item {
	t.Helper()
	items := rawItems(t, s)
	defer func() {
		for i := range items {
			items[i].ClearPasskeys()
		}
	}()
	for _, item := range items {
		if item.ID == id {
			return vault.CloneItem(item)
		}
	}
	t.Fatalf("item %q missing", id)
	return vault.Item{}
}

func transferApplyMustRefuse(t *testing.T, receiver *Session, apply func() (PasskeyTransferApplyReceipt, error)) {
	t.Helper()
	beforeAudit := rawAuditCountNoSession(t, receiver.path)
	beforeConsume := rawAuditActionCount(t, receiver, passkeyTransferConsumeAction)
	beforeEpoch := receiver.PasskeyRevocationEpoch()
	beforeItems := rawItems(t, receiver)
	defer func() {
		for i := range beforeItems {
			beforeItems[i].ClearPasskeys()
		}
	}()
	out, err := apply()
	if err == nil {
		t.Fatal("apply succeeded unexpectedly")
	}
	if len(out.Items) != 0 {
		t.Fatalf("refusal leaked receipt: %+v", out)
	}
	afterItems := rawItems(t, receiver)
	defer func() {
		for i := range afterItems {
			afterItems[i].ClearPasskeys()
		}
	}()
	if !reflect.DeepEqual(beforeItems, afterItems) {
		t.Fatal("refused apply changed an item")
	}
	if rawAuditCountNoSession(t, receiver.path) != beforeAudit {
		t.Fatal("refused apply appended audit")
	}
	if rawAuditActionCount(t, receiver, passkeyTransferConsumeAction) != beforeConsume {
		t.Fatal("refused apply consumed the invitation")
	}
	if receiver.PasskeyRevocationEpoch() != beforeEpoch {
		t.Fatal("refused apply revoked queued authority")
	}
}

func TestPasskeyTransferApplyNewLoginNativeAssertionAndReplayRefused(t *testing.T) {
	source, receiver, invite, export, plan, targets, _, _ := transferApplyPlanFixture(t, 5*time.Minute)
	mapping := transferApplyNewMapping(plan, "Imported Parent", "explicit-import-user")
	beforeEpoch := receiver.PasskeyRevocationEpoch()
	receipt, err := receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, dailyGate(t, receiver))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(receipt.Items) != 1 {
		t.Fatalf("receipt: %+v", receipt)
	}
	item := receipt.Items[0]
	if !idOK(item.ID) || !digestOK(item.Revision) {
		t.Fatalf("bad receipt selectors: %+v", item)
	}
	if receiver.PasskeyRevocationEpoch() != beforeEpoch+1 {
		t.Fatal("apply did not revoke queued passkey authority")
	}
	stored := transferApplyItem(t, receiver, item.ID)
	defer stored.ClearPasskeys()
	if stored.Title != "Imported Parent" || stored.URL != "https://example.test" || stored.Username != "explicit-import-user" {
		t.Fatalf("new parent metadata: title=%q url=%q username=%q", stored.Title, stored.URL, stored.Username)
	}
	if len(stored.Passkeys) != len(targets) || len(stored.Passkey) != 0 {
		t.Fatalf("collection form: collection=%d legacy=%d records=%d", len(stored.Passkeys), len(stored.Passkey), len(stored.PasskeyRecords()))
	}
	want := make(map[string][]byte, len(targets))
	for _, target := range targets {
		want[target.CredentialID] = passkeyRecord(t, source, target.ItemID, target.CredentialID)
	}
	defer func() {
		for _, raw := range want {
			clear(raw)
		}
	}()
	for _, raw := range stored.PasskeyRecords() {
		record, loadErr := passkey.Load(raw)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		credentialID := record.ID
		name := record.Name
		record.Clear()
		if !bytes.Equal(raw, want[credentialID]) {
			t.Fatalf("credential %q bytes or name changed", credentialID)
		}
		if name == "" {
			t.Fatalf("credential %q name was not preserved", credentialID)
		}
	}
	if suggestionsRevision(t, receiver, item.ID) != item.Revision {
		t.Fatal("receipt revision is not the live parent revision")
	}
	ctx := BrowserContext{RequestID: strings.Repeat("5", 32), Origin: "https://example.test", TabID: 5, DocumentID: "document-5"}
	get := PasskeyTarget{Context: ctx, ID: item.ID, Revision: item.Revision, CredentialID: targets[0].CredentialID, Options: passkeyGetOptions(targets[0].CredentialID)}
	response, err := receiver.PerformPasskey(get, false, dailyGate(t, receiver))
	if err != nil {
		t.Fatalf("native assertion with imported record: %v", err)
	}
	verifyPasskeySignature(t, passkeyRecord(t, receiver, item.ID, targets[0].CredentialID), response)

	path := receiver.path
	receiver.Lock()
	fresh, err := UnlockSession(path, []byte("fixture"), bytes.Repeat([]byte{9}, 16), time.Minute)
	if err != nil {
		t.Fatalf("cold reopen: %v", err)
	}
	defer fresh.Lock()
	items, revisions, err := fresh.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatalf("cold authenticated read: %v", err)
	}
	defer func() {
		for i := range items {
			items[i].ClearPasskeys()
		}
	}()
	if revisions[item.ID] != item.Revision {
		t.Fatalf("cold revision %q want %q", revisions[item.ID], item.Revision)
	}
	rows, err := fresh.Audit()
	if err != nil {
		t.Fatal(err)
	}
	foundItem, foundConsume := false, false
	for _, row := range rows {
		if row.Action == passkeyTransferItemAction && row.Item == item.ID {
			foundItem = true
			if row.BaseRevision != "" || !digestOK(row.Link) {
				t.Fatalf("new-parent item event shape: %+v", row)
			}
		}
		if row.Action == passkeyTransferConsumeAction && row.Item == invite.ID {
			foundConsume = true
		}
	}
	if !foundItem || !foundConsume {
		t.Fatalf("history item=%v consume=%v", foundItem, foundConsume)
	}

	before := rawAuditCountNoSession(t, fresh.path)
	replay, err := fresh.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, dailyGate(t, fresh))
	if err == nil || len(replay.Items) != 0 {
		t.Fatalf("second apply: err=%v receipt=%+v", err, replay)
	}
	if rawAuditCountNoSession(t, fresh.path) != before {
		t.Fatal("second apply wrote audit")
	}
}

func TestPasskeyTransferApplyExistingTargetPreservesFieldsAndAppends(t *testing.T) {
	_, receiver, invite, export, _, targets, existingID, existingRevision := transferApplyPlanFixture(t, 5*time.Minute)
	revision := existingRevision
	edits := []Edit{
		{Field: "title", Value: "Existing Parent"},
		{Field: "username", Value: "existing-user"},
		{Field: "password", Value: "existing-password-123"},
		{Field: "notes", Value: "notes kept across import"},
		{Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"},
		{Field: "url", Value: "https://example.test/login"},
	}
	for _, edit := range edits {
		edit.ID, edit.Revision = existingID, revision
		next, err := receiver.Edit(edit)
		if err != nil {
			t.Fatalf("edit %s: %v", edit.Field, err)
		}
		revision = next
	}
	plan, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Groups) != 1 || len(plan.Groups[0].EligibleTargets) != 1 {
		t.Fatalf("eligible targets after edits: %+v", plan.Groups)
	}
	eligible := plan.Groups[0].EligibleTargets[0]
	if eligible.ID != existingID || eligible.Revision != revision {
		t.Fatalf("eligible target did not refresh: %+v", eligible)
	}
	beforeRecords := transferApplyRecords(t, receiver, existingID)
	defer func() {
		for _, raw := range beforeRecords {
			clear(raw)
		}
	}()
	receipt, err := receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{transferApplyExistingMapping(plan, eligible.ID, eligible.Revision)}, dailyGate(t, receiver))
	if err != nil {
		t.Fatalf("apply existing: %v", err)
	}
	if len(receipt.Items) != 1 || receipt.Items[0].ID != existingID || receipt.Items[0].Revision == revision || !digestOK(receipt.Items[0].Revision) {
		t.Fatalf("existing receipt: %+v", receipt)
	}
	stored := transferApplyItem(t, receiver, existingID)
	defer stored.ClearPasskeys()
	if stored.Title != "Existing Parent" || stored.Username != "existing-user" || stored.Password != "existing-password-123" || stored.Notes != "notes kept across import" || stored.OTP != "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" || stored.URL != "https://example.test/login" {
		t.Fatalf("existing unrelated fields changed: %+v", stored)
	}
	if len(stored.Passkeys) != len(beforeRecords)+len(targets) || len(stored.Passkey) != 0 {
		t.Fatalf("appended collection: collection=%d legacy=%d want=%d", len(stored.Passkeys), len(stored.Passkey), len(beforeRecords)+len(targets))
	}
	records := stored.PasskeyRecords()
	for i, raw := range beforeRecords {
		if !bytes.Equal(records[i], raw) {
			t.Fatalf("existing record %d changed", i)
		}
	}
	for _, target := range targets {
		found := false
		for _, raw := range records[len(beforeRecords):] {
			record, loadErr := passkey.Load(raw)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			found = found || record.ID == target.CredentialID
			record.Clear()
		}
		if !found {
			t.Fatalf("imported credential %q missing", target.CredentialID)
		}
	}
}

func TestPasskeyTransferApplyStaleTargetRefusedWithoutConsume(t *testing.T) {
	_, receiver, invite, export, plan, _, existingID, existingRevision := transferApplyPlanFixture(t, 5*time.Minute)
	ctx := BrowserContext{RequestID: strings.Repeat("6", 32), Origin: "https://example.test", TabID: 6, DocumentID: "document-6"}
	if _, err := receiver.PerformPasskey(transferPlanLoginTarget(ctx, existingID, existingRevision), false, dailyGate(t, receiver)); err != nil {
		t.Fatal(err)
	}
	mapping := transferApplyExistingMapping(plan, existingID, existingRevision)
	transferApplyMustRefuse(t, receiver, func() (PasskeyTransferApplyReceipt, error) {
		return receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, dailyGate(t, receiver))
	})
}

func TestPasskeyTransferApplyMappingAndPinRefusals(t *testing.T) {
	_, receiver, invite, export, plan, _, existingID, existingRevision := transferApplyPlanFixture(t, 5*time.Minute)
	group := plan.Groups[0]
	cases := []struct {
		name     string
		digest   string
		pin      string
		mappings []PasskeyTransferMapping
	}{
		{"wrong-plan-digest", strings.Repeat("a", 64), export.SourceFingerprint, []PasskeyTransferMapping{transferApplyNewMapping(plan, "New", "")}},
		{"wrong-source-pin", plan.Digest, strings.Repeat("a", 64), []PasskeyTransferMapping{transferApplyNewMapping(plan, "New", "")}},
		{"empty-mappings", plan.Digest, export.SourceFingerprint, nil},
		{"missing-group", plan.Digest, export.SourceFingerprint, []PasskeyTransferMapping{{GroupID: strings.Repeat("b", 64), NewTitle: "New"}}},
		{"duplicate-group", plan.Digest, export.SourceFingerprint, []PasskeyTransferMapping{transferApplyNewMapping(plan, "New", ""), transferApplyNewMapping(plan, "Other", "")}},
		{"ambiguous-mapping", plan.Digest, export.SourceFingerprint, []PasskeyTransferMapping{{GroupID: group.GroupID, ExistingTargetID: existingID, ExistingRevision: existingRevision, NewTitle: "New"}}},
		{"empty-new-title", plan.Digest, export.SourceFingerprint, []PasskeyTransferMapping{{GroupID: group.GroupID, NewUsername: "user"}}},
		{"unsafe-new-title", plan.Digest, export.SourceFingerprint, []PasskeyTransferMapping{{GroupID: group.GroupID, NewTitle: "bad\nline"}}},
		{"ineligible-target", plan.Digest, export.SourceFingerprint, []PasskeyTransferMapping{{GroupID: group.GroupID, ExistingTargetID: strings.Repeat("0", 32), ExistingRevision: existingRevision}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transferApplyMustRefuse(t, receiver, func() (PasskeyTransferApplyReceipt, error) {
				return receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, tc.pin, tc.digest, tc.mappings, dailyGate(t, receiver))
			})
		})
	}
}

func TestPasskeyTransferApplyDuplicateTrashedCredentialRefused(t *testing.T) {
	source, receiver, invite, export, plan, targets, _, _ := transferApplyPlanFixture(t, 5*time.Minute)
	duplicate := passkeyRecord(t, source, targets[0].ItemID, targets[0].CredentialID)
	installTrashedTransferCredential(t, receiver, duplicate)
	transferApplyMustRefuse(t, receiver, func() (PasskeyTransferApplyReceipt, error) {
		return receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{transferApplyNewMapping(plan, "Duplicate", "")}, dailyGate(t, receiver))
	})
}

func TestPasskeyTransferApplyMax16RefusedWithoutPartialWrite(t *testing.T) {
	_, receiver, invite, export, _, _, existingID, _ := transferApplyPlanFixture(t, 5*time.Minute)
	for i := 0; i < 14; i++ {
		ctx := BrowserContext{RequestID: fmt.Sprintf("%032x", i+1), Origin: "https://example.test", TabID: int64(i + 10), DocumentID: fmt.Sprintf("document-%d", i+10)}
		target := transferPlanLoginTarget(ctx, existingID, suggestionsRevision(t, receiver, existingID))
		if _, err := receiver.PerformPasskey(target, false, dailyGate(t, receiver)); err != nil {
			t.Fatalf("append credential %d: %v", i, err)
		}
	}
	plan, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Groups[0].EligibleTargets) != 1 {
		t.Fatalf("eligible targets: %+v", plan.Groups[0].EligibleTargets)
	}
	eligible := plan.Groups[0].EligibleTargets[0]
	beforeRecords := transferApplyRecords(t, receiver, existingID)
	defer func() {
		for _, raw := range beforeRecords {
			clear(raw)
		}
	}()
	if len(beforeRecords) != 15 {
		t.Fatalf("fixture records: %d", len(beforeRecords))
	}
	transferApplyMustRefuse(t, receiver, func() (PasskeyTransferApplyReceipt, error) {
		return receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{transferApplyExistingMapping(plan, eligible.ID, eligible.Revision)}, dailyGate(t, receiver))
	})
	if got := len(transferApplyRecords(t, receiver, existingID)); got != 15 {
		t.Fatalf("max16 refusal changed records: %d", got)
	}
}

func TestPasskeyTransferApplyCommitThenLockOrCloseIsUnknownAndAtomic(t *testing.T) {
	t.Run("lock", func(t *testing.T) {
		_, receiver, invite, export, plan, _, _, _ := transferApplyPlanFixture(t, 5*time.Minute)
		mapping := transferApplyNewMapping(plan, "Locked Import", "")
		gate := dailyGate(t, receiver)
		receipt, err := receiver.applyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, gate, receiver.RequestLock, nil)
		if !errors.Is(err, ErrMutationUnknown) || len(receipt.Items) != 0 || !gate.CommitWon() || receiver.Unlocked() {
			t.Fatalf("commit-then-lock: err=%v receipt=%+v won=%v unlocked=%v", err, receipt, gate.CommitWon(), receiver.Unlocked())
		}
		path := receiver.path
		fresh, err := UnlockSession(path, []byte("fixture"), bytes.Repeat([]byte{9}, 16), time.Minute)
		if err != nil {
			t.Fatalf("reopen after lock: %v", err)
		}
		defer fresh.Lock()
		if rawAuditActionCount(t, fresh, passkeyTransferItemAction) != 1 || rawAuditActionCount(t, fresh, passkeyTransferConsumeAction) != 1 {
			t.Fatal("locked apply did not commit one item event and one consume event")
		}
		items, revisions, err := fresh.ReadAuthenticatedItems(false)
		if err != nil {
			t.Fatalf("cold read committed apply: %v", err)
		}
		defer func() {
			for i := range items {
				items[i].ClearPasskeys()
			}
		}()
		found := false
		for _, item := range items {
			if item.Title == "Locked Import" {
				found = revisions[item.ID] != ""
			}
		}
		if !found {
			t.Fatal("committed apply is missing after lock")
		}
	})
	t.Run("close", func(t *testing.T) {
		_, receiver, invite, export, plan, _, _, _ := transferApplyPlanFixture(t, 5*time.Minute)
		mapping := transferApplyNewMapping(plan, "Close Import", "")
		gate := dailyGate(t, receiver)
		receipt, err := receiver.applyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, gate, nil, func(*bolt.DB) error { return errors.New("synthetic close failure") })
		if !errors.Is(err, ErrMutationUnknown) || len(receipt.Items) != 0 || !gate.CommitWon() {
			t.Fatalf("close failure: err=%v receipt=%+v won=%v", err, receipt, gate.CommitWon())
		}
		if rawAuditActionCount(t, receiver, passkeyTransferItemAction) != 1 || rawAuditActionCount(t, receiver, passkeyTransferConsumeAction) != 1 {
			t.Fatal("close-failure apply did not commit one item event and one consume event")
		}
		items := rawItems(t, receiver)
		defer func() {
			for i := range items {
				items[i].ClearPasskeys()
			}
		}()
		found := false
		for _, item := range items {
			found = found || item.Title == "Close Import"
		}
		if !found {
			t.Fatal("committed apply is missing after close failure")
		}
	})
}

func TestPasskeyTransferApplyRevokedOrExpiredInvitationRefused(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		_, receiver, invite, export, plan, _, _, _ := transferApplyPlanFixture(t, 5*time.Minute)
		if err := receiver.RevokePasskeyTransferInvitation(invite.Raw, dailyGate(t, receiver)); err != nil {
			t.Fatal(err)
		}
		mapping := transferApplyNewMapping(plan, "Revoked Import", "")
		transferApplyMustRefuse(t, receiver, func() (PasskeyTransferApplyReceipt, error) {
			return receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, dailyGate(t, receiver))
		})
	})
	t.Run("expired", func(t *testing.T) {
		_, receiver, invite, export, plan, _, _, _ := transferApplyPlanFixture(t, 2*time.Second)
		time.Sleep(2100 * time.Millisecond)
		mapping := transferApplyNewMapping(plan, "Expired Import", "")
		transferApplyMustRefuse(t, receiver, func() (PasskeyTransferApplyReceipt, error) {
			return receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, dailyGate(t, receiver))
		})
	})
}
