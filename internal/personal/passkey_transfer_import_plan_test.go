package personal

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func transferPlanLoginTarget(context BrowserContext, id, revision string) PasskeyTarget {
	return PasskeyTarget{
		Context:  context,
		Create:   true,
		ID:       id,
		Revision: revision,
		Options:  []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"passkey-fixture-user","displayName":"Fixture"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`),
	}
}

func passkeyTransferPlanFixture(t *testing.T, ttl time.Duration) (source, receiver *Session, invite PasskeyTransferInvitation, public publicTransferIdentity, export PasskeyTransferExport, targets []PasskeyTransferTarget, existingID, existingRevision string) {
	t.Helper()
	source, sourceTarget, _, _, _ := passkeyMultiFixture(t)
	receiver, public = exportTestReceiver(t)
	context := BrowserContext{RequestID: "22222222222222222222222222222222", Origin: "https://example.test", TabID: 2, DocumentID: "document-2"}
	if _, err := receiver.PerformPasskey(transferPlanLoginTarget(context, "", ""), false, dailyGate(t, receiver)); err != nil {
		t.Fatalf("receiver login: %v", err)
	}
	metadata, err := receiver.ReadManagedPasskeysMetadata(false)
	if err != nil || len(metadata) != 1 {
		t.Fatalf("receiver metadata: %v rows=%d", err, len(metadata))
	}
	for id := range metadata {
		existingID = id
	}
	existingRevision = suggestionsRevision(t, receiver, existingID)
	targets = exportTestTargets(t, source, sourceTarget.ID)
	if len(targets) == 0 {
		t.Fatal("no source targets")
	}
	invite, err = receiver.NewPasskeyTransferInvitation(ttl, dailyGate(t, receiver))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	export, err = source.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, dailyGate(t, source))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return source, receiver, invite, public, export, targets, existingID, existingRevision
}

func transferCredentialSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func TestPasskeyTransferPlanPublicReadOnlyAndStable(t *testing.T) {
	_, receiver, invite, public, export, targets, existingID, existingRevision := passkeyTransferPlanFixture(t, 5*time.Minute)
	beforeItems := rawItems(t, receiver)
	beforeAudit := rawAuditCountNoSession(t, receiver.path)
	beforeEpoch := receiver.PasskeyRevocationEpoch()
	plan, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if rawAuditCountNoSession(t, receiver.path) != beforeAudit {
		t.Fatal("plan appended an audit event")
	}
	if receiver.PasskeyRevocationEpoch() != beforeEpoch {
		t.Fatal("plan changed the passkey revocation epoch")
	}
	if !digestOK(plan.Digest) || plan.InvitationID != invite.ID || plan.SourceFingerprint != export.SourceFingerprint || plan.TargetFingerprint != public.Fingerprint || plan.ExpiresAt.Unix() != invite.ExpiresAt.Unix() {
		t.Fatalf("bad plan header: %+v", plan)
	}
	if len(plan.Groups) != 1 {
		t.Fatalf("groups: %d", len(plan.Groups))
	}
	group := plan.Groups[0]
	if group.RPID != "example.test" || !digestOK(group.GroupID) {
		t.Fatalf("bad group: %+v", group)
	}
	if len(group.CredentialIDs) != len(targets) {
		t.Fatalf("credentials: %d want %d", len(group.CredentialIDs), len(targets))
	}
	wantCredentials := map[string]bool{}
	for _, target := range targets {
		wantCredentials[target.CredentialID] = true
	}
	if !reflect.DeepEqual(transferCredentialSet(group.CredentialIDs), wantCredentials) {
		t.Fatalf("credential selectors: %v", group.CredentialIDs)
	}
	if len(group.EligibleTargets) != 1 || group.EligibleTargets[0].ID != existingID || group.EligibleTargets[0].Revision != existingRevision {
		t.Fatalf("eligible targets: %+v", group.EligibleTargets)
	}
	if suggestionsRevision(t, receiver, existingID) != existingRevision {
		t.Fatal("plan changed the target parent revision")
	}
	afterItems := rawItems(t, receiver)
	defer func() {
		for i := range beforeItems {
			beforeItems[i].ClearPasskeys()
		}
		for i := range afterItems {
			afterItems[i].ClearPasskeys()
		}
	}()
	if !reflect.DeepEqual(afterItems, beforeItems) {
		t.Fatal("plan changed receiver items")
	}
	if got := fmt.Sprintf("%v", plan); got != "[passkey transfer plan]" {
		t.Fatalf("plan fmt leaked: %q", got)
	}
	publicJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(publicJSON)
	for _, forbidden := range []string{"private_key", "user_id", "source_item_id", "dXNlcjE", "credential_revision"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("public plan leaked %q: %s", forbidden, text)
		}
	}
	if _, err := receiver.Audit(); err != nil {
		t.Fatal(err)
	}
	again, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest != plan.Digest {
		t.Fatal("a normal full-audit read invalidated the plan digest")
	}
}

func TestPasskeyTransferPlanDigestChangesWithTargetRevision(t *testing.T) {
	_, receiver, invite, _, export, _, existingID, existingRevision := passkeyTransferPlanFixture(t, 5*time.Minute)
	first, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	context := BrowserContext{RequestID: "33333333333333333333333333333333", Origin: "https://example.test", TabID: 3, DocumentID: "document-3"}
	if _, err := receiver.PerformPasskey(transferPlanLoginTarget(context, existingID, existingRevision), false, dailyGate(t, receiver)); err != nil {
		t.Fatalf("append target credential: %v", err)
	}
	second, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Fatal("target parent revision change did not change the plan digest")
	}
	if len(second.Groups) != 1 || len(second.Groups[0].EligibleTargets) != 1 || second.Groups[0].EligibleTargets[0].Revision == existingRevision {
		t.Fatalf("eligible revision was not refreshed: %+v", second.Groups)
	}
}

func appendTransferConsume(t *testing.T, receiver *Session, invite PasskeyTransferInvitation) {
	t.Helper()
	db, err := existing(receiver.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyTransferConsumeAction, receiver)
		if err != nil {
			return err
		}
		defer auth.clear()
		var creation Event
		for _, row := range auth.rows {
			if row.Action == passkeyTransferInviteAction && row.Item == invite.ID {
				creation = row
			}
		}
		if creation.Item == "" {
			return invalid
		}
		_, err = appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, auth.snapshot, passkeyTransferConsumeAction, invite.ID, "succeeded", creation.hash(), creation.Link)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyTransferPlanRefusals(t *testing.T) {
	t.Run("missing-source-pin", func(t *testing.T) {
		_, receiver, invite, _, export, _, _, _ := passkeyTransferPlanFixture(t, 5*time.Minute)
		before := rawAuditCountNoSession(t, receiver.path)
		if _, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, ""); err == nil {
			t.Fatal("empty source pin accepted")
		}
		if rawAuditCountNoSession(t, receiver.path) != before {
			t.Fatal("refusal appended audit")
		}
	})
	t.Run("foreign-source-pin", func(t *testing.T) {
		_, receiver, invite, _, export, _, _, _ := passkeyTransferPlanFixture(t, 5*time.Minute)
		if _, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, strings.Repeat("a", 64)); err == nil {
			t.Fatal("foreign source pin accepted")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		_, receiver, invite, _, export, _, _, _ := passkeyTransferPlanFixture(t, 5*time.Minute)
		if err := receiver.RevokePasskeyTransferInvitation(invite.Raw, dailyGate(t, receiver)); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint); err == nil {
			t.Fatal("revoked invitation planned")
		}
	})
	t.Run("consumed-replay", func(t *testing.T) {
		_, receiver, invite, _, export, _, _, _ := passkeyTransferPlanFixture(t, 5*time.Minute)
		appendTransferConsume(t, receiver, invite)
		if _, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint); err == nil {
			t.Fatal("consumed invitation planned twice")
		}
	})
	t.Run("expired", func(t *testing.T) {
		_, receiver, invite, _, export, _, _, _ := passkeyTransferPlanFixture(t, 2*time.Second)
		time.Sleep(2100 * time.Millisecond)
		if _, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint); err == nil {
			t.Fatal("expired invitation planned")
		}
	})
}

func installTrashedTransferCredential(t *testing.T, receiver *Session, raw []byte) {
	t.Helper()
	defer clear(raw)
	record, err := passkey.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Clear()
	itemID, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	item := vault.Item{ID: itemID, Kind: "login", Title: "trashed duplicate", State: "trashed"}
	if err := item.SetLegacyPasskey(raw); err != nil {
		t.Fatal(err)
	}
	defer item.ClearPasskeys()
	db, err := existing(receiver.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, "item.add", receiver)
		if err != nil {
			return err
		}
		defer auth.clear()
		items := append([]vault.Item(nil), auth.items...)
		items = append(items, item)
		if vault.ValidateItems([]byte(schema), items) != nil {
			return invalid
		}
		snapshot, err := seal(tx.Bucket(bucket), auth.identity, auth.snapshot.Epoch+1, items)
		if err != nil {
			return err
		}
		_, err = appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, snapshot, "item.add", itemID, "succeeded", "", "")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyTransferPlanRefusesDuplicateAnyVaultItem(t *testing.T) {
	source, receiver, invite, _, export, targets, _, _ := passkeyTransferPlanFixture(t, 5*time.Minute)
	duplicate := passkeyRecord(t, source, targets[0].ItemID, targets[0].CredentialID)
	installTrashedTransferCredential(t, receiver, duplicate)
	if _, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint); err == nil {
		t.Fatal("duplicate credential in a trashed recipient item was accepted")
	}
}

func TestPasskeyTransferPlanRestoredOldChainRefuses(t *testing.T) {
	source, sourceTarget, _, _, _ := passkeyMultiFixture(t)
	receiver, public := exportTestReceiver(t)
	archive := t.TempDir() + "/before.llbackup"
	kit, err := Backup(receiver.path, archive, "fixture", transferPlanKey(9))
	if err != nil {
		t.Fatal(err)
	}
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	targets := exportTestTargets(t, source, sourceTarget.ID)
	export, err := source.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, dailyGate(t, source))
	if err != nil {
		t.Fatal(err)
	}
	restored := t.TempDir() + "/restored.ll"
	if err := Restore(archive, restored, "fixture", transferPlanKey(9), kit, transferPlanKey(8)); err != nil {
		t.Fatal(err)
	}
	old, err := UnlockSession(restored, []byte("fixture"), transferPlanKey(8), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Lock()
	if _, err := old.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint); err == nil {
		t.Fatal("plan accepted an invitation absent from the restored current chain")
	}
}

func transferPlanKey(b byte) []byte { return []byte{b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b} }
