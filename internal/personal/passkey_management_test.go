package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func removeFixture(t *testing.T) (*Session, PasskeyTarget, passkey.Response) {
	t.Helper()
	s, target := passkeyTarget(t)
	created, err := s.PerformPasskey(target, false, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return s, target, created
}

func rawItems(t *testing.T, s *Session) []vault.Item {
	t.Helper()
	var identityValue identity
	if err := json.Unmarshal(s.material, &identityValue); err != nil {
		t.Fatal(err)
	}
	defer identityValue.clear()
	device, err := age.ParseX25519Identity(identityValue.Device)
	if err != nil {
		t.Fatal(err)
	}
	signer := ed25519.NewKeyFromSeed(identityValue.Signing)
	defer clear(signer)
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var items []vault.Item
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return invalid
		}
		var snapshot vault.Snapshot
		if json.Unmarshal(b.Get(snapshotKey), &snapshot) != nil {
			return invalid
		}
		_, opened, err := vault.OpenItems(snapshot, device, signer.Public().(ed25519.PublicKey), snapshot.Epoch)
		items = opened
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func itemByID(items []vault.Item, id string) (vault.Item, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return vault.Item{}, false
}

func lastAuditEvent(t *testing.T, s *Session) Event {
	t.Helper()
	var identityValue identity
	if err := json.Unmarshal(s.material, &identityValue); err != nil {
		t.Fatal(err)
	}
	defer identityValue.clear()
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var event Event
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return invalid
		}
		events := b.Bucket(eventsKey)
		if events == nil {
			return invalid
		}
		cipher, err := auditCipher(identityValue)
		if err != nil {
			return err
		}
		return events.ForEach(func(key, raw []byte) error {
			if len(key) != 8 {
				return invalid
			}
			var candidate Event
			if readSealed(cipher, eventLabel(key), raw, &candidate) != nil {
				return invalid
			}
			if candidate.Sequence >= event.Sequence {
				event = candidate
			}
			return nil
		})
	})
	if err != nil || event.Sequence == 0 {
		t.Fatalf("read audit event: %v", err)
	}
	return event
}

func TestRemovePasskeyAtomicPreservationAuditAndSelectorRefusals(t *testing.T) {
	s, target, created := removeFixture(t)
	revision, err := rowRevision(t, s, "active", target.ID)
	if revision, err = s.Edit(Edit{ID: target.ID, Revision: revision, Field: "notes", Value: "notes preserved through removal"}); err != nil {
		t.Fatal(err)
	}
	if revision, err = s.Edit(Edit{ID: target.ID, Revision: revision, Field: "otp", Value: v2OTPConfig}); err != nil {
		t.Fatal(err)
	}
	if revision, err = s.SetTags(target.ID, revision, []string{"preserved", "passkey"}, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	if _, revision, err = s.AddAttachment(target.ID, revision, "preserved.txt", "text/plain", []byte("attachment bytes"), dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	if revision, err = s.SetState(target.ID, revision, "item.archive"); err != nil {
		t.Fatal(err)
	}
	if got, err := rowRevision(t, s, "all", target.ID); err != nil || got != revision {
		t.Fatalf("archived fixture revision: %q %v", got, err)
	}
	beforeItems := rawItems(t, s)
	before, ok := itemByID(beforeItems, target.ID)
	if !ok || len(before.Passkey) == 0 {
		t.Fatal("missing persisted passkey")
	}
	expected := vault.CloneItem(before)
	auditBefore := rawAuditActionCount(t, s, passkeyRemoveAction)

	// Known pre-commit selectors refuse without changing the item or journal.
	for name, attempt := range map[string]struct {
		id, revision, credential string
		want                     error
	}{
		"wrong credential": {target.ID, revision, strings.Repeat("A", 43), ErrMutationRefused},
		"stale revision":   {target.ID, strings.Repeat("a", 64), created.ID, ErrConflict},
		"unknown item":     {strings.Repeat("b", 32), revision, created.ID, ErrNotFound},
	} {
		if _, err = s.RemovePasskey(attempt.id, attempt.revision, attempt.credential, dailyGate(t, s)); !errors.Is(err, attempt.want) {
			t.Fatalf("%s: got %v want %v", name, err, attempt.want)
		}
		if got := rawItems(t, s); !reflect.DeepEqual(got, beforeItems) {
			t.Fatalf("%s changed the item", name)
		}
		if got := rawAuditActionCount(t, s, passkeyRemoveAction); got != auditBefore {
			t.Fatalf("%s appended an audit event: %d -> %d", name, auditBefore, got)
		}
	}
	noKey, err := s.AddLogin("No passkey", "nobody", "password")
	if err != nil {
		t.Fatal(err)
	}
	noKeyRows, err := s.List("all")
	if err != nil {
		t.Fatal(err)
	}
	var noKeyRevision string
	for _, row := range noKeyRows {
		if row.ID == noKey {
			noKeyRevision = row.Revision
		}
	}
	if _, err = s.RemovePasskey(noKey, noKeyRevision, created.ID, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("no-key removal: %v", err)
	}
	if got := rawAuditActionCount(t, s, passkeyRemoveAction); got != auditBefore {
		t.Fatalf("no-key removal audit count: %d -> %d", auditBefore, got)
	}

	newRevision, err := s.RemovePasskey(target.ID, revision, created.ID, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if newRevision == "" || newRevision == revision {
		t.Fatal("removal did not advance the revision")
	}
	afterItems := rawItems(t, s)
	after, ok := itemByID(afterItems, target.ID)
	if !ok {
		t.Fatal("login disappeared")
	}
	if len(after.Passkey) != 0 {
		t.Fatal("credential remained in the durable record")
	}
	// Only Passkey (and the mutation timestamp) may differ.
	expected.Passkey = nil
	expected.UpdatedAt = after.UpdatedAt
	if !reflect.DeepEqual(expected, after) {
		t.Fatalf("remove changed unrelated fields:\nbefore=%#v\nafter=%#v", expected, after)
	}
	if after.Password == "" || after.Notes == "" || after.OTP == "" || len(after.Attachments) != 1 || after.State != "archived" {
		t.Fatal("login, password, notes, OTP, attachment or archived state was lost")
	}
	event := lastAuditEvent(t, s)
	if event.Action != passkeyRemoveAction || event.Result != "succeeded" || event.Item != target.ID || event.BaseRevision != revision || event.Link != "" {
		t.Fatalf("removal audit: %#v", event)
	}
	if event.hash() != newRevision {
		t.Fatal("returned revision is not the durable audit revision")
	}
	if got := rawAuditActionCount(t, s, passkeyRemoveAction); got != auditBefore+1 {
		t.Fatalf("removal audit count: got %d want %d", got, auditBefore+1)
	}

	// Reopen the vault and use the normal authenticated read/history path: the
	// removal event must verify, and its digest must be the item's revision.
	s.Lock()
	key := bytes.Repeat([]byte{4}, 16)
	next, err := UnlockSession(s.path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Lock()
	items, revisions, err := next.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	if revisions[target.ID] != newRevision {
		FatalRevision(t, revisions[target.ID], newRevision)
	}
	reopened, ok := itemByID(items, target.ID)
	if !ok || len(reopened.Passkey) != 0 || reopened.Password == "" || reopened.Notes == "" || reopened.OTP == "" || len(reopened.Attachments) != 1 || reopened.State != "archived" {
		t.Fatalf("reopened item lost unrelated data: %#v", reopened)
	}
	detail, err := next.GetItemDetail(target.ID, newRevision, false)
	if err != nil || detail.HasPasskey || detail.State != "archived" || len(detail.Attachments) != 1 || detail.Notes != reopened.Notes || detail.OTP != "" {
		t.Fatalf("reopened detail: %#v %v", detail, err)
	}
	found := false
	events, err := next.Audit()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range events {
		if candidate.Action == passkeyRemoveAction && candidate.Result == "succeeded" && candidate.Item == target.ID && candidate.BaseRevision == revision {
			found = candidate.hash() != ""
		}
	}
	if !found {
		FatalRevision(t, "missing", passkeyRemoveAction)
	}
}

func FatalRevision(t *testing.T, got, want string) {
	t.Helper()
	t.Fatalf("revision mismatch: got %q want %q", got, want)
}

func rowRevision(t *testing.T, s *Session, state, id string) (string, error) {
	t.Helper()
	rows, err := s.List(state)
	if err != nil {
		return "", err
	}
	for _, row := range rows {
		if row.ID == id {
			return row.Revision, nil
		}
	}
	return "", ErrNotFound
}

func rawAuditActionCount(t *testing.T, s *Session, action string) int {
	t.Helper()
	var identityValue identity
	if err := json.Unmarshal(s.material, &identityValue); err != nil {
		t.Fatal(err)
	}
	defer identityValue.clear()
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	count := 0
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil || b.Bucket(eventsKey) == nil {
			return invalid
		}
		cipher, err := auditCipher(identityValue)
		if err != nil {
			return err
		}
		return b.Bucket(eventsKey).ForEach(func(key, raw []byte) error {
			var event Event
			if readSealed(cipher, eventLabel(key), raw, &event) != nil {
				return invalid
			}
			if event.Action == action {
				count++
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func rawAuditCount(t *testing.T, s *Session) int {
	t.Helper()
	return rawAuditCountNoSession(t, s.path)
}

func rawAuditCountNoSession(t *testing.T, path string) int {
	t.Helper()
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	count := 0
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil || b.Bucket(eventsKey) == nil {
			return invalid
		}
		return b.Bucket(eventsKey).ForEach(func(key, _ []byte) error {
			if len(key) != 8 || binary.BigEndian.Uint64(key) != uint64(count+1) {
				return invalid
			}
			count++
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func mustAudit(t *testing.T, s *Session) []Event {
	t.Helper()
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestRemovePasskeyRefusesTrashedCancelledAndLockedWithoutMutation(t *testing.T) {
	s, target, created := removeFixture(t)
	revision, err := rowRevision(t, s, "active", target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err = s.SetState(target.ID, revision, "item.trash"); err != nil {
		t.Fatal(err)
	}
	before := rawItems(t, s)
	beforeAudit := rawAuditActionCount(t, s, passkeyRemoveAction)
	if revision, err = rowRevision(t, s, "all", target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RemovePasskey(target.ID, revision, created.ID, dailyGate(t, s)); !errors.Is(err, ErrTrashed) {
		t.Fatalf("trashed removal: %v", err)
	}
	after := rawItems(t, s)
	auditAfter := rawAuditActionCount(t, s, passkeyRemoveAction)
	if !reflect.DeepEqual(after, before) || auditAfter != beforeAudit {
		t.Fatalf("trashed refusal changed data or journal: audit %d -> %d; before=%#v after=%#v", beforeAudit, auditAfter, before, after)
	}
}

func TestRemovePasskeyCancelledAndLockedGates(t *testing.T) {
	s, target, created := removeFixture(t)
	revision, err := rowRevision(t, s, "active", target.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := rawItems(t, s)
	beforeAudit := rawAuditActionCount(t, s, passkeyRemoveAction)
	totalBefore := rawAuditCountNoSession(t, s.path)
	cancelled := dailyGate(t, s)
	cancelled.Cancel()
	if _, err = s.RemovePasskey(target.ID, revision, created.ID, cancelled); !errors.Is(err, ErrMutationCancelled) {
		t.Fatalf("cancelled gate: %v", err)
	}
	locked := dailyGate(t, s)
	s.RequestLock()
	if _, err = s.RemovePasskey(target.ID, revision, created.ID, locked); !errors.Is(err, ErrMutationCancelled) && !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("locked removal: %v", err)
	}
	if !reflect.DeepEqual(rawItems(t, s), before) || rawAuditActionCount(t, s, passkeyRemoveAction) != beforeAudit {
		t.Fatal("cancelled/locked removal changed data or journal")
	}
	s.Lock()
	if rawAuditCountNoSession(t, s.path) != totalBefore {
		t.Fatal("locked removal changed the journal")
	}
}

func passkeyGetOptions(credential string) []byte {
	return []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","allowCredentials":[{"type":"public-key","id":"` + credential + `"}]}`)
}

func TestRemovePasskeyKeepsOtherAccountSigning(t *testing.T) {
	s, target, first := removeFixture(t)
	secondTarget := target
	secondTarget.ID = ""
	secondTarget.Revision = ""
	secondTarget.Options = []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjI","name":"second-user","displayName":"Second"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)
	second, err := s.PerformPasskey(secondTarget, false, dailyGate(t, s))
	if err != nil || second.ID == first.ID {
		t.Fatalf("second credential: %v", err)
	}
	rows, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	secondID := ""
	for _, row := range rows {
		if row.Title == "example.test · second-user" {
			secondID = row.ID
		}
	}
	if secondID == "" || secondID == target.ID {
		t.Fatal("second login missing")
	}
	firstRevision, err := rowRevision(t, s, "active", target.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondRevision, err := rowRevision(t, s, "active", secondID)
	if err != nil {
		t.Fatal(err)
	}
	removedRevision, err := s.RemovePasskey(target.ID, firstRevision, first.ID, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	oldGet := PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(first.ID)}
	if choices, err := s.ReviewPasskey(oldGet); err != nil || len(choices) != 0 {
		t.Fatalf("removed credential still selectable: %v %#v", err, choices)
	}
	oldGet.ID, oldGet.Revision = target.ID, removedRevision
	if _, err := s.PerformPasskey(oldGet, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("removed credential signed: %v", err)
	}
	newGet := PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(second.ID)}
	choices, err := s.ReviewPasskey(newGet)
	if err != nil || len(choices) != 1 || choices[0].ID != secondID || choices[0].Revision != secondRevision {
		t.Fatalf("other account choices: %v %#v", err, choices)
	}
	newGet.ID, newGet.Revision = choices[0].ID, choices[0].Revision
	signed, err := s.PerformPasskey(newGet, false, dailyGate(t, s))
	if err != nil || signed.ID != second.ID {
		t.Fatalf("other account sign: %v", err)
	}
	if _, err := s.List("active"); err != nil {
		t.Fatal("session unusable after removal", err)
	}
}
