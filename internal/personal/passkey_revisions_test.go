package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/passkey"
)

func managedValues(t *testing.T, s *Session, itemID string) map[string]ManagedPasskeyMetadata {
	t.Helper()
	all, err := s.ReadManagedPasskeysMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]ManagedPasskeyMetadata{}
	for _, value := range all[itemID] {
		if _, seen := values[value.CredentialID]; seen {
			t.Fatalf("duplicate managed credential %q", value.CredentialID)
		}
		values[value.CredentialID] = value
	}
	return values
}

func TestManagedPasskeyMetadataDistinctAndPublic(t *testing.T) {
	s, target, first, second, _ := passkeyMultiFixture(t)
	all, err := s.ReadManagedPasskeysMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	values := all[target.ID]
	if len(values) != 2 {
		t.Fatalf("managed metadata entries: %d", len(values))
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !digestOK(value.Revision) {
			t.Fatalf("revision is not canonical 64-hex: %q", value.Revision)
		}
		if value.RPID != "example.test" || value.UserName != "passkey-fixture-user" || value.DisplayName != "Fixture" {
			t.Fatalf("lost public fields: %+v", value)
		}
		seen[value.CredentialID] = true
		seen[value.Revision] = true
	}
	if !seen[first.ID] || !seen[second.ID] {
		t.Fatalf("credentials missing: %v", seen)
	}
	// Two credentials of one login must have independent revisions.
	if values[0].Revision == values[1].Revision {
		t.Fatal("sibling credentials share a revision")
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private_key")) || bytes.Contains(raw, []byte("user_id")) || bytes.Contains(raw, []byte("PRIVATE")) {
		t.Fatalf("metadata JSON exposed secret field names: %s", raw)
	}
	recordRaw := passkeyRecord(t, s, target.ID, first.ID)
	defer clear(recordRaw)
	record, err := passkey.Load(recordRaw)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Clear()
	if bytes.Contains(raw, []byte(record.UserID)) {
		t.Fatal("metadata JSON exposed the raw user handle")
	}
}

func TestCredentialRevisionCanonicalJSONOrder(t *testing.T) {
	s, target, first, _, _ := passkeyMultiFixture(t)
	var identityValue identity
	if err := json.Unmarshal(s.material, &identityValue); err != nil {
		t.Fatal(err)
	}
	defer identityValue.clear()
	raw := passkeyRecord(t, s, target.ID, first.ID)
	defer clear(raw)
	want, err := credentialRevision(identityValue.AuditEncryption, target.ID, raw)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, reordered) {
		t.Fatal("reordered fixture is byte-identical")
	}
	if _, err = passkey.Load(reordered); err != nil {
		t.Fatalf("reordered canonical record rejected: %v", err)
	}
	got, err := credentialRevision(identityValue.AuditEncryption, target.ID, reordered)
	if err != nil || got != want {
		t.Fatalf("reordered record revision: %q %v want %q", got, err, want)
	}
	if values := managedValues(t, s, target.ID); values[first.ID].Revision != want {
		t.Fatal("managed revision differs from the canonical record revision")
	}
}

func TestManagedCredentialRevisionTracksOnlyOwnContent(t *testing.T) {
	s, target, first, second, revision := passkeyMultiFixture(t)
	before := managedValues(t, s, target.ID)
	if _, err := s.Edit(Edit{ID: target.ID, Revision: revision, Field: "notes", Value: "unrelated edit"}); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		target.Revision = suggestionsRevision(t, s, target.ID)
		if _, err := s.PerformPasskey(target, false, dailyGate(t, s)); err != nil {
			t.Fatalf("add credential %d: %v", n, err)
		}
	}
	after := managedValues(t, s, target.ID)
	if len(after) != 5 {
		t.Fatalf("managed entries after additions: %d", len(after))
	}
	if after[first.ID].Revision != before[first.ID].Revision || after[second.ID].Revision != before[second.ID].Revision {
		t.Fatal("an untouched sibling credential changed its revision")
	}
	seen := map[string]bool{}
	for _, value := range after {
		if seen[value.Revision] {
			t.Fatalf("duplicate credential revision %q", value.Revision)
		}
		seen[value.Revision] = true
	}
	revision = suggestionsRevision(t, s, target.ID)
	if _, err := s.RemovePasskey(target.ID, revision, first.ID, dailyGate(t, s)); err != nil {
		t.Fatalf("remove first credential: %v", err)
	}
	remaining := managedValues(t, s, target.ID)
	if len(remaining) != 4 {
		t.Fatalf("managed entries after removal: %d", len(remaining))
	}
	if remaining[second.ID].Revision != before[second.ID].Revision {
		t.Fatal("removing a sibling changed the untouched credential revision")
	}
}

func TestManagedCredentialRevisionChangesOnOwnMetadata(t *testing.T) {
	s, target, first, second, _ := passkeyMultiFixture(t)
	before := managedValues(t, s, target.ID)
	request := signalUser("https://example.test", "example.test", "dXNlcjE", "renamed-user", "Renamed User")
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 2 {
		t.Fatalf("signal review: %#v %v", proposal, err)
	}
	if _, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s)); err != nil {
		t.Fatalf("apply signal: %v", err)
	}
	after := managedValues(t, s, target.ID)
	for _, credential := range []string{first.ID, second.ID} {
		if after[credential].Revision == before[credential].Revision {
			t.Fatalf("credential %q kept its revision after its own metadata changed", credential)
		}
		if after[credential].UserName != "renamed-user" || after[credential].DisplayName != "Renamed User" {
			t.Fatalf("managed names not updated for %q: %+v", credential, after[credential])
		}
	}
	if after[first.ID].Revision == after[second.ID].Revision {
		t.Fatal("updated siblings share a revision")
	}
}

func credentialTarget(t *testing.T, s *Session, target PasskeyTarget, credential string) PasskeyTarget {
	t.Helper()
	value, ok := managedValues(t, s, target.ID)[credential]
	if !ok {
		t.Fatalf("credential %q missing from managed metadata", credential)
	}
	return PasskeyTarget{Context: target.Context, ID: target.ID, Revision: suggestionsRevision(t, s, target.ID), CredentialID: credential, CredentialRevision: value.Revision, Options: passkeyGetOptions(credential)}
}

func TestPasskeyCredentialRevisionSelector(t *testing.T) {
	s, target, first, second, _ := passkeyMultiFixture(t)
	choices, err := s.ReviewPasskey(PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(first.ID)})
	if err != nil || len(choices) != 1 || choices[0].CredentialRevision != managedValues(t, s, target.ID)[first.ID].Revision {
		t.Fatalf("review revision: %+v %v", choices, err)
	}
	good := credentialTarget(t, s, target, first.ID)
	if response, err := s.PerformPasskey(good, false, dailyGate(t, s)); err != nil || response.ID != first.ID {
		t.Fatalf("exact child revision assertion: %v %+v", err, response)
	}
	legacy := good
	legacy.CredentialRevision = ""
	if response, err := s.PerformPasskey(legacy, false, dailyGate(t, s)); err != nil || response.ID != first.ID {
		t.Fatalf("legacy selector-less revision behavior changed: %v %+v", err, response)
	}
	if _, err := s.PerformPasskey(PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(first.ID)}, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("missing selector on a multi-credential login was not refused: %v", err)
	}
	create := good
	create.Create, create.ID, create.Revision = true, "", ""
	if _, err := s.PerformPasskey(create, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("creation accepted a child revision: %v", err)
	}
	stale := good
	stale.CredentialRevision = managedValues(t, s, target.ID)[second.ID].Revision
	if reviewed, reviewErr := s.ReviewPasskey(stale); reviewErr == nil && len(reviewed) != 0 {
		t.Fatal("review silently repaired a stale child revision")
	}
	if _, err := s.PerformPasskey(stale, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("current parent accepted another credential's child revision: %v", err)
	}
	wrongParent := good
	wrongParent.Revision = strings.Repeat("a", 64)
	if _, err := s.PerformPasskey(wrongParent, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("stale parent was not refused: %v", err)
	}
	wrongCredential := good
	wrongCredential.CredentialID, wrongCredential.Options = second.ID, passkeyGetOptions(second.ID)
	if _, err := s.PerformPasskey(wrongCredential, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("wrong credential accepted a foreign child revision: %v", err)
	}
}

func TestRemovePasskeyWithRevisionChildCheck(t *testing.T) {
	s, target, first, second, _ := passkeyMultiFixture(t)
	values := managedValues(t, s, target.ID)
	revision := suggestionsRevision(t, s, target.ID)
	if _, err := s.RemovePasskeyWithRevision(target.ID, revision, first.ID, strings.Repeat("0", 64), dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("stale child revision with current parent: %v", err)
	}
	if _, err := s.RemovePasskeyWithRevision(target.ID, strings.Repeat("a", 64), first.ID, values[first.ID].Revision, dailyGate(t, s)); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong parent: %v", err)
	}
	if _, err := s.RemovePasskeyWithRevision(target.ID, revision, second.ID, values[first.ID].Revision, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("wrong credential accepted a foreign child revision: %v", err)
	}
	if _, err := s.RemovePasskeyWithRevision(target.ID, revision, first.ID, "short", dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("invalid child revision: %v", err)
	}
	if _, err := s.RemovePasskeyWithRevision(target.ID, revision, first.ID, values[first.ID].Revision, dailyGate(t, s)); err != nil {
		t.Fatalf("exact parent and child revision removal: %v", err)
	}
	remaining := managedValues(t, s, target.ID)
	if len(remaining) != 1 || remaining[second.ID].Revision != values[second.ID].Revision {
		t.Fatalf("sibling changed across exact removal: %+v", remaining)
	}
}
