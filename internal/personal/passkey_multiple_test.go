package personal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
)

func useReadAuthenticatedItems(t *testing.T, s *Session) []vault.Item {
	t.Helper()
	items, _, err := s.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func deferClearPasskeys(t *testing.T, items []vault.Item) {
	t.Helper()
	t.Cleanup(func() {
		for n := range items {
			items[n].ClearPasskeys()
		}
	})
}

func passkeyRecord(t *testing.T, s *Session, itemID, credentialID string) []byte {
	t.Helper()
	// ReadAuthenticatedItems deliberately zeroes passkey backing bytes, so raw
	// records are opened through the existing snapshot helper and cleared here.
	items := rawItems(t, s)
	defer func() {
		for n := range items {
			items[n].ClearPasskeys()
		}
	}()
	for _, item := range items {
		if item.ID != itemID {
			continue
		}
		for _, raw := range item.PasskeyRecords() {
			record, err := passkey.Load(raw)
			if err != nil {
				continue
			}
			matches := record.ID == credentialID
			record.Clear()
			if matches {
				return bytes.Clone(raw)
			}
		}
	}
	t.Fatalf("credential %q missing from item %q", credentialID, itemID)
	return nil
}

func passkeyMultiFixture(t *testing.T) (*Session, PasskeyTarget, passkey.Response, passkey.Response, string) {
	t.Helper()
	s, target := passkeyTarget(t)
	first, err := s.PerformPasskey(target, false, dailyGate(t, s))
	if err != nil {
		t.Fatalf("first credential: %v", err)
	}
	// The same login, same RP and same user handle, with a fresh revision.
	target.Revision = suggestionsRevision(t, s, target.ID)
	second, err := s.PerformPasskey(target, false, dailyGate(t, s))
	if err != nil {
		t.Fatalf("second credential: %v", err)
	}
	if first.ID == second.ID {
		t.Fatal("second credential reused the first credential ID")
	}
	return s, target, first, second, suggestionsRevision(t, s, target.ID)
}

func verifyPasskeySignature(t *testing.T, raw []byte, response passkey.Response) {
	t.Helper()
	record, err := passkey.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Clear()
	if response.ID != record.ID {
		t.Fatalf("assertion signed by %q, want %q", response.ID, record.ID)
	}
	key, err := x509.ParsePKCS8PrivateKey(record.PrivateKey)
	private, ok := key.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		t.Fatalf("private key: %v", err)
	}
	authData, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.AuthenticatorData)
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.ClientDataJSON)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.Signature)
	if err != nil {
		t.Fatal(err)
	}
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(&private.PublicKey, digest[:], signature) {
		t.Fatal("selected credential produced an invalid assertion signature")
	}
}

func TestPasskeySecondCredentialAppendsToOneLogin(t *testing.T) {
	s, target, first, second, revision := passkeyMultiFixture(t)
	items := useReadAuthenticatedItems(t, s)
	deferClearPasskeys(t, items)
	found := 0
	for _, item := range items {
		if item.ID != target.ID {
			continue
		}
		found++
		records := item.PasskeyRecords()
		if len(records) != 2 {
			t.Fatalf("one login stored %d credentials, want 2", len(records))
		}
		if len(item.Passkeys) != 2 || len(item.Passkey) != 0 {
			t.Fatalf("collection form: collection=%d legacy=%d", len(item.Passkeys), len(item.Passkey))
		}
	}
	if found != 1 {
		t.Fatalf("found %d copies of the login, want exactly 1", found)
	}
	rawItems := rawItems(t, s)
	deferClearPasskeys(t, rawItems)
	ids := map[string]bool{}
	for _, item := range rawItems {
		if item.ID != target.ID {
			continue
		}
		for _, raw := range item.PasskeyRecords() {
			record, err := passkey.Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			ids[record.ID] = true
			record.Clear()
		}
	}
	if !ids[first.ID] || !ids[second.ID] {
		t.Fatalf("stored credentials %v missing one of %q/%q", ids, first.ID, second.ID)
	}
	if revision == "" {
		t.Fatal("missing parent revision after two creations")
	}
}

func TestPasskeyAssertionRequiresExactSelector(t *testing.T) {
	s, target, first, second, _ := passkeyMultiFixture(t)
	both := []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","allowCredentials":[{"type":"public-key","id":"` + first.ID + `"},{"type":"public-key","id":"` + second.ID + `"}]}`)
	base := PasskeyTarget{Context: target.Context, ID: target.ID, Revision: suggestionsRevision(t, s, target.ID), Options: both}
	if _, err := s.PerformPasskey(base, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("assertion without selector on two credentials: %v", err)
	}
	wrong := base
	wrong.CredentialID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if !passkey.ValidCredentialID(wrong.CredentialID) {
		t.Fatal("fixture wrong selector is not canonical")
	}
	if _, err := s.PerformPasskey(wrong, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("assertion with unknown selector: %v", err)
	}
	mismatch := base
	mismatch.CredentialID = first.ID
	mismatch.Options = passkeyGetOptions(second.ID)
	if _, err := s.PerformPasskey(mismatch, false, dailyGate(t, s)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatalf("selector does not match allowCredentials: %v", err)
	}
	choices, err := s.ReviewPasskey(PasskeyTarget{Context: target.Context, Options: both, CredentialID: second.ID})
	if err != nil || len(choices) != 1 || choices[0].CredentialID != second.ID || choices[0].ID != target.ID {
		t.Fatalf("explicit selector choices: %v %+v", err, choices)
	}
	get := PasskeyTarget{Context: target.Context, ID: target.ID, Revision: suggestionsRevision(t, s, target.ID), CredentialID: second.ID, Options: passkeyGetOptions(second.ID)}
	response, err := s.PerformPasskey(get, false, dailyGate(t, s))
	if err != nil || response.ID != second.ID {
		t.Fatalf("selected assertion: %v %+v", err, response)
	}
	verifyPasskeySignature(t, passkeyRecord(t, s, target.ID, second.ID), response)
}

func TestRemovePasskeyExactFromMultiplePreservesSibling(t *testing.T) {
	s, target, first, second, revision := passkeyMultiFixture(t)
	var err error
	if revision, err = s.Edit(Edit{ID: target.ID, Revision: revision, Field: "notes", Value: "notes kept across one removal"}); err != nil {
		t.Fatal(err)
	}
	items := useReadAuthenticatedItems(t, s)
	deferClearPasskeys(t, items)
	before := vault.Item{}
	for _, item := range items {
		if item.ID == target.ID {
			before = item
		}
	}
	if len(before.PasskeyRecords()) != 2 || before.Password == "" || before.Notes == "" {
		t.Fatalf("before removal: records=%d password=%q notes=%q", len(before.PasskeyRecords()), before.Password, before.Notes)
	}
	sibling := passkeyRecord(t, s, target.ID, second.ID)
	defer clear(sibling)
	removed, err := s.RemovePasskey(target.ID, revision, first.ID, dailyGate(t, s))
	if err != nil {
		t.Fatalf("exact removal: %v", err)
	}
	items = rawItems(t, s)
	deferClearPasskeys(t, items)
	after := vault.Item{}
	for _, item := range items {
		if item.ID == target.ID {
			after = item
		}
	}
	records := after.PasskeyRecords()
	if len(records) != 1 || len(after.Passkey) != 0 || len(after.Passkeys) != 1 {
		t.Fatalf("sibling layout: records=%d legacy=%d collection=%d", len(records), len(after.Passkey), len(after.Passkeys))
	}
	if !bytes.Equal(records[0], sibling) {
		t.Fatal("remaining credential bytes changed")
	}
	if after.Password != before.Password || after.Notes != before.Notes || after.Username != before.Username || after.Title != before.Title {
		t.Fatal("removal changed login, password, notes or title")
	}
	id, err := passkey.Load(records[0])
	if err != nil || id.ID != second.ID {
		t.Fatalf("surviving credential: %v %+v", err, id)
	}
	id.Clear()
	if candidates, err := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(first.ID)}); err != nil || len(candidates) != 0 {
		t.Fatalf("removed credential still discoverable: %v %d", err, len(candidates))
	}
	if _, err := s.RemovePasskey(target.ID, removed, second.ID, dailyGate(t, s)); err != nil {
		t.Fatalf("last exact removal: %v", err)
	}
	items = useReadAuthenticatedItems(t, s)
	deferClearPasskeys(t, items)
	for _, item := range items {
		if item.ID == target.ID && (len(item.PasskeyRecords()) != 0 || item.Password != before.Password || item.Notes != before.Notes) {
			t.Fatalf("last removal left credentials or lost fields: %#v", item)
		}
	}
}

func TestReadPasskeysMetadataMultipleAndLegacyCompatibility(t *testing.T) {
	s, target, first, second, _ := passkeyMultiFixture(t)
	all, err := s.ReadPasskeysMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	values := all[target.ID]
	if len(values) != 2 {
		t.Fatalf("multi metadata entries: %d", len(values))
	}
	ids := map[string]bool{}
	for _, value := range values {
		if value.RPID != "example.test" || value.UserName != "passkey-fixture-user" {
			t.Fatalf("metadata leaked or lost fields: %+v", value)
		}
		ids[value.CredentialID] = true
	}
	if !ids[first.ID] || !ids[second.ID] {
		t.Fatalf("metadata credentials: %v", ids)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private_key")) || bytes.Contains(raw, []byte("user_id")) || bytes.Contains(raw, []byte("PRIVATE")) {
		t.Fatalf("metadata JSON exposed secret fields: %s", raw)
	}
	if !bytes.Contains(raw, []byte(first.ID)) || !bytes.Contains(raw, []byte(second.ID)) {
		t.Fatal("public metadata JSON lost a credential ID")
	}
	legacy, err := s.ReadPasskeyMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := legacy[target.ID]; ok {
		t.Fatal("single-credential projection reported an ambiguous login")
	}
}

func TestConditionalPasskeyCandidatesTwoCredentialsOneLogin(t *testing.T) {
	s, target, first, second, revision := passkeyMultiFixture(t)
	candidates, err := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates: %d", len(candidates))
	}
	ids := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.ItemID != target.ID || candidate.Revision != revision || candidate.RPID != "example.test" {
			t.Fatalf("candidate metadata: %+v", candidate)
		}
		ids[candidate.CredentialID] = true
	}
	if !ids[first.ID] || !ids[second.ID] {
		t.Fatalf("candidate credentials: %v", ids)
	}
	if candidates[0].CredentialID >= candidates[1].CredentialID {
		t.Fatalf("credential order is not deterministic: %q >= %q", candidates[0].CredentialID, candidates[1].CredentialID)
	}
}
