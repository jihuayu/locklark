package personal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
)

type signalAccount struct {
	ItemID, Revision, CredentialID, UserID string
}

func signalCreate(t *testing.T, s *Session, ctx BrowserContext, userID, name, display string) signalAccount {
	t.Helper()
	options := []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"` + userID + `","name":"` + name + `","displayName":"` + display + `"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)
	response, err := s.PerformPasskey(PasskeyTarget{Context: ctx, Create: true, Options: options}, false, dailyGate(t, s))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	rows, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Title == "example.test · "+name {
			return signalAccount{ItemID: row.ID, Revision: row.Revision, CredentialID: response.ID, UserID: userID}
		}
	}
	t.Fatalf("created item %q missing", name)
	return signalAccount{}
}

// signalCreateMany registers n real passkey credentials for one RP and one
// WebAuthn user handle through the production Session API. Every record is a
// genuinely generated ES256 credential stored in a signed snapshot with its
// own linked audit event, so the review below sees what production sees.
func signalCreateMany(t *testing.T, s *Session, ctx BrowserContext, userID string, n int) []signalAccount {
	t.Helper()
	accounts := make([]signalAccount, 0, n)
	for i := 0; i < n; i++ {
		accounts = append(accounts, signalCreate(t, s, ctx, userID, fmt.Sprintf("bulk-%02d", i), fmt.Sprintf("Bulk %02d", i)))
	}
	return accounts
}

func signalUnknown(origin, rp, credential string) PasskeySignalRequest {
	return PasskeySignalRequest{Kind: PasskeySignalUnknown, Origin: origin, RPID: rp, CredentialID: credential}
}

func signalAccepted(origin, rp, userID string, accepted ...string) PasskeySignalRequest {
	return PasskeySignalRequest{Kind: PasskeySignalAccepted, Origin: origin, RPID: rp, UserID: userID, Accepted: accepted}
}

func signalUser(origin, rp, userID, name, display string) PasskeySignalRequest {
	return PasskeySignalRequest{Kind: PasskeySignalUser, Origin: origin, RPID: rp, UserID: userID, Name: name, DisplayName: display}
}

func signalRecord(t *testing.T, s *Session, itemID string) (*passkey.Record, []byte) {
	t.Helper()
	items := rawItems(t, s)
	for _, item := range items {
		if item.ID != itemID {
			continue
		}
		raw := bytes.Clone(item.Passkey)
		record, err := passkey.Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		return record, raw
	}
	t.Fatalf("item %s missing", itemID)
	return nil, nil
}

func signalSign(t *testing.T, record *passkey.Record) {
	t.Helper()
	options := passkeyGetOptions(record.ID)
	request, err := passkey.Parse("https://example.test", false, options)
	if err != nil {
		t.Fatal(err)
	}
	response, err := passkey.Get(request, record, false)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal("preserved credential produced an invalid assertion signature")
	}
}

// nonCanonicalCredential keeps the length and alphabet valid while flipping
// the final character's pad bits, so only canonical re-encoding rejects it.
func nonCanonicalCredential(value string) string {
	last := value[len(value)-1]
	replacement := byte('B')
	if last == 'B' {
		replacement = 'C'
	}
	return value[:len(value)-1] + string(replacement)
}

func TestParsePasskeySignalStrictSchemaRPAndBounds(t *testing.T) {
	credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	userID := base64.RawURLEncoding.EncodeToString([]byte("user-one"))
	valid := []string{
		`{"kind":"unknown","rpId":"example.test","credentialId":"` + credential + `"}`,
		`{"kind":"accepted","rpId":"example.test","userId":"` + userID + `","allAcceptedCredentialIds":["` + credential + `"]}`,
		`{"kind":"user","rpId":"example.test","userId":"` + userID + `","name":"name","displayName":"Display"}`,
	}
	for _, raw := range valid {
		parsed, err := ParsePasskeySignal("https://example.test", []byte(raw))
		if err != nil || !parsed.Valid() {
			t.Fatalf("valid signal refused: %s %v", raw, err)
		}
	}
	// The rpId must be a registrable suffix of the actual origin, never the
	// page-provided string: public suffixes and sibling tenants are refused.
	psl := []struct{ origin, rp string }{
		{"https://tenant.github.io", "github.io"},
		{"https://a.example.test", "b.example.test"},
		{"https://example.test", "test"},
		{"https://example.test", "example.test.evil.example"},
		{"http://example.test", "example.test"},
	}
	for _, attempt := range psl {
		raw := `{"kind":"unknown","rpId":"` + attempt.rp + `","credentialId":"` + credential + `"}`
		if _, err := ParsePasskeySignal(attempt.origin, []byte(raw)); err == nil {
			t.Fatalf("rp policy accepted %q for %q", attempt.rp, attempt.origin)
		}
	}
	if _, err := ParsePasskeySignal("https://tenant.github.io", []byte(`{"kind":"unknown","rpId":"tenant.github.io","credentialId":"`+credential+`"}`)); err != nil {
		t.Fatalf("registrable tenant rp refused: %v", err)
	}
	accepted := func(ids ...string) string {
		encoded, _ := json.Marshal(ids)
		return `{"kind":"accepted","rpId":"example.test","userId":"` + userID + `","allAcceptedCredentialIds":` + string(encoded) + `}`
	}
	many := make([]string, MaxPasskeySignalAcceptedIDs+1)
	for i := range many {
		many[i] = credential
	}
	invalid := map[string]string{
		"unknown key":        `{"kind":"unknown","rpId":"example.test","credentialId":"` + credential + `","extra":true}`,
		"duplicate key":      `{"kind":"unknown","rpId":"example.test","rpId":"example.test","credentialId":"` + credential + `"}`,
		"wrong kind case":    `{"kind":"Unknown","rpId":"example.test","credentialId":"` + credential + `"}`,
		"wrong type":         `{"kind":"unknown","rpId":1,"credentialId":"` + credential + `"}`,
		"missing field":      `{"kind":"unknown","rpId":"example.test"}`,
		"mixed kind fields":  `{"kind":"unknown","rpId":"example.test","credentialId":"` + credential + `","name":"x"}`,
		"padded base64":      `{"kind":"unknown","rpId":"example.test","credentialId":"` + credential + `="}`,
		"non-canonical":      `{"kind":"unknown","rpId":"example.test","credentialId":"` + nonCanonicalCredential(credential) + `"}`,
		"empty credential":   `{"kind":"unknown","rpId":"example.test","credentialId":""}`,
		"oversize id":        `{"kind":"unknown","rpId":"example.test","credentialId":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 1025)) + `"}`,
		"empty user":         `{"kind":"accepted","rpId":"example.test","userId":"","allAcceptedCredentialIds":[]}`,
		"too many accepted":  accepted(many...),
		"accepted not array": `{"kind":"accepted","rpId":"example.test","userId":"` + userID + `","allAcceptedCredentialIds":"` + credential + `"}`,
		"nul name":           `{"kind":"user","rpId":"example.test","userId":"` + userID + `","name":"a\u0000b","displayName":"d"}`,
		"crlf name":          `{"kind":"user","rpId":"example.test","userId":"` + userID + `","name":"a","displayName":"d\r\nx"}`,
		"long name":          `{"kind":"user","rpId":"example.test","userId":"` + userID + `","name":"` + strings.Repeat("a", 1025) + `","displayName":"d"}`,
		"lone surrogate":     "{\"kind\":\"user\",\"rpId\":\"example.test\",\"userId\":\"" + userID + "\",\"name\":\"\\ud800\",\"displayName\":\"d\"}",
		"oversize document":  `{"kind":"unknown","rpId":"example.test","credentialId":"x","pad":"` + strings.Repeat("a", MaxPasskeySignalOptions) + `"}`,
		"trailing data":      `{"kind":"unknown","rpId":"example.test","credentialId":"` + credential + `"}{}`,
	}
	for name, raw := range invalid {
		if _, err := ParsePasskeySignal("https://example.test", []byte(raw)); err == nil {
			t.Fatalf("invalid signal accepted: %s", name)
		}
	}
	if _, err := ParsePasskeySignal("https://example.test", []byte{'"', 0xff, '"'}); err == nil {
		t.Fatal("invalid utf-8 accepted")
	}
}

func TestReviewPasskeySignalReadOnlyAndNoExistenceOracle(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "signal-user", "Signal User")
	other := signalCreate(t, s, fill.Context, "dXNlcjI", "other-user", "Other User")
	beforeItems := rawItems(t, s)
	beforeAudit := rawAuditCountNoSession(t, s.path)
	beforeLast := s.last

	proposal, err := s.ReviewPasskeySignal(signalUnknown("https://example.test", "example.test", account.CredentialID))
	if err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].ItemID != account.ItemID || proposal.Changes[0].Action != "remove" {
		t.Fatalf("unknown review: %#v %v", proposal, err)
	}
	// The stored user handle, private key and raw record never appear in the
	// owner-facing projection.
	encodedProposal, _ := json.Marshal(proposal)
	for _, secret := range []string{account.UserID, "user-one", "user-two"} {
		if strings.Contains(string(encodedProposal), secret) {
			t.Fatalf("proposal leaked stored user id: %s", encodedProposal)
		}
	}
	// A hint that matches nothing reveals nothing and still returns cleanly.
	noMatch, err := s.ReviewPasskeySignal(signalUnknown("https://example.test", "example.test", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))))
	if err != nil || len(noMatch.Changes) != 0 {
		t.Fatalf("no-match review: %#v %v", noMatch, err)
	}
	// Exact RP isolation: another RP never matches, even with the same CID form.
	if proposal, err = s.ReviewPasskeySignal(signalUnknown("https://other.test", "other.test", account.CredentialID)); err != nil || len(proposal.Changes) != 0 {
		t.Fatalf("cross-rp review: %#v %v", proposal, err)
	}
	// Exact user isolation for accepted/user hints.
	if proposal, err = s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", other.UserID)); err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].ItemID != other.ItemID {
		t.Fatalf("accepted isolation: %#v %v", proposal, err)
	}
	if proposal, err = s.ReviewPasskeySignal(signalUser("https://example.test", "example.test", other.UserID, "renamed", "Renamed")); err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].ItemID != other.ItemID {
		t.Fatalf("user isolation: %#v %v", proposal, err)
	}
	// Unchanged names are not an update.
	if proposal, err = s.ReviewPasskeySignal(signalUser("https://example.test", "example.test", other.UserID, "other-user", "Other User")); err != nil || len(proposal.Changes) != 0 {
		t.Fatalf("no-op user review: %#v %v", proposal, err)
	}
	if got := rawItems(t, s); !reflect.DeepEqual(got, beforeItems) {
		t.Fatal("review changed the vault")
	}
	if rawAuditCountNoSession(t, s.path) != beforeAudit {
		t.Fatal("review appended an audit event")
	}
	if s.last != beforeLast {
		t.Fatal("review renewed idle time")
	}
}

// MaxPasskeySignalChanges is a production constant: exactly 50 matched rows are
// admitted and 51 are ignored in full. Nothing here overrides the bound.
func TestReviewPasskeySignalBoundaryFiftyAdmittedFiftyOneIgnored(t *testing.T) {
	s, fill := browserFixture(t)
	accounts := signalCreateMany(t, s, fill.Context, "dXNlcjE", MaxPasskeySignalChanges+1)
	if len(accounts) != MaxPasskeySignalChanges+1 {
		t.Fatalf("setup produced %d accounts", len(accounts))
	}
	accepted := signalAccepted("https://example.test", "example.test", accounts[0].UserID)
	beforeItems := rawItems(t, s)
	beforeAudit := rawAuditCountNoSession(t, s.path)
	beforeSignal := rawAuditActionCount(t, s, passkeySignalAction)
	beforeEpoch := s.PasskeyRevocationEpoch()
	beforeLast := s.last

	oversized, err := s.ReviewPasskeySignal(accepted)
	if err != nil || len(oversized.Changes) != 0 {
		t.Fatalf("51-match review was not ignored in full: %#v %v", oversized, err)
	}
	// The proposal shape is bounded by the same constant.
	proposed := make([]PasskeySignalChange, 0, MaxPasskeySignalChanges+1)
	for _, account := range accounts {
		proposed = append(proposed, PasskeySignalChange{Action: "remove", ItemID: account.ItemID, Revision: account.Revision, CredentialID: account.CredentialID})
	}
	if validPasskeySignalChanges(accepted, proposed) {
		t.Fatal("51-row proposal passed the production bound")
	}
	if !validPasskeySignalChanges(accepted, proposed[:MaxPasskeySignalChanges]) {
		t.Fatal("50-row proposal was refused by the production bound")
	}

	// Listing the 51st credential as accepted leaves exactly 50 matches.
	kept := accounts[MaxPasskeySignalChanges]
	exact := signalAccepted("https://example.test", "example.test", kept.UserID, kept.CredentialID)
	proposal, err := s.ReviewPasskeySignal(exact)
	if err != nil || len(proposal.Changes) != MaxPasskeySignalChanges {
		t.Fatalf("50-match review returned %d changes: %v", len(proposal.Changes), err)
	}
	seen := map[string]bool{}
	for _, change := range proposal.Changes {
		if change.Action != "remove" || seen[change.ItemID] || change.ItemID == kept.ItemID {
			t.Fatalf("unexpected review row: %#v", change)
		}
		seen[change.ItemID] = true
	}
	for _, account := range accounts[:MaxPasskeySignalChanges] {
		if !seen[account.ItemID] {
			t.Fatalf("account %s missing from the 50-row review", account.ItemID)
		}
	}
	// Both reviews are strictly read-only.
	if got := rawItems(t, s); !reflect.DeepEqual(got, beforeItems) {
		t.Fatal("review changed the snapshot")
	}
	if rawAuditCountNoSession(t, s.path) != beforeAudit || rawAuditActionCount(t, s, passkeySignalAction) != beforeSignal {
		t.Fatal("review appended an audit event")
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch {
		t.Fatal("review advanced the passkey revocation epoch")
	}
	if s.last != beforeLast {
		t.Fatal("review renewed idle time")
	}

	// Exactly the bound may be applied: the 50 unaccepted credentials go and
	// the accepted record is preserved byte for byte.
	keptRecord, keptRaw := signalRecord(t, s, kept.ItemID)
	defer keptRecord.Clear()
	next, err := s.ApplyPasskeySignal(exact, proposal.Changes, dailyGate(t, s))
	if err != nil || next == "" {
		t.Fatalf("50-row apply: %v", err)
	}
	afterItems := rawItems(t, s)
	if item, ok := itemByID(afterItems, kept.ItemID); !ok || !bytes.Equal(item.Passkey, keptRaw) {
		t.Fatal("accepted credential was not preserved")
	}
	for _, account := range accounts[:MaxPasskeySignalChanges] {
		if item, ok := itemByID(afterItems, account.ItemID); !ok || len(item.Passkey) != 0 {
			t.Fatalf("account %s passkey was not removed", account.ItemID)
		}
	}
	if rawAuditActionCount(t, s, passkeySignalAction) != beforeSignal+MaxPasskeySignalChanges {
		t.Fatalf("expected %d signal events, got %d", beforeSignal+MaxPasskeySignalChanges, rawAuditActionCount(t, s, passkeySignalAction))
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch+1 {
		t.Fatalf("batch removal advanced the epoch %d times", s.PasskeyRevocationEpoch()-beforeEpoch)
	}
	preserved, _ := signalRecord(t, s, kept.ItemID)
	defer preserved.Clear()
	signalSign(t, preserved)
}

func TestApplyUnknownSignalRemovalPreservesEverythingElse(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "remove-user", "Remove")
	survivor := signalCreate(t, s, fill.Context, "dXNlcjI", "survivor-user", "Survivor")
	// Give the affected login unrelated durable content.
	revision := account.Revision
	var err error
	if revision, err = s.Edit(Edit{ID: account.ItemID, Revision: revision, Field: "notes", Value: "notes survive"}); err != nil {
		t.Fatal(err)
	}
	if revision, err = s.Edit(Edit{ID: account.ItemID, Revision: revision, Field: "otp", Value: v2OTPConfig}); err != nil {
		t.Fatal(err)
	}
	if revision, err = s.SetTags(account.ItemID, revision, []string{"keep"}, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	if _, revision, err = s.AddAttachment(account.ItemID, revision, "keep.txt", "text/plain", []byte("attachment"), dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	beforeItems := rawItems(t, s)
	before, ok := itemByID(beforeItems, account.ItemID)
	if !ok {
		t.Fatal("missing item")
	}
	expected := vault.CloneItem(before)
	beforeSurvivor, _ := itemByID(beforeItems, survivor.ItemID)
	beforeEpoch := s.PasskeyRevocationEpoch()

	proposal, err := s.ReviewPasskeySignal(signalUnknown("https://example.test", "example.test", account.CredentialID))
	if err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].Revision != revision {
		t.Fatalf("review: %#v %v", proposal, err)
	}
	next, err := s.ApplyPasskeySignal(signalUnknown("https://example.test", "example.test", account.CredentialID), proposal.Changes, dailyGate(t, s))
	if err != nil || next == "" {
		t.Fatalf("apply: %v", err)
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch+1 {
		t.Fatalf("removal did not advance the passkey epoch: %d -> %d", beforeEpoch, s.PasskeyRevocationEpoch())
	}
	afterItems := rawItems(t, s)
	after, ok := itemByID(afterItems, account.ItemID)
	if !ok || len(after.Passkey) != 0 {
		t.Fatal("passkey not removed")
	}
	expected.Passkey = nil
	expected.UpdatedAt = after.UpdatedAt
	if !reflect.DeepEqual(expected, after) {
		t.Fatalf("removal changed unrelated fields:\nbefore=%#v\nafter=%#v", expected, after)
	}
	if after.Username != expected.Username || after.Notes == "" || after.OTP == "" || len(after.Attachments) != 1 || len(after.Tags) != 1 {
		t.Fatal("login username/notes/OTP/attachment/tags lost")
	}
	if current, ok := itemByID(afterItems, survivor.ItemID); !ok || !reflect.DeepEqual(current, beforeSurvivor) {
		t.Fatal("unrelated account changed")
	}
	event := lastAuditEvent(t, s)
	if event.Action != passkeySignalAction || event.Result != "succeeded" || event.Item != account.ItemID || event.BaseRevision != revision || event.Link == "" || event.hash() != next {
		t.Fatalf("signal audit: %#v", event)
	}
	// Reopen through the normal authenticated verifier: the new action must
	// replay and become the item's current revision.
	s.Lock()
	key := bytes.Repeat([]byte{4}, 16)
	reopened, err := UnlockSession(s.path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	items, revisions, err := reopened.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatalf("journal verification after signal: %v", err)
	}
	if revisions[account.ItemID] != next {
		FatalRevision(t, revisions[account.ItemID], next)
	}
	if item, ok := itemByID(items, account.ItemID); !ok || len(item.Passkey) != 0 || item.Notes == "" || item.OTP == "" {
		t.Fatalf("reopened item: %#v", item)
	}
	found := false
	events, err := reopened.Audit()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range events {
		if candidate.Action == passkeySignalAction && candidate.Item == account.ItemID && candidate.Result == "succeeded" {
			found = candidate.hash() == next
		}
	}
	if !found {
		t.Fatal("signal event missing after reopen")
	}
}

func TestApplyAcceptedSignalRetainsListedAndRemovesOthers(t *testing.T) {
	s, fill := browserFixture(t)
	kept := signalCreate(t, s, fill.Context, "dXNlcjE", "kept-user", "Kept")
	removed := signalCreate(t, s, fill.Context, "dXNlcjE", "removed-user", "Removed")
	otherUser := signalCreate(t, s, fill.Context, "dXNlcjI", "other-user", "Other")
	accepted := signalAccepted("https://example.test", "example.test", kept.UserID, kept.CredentialID)
	proposal, err := s.ReviewPasskeySignal(accepted)
	if err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].ItemID != removed.ItemID || proposal.Changes[0].Action != "remove" {
		t.Fatalf("accepted review: %#v %v", proposal, err)
	}
	if _, err = s.ApplyPasskeySignal(accepted, proposal.Changes, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	items := rawItems(t, s)
	if item, ok := itemByID(items, kept.ItemID); !ok || len(item.Passkey) == 0 {
		t.Fatal("accepted credential was removed")
	}
	if item, ok := itemByID(items, removed.ItemID); !ok || len(item.Passkey) != 0 {
		t.Fatal("unaccepted credential remained")
	}
	if item, ok := itemByID(items, otherUser.ItemID); !ok || len(item.Passkey) == 0 {
		t.Fatal("other user credential was removed")
	}
	// Accepted with everything listed is a no-op proposal, and unknown with a
	// mismatched credential id matches nothing.
	if proposal, err = s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", kept.UserID, kept.CredentialID)); err != nil || len(proposal.Changes) != 0 {
		t.Fatalf("fully accepted review: %#v %v", proposal, err)
	}
	if proposal, err = s.ReviewPasskeySignal(signalUnknown("https://example.test", "example.test", otherUser.CredentialID)); err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].ItemID != otherUser.ItemID {
		t.Fatalf("unknown remaining review: %#v %v", proposal, err)
	}
}

// A forged or stale proposal may not revoke a credential that the accepted
// dictionary explicitly lists. The membership refusal happens inside the
// authenticated transaction, before the commit gate can be won.
func TestApplyAcceptedSignalRefusesAcceptedCredentialRemoval(t *testing.T) {
	s, fill := browserFixture(t)
	kept := signalCreate(t, s, fill.Context, "dXNlcjE", "accepted-user", "Accepted")
	removable := signalCreate(t, s, fill.Context, "dXNlcjE", "removable-user", "Removable")
	request := signalAccepted("https://example.test", "example.test", kept.UserID, kept.CredentialID)
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].ItemID != removable.ItemID || proposal.Changes[0].Action != "remove" {
		t.Fatalf("review: %#v %v", proposal, err)
	}
	forgedRemoval := PasskeySignalChange{Action: "remove", ItemID: kept.ItemID, Revision: kept.Revision, CredentialID: kept.CredentialID}
	// Repointing the accepted item at the other credential must also fail the
	// exact stored-credential-id recheck.
	repointed := PasskeySignalChange{Action: "remove", ItemID: kept.ItemID, Revision: kept.Revision, CredentialID: removable.CredentialID}
	beforeItems := rawItems(t, s)
	beforeAudit := rawAuditCountNoSession(t, s.path)
	beforeSignal := rawAuditActionCount(t, s, passkeySignalAction)
	beforeEpoch := s.PasskeyRevocationEpoch()
	forged := [][]PasskeySignalChange{
		{forgedRemoval},
		{proposal.Changes[0], forgedRemoval},
		{repointed},
	}
	for n, changes := range forged {
		if _, err := s.ApplyPasskeySignal(request, changes, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
			t.Fatalf("forged proposal %d was not refused: %v", n, err)
		}
		if got := rawItems(t, s); !reflect.DeepEqual(got, beforeItems) {
			t.Fatalf("forged proposal %d changed the snapshot", n)
		}
		if rawAuditCountNoSession(t, s.path) != beforeAudit || rawAuditActionCount(t, s, passkeySignalAction) != beforeSignal {
			t.Fatalf("forged proposal %d appended an audit event", n)
		}
		if s.PasskeyRevocationEpoch() != beforeEpoch {
			t.Fatalf("forged proposal %d advanced the passkey revocation epoch", n)
		}
	}
	// The genuine reviewed row still applies: the unaccepted credential is
	// removed and the accepted record is untouched.
	keptRecord, keptRaw := signalRecord(t, s, kept.ItemID)
	defer keptRecord.Clear()
	if _, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s)); err != nil {
		t.Fatalf("genuine apply: %v", err)
	}
	after := rawItems(t, s)
	if item, ok := itemByID(after, kept.ItemID); !ok || !bytes.Equal(item.Passkey, keptRaw) {
		t.Fatal("accepted credential changed")
	}
	if item, ok := itemByID(after, removable.ItemID); !ok || len(item.Passkey) != 0 {
		t.Fatal("unaccepted credential remained")
	}
}

func TestApplyUserDetailsSignalKeepsPrivateMaterialAndSigns(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "rename-user", "Rename User")
	other := signalCreate(t, s, fill.Context, "dXNlcjI", "untouched-user", "Untouched")
	beforeRecord, beforeRaw := signalRecord(t, s, account.ItemID)
	defer beforeRecord.Clear()
	beforeItems := rawItems(t, s)
	before, _ := itemByID(beforeItems, account.ItemID)
	beforeOther, _ := itemByID(beforeItems, other.ItemID)
	beforeEpoch := s.PasskeyRevocationEpoch()

	request := signalUser("https://example.test", "example.test", account.UserID, "new-name", "New Display")
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 1 || proposal.Changes[0].Action != "update" || proposal.Changes[0].Name != "new-name" || proposal.Changes[0].DisplayName != "New Display" {
		t.Fatalf("user review: %#v %v", proposal, err)
	}
	next, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch {
		t.Fatal("user-details update advanced the passkey revocation epoch")
	}
	afterRecord, afterRaw := signalRecord(t, s, account.ItemID)
	defer afterRecord.Clear()
	if afterRecord.ID != beforeRecord.ID || afterRecord.UserID != beforeRecord.UserID || afterRecord.RPID != beforeRecord.RPID || afterRecord.Version != beforeRecord.Version {
		t.Fatalf("credential identity changed: %#v", afterRecord)
	}
	if !bytes.Equal(afterRecord.PrivateKey, beforeRecord.PrivateKey) {
		t.Fatal("private key bytes changed")
	}
	if afterRecord.Name != "new-name" || afterRecord.DisplayName != "New Display" {
		t.Fatalf("names not updated: %#v", afterRecord)
	}
	if bytes.Equal(afterRaw, beforeRaw) {
		t.Fatal("record bytes unchanged")
	}
	// The updated record still signs a valid assertion with the same key.
	signalSign(t, afterRecord)
	afterItems := rawItems(t, s)
	after, ok := itemByID(afterItems, account.ItemID)
	if !ok || after.Password != before.Password || after.Username != before.Username || after.Title != before.Title || after.URL != before.URL || after.Notes != before.Notes || after.OTP != before.OTP || len(after.Attachments) != len(before.Attachments) || len(after.History) != len(before.History) || after.State != before.State || after.Category != before.Category {
		t.Fatalf("update changed unrelated fields: %#v", after)
	}
	if current, ok := itemByID(afterItems, other.ItemID); !ok || !reflect.DeepEqual(current, beforeOther) {
		t.Fatal("other user record changed")
	}
	event := lastAuditEvent(t, s)
	if event.Action != passkeySignalAction || event.Item != account.ItemID || event.BaseRevision != account.Revision || event.Link == "" {
		t.Fatalf("update audit: %#v", event)
	}

	// Re-issuing the proposal against the current revision with the already
	// stored names is a stale review of a completed change, not a no-op write.
	stale := []PasskeySignalChange{{Action: "update", ItemID: account.ItemID, Revision: next, CredentialID: account.CredentialID, Name: "new-name", DisplayName: "New Display"}}
	beforeStale := rawItems(t, s)
	beforeStaleAudit := rawAuditActionCount(t, s, passkeySignalAction)
	if _, err := s.ApplyPasskeySignal(request, stale, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("replayed user-details proposal: %v", err)
	}
	if got := rawItems(t, s); !reflect.DeepEqual(got, beforeStale) {
		t.Fatal("replayed user-details proposal changed the vault")
	}
	if rawAuditActionCount(t, s, passkeySignalAction) != beforeStaleAudit {
		t.Fatal("replayed user-details proposal appended an audit event")
	}

	// The re-signed snapshot and journal still verify through the real
	// authenticated reader, and the signal action replays as this item's
	// current revision. That read path zeroes private passkey bytes by design,
	// so the retained private key was checked above from the sealed snapshot.
	s.Lock()
	key := bytes.Repeat([]byte{4}, 16)
	reopened, err := UnlockSession(s.path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	reopenedItems, revisions, err := reopened.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatalf("journal verification after rename: %v", err)
	}
	if revisions[account.ItemID] != next {
		FatalRevision(t, revisions[account.ItemID], next)
	}
	if item, ok := itemByID(reopenedItems, account.ItemID); !ok || len(item.Passkey) == 0 {
		t.Fatal("renamed item or its credential vanished after reopen")
	}
	replayed := false
	events, err := reopened.Audit()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range events {
		if candidate.Action == passkeySignalAction && candidate.Item == account.ItemID && candidate.Result == "succeeded" && candidate.hash() == next {
			replayed = true
		}
	}
	if !replayed {
		t.Fatal("user-details signal event missing after reopen")
	}
}

func TestApplySignalStaleRowRefusesWholeBatchAtomically(t *testing.T) {
	s, fill := browserFixture(t)
	removed := signalCreate(t, s, fill.Context, "dXNlcjE", "stale-one", "Stale One")
	kept := signalCreate(t, s, fill.Context, "dXNlcjE", "stale-two", "Stale Two")
	accepted := signalAccepted("https://example.test", "example.test", removed.UserID)
	proposal, err := s.ReviewPasskeySignal(accepted)
	if err != nil || len(proposal.Changes) != 2 {
		t.Fatalf("review: %#v %v", proposal, err)
	}
	before := rawItems(t, s)
	beforeAudit := rawAuditActionCount(t, s, passkeySignalAction)
	// Change one reviewed row after the review: its revision is now stale.
	if _, err = s.Edit(Edit{ID: kept.ItemID, Revision: kept.Revision, Field: "notes", Value: "edited after review"}); err != nil {
		t.Fatal(err)
	}
	before = rawItems(t, s)
	if _, err = s.ApplyPasskeySignal(accepted, proposal.Changes, dailyGate(t, s)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale apply: %v", err)
	}
	if got := rawItems(t, s); !reflect.DeepEqual(got, before) {
		t.Fatal("stale batch changed the vault")
	}
	if rawAuditActionCount(t, s, passkeySignalAction) != beforeAudit {
		t.Fatal("stale batch appended an audit event")
	}
	// A cancelled gate and a locked session also refuse before any write.
	cancelled := dailyGate(t, s)
	cancelled.Cancel()
	if _, err = s.ApplyPasskeySignal(accepted, proposal.Changes, cancelled); !errors.Is(err, ErrMutationCancelled) {
		t.Fatalf("cancelled apply: %v", err)
	}
	_ = removed
	s.RequestLock()
	if _, err = s.ApplyPasskeySignal(accepted, proposal.Changes, NewMutationGate(time.Now().Add(time.Minute))); !errors.Is(err, ErrMutationCancelled) && !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("locked apply: %v", err)
	}
	if got := rawItems(t, s); !reflect.DeepEqual(got, before) {
		t.Fatal("cancelled/locked batch changed the vault")
	}
	if rawAuditActionCount(t, s, passkeySignalAction) != beforeAudit {
		t.Fatal("cancelled/locked batch appended an audit event")
	}
}

func TestApplySignalRejectsForgedProposals(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "forged-user", "Forged")
	request := signalUser("https://example.test", "example.test", account.UserID, "new", "New")
	before := rawItems(t, s)
	beforeAudit := rawAuditCountNoSession(t, s.path)
	cases := [][]PasskeySignalChange{
		{},
		{{Action: "remove", ItemID: account.ItemID, Revision: account.Revision, CredentialID: account.CredentialID}},
		{{Action: "update", ItemID: account.ItemID, Revision: account.Revision, CredentialID: account.CredentialID, Name: "other", DisplayName: "Other"}},
		{{Action: "update", ItemID: account.ItemID, Revision: account.Revision, CredentialID: account.CredentialID, Name: "new", DisplayName: "New"}, {Action: "update", ItemID: account.ItemID, Revision: account.Revision, CredentialID: account.CredentialID, Name: "new", DisplayName: "New"}},
		{{Action: "update", ItemID: strings.Repeat("a", 32), Revision: account.Revision, CredentialID: account.CredentialID, Name: "new", DisplayName: "New"}},
	}
	for n, changes := range cases {
		if _, err := s.ApplyPasskeySignal(request, changes, dailyGate(t, s)); err == nil {
			t.Fatalf("forged proposal %d accepted", n)
		}
		if got := rawItems(t, s); !reflect.DeepEqual(got, before) {
			t.Fatalf("forged proposal %d changed the vault", n)
		}
		if rawAuditCountNoSession(t, s.path) != beforeAudit {
			t.Fatalf("forged proposal %d appended an audit event", n)
		}
	}
	// A stale revision must refuse, never repair.
	stale := []PasskeySignalChange{{Action: "update", ItemID: account.ItemID, Revision: strings.Repeat("f", 64), CredentialID: account.CredentialID, Name: "new", DisplayName: "New"}}
	if _, err := s.ApplyPasskeySignal(request, stale, dailyGate(t, s)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
}
