package personal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
)

// signalAttachCredentials registers n additional real ES256 credentials for one
// existing login through the production creation path. The result is a single
// durable login owning several credentials of the same RP and WebAuthn user.
func signalAttachCredentials(t *testing.T, s *Session, ctx BrowserContext, account signalAccount, n int) []string {
	t.Helper()
	ids := []string{account.CredentialID}
	for i := 0; i < n; i++ {
		options := []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"` + account.UserID + `","name":"attached-` + strconv.Itoa(i) + `","displayName":"Attached"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)
		response, err := s.PerformPasskey(PasskeyTarget{Context: ctx, Create: true, ID: account.ItemID, Revision: suggestionsRevision(t, s, account.ItemID), Options: options}, false, dailyGate(t, s))
		if err != nil {
			t.Fatalf("attach credential %d: %v", i, err)
		}
		ids = append(ids, response.ID)
	}
	return ids
}

// signalEventsFor returns the committed signal events of exactly one login in
// journal order so a test can assert the predecessor chain of a multi-row batch.
func signalEventsFor(t *testing.T, s *Session, itemID string) []Event {
	t.Helper()
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	var rows []Event
	for _, event := range events {
		if event.Action == passkeySignalAction && event.Item == itemID {
			rows = append(rows, event)
		}
	}
	return rows
}

// signalCredentialKeys records the identity and private key bytes of every
// credential of one login so an update can be proven to keep them intact.
func signalCredentialKeys(t *testing.T, s *Session, itemID string) map[string]struct {
	RPID, UserID string
	Key          []byte
} {
	t.Helper()
	items := rawItems(t, s)
	deferClearPasskeys(t, items)
	item, ok := itemByID(items, itemID)
	if !ok {
		t.Fatalf("item %s missing", itemID)
	}
	out := map[string]struct {
		RPID, UserID string
		Key          []byte
	}{}
	for _, raw := range item.PasskeyRecords() {
		record, err := passkey.Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		out[record.ID] = struct {
			RPID, UserID string
			Key          []byte
		}{record.RPID, record.UserID, bytes.Clone(record.PrivateKey)}
		record.Clear()
	}
	return out
}

// signalSyntheticCredential builds a canonical 32-byte credential selector that
// is unique per seed and deliberately never stored in the vault.
func signalSyntheticCredential(seed int) string {
	raw := make([]byte, 32)
	raw[0], raw[1], raw[2] = 0x5a, byte(seed>>8), byte(seed)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// One signal hint over a login that owns several credentials yields exactly one
// review row per affected credential, ordered by item id then credential id.
func TestReviewSignalOneRowPerAffectedCredential(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "multi-review", "Multi Review")
	ids := signalAttachCredentials(t, s, fill.Context, account, 2)
	if len(ids) != 3 {
		t.Fatalf("login stored %d credentials, want 3", len(ids))
	}
	sibling := signalCreate(t, s, fill.Context, "dXNlcjI", "review-sibling", "Sibling")
	revision := suggestionsRevision(t, s, account.ItemID)

	proposal, err := s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", account.UserID, ids[0]))
	if err != nil || len(proposal.Changes) != 2 {
		t.Fatalf("multi-credential review: %#v %v", proposal, err)
	}
	want := map[string]bool{ids[1]: true, ids[2]: true}
	for _, change := range proposal.Changes {
		if change.ItemID != account.ItemID || change.Revision != revision || change.Action != "remove" || !want[change.CredentialID] || change.ItemID == sibling.ItemID {
			t.Fatalf("unexpected review row: %#v", change)
		}
		delete(want, change.CredentialID)
	}
	if len(want) != 0 {
		t.Fatalf("review missed credentials: %v", want)
	}
	if proposal.Changes[0].CredentialID >= proposal.Changes[1].CredentialID {
		t.Fatalf("credential order is not deterministic: %q >= %q", proposal.Changes[0].CredentialID, proposal.Changes[1].CredentialID)
	}
	// Listing every credential is a no-op; the other user's login never matches.
	if noop, err := s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", account.UserID, ids...)); err != nil || len(noop.Changes) != 0 {
		t.Fatalf("fully accepted review: %#v %v", noop, err)
	}
	if other, err := s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", sibling.UserID, sibling.CredentialID)); err != nil || len(other.Changes) != 0 {
		t.Fatalf("sibling review: %#v %v", other, err)
	}
	// A user-details hint renames every credential of the same user handle.
	rename := signalUser("https://example.test", "example.test", account.UserID, "renamed", "Renamed")
	updates, err := s.ReviewPasskeySignal(rename)
	if err != nil || len(updates.Changes) != 3 {
		t.Fatalf("rename review returned %d rows: %v", len(updates.Changes), err)
	}
	for _, change := range updates.Changes {
		if change.Action != "update" || change.Name != "renamed" || change.DisplayName != "Renamed" || change.ItemID != account.ItemID {
			t.Fatalf("unexpected rename row: %#v", change)
		}
	}
}

// Two reviewed rows of one login must chain: the first event names the reviewed
// parent revision, the second names the first event. Cold replay from a fresh
// session then folds both events without ordering ambiguity.
func TestApplySignalSameLoginTwoUpdatesChainsRevisionsAndColdReplays(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "multi-update", "Multi Update")
	if ids := signalAttachCredentials(t, s, fill.Context, account, 1); len(ids) != 2 {
		t.Fatalf("login stored %d credentials, want 2", len(ids))
	}
	parent := suggestionsRevision(t, s, account.ItemID)
	before := signalCredentialKeys(t, s, account.ItemID)
	beforeEpoch := s.PasskeyRevocationEpoch()
	beforeEvents := len(signalEventsFor(t, s, account.ItemID))

	request := signalUser("https://example.test", "example.test", account.UserID, "renamed", "Renamed")
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 2 {
		t.Fatalf("rename review: %#v %v", proposal, err)
	}
	next, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s))
	if err != nil || next == "" {
		t.Fatalf("rename apply: %v", err)
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch {
		t.Fatal("user-details update advanced the passkey revocation epoch")
	}
	events := signalEventsFor(t, s, account.ItemID)
	if len(events) != beforeEvents+2 {
		t.Fatalf("expected %d signal events, got %d", beforeEvents+2, len(events))
	}
	first, second := events[len(events)-2], events[len(events)-1]
	if first.BaseRevision != parent {
		t.Fatalf("first event base %q, want reviewed parent %q", first.BaseRevision, parent)
	}
	if second.BaseRevision != first.hash() {
		t.Fatalf("second event base %q, want first event %q", second.BaseRevision, first.hash())
	}
	if next != second.hash() {
		t.Fatalf("returned revision %q, want last event %q", next, second.hash())
	}

	items := rawItems(t, s)
	deferClearPasskeys(t, items)
	item, ok := itemByID(items, account.ItemID)
	if !ok {
		t.Fatal("login vanished")
	}
	records := item.PasskeyRecords()
	if len(records) != 2 || len(item.Passkeys) != 2 || len(item.Passkey) != 0 {
		t.Fatalf("layout after two updates: records=%d collection=%d legacy=%d", len(records), len(item.Passkeys), len(item.Passkey))
	}
	seen := map[string]bool{}
	for _, raw := range records {
		record, err := passkey.Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		key, stored := before[record.ID]
		if !stored {
			record.Clear()
			t.Fatalf("credential %s is not one of the stored ones", record.ID)
		}
		if record.Name != "renamed" || record.DisplayName != "Renamed" {
			record.Clear()
			t.Fatalf("credential %s names not updated: %q/%q", record.ID, record.Name, record.DisplayName)
		}
		if record.RPID != key.RPID || record.UserID != key.UserID || !bytes.Equal(record.PrivateKey, key.Key) {
			record.Clear()
			t.Fatalf("credential %s identity or private key changed", record.ID)
		}
		seen[record.ID] = true
		record.Clear()
	}
	if len(seen) != len(before) {
		t.Fatalf("updated %d credentials, want %d", len(seen), len(before))
	}

	s.Lock()
	reopened, err := UnlockSession(s.path, []byte("fixture"), bytes.Repeat([]byte{4}, 16), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	if _, revisions, err := reopened.ReadAuthenticatedItems(false); err != nil {
		t.Fatalf("journal verification after two same-login events: %v", err)
	} else if revisions[account.ItemID] != next {
		FatalRevision(t, revisions[account.ItemID], next)
	}
	replayed := rawItems(t, reopened)
	deferClearPasskeys(t, replayed)
	item, ok = itemByID(replayed, account.ItemID)
	if !ok || len(item.PasskeyRecords()) != 2 {
		t.Fatalf("credentials after cold replay: %d", len(item.PasskeyRecords()))
	}
	for _, raw := range item.PasskeyRecords() {
		record, err := passkey.Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		if record.Name != "renamed" || record.DisplayName != "Renamed" {
			record.Clear()
			t.Fatal("cold replay lost the rename")
		}
		record.Clear()
	}
}

// A page that still lists one credential must lose only the unlisted siblings of
// that login. The listed record is preserved byte for byte and the login keeps
// the versioned collection form for its one remaining credential.
func TestApplySignalUnacceptedCredentialsRemovedAcceptedSiblingKept(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "multi-keep", "Multi Keep")
	ids := signalAttachCredentials(t, s, fill.Context, account, 2)
	items := rawItems(t, s)
	deferClearPasskeys(t, items)
	before, ok := itemByID(items, account.ItemID)
	if !ok || len(before.PasskeyRecords()) != 3 {
		t.Fatalf("fixture login: %#v", before.PasskeyRecords())
	}
	keptRaw := passkeyRecord(t, s, account.ItemID, ids[0])
	defer clear(keptRaw)
	parent := suggestionsRevision(t, s, account.ItemID)
	beforeEpoch := s.PasskeyRevocationEpoch()

	request := signalAccepted("https://example.test", "example.test", account.UserID, ids[0])
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 2 {
		t.Fatalf("accepted review: %#v %v", proposal, err)
	}
	next, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s))
	if err != nil || next == "" {
		t.Fatalf("accepted apply: %v", err)
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch+1 {
		t.Fatalf("batch removal advanced the epoch %d times", s.PasskeyRevocationEpoch()-beforeEpoch)
	}
	items = rawItems(t, s)
	deferClearPasskeys(t, items)
	after, ok := itemByID(items, account.ItemID)
	if !ok {
		t.Fatal("login vanished")
	}
	records := after.PasskeyRecords()
	if len(records) != 1 || len(after.Passkeys) != 1 || len(after.Passkey) != 0 {
		t.Fatalf("sibling layout: records=%d collection=%d legacy=%d", len(records), len(after.Passkeys), len(after.Passkey))
	}
	if !bytes.Equal(records[0], keptRaw) {
		t.Fatal("accepted credential bytes changed")
	}
	if after.Password != before.Password || after.Username != before.Username || after.Title != before.Title || after.URL != before.URL {
		t.Fatal("removal changed unrelated login fields")
	}
	events := signalEventsFor(t, s, account.ItemID)
	if len(events) != 2 || events[0].BaseRevision != parent || events[1].BaseRevision != events[0].hash() || next != events[1].hash() {
		t.Fatalf("event chain: %#v", events)
	}
}

// Removing every credential of one login clears both persisted passkey forms and
// keeps the login itself, while the two chained events still replay cold.
func TestApplySignalRemovingEveryCredentialClearsBothForms(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "multi-clear", "Multi Clear")
	signalAttachCredentials(t, s, fill.Context, account, 1)
	request := signalAccepted("https://example.test", "example.test", account.UserID)
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 2 {
		t.Fatalf("all-remove review: %#v %v", proposal, err)
	}
	next, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s))
	if err != nil || next == "" {
		t.Fatalf("all-remove apply: %v", err)
	}
	items := rawItems(t, s)
	deferClearPasskeys(t, items)
	item, ok := itemByID(items, account.ItemID)
	if !ok {
		t.Fatal("login vanished when its last credential was removed")
	}
	if len(item.PasskeyRecords()) != 0 || len(item.Passkey) != 0 || len(item.Passkeys) != 0 {
		t.Fatalf("both forms must be cleared: legacy=%d collection=%d", len(item.Passkey), len(item.Passkeys))
	}
	if item.Title == "" || item.Username == "" || item.Kind != "login" || item.State != "" {
		t.Fatalf("login damaged by last removal: %#v", item)
	}
	events := signalEventsFor(t, s, account.ItemID)
	if len(events) != 2 || events[1].BaseRevision != events[0].hash() || next != events[1].hash() {
		t.Fatalf("event chain after last removal: %#v", events)
	}
	s.Lock()
	reopened, err := UnlockSession(s.path, []byte("fixture"), bytes.Repeat([]byte{4}, 16), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	if _, revisions, err := reopened.ReadAuthenticatedItems(false); err != nil {
		t.Fatalf("journal verification after two removals: %v", err)
	} else if revisions[account.ItemID] != next {
		FatalRevision(t, revisions[account.ItemID], next)
	}
}

// A proposal may name several credentials of one login but never the same
// (item, credential) pair twice, and its 50-row bound counts credentials rather
// than parent logins.
func TestSignalChangesBoundAndCredentialPairUniqueness(t *testing.T) {
	itemA, itemB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	revision := strings.Repeat("c", 64)
	rows := func(items []string, per int) []PasskeySignalChange {
		out := make([]PasskeySignalChange, 0, len(items)*per)
		seed := 0
		for _, id := range items {
			for i := 0; i < per; i++ {
				out = append(out, PasskeySignalChange{Action: "remove", ItemID: id, Revision: revision, CredentialID: signalSyntheticCredential(seed)})
				seed++
			}
		}
		return out
	}
	request := signalAccepted("https://example.test", "example.test", "dXNlcjE")
	if !validPasskeySignalChanges(request, rows([]string{itemA, itemB}, 25)) {
		t.Fatal("50 credential rows across two parents were refused")
	}
	if validPasskeySignalChanges(request, rows([]string{itemA, itemB}, 26)) {
		t.Fatal("51 credential rows were admitted")
	}
	pair := rows([]string{itemA}, 2)
	if !validPasskeySignalChanges(request, pair) {
		t.Fatal("two credentials of one login were refused")
	}
	if validPasskeySignalChanges(request, []PasskeySignalChange{pair[0], pair[0]}) {
		t.Fatal("duplicate (item, credential) pair admitted")
	}
	if validPasskeySignalChanges(request, []PasskeySignalChange{pair[0], {Action: "remove", ItemID: pair[0].ItemID, Revision: strings.Repeat("d", 64), CredentialID: pair[0].CredentialID}}) {
		t.Fatal("duplicate pair with a different revision admitted")
	}

	// The same refusal happens in the real apply path, before any write.
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "multi-pair", "Multi Pair")
	signalAttachCredentials(t, s, fill.Context, account, 1)
	applied := signalAccepted("https://example.test", "example.test", account.UserID)
	review, err := s.ReviewPasskeySignal(applied)
	if err != nil || len(review.Changes) != 2 {
		t.Fatalf("pair review: %#v %v", review, err)
	}
	before := rawItems(t, s)
	deferClearPasskeys(t, before)
	beforeAudit := rawAuditActionCount(t, s, passkeySignalAction)
	beforeEpoch := s.PasskeyRevocationEpoch()
	forged := [][]PasskeySignalChange{
		{review.Changes[0], review.Changes[0]},
		{review.Changes[0], {Action: "remove", ItemID: review.Changes[0].ItemID, Revision: strings.Repeat("e", 64), CredentialID: review.Changes[0].CredentialID}},
	}
	for n, changes := range forged {
		if _, err := s.ApplyPasskeySignal(applied, changes, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
			t.Fatalf("forged pair batch %d: %v", n, err)
		}
		got := rawItems(t, s)
		if !reflect.DeepEqual(got, before) {
			t.Fatal("forged pair batch changed the vault")
		}
		deferClearPasskeys(t, got)
		if rawAuditActionCount(t, s, passkeySignalAction) != beforeAudit || s.PasskeyRevocationEpoch() != beforeEpoch {
			t.Fatalf("forged pair batch %d advanced audit or epoch", n)
		}
	}
}

// One stale row of a batch refuses every sibling row of the same parent, and the
// whole batch stays unwritten.
func TestApplySignalStaleParentRollsBackEverySiblingRow(t *testing.T) {
	s, fill := browserFixture(t)
	first := signalCreate(t, s, fill.Context, "dXNlcjE", "stale-multi-a", "Stale Multi A")
	signalAttachCredentials(t, s, fill.Context, first, 1)
	second := signalCreate(t, s, fill.Context, "dXNlcjE", "stale-multi-b", "Stale Multi B")
	request := signalAccepted("https://example.test", "example.test", first.UserID)
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 3 {
		t.Fatalf("stale review: %#v %v", proposal, err)
	}
	// Edit the single-credential login after the review: only its row is stale,
	// while the two rows of the other login are still fresh.
	if _, err := s.Edit(Edit{ID: second.ItemID, Revision: second.Revision, Field: "notes", Value: "edited after review"}); err != nil {
		t.Fatal(err)
	}
	before := rawItems(t, s)
	deferClearPasskeys(t, before)
	beforeAudit := rawAuditActionCount(t, s, passkeySignalAction)
	beforeEpoch := s.PasskeyRevocationEpoch()
	if _, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale sibling batch: %v", err)
	}
	got := rawItems(t, s)
	deferClearPasskeys(t, got)
	if !reflect.DeepEqual(got, before) {
		t.Fatal("stale sibling batch changed the vault")
	}
	if rawAuditActionCount(t, s, passkeySignalAction) != beforeAudit {
		t.Fatal("stale sibling batch appended an audit event")
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch {
		t.Fatal("stale sibling batch advanced the passkey epoch")
	}
	item, ok := itemByID(got, first.ItemID)
	if !ok || len(item.PasskeyRecords()) != 2 {
		t.Fatalf("fresh login lost credentials: %d", len(item.PasskeyRecords()))
	}
	// A fresh review of the same hint still applies every credential.
	proposal, err = s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 3 {
		t.Fatalf("re-review: %#v %v", proposal, err)
	}
	if _, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s)); err != nil {
		t.Fatalf("fresh multi batch: %v", err)
	}
	after := rawItems(t, s)
	deferClearPasskeys(t, after)
	for _, id := range []string{first.ItemID, second.ItemID} {
		item, ok := itemByID(after, id)
		if !ok || len(item.PasskeyRecords()) != 0 {
			t.Fatalf("login %s kept credentials", id)
		}
	}
}

// A row must still name a credential the login really stores and the same
// predicate must still select it; anything else refuses before the commit gate,
// so no sibling row of the batch can be written.
func TestApplySignalForgedCredentialSelectorRefused(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "forged-multi-a", "Forged Multi A")
	signalAttachCredentials(t, s, fill.Context, account, 1)
	other := signalCreate(t, s, fill.Context, "dXNlcjE", "forged-multi-b", "Forged Multi B")
	request := signalAccepted("https://example.test", "example.test", account.UserID)
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 3 {
		t.Fatalf("forged review: %#v %v", proposal, err)
	}
	var accountRow, otherRow PasskeySignalChange
	for _, change := range proposal.Changes {
		if change.ItemID == account.ItemID {
			accountRow = change
		} else {
			otherRow = change
		}
	}
	// Remove exactly one reviewed credential through the ordinary path: its row
	// is now stale in the credential sense while the item revision also moved.
	if _, err := s.RemovePasskey(account.ItemID, accountRow.Revision, accountRow.CredentialID, dailyGate(t, s)); err != nil {
		t.Fatalf("ordinary removal: %v", err)
	}
	current := suggestionsRevision(t, s, account.ItemID)
	foreign := PasskeySignalChange{Action: "remove", ItemID: account.ItemID, Revision: current, CredentialID: other.CredentialID}
	gone := PasskeySignalChange{Action: "remove", ItemID: account.ItemID, Revision: current, CredentialID: accountRow.CredentialID}
	before := rawItems(t, s)
	deferClearPasskeys(t, before)
	beforeAudit := rawAuditActionCount(t, s, passkeySignalAction)
	beforeEpoch := s.PasskeyRevocationEpoch()
	for n, changes := range [][]PasskeySignalChange{{foreign}, {otherRow, foreign}, {gone}} {
		if _, err := s.ApplyPasskeySignal(request, changes, dailyGate(t, s)); err == nil {
			t.Fatalf("forged selector batch %d accepted", n)
		}
		got := rawItems(t, s)
		if !reflect.DeepEqual(got, before) {
			t.Fatalf("forged selector batch %d changed the vault", n)
		}
		deferClearPasskeys(t, got)
		if rawAuditActionCount(t, s, passkeySignalAction) != beforeAudit || s.PasskeyRevocationEpoch() != beforeEpoch {
			t.Fatalf("forged selector batch %d advanced audit or epoch", n)
		}
	}
	if item, ok := itemByID(before, other.ItemID); !ok || len(item.PasskeyRecords()) != 1 {
		t.Fatal("untouched sibling login was damaged")
	}
}

// The review bound counts affected credentials, not parent logins: 51 matching
// credentials spread over only four logins are still ignored in full, and the
// admitted 50-row batch applies one credential at a time and replays cold.
func TestReviewSignalBoundCountsCredentialsNotParents(t *testing.T) {
	s, fill := browserFixture(t)
	const parents, each = 4, 13
	accounts := make([]signalAccount, 0, parents)
	creds := make([]string, 0, parents*each)
	for i := 0; i < parents; i++ {
		account := signalCreate(t, s, fill.Context, "dXNlcjE", fmt.Sprintf("bound-cred-%02d", i), fmt.Sprintf("Bound Cred %02d", i))
		accounts = append(accounts, account)
		creds = append(creds, signalAttachCredentials(t, s, fill.Context, account, each-1)...)
	}
	if len(creds) != parents*each {
		t.Fatalf("fixture produced %d credentials", len(creds))
	}
	user := accounts[0].UserID
	if all, err := s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", user)); err != nil || len(all.Changes) != 0 {
		t.Fatalf("52-match review was not ignored in full: %#v %v", all, err)
	}
	if one, err := s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", user, creds[0])); err != nil || len(one.Changes) != 0 {
		t.Fatalf("51-match review was not ignored in full: %#v %v", one, err)
	}
	request := signalAccepted("https://example.test", "example.test", user, creds[0], creds[1])
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != MaxPasskeySignalChanges {
		t.Fatalf("50-match review returned %d changes: %v", len(proposal.Changes), err)
	}
	touched := map[string]bool{}
	for _, change := range proposal.Changes {
		touched[change.ItemID] = true
	}
	if len(touched) >= len(proposal.Changes) || len(touched) > parents {
		t.Fatalf("bound fixture is not credential-level: %d rows over %d parents", len(proposal.Changes), len(touched))
	}
	beforeEpoch := s.PasskeyRevocationEpoch()
	beforeSignal := rawAuditActionCount(t, s, passkeySignalAction)
	if next, err := s.ApplyPasskeySignal(request, proposal.Changes, dailyGate(t, s)); err != nil || next == "" {
		t.Fatalf("50-row multi-parent apply: %v", err)
	}
	if got := rawAuditActionCount(t, s, passkeySignalAction) - beforeSignal; got != MaxPasskeySignalChanges {
		t.Fatalf("expected %d signal events, got %d", MaxPasskeySignalChanges, got)
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch+1 {
		t.Fatalf("batch removal advanced the epoch %d times", s.PasskeyRevocationEpoch()-beforeEpoch)
	}
	items := rawItems(t, s)
	deferClearPasskeys(t, items)
	for i, account := range accounts {
		item, ok := itemByID(items, account.ItemID)
		if !ok {
			t.Fatalf("login %d vanished", i)
		}
		want := 0
		if i == 0 {
			want = 2 // both accepted credentials belong to the first login
		}
		if len(item.PasskeyRecords()) != want {
			t.Fatalf("login %d kept %d credentials, want %d", i, len(item.PasskeyRecords()), want)
		}
	}
	last := map[string]string{}
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == passkeySignalAction {
			last[event.Item] = event.hash()
		}
	}
	s.Lock()
	reopened, err := UnlockSession(s.path, []byte("fixture"), bytes.Repeat([]byte{4}, 16), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	_, revisions, err := reopened.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatalf("journal verification after 50 credential rows: %v", err)
	}
	for id := range touched {
		if revisions[id] != last[id] {
			FatalRevision(t, revisions[id], last[id])
		}
	}
}
