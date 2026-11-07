package personal

import (
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/passkey"
)

func suggestionsRevision(t *testing.T, s *Session, id string) string {
	t.Helper()
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == id {
			return row.Revision
		}
	}
	t.Fatal("item missing")
	return ""
}

func suggestionsCreate(userID, name string) []byte {
	return []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"` + userID + `","name":"` + name + `","displayName":"` + name + ` display"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)
}

func TestConditionalPasskeyCandidatesMetadataOnlyAndReadOnly(t *testing.T) {
	s, target, created := removeFixture(t)
	revision := suggestionsRevision(t, s, target.ID)
	last := s.last
	epoch := s.PasskeyRevocationEpoch()
	before, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	// The audited read above touches idle and journal, so the read-only
	// baseline is captured after every setup/observer call.
	last = s.last
	auditCount := len(before)
	candidates, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(created.ID)})
	if e != nil {
		t.Fatal(e)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates: %d", len(candidates))
	}
	candidate := candidates[0]
	if candidate.ItemID != target.ID || candidate.Revision != revision || candidate.CredentialID != created.ID ||
		candidate.RPID != "example.test" || candidate.UserName != "passkey-fixture-user" || candidate.DisplayName != "Fixture" {
		t.Fatalf("wrong metadata: %+v", candidate)
	}
	if s.last != last {
		t.Fatal("conditional listing renewed idle authority")
	}
	if s.PasskeyRevocationEpoch() != epoch {
		t.Fatal("conditional listing advanced the passkey epoch")
	}
	s.saveMu.Lock()
	gate := s.saveGate
	s.saveMu.Unlock()
	if gate != nil {
		t.Fatal("conditional listing reserved a mutation gate")
	}
	after, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	// Audit() itself appends exactly one disclosure event; nothing else changed.
	if len(after) != auditCount+1 || after[len(after)-1].Action != "audit.list" {
		t.Fatal("conditional listing appended a journal event")
	}
	for n := range before {
		if after[n].hash() != before[n].hash() {
			t.Fatal("conditional listing changed an existing journal event")
		}
	}
	if suggestionsRevision(t, s, target.ID) != revision {
		t.Fatal("conditional listing mutated the item")
	}
}

func TestConditionalPasskeyCandidatesRespectSiteAllowlistAndState(t *testing.T) {
	s, target, created := removeFixture(t)
	other := target.Context
	other.Origin = "https://other.test"
	cross, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: other, Options: []byte(`{"rpId":"other.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}`)})
	if e != nil || len(cross) != 0 {
		t.Fatalf("cross-site candidates: %v %d", e, len(cross))
	}
	foreign := strings.Repeat("A", 43)
	if passkey.ValidCredentialID(foreign) != true {
		t.Fatal("fixture foreign id is not a valid credential selector")
	}
	wrong, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","allowCredentials":[{"type":"public-key","id":"` + foreign + `"}]}`)})
	if e != nil || len(wrong) != 0 {
		t.Fatalf("foreign allowlist candidates: %v %d", e, len(wrong))
	}
	right, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(created.ID)})
	if e != nil || len(right) != 1 {
		t.Fatalf("matching allowlist candidates: %v %d", e, len(right))
	}
	// Creation is refused: conditional enumeration is a read-only assertion path.
	if _, e = s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Create: true, Options: suggestionsCreate("dXNlcjE", "alice")}); e == nil {
		t.Fatal("conditional listing accepted a creation target")
	}
	// A pinned selector is refused here; selection belongs to the get flow.
	if _, e = s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, ID: target.ID, Revision: suggestionsRevision(t, s, target.ID), Options: passkeyGetOptions(created.ID)}); e == nil {
		t.Fatal("conditional listing accepted a pinned selector")
	}
	// An RP the page cannot claim is refused by the existing RP policy.
	if _, e = s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: []byte(`{"rpId":"evil.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}`)}); e == nil {
		t.Fatal("conditional listing accepted a foreign RP")
	}
	// Archived and trashed logins are excluded.
	revision := suggestionsRevision(t, s, target.ID)
	if revision, e = s.SetState(target.ID, revision, "item.archive"); e != nil {
		t.Fatal(e)
	}
	if got, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(created.ID)}); e != nil || len(got) != 0 {
		t.Fatalf("archived candidate: %v %d", e, len(got))
	}
	if revision, e = s.SetState(target.ID, revision, "item.trash"); e != nil {
		t.Fatal(e)
	}
	if got, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(created.ID)}); e != nil || len(got) != 0 {
		t.Fatalf("trashed candidate: %v %d", e, len(got))
	}
}

func TestConditionalPasskeyCandidatesStableOrder(t *testing.T) {
	s, target, _ := removeFixture(t)
	for _, account := range []struct{ id, name string }{{"dXNlcjI", "zeta-user"}, {"dXNlcjM", "alpha-user"}} {
		target.Options = suggestionsCreate(account.id, account.name)
		target.ID, target.Revision = "", ""
		if _, e := s.PerformPasskey(target, false, dailyGate(t, s)); e != nil {
			t.Fatal(e)
		}
	}
	first, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}`)})
	if e != nil || len(first) != 3 {
		t.Fatalf("candidates: %v %d", e, len(first))
	}
	for n := 1; n < len(first); n++ {
		left, right := first[n-1], first[n]
		if left.UserName > right.UserName || left.UserName == right.UserName && (left.Title > right.Title || left.Title == right.Title && left.ItemID > right.ItemID) {
			t.Fatalf("unstable order: %+v", first)
		}
	}
	again, e := s.ConditionalPasskeyCandidates(PasskeyTarget{Context: target.Context, Options: []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}`)})
	if e != nil || len(again) != len(first) {
		t.Fatalf("repeat candidates: %v", e)
	}
	for n := range first {
		if first[n] != again[n] {
			t.Fatal("candidate order is not stable")
		}
	}
}

func TestReviewPasskeyPinnedTargetIsExact(t *testing.T) {
	s, target, created := removeFixture(t)
	first := target.ID
	secondID, e := s.AddLogin("Second login", "second-user", "second-password")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Edit(Edit{ID: secondID, Revision: suggestionsRevision(t, s, secondID), Field: "url", Value: "https://example.test/login"}); e != nil {
		t.Fatal(e)
	}
	secondTarget := target
	secondTarget.ID = secondID
	secondTarget.Revision = suggestionsRevision(t, s, secondID)
	secondTarget.Options = suggestionsCreate("dXNlcjI", "second-user")
	second, e := s.PerformPasskey(secondTarget, false, dailyGate(t, s))
	if e != nil || second.ID == created.ID {
		t.Fatalf("second credential: %v", e)
	}
	get := PasskeyTarget{Context: target.Context, Options: passkeyGetOptions(created.ID)}
	choices, e := s.ReviewPasskey(get)
	if e != nil || len(choices) != 1 || choices[0].ID != first {
		t.Fatalf("unpinned review: %v %+v", e, choices)
	}
	pinned := PasskeyTarget{Context: target.Context, ID: first, Revision: choices[0].Revision, Options: []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}`)}
	choices, e = s.ReviewPasskey(pinned)
	if e != nil || len(choices) != 1 || choices[0].ID != first {
		t.Fatalf("pinned review: %v %+v", e, choices)
	}
	stale := pinned
	stale.Revision = strings.Repeat("a", 64)
	if _, e = s.ReviewPasskey(stale); e == nil {
		t.Fatal("stale pinned review offered unrelated choices")
	}
	missing := pinned
	missing.ID = "0123456789abcdef0123456789abcdef"
	if _, e = s.ReviewPasskey(missing); e == nil {
		t.Fatal("missing pinned review offered unrelated choices")
	}
	// Another account can never be promoted to the pinned identity.
	if _, e = s.PerformPasskey(PasskeyTarget{Context: target.Context, ID: secondID, Revision: stale.Revision, Options: pinned.Options}, false, dailyGate(t, s)); e == nil {
		t.Fatal("stale selector signed another account")
	}
	revision := choices[0].Revision
	signed, e := s.PerformPasskey(PasskeyTarget{Context: target.Context, ID: first, Revision: revision, Options: pinned.Options}, false, dailyGate(t, s))
	if e != nil || signed.ID != created.ID {
		t.Fatalf("pinned assertion: %v", e)
	}
	s.RequestLock()
	if _, e = s.ReviewPasskey(pinned); e == nil {
		t.Fatal("locked pinned review")
	}
}
