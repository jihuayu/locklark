package personal

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWatchtowerSummaryFlagsAndOriginFilter(t *testing.T) {
	s, fill := browserFixture(t)
	if s.VaultPath() == "" {
		t.Fatal("unlocked vault path missing")
	}
	first, e := s.AddLogin("Watch A", "a", "reused-secret")
	if e != nil {
		t.Fatal(e)
	}
	second, e := s.AddLogin("Watch B", "b", "reused-secret")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	revs := map[string]string{}
	for _, row := range rows {
		revs[row.ID] = row.Revision
	}
	s.PatchMeta(fill.ID, func(m *V2ItemMeta) {
		m.URLs = []V2ItemURL{{URL: "http://insecure.example/path", Primary: true}}
		m.CreditCard = &V2CreditCard{ExpiryDate: time.Now().AddDate(0, -1, 0).Format("2006-01")}
	})
	s.PatchMeta(first, func(m *V2ItemMeta) { m.Favorite = true })
	_ = second
	summary, e := s.WatchtowerSummary("https://example.test")
	if e != nil {
		t.Fatal(e)
	}
	if summary.OverallScore < 0 || summary.OverallScore > 100 || summary.Checked < 1 {
		t.Fatalf("score: %#v", summary)
	}
	if summary.Counts["reused"] < 2 {
		t.Fatalf("reuse counts: %#v", summary.Counts)
	}
	found := map[string]bool{}
	for _, f := range summary.Findings {
		for _, flag := range f.Flags {
			found[flag] = true
		}
	}
	for _, want := range []string{"reused", "unsecured-http", "totp-not-stored", "expired"} {
		if !found[want] {
			t.Fatalf("missing flag %q: %#v", want, summary.Findings)
		}
	}
	if len(summary.SiteFindings) != 1 || summary.SiteFindings[0].Origin != "https://example.test" {
		t.Fatalf("site filter: %#v", summary.SiteFindings)
	}
	if len(summary.Findings) < 2 {
		t.Fatalf("findings: %#v", summary.Findings)
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	healthSeen := false
	for _, event := range events {
		if event.Action == healthAction && event.Result == "succeeded" {
			healthSeen = true
		}
	}
	if !healthSeen {
		t.Fatal("watchtower read did not record health audit")
	}
	_ = revs
	s.Lock()
	if s.VaultPath() != "" {
		t.Fatal("locked vault exposed a path")
	}
}

func TestCLIBrokerTargetsSingleView(t *testing.T) {
	s, fill := browserFixture(t)
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	var row Row
	for _, candidate := range rows {
		if candidate.ID == fill.ID {
			row = candidate
		}
	}
	if row.Revision == "" {
		t.Fatal("fixture row")
	}
	rev, e := s.Edit(Edit{ID: row.ID, Revision: row.Revision, Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.AddLogin("CLI other", "other", "other-secret"); e != nil {
		t.Fatal(e)
	}
	targets := []CLIBrokerTarget{
		{Slot: "USER", ID: row.ID, Revision: rev, Field: "username"},
		{Slot: "PASS", ID: row.ID, Revision: rev, Field: "password"},
		{Slot: "OTP", ID: row.ID, Revision: rev, Field: "otp"},
	}
	values, e := s.ExtractCLIBrokerTargets(targets)
	if e != nil || values["PASS"] == "" || values["OTP"] == "" {
		t.Fatalf("extract: %v %#v", e, values)
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	intents := 0
	for _, event := range events {
		if event.Action == "item.desktop.show.password" && event.Item == row.ID && event.Result == "intent" {
			intents++
		}
	}
	if intents != 1 {
		t.Fatalf("audit intents: %d", intents)
	}
	stale := []CLIBrokerTarget{{Slot: "PASS", ID: row.ID, Revision: strings.Repeat("a", 64), Field: "password"}}
	if values, e = s.ExtractCLIBrokerTargets(stale); e == nil || values != nil {
		t.Fatal("stale revision disclosed")
	}
	if !errors.Is(e, ErrConflict) {
		t.Fatalf("stale error: %v", e)
	}
	many := make([]CLIBrokerTarget, 17)
	for i := range many {
		many[i] = CLIBrokerTarget{Slot: "S", ID: row.ID, Revision: rev, Field: "username"}
	}
	if _, e = s.ExtractCLIBrokerTargets(many); !errors.Is(e, ErrRunCredential) {
		t.Fatalf("target limit: %v", e)
	}
	if _, e = s.SetState(row.ID, rev, "item.trash"); e != nil {
		t.Fatal(e)
	}
	rows, e = s.List("trashed")
	if e != nil {
		t.Fatal(e)
	}
	trashedRev := rows[0].Revision
	if _, e = s.ExtractCLIBrokerTargets([]CLIBrokerTarget{{Slot: "PASS", ID: row.ID, Revision: trashedRev, Field: "password"}}); !errors.Is(e, ErrTrashed) {
		t.Fatalf("trashed: %v", e)
	}
}
