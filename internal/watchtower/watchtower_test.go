package watchtower

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func activeItem(id, password string) Item {
	return Item{ID: id, Revision: strings.Repeat("a", 64), Kind: "login", Title: "Example", Password: password, OTP: "seed", HasPasskey: true}
}

func TestStrengthTiers(t *testing.T) {
	cases := []struct {
		name     string
		password string
		category string
		score    int
		flags    []string
	}{
		{"empty", "", "terrible", 0, []string{"empty"}},
		{"common", "password", "terrible", 15, []string{"common-pattern", "short", "weak"}},
		{"weak", "abcdeabcdeab", "weak", 27, []string{"weak"}},
		{"fair", "AaBBBBCCCCDD", "fair", 51, nil},
		{"good", "AaBbCCCCDDDD", "good", 59, nil},
		{"very-good", "AaBbCDdddddd", "very-good", 66, nil},
		{"excellent", "AaBbCcDdEEEE", "excellent", 82, nil},
		{"fantastic", "correct horse battery staple", "fantastic", 100, nil},
		{"single-class-long", "abcdefghijklmnop", "fantastic", 100, nil},
		{"short-capped", "Tr0ub4dor&3", "weak", 42, []string{"short", "weak"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, category, flags := Strength(tc.password)
			if score != tc.score || category != tc.category {
				t.Fatalf("got score=%d category=%q, want %d %q", score, category, tc.score, tc.category)
			}
			if tc.flags != nil && !equalStrings(flags, tc.flags) {
				t.Fatalf("flags=%v, want %v", flags, tc.flags)
			}
			if score < 0 || score > 100 {
				t.Fatal("score out of range")
			}
		})
	}
}

func TestStrengthCommonAndVarietyPenalties(t *testing.T) {
	score, category, flags := Strength("MyPassword123!")
	if category != "terrible" || score != 24 || !equalStrings(flags, []string{"common-pattern", "weak"}) {
		t.Fatalf("common substring not capped: %d %q %v", score, category, flags)
	}
	score, _, flags = Strength("aaaaaaaaaaaa")
	if score != 11 || !equalStrings(flags, []string{"common-pattern", "low-variety", "weak"}) {
		t.Fatalf("repeated/low-variety: %d %v", score, flags)
	}
	if _, _, flags = Strength("abcdefghijkl"); len(flags) != 0 {
		t.Fatalf("strong lowercase flagged %v", flags)
	}
	// Flag order is stable even when every category is present.
	now := time.Now()
	items := []Item{
		{ID: "1", Revision: strings.Repeat("a", 64), Kind: "login", Title: "T", Password: "password", URL: "http://example.test/login", ExpiresAt: now.Add(-time.Hour)},
		{ID: "2", Revision: strings.Repeat("a", 64), Kind: "login", Title: "T", Password: "password", URL: "http://example.test/login"},
	}
	report, err := Evaluate(items, Options{Now: now, HIBPResults: map[string]int{"1": 100, "2": 100}, IncludeHIBP: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"common-pattern", "short", "weak", "reused", "unsecured-http", "totp-not-stored", "passkey-not-stored", "expired", "vulnerable"}
	if len(report.Findings) != 2 || !equalStrings(report.Findings[0].Flags, want) {
		t.Fatalf("unstable flag order: %v", report.Findings)
	}
	if report.Findings[0].BreachCount != 100 || report.Findings[0].ReuseCount != 2 {
		t.Fatal("finding metadata")
	}
}

func TestAnalyzeScopeAndTwoFactor(t *testing.T) {
	items := []Item{
		{ID: "1", Revision: strings.Repeat("a", 64), Kind: "login", Title: "One", Password: "password", OTP: "seed"},
		{ID: "2", Revision: strings.Repeat("b", 64), Kind: "login", Title: "Two", Password: "password", State: "archived"},
		{ID: "3", Revision: strings.Repeat("c", 64), Kind: "login", Title: "Three", Password: "", HasPasskey: true},
		{ID: "4", Revision: strings.Repeat("d", 64), Kind: "document", Title: "Doc"},
		{ID: "5", Revision: strings.Repeat("e", 64), Kind: "login", Title: "Five", Password: "correct horse battery staple", OTP: "seed", HasPasskey: true},
		{ID: "6", Revision: strings.Repeat("f", 64), Kind: "login", Title: "Six", Password: "AaBbCcDdEEEE", OTP: "", HasPasskey: false},
	}
	report, err := Evaluate(items, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 4 || report.Skipped != 2 {
		t.Fatalf("scope checked=%d skipped=%d", report.Checked, report.Skipped)
	}
	if report.Counts.Weak != 1 || report.Counts.TOTPNotStored != 1 || report.Counts.PasskeyNotStored != 2 {
		t.Fatalf("counts=%+v", report.Counts)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("want 3 flagged findings, got %+v", report.Findings)
	}
	// Item 5 is strong with OTP and a passkey: no findings. Item 6 carries the
	// two 2FA flags. Item 1 is weak and missing a passkey.
	if report.Findings[0].ID != "1" || !equalStrings(report.Findings[0].Flags, []string{"common-pattern", "short", "weak", "passkey-not-stored"}) {
		t.Fatalf("finding 1: %+v", report.Findings[0])
	}
	if report.Findings[1].ID != "3" || !equalStrings(report.Findings[1].Flags, []string{"empty"}) {
		t.Fatalf("finding 3: %+v", report.Findings[1])
	}
	if report.Findings[2].ID != "6" || !equalStrings(report.Findings[2].Flags, []string{"totp-not-stored", "passkey-not-stored"}) {
		t.Fatalf("finding 6: %+v", report.Findings[2])
	}
}

func TestReuseHMACCaseSensitiveActiveOnly(t *testing.T) {
	revision := strings.Repeat("a", 64)
	items := []Item{
		{ID: "1", Revision: revision, Kind: "login", Password: "AaBbCcDdEEEE", HasPasskey: true, OTP: "seed"},
		{ID: "2", Revision: revision, Kind: "login", Password: "AaBbCcDdEEEE", HasPasskey: true, OTP: "seed"},
		{ID: "3", Revision: revision, Kind: "login", Password: "AaBbCcDdEEEe", HasPasskey: true, OTP: "seed"},
		{ID: "4", Revision: revision, Kind: "login", Password: "AaBbCcDdEEEE", State: "archived", HasPasskey: true},
		{ID: "5", Revision: revision, Kind: "login", Password: "AaBbCcDdEEEE", State: "trashed", HasPasskey: true},
	}
	key := bytes.Repeat([]byte{9}, 32)
	report, err := Evaluate(items, Options{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if report.Counts.Reused != 2 || len(report.Findings) != 2 {
		t.Fatalf("reuse counts=%+v findings=%+v", report.Counts, report.Findings)
	}
	for _, finding := range report.Findings {
		if finding.ReuseCount != 2 || !hasFlag(finding.Flags, "reused") {
			t.Fatalf("reuse finding: %+v", finding)
		}
	}
	// The same key is deterministic; a different key leaves grouping correct.
	other, err := Evaluate(items, Options{Key: bytes.Repeat([]byte{7}, 32)})
	if err != nil || other.Counts.Reused != 2 {
		t.Fatalf("per-analysis key changed grouping: %v", err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AaBbCcDdEEEE", "AaBbCcDdEEEe"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("reuse report leaked item data")
		}
	}
}

func TestUnsecuredHTTPAndLocalhost(t *testing.T) {
	revision := strings.Repeat("a", 64)
	items := []Item{
		{ID: "1", Revision: revision, Kind: "login", URL: "http://example.test/login", Password: "correct horse battery staple 1", HasPasskey: true, OTP: "seed"},
		{ID: "2", Revision: revision, Kind: "login", URL: "http://localhost:8080/login", Password: "correct horse battery staple 2", HasPasskey: true, OTP: "seed"},
		{ID: "3", Revision: revision, Kind: "login", URL: "http://127.0.0.1/login", Password: "correct horse battery staple 3", HasPasskey: true, OTP: "seed"},
		{ID: "4", Revision: revision, Kind: "login", URL: "http://[::1]:9000/login", Password: "correct horse battery staple 4", HasPasskey: true, OTP: "seed"},
		{ID: "5", Revision: revision, Kind: "login", URL: "https://example.test/login", Password: "correct horse battery staple 5", HasPasskey: true, OTP: "seed"},
	}
	report, err := Evaluate(items, Options{Origin: "http://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Counts.UnsecuredHTTP != 1 || !report.Site.UnsecuredHTTP {
		t.Fatalf("http counts=%+v site=%+v", report.Counts, report.Site)
	}
	if len(report.SiteFindings) != 1 || report.SiteFindings[0].ID != "1" || report.SiteFindings[0].Origin != "http://example.test" {
		t.Fatalf("site findings=%+v", report.SiteFindings)
	}
	for _, finding := range report.Findings {
		if finding.ID != "1" && hasFlag(finding.Flags, "unsecured-http") {
			t.Fatalf("loopback/https flagged: %+v", finding)
		}
	}
	httpsReport, err := Evaluate(items, Options{Origin: "https://example.test"})
	if err != nil || len(httpsReport.SiteFindings) != 0 || httpsReport.Site.UnsecuredHTTP {
		t.Fatalf("https site: %+v %v", httpsReport.SiteFindings, err)
	}
}

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	revision := strings.Repeat("a", 64)
	makeItem := func(id string, expires time.Time) Item {
		return Item{ID: id, Revision: revision, Kind: "login", Password: "correct horse battery staple", OTP: "seed", HasPasskey: true, ExpiresAt: expires}
	}
	items := []Item{
		makeItem("1", now.Add(-time.Second)),
		makeItem("2", now),
		makeItem("3", now.Add(10*24*time.Hour)),
		makeItem("4", now.Add(31*24*time.Hour)),
		makeItem("5", time.Time{}),
	}
	report, err := Evaluate(items, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if report.Counts.Expiring != 3 {
		t.Fatalf("expiring count=%d", report.Counts.Expiring)
	}
	byID := map[string]Finding{}
	for _, finding := range report.Findings {
		byID[finding.ID] = finding
	}
	if !hasFlag(byID["1"].Flags, "expired") || !hasFlag(byID["2"].Flags, "expired") {
		t.Fatal("past/equal expiry")
	}
	if !hasFlag(byID["3"].Flags, "expiring-soon") {
		t.Fatal("30-day window")
	}
	for _, id := range []string{"4", "5"} {
		if finding, ok := byID[id]; ok && (hasFlag(finding.Flags, "expired") || hasFlag(finding.Flags, "expiring-soon")) {
			t.Fatalf("future/zero expiry flagged: %+v", finding)
		}
	}
}

func TestOverallScorePenalties(t *testing.T) {
	revision := strings.Repeat("a", 64)
	strong := "correct horse battery staple"
	t.Run("no-active-logins", func(t *testing.T) {
		report, err := Evaluate([]Item{{ID: "1", Revision: revision, Kind: "document"}}, Options{})
		if err != nil || report.OverallScore != 100 || report.Checked != 0 {
			t.Fatalf("empty vault: %+v %v", report, err)
		}
	})
	t.Run("unsecured-http", func(t *testing.T) {
		report, err := Evaluate([]Item{{ID: "1", Revision: revision, Kind: "login", Password: strong, OTP: "seed", HasPasskey: true, URL: "http://example.test"}}, Options{})
		if err != nil || report.OverallScore != 85 {
			t.Fatalf("http penalty: %d %v", report.OverallScore, err)
		}
	})
	t.Run("reused", func(t *testing.T) {
		report, err := Evaluate([]Item{
			{ID: "1", Revision: revision, Kind: "login", Password: strong, OTP: "seed", HasPasskey: true},
			{ID: "2", Revision: revision, Kind: "login", Password: strong, OTP: "seed", HasPasskey: true},
		}, Options{})
		if err != nil || report.OverallScore != 30 {
			t.Fatalf("reuse penalty: %d %v", report.OverallScore, err)
		}
	})
	t.Run("weak", func(t *testing.T) {
		report, err := Evaluate([]Item{{ID: "1", Revision: revision, Kind: "login", Password: "password", OTP: "seed", HasPasskey: true}}, Options{})
		if err != nil || report.OverallScore != 15 {
			t.Fatalf("weak penalty: %d %v", report.OverallScore, err)
		}
	})
	t.Run("vulnerable", func(t *testing.T) {
		report, err := Evaluate([]Item{{ID: "1", Revision: revision, Kind: "login", Password: strong, OTP: "seed", HasPasskey: true}}, Options{IncludeHIBP: true, HIBPResults: map[string]int{"1": 9}})
		if err != nil || report.OverallScore != 0 || !report.HIBPChecked || report.Counts.Vulnerable != 1 {
			t.Fatalf("breach penalty: %+v %v", report, err)
		}
	})
	t.Run("average-rounds", func(t *testing.T) {
		report, err := Evaluate([]Item{
			{ID: "1", Revision: revision, Kind: "login", Password: strong, OTP: "seed", HasPasskey: true},
			{ID: "2", Revision: revision, Kind: "login", Password: "password", OTP: "seed", HasPasskey: true},
		}, Options{})
		// (100 + 15) / 2 = 57.5 -> 58
		if err != nil || report.OverallScore != 58 {
			t.Fatalf("rounding: %d %v", report.OverallScore, err)
		}
	})
}

func TestSiteFindingsExactOrigin(t *testing.T) {
	revision := strings.Repeat("a", 64)
	items := []Item{
		{ID: "1", Revision: revision, Kind: "login", Title: "One", URL: "https://example.test/login", Password: "password", HasPasskey: true, OTP: "seed"},
		{ID: "2", Revision: revision, Kind: "login", Title: "Two", URL: "https://example.test:8443/login", Password: "password", HasPasskey: true, OTP: "seed"},
		{ID: "3", Revision: revision, Kind: "login", Title: "Three", URL: "https://other.test/login", Password: "password", HasPasskey: true, OTP: "seed"},
	}
	report, err := Evaluate(items, Options{Origin: "https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SiteFindings) != 1 || report.SiteFindings[0].ID != "1" || report.SiteFindings[0].Origin != "https://example.test" {
		t.Fatalf("site findings=%+v", report.SiteFindings)
	}
	if report.Site.Origin != "https://example.test" || report.Site.UnsecuredHTTP {
		t.Fatalf("site=%+v", report.Site)
	}
}

func TestJSONNeverCarriesSecrets(t *testing.T) {
	revision := strings.Repeat("a", 64)
	items := []Item{
		{ID: "1", Revision: revision, Kind: "login", Title: "Private title", Username: "private-user", Password: "password", OTP: "private-otp", URL: "https://example.test"},
	}
	analysis, err := Analyze(items, Options{Origin: "https://example.test", CollectHIBP: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-user", "password", "private-otp", "5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("analysis JSON leaked %q: %s", secret, raw)
		}
	}
	if _, err = json.Marshal(items[0]); err == nil {
		t.Fatal("Item serialized")
	}
	if _, err = json.Marshal(analysis.HIBPCandidates[0]); err == nil {
		t.Fatal("HIBPCandidate serialized")
	}
	var wire map[string]any
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["Report"]; !ok {
		t.Fatal("analysis did not retain the report")
	}
}

func TestFindingsSlicesNeverNil(t *testing.T) {
	report, err := Evaluate(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"findings":[]`, `"site_findings":[]`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("missing non-nil %s: %s", key, raw)
		}
	}
}

func TestAnalyzeBoundedInputs(t *testing.T) {
	tooMany := make([]Item, 257)
	for i := range tooMany {
		tooMany[i] = activeItem(strings.Repeat("0", 32), "password")
	}
	if _, err := Evaluate(tooMany, Options{}); err == nil {
		t.Fatal("item count not bounded")
	}
	if _, err := Evaluate([]Item{{ID: "1", Kind: "login", Title: strings.Repeat("t", 1025), Password: "password"}}, Options{}); err == nil {
		t.Fatal("title not bounded")
	}
	if _, err := Evaluate([]Item{{ID: "1", Kind: "login", Password: strings.Repeat("p", 16<<10+1)}}, Options{}); err == nil {
		t.Fatal("password not bounded")
	}
}

type countingLookup struct {
	calls   int
	results map[string]map[string]int
	err     error
}

func (c *countingLookup) Lookup(_ context.Context, prefix string) (map[string]int, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	return c.results[prefix], nil
}

func TestHIBPOfflineByDefault(t *testing.T) {
	lookup := &countingLookup{err: errTestLookup}
	items := []Item{activeItem("1", "password")}
	report, err := Evaluate(items, Options{HIBP: lookup, IncludeHIBP: false})
	if err != nil {
		t.Fatal(err)
	}
	if lookup.calls != 0 || report.HIBPChecked || report.HIBPError != "" || report.Counts.Vulnerable != 0 {
		t.Fatalf("offline breach: %+v calls=%d", report, lookup.calls)
	}
	analysis, err := Analyze(items, Options{HIBP: lookup, IncludeHIBP: false, CollectHIBP: true})
	if err != nil || lookup.calls != 0 || len(analysis.HIBPCandidates) != 1 {
		t.Fatalf("collect candidates: %+v calls=%d err=%v", analysis, lookup.calls, err)
	}
	if analysis.HIBPCandidates[0].Prefix != "5BAA6" || analysis.HIBPCandidates[0].Suffix != "1E4C9B93F3F0682250B6CF8331B7EE68FD8" {
		t.Fatalf("candidate split: %+v", analysis.HIBPCandidates[0])
	}
}

func TestHIBPNilLookupIsUnavailable(t *testing.T) {
	report, err := Evaluate([]Item{activeItem("1", "password")}, Options{IncludeHIBP: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.HIBPChecked || report.HIBPError != "unavailable" || report.Counts.Vulnerable != 0 {
		t.Fatalf("nil lookup: %+v", report)
	}
}

func TestHIBPLookupErrorIsUnavailable(t *testing.T) {
	lookup := &countingLookup{err: errTestLookup}
	report, err := Evaluate([]Item{activeItem("1", "password")}, Options{IncludeHIBP: true, HIBP: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if report.HIBPChecked || report.HIBPError != "unavailable" || report.Counts.Vulnerable != 0 || lookup.calls != 1 {
		t.Fatalf("lookup error: %+v calls=%d", report, lookup.calls)
	}
	raw, _ := json.Marshal(report)
	if bytes.Contains(raw, []byte("5BAA6")) || bytes.Contains(raw, []byte("password")) {
		t.Fatal("error report leaked lookup material")
	}
}

func TestHIBPResultsAppliedLocally(t *testing.T) {
	lookup := &countingLookup{err: errTestLookup}
	report, err := Evaluate([]Item{activeItem("1", "password")}, Options{
		IncludeHIBP: true,
		HIBP:        lookup,
		HIBPResults: map[string]int{"1": 42},
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookup.calls != 0 || !report.HIBPChecked || report.Counts.Vulnerable != 1 {
		t.Fatalf("precomputed results: %+v calls=%d", report, lookup.calls)
	}
	if report.Findings[0].BreachCount != 42 || !hasFlag(report.Findings[0].Flags, "vulnerable") {
		t.Fatalf("breach finding: %+v", report.Findings[0])
	}
}

func TestCollectHIBPCandidatesNeverSerialized(t *testing.T) {
	analysis, err := Analyze([]Item{activeItem("1", "password"), {ID: "2", Revision: strings.Repeat("a", 64), Kind: "login", Password: "", State: "archived"}}, Options{CollectHIBP: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.HIBPCandidates) != 1 {
		t.Fatalf("candidates=%+v", analysis.HIBPCandidates)
	}
	raw, _ := json.Marshal(analysis)
	if bytes.Contains(raw, []byte("5BAA6")) || bytes.Contains(raw, []byte("1E4C9B")) {
		t.Fatal("candidates serialized")
	}
}

var errTestLookup = &testLookupError{}

type testLookupError struct{}

func (*testLookupError) Error() string { return "test lookup failure" }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compile-time evidence that the expected SHA-1 split is what the production
// candidate builder emits.
func TestCandidateSHA1Split(t *testing.T) {
	sum := sha1.Sum([]byte("password"))
	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))
	if hexSum != "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8" {
		t.Fatal("sha1 fixture")
	}
	candidate := makeCandidate(activeItem("1", "password"))
	if candidate.Prefix != hexSum[:5] || candidate.Suffix != hexSum[5:] {
		t.Fatalf("candidate=%+v", candidate)
	}
}
