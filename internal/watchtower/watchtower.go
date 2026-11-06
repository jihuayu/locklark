// Package watchtower implements the pure, offline-first credential health
// analysis behind the desktop and browser Watchtower surfaces. It deliberately
// does not import internal/personal or internal/browserhost: it can only see
// the bounded, caller-supplied item projection below.
package watchtower

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const Profile = "watchtower-v2"

var (
	// ErrLimit is a fixed business refusal for inputs outside the bounded
	// Watchtower projection. It never includes item data.
	ErrLimit = errors.New("watchtower input exceeds limits")
	// ErrSecret is returned when a caller tries to JSON-encode plaintext or
	// hash material. Item and HIBPCandidate intentionally cannot marshal.
	ErrSecret = errors.New("watchtower secret material cannot be serialized")
)

// These are deliberately larger than any browser-facing DTO, but small enough
// that one analysis is bounded (256 items, each field bounded).
const (
	maxItems    = 256
	maxID       = 256
	maxRevision = 256
	maxKind     = 64
	maxTitle    = 1024
	maxUsername = 16 << 10
	maxPassword = 16 << 10
	maxOTP      = 16 << 10
	maxURL      = 2048
	maxState    = 64
	maxOrigin   = 2048
)

// Item is the pure projection of one vault login. Password, OTP and HasPasskey
// never leave this process through Watchtower JSON; MarshalJSON fails closed.
type Item struct {
	ID, Revision, Kind, Title, Username, URL, Password, OTP, State string
	HasPasskey                                                     bool
	ExpiresAt                                                      time.Time
}

func (Item) MarshalJSON() ([]byte, error) { return nil, ErrSecret }
func (Item) String() string               { return "[watchtower item]" }
func (Item) GoString() string             { return "[watchtower item]" }

type Options struct {
	Now         time.Time // zero => time.Now()
	Key         []byte    // optional HMAC key for reuse grouping; nil => random 32 bytes
	Origin      string    // current site origin for SiteFindings; "" allowed
	IncludeHIBP bool
	HIBP        RangeLookup    // nil => no network; HIBPError="unavailable" when IncludeHIBP
	HIBPResults map[string]int // optional precomputed itemID -> breach count
	CollectHIBP bool           // return HIBPCandidates from Analyze
}

// HIBPCandidate carries the local SHA-1 prefix/suffix split. It is never
// serialized; only Prefix is ever placed in an outbound URL.
type HIBPCandidate struct {
	ID, Prefix, Suffix string
}

func (HIBPCandidate) MarshalJSON() ([]byte, error) { return nil, ErrSecret }
func (HIBPCandidate) String() string               { return "[watchtower breach candidate]" }
func (HIBPCandidate) GoString() string             { return "[watchtower breach candidate]" }

type Counts struct {
	Vulnerable       int `json:"vulnerable"`
	Reused           int `json:"reused"`
	Weak             int `json:"weak"`
	UnsecuredHTTP    int `json:"unsecured_http"`
	TOTPNotStored    int `json:"totp_not_stored"`
	Expiring         int `json:"expiring"`
	PasskeyNotStored int `json:"passkey_not_stored"`
}

type Finding struct {
	ID               string   `json:"id"`
	Revision         string   `json:"revision"`
	Title            string   `json:"title"`
	Origin           string   `json:"origin,omitempty"`
	Flags            []string `json:"flags"`
	StrengthScore    int      `json:"strength_score"`
	StrengthCategory string   `json:"strength_category"`
	ReuseCount       int      `json:"reuse_count"`
	BreachCount      int      `json:"breach_count"`
}

type Site struct {
	Origin        string `json:"origin,omitempty"`
	UnsecuredHTTP bool   `json:"unsecured_http"`
}

type Report struct {
	Profile      string    `json:"profile"`
	HIBPChecked  bool      `json:"hibp_checked"`
	HIBPError    string    `json:"hibp_error,omitempty"`
	OverallScore int       `json:"overall_score"`
	Checked      int       `json:"checked"`
	Skipped      int       `json:"skipped,omitempty"`
	Counts       Counts    `json:"counts"`
	Site         Site      `json:"site"`
	SiteFindings []Finding `json:"site_findings"`
	Findings     []Finding `json:"findings"`
}

type Analysis struct {
	Report         Report
	HIBPCandidates []HIBPCandidate `json:"-"`
}

// flag ranks are the stable wire order required by the protocol contract.
var flagRank = map[string]int{
	"empty":              0,
	"common-pattern":     1,
	"short":              2,
	"low-variety":        3,
	"weak":               4,
	"reused":             5,
	"unsecured-http":     6,
	"totp-not-stored":    7,
	"passkey-not-stored": 8,
	"expiring-soon":      9,
	"expired":            10,
	"vulnerable":         11,
}

func orderFlags(flags []string) []string {
	if len(flags) == 0 {
		return []string{}
	}
	sort.SliceStable(flags, func(i, j int) bool { return flagRank[flags[i]] < flagRank[flags[j]] })
	return flags
}

// Strength scores one password without any vault metadata. It is exported for
// deterministic table tests and for callers that only need the local estimate.
func Strength(password string) (score int, category string, flags []string) {
	e, strengthFlags := passwordEntropy(password, nil)
	score, category = normalize(e)
	return score, category, strengthFlags
}

// Evaluate is Analyze without exposing breach candidates.
func Evaluate(items []Item, opts Options) (Report, error) {
	a, err := Analyze(items, opts)
	return a.Report, err
}

type itemResult struct {
	finding    Finding
	score      int
	reuse      int
	unsecured  bool
	vulnerable bool
	weak       bool
	reused     bool
}

// Analyze is the single pure entry point. It never keeps a plaintext password
// as a map key; reuse groups are keyed by a keyed HMAC-SHA256 digest.
func Analyze(items []Item, opts Options) (Analysis, error) {
	if len(items) > maxItems || len(opts.Origin) > maxOrigin {
		return Analysis{}, ErrLimit
	}
	for _, it := range items {
		if len(it.ID) > maxID || len(it.Revision) > maxRevision || len(it.Kind) > maxKind ||
			len(it.Title) > maxTitle || len(it.Username) > maxUsername || len(it.Password) > maxPassword ||
			len(it.OTP) > maxOTP || len(it.URL) > maxURL || len(it.State) > maxState {
			return Analysis{}, ErrLimit
		}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	key := opts.Key
	if key == nil {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return Analysis{}, ErrLimit
		}
	}

	// Reuse grouping happens before per-item scoring, but the map is keyed by
	// an HMAC digest. The plaintext itself is never a map key or retained.
	reuse := make(map[string]int)
	for _, it := range items {
		if it.Kind == "login" && it.State == "" && it.Password != "" {
			reuse[reuseDigest(key, it.Password)]++
		}
	}

	report := Report{
		Profile:      Profile,
		SiteFindings: []Finding{},
		Findings:     []Finding{},
	}
	var results []itemResult
	var candidates []HIBPCandidate
	for _, it := range items {
		if it.Kind != "login" || it.State != "" {
			report.Skipped++
			continue
		}
		report.Checked++
		extra := commonMetadata(it.Username, it.Title)
		e, flags := passwordEntropy(it.Password, extra)
		score, category := normalize(e)
		result := itemResult{score: score}
		result.finding = Finding{
			ID:               it.ID,
			Revision:         it.Revision,
			Title:            it.Title,
			StrengthScore:    score,
			StrengthCategory: category,
		}
		if it.URL != "" {
			if origin, unsecured := websiteOrigin(it.URL); origin != "" {
				result.finding.Origin = origin
				if unsecured {
					result.unsecured = true
					flags = append(flags, "unsecured-http")
				}
			}
		}
		if it.Password != "" {
			count := reuse[reuseDigest(key, it.Password)]
			if count > 1 {
				result.reused = true
				result.reuse = count
				flags = append(flags, "reused")
			}
		}
		if it.OTP == "" && !it.HasPasskey {
			flags = append(flags, "totp-not-stored")
		}
		if !it.HasPasskey {
			flags = append(flags, "passkey-not-stored")
		}
		if !it.ExpiresAt.IsZero() {
			switch {
			case !it.ExpiresAt.After(now):
				flags = append(flags, "expired")
			case !it.ExpiresAt.After(now.Add(30 * 24 * time.Hour)):
				flags = append(flags, "expiring-soon")
			}
		}
		result.finding.Flags = orderFlags(flags)
		result.finding.ReuseCount = result.reuse
		result.weak = hasFlag(result.finding.Flags, "weak")
		results = append(results, result)

		if (opts.CollectHIBP || opts.IncludeHIBP) && it.Password != "" {
			candidates = append(candidates, makeCandidate(it))
		}
	}

	if opts.IncludeHIBP {
		switch {
		case opts.HIBPResults != nil:
			report.HIBPChecked = true
			applyHIBPResults(results, opts.HIBPResults)
		case opts.HIBP != nil:
			got, err := LookupCandidates(context.Background(), opts.HIBP, candidates)
			if err != nil {
				report.HIBPError = "unavailable"
			} else {
				report.HIBPChecked = true
				applyHIBPResults(results, got)
			}
		default:
			report.HIBPError = "unavailable"
		}
	}

	for _, result := range results {
		f := result.finding
		for _, flag := range f.Flags {
			switch flag {
			case "vulnerable":
				report.Counts.Vulnerable++
			case "reused":
				report.Counts.Reused++
			case "weak":
				report.Counts.Weak++
			case "unsecured-http":
				report.Counts.UnsecuredHTTP++
			case "totp-not-stored":
				report.Counts.TOTPNotStored++
			case "passkey-not-stored":
				report.Counts.PasskeyNotStored++
			case "expiring-soon", "expired":
				report.Counts.Expiring++
			}
		}
		if len(f.Flags) > 0 {
			f.Flags = append([]string{}, f.Flags...)
			report.Findings = append(report.Findings, f)
		}
	}
	sort.Slice(report.Findings, func(i, j int) bool { return report.Findings[i].ID < report.Findings[j].ID })

	siteOrigin, siteUnsecured := websiteOrigin(opts.Origin)
	report.Site = Site{Origin: opts.Origin, UnsecuredHTTP: siteUnsecured}
	if siteOrigin != "" {
		for _, f := range report.Findings {
			if f.Origin == siteOrigin {
				report.SiteFindings = append(report.SiteFindings, f)
			}
		}
	}
	report.OverallScore = overallScore(results)
	if opts.CollectHIBP {
		return Analysis{Report: report, HIBPCandidates: candidates}, nil
	}
	return Analysis{Report: report}, nil
}

func makeCandidate(it Item) HIBPCandidate {
	sum := sha1.Sum([]byte(it.Password))
	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))
	return HIBPCandidate{ID: it.ID, Prefix: hexSum[:5], Suffix: hexSum[5:]}
}

func reuseDigest(key []byte, password string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(password))
	return hex.EncodeToString(mac.Sum(nil))
}

func applyHIBPResults(results []itemResult, counts map[string]int) {
	for i := range results {
		count := counts[results[i].finding.ID]
		if count < 0 {
			count = 0
		}
		results[i].finding.BreachCount = count
		if count > 0 {
			results[i].vulnerable = true
			results[i].finding.Flags = orderFlags(append(results[i].finding.Flags, "vulnerable"))
		}
	}
}

func overallScore(results []itemResult) int {
	if len(results) == 0 {
		return 100
	}
	total := 0
	for _, result := range results {
		score := result.score
		switch {
		case result.vulnerable:
			score = 0
		default:
			if result.reused && score > 30 {
				score = 30
			}
			if result.weak && score > 40 {
				score = 40
			}
			if result.unsecured {
				score -= 15
				if score < 0 {
					score = 0
				}
			}
		}
		total += score
	}
	score := int(math.Round(float64(total) / float64(len(results))))
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func hasFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

// normalize maps entropy bits to the 0-100 score and seven categories.
func normalize(e float64) (int, string) {
	if e < 0 {
		e = 0
	}
	score := int(e * 100 / 75)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	var category string
	switch {
	case e <= 20:
		category = "terrible"
	case e <= 33:
		category = "weak"
	case e <= 40:
		category = "fair"
	case e <= 45:
		category = "good"
	case e <= 55:
		category = "very-good"
	case e <= 64:
		category = "excellent"
	default:
		category = "fantastic"
	}
	return score, category
}

// passwordEntropy implements the contract formula exactly. extraCommon holds
// already-lowercased username/title tokens that are common when contained in
// the password.
func passwordEntropy(password string, extraCommon []string) (float64, []string) {
	runes := []rune(password)
	length := len(runes)
	if length == 0 {
		return 0, []string{"empty"}
	}
	var lower, upper, digit, symbol, nonASCII bool
	distinct := make(map[rune]bool, length)
	for _, r := range runes {
		distinct[r] = true
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		case r == ' ' || (r >= 33 && r <= 126):
			symbol = true
		case r > 126:
			nonASCII = true
		}
	}
	pool := 0
	if lower {
		pool += 26
	}
	if upper {
		pool += 26
	}
	if digit {
		pool += 10
	}
	if symbol {
		pool += 33
	}
	if nonASCII {
		pool += 100
	}
	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol, nonASCII} {
		if present {
			classes++
		}
	}
	u := float64(len(distinct))
	l := float64(length)
	if pool < 2 {
		pool = 2
	}
	e := l * math.Log2(float64(pool)) * math.Min(1, u/l+0.15)

	flags := []string{}
	lowerPassword := strings.ToLower(password)
	if commonPassword(lowerPassword) || containsCommon(lowerPassword, extraCommon) {
		flags = append(flags, "common-pattern")
		if e > 18 {
			e = 18
		}
	}
	if length < 12 {
		flags = append(flags, "short")
		if e > 32 {
			e = 32
		}
	}
	if len(distinct) < 4 {
		flags = append(flags, "low-variety")
		if e > 20 {
			e = 20
		}
	}
	if classes == 1 && length < 16 {
		e *= 0.65
	}
	if e <= 33 {
		flags = append(flags, "weak")
	}
	return e, orderFlags(flags)
}

func containsCommon(password string, extra []string) bool {
	for _, token := range extra {
		if utf8.RuneCountInString(token) >= 4 && strings.Contains(password, token) {
			return true
		}
	}
	return false
}

func commonMetadata(username, title string) []string {
	out := make([]string, 0, 4)
	if utf8.RuneCountInString(username) >= 4 {
		out = append(out, strings.ToLower(username))
	}
	if utf8.RuneCountInString(title) >= 4 {
		out = append(out, strings.ToLower(title))
	}
	for _, token := range strings.FieldsFunc(strings.ToLower(title), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 126)
	}) {
		if utf8.RuneCountInString(token) >= 4 {
			out = append(out, token)
		}
	}
	return out
}

var commonTokens = []string{
	"123456", "1234567", "12345678", "123456789", "1234567890", "12345", "1234",
	"111111", "000000", "121212", "123123", "654321", "666666", "777777",
	"password", "passw0rd", "pass", "letmein", "welcome", "admin", "root", "toor",
	"iloveyou", "monkey", "dragon", "master", "sunshine", "princess", "football",
	"baseball", "shadow", "superman", "michael", "trustno1", "abc123", "login",
	"secret", "changeme", "default", "qwerty", "qwertyuiop", "asdfgh", "asdf",
	"zxcvbn", "zxcv", "1q2w3e4r", "zaq12wsx", "qazwsx", "starwars", "whatever",
}

// commonPassword detects exact dictionary matches, weak substrings, keyboard
// walks and repeated sequences. Substring matching only applies to tokens of
// five or more runes so ordinary words are not broadly penalized.
func commonPassword(lower string) bool {
	for _, token := range commonTokens {
		if lower == token {
			return true
		}
		if len(token) >= 5 && strings.Contains(lower, token) {
			return true
		}
	}
	return repeatedSequence(lower)
}

func repeatedSequence(password string) bool {
	runes := []rune(password)
	if len(runes) < 3 {
		return false
	}
	for period := 1; period <= 4 && period < len(runes); period++ {
		if len(runes)%period != 0 {
			continue
		}
		repeated := true
		for i := period; i < len(runes); i++ {
			if runes[i] != runes[i%period] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}

// websiteOrigin extracts a scheme/host/port origin without the HTTPS-only
// restriction of internal/origin. It also reports the unsecured-HTTP rule used
// by the pure package (the vault itself cannot currently store http URLs).
func websiteOrigin(raw string) (string, bool) {
	if raw == "" || len(raw) > maxURL {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	if scheme == "http" && port == "80" || scheme == "https" && port == "443" {
		port = ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	origin := scheme + "://" + authority
	unsecured := scheme == "http" && !loopbackHost(host)
	return origin, unsecured
}

func loopbackHost(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "127.0.0.1" || host == "::1"
}
