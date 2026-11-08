package personal

import (
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// ---------------------------------------------------------------------------
// v2 item metadata DTO
//
// vault.Item models every v2 attribute durably (see vault/items_v2.go), so
// V2ItemMeta is only a DTO projection of authenticated item fields. There is no
// process-local overlay and no memory-only fallback: reads project an already
// authenticated item and writes go through the whole-item audited mutation
// path (AddItem / EditItem / SetFavorite). See browser_v2_persistence.go.
// ---------------------------------------------------------------------------

// V2ItemMeta is the v2 metadata DTO projected from persisted vault.Item
// fields. It is always derived from an authenticated item, never merged back
// from process memory.
type V2ItemMeta struct {
	Category   string        `json:"category,omitempty"`
	VaultID    string        `json:"vault_id,omitempty"`
	Favorite   bool          `json:"favorite,omitempty"`
	AutoSubmit *bool         `json:"auto_submit,omitempty"`
	Tags       []string      `json:"tags,omitempty"`
	URLs       []V2ItemURL   `json:"urls,omitempty"`
	Sections   []V2Section   `json:"sections,omitempty"`
	CreditCard *V2CreditCard `json:"credit_card,omitempty"`
	Identity   *V2Identity   `json:"identity,omitempty"`
	CreatedAt  int64         `json:"created_at,omitempty"`
	UpdatedAt  int64         `json:"updated_at,omitempty"`
}

type V2ItemURL struct {
	Label     string `json:"label,omitempty"`
	URL       string `json:"url"`
	Primary   bool   `json:"primary,omitempty"`
	MatchMode string `json:"match_mode,omitempty"`
}

type V2Section struct {
	ID     string          `json:"id"`
	Title  string          `json:"title"`
	Fields []V2CustomField `json:"fields,omitempty"`
}

type V2CustomField struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Concealed bool   `json:"concealed,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
}

type V2CreditCard struct {
	CardholderName string `json:"cardholder_name,omitempty"`
	Type           string `json:"type,omitempty"`
	Number         string `json:"number,omitempty"`
	Verification   string `json:"verification,omitempty"`
	ExpiryDate     string `json:"expiry_date,omitempty"`
	ValidFrom      string `json:"valid_from,omitempty"`
	PIN            string `json:"pin,omitempty"`
	IssuingBank    string `json:"issuing_bank,omitempty"`
}

type V2Identity struct {
	Title          string `json:"title,omitempty"`
	FirstName      string `json:"first_name,omitempty"`
	MiddleName     string `json:"middle_name,omitempty"`
	LastName       string `json:"last_name,omitempty"`
	BirthDate      string `json:"birth_date,omitempty"`
	Company        string `json:"company,omitempty"`
	Department     string `json:"department,omitempty"`
	JobTitle       string `json:"job_title,omitempty"`
	Email          string `json:"email,omitempty"`
	Phone          string `json:"phone,omitempty"`
	AddressLine1   string `json:"address_line1,omitempty"`
	AddressLine2   string `json:"address_line2,omitempty"`
	City           string `json:"city,omitempty"`
	State          string `json:"state,omitempty"`
	PostalCode     string `json:"postal_code,omitempty"`
	Country        string `json:"country,omitempty"`
	SSN            string `json:"ssn,omitempty"`
	PassportNumber string `json:"passport_number,omitempty"`
	LicenseNumber  string `json:"license_number,omitempty"`
	Website        string `json:"website,omitempty"`
}

// VaultPath returns the authenticated vault path, or "" when locked.
func (s *Session) VaultPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil {
		return ""
	}
	return s.path
}

// Meta projects the v2 metadata of one item directly from the authenticated
// durable record. It returns nil when the session is locked or the item does
// not exist, and never exposes process-local state.
func (s *Session) Meta(id string) *V2ItemMeta {
	if s == nil || !idOK(id) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, _, err := s.authenticatedItemLocked(id)
	if err != nil {
		return nil
	}
	return V2MetaFromItem(item)
}

// PatchMeta applies patch to the authenticated projection and persists the
// complete item through one exact-revision audited mutation. It returns an
// error instead of falling back to memory-only metadata when the vault refuses
// or the revision moved.
func (s *Session) PatchMeta(id string, patch func(*V2ItemMeta)) error {
	return s.persistMeta(id, patch)
}

// ReadAuthenticatedItems opens a single authenticated read-only view and
// returns the authenticated items plus the signed revision map. Every supported
// item kind is returned so browser search, detail, match and watchtower view
// the same durable records the desktop vault owns.
// SSHSeed and Passkey backing bytes are cleared before return; their lengths
// retain presence flags. Key operations and public passkey metadata use their
// dedicated authenticated transaction paths rather than cloning secret records.
func (s *Session) ReadAuthenticatedItems(touch bool) ([]vault.Item, map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(touch); e != nil {
		return nil, nil, e
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return nil, nil, e
	}
	var items []vault.Item
	var auditCandidate *auditCache
	revisions := map[string]string{}
	e = db.View(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, "item.list", s)
		if e != nil {
			return e
		}
		defer a.clear()
		auditCandidate = a.nextCache
		for _, it := range a.items {
			items = append(items, it)
		}
		for id, rev := range a.revisions {
			revisions[id] = rev
		}
		return nil
	})
	if closeErr := db.Close(); closeErr != nil && e == nil {
		e = ErrCommandClose
	}
	if errors.Is(e, invalid) {
		s.lock()
	}
	if e != nil {
		return nil, nil, e
	}
	if s.active(false) != nil {
		return nil, nil, ErrSessionLocked
	}
	s.setAuditCache(auditCandidate)
	return items, revisions, nil
}

// ---------------------------------------------------------------------------
// Watchtower summary
// ---------------------------------------------------------------------------

func strengthCategory(score int) string {
	switch {
	case score <= 26:
		return "terrible"
	case score <= 44:
		return "weak"
	case score <= 53:
		return "fair"
	case score <= 60:
		return "good"
	case score <= 73:
		return "very-good"
	case score <= 85:
		return "excellent"
	default:
		return "fantastic"
	}
}

func passwordStrength(password string) (int, []string) {
	flags := []string{}
	if password == "" {
		return 0, []string{"empty"}
	}
	runes := []rune(password)
	length := len(runes)
	distinct := map[rune]bool{}
	for _, r := range runes {
		distinct[r] = true
	}
	variety := len(distinct)
	if length < 12 {
		flags = append(flags, "short")
	}
	if variety < 4 {
		flags = append(flags, "low-variety")
	}
	switch strings.ToLower(password) {
	case "password", "password123", "123456", "12345678", "123456789", "1234567890", "qwerty", "qwerty123", "letmein", "welcome", "admin", "iloveyou":
		flags = append(flags, "common-example")
	}
	pool := 0
	var lower, upper, digit, symbol, other bool
	for _, r := range runes {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		case r >= 33 && r <= 126:
			symbol = true
		default:
			other = true
		}
	}
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
	if other {
		pool += 100
	}
	if pool < 2 {
		pool = 2
	}
	bits := float64(length) * mathLog2(float64(pool))
	ratio := float64(variety) / float64(length)
	if ratio > 0.85 {
		ratio = 0.85
	}
	bits *= 0.55 + ratio*0.45
	for _, f := range flags {
		switch f {
		case "common-example":
			if bits > 18 {
				bits = 18
			}
		case "short":
			if bits > 32 {
				bits = 32
			}
		case "low-variety":
			if bits > 20 {
				bits = 20
			}
		}
	}
	if digit && !lower && !upper && !symbol && !other {
		bits *= 0.65
	}
	if bits < 0 {
		bits = 0
	}
	score := int(bits * 100 / 78)
	if score > 100 {
		score = 100
	}
	return score, flags
}

// mathLog2 avoids a math import solely for a bounded logarithm.
func mathLog2(v float64) float64 {
	if v <= 0 {
		return 0
	}
	n := 0.0
	for v >= 2 {
		v /= 2
		n++
	}
	for v < 1 {
		v *= 2
		n--
	}
	x := v - 1
	term := x
	sum := 0.0
	for i := 1; i <= 20; i++ {
		sum += term / float64(i)
		term *= -x
	}
	return n + sum/0.6931471805599453
}

// WatchtowerItemFinding is a non-secret per-item summary.
type WatchtowerItemFinding struct {
	ID               string   `json:"id"`
	Revision         string   `json:"revision"`
	Title            string   `json:"title"`
	Origin           string   `json:"origin"`
	Flags            []string `json:"flags"`
	StrengthScore    int      `json:"strength_score"`
	StrengthCategory string   `json:"strength_category"`
	ReuseCount       int      `json:"reuse_count"`
	BreachCount      int      `json:"breach_count"`
}

// WatchtowerSummaryResult is the internal aggregate returned to browserhost.
type WatchtowerSummaryResult struct {
	OverallScore int
	Checked      int
	Counts       map[string]int
	SiteFindings []WatchtowerItemFinding
	Findings     []WatchtowerItemFinding
}

func passwordCategory(it vault.Item) bool {
	switch it.EffectiveCategory() {
	case vault.CategoryLogin, vault.CategoryPassword:
		return true
	}
	return false
}

func cardExpiry(expiryDate string) (time.Time, bool) {
	if expiryDate == "" {
		return time.Time{}, false
	}
	t, e := time.Parse("2006-01", expiryDate)
	if e != nil {
		return time.Time{}, false
	}
	// A card is valid through the end of its expiry month.
	return t.AddDate(0, 1, 0), true
}

func insecureHTTP(raw string) bool {
	if !strings.HasPrefix(strings.ToLower(raw), "http://") {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil {
		return true
	}
	host := strings.ToLower(u.Hostname())
	return host != "localhost" && host != "127.0.0.1" && host != "::1"
}

// WatchtowerSummary computes local Watchtower findings and records the
// authenticated local health audit.
func (s *Session) WatchtowerSummary(originFilter string) (WatchtowerSummaryResult, error) {
	return s.watchtowerSummary(originFilter, true)
}

// WatchtowerSummaryLocal computes the same view without writing a health audit.
// It is used for informational per-item badges during search/item-get.
func (s *Session) WatchtowerSummaryLocal(originFilter string) (WatchtowerSummaryResult, error) {
	return s.watchtowerSummary(originFilter, false)
}

func (s *Session) watchtowerSummary(originFilter string, audit bool) (WatchtowerSummaryResult, error) {
	if audit {
		if _, e := s.Health(); e != nil {
			return WatchtowerSummaryResult{}, e
		}
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return WatchtowerSummaryResult{}, e
	}
	counts := map[string]int{}
	for _, it := range items {
		if it.State != "" || it.Password == "" || !passwordCategory(it) {
			continue
		}
		counts[it.Password]++
	}
	now := time.Now()
	result := WatchtowerSummaryResult{Counts: map[string]int{"vulnerable": 0, "reused": 0, "weak": 0, "unsecured_http": 0, "totp_not_stored": 0, "expiring": 0}}
	total := 0
	scored := 0
	for _, it := range items {
		if it.State != "" {
			continue
		}
		rev, ok := revisions[it.ID]
		if !ok || !idOK(it.ID) || !digestOK(rev) {
			return WatchtowerSummaryResult{}, invalid
		}
		if !passwordCategory(it) {
			continue
		}
		score, strengthFlags := passwordStrength(it.Password)
		flags := make([]string, 0, 8)
		weak := score <= 44
		flags = append(flags, strengthFlags...)
		if weak {
			flags = append(flags, "weak")
		}
		reuse := 0
		if it.Password != "" && counts[it.Password] > 1 {
			reuse = counts[it.Password]
			flags = append(flags, "reused")
		}
		unsecured := insecureHTTP(it.URL)
		if !unsecured {
			for _, u := range it.URLs {
				if insecureHTTP(u.URL) {
					unsecured = true
					break
				}
			}
		}
		if unsecured {
			flags = append(flags, "unsecured-http")
		}
		if it.OTP == "" && len(it.PasskeyRecords()) == 0 {
			flags = append(flags, "totp-not-stored")
		}
		if card := it.NormalizedCreditCard(); card != nil {
			if expiry, ok := cardExpiry(card.ExpiryDate); ok {
				if !now.Before(expiry) {
					flags = append(flags, "expired")
				} else if !expiry.After(now.Add(30 * 24 * time.Hour)) {
					flags = append(flags, "expiring-soon")
				}
			}
		}
		if len(flags) > 0 {
			category := strengthCategory(score)
			f := WatchtowerItemFinding{ID: it.ID, Revision: rev, Title: it.Title, Origin: websiteOrEmpty(it.URL), Flags: dedupeStrings(flags), StrengthScore: score, StrengthCategory: category, ReuseCount: reuse}
			result.Findings = append(result.Findings, f)
			if weak {
				result.Counts["weak"]++
			}
			if reuse > 0 {
				result.Counts["reused"]++
			}
			if unsecured {
				result.Counts["unsecured_http"]++
			}
			if includesString(flags, "totp-not-stored") {
				result.Counts["totp_not_stored"]++
			}
			if includesString(flags, "expiring-soon") || includesString(flags, "expired") {
				result.Counts["expiring"]++
			}
			if originFilter != "" && (websiteOrEmpty(it.URL) == originFilter || it.URL == originFilter) {
				result.SiteFindings = append(result.SiteFindings, f)
			}
		}
		total += score
		scored++
	}
	result.Checked = scored
	if scored == 0 {
		result.OverallScore = 100
	} else {
		result.OverallScore = total / scored
	}
	if result.SiteFindings == nil {
		result.SiteFindings = []WatchtowerItemFinding{}
	}
	if result.Findings == nil {
		result.Findings = []WatchtowerItemFinding{}
	}
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].ID < result.Findings[j].ID })
	sort.Slice(result.SiteFindings, func(i, j int) bool { return result.SiteFindings[i].ID < result.SiteFindings[j].ID })
	return result, nil
}

func websiteOrEmpty(raw string) string {
	if raw == "" {
		return ""
	}
	site, e := origin.Website(raw)
	if e != nil {
		return ""
	}
	return site
}

func includesString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// ---------------------------------------------------------------------------
// F17 CLI run broker targets
// ---------------------------------------------------------------------------

type CLIBrokerTarget struct {
	Slot     string `json:"slot"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Field    string `json:"field"`
}

func validCLIBrokerField(field string) bool {
	switch field {
	case "username", "password", "url", "notes", "otp":
		return true
	}
	return false
}

// ExtractCLIBrokerTargets validates every target in one authenticated view and
// discloses the pinned values only when all of them are current and active.
func (s *Session) ExtractCLIBrokerTargets(targets []CLIBrokerTarget) (map[string]string, error) {
	if len(targets) < 1 || len(targets) > 16 {
		return nil, ErrRunCredential
	}
	for _, t := range targets {
		if !idOK(t.ID) || !digestOK(t.Revision) || t.Slot == "" || len(t.Slot) > 128 || !validCLIBrokerField(t.Field) || !utf8.ValidString(t.Slot) {
			return nil, ErrRunCredential
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.extractCLIBrokerTargetsLocked(targets)
}

func (s *Session) extractCLIBrokerTargetsLocked(targets []CLIBrokerTarget) (map[string]string, error) {
	values := map[string]string{}
	if e := s.active(true); e != nil {
		return nil, e
	}
	db, e := existing(s.path)
	if e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	e = db.Update(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, "item.list", s)
		if e != nil {
			return e
		}
		defer a.clear()
		b := tx.Bucket(bucket)
		if b == nil {
			return invalid
		}
		byID := map[string]vault.Item{}
		for _, it := range a.items {
			byID[it.ID] = it
		}
		for _, t := range targets {
			it, ok := byID[t.ID]
			if !ok {
				return ErrNotFound
			}
			if t.Field == "password" && !passwordCategory(it) {
				return ErrRunCredential
			}
			if it.State == "trashed" {
				return ErrTrashed
			}
			if it.State != "" {
				return ErrNotFound
			}
			if a.revisions[t.ID] != t.Revision {
				return ErrConflict
			}
			if seen[t.Slot] {
				return ErrRunCredential
			}
			seen[t.Slot] = true
			switch t.Field {
			case "username":
				values[t.Slot] = it.Username
			case "password":
				values[t.Slot] = it.Password
			case "url":
				values[t.Slot] = it.URL
			case "notes":
				values[t.Slot] = it.Notes
			case "otp":
				values[t.Slot] = it.OTP
			}
		}
		tip := a.tip
		for _, t := range targets {
			action := "item.desktop.show.username"
			if t.Field == "password" {
				action = "item.desktop.show.password"
			} else if t.Field == "notes" {
				action = "item.desktop.show.notes"
			} else if t.Field == "otp" {
				action = desktopOTPShowAction
			}
			ev, err := appendLinked(b, a.identity, tip, a.snapshot, action, t.ID, "intent", t.Revision, "", eventDetails{})
			if err != nil {
				return err
			}
			tip = auditTip{Count: ev.Sequence, Last: ev.hash(), Origin: tip.Origin}
		}
		return nil
	})
	if closeErr := db.Close(); closeErr != nil && e == nil {
		e = ErrCommandClose
	}
	if errors.Is(e, invalid) {
		s.lock()
	}
	if e != nil {
		for k := range values {
			values[k] = ""
		}
		return nil, e
	}
	if s.active(false) != nil {
		for k := range values {
			values[k] = ""
		}
		return nil, ErrSessionLocked
	}
	return values, nil
}

// SetV2State persists favorite through the durable whole-item favorite
// mutation and maps lifecycle actions onto the real state machine. Every action
// advances the signed revision and survives a reopen.
func (s *Session) SetV2State(id, revision, action string) (string, string, error) {
	switch action {
	case "favorite", "unfavorite":
		if !idOK(id) || !digestOK(revision) {
			return "", "", ErrMutationRefused
		}
		// Read the authenticated state first so a stale revision is refused
		// before any mutation is attempted.
		detail, e := s.GetItemDetail(id, revision, false)
		if e != nil {
			return "", "", e
		}
		gate := NewMutationGate(time.Now().Add(30 * time.Second))
		if e := s.RegisterMutation(gate); e != nil {
			return "", "", ErrMutationCancelled
		}
		next, e := s.SetFavorite(id, revision, action == "favorite", gate)
		if e != nil {
			return "", "", e
		}
		return next, detail.State, nil
	case "archive", "unarchive", "trash", "untrash":
		mapped := map[string]string{"archive": "item.archive", "unarchive": "item.unarchive", "trash": "item.trash", "untrash": "item.untrash"}[action]
		rev, e := s.SetState(id, revision, mapped)
		if e != nil {
			return "", "", e
		}
		state := "active"
		if action == "archive" {
			state = "archived"
		}
		if action == "trash" {
			state = "trashed"
		}
		return rev, state, nil
	}
	return "", "", ErrMutationRefused
}

// ActiveItems returns cloned active login items and their signed revisions.
func (s *Session) ActiveItems() ([]vault.Item, map[string]string, error) {
	return s.AllItems("active")
}

// AllItems returns cloned login items filtered by state ("active", "archived",
// "trashed", "all" or "").
func (s *Session) AllItems(state string) ([]vault.Item, map[string]string, error) {
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil {
		return nil, nil, e
	}
	out := make([]vault.Item, 0, len(items))
	for _, it := range items {
		actual := it.State
		if actual == "" {
			actual = "active"
		}
		if state == "" || state == "all" || actual == state {
			out = append(out, it)
		}
	}
	return out, revisions, nil
}

// AuditV2Disclosure commits an authenticated intent event before a popup field
// value is returned. The event uses the existing bounded disclosure actions so
// the signed journal remains verifiable by older readers.
func (s *Session) AuditV2Disclosure(id, revision, field string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(false); e != nil {
		return e
	}
	if !idOK(id) || !digestOK(revision) {
		return invalid
	}
	action := "item.desktop.show.username"
	switch {
	case field == "password", field == "cc-number", field == "cc-csc", field == "cc-pin":
		action = "item.desktop.show.password"
	case field == "notes":
		action = "item.desktop.show.notes"
	case field == "otp":
		action = desktopOTPShowAction
	}
	db, e := existing(s.path)
	if e != nil {
		return e
	}
	e = db.Update(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, "item.list", s)
		if e != nil {
			return e
		}
		defer a.clear()
		b := tx.Bucket(bucket)
		if b == nil {
			return invalid
		}
		if a.revisions[id] != revision {
			return ErrConflict
		}
		_, e = appendLinked(b, a.identity, a.tip, a.snapshot, action, id, "intent", revision, "", eventDetails{})
		return e
	})
	if closeErr := db.Close(); closeErr != nil && e == nil {
		e = ErrCommandClose
	}
	if errors.Is(e, invalid) {
		s.lock()
	}
	return e
}
