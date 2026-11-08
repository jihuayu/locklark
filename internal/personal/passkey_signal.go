package personal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// item.passkey.signal records one bounded, owner-approved application of a
// WebAuthn signal API hint. One event is appended per affected login inside the
// same transaction, so the signed history keeps a single-item, replayable shape.
const passkeySignalAction = "item.passkey.signal"

const (
	// MaxPasskeySignalOptions bounds the options document before the strict
	// duplicate/unknown key walk.
	MaxPasskeySignalOptions = 32 << 10
	// MaxPasskeySignalChanges caps one review. A larger match set is ignored in
	// full: a destructive signal must never be applied partially.
	MaxPasskeySignalChanges = 50
	// MaxPasskeySignalAcceptedIDs is the WebAuthn accepted-credential bound.
	MaxPasskeySignalAcceptedIDs = 64

	PasskeySignalUnknown  = "unknown"
	PasskeySignalAccepted = "accepted"
	PasskeySignalUser     = "user"
)

// PasskeySignalRequest is the parsed, still page-supplied hint. Origin is the
// browser-asserted origin; it is never taken from the options document.
type PasskeySignalRequest struct {
	Kind         string
	Origin       string
	RPID         string
	CredentialID string
	UserID       string
	Accepted     []string
	Name         string
	DisplayName  string
}

// PasskeySignalChange is the safe owner-facing projection of one affected
// row. It never carries the stored UserID, private key or raw record.
type PasskeySignalChange struct {
	Action       string
	ItemID       string
	Revision     string
	Title        string
	Username     string
	CredentialID string
	Name         string
	DisplayName  string
}

// PasskeySignalProposal is the bounded review shown by the native owner UI.
type PasskeySignalProposal struct {
	Changes []PasskeySignalChange
}

func (PasskeySignalRequest) String() string    { return "[passkey signal request]" }
func (PasskeySignalRequest) GoString() string  { return "[passkey signal request]" }
func (PasskeySignalProposal) String() string   { return "[passkey signal proposal]" }
func (PasskeySignalProposal) GoString() string { return "[passkey signal proposal]" }

func decodeSignalID(value string, min, max int) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return decoded, err == nil && len(decoded) >= min && len(decoded) <= max && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// validSignalCredentialID accepts the canonical un-padded base64url encoding of
// a 1..1024 byte credential id. Only a stored 32-byte id can ever match.
func validSignalCredentialID(value string) bool {
	_, ok := decodeSignalID(value, 1, 1024)
	return ok
}

func validSignalUserID(value string) bool {
	_, ok := decodeSignalID(value, 1, 64)
	return ok
}

// signalTextOK mirrors the stored record's text policy: valid UTF-8, at most
// 1024 bytes and no NUL/CR/LF that could forge a native UI line.
func signalTextOK(value string) bool {
	return len(value) <= 1024 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

// Valid re-checks the complete shape, including the RP policy against the
// browser-asserted origin. The page cannot supply its own origin: rpId must be
// a registrable suffix of the actual origin, private suffixes included.
func (r PasskeySignalRequest) Valid() bool {
	if !passkey.ValidRP(r.Origin, r.RPID) {
		return false
	}
	switch r.Kind {
	case PasskeySignalUnknown:
		return validSignalCredentialID(r.CredentialID) && r.UserID == "" && len(r.Accepted) == 0 && r.Name == "" && r.DisplayName == ""
	case PasskeySignalAccepted:
		if r.CredentialID != "" || !validSignalUserID(r.UserID) || r.Name != "" || r.DisplayName != "" || len(r.Accepted) > MaxPasskeySignalAcceptedIDs {
			return false
		}
		for _, id := range r.Accepted {
			if !validSignalCredentialID(id) {
				return false
			}
		}
		return true
	case PasskeySignalUser:
		return r.CredentialID == "" && validSignalUserID(r.UserID) && len(r.Accepted) == 0 && signalTextOK(r.Name) && signalTextOK(r.DisplayName)
	}
	return false
}

func signalString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func signalStringList(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil {
		return nil, false
	}
	return values, true
}

func signalExactKeys(fields map[string]json.RawMessage, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

// signalDuplicateKeys rejects duplicate object keys at every depth (case
// folded) before the map/struct decode can silently keep the last value.
func signalDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return passkey.ErrRefused
		}
		token, err := dec.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[strings.ToLower(name)] {
					return passkey.ErrRefused
				}
				seen[strings.ToLower(name)] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return passkey.ErrRefused
	}
	return nil
}

// signalStrictUnicode rejects invalid UTF-8 and lone surrogate escapes that
// encoding/json would otherwise silently replace with U+FFFD.
func signalStrictUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for n := 0; n < len(raw); n++ {
		if raw[n] != '"' {
			continue
		}
		n++
		for ; n < len(raw) && raw[n] != '"'; n++ {
			if raw[n] != '\\' {
				continue
			}
			n++
			if n >= len(raw) || raw[n] != 'u' {
				continue
			}
			if n+4 >= len(raw) {
				return false
			}
			value, err := parseHex4(raw[n+1 : n+5])
			if err != nil {
				return false
			}
			n += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			if value >= 0xd800 && value <= 0xdbff {
				if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
					return false
				}
				low, err := parseHex4(raw[n+3 : n+7])
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				n += 6
			}
		}
	}
	return true
}

func parseHex4(raw []byte) (uint64, error) {
	var value uint64
	for _, c := range raw {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, passkey.ErrRefused
		}
		value = value<<4 | uint64(c)
	}
	return value, nil
}

// ParsePasskeySignal strictly parses the exact WebAuthn3 signal dictionaries:
//
//	signalUnknownCredential        {rpId, credentialId}
//	signalAllAcceptedCredentials   {rpId, userId, allAcceptedCredentialIds}
//	signalCurrentUserDetails       {rpId, userId, name, displayName}
//
// The "kind" discriminator is a native wire extension. Every other key is the
// standard dictionary member name; unknown keys, wrong types, duplicate keys,
// oversize input and a cross-origin rpId are refused before any lookup.
func ParsePasskeySignal(origin string, raw []byte) (PasskeySignalRequest, error) {
	if len(raw) == 0 || len(raw) > MaxPasskeySignalOptions || !signalStrictUnicode(raw) {
		return PasskeySignalRequest{}, passkey.ErrRefused
	}
	if signalDuplicateKeys(raw) != nil {
		return PasskeySignalRequest{}, passkey.ErrRefused
	}
	fields := map[string]json.RawMessage{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(&fields) != nil || fields == nil {
		return PasskeySignalRequest{}, passkey.ErrRefused
	}
	if dec.Decode(new(any)) != io.EOF {
		return PasskeySignalRequest{}, passkey.ErrRefused
	}
	kind, ok := signalString(fields["kind"])
	if !ok {
		return PasskeySignalRequest{}, passkey.ErrRefused
	}
	out := PasskeySignalRequest{Kind: kind, Origin: origin}
	switch kind {
	case PasskeySignalUnknown:
		if !signalExactKeys(fields, "kind", "rpId", "credentialId") {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.RPID, ok = signalString(fields["rpId"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.CredentialID, ok = signalString(fields["credentialId"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
	case PasskeySignalAccepted:
		if !signalExactKeys(fields, "kind", "rpId", "userId", "allAcceptedCredentialIds") {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.RPID, ok = signalString(fields["rpId"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.UserID, ok = signalString(fields["userId"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.Accepted, ok = signalStringList(fields["allAcceptedCredentialIds"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
	case PasskeySignalUser:
		if !signalExactKeys(fields, "kind", "rpId", "userId", "name", "displayName") {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.RPID, ok = signalString(fields["rpId"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.UserID, ok = signalString(fields["userId"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.Name, ok = signalString(fields["name"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
		if out.DisplayName, ok = signalString(fields["displayName"]); !ok {
			return PasskeySignalRequest{}, passkey.ErrRefused
		}
	default:
		return PasskeySignalRequest{}, passkey.ErrRefused
	}
	if !out.Valid() {
		return PasskeySignalRequest{}, passkey.ErrRefused
	}
	return out, nil
}

// signalMatch decides whether one stored record is affected by the hint and
// builds the metadata-only projection. Stored records are only ever matched by
// their exact RP, credential id and (for accepted/user) exact user id.
func signalMatch(r PasskeySignalRequest, item vault.Item, revision string, record *passkey.Record) (PasskeySignalChange, bool) {
	if record == nil || record.RPID != r.RPID {
		return PasskeySignalChange{}, false
	}
	change := PasskeySignalChange{ItemID: item.ID, Revision: revision, Title: item.Title, Username: item.Username, CredentialID: record.ID}
	switch r.Kind {
	case PasskeySignalUnknown:
		if record.ID != r.CredentialID {
			return PasskeySignalChange{}, false
		}
		change.Action = "remove"
	case PasskeySignalAccepted:
		if record.UserID != r.UserID {
			return PasskeySignalChange{}, false
		}
		for _, accepted := range r.Accepted {
			if accepted == record.ID {
				return PasskeySignalChange{}, false
			}
		}
		change.Action = "remove"
	case PasskeySignalUser:
		if record.UserID != r.UserID {
			return PasskeySignalChange{}, false
		}
		if record.Name == r.Name && record.DisplayName == r.DisplayName {
			return PasskeySignalChange{}, false
		}
		change.Action = "update"
		change.Name, change.DisplayName = r.Name, r.DisplayName
	default:
		return PasskeySignalChange{}, false
	}
	return change, true
}

func passkeySignalEligible(item vault.Item) bool {
	return item.Kind == "login" && item.State == "" && item.EffectiveCategory() == vault.CategoryLogin && len(item.PasskeyRecords()) > 0
}

// ReviewPasskeySignal enumerates the bounded owner-approval proposal for one
// hint. It is strictly read-only: no MutationGate, no audit event, no signed
// snapshot rewrite and no idle touch, so a page cannot use a signal hint to
// renew a session. More than MaxPasskeySignalChanges matches are ignored in
// full instead of being silently truncated.
func (s *Session) ReviewPasskeySignal(r PasskeySignalRequest) (PasskeySignalProposal, error) {
	if s == nil {
		return PasskeySignalProposal{}, ErrSessionLocked
	}
	if !r.Valid() {
		return PasskeySignalProposal{}, passkey.ErrRefused
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil {
		return PasskeySignalProposal{}, ErrSessionLocked
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return PasskeySignalProposal{}, passkey.ErrRefused
	}
	changes := []PasskeySignalChange{}
	ignored := false
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyGetAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		for _, item := range auth.items {
			if !passkeySignalEligible(item) {
				continue
			}
			revision := auth.revisions[item.ID]
			if revision == "" {
				continue
			}
			// Every durable credential of the login is considered, so one login
			// with several credentials contributes one row per affected credential.
			for _, raw := range item.PasskeyRecords() {
				record, err := passkey.Load(raw)
				if err != nil {
					continue
				}
				change, matched := signalMatch(r, item, revision, record)
				record.Clear()
				if !matched {
					continue
				}
				changes = append(changes, change)
				if len(changes) > MaxPasskeySignalChanges {
					ignored = true
					changes = nil
					return nil
				}
			}
		}
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil || closeErr != nil {
		return PasskeySignalProposal{}, passkey.ErrRefused
	}
	if s.active(false) != nil {
		return PasskeySignalProposal{}, passkey.ErrRefused
	}
	if ignored {
		return PasskeySignalProposal{Changes: []PasskeySignalChange{}}, nil
	}
	sort.SliceStable(changes, func(a, b int) bool {
		if changes[a].ItemID != changes[b].ItemID {
			return changes[a].ItemID < changes[b].ItemID
		}
		return changes[a].CredentialID < changes[b].CredentialID
	})
	return PasskeySignalProposal{Changes: changes}, nil
}

func validPasskeySignalChanges(r PasskeySignalRequest, changes []PasskeySignalChange) bool {
	if len(changes) == 0 || len(changes) > MaxPasskeySignalChanges {
		return false
	}
	// One reviewed row names exactly one credential, so the uniqueness key is
	// the (item, credential) pair: a login may legitimately contribute several
	// rows, one per affected credential, but never the same credential twice.
	seen := map[[2]string]bool{}
	for _, change := range changes {
		if !idOK(change.ItemID) || !digestOK(change.Revision) || !validSignalCredentialID(change.CredentialID) {
			return false
		}
		pair := [2]string{change.ItemID, change.CredentialID}
		if seen[pair] {
			return false
		}
		seen[pair] = true
		switch change.Action {
		case "remove":
			if r.Kind == PasskeySignalUser || change.Name != "" || change.DisplayName != "" {
				return false
			}
			if r.Kind == PasskeySignalUnknown && change.CredentialID != r.CredentialID {
				return false
			}
		case "update":
			if r.Kind != PasskeySignalUser || !signalTextOK(change.Name) || !signalTextOK(change.DisplayName) {
				return false
			}
			// An update renames the exact stored record only. Any proposal that
			// claims other values is refused rather than "repaired".
			if change.Name != r.Name || change.DisplayName != r.DisplayName {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// passkeySignalBinding HMAC-binds the signal dictionary and every reviewed
// selector to the audit link. Raw values (including the page user id) never
// appear in the journal; only this keyed digest is stored.
func passkeySignalBinding(key []byte, r PasskeySignalRequest, changes []PasskeySignalChange) (string, error) {
	type selector struct{ Action, ItemID, Revision, CredentialID, Name, DisplayName string }
	rows := make([]selector, len(changes))
	for n, change := range changes {
		rows[n] = selector{change.Action, change.ItemID, change.Revision, change.CredentialID, change.Name, change.DisplayName}
	}
	raw, err := json.Marshal(struct {
		Version                                                       int
		Kind, Origin, RPID, CredentialID, UserID, Name, DisplayName   string
		Accepted                                                      []string
		Changes                                                       []selector
	}{1, r.Kind, r.Origin, r.RPID, r.CredentialID, r.UserID, r.Name, r.DisplayName, r.Accepted, rows})
	if err != nil {
		return "", ErrMutationRefused
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("locklark/passkey-signal/v1\x00"))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// signalChangePredicate rechecks one reviewed row against the durable record it
// names: exact credential id, exact RP, exact WebAuthn user handle and the same
// kind-specific membership or difference rule that made the review match it.
// It is the only definition of "this row still affects this credential".
func signalChangePredicate(r PasskeySignalRequest, change PasskeySignalChange, record *passkey.Record) bool {
	if record == nil || record.ID != change.CredentialID || record.RPID != r.RPID {
		return false
	}
	if r.Kind != PasskeySignalUnknown && record.UserID != r.UserID {
		return false
	}
	if change.Action == "remove" {
		if r.Kind == PasskeySignalUser {
			return false
		}
		if r.Kind == PasskeySignalAccepted {
			// The accepted dictionary is authoritative: the page has just
			// asserted this exact credential still exists for this user, so a
			// forged or stale proposal may never remove it.
			for _, accepted := range r.Accepted {
				if accepted == record.ID {
					return false
				}
			}
		}
		return true
	}
	// An update renames the exact stored record only, and must still differ:
	// identical names are a stale review, not a no-op write.
	return change.Action == "update" && r.Kind == PasskeySignalUser && (record.Name != r.Name || record.DisplayName != r.DisplayName)
}

// applyPasskeySignalChange rewrites one owned item clone so exactly one
// credential is removed or renamed. Every sibling record is retained byte for
// byte; a login still stored in the legacy single-record form keeps that form
// on update, and removing the last credential clears both persisted forms.
func applyPasskeySignalChange(next *vault.Item, change PasskeySignalChange) error {
	records := next.PasskeyRecords()
	if len(records) == 0 {
		return ErrMutationRefused
	}
	collection := len(next.Passkeys) > 0
	remaining := make([][]byte, 0, len(records))
	var encoded []byte
	defer func() { clear(encoded) }()
	matched := false
	for _, raw := range records {
		record, err := passkey.Load(raw)
		if err != nil {
			// An unreadable sibling can never be silently dropped or rewritten.
			return ErrMutationRefused
		}
		hit := record.ID == change.CredentialID
		if !hit {
			record.Clear()
			remaining = append(remaining, raw)
			continue
		}
		if matched {
			record.Clear()
			return ErrMutationRefused
		}
		matched = true
		if change.Action == "remove" {
			record.Clear()
			continue
		}
		updated := passkey.Record{
			Version:     record.Version,
			ID:          record.ID,
			RPID:        record.RPID,
			UserID:      record.UserID,
			Name:        change.Name,
			DisplayName: change.DisplayName,
			PrivateKey:  append([]byte(nil), record.PrivateKey...),
		}
		record.Clear()
		encoded, err = json.Marshal(updated)
		clear(updated.PrivateKey)
		if err != nil || !passkey.ValidRecord(encoded) {
			clear(encoded)
			return ErrMutationRefused
		}
		remaining = append(remaining, encoded)
	}
	if !matched {
		return ErrMutationRefused
	}
	if len(remaining) == 0 {
		// The last credential is gone: both persisted forms are cleared so the
		// login cannot keep an empty-but-present passkey slot.
		next.ClearPasskeys()
		clear(encoded)
		return nil
	}
	// The retain-form helpers clone before zeroing the borrowed durable bytes.
	var err error
	if collection {
		err = next.SetPasskeyRecords(remaining)
	} else {
		err = next.SetLegacyPasskey(remaining[0])
	}
	clear(encoded)
	return err
}

// ApplyPasskeySignal applies one owner-confirmed proposal. Every reviewed row is
// revalidated inside one authenticated write transaction before the single
// commit gate is won: item id, the original parent revision of that item, active
// login state and the exact stored record named by the row, including RP, user
// handle and the kind-specific predicate. Any stale or forged row refuses the
// whole batch without a write.
//
// Each row then applies exactly one credential change to an owned item clone
// (siblings are retained byte for byte) and seals its own intermediate snapshot
// with one linked single-item audit event. Multiple rows of the same login share
// the same parent revision only for the first event: the second event names the
// first event's hash as its base revision, so cold journal replay folds a login's
// events in exactly the order they were committed. Everything happens in one
// Bolt transaction, so a failure never commits a partial batch.
func (s *Session) ApplyPasskeySignal(r PasskeySignalRequest, changes []PasskeySignalChange, g *MutationGate) (string, error) {
	if s == nil {
		if g != nil {
			g.Cancel()
		}
		return "", ErrMutationRefused
	}
	if !r.Valid() || !validPasskeySignalChanges(r, changes) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	defer s.ReleaseMutation(g)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registeredMutation(g) || s.active(true) != nil {
		return "", ErrMutationCancelled
	}
	db, err := existing(s.path)
	if err != nil {
		return "", ErrMutationRefused
	}
	var nextRevision string
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeySignalAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		rows := make(map[string]int, len(changes))
		for _, change := range changes {
			if _, resolved := rows[change.ItemID]; !resolved {
				row := -1
				for k := range auth.items {
					if auth.items[k].ID != change.ItemID {
						continue
					}
					if row >= 0 {
						return invalid
					}
					row = k
				}
				if row < 0 {
					return ErrNotFound
				}
				rows[change.ItemID] = row
			}
			// The reviewed parent revision must still be the item's original
			// revision: every row of one login was reviewed against it.
			if auth.revisions[change.ItemID] != change.Revision {
				return ErrConflict
			}
			current := auth.items[rows[change.ItemID]]
			if current.State != "" || current.Kind != "login" || current.EffectiveCategory() != vault.CategoryLogin {
				return ErrMutationRefused
			}
			matched := false
			for _, raw := range current.PasskeyRecords() {
				record, err := passkey.Load(raw)
				if err != nil {
					continue
				}
				hit := signalChangePredicate(r, change, record)
				record.Clear()
				if hit {
					matched = true
				}
			}
			if !matched {
				return ErrMutationRefused
			}
		}
		// Every selector is now verified. Win the one-shot decision before any
		// revocation or write; a win is not yet a persistence receipt.
		if !s.winBrowserSave(g) {
			return ErrMutationCancelled
		}
		// Conservative revocation: even if a later seal/audit append fails, a
		// credential removal never leaves queued signatures valid elsewhere.
		for _, change := range changes {
			if change.Action == "remove" {
				s.passkeyEpoch.Add(1)
				break
			}
		}
		link, err := passkeySignalBinding(auth.identity.AuditEncryption, r, changes)
		if err != nil {
			return err
		}
		items := append([]vault.Item(nil), auth.items...)
		tip, snapshot := auth.tip, auth.snapshot
		// parent holds the revision each new event must name as its base. It
		// starts as the original authenticated revisions and advances to the
		// previous event of the same login, so a second row of one login never
		// re-uses the reviewed revision and cold replay never breaks.
		parent := make(map[string]string, len(auth.revisions))
		for id, revision := range auth.revisions {
			parent[id] = revision
		}
		// Every clone created below owns private passkey buffers that auth.clear
		// does not know about. Zero them on success and on every error exit.
		owned := make(map[string]*vault.Item, len(changes))
		defer func() {
			for _, item := range owned {
				item.ClearPasskeys()
			}
		}()
		for _, change := range changes {
			row := rows[change.ItemID]
			next, cloned := owned[change.ItemID]
			if !cloned {
				clone := vault.CloneItem(items[row])
				next = &clone
				owned[change.ItemID] = next
			}
			if err := applyPasskeySignalChange(next, change); err != nil {
				return err
			}
			next.UpdatedAt = time.Now().Unix()
			items[row] = *next
			if vault.ValidateItems([]byte(schema), items) != nil {
				return ErrMutationRefused
			}
			snapshot, err = seal(tx.Bucket(bucket), auth.identity, snapshot.Epoch+1, items)
			if err != nil {
				return err
			}
			event, err := appendLinked(tx.Bucket(bucket), auth.identity, tip, snapshot, passkeySignalAction, change.ItemID, "succeeded", parent[change.ItemID], link, eventDetails{})
			if err != nil {
				return err
			}
			tip = auditTip{Count: event.Sequence, Epoch: snapshot.Epoch, Last: event.hash(), Snapshot: hex.EncodeToString(snapshot.Signature), Origin: auth.tip.Origin}
			parent[change.ItemID] = event.hash()
			nextRevision = event.hash()
		}
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	active := s.active(false) == nil
	if err != nil || closeErr != nil || !active {
		if g.CommitWon() {
			return "", ErrMutationUnknown
		}
		if !active {
			return "", ErrMutationCancelled
		}
		if err != nil {
			return "", err
		}
		return "", ErrMutationRefused
	}
	if nextRevision == "" {
		return "", ErrMutationUnknown
	}
	return nextRevision, nil
}
