// Package browserhost implements the bounded native messaging channel. An
// extension's API assertions are trusted only after explicit native pairing.
package browserhost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/personal"
)

const HostName = "org.locklark.browser"
const ChromiumID = "geldnhjapnackobgknocomedmjgphnpe"
const FirefoxID = "browser@locklark.local"
const MaxInput = 256 << 10
const MaxOutput = 256 << 10

type Browser string

const (
	Chromium Browser = "chromium"
	Firefox  Browser = "firefox"
)

var ErrProtocol = errors.New("native messaging refused")
var ErrBrokerUnavailable = errors.New("desktop browser broker is unavailable")
var errDuplicateRequest = errors.New("native duplicate request ignored")
var token = regexp.MustCompile(`^[a-f0-9]{32}$`)
var revision = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Request struct {
	Options    string `json:"options,omitempty"`
	payload    *savePayload
	WindowID   int64  `json:"window_id,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	V          int    `json:"v"`
	ID         string `json:"id"`
	Type       string `json:"type"`
	Capability string `json:"capability,omitempty"`
	Origin     string `json:"origin,omitempty"`
	TabID      int64  `json:"tab_id,omitempty"`
	DocumentID string `json:"document_id,omitempty"`
	ItemID     string `json:"item_id,omitempty"`
	Revision   string `json:"revision,omitempty"`

	GenMode     string `json:"mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Digits      *bool  `json:"digits,omitempty"`
	Symbols     *bool  `json:"symbols,omitempty"`
	SaveHistory *bool  `json:"save_history,omitempty"`

	StageID        string `json:"stage_id,omitempty"`
	Title          string `json:"title,omitempty"`
	NeverForOrigin *bool  `json:"never_for_origin,omitempty"`

	Query         string `json:"query,omitempty"`
	Category      string `json:"category,omitempty"`
	VaultID       string `json:"vault_id,omitempty"`
	Tag           string `json:"tag,omitempty"`
	StateFilter   string `json:"state,omitempty"`
	FavoritesOnly *bool  `json:"favorites_only,omitempty"`
	Field         string `json:"field,omitempty"`
	FieldAction   string `json:"action,omitempty"`
	StateAction   string `json:"state_action,omitempty"`
	ItemJSON      string `json:"item_json,omitempty"`

	ProfileKind  string `json:"profile_kind,omitempty"`
	IncludeHIBP  *bool  `json:"include_hibp,omitempty"`
	desktopShare bool
}

func (r Request) Context() personal.BrowserContext {
	return personal.BrowserContext{RequestID: r.ID, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID}
}

func (r Request) valid() bool {
	if r.V != 1 || !token.MatchString(r.ID) {
		return false
	}
	legacyValue := r.Type == "save-new" || r.Type == "save-update" || r.Type == "commit-ready" || r.Type == "cancel-save" || r.Type == "otp" || r.Type == "otp-ack" || r.Type == "cancel-otp"
	v2Value := isV2ValueType(r.Type)
	if !legacyValue && !v2Value && (r.payload != nil || r.WindowID != 0 || r.RequestID != "" || r.Nonce != "") {
		return false
	}
	if r.Type != "passkey-create" && r.Type != "passkey-get" && r.Options != "" && r.Type != "generate" {
		return false
	}
	switch r.Type {
	case "passkey-create", "passkey-get":
		return token.MatchString(r.Capability) && r.Context().Valid() && r.ItemID == "" && r.Revision == "" && len(r.Options) > 0 && len(r.Options) <= 32768 && strictUnicode([]byte(r.Options))
	case "otp":
		return token.MatchString(r.Capability) && r.OTPContext().Valid() && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "otp-ack", "cancel-otp":
		return token.MatchString(r.Capability) && token.MatchString(r.RequestID) && r.payload == nil && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && (r.Type == "cancel-otp" && r.Nonce == "" || r.Type == "otp-ack" && revision.MatchString(r.Nonce))
	case "save-new", "save-update":
		if !token.MatchString(r.Capability) || !r.SaveContext().Valid() || r.RequestID != "" || r.Nonce != "" || r.payload == nil || !validPayload(r.payload) {
			return false
		}
		return r.Type == "save-new" && r.ItemID == "" && r.Revision == "" || r.Type == "save-update" && token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
	case "commit-ready", "cancel-save":
		return token.MatchString(r.Capability) && token.MatchString(r.RequestID) && r.payload == nil && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && (r.Type == "cancel-save" && r.Nonce == "" || r.Type == "commit-ready" && revision.MatchString(r.Nonce))
	case "hello":
		return r.Capability == "" && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.ItemID == "" && r.Revision == ""
	case "cancel":
		return token.MatchString(r.Capability) && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.ItemID == "" && r.Revision == ""
	case "match":
		return token.MatchString(r.Capability) && r.Context().Valid() && r.ItemID == "" && r.Revision == ""
	case "fill":
		return token.MatchString(r.Capability) && r.Context().Valid() && token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
	case "status", "session-status", "lock", "vault-lock", "unlock-request", "watchtower", "watchtower-summary":
		return (r.Capability == "" || token.MatchString(r.Capability)) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "generate":
		if !token.MatchString(r.Capability) || r.payload != nil || r.RequestID != "" || r.Nonce != "" {
			return false
		}
		return r.Options != "" || r.GenMode != "" && r.Length > 0
	case "stage-save":
		if !token.MatchString(r.Capability) || r.payload == nil || !validPayload(r.payload) || !r.SaveContext().Valid() || r.RequestID != "" || r.Nonce != "" {
			return false
		}
		if r.ItemID == "" && r.Revision == "" {
			return r.GenMode == "" || r.GenMode == "new"
		}
		return token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && (r.GenMode == "" || r.GenMode == "update")
	case "pending-save":
		if !token.MatchString(r.Capability) || r.payload != nil || r.RequestID != "" || r.Nonce != "" || r.WindowID < 0 || r.TabID < 1 || r.TabID > 9007199254740991 {
			return false
		}
		_, e := origin.Parse(r.Origin)
		return e == nil
	case "commit-staged-save":
		return token.MatchString(r.Capability) && token.MatchString(r.StageID) && r.Context().Valid() && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "dismiss-save":
		return token.MatchString(r.Capability) && r.payload == nil && r.RequestID == "" && r.Nonce == "" && (r.Origin != "" || token.MatchString(r.StageID))
	case "search", "list", "vault-search", "vault-list":
		return token.MatchString(r.Capability) && r.payload == nil && r.RequestID == "" && r.Nonce == "" && r.ItemID == "" && r.Revision == ""
	case "item-get":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && (r.Revision == "" || revision.MatchString(r.Revision)) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "item-copy-field", "item-reveal-field":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.Field != "" && (r.FieldAction == "" || r.FieldAction == "copy" || r.FieldAction == "reveal") && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "item-create", "item-edit", "item-save":
		if !token.MatchString(r.Capability) || r.ItemJSON == "" || len(r.ItemJSON) > 64<<10 || !strictUnicode([]byte(r.ItemJSON)) || r.payload != nil || r.RequestID != "" || r.Nonce != "" {
			return false
		}
		if r.Type == "item-edit" {
			return token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
		}
		if r.Type == "item-save" {
			return r.ItemID == "" && r.Revision == "" || token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
		}
		return r.ItemID == "" && r.Revision == ""
	case "item-state":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.StateAction != "" && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "match-profiles":
		return token.MatchString(r.Capability) && r.Context().Valid() && (r.ProfileKind == "" || r.ProfileKind == "all" || r.ProfileKind == "identity" || r.ProfileKind == "credit_card") && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "fill-profile":
		return token.MatchString(r.Capability) && r.Context().Valid() && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	}
	return false
}

func isV2ValueType(t string) bool {
	switch t {
	case "stage-save", "pending-save", "commit-staged-save", "dismiss-save":
		return true
	}
	return false
}

type Response struct {
	Credential string         `json:"credential,omitempty"`
	QuickFill  bool           `json:"quick_fill,omitempty"`
	Code       string         `json:"code,omitempty"`
	Nonce      string         `json:"nonce,omitempty"`
	ItemID     string         `json:"item_id,omitempty"`
	Revision   string         `json:"revision,omitempty"`
	V          int            `json:"v"`
	ID         string         `json:"id,omitempty"`
	Type       string         `json:"type"`
	Capability string         `json:"capability,omitempty"`
	Candidates []personal.Row `json:"candidates,omitempty"`
	Username   string         `json:"username,omitempty"`
	Password   string         `json:"password,omitempty"`
	Error      string         `json:"error,omitempty"`

	DesktopConnected bool     `json:"desktop_connected,omitempty"`
	Unlocked         bool     `json:"unlocked,omitempty"`
	VaultLocked      bool     `json:"vault_locked,omitempty"`
	Paired           bool     `json:"paired,omitempty"`
	SessionEpoch     uint64   `json:"session_epoch,omitempty"`
	Capabilities     []string `json:"capabilities,omitempty"`

	GeneratedPassword string                  `json:"generated_password,omitempty"`
	PasswordProfile   *BrowserPasswordProfile `json:"profile,omitempty"`
	HistoryID         string                  `json:"history_id,omitempty"`

	StagedSave   *BrowserStagedSave `json:"staged_save,omitempty"`
	NeverOrigins []string           `json:"never_origins,omitempty"`

	Items            []BrowserItemSummary  `json:"items,omitempty"`
	Vaults           []BrowserVaultSummary `json:"vaults,omitempty"`
	Item             *BrowserItemDetail    `json:"item,omitempty"`
	ItemSummary      *BrowserItemSummary   `json:"item_summary,omitempty"`
	Field            string                `json:"field,omitempty"`
	FieldValue       string                `json:"value,omitempty"`
	Copied           bool                  `json:"copied,omitempty"`
	ExpiresInSeconds int                   `json:"expires_in_seconds,omitempty"`
	State            string                `json:"state,omitempty"`
	Favorite         bool                  `json:"favorite,omitempty"`

	Profiles    []BrowserProfileSummary `json:"profiles,omitempty"`
	ProfileFill *BrowserProfileFill     `json:"profile_fill,omitempty"`

	Watchtower *BrowserWatchtowerSummary `json:"watchtower,omitempty"`
}

// A legitimate login may have an empty username. Fill responses always carry
// both fixed fields; other messages cannot accidentally serialize field values.
func (r Response) MarshalJSON() ([]byte, error) {
	type plain Response
	type candidate struct {
		ID       string `json:"id"`
		Revision string `json:"revision"`
		Title    string `json:"title"`
		State    string `json:"state"`
	}
	type wire struct {
		plain
		Candidates []candidate `json:"candidates,omitempty"`
	}
	if r.Type == "otp-fill" {
		return nil, ErrProtocol
	}
	r.Code = ""
	if r.Type != "passkey-result" {
		r.Credential = ""
	}
	if r.Type != "paired" && r.Type != "unlocked" && r.Type != "status" && r.Type != "session-status" {
		r.QuickFill = false
	}
	if r.Type == "otp-ready" {
		return json.Marshal(struct {
			V     int    `json:"v"`
			ID    string `json:"id"`
			Type  string `json:"type"`
			Nonce string `json:"nonce"`
		}{r.V, r.ID, r.Type, r.Nonce})
	}
	if r.Type == "paired" {
		out := struct {
			V            int      `json:"v"`
			ID           string   `json:"id,omitempty"`
			Type         string   `json:"type"`
			Capability   string   `json:"capability,omitempty"`
			QuickFill    bool     `json:"quick_fill,omitempty"`
			Capabilities []string `json:"capabilities,omitempty"`
		}{r.V, r.ID, r.Type, r.Capability, r.QuickFill, r.Capabilities}
		return json.Marshal(out)
	}
	if r.Type == "locked" {
		out := struct {
			V    int    `json:"v"`
			ID   string `json:"id,omitempty"`
			Type string `json:"type"`
		}{r.V, r.ID, r.Type}
		return json.Marshal(out)
	}
	if r.Type != "fill" {
		r.Username = ""
		r.Password = ""
	}
	if r.Type != "generated" {
		r.GeneratedPassword = ""
	}
	if r.Type != "generated" {
		r.PasswordProfile = nil
	}
	if r.Type != "field-value" {
		r.FieldValue = ""
	}
	if r.Type != "profile-fill" {
		r.ProfileFill = nil
	}
	// The general native Row may gain metadata such as Kind; the fixed browser
	// protocol exposes exactly its original four candidate keys.
	var candidates []candidate
	if len(r.Candidates) > 0 {
		candidates = make([]candidate, len(r.Candidates))
	}
	for n, row := range r.Candidates {
		if row.Kind != "" && row.Kind != "login" {
			return nil, ErrProtocol
		}
		candidates[n] = candidate{row.ID, row.Revision, row.Title, row.State}
	}
	base := wire{plain(r), candidates}
	if r.Type != "fill" {
		return json.Marshal(base)
	}
	return json.Marshal(struct {
		wire
		Username string `json:"username"`
		Password string `json:"password"`
	}{wire: base, Username: r.Username, Password: r.Password})
}

func (Response) String() string   { return "[native browser response]" }
func (Response) GoString() string { return "[native browser response]" }
func (r Request) OTPContext() personal.BrowserOTPContext {
	return personal.BrowserOTPContext{BrowserContext: r.Context(), WindowID: r.WindowID}
}

type savePayload struct{ username, password []byte }

func (p *savePayload) clear() {
	if p != nil {
		clear(p.username)
		clear(p.password)
		p.username = nil
		p.password = nil
	}
}
func (p *savePayload) take() *savePayload {
	v := &savePayload{p.username, p.password}
	p.username = nil
	p.password = nil
	return v
}
func validPayload(p *savePayload) bool {
	if !(p != nil && len(p.username) <= 16384 && len(p.password) > 0 && len(p.password) <= 16384 && utf8.Valid(p.username) && utf8.Valid(p.password)) {
		return false
	}
	for _, value := range [][]byte{p.username, p.password} {
		for _, r := range string(value) {
			if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
				return false
			}
		}
	}
	return true
}
func (r Request) SaveContext() personal.BrowserSaveContext {
	return personal.BrowserSaveContext{BrowserContext: r.Context(), WindowID: r.WindowID}
}
func (r *Request) Clear() {
	if r != nil {
		r.payload.clear()
		r.payload = nil
		r.ItemJSON = ""
	}
}

func (Request) String() string                   { return "[native browser request]" }
func (Request) GoString() string                 { return "[native browser request]" }
func (Request) MarshalJSON() ([]byte, error)     { return nil, ErrProtocol }
func (savePayload) String() string               { return "[private save payload]" }
func (savePayload) GoString() string             { return "[private save payload]" }
func (savePayload) MarshalJSON() ([]byte, error) { return nil, ErrProtocol }

// encoding/json replaces malformed UTF-8/surrogates. Reject them before any
// credential decoding, so the saved value is never silently normalized.
func strictUnicode(raw []byte) bool {
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
			if n >= len(raw) {
				return false
			}
			if raw[n] != 'u' {
				continue
			}
			if n+4 >= len(raw) {
				return false
			}
			v, e := strconv.ParseUint(string(raw[n+1:n+5]), 16, 16)
			if e != nil {
				return false
			}
			n += 4
			if v >= 0xdc00 && v <= 0xdfff {
				return false
			}
			if v >= 0xd800 && v <= 0xdbff {
				if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
					return false
				}
				w, e := strconv.ParseUint(string(raw[n+3:n+7]), 16, 16)
				if e != nil || w < 0xdc00 || w > 0xdfff {
					return false
				}
				n += 6
			}
		}
	}
	return true
}
func ReadRequest(reader io.Reader) (Request, error) {
	var h [4]byte
	if _, e := io.ReadFull(reader, h[:]); e != nil {
		return Request{}, e
	}
	n := binary.NativeEndian.Uint32(h[:])
	if n == 0 || n > MaxInput {
		return Request{}, ErrProtocol
	}
	raw := make([]byte, int(n))
	defer clear(raw)
	if _, e := io.ReadFull(reader, raw); e != nil || !strictUnicode(raw) {
		return Request{}, ErrProtocol
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, e := dec.Token()
	if e != nil || first != json.Delim('{') {
		return Request{}, ErrProtocol
	}
	seen := map[string]bool{}
	for dec.More() {
		key, e := dec.Token()
		name, ok := key.(string)
		if e != nil || !ok || seen[name] || len(seen) >= 24 {
			return Request{}, ErrProtocol
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || len(value) == 0 || value[0] != '"' && (value[0] < '0' || value[0] > '9') && value[0] != '-' && value[0] != 't' && value[0] != 'f' {
			clear(value)
			return Request{}, ErrProtocol
		}
		clear(value)
	}
	last, e := dec.Token()
	if e != nil || last != json.Delim('}') {
		return Request{}, ErrProtocol
	}
	if _, e = dec.Token(); e != io.EOF {
		return Request{}, ErrProtocol
	}
	var wire struct {
		Options        string  `json:"options"`
		V              int     `json:"v"`
		ID             string  `json:"id"`
		Type           string  `json:"type"`
		Capability     string  `json:"capability"`
		Origin         string  `json:"origin"`
		TabID          int64   `json:"tab_id"`
		DocumentID     string  `json:"document_id"`
		WindowID       int64   `json:"window_id"`
		ItemID         string  `json:"item_id"`
		Revision       string  `json:"revision"`
		RequestID      string  `json:"request_id"`
		Nonce          string  `json:"nonce"`
		Username       *string `json:"username"`
		Password       *string `json:"password"`
		Mode           string  `json:"mode"`
		Length         int     `json:"length"`
		Digits         *bool   `json:"digits"`
		Symbols        *bool   `json:"symbols"`
		SaveHistory    *bool   `json:"save_history"`
		StageID        string  `json:"stage_id"`
		Title          string  `json:"title"`
		NeverForOrigin *bool   `json:"never_for_origin"`
		Query          string  `json:"query"`
		Category       string  `json:"category"`
		VaultID        string  `json:"vault_id"`
		Tag            string  `json:"tag"`
		StateFilter    string  `json:"state"`
		FavoritesOnly  *bool   `json:"favorites_only"`
		Field          string  `json:"field"`
		FieldAction    string  `json:"action"`
		StateAction    string  `json:"state_action"`
		ItemJSON       string  `json:"item_json"`
		ProfileKind    string  `json:"profile_kind"`
		IncludeHIBP    *bool   `json:"include_hibp"`
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil {
		return Request{}, ErrProtocol
	}
	r := Request{Options: wire.Options, V: wire.V, ID: wire.ID, Type: wire.Type, Capability: wire.Capability, Origin: wire.Origin, TabID: wire.TabID, DocumentID: wire.DocumentID, WindowID: wire.WindowID, ItemID: wire.ItemID, Revision: wire.Revision, RequestID: wire.RequestID, Nonce: wire.Nonce, GenMode: wire.Mode, Length: wire.Length, Digits: wire.Digits, Symbols: wire.Symbols, SaveHistory: wire.SaveHistory, StageID: wire.StageID, Title: wire.Title, NeverForOrigin: wire.NeverForOrigin, Query: wire.Query, Category: wire.Category, VaultID: wire.VaultID, Tag: wire.Tag, StateFilter: wire.StateFilter, FavoritesOnly: wire.FavoritesOnly, Field: wire.Field, FieldAction: wire.FieldAction, StateAction: wire.StateAction, ItemJSON: wire.ItemJSON, ProfileKind: wire.ProfileKind, IncludeHIBP: wire.IncludeHIBP}
	if wire.Username != nil && wire.Password != nil {
		r.payload = &savePayload{[]byte(*wire.Username), []byte(*wire.Password)}
	}
	expected, optional, ok := requestKeys(r.Type)
	if !ok {
		r.Clear()
		return Request{}, ErrProtocol
	}
	for _, name := range expected {
		if !seen[name] {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	for name := range seen {
		required := false
		for _, want := range expected {
			if name == want {
				required = true
				break
			}
		}
		if required {
			continue
		}
		allowed := false
		for _, want := range optional {
			if name == want {
				allowed = true
				break
			}
		}
		if !allowed {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if r.Type == "dismiss-save" {
		if !seen["origin"] && !seen["stage_id"] {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if r.Origin != "" {
		if _, e := origin.Parse(r.Origin); e != nil {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if r.Type == "generate" {
		if r.Options == "" && (r.GenMode == "" || r.Length == 0) || r.Options != "" && len(r.Options) > 4096 || r.Options != "" && !strictUnicode([]byte(r.Options)) {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if !r.valid() {
		r.Clear()
		return Request{}, ErrProtocol
	}
	return r, nil
}

func requestKeys(kind string) (required, optional []string, ok bool) {
	base := []string{"v", "id", "type"}
	switch kind {
	case "hello":
		return base, nil, true
	case "cancel":
		return append(base, "capability"), nil, true
	case "passkey-create", "passkey-get":
		return append(base, "capability", "origin", "tab_id", "document_id", "options"), nil, true
	case "match", "fill", "save-new", "save-update", "otp":
		required = append(base, "capability", "origin", "tab_id", "document_id")
		if kind == "fill" || kind == "save-update" || kind == "otp" {
			required = append(required, "item_id", "revision")
		}
		if kind == "otp" {
			required = append(required, "window_id")
		}
		if kind == "save-new" || kind == "save-update" {
			required = append(required, "window_id", "username", "password")
		}
		return required, nil, true
	case "commit-ready", "cancel-save", "otp-ack", "cancel-otp":
		required = append(base, "capability", "request_id")
		if kind == "commit-ready" || kind == "otp-ack" {
			required = append(required, "nonce")
		}
		return required, nil, true
	case "status", "session-status":
		return base, []string{"capability"}, true
	case "lock", "vault-lock", "unlock-request":
		return base, []string{"capability"}, true
	case "generate":
		return append(base, "capability"), []string{"options", "mode", "length", "digits", "symbols", "origin", "save_history"}, true
	case "stage-save":
		return append(base, "capability", "origin", "tab_id", "window_id", "document_id", "username", "password"), []string{"title", "mode", "item_id", "revision"}, true
	case "pending-save":
		return append(base, "capability", "origin", "tab_id"), []string{"window_id", "document_id"}, true
	case "commit-staged-save":
		return append(base, "capability", "stage_id", "origin", "tab_id", "window_id", "document_id"), []string{"title", "mode", "item_id", "revision"}, true
	case "dismiss-save":
		return append(base, "capability"), []string{"origin", "stage_id", "never_for_origin", "tab_id", "window_id", "document_id"}, true
	case "search", "list", "vault-search", "vault-list":
		return append(base, "capability"), []string{"query", "category", "vault_id", "state", "favorites_only", "origin", "tag"}, true
	case "item-get":
		return append(base, "capability", "item_id"), []string{"revision"}, true
	case "item-copy-field", "item-reveal-field":
		return append(base, "capability", "item_id", "revision", "field"), []string{"action"}, true
	case "item-create":
		return append(base, "capability", "item_json"), nil, true
	case "item-edit":
		return append(base, "capability", "item_id", "revision", "item_json"), nil, true
	case "item-save":
		return append(base, "capability", "item_json"), []string{"item_id", "revision"}, true
	case "item-state":
		return append(base, "capability", "item_id", "revision", "state_action"), nil, true
	case "match-profiles":
		return append(base, "capability", "origin", "tab_id", "document_id"), []string{"profile_kind"}, true
	case "fill-profile":
		return append(base, "capability", "origin", "tab_id", "document_id", "item_id", "revision"), nil, true
	case "watchtower", "watchtower-summary":
		return append(base, "capability"), []string{"origin", "include_hibp"}, true
	}
	return nil, nil, false
}

// These checks constrain normal browser launch; a same-user native process can
// forge argv and is outside this authentication boundary.
func ValidateLaunch(browser Browser, args []string) error {
	if browser == Chromium {
		if len(args) < 1 || len(args) > 2 || args[0] != "chrome-extension://"+ChromiumID+"/" {
			return ErrProtocol
		}
		if len(args) == 2 {
			if runtime.GOOS != "windows" || !strings.HasPrefix(args[1], "--parent-window=") {
				return ErrProtocol
			}
			p := strings.TrimPrefix(args[1], "--parent-window=")
			n, e := strconv.ParseUint(p, 10, 64)
			if e != nil || strconv.FormatUint(n, 10) != p {
				return ErrProtocol
			}
		}
		return nil
	}
	if browser == Firefox && len(args) == 2 && filepath.IsAbs(args[0]) && filepath.Clean(args[0]) == args[0] && filepath.Base(args[0]) == HostName+".json" && args[1] == FirefoxID {
		return nil
	}
	return ErrProtocol
}
