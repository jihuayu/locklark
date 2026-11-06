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
var errDuplicateRequest = errors.New("native duplicate request ignored")
var token = regexp.MustCompile(`^[a-f0-9]{32}$`)
var revision = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Request struct {
	Options        string `json:"options,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Title          string `json:"title,omitempty"`
	StageID        string `json:"stage_id,omitempty"`
	NeverForOrigin bool   `json:"never_for_origin,omitempty"`
	payload        *savePayload
	WindowID       int64  `json:"window_id,omitempty"`
	V              int    `json:"v"`
	ID             string `json:"id"`
	Type           string `json:"type"`
	Capability     string `json:"capability,omitempty"`
	Origin         string `json:"origin,omitempty"`
	TabID          int64  `json:"tab_id,omitempty"`
	DocumentID     string `json:"document_id,omitempty"`
	ItemID         string `json:"item_id,omitempty"`
	Revision       string `json:"revision,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
}

func (r Request) Context() personal.BrowserContext {
	return personal.BrowserContext{RequestID: r.ID, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID}
}
func validTitle(value string) bool {
	if len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}
func (r Request) valid() bool {
	if r.V != 1 || !token.MatchString(r.ID) {
		return false
	}
	switch r.Type {
	case "save-new", "save-update", "commit-ready", "cancel-save", "otp", "otp-ack", "cancel-otp", "stage-save", "commit-staged-save", "dismiss-save":
	default:
		if r.payload != nil || r.WindowID != 0 || r.RequestID != "" || r.Nonce != "" || r.StageID != "" || r.Mode != "" || r.Title != "" || r.NeverForOrigin {
			return false
		}
	}
	if r.Type != "passkey-create" && r.Type != "passkey-get" && r.Type != "generate" && r.Options != "" {
		return false
	}
	if r.Type != "stage-save" && r.Type != "commit-staged-save" && r.Type != "dismiss-save" && (r.StageID != "" || r.Mode != "" || r.Title != "" || r.NeverForOrigin) {
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
		return token.MatchString(r.Capability) && token.MatchString(r.RequestID) && r.payload == nil && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && r.StageID == "" && r.Mode == "" && r.Title == "" && (r.Type == "cancel-save" && r.Nonce == "" || r.Type == "commit-ready" && revision.MatchString(r.Nonce))
	case "generate":
		return token.MatchString(r.Capability) && len(r.Options) > 0 && len(r.Options) <= 4096 && strictUnicode([]byte(r.Options)) && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && r.RequestID == "" && r.Nonce == "" && r.StageID == "" && r.Mode == "" && r.Title == "" && r.payload == nil
	case "stage-save":
		if !token.MatchString(r.Capability) || !r.SaveContext().Valid() || r.payload == nil || !validPayload(r.payload) || !validTitle(r.Title) || r.RequestID != "" || r.Nonce != "" || r.StageID != "" || r.NeverForOrigin {
			return false
		}
		if r.Mode == "new" {
			return r.ItemID == "" && r.Revision == ""
		}
		return r.Mode == "update" && token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
	case "pending-save":
		return token.MatchString(r.Capability) && r.Context().Valid() && r.payload == nil && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && r.RequestID == "" && r.Nonce == "" && r.StageID == "" && r.Mode == "" && r.Title == "" && !r.NeverForOrigin
	case "commit-staged-save":
		if !token.MatchString(r.Capability) || !token.MatchString(r.StageID) || !r.SaveContext().Valid() || !validTitle(r.Title) || r.payload != nil || r.RequestID != "" || r.Nonce != "" || r.NeverForOrigin {
			return false
		}
		if r.Mode == "new" {
			return r.ItemID == "" && r.Revision == ""
		}
		return r.Mode == "update" && token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
	case "dismiss-save":
		return token.MatchString(r.Capability) && token.MatchString(r.StageID) && r.payload == nil && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && r.RequestID == "" && r.Nonce == "" && r.Mode == "" && r.Title == ""
	case "hello":
		return r.Capability == "" && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.ItemID == "" && r.Revision == ""
	case "cancel":
		return token.MatchString(r.Capability) && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.ItemID == "" && r.Revision == ""
	case "match":
		return token.MatchString(r.Capability) && r.Context().Valid() && r.ItemID == "" && r.Revision == ""
	case "fill":
		return token.MatchString(r.Capability) && r.Context().Valid() && token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
	}
	return false
}

// GeneratedProfile publishes only policy counts, never the generated secret.
type GeneratedProfile struct {
	Mode             string `json:"mode"`
	Length           int    `json:"length"`
	AlphabetSize     int    `json:"alphabet_size"`
	EntropyBitsFloor int    `json:"entropy_bits_floor"`
}

// StagedSave is metadata only. The staged password never leaves private memory.
type StagedSave struct {
	StageID          string `json:"stage_id"`
	Origin           string `json:"origin"`
	Username         string `json:"username"`
	Title            string `json:"title"`
	Mode             string `json:"mode"`
	ExistingItemID   string `json:"existing_item_id"`
	ExistingRevision string `json:"existing_revision"`
	ExpiresAt        int64  `json:"expires_at"`
}

type Response struct {
	Credential        string            `json:"credential,omitempty"`
	QuickFill         bool              `json:"quick_fill,omitempty"`
	Code              string            `json:"code,omitempty"`
	Nonce             string            `json:"nonce,omitempty"`
	ItemID            string            `json:"item_id,omitempty"`
	Revision          string            `json:"revision,omitempty"`
	V                 int               `json:"v"`
	ID                string            `json:"id,omitempty"`
	Type              string            `json:"type"`
	Capability        string            `json:"capability,omitempty"`
	GeneratedPassword string            `json:"generated_password,omitempty"`
	HistoryID         string            `json:"history_id,omitempty"`
	Candidates        []personal.Row    `json:"candidates,omitempty"`
	Capabilities      []string          `json:"capabilities,omitempty"`
	NeverOrigins      []string          `json:"never_origins,omitempty"`
	Profile           *GeneratedProfile `json:"profile,omitempty"`
	Staged            *StagedSave       `json:"staged_save,omitempty"`
	Username          string            `json:"username,omitempty"`
	Password          string            `json:"password,omitempty"`
	Error             string            `json:"error,omitempty"`
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
	if r.Type != "paired" {
		r.QuickFill = false
		r.Capabilities = nil
	}
	if r.Type != "generated" {
		r.GeneratedPassword = ""
		r.HistoryID = ""
		r.Profile = nil
	}
	if r.Type != "save-staged" && r.Type != "save-pending" {
		r.Staged = nil
	}
	if r.Type != "save-dismissed" {
		r.NeverOrigins = nil
	}
	if r.Type == "otp-ready" {
		return json.Marshal(struct {
			V     int    `json:"v"`
			ID    string `json:"id"`
			Type  string `json:"type"`
			Nonce string `json:"nonce"`
		}{r.V, r.ID, r.Type, r.Nonce})
	}
	if r.Type != "fill" {
		r.Username = ""
		r.Password = ""
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
		if e != nil || !ok || seen[name] || len(seen) >= 20 {
			return Request{}, ErrProtocol
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || len(value) == 0 {
			clear(value)
			return Request{}, ErrProtocol
		}
		scalar := value[0] == '"' || value[0] == '-' || value[0] >= '0' && value[0] <= '9' || string(value) == "true" || string(value) == "false"
		if !scalar {
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
		Mode           string  `json:"mode"`
		Title          string  `json:"title"`
		StageID        string  `json:"stage_id"`
		NeverForOrigin *bool   `json:"never_for_origin"`
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
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil {
		return Request{}, ErrProtocol
	}
	r := Request{Options: wire.Options, Mode: wire.Mode, Title: wire.Title, StageID: wire.StageID, V: wire.V, ID: wire.ID, Type: wire.Type, Capability: wire.Capability, Origin: wire.Origin, TabID: wire.TabID, DocumentID: wire.DocumentID, WindowID: wire.WindowID, ItemID: wire.ItemID, Revision: wire.Revision, RequestID: wire.RequestID, Nonce: wire.Nonce}
	r.NeverForOrigin = wire.NeverForOrigin != nil && *wire.NeverForOrigin
	if wire.Username != nil && wire.Password != nil {
		r.payload = &savePayload{[]byte(*wire.Username), []byte(*wire.Password)}
	}
	expected := []string{"v", "id", "type"}
	switch r.Type {
	case "hello":
	case "cancel":
		expected = append(expected, "capability")
	case "passkey-create", "passkey-get":
		expected = append(expected, "capability", "origin", "tab_id", "document_id", "options")
	case "generate":
		expected = append(expected, "capability", "options")
	case "match", "fill", "save-new", "save-update", "otp", "pending-save":
		expected = append(expected, "capability", "origin", "tab_id", "document_id")
		if r.Type == "fill" || r.Type == "save-update" || r.Type == "otp" {
			expected = append(expected, "item_id", "revision")
		}
		if r.Type == "otp" {
			expected = append(expected, "window_id")
		}
		if r.Type == "save-new" || r.Type == "save-update" {
			expected = append(expected, "window_id", "username", "password")
		}
	case "stage-save":
		expected = append(expected, "capability", "origin", "tab_id", "document_id", "window_id", "username", "password", "mode", "title", "item_id", "revision")
	case "commit-staged-save":
		expected = append(expected, "capability", "stage_id", "origin", "tab_id", "document_id", "window_id", "title", "mode", "item_id", "revision")
	case "dismiss-save":
		expected = append(expected, "capability", "stage_id", "never_for_origin")
	case "commit-ready", "cancel-save", "otp-ack", "cancel-otp":
		expected = append(expected, "capability", "request_id")
		if r.Type == "commit-ready" || r.Type == "otp-ack" {
			expected = append(expected, "nonce")
		}
	default:
		r.Clear()
		return Request{}, ErrProtocol
	}
	if len(seen) != len(expected) {
		r.Clear()
		return Request{}, ErrProtocol
	}
	for _, name := range expected {
		if !seen[name] {
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
