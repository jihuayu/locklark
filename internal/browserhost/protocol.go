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
	"sync"
	"time"
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
var token = regexp.MustCompile(`^[a-f0-9]{32}$`)
var revision = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Request struct {
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
}

func (r Request) Context() personal.BrowserContext {
	return personal.BrowserContext{RequestID: r.ID, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID}
}
func (r Request) valid() bool {
	if r.V != 1 || !token.MatchString(r.ID) {
		return false
	}
	if r.Type != "save-new" && r.Type != "save-update" && r.Type != "commit-ready" && r.Type != "cancel-save" && (r.payload != nil || r.WindowID != 0 || r.RequestID != "" || r.Nonce != "") {
		return false
	}
	switch r.Type {
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
	}
	return false
}

type Response struct {
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
}

// A legitimate login may have an empty username. Fill responses always carry
// both fixed fields; other messages cannot accidentally serialize field values.
func (r Response) MarshalJSON() ([]byte, error) {
	type plain Response
	if r.Type != "fill" {
		r.Username = ""
		r.Password = ""
		return json.Marshal(plain(r))
	}
	return json.Marshal(struct {
		plain
		Username string `json:"username"`
		Password string `json:"password"`
	}{plain: plain(r), Username: r.Username, Password: r.Password})
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
		if e != nil || !ok || seen[name] || len(seen) >= 14 {
			return Request{}, ErrProtocol
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || len(value) == 0 || value[0] != '"' && (value[0] < '0' || value[0] > '9') && value[0] != '-' {
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
		V          int     `json:"v"`
		ID         string  `json:"id"`
		Type       string  `json:"type"`
		Capability string  `json:"capability"`
		Origin     string  `json:"origin"`
		TabID      int64   `json:"tab_id"`
		DocumentID string  `json:"document_id"`
		WindowID   int64   `json:"window_id"`
		ItemID     string  `json:"item_id"`
		Revision   string  `json:"revision"`
		RequestID  string  `json:"request_id"`
		Nonce      string  `json:"nonce"`
		Username   *string `json:"username"`
		Password   *string `json:"password"`
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil {
		return Request{}, ErrProtocol
	}
	r := Request{V: wire.V, ID: wire.ID, Type: wire.Type, Capability: wire.Capability, Origin: wire.Origin, TabID: wire.TabID, DocumentID: wire.DocumentID, WindowID: wire.WindowID, ItemID: wire.ItemID, Revision: wire.Revision, RequestID: wire.RequestID, Nonce: wire.Nonce}
	if wire.Username != nil && wire.Password != nil {
		r.payload = &savePayload{[]byte(*wire.Username), []byte(*wire.Password)}
	}
	expected := []string{"v", "id", "type"}
	switch r.Type {
	case "hello":
	case "cancel":
		expected = append(expected, "capability")
	case "match", "fill", "save-new", "save-update":
		expected = append(expected, "capability", "origin", "tab_id", "document_id")
		if r.Type == "fill" || r.Type == "save-update" {
			expected = append(expected, "item_id", "revision")
		}
		if r.Type == "save-new" || r.Type == "save-update" {
			expected = append(expected, "window_id", "username", "password")
		}
	case "commit-ready", "cancel-save":
		expected = append(expected, "capability", "request_id")
		if r.Type == "commit-ready" {
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

// Writer closes the pipe at a finite deadline, releasing a blocked write. A
// failed writer is terminal: retries could duplicate an unknown partial frame.
type Writer struct {
	mu      sync.Mutex
	out     io.WriteCloser
	timeout time.Duration
	failed  bool
}

func NewWriter(w io.WriteCloser, timeout time.Duration) *Writer {
	return &Writer{out: w, timeout: timeout}
}
func (w *Writer) Write(response Response) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed || w.timeout <= 0 || w.timeout > time.Second {
		return ErrProtocol
	}
	raw, e := json.Marshal(response)
	if e != nil || len(raw) > MaxOutput {
		clear(raw)
		return ErrProtocol
	}
	defer clear(raw)
	data := binary.NativeEndian.AppendUint32(make([]byte, 0, len(raw)+4), uint32(len(raw)))
	data = append(data, raw...)
	defer clear(data)
	expired := make(chan struct{})
	timer := time.AfterFunc(w.timeout, func() { close(expired); w.out.Close() })
	for len(data) > 0 {
		n, err := w.out.Write(data)
		if err != nil || n <= 0 || n > len(data) {
			w.failed = true
			timer.Stop()
			w.out.Close()
			return ErrProtocol
		}
		data = data[n:]
	}
	if !timer.Stop() {
		w.failed = true
		return ErrProtocol
	}
	select {
	case <-expired:
		w.failed = true
		return ErrProtocol
	default:
	}
	return nil
}
func (w *Writer) Close() error { return w.out.Close() }

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
