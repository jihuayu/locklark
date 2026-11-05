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

	"github.com/jihuayu/locklark/internal/personal"
)

const HostName = "org.locklark.browser"
const ChromiumID = "geldnhjapnackobgknocomedmjgphnpe"
const FirefoxID = "browser@locklark.local"
const MaxInput = 16 << 10
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
	switch r.Type {
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

func ReadRequest(r io.Reader) (Request, error) {
	var header [4]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return Request{}, e
	}
	n := binary.NativeEndian.Uint32(header[:])
	if n == 0 || n > MaxInput {
		return Request{}, ErrProtocol
	}
	raw := make([]byte, int(n))
	defer clear(raw)
	if _, e := io.ReadFull(r, raw); e != nil {
		return Request{}, ErrProtocol
	}
	// A single flat object is the entire input grammar. Detect duplicates before
	// strict DTO decoding; encoding/json alone silently accepts duplicate keys.
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, e := dec.Token()
	if e != nil || t != json.Delim('{') {
		return Request{}, ErrProtocol
	}
	seen := map[string]bool{}
	for dec.More() {
		t, e = dec.Token()
		key, ok := t.(string)
		if e != nil || !ok || seen[key] || len(seen) >= 9 {
			return Request{}, ErrProtocol
		}
		seen[key] = true
		t, e = dec.Token()
		if e != nil {
			return Request{}, ErrProtocol
		}
		switch t.(type) {
		case string, float64:
		default:
			return Request{}, ErrProtocol
		}
	}
	if t, e = dec.Token(); e != nil || t != json.Delim('}') {
		return Request{}, ErrProtocol
	}
	if _, e = dec.Token(); e != io.EOF {
		return Request{}, ErrProtocol
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req Request
	if dec.Decode(&req) != nil || !req.valid() {
		return Request{}, ErrProtocol
	}
	return req, nil
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
