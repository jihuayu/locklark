package browserhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

// Peer identifies the authenticated local OS peer of a broker connection.
type Peer struct {
	User    string
	PID     uint32
	Process string
}

// BrokerHello is the first authenticated frame on a broker connection.
type BrokerHello struct {
	V       int     `json:"v"`
	Mode    string  `json:"mode,omitempty"`
	Browser Browser `json:"browser,omitempty"`
	Origin  string  `json:"origin,omitempty"`
}

// BrowserPairRequest is the native review of one local browser-host peer. The
// Browser and Origin fields are asserted by the client and are display-only;
// the OS-authenticated Peer and the user's decision are the authority.
type BrowserPairRequest struct {
	Peer    Peer
	Browser Browser
	Origin  string
}

// BrowserPairDecision is the explicit native pairing result. QuickFill is a
// separate user gesture, never inferred from a browser-supplied field.
type BrowserPairDecision struct {
	Approved  bool
	QuickFill bool
}

// CLIRunBrokerRequest asks the desktop broker for pinned secret values.
type CLIRunBrokerRequest struct {
	V         int                        `json:"v"`
	VaultPath string                     `json:"vault_path"`
	Targets   []personal.CLIBrokerTarget `json:"targets"`
}

// CLIRunBrokerResponse carries disclosed values back to the CLI client.
type CLIRunBrokerResponse struct {
	V      int               `json:"v"`
	Values map[string]string `json:"values,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// BrokerCallbacks are implemented by the desktop App. Callbacks must not block
// the broker accept loop; they may be invoked from connection goroutines.
type BrokerCallbacks struct {
	CurrentSession     func() (*personal.Session, uint64, bool)
	RequestLock        func()
	RequestUnlockFocus func()
	NotifyChanged      func()
	ApproveCLIRun      func(context.Context, Peer, CLIRunBrokerRequest) (bool, error)
	HandleCLIRun       func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error)
	// ApproveBrowserPair is the explicit browser pairing gate. It is required
	// for every brokered browser connection; a nil callback refuses pairing.
	// The callback may block while the native owner decides.
	ApproveBrowserPair func(context.Context, BrowserPairRequest) (BrowserPairDecision, error)
	// NewClipboard is the only native-clipboard-lease-v1 capability source.
	// It returns one manager and one immutable clear TTL per connection; a
	// zero TTL disables automatic clearing. Without this callback the browser
	// protocol never advertises or accepts the clipboard lease operations.
	NewClipboard func() (*nativeclipboard.Manager, time.Duration)
	// ClipboardClearDuration is the live settings getter. It is captured per
	// prepare and must be atomic and non-blocking; nil keeps the duration
	// returned alongside NewClipboard for tests and compatibility.
	ClipboardClearDuration func() time.Duration
}

// Broker is the desktop-hosted local IPC endpoint.
type Broker struct {
	callbacks BrokerCallbacks
	listener  net.Listener
	mu        sync.Mutex
	conns     map[*Connection]bool
	never     map[string]bool
	closed    bool
	done      chan struct{}
}

func NewBroker(callbacks BrokerCallbacks) *Broker {
	return &Broker{callbacks: callbacks, conns: map[*Connection]bool{}, never: map[string]bool{}, done: make(chan struct{})}
}

func (b *Broker) Start(endpoint string) error {
	l, e := listenLocal(endpoint)
	if e != nil {
		return ErrBrokerUnavailable
	}
	b.mu.Lock()
	b.listener = l
	b.closed = false
	b.mu.Unlock()
	go b.acceptLoop(l)
	return nil
}

func (b *Broker) acceptLoop(l net.Listener) {
	for {
		conn, e := l.Accept()
		if e != nil {
			select {
			case <-b.done:
			default:
			}
			return
		}
		go b.serve(conn)
	}
}

func (b *Broker) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	l := b.listener
	conns := make([]*Connection, 0, len(b.conns))
	for c := range b.conns {
		conns = append(conns, c)
	}
	b.conns = map[*Connection]bool{}
	close(b.done)
	b.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	if l != nil {
		return l.Close()
	}
	return nil
}

func (b *Broker) addConn(c *Connection) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.conns[c] = true
	return true
}

func (b *Broker) dropConn(c *Connection) {
	b.mu.Lock()
	delete(b.conns, c)
	b.mu.Unlock()
}

// Connections returns a stable copy of the active browser connections. The
// desktop UI uses it to surface and route native approvals to the exact
// originating connection; it never grants authority by itself.
func (b *Broker) Connections() []*Connection {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*Connection, 0, len(b.conns))
	for c := range b.conns {
		out = append(out, c)
	}
	return out
}

// NotifyUnlocked publishes the newly unlocked session to the connections that
// sent hello before it was unlocked. It never grants authority by itself: those
// hellos are only offered to the explicit native pairing approval, and a
// connection without a pending hello waits for its next one.
func (b *Broker) NotifyUnlocked(s *personal.Session, epoch uint64) {
	if s == nil || !s.Unlocked() {
		return
	}
	b.mu.Lock()
	conns := make([]*Connection, 0, len(b.conns))
	for c := range b.conns {
		conns = append(conns, c)
	}
	b.mu.Unlock()
	for _, c := range conns {
		if c.offerBrowserSession(s, epoch) && b.callbacks.NotifyChanged != nil {
			b.callbacks.NotifyChanged()
		}
	}
}

// NotifyLocked revokes every shared capability and pushes "locked".
func (b *Broker) NotifyLocked(epoch uint64) {
	b.mu.Lock()
	conns := make([]*Connection, 0, len(b.conns))
	for c := range b.conns {
		conns = append(conns, c)
	}
	b.mu.Unlock()
	for _, c := range conns {
		c.InvalidateDesktopLock()
	}
	if b.callbacks.NotifyChanged != nil {
		b.callbacks.NotifyChanged()
	}
}

func (b *Broker) addNeverOrigin(origin string) {
	b.mu.Lock()
	b.never[origin] = true
	b.mu.Unlock()
}

func (b *Broker) hasNeverOrigin(origin string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.never[origin]
}

func (b *Broker) neverOrigins() []string {
	b.mu.Lock()
	out := make([]string, 0, len(b.never))
	for k := range b.never {
		out = append(out, k)
	}
	b.mu.Unlock()
	sort.Strings(out)
	return out
}

func (b *Broker) serve(conn net.Conn) {
	defer conn.Close()
	peer, e := authenticatedPeer(conn)
	if e != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, e := readFrame(conn, 4096)
	if e != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var hello BrokerHello
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&hello) != nil || hello.V != 1 {
		clear(raw)
		return
	}
	clear(raw)
	switch hello.Mode {
	case "", "browser":
		b.serveBrowser(conn, peer, hello)
	case "cli-run":
		b.serveCLIRun(conn, peer)
	}
}

func validHello(hello BrokerHello) bool {
	return validHelloForOS(hello, runtime.GOOS)
}

// validSafariHelloForOS pins the compiled Safari identity and refuses the mode
// on every non-macOS host, so a forged local hello cannot select it elsewhere.
func validSafariHelloForOS(hello BrokerHello, goos string) bool {
	return goos == "darwin" && hello.Origin == SafariID
}

func validHelloForOS(hello BrokerHello, goos string) bool {
	if hello.V != 1 {
		return false
	}
	if hello.Browser == Safari {
		return validSafariHelloForOS(hello, goos)
	}
	if hello.Browser != Chromium && hello.Browser != Firefox {
		return false
	}
	if hello.Browser == Chromium && hello.Origin != "chrome-extension://"+ChromiumID+"/" {
		return false
	}
	if hello.Browser == Firefox && hello.Origin != FirefoxID {
		return false
	}
	return true
}

func (b *Broker) serveBrowser(conn net.Conn, peer Peer, hello BrokerHello) {
	if !validHello(hello) || !peerProcessAllowed(peer) {
		return
	}
	writer := NewNativeWriter(conn, 250*time.Millisecond, func() { _ = conn.Close() })
	c := NewDesktopConnection(writer, func() {
		if b.callbacks.NotifyChanged != nil {
			b.callbacks.NotifyChanged()
		}
	})
	c.SetBroker(b)
	c.setBrokerPeer(peer, hello)
	if !b.addConn(c) {
		return
	}
	defer func() {
		b.dropConn(c)
		c.Close()
	}()
	// No session authority is granted here. A browser connection must send
	// "hello" and pass ApproveBrowserPair before any capability is issued.
	for {
		req, e := ReadRequest(conn)
		if e != nil {
			req.Clear()
			return
		}
		e = c.Handle(req)
		req.Clear()
		if e != nil {
			return
		}
	}
}

func (b *Broker) serveCLIRun(conn net.Conn, peer Peer) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, e := readFrame(conn, MaxInput)
	if e != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	defer clear(raw)
	var req CLIRunBrokerRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.V != 1 || len(req.Targets) < 1 || len(req.Targets) > 16 || len(req.VaultPath) == 0 || len(req.VaultPath) > 4096 {
		writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: "refused"})
		return
	}
	resp := CLIRunBrokerResponse{V: 1}
	if b.callbacks.HandleCLIRun != nil {
		out, err := b.callbacks.HandleCLIRun(context.Background(), peer, req)
		if err != nil {
			if errors.Is(err, ErrBrokerUnavailable) {
				resp.Error = "unavailable"
			} else {
				resp.Error = "refused"
			}
		} else {
			resp.Values = out.Values
		}
	} else {
		resp.Error = "unavailable"
	}
	writeCLIResponse(conn, resp)
	for k := range resp.Values {
		resp.Values[k] = ""
	}
}

func writeCLIResponse(conn net.Conn, resp CLIRunBrokerResponse) {
	raw, e := json.Marshal(resp)
	if e != nil {
		return
	}
	defer clear(raw)
	if len(raw) > MaxOutput {
		raw, _ = json.Marshal(CLIRunBrokerResponse{V: 1, Error: "refused"})
	}
	_ = writeFrame(conn, raw)
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.NativeEndian.Uint32(h[:])
	if n == 0 || n > uint32(max) {
		return nil, ErrProtocol
	}
	raw := make([]byte, int(n))
	if _, e := io.ReadFull(r, raw); e != nil {
		clear(raw)
		return nil, ErrProtocol
	}
	return raw, nil
}

func writeFrame(w io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxOutput {
		return ErrProtocol
	}
	frame := binary.NativeEndian.AppendUint32(make([]byte, 0, len(raw)+4), uint32(len(raw)))
	frame = append(frame, raw...)
	defer clear(frame)
	for len(frame) > 0 {
		n, e := w.Write(frame)
		if e != nil || n <= 0 {
			return ErrProtocol
		}
		frame = frame[n:]
	}
	return nil
}

// peerProcessAllowed checks the OS-authenticated executable path. It is a
// defence in depth on top of same-UID socket credentials, not a code-signing
// claim: a same-UID process that can replace a trusted path is still stopped by
// the explicit native pairing prompt. The request's declared Browser/Origin
// never participate.
func peerProcessAllowed(peer Peer) bool {
	if peer.PID == 0 || peer.User == "" {
		return false
	}
	self, e := os.Executable()
	if e != nil {
		return false
	}
	return peerProcessAllowedFor(peer, self, runtime.GOOS)
}

// peerProcessAllowedFor is the pure policy used by tests. A browser host must
// be the current executable (tests/embedders) or one exact Locklark browser
// host name installed beside the desktop executable. macOS Safari helpers may
// sit in a sibling signed app bundle, but never at an arbitrary path.
func peerProcessAllowedFor(peer Peer, selfPath, goos string) bool {
	if peer.PID == 0 || peer.User == "" {
		return false
	}
	process, ok := canonicalExecutablePath(peer.Process)
	if !ok {
		return false
	}
	self, ok := canonicalExecutablePath(selfPath)
	if !ok {
		return false
	}
	if process == self {
		return true
	}
	name := filepath.Base(process)
	if !trustedBrowserHostName(name, goos) {
		return false
	}
	if filepath.Dir(process) == filepath.Dir(self) {
		return true
	}
	return goos == "darwin" && trustedDarwinSafariHelper(process, self)
}

func canonicalExecutablePath(path string) (string, bool) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return "", false
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", false
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return "", false
	}
	return resolved, true
}

func trustedBrowserHostName(name, goos string) bool {
	if goos == "windows" {
		name = strings.TrimSuffix(name, ".exe")
	}
	switch name {
	case "locklark-browser-chromium", "locklark-browser-firefox", "locklark-browser-safari":
		return true
	}
	return false
}

// trustedDarwinSafariHelper accepts only a Safari helper inside a sibling
// Locklark app bundle. The bundle identity is not verified here; the explicit
// pairing prompt remains the authorization boundary.
func trustedDarwinSafariHelper(process, self string) bool {
	if filepath.Base(process) != "locklark-browser-safari" {
		return false
	}
	processBundle, ok := darwinAppBundleRoot(process)
	if !ok {
		return false
	}
	selfBundle, ok := darwinAppBundleRoot(self)
	if !ok {
		return false
	}
	return filepath.Dir(processBundle) == filepath.Dir(selfBundle)
}

func darwinAppBundleRoot(path string) (string, bool) {
	macos := filepath.Dir(path)
	contents := filepath.Dir(macos)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" {
		return "", false
	}
	root := filepath.Dir(contents)
	if !strings.HasSuffix(root, ".app") {
		return "", false
	}
	return root, true
}

// RelayStdio dials the desktop broker and relays framed native messages.
func RelayStdio(browser Browser, args []string, stdin io.Reader, stdout io.WriteCloser) error {
	if ValidateLaunch(browser, args) != nil {
		return ErrProtocol
	}
	endpoint, e := DefaultBrokerEndpoint()
	if e != nil {
		return ErrBrokerUnavailable
	}
	conn, e := dialLocal(context.Background(), endpoint)
	if e != nil {
		return ErrBrokerUnavailable
	}
	defer conn.Close()
	origin := "chrome-extension://" + ChromiumID + "/"
	if browser == Firefox {
		origin = FirefoxID
	}
	if browser == Safari {
		origin = SafariID
	}
	hello, e := json.Marshal(BrokerHello{V: 1, Browser: browser, Origin: origin})
	if e != nil {
		return ErrBrokerUnavailable
	}
	if e = writeFrame(conn, hello); e != nil {
		clear(hello)
		return ErrBrokerUnavailable
	}
	clear(hello)
	errs := make(chan error, 2)
	go func() {
		for {
			raw, e := readFrame(stdin, MaxInput)
			if e != nil {
				errs <- nil
				return
			}
			e = writeFrame(conn, raw)
			clear(raw)
			if e != nil {
				errs <- ErrBrokerUnavailable
				return
			}
		}
	}()
	go func() {
		for {
			raw, e := readFrame(conn, MaxOutput)
			if e != nil {
				errs <- nil
				return
			}
			frame := binary.NativeEndian.AppendUint32(make([]byte, 0, len(raw)+4), uint32(len(raw)))
			frame = append(frame, raw...)
			_, e = stdout.Write(frame)
			clear(frame)
			clear(raw)
			if e != nil {
				errs <- ErrBrokerUnavailable
				return
			}
		}
	}()
	<-errs
	return nil
}

// cliRunReply is the strict on-the-wire shape of a fixed CLI-run broker reply
// without values ({"v":1,"error":...}). Decoding into this struct only happens
// after the raw object has already been validated as one duplicate-free JSON
// object with exactly the expected keys.
type cliRunReply struct {
	V     int    `json:"v"`
	Error string `json:"error"`
}

// cliRunWireError reports a transport or protocol failure on the CLI-run
// channel. Its text never carries broker payloads, endpoint paths, or request
// secrets, and it never wraps the underlying error.
type cliRunWireError struct{ kind string }

func (e *cliRunWireError) Error() string { return "desktop browser broker " + e.kind }

var (
	errCLIRunHello        = &cliRunWireError{kind: "hello failed"}
	errCLIRunRequest      = &cliRunWireError{kind: "request failed"}
	errCLIRunDial         = &cliRunWireError{kind: "connection failed"}
	errCLIRunResponse     = &cliRunWireError{kind: "response invalid"}
	errCLIRunDisconnected = &cliRunWireError{kind: "disconnected before a response"}
)

var (
	errCLIRunInvalid = errors.New("desktop browser broker request invalid")
	errCLIRunTimeout = errors.New("desktop browser broker timed out")
)

// RequestCLIRun asks a running desktop broker for F17 pinned credentials.
//
// ErrBrokerUnavailable (matched with errors.Is) is returned only when the
// broker is unambiguously absent before any byte was sent (missing or refused
// local socket / missing named pipe) or when the server replies with the exact
// one-object protocol response {"v":1,"error":"unavailable"}. Invalid or
// untrusted endpoint configuration, access/trust dial failures, timeouts,
// malformed or unknown replies, and refusals are never ErrBrokerUnavailable, so
// callers cannot silently fall back to local factors after disclosure may have
// occurred. Cancellation and deadlines are always preserved in every phase.
// Errors never echo broker payloads, endpoint paths, or request secrets.
func RequestCLIRun(ctx context.Context, req CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
	if ctx == nil {
		return CLIRunBrokerResponse{}, errCLIRunInvalid
	}
	if req.V != 1 || len(req.VaultPath) == 0 || len(req.Targets) < 1 || len(req.Targets) > 16 {
		// Invalid input is a caller bug, not proof the broker is absent.
		return CLIRunBrokerResponse{}, errCLIRunInvalid
	}
	if ce := ctx.Err(); ce != nil {
		return CLIRunBrokerResponse{}, ce
	}
	endpoint, e := DefaultBrokerEndpoint()
	if e != nil {
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, ce
		}
		// Invalid or untrusted configuration is not proof of absence.
		return CLIRunBrokerResponse{}, errCLIRunEndpoint
	}
	conn, e := dialLocal(ctx, endpoint)
	if e != nil {
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, ce
		}
		if dialAbsent(e) {
			return CLIRunBrokerResponse{}, ErrBrokerUnavailable
		}
		return CLIRunBrokerResponse{}, errCLIRunDial
	}
	defer conn.Close()
	// Interrupt a blocked hello/request write or response read on cancellation.
	// After the request frame the reply alone decides availability.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	resp, e := cliRunExchange(ctx, conn, req)
	if e == nil {
		return resp, nil
	}
	// A completed exact "unavailable" reply stays fallback-eligible. Every
	// other failure after a cancellation races to the context error so
	// errors.Is(err, context.Canceled/DeadlineExceeded) is preserved.
	if e != ErrBrokerUnavailable {
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, cliRunContextError(ce)
		}
	}
	return CLIRunBrokerResponse{}, e
}

// cliRunContextError preserves errors.Is(..., context.Canceled) and
// errors.Is(..., context.DeadlineExceeded) for cause-carrying contexts (for
// example WithTimeoutCause) without exposing the caller's cause text.
func cliRunContextError(ce error) error {
	switch {
	case errors.Is(ce, context.Canceled):
		return context.Canceled
	case errors.Is(ce, context.DeadlineExceeded):
		return context.DeadlineExceeded
	}
	return errCLIRunTimeout
}

// cliRunExchange writes the hello and request frames, then reads and strictly
// classifies the single response. Once the hello write starts, every failure
// except the exact "unavailable" reply is non-fallback.
func cliRunExchange(ctx context.Context, conn net.Conn, req CLIRunBrokerRequest) (resp CLIRunBrokerResponse, e error) {
	hello, _ := json.Marshal(BrokerHello{V: 1, Mode: "cli-run"})
	if e = writeFrame(conn, hello); e != nil {
		clear(hello)
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, cliRunContextError(ce)
		}
		return CLIRunBrokerResponse{}, errCLIRunHello
	}
	clear(hello)
	raw, _ := json.Marshal(req)
	defer clear(raw)
	if e = writeFrame(conn, raw); e != nil {
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, cliRunContextError(ce)
		}
		return CLIRunBrokerResponse{}, errCLIRunRequest
	}
	respRaw, e := readFrame(conn, MaxOutput)
	if e != nil {
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, cliRunContextError(ce)
		}
		return CLIRunBrokerResponse{}, errCLIRunDisconnected
	}
	defer clear(respRaw)
	return classifyCLIRunResponse(ctx, respRaw)
}

// classifyCLIRunResponse accepts exactly one JSON object with unique keys and
// no trailing data. Only {"v":1,"error":"unavailable"} is fallback-eligible;
// only {"v":1,"error":"refused"} maps to ErrCLIRunRefused. A value reply is
// accepted only without an "error" key and with at least one slot.
func classifyCLIRunResponse(ctx context.Context, raw []byte) (CLIRunBrokerResponse, error) {
	if ce := ctx.Err(); ce != nil {
		return CLIRunBrokerResponse{}, cliRunContextError(ce)
	}
	keys, values, ok := strictJSONObject(raw)
	if !ok {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	if _, hasError := keys["error"]; !hasError {
		return cliRunValuesResponse(keys, values)
	}
	if _, hasValues := keys["values"]; hasValues {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	var errorText string
	if json.Unmarshal(values["error"], &errorText) != nil {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	switch rawError := errorText; rawError {
	case "unavailable", "refused":
		var reply cliRunReply
		if len(keys) != 2 || json.Unmarshal(raw, &reply) != nil || reply.V != 1 || reply.Error != rawError {
			return CLIRunBrokerResponse{}, errCLIRunResponse
		}
		if rawError == "unavailable" {
			return CLIRunBrokerResponse{}, ErrBrokerUnavailable
		}
		return CLIRunBrokerResponse{}, ErrCLIRunRefused
	}
	// Unknown error tokens are surfaced only as a fixed, non-sensitive error.
	return CLIRunBrokerResponse{}, errCLIRunResponse
}

// cliRunValuesResponse maps a disclosed-values reply {"v":1,"values":{...}}.
// The body is re-encoded from the already duplicate-free top-level object and
// decoded with DisallowUnknownFields; on any defect every decoded value is
// cleared and a generic error is returned.
func cliRunValuesResponse(keys map[string]struct{}, values map[string]json.RawMessage) (CLIRunBrokerResponse, error) {
	if len(keys) != 2 || !json.Valid(values["values"]) {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	var slotKeys map[string]json.RawMessage
	if err := json.Unmarshal(values["values"], &slotKeys); err != nil {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	if len(slotKeys) == 0 {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	for slot := range slotKeys {
		if slot == "" {
			return CLIRunBrokerResponse{}, errCLIRunResponse
		}
	}
	var body struct {
		V      int               `json:"v"`
		Values map[string]string `json:"values"`
	}
	dec := json.NewDecoder(bytes.NewReader(values["values"]))
	dec.DisallowUnknownFields()
	if json.Unmarshal(values["v"], &body.V) != nil || body.V != 1 ||
		dec.Decode(&body.Values) != nil || len(body.Values) != len(slotKeys) {
		clearCLIRunValues(body.Values)
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	for _, value := range body.Values {
		if value == "" {
			clearCLIRunValues(body.Values)
			return CLIRunBrokerResponse{}, errCLIRunResponse
		}
	}
	return CLIRunBrokerResponse{V: 1, Values: body.Values}, nil
}

// clearCLIRunValues clears decoded (and duplicated) secret strings on refusal
// paths so they are not retained by returned errors.
func clearCLIRunValues(values map[string]string) {
	for slot := range values {
		values[slot] = ""
	}
}

// strictJSONObject validates that raw is exactly one JSON object (no trailing
// values), reports its top-level keys (rejecting duplicates and non-string
// keys), and returns each top-level value's raw bytes.
func strictJSONObject(raw []byte) (map[string]struct{}, map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, e := dec.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, nil, false
	}
	keys := map[string]struct{}{}
	values := map[string]json.RawMessage{}
	for dec.More() {
		tok, e := dec.Token()
		if e != nil {
			return nil, nil, false
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil, false
		}
		if _, dup := keys[key]; dup {
			return nil, nil, false
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return nil, nil, false
		}
		keys[key] = struct{}{}
		values[key] = value
	}
	if tok, e := dec.Token(); e != nil || tok != json.Delim('}') {
		return nil, nil, false
	}
	if _, e := dec.Token(); e != io.EOF {
		return nil, nil, false
	}
	return keys, values, true
}
