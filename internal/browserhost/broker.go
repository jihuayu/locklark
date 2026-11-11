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

// handshake reads the bounded hello and authenticates the OS peer before any
// hello byte is decoded or any side effect is dispatched. peerBeforeHello
// is false on Unix, which takes the peer identity from already-connected
// socket credentials before reading (unchanged); it is true on Windows, where
// ImpersonateNamedPipeClient authenticates the security context of the last
// message read, so the hello must be the first read and the peer is resolved
// from that same pipe handle before parsing. Every step fails closed with a
// nil frame and no peer.
func (b *Broker) handshake(conn net.Conn) (Peer, []byte) {
	if !peerBeforeHello {
		peer, e := authenticatedPeer(conn)
		if e != nil {
			return Peer{}, nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, e := readFrame(conn, 4096)
		if e != nil {
			clear(raw)
			return Peer{}, nil
		}
		_ = conn.SetReadDeadline(time.Time{})
		return peer, raw
	}
	// Clear the read deadline before impersonating: the identity query issues
	// overlapped I/O on the same pipe handle the deadline timer would close.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, e := readFrame(conn, 4096)
	_ = conn.SetReadDeadline(time.Time{})
	if e != nil {
		clear(raw)
		return Peer{}, nil
	}
	peer, e := authenticatedPeer(conn)
	if e != nil {
		clear(raw)
		return Peer{}, nil
	}
	return peer, raw
}

func (b *Broker) serve(conn net.Conn) {
	defer conn.Close()
	peer, raw := b.handshake(conn)
	if raw == nil {
		return
	}
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
// never participate. The on-disk owner/permission check is platform-specific
// (see peer_exec_*.go); it refuses a host binary writable by anyone but its
// owner.
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

// peerProcessAllowedFor is the pure policy used by tests. The process must be
// the desktop's own canonical executable or one exact Locklark browser host
// name at any absolute installation directory. The directory is deliberately
// not constrained: native-host registration accepts any absolute --host path.
// What binds the peer is the OS-authenticated canonical path, its exact
// basename, and the owner/permission trust of the file on disk. The user's
// declared Browser/Origin never participate.
func peerProcessAllowedFor(peer Peer, selfPath, goos string) bool {
	if peer.PID == 0 || peer.User == "" {
		return false
	}
	process, ok := canonicalExecutablePath(peer.Process)
	if !ok {
		return false
	}
	if self, ok := canonicalExecutablePath(selfPath); ok && process == self {
		return true
	}
	if !trustedBrowserHostName(filepath.Base(process), goos) {
		return false
	}
	return trustedPeerExecutable(process, peer.User, goos)
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

// RequestCLIRun asks a running desktop broker for F17 pinned credentials.
func RequestCLIRun(ctx context.Context, req CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
	if ctx == nil || req.V != 1 || len(req.VaultPath) == 0 || len(req.Targets) < 1 || len(req.Targets) > 16 {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	endpoint, e := DefaultBrokerEndpoint()
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	conn, e := dialLocal(ctx, endpoint)
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	defer conn.Close()
	hello, _ := json.Marshal(BrokerHello{V: 1, Mode: "cli-run"})
	if e = writeFrame(conn, hello); e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	clear(hello)
	raw, e := json.Marshal(req)
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	defer clear(raw)
	if e = writeFrame(conn, raw); e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	respRaw, e := readFrame(conn, MaxOutput)
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	defer clear(respRaw)
	var resp CLIRunBrokerResponse
	dec := json.NewDecoder(bytes.NewReader(respRaw))
	dec.DisallowUnknownFields()
	if dec.Decode(&resp) != nil || resp.V != 1 {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	if resp.Error != "" {
		if resp.Error == "unavailable" {
			return CLIRunBrokerResponse{}, ErrBrokerUnavailable
		}
		return CLIRunBrokerResponse{}, errors.New(resp.Error)
	}
	return resp, nil
}
