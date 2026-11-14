package browserhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

// CLIRunApprovalMaxLifetime bounds one legacy CLI approval from the request
// frame through the response. It is absolute: activity never extends it, and a
// caller deadline earlier than this cap remains authoritative.
const CLIRunApprovalMaxLifetime = 60 * time.Second

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

// NotifyUnlocked binds the shared desktop session to all connected clients.
func (b *Broker) NotifyUnlocked(s *personal.Session, epoch uint64, quickFill bool) {
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
		_ = c.BindDesktopSession(s, epoch, quickFill)
	}
	if b.callbacks.NotifyChanged != nil {
		b.callbacks.NotifyChanged()
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
	if !validHello(hello) {
		return
	}
	writer := NewNativeWriter(conn, 250*time.Millisecond, func() { _ = conn.Close() })
	c := NewDesktopConnection(writer, func() {
		if b.callbacks.NotifyChanged != nil {
			b.callbacks.NotifyChanged()
		}
	})
	c.SetBroker(b)
	if !b.addConn(c) {
		return
	}
	defer func() {
		b.dropConn(c)
		c.Close()
	}()
	if b.callbacks.CurrentSession != nil {
		if s, epoch, quick := b.callbacks.CurrentSession(); s != nil && s.Unlocked() {
			_ = c.bindDesktopSession(s, epoch, quick, false)
		}
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), CLIRunApprovalMaxLifetime)
	defer cancel()

	// The legacy CLI wire contract sends one request and then waits. Any read
	// after that frame -- EOF, a fully closed connection, or an unexpected byte
	// -- means the client is gone or violated the contract. Cancel the native
	// approval immediately so its exact pending review is retired instead of
	// lingering until the absolute lifetime expires.
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		var extra [1]byte
		_, _ = conn.Read(extra[:])
		cancel()
	}()

	resp := CLIRunBrokerResponse{V: 1}
	var callbackValues map[string]string
	if b.callbacks.HandleCLIRun != nil {
		out, err := b.callbacks.HandleCLIRun(ctx, peer, req)
		callbackValues = out.Values
		switch {
		case ctx.Err() != nil:
			// A disconnect, unexpected input, or the absolute deadline wins
			// over a late callback result. Values are cleared below and never
			// reach the wire.
			resp.Error = "refused"
		case err != nil:
			if errors.Is(err, ErrBrokerUnavailable) {
				resp.Error = "unavailable"
			} else {
				resp.Error = "refused"
			}
		default:
			resp.Values = out.Values
		}
	} else {
		resp.Error = "unavailable"
	}
	// Recheck after approval and immediately before encoding/disclosure. This
	// is the same absolute deadline; no activity renews it.
	if ctx.Err() != nil {
		resp.Values = nil
		resp.Error = "refused"
	}
	writeCLIResponse(conn, resp)
	clearCLIResponseValues(callbackValues)
	clearCLIResponseValues(resp.Values)
	// Closing the connection unblocks the watcher; waiting for it proves no
	// read goroutine outlives the request.
	_ = conn.Close()
	<-watchDone
}

func clearCLIResponseValues(values map[string]string) {
	for key := range values {
		values[key] = ""
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
	// The cap is absolute. A shorter caller deadline is preserved by
	// WithTimeout and closes the connection below, which also cancels the
	// desktop-side approval promptly.
	ctx, cancel := context.WithTimeout(ctx, CLIRunApprovalMaxLifetime)
	defer cancel()
	endpoint, e := DefaultBrokerEndpoint()
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	conn, e := dialLocal(ctx, endpoint)
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	defer conn.Close()
	// Context expiry interrupts a blocked frame read; without this the client
	// would wait for the server's absolute lifetime even after its own caller
	// deadline passed.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
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
	if ctx.Err() != nil {
		for key := range resp.Values {
			resp.Values[key] = ""
		}
		return CLIRunBrokerResponse{}, ErrBrokerUnavailable
	}
	return resp, nil
}
