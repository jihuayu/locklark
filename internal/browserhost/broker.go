package browserhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

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
	// PrepareCLIRunV2 is the one-shot cli-run v2 approval path. It receives the
	// fully reconstructed trusted scope (never caller JSON) and returns only an
	// opaque native grant. When it is set, the legacy per-field v1 path is
	// disabled so an old client can never be served implicitly.
	PrepareCLIRunV2 func(context.Context, CLIRunV2Scope) (*NativeCLIRunV2, error)
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
	// authenticatedPeer names the connection creator (SO_PEERCRED). On Linux the
	// creator is not necessarily the writer: a forked/exec'd child can inherit
	// the connected descriptor and send the request. Every subsequent read must
	// therefore be attributed to its real writer before the first hello byte is
	// parsed, so wrap the connection ahead of readFrame. The wrapper keeps normal
	// writes, deadlines and Close and refuses mismatched or missing
	// SCM_CREDENTIALS instead of falling back to an unverified Read.
	conn, e = guardRequestWriter(conn)
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
	if dec.Decode(&hello) != nil {
		clear(raw)
		return
	}
	v1 := hello.V == 1
	v2 := hello.V == cliRunV2Version && hello.Mode == cliRunV2Mode && hello.Browser == "" && hello.Origin == "" && validCLIRunV2Hello(raw)
	clear(raw)
	if v2 {
		b.serveCLIRunV2(conn, peer)
		return
	}
	if !v1 {
		return
	}
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
	// A shipped v2 CLI disables the legacy per-field path entirely: no request
	// may silently fall through to the older extract-and-return protocol.
	if b.callbacks.PrepareCLIRunV2 != nil {
		writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: "refused"})
		return
	}
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
			switch {
			case errors.Is(err, ErrBrokerUnavailable):
				resp.Error = "unavailable"
			case errors.Is(err, ErrBrokerUnknown):
				resp.Error = "unknown"
			default:
				resp.Error = "refused"
			}
		} else {
			resp.Values = out.Values
		}
	} else {
		resp.Error = "unavailable"
	}
	writeCLIResponse(conn, resp)
	resp.dropValues()
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

// cliRunMaxValueBytes bounds each disclosed CLI-run value so one slot can never
// consume the whole response frame.
const cliRunMaxValueBytes = 64 << 10

// RequestCLIRun asks a running desktop broker for F17 pinned credentials.
//
// The returned sentinel drives the caller's fallback decision. ErrBrokerUnavailable
// is reserved for a clearly absent trusted endpoint or a connection that was
// never established, which are the only cases where no secret request can have
// reached the broker. Anything after the connection exists (write failure, read
// timeout, disconnect, malformed or unverifiable response, unknown server
// outcome) may already have disclosed credentials and is reported as
// ErrBrokerUnknown. Locally rejected requests, cancellation before the
// secret request is written, and explicit refusals are ErrBrokerRefused.
// Neither sentinel permits an automatic fallback, and peer-supplied error text
// is never echoed.
func RequestCLIRun(ctx context.Context, req CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
	if ctx == nil || !validCLIRunBrokerRequest(req) || ctx.Err() != nil {
		return CLIRunBrokerResponse{}, ErrBrokerRefused
	}
	hello, e := json.Marshal(BrokerHello{V: 1, Mode: "cli-run"})
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerRefused
	}
	defer clear(hello)
	raw, e := json.Marshal(req)
	if e != nil {
		return CLIRunBrokerResponse{}, ErrBrokerRefused
	}
	defer clear(raw)

	endpoint, e := brokerEndpointForClient()
	if e != nil {
		return CLIRunBrokerResponse{}, e
	}
	conn, e := dialVerifiedBroker(ctx, endpoint)
	if e != nil {
		return CLIRunBrokerResponse{}, e
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := watchCLIRunContext(ctx, conn)
	defer stop()

	// From here on the trusted broker is reachable and may act on the request,
	// so no failure may be classified as "unavailable" (fallback-safe).
	if e = writeFrame(conn, hello); e != nil {
		return CLIRunBrokerResponse{}, cliRunFailure(ctx, false)
	}
	clear(hello)
	if e = writeFrame(conn, raw); e != nil {
		return CLIRunBrokerResponse{}, cliRunFailure(ctx, true)
	}
	clear(raw)
	respRaw, e := readFrame(conn, MaxOutput)
	if e != nil {
		return CLIRunBrokerResponse{}, cliRunFailure(ctx, true)
	}
	defer clear(respRaw)
	resp, e := decodeCLIRunResponse(respRaw)
	if e != nil {
		return CLIRunBrokerResponse{}, e
	}
	if ctx.Err() != nil {
		resp.dropValues()
		return CLIRunBrokerResponse{}, ErrBrokerUnknown
	}
	if resp.Error != "" {
		e := cliRunServerError(resp.Error)
		resp.dropValues()
		return CLIRunBrokerResponse{}, e
	}
	if !cliRunSlotsMatch(req.Targets, resp.Values) {
		resp.dropValues()
		// The request was accepted and possibly acted on; a nonconforming
		// success payload is an unverifiable post-request outcome, not a
		// pre-disclosure refusal.
		return CLIRunBrokerResponse{}, ErrBrokerUnknown
	}
	return resp, nil
}

// watchCLIRunContext closes conn as soon as ctx is done, including contexts
// without a deadline. The returned stop function waits for the watcher to exit
// so no goroutine outlives the request.
func watchCLIRunContext(ctx context.Context, conn net.Conn) func() {
	stop := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-exited
	}
}

// cliRunFailure classifies a post-connect transport failure. Before the secret
// request write is attempted a cancelled context is a local refusal; once that
// write has been attempted the broker may already have acted and disclosed
// credentials, so cancellation and deadline expiry are unknown.
func cliRunFailure(ctx context.Context, submitted bool) error {
	if !submitted && ctx.Err() != nil {
		return ErrBrokerRefused
	}
	return ErrBrokerUnknown
}

func validCLIRunBrokerRequest(req CLIRunBrokerRequest) bool {
	if req.V != 1 || len(req.VaultPath) == 0 || len(req.VaultPath) > 4096 || !utf8.ValidString(req.VaultPath) {
		return false
	}
	if len(req.Targets) < 1 || len(req.Targets) > 16 {
		return false
	}
	seen := make(map[string]bool, len(req.Targets))
	for _, t := range req.Targets {
		if t.Slot == "" || len(t.Slot) > 128 || !utf8.ValidString(t.Slot) || seen[t.Slot] {
			return false
		}
		if !cliRunCanonicalHex(t.ID, 16) || !cliRunCanonicalHex(t.Revision, 32) {
			return false
		}
		switch t.Field {
		case "username", "password", "url", "notes", "otp":
		default:
			return false
		}
		seen[t.Slot] = true
	}
	return true
}

// cliRunCanonicalHex accepts exactly the canonical lowercase hex encoding of
// an n-byte value (16 bytes for item IDs, 32 for revisions). Anything else,
// including shorter, longer, uppercase or non-hex text, is invalid locally.
func cliRunCanonicalHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	raw, e := hex.DecodeString(s)
	if e != nil || len(raw) != n {
		return false
	}
	canonical := hex.EncodeToString(raw) == s
	clear(raw)
	return canonical
}

// decodeCLIRunResponse accepts exactly one bounded version-1 response object.
// Version drift, unknown fields and trailing content are distinct from an
// explicit refusal and are reported as unknown.
func decodeCLIRunResponse(raw []byte) (CLIRunBrokerResponse, error) {
	var resp CLIRunBrokerResponse
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&resp) != nil {
		return CLIRunBrokerResponse{}, ErrBrokerUnknown
	}
	var extra json.RawMessage
	if dec.Decode(&extra) != io.EOF {
		resp.dropValues()
		return CLIRunBrokerResponse{}, ErrBrokerUnknown
	}
	if resp.V != 1 {
		resp.dropValues()
		return CLIRunBrokerResponse{}, ErrBrokerUnknown
	}
	return resp, nil
}

// cliRunServerError maps the broker's fixed error codes onto fixed sentinels.
// The peer string is never propagated to the caller.
func cliRunServerError(code string) error {
	switch code {
	case "unavailable":
		return ErrBrokerUnavailable
	case "refused":
		return ErrBrokerRefused
	default:
		return ErrBrokerUnknown
	}
}

// cliRunSlotsMatch requires the success payload to carry exactly one
// length-bounded value for each requested slot, with no extras or omissions.
func cliRunSlotsMatch(targets []personal.CLIBrokerTarget, values map[string]string) bool {
	if len(values) != len(targets) {
		return false
	}
	for _, t := range targets {
		value, ok := values[t.Slot]
		if !ok || len(value) > cliRunMaxValueBytes {
			return false
		}
	}
	return true
}

// dropValues releases the response's owned secret references. Go strings cannot
// be zeroized, so this drops the map rather than claiming erasure.
func (r *CLIRunBrokerResponse) dropValues() {
	if r.Values == nil {
		return
	}
	for k := range r.Values {
		r.Values[k] = ""
	}
	r.Values = nil
}
