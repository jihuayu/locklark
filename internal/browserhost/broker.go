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

	"github.com/jihuayu/locklark/internal/cliprofile"
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

// CLIRunBrokerRequest asks the desktop broker for pinned secret values. Scope
// is the immutable, bounded execution scope shown in native approval; Targets
// are the immutable vault slots/revisions/fields. Nothing else crosses the wire.
type CLIRunBrokerRequest struct {
	V         int                        `json:"v"`
	VaultPath string                     `json:"vault_path"`
	Scope     CLIRunScope                `json:"scope"`
	Targets   []personal.CLIBrokerTarget `json:"targets"`
	// DeliveryControl is an explicit opt-in for the post-response control
	// socket. It is an intent only: proof, nonce, scope, and approval still
	// decide every authorization question.
	DeliveryControl bool `json:"delivery_control,omitempty"`
	cttyProof       *clirunCTTYProof
}

// CLIRunBrokerResponse is the audited one-shot reply of the desktop broker.
//
// PreparedValues are the exact per-slot bytes PrepareBrokeredRun prepared,
// after the matching item.run.bundle intent was committed, and Receipt names
// that intent. They are the only success payload that can reach the wire, as
// the values_b64 and receipt members (broker_response.go), and a success must
// carry both or the broker writes a fixed refusal.
//
// Values is the legacy, unaudited payload an older callback returns from
// ExtractCLIBrokerTargets. It is retained only so that source stays
// compatible; it is never encoded, never decoded, and never decoded back into
// this field, so it cannot disclose a value between checkpoints. A success
// with only Values is replaced by the fixed refusal.
type CLIRunBrokerResponse struct {
	V              int                                  `json:"v"`
	Values         map[string]string                    `json:"-"`
	PreparedValues map[string][]byte                    `json:"-"`
	Receipt        personal.RunBundlePreparationReceipt `json:"-"`
	Error          string                               `json:"error,omitempty"`
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
// cliRunControlMaxLifetime bounds the transport control socket. It is not a
// session authority cap; a future lease activation must additionally take the
// minimum with the real Session.AuthorityDeadline.
const cliRunControlMaxLifetime = 2 * time.Minute

type cliRunControlReadOutcome uint8

const (
	cliRunControlReadError cliRunControlReadOutcome = iota
	cliRunControlReadEOF
	cliRunControlReadFrame
)

type cliRunControlReadObservation struct {
	Outcome cliRunControlReadOutcome
	Length  int
}

type Broker struct {
	callbacks BrokerCallbacks
	listener  net.Listener
	// cliRunControlLifetime can only shorten the fixed two-minute control
	// lifetime; it is a per-broker test seam, never a production extension.
	cliRunControlLifetime time.Duration
	// cliRunControlObserve is a nil-by-default, per-broker test observation of
	// the unique post-ready reader's fixed outcome and frame length. It never
	// receives raw bytes, a connection, proof material, or authority.
	cliRunControlObserve func(cliRunControlReadObservation)
	// cliRunControlChallenge is a nil-by-default per-broker entropy seam for
	// tests; production uses crypto/rand. It cannot grant authority.
	cliRunControlChallenge func() (string, error)
	mu                     sync.Mutex
	conns                  map[*Connection]bool
	never                  map[string]bool
	closed                 bool
	done                   chan struct{}
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

// peerAfterHello picks the handshake order at compile time. On Windows it is
// true: ImpersonateNamedPipeClient authenticates the security context of the
// last message read from the pipe, so the broker reads the bounded hello first
// and only then queries the client identity from that same pipe handle. Every
// other build is false: the peer identity comes from already-connected socket
// credentials before any read.
const peerAfterHello = runtime.GOOS == "windows"

// handshake reads the bounded hello and authenticates the OS peer before any
// hello byte is decoded or any side effect is dispatched. Every step fails
// closed with a nil frame and no peer.
func (b *Broker) handshake(conn net.Conn) (Peer, []byte) {
	if !peerAfterHello {
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
	// A deadline that cannot be set leaves the read unbounded: fail closed.
	if conn.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		return Peer{}, nil
	}
	raw, e := readFrame(conn, 4096)
	if e != nil {
		clear(raw)
		return Peer{}, nil
	}
	// Clear the deadline before authenticating the peer on this same handle; a
	// deadline that cannot be cleared aborts the hello unparsed.
	if conn.SetReadDeadline(time.Time{}) != nil {
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

func (b *Broker) serveCLIRun(conn net.Conn, peer Peer) error {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, e := readFrame(conn, MaxInput)
	if e != nil {
		return e
	}
	_ = conn.SetReadDeadline(time.Time{})
	// The decoded scope is the only copy kept: it stays alive through native
	// approval and the callback and is cleared, with the raw request frame and
	// the decoded targets, once the response is written.
	req, ok := decodeCLIRunBrokerRequest(raw)
	if !ok {
		clear(raw)
		return writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
	}
	defer func() {
		clear(raw)
		req.Scope.Clear()
		clearCLIRunTargets(req.Targets)
	}()
	resp := CLIRunBrokerResponse{V: 1}
	// Authorization checkpoint, both before native approval:
	//
	//  1. The nonce is consumed now, at most once, and stays consumed for
	//     every later outcome: refused, cancelled, timed out, or never
	//     delivered. A replay or a full cache is refused before approval, and
	//     before the terminal check, so neither can be used to probe it.
	//  2. The terminal must be authenticated from this connection, never from
	//     a declared string. Linux uses the sealed live CTTY association built
	//     from the authenticated Unix socket; Darwin/Windows retain the legacy
	//     gate. A Linux connection with no self CTTY/no Unix socket uses the
	//     legacy gate as its only decider; production Linux still refuses there.
	//     Every proof/gate failure, including unsupported, stale, mismatched,
	//     or missing proof, is a fixed refusal. After a valid proof only the
	//     exact ErrBrokerUnavailable callback sentinel or a missing callback
	//     may select "unavailable" (handleCLIRunConn), so no TTY outcome can be
	//     fallback-eligible.
	//
	// Only after a valid proof/gate is a missing HandleCLIRun classified as the
	// explicit unavailable: it must not short-circuit a refused nonce or an
	// unattested, unsupported, or mismatching terminal, so those always stay a
	// fixed refusal whatever the callback state.
	if consumeCLIRunNonce(peer, req.Scope.Nonce) != nil {
		return writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
	}
	if cliRunCTTYProofRequired() {
		proof, boundPeer, proofErr := newCLIRunCTTYProof(conn, peer, req.Scope)
		switch {
		case proofErr == errCLIRunCTTYUnsupported:
			// No self CTTY or no Unix connection: the legacy gate remains the
			// only decider. On Linux production it always refuses.
			if cliRunTTYGate(peer, req.Scope.TTY, req.Scope.TTYPlatform, req.Scope.TTYPeerID) != nil {
				return writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
			}
		case proofErr != nil:
			return writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
		default:
			defer proof.Close()
			req.cttyProof = proof
			peer = boundPeer
			if !req.VerifyCLIRunCTTY(peer) {
				return writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
			}
		}
	} else if cliRunTTYGate(peer, req.Scope.TTY, req.Scope.TTYPlatform, req.Scope.TTYPeerID) != nil {
		return writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
	}
	if b.callbacks.HandleCLIRun == nil {
		if req.cttyProof != nil && !req.VerifyCLIRunCTTY(peer) {
			return writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
		}
		resp.Error = cliRunErrorUnavailable
		return writeCLIResponse(conn, resp)
	}
	// The request frame is fully read, validated, terminal-attested, and its
	// nonce consumed; the callback still runs with an OS-authenticated peer.
	// Monitor the now-idle connection while it waits: a client that closes,
	// or sends an unexpected extra byte, cancels the callback instead of
	// leaving a native approval prompt pending after the CLI exited. Context
	// values stay nil; only cancellation is propagated.
	writeErr := b.handleCLIRunConn(conn, peer, req, &resp)
	// Whether the frame was written fully or failed, the broker's own prepared
	// copy is cleared here. A successful write is only transport completion,
	// never proof that the client adopted a value or granted a lease.
	clearCLIRunResponse(&resp)
	return writeErr
}

// cliRunTTYGate is the legacy/self-CTTY-missing gate. On Linux, a self CTTY
// uses newCLIRunCTTYProof instead; when no self CTTY or Unix connection exists,
// this gate remains the only decider and production Linux still refuses. Its
// verdict has two outcomes here: nil proceeds, anything else is the fixed
// refusal. Tests replace it only for unit coverage; that seam never authorizes
// a Linux connection that has a live qualified proof.
var cliRunTTYGate = verifyCLIRunTTY

// handleCLIRunConn runs HandleCLIRun with a cancelable context, writes the
// single classified response, and only then closes conn. The close is what
// releases the connection monitor, which is never awaited here because it
// cannot write: a close after the response, while the monitor goroutine only
// reads, is safe. Until then the monitor keeps reading across idle timeouts,
// so a client that closes (EOF) or sends an unexpected extra byte at any point
// cancels the callback instead of leaving a native approval pending after the
// CLI has exited.
//
// The callback never sees the broker's parsed request. Before it runs, the
// requested target identities are captured in an immutable expectedTargets
// slot snapshot that no callback-reachable value aliases, and the callback
// receives a deep request copy it owns outright: the scope is copied by
// CLIRunScope.Clone and the targets slice is freshly allocated. A callback that
// mutates, reorders, or clears anything in its copy therefore changes neither
// the broker's parsed request nor the slots the returned PreparedValues are
// bound to.
func (b *Broker) handleCLIRunConn(conn net.Conn, peer Peer, req CLIRunBrokerRequest, resp *CLIRunBrokerResponse) error {
	controlStarted := time.Now()
	// The snapshot is captured from req and never handed out. Its slot names
	// are owned string copies, so nothing the callback (or the broker clearing
	// req later) does to another slice reaches it. The callback request is a
	// distinct allocation for the targets slice, a clone for the scope, and
	// independent copies for every derived slice and map. Both are cleared on
	// every return; Go strings cannot be securely wiped, only the containers.
	expectedTargets := make([]personal.CLIBrokerTarget, len(req.Targets))
	for i, target := range req.Targets {
		expectedTargets[i] = personal.CLIBrokerTarget{
			Slot:     string([]byte(target.Slot)),
			ID:       string([]byte(target.ID)),
			Revision: string([]byte(target.Revision)),
			Field:    string([]byte(target.Field)),
		}
	}
	callbackReq := CLIRunBrokerRequest{
		V:               req.V,
		VaultPath:       string([]byte(req.VaultPath)),
		Scope:           req.Scope.Clone(),
		Targets:         make([]personal.CLIBrokerTarget, len(expectedTargets)),
		DeliveryControl: req.DeliveryControl,
		cttyProof:       req.cttyProof,
	}
	copy(callbackReq.Targets, expectedTargets)
	defer clearCLIRunTargets(expectedTargets)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var controlTimer *time.Timer
	if req.DeliveryControl {
		lifetime := cliRunControlMaxLifetime
		if b.cliRunControlLifetime > 0 && b.cliRunControlLifetime < lifetime {
			lifetime = b.cliRunControlLifetime
		}
		remaining := lifetime - time.Since(controlStarted)
		if remaining <= 0 {
			cancel()
			_ = conn.Close()
			return errCLIRunControl
		}
		controlTimer = time.AfterFunc(remaining, func() {
			cancel()
			_ = conn.Close()
		})
		defer controlTimer.Stop()
	}
	stop := make(chan struct{})
	watchExit := make(chan bool, 1)
	go func() {
		watchExit <- watchCLIRunConn(conn, cancel, stop, cliRunMonitorIdle)
	}()
	out, err := b.callbacks.HandleCLIRun(ctx, peer, callbackReq)
	// Everything the callback returned that is not transferred is cleared on
	// every exit. Only a successful callback hands its prepared bytes over to
	// resp; an error, a legacy-only or otherwise unaudited reply, and a reply
	// the writer rejects all leave the callback's buffers to be zeroed below.
	//
	// The callback's PreparedValues are bound to the expectedTargets snapshot
	// before the reply is encoded: the served reply must carry exactly one
	// non-nil buffer per requested slot and nothing else, and it is encoded
	// here rather than left to the writer's unbound generic check. A missing,
	// extra, nil, or legacy-only reply is the fixed refusal. Every callback
	// buffer is zeroed here on every exit, whichever of the above happened.
	transferred := false
	bound, bindErr := []byte(nil), error(errCLIRunResponse)
	defer func() {
		if !transferred {
			resp.PreparedValues = nil
			resp.Receipt = personal.RunBundlePreparationReceipt{}
		}
		clearCLIRunValueMap(out.PreparedValues)
		clearCLIRunValues(out.Values)
		out.PreparedValues, out.Values = nil, nil
		// The callback's request containers are cleared on every return,
		// whatever the callback did to them; Go strings are not wiped.
		callbackReq.Scope.Clear()
		clearCLIRunTargets(callbackReq.Targets)
		callbackReq.Targets = nil
	}()
	// A stale proof never turns a callback success or unavailable sentinel into
	// disclosure: recheck the exact peer/scope binding before any transfer.
	staleProof := req.cttyProof != nil && !req.VerifyCLIRunCTTY(peer)
	// Only the exact transport/service-unavailable sentinel may select the
	// explicit unavailable token; a wrapped copy of it (errors.Is), a refusal,
	// a cancellation, a deadline, or any other callback error is a refusal.
	switch {
	case staleProof:
		resp.Error = cliRunErrorRefused
	case err == nil:
		// Only the audited pair crosses: prepared bytes plus the canonical
		// receipt, and only when the slots are exactly the requested ones as
		// captured before the callback, never as the callback left them.
		// The legacy Values map is never taken, so an unaudited reply is
		// replaced by the fixed refusal by the writer.
		if validCLIRunValues(expectedTargets, out.PreparedValues) {
			bound, bindErr = marshalCLIRunValues(out.PreparedValues, out.Receipt)
		}
		if bindErr == nil {
			resp.PreparedValues, resp.Receipt = out.PreparedValues, out.Receipt
			out.PreparedValues = nil
			transferred = true
		} else {
			resp.Error = cliRunErrorRefused
		}
	case err == ErrBrokerUnavailable:
		resp.Error = cliRunErrorUnavailable
	default:
		resp.Error = cliRunErrorRefused
	}
	// Generate the delivery-control challenge before writing any successful
	// prepared reply. An entropy failure writes only the fixed refusal and
	// never leaks the prepared values.
	var controlChallenge string
	if req.DeliveryControl && transferred && bindErr == nil {
		generate := b.cliRunControlChallenge
		if generate == nil {
			generate = newCLIRunControlChallenge
		}
		challenge, challengeErr := generate()
		if challengeErr != nil || !validCLIRunControlChallenge(challenge) {
			writeErr := writeCLIResponse(conn, CLIRunBrokerResponse{V: 1, Error: cliRunErrorRefused})
			close(stop)
			_ = conn.Close()
			if writeErr != nil {
				return writeErr
			}
			return errCLIRunControl
		}
		controlChallenge = challenge
	}
	// writeCLIResponse neither modifies nor takes ownership of resp: it
	// re-checks the response pair first, so values with an error, values
	// without a canonical receipt, and the legacy map can never reach the
	// wire. Whatever it rejects stays callback-owned and is cleared above;
	// whatever it writes is cleared by the caller. A transferred success is
	// written from the already slot-bound encoding, so the bytes that were
	// checked against the expected target snapshot are exactly the bytes that
	// go out.
	var writeErr error
	if transferred && bindErr == nil {
		writeErr = writeCLIRunRaw(conn, bound)
	} else {
		writeErr = writeCLIResponse(conn, *resp)
	}
	// A control-ready reply is sent only after a complete audited success was
	// written and only when the request explicitly opted in. The monitor stays
	// alive to detect the client's Close, EOF, or cancellation; this handler
	// then closes the retained socket. No lease is activated here.
	if req.DeliveryControl && transferred && bindErr == nil && writeErr == nil {
		// Stop the pre-ready monitor before writing the ready frame. The
		// deadline wake bounds this; a byte it already read is a refusal. Only
		// after its Read has exited does the single new reader touch the conn.
		if !stopCLIRunMonitor(conn, stop, watchExit) {
			_ = conn.Close()
			return errCLIRunControl
		}
		if e := writeCLIRunControlReady(conn, controlChallenge); e != nil {
			_ = conn.Close()
			return e
		}
		raw, readErr := readFrame(conn, MaxOutput)
		if b.cliRunControlObserve != nil {
			observation := cliRunControlReadObservation{Outcome: cliRunControlReadError}
			switch {
			case readErr == nil:
				observation.Outcome = cliRunControlReadFrame
				observation.Length = len(raw)
			case errors.Is(readErr, io.EOF):
				observation.Outcome = cliRunControlReadEOF
			}
			b.cliRunControlObserve(observation)
		}
		clear(raw)
		_ = conn.Close()
		return nil
	}
	// Closing unblocks the monitor if it is still reading; the close of stop
	// tells it a lost monitor is expected rather than a client cancellation.
	close(stop)
	_ = conn.Close()
	return writeErr
}

// watchCLIRunConn watches an idle CLI-run connection for the whole time the
// callback is pending and calls cancel on EOF, on any unexpected inbound byte,
// or on any non-timeout read failure. An idle read timeout is not a
// cancellation: it only bounds each read (so the monitor wakes to observe
// stop), after which the monitor keeps reading. Closing stop is used for the
// control handoff: the monitor exits without consuming or cancelling, and the
// handler does not write control-ready until that Read has exited. The watcher
// never writes.
func watchCLIRunConn(conn net.Conn, cancel context.CancelFunc, stop <-chan struct{}, idle time.Duration) bool {
	var in [1]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		n, e := conn.Read(in[:])
		if n > 0 {
			cancel() // unexpected input, even alongside a timeout error
			return true
		}
		if !cliRunMonitorTimeout(e) {
			cancel()
			return true
		}
		select {
		case <-stop:
			return false
		default:
		}
	}
}

const cliRunControlHandoffLimit = 2 * time.Second

// stopCLIRunMonitor wakes the sole pre-ready reader with a deadline, confirms
// its Read has exited, and resets the deadline before the new owner reads.
// It returns false on a pre-ready byte/disconnect or if the bounded handoff
// does not complete.
func stopCLIRunMonitor(conn net.Conn, stop chan struct{}, exit <-chan bool) bool {
	close(stop)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	limit := time.NewTimer(cliRunControlHandoffLimit)
	defer limit.Stop()
	deadline := time.Now()
	for {
		_ = conn.SetReadDeadline(deadline)
		select {
		case canceled := <-exit:
			if canceled {
				return false
			}
			if conn.SetReadDeadline(time.Time{}) != nil {
				return false
			}
			return true
		case <-ticker.C:
		case <-limit.C:
			return false
		}
	}
}

// cliRunMonitorTimeout reports whether a read error is an idle deadline, not a
// disconnect. It accepts both the portable net.Error timeout and
// os.ErrDeadlineExceeded: some transports (for example Windows named pipes via
// go-winio) report a timeout without unwrapping to os.ErrDeadlineExceeded.
func cliRunMonitorTimeout(e error) bool {
	if errors.Is(e, os.ErrDeadlineExceeded) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(e, &timeout) && timeout.Timeout()
}

// cliRunMonitorIdle bounds one idle read of the continuous CLI-run connection
// monitor. Reaching it only reschedules the next read; cancellation is still
// observed when the CLI later disconnects or sends an extra byte.
const cliRunMonitorIdle = time.Minute

// maxCLIRunFieldBytes bounds every top-level value of a CLI-run request except
// the scope object itself, whose fields are bounded individually.
const maxCLIRunFieldBytes = 16 << 10

// decodeCLIRunBrokerRequest strictly validates one CLI-run request frame. The
// frame must be a single object without duplicate or unknown keys; the vault
// path and targets are bounded, and the scope is decoded by DecodeCLIRunScope.
//
// Any defect returns false and leaves nothing decoded behind: the local scope,
// the local targets, and every raw copy of the frame are cleared on every
// path. The decoded scope and targets are returned only to the caller that
// owns them; serveCLIRun clears them once the callback and the response are
// done.
func decodeCLIRunBrokerRequest(raw []byte) (CLIRunBrokerRequest, bool) {
	keys, values, parsed := strictJSONObject(raw)
	defer clearCLIRunRawMessages(values) // every raw byte, scope included
	if !parsed {
		return CLIRunBrokerRequest{}, false
	}
	keysAllowed := map[string]struct{}{"v": {}, "vault_path": {}, "scope": {}, "targets": {}, "delivery_control": {}}
	for key, value := range values {
		if _, allowed := keysAllowed[key]; !allowed {
			return CLIRunBrokerRequest{}, false
		}
		if key != "scope" && len(value) > maxCLIRunFieldBytes {
			return CLIRunBrokerRequest{}, false
		}
	}
	if _, present := keys["scope"]; !present {
		return CLIRunBrokerRequest{}, false
	}
	// The locals below are what the cleanup closure sees; returning a zero
	// request does not reset them before it runs.
	var (
		vaultPath string
		targets   []personal.CLIBrokerTarget
		scope     CLIRunScope
		valid     bool
	)
	defer func() {
		if !valid {
			scope.Clear()
			clearCLIRunTargets(targets)
		}
	}()
	var v int
	if json.Unmarshal(values["v"], &v) != nil || v != 1 {
		return CLIRunBrokerRequest{}, false
	}
	var deliveryControl bool
	if raw, present := values["delivery_control"]; present && json.Unmarshal(raw, &deliveryControl) != nil {
		return CLIRunBrokerRequest{}, false
	}
	if json.Unmarshal(values["vault_path"], &vaultPath) != nil {
		return CLIRunBrokerRequest{}, false
	}
	// The scope and the target list are decoded only after the small fields,
	// and the full shared request check, including profile and target
	// validation, runs before anything is returned or approved.
	decoded, e := DecodeCLIRunScope(values["scope"])
	if e != nil {
		return CLIRunBrokerRequest{}, false
	}
	scope = decoded
	if json.Unmarshal(values["targets"], &targets) != nil || !validCLIRunRequest(v, vaultPath, scope, targets) {
		return CLIRunBrokerRequest{}, false
	}
	valid = true
	return CLIRunBrokerRequest{V: 1, VaultPath: vaultPath, Scope: scope, Targets: targets, DeliveryControl: deliveryControl}, true
}

// CanonicalCLIRunTargets converts the wire targets to the exact RunBundle
// target values, in wire order. The copies are fresh, so the caller owns them.
func CanonicalCLIRunTargets(targets []personal.CLIBrokerTarget) []personal.BundleTarget {
	out := make([]personal.BundleTarget, len(targets))
	for i, target := range targets {
		out[i] = personal.BundleTarget{Slot: target.Slot, ID: target.ID, Revision: target.Revision, Field: target.Field}
	}
	return out
}

// CanonicalCLIRunRequest reconstructs the exact RunBundleRequest for a
// validated CLI-run scope: the profile is resolved to its built-in cliprofile
// spec, every other component is taken verbatim from the scope (never from a
// request field the desktop did not review), and TempRoot must be exactly the
// scope's private run root. An invalid scope, an unknown profile, or a
// mismatched root is refused with the generic request error, so the caller can
// never prepare or render a request that differs from what was approved.
func CanonicalCLIRunRequest(scope CLIRunScope, tempRoot string) (personal.RunBundleRequest, error) {
	if ValidateCLIRunScope(scope) != nil || tempRoot == "" || tempRoot != scope.TempRoot {
		return personal.RunBundleRequest{}, errCLIRunInvalid
	}
	spec, e := bindProfile(scope.Profile)
	if e != nil {
		return personal.RunBundleRequest{}, errCLIRunInvalid
	}
	request := personal.RunBundleRequest{
		Program:        scope.Program,
		Args:           append([]string(nil), scope.Args...),
		Directory:      scope.CWD,
		TimeoutSeconds: scope.Timeout,
		HelperPath:     append([]string(nil), scope.Helper...),
		Passthrough:    make(map[string]string, len(scope.Passthru)),
		TokenEnvName:   scope.TokenEnv,
		Spec:           spec,
	}
	for name, value := range scope.Passthru {
		request.Passthrough[name] = value
	}
	return request, nil
}

// validCLIRunRequest is the shared request check used by both the CLI before
// transmission and the broker on receipt, so a caller cannot bypass it.
//
// It requires a valid scope and a bounded absolute vault path, resolves the
// named profile to the built-in cliprofile spec (an unknown profile is
// refused), and holds the whole request to exactly the RunBundle rules via
// personal.RunBundleRequest.Validate with that canonical spec: program,
// working directory, arguments against the profile's denied sequences, helper
// directories, the profile's own timeout bound, the dynamic token variable,
// the passthrough environment names, and every target slot, field, item ID,
// and revision. All of it is checked before native approval is ever requested;
// the profile spec itself never crosses the wire.
func validCLIRunRequest(v int, vaultPath string, scope CLIRunScope, targets []personal.CLIBrokerTarget) bool {
	if v != 1 || ValidateCLIRunScope(scope) != nil || !scopeAbsPath(vaultPath) {
		return false
	}
	// The canonical builder is the same one the desktop later prepares and
	// renders, so a request that passes here is exactly a RunBundle request.
	// Its copy is scratch: its mutable containers are emptied on every return,
	// and the caller's scope and targets are never modified.
	request, e := CanonicalCLIRunRequest(scope, scope.TempRoot)
	defer clearCLIRunValidationRequest(&request)
	if e != nil {
		return false
	}
	bundleTargets := CanonicalCLIRunTargets(targets)
	defer clearCLIRunBundleTargets(bundleTargets)
	return len(targets) > 0 && request.Validate(bundleTargets) == nil
}

// clearCLIRunValidationRequest empties every mutable container of the
// canonical request copy validCLIRunRequest validates: its arguments, helper
// paths, passthrough map, and the profile spec's slots, environment map,
// files, directories, passthrough names, and nested deny-argument slices are
// blanked in place before their references are dropped, and the request is
// then zeroed.
//
// Go strings are immutable, so their bytes cannot be securely wiped; only the
// containers holding them are cleared. The values involved are the bounded,
// secret-free execution scope (no credential is ever copied here) and the
// built-in profile spec, so no secret is promised to be wiped by this helper.
func clearCLIRunValidationRequest(request *personal.RunBundleRequest) {
	if request == nil {
		return
	}
	for i := range request.Args {
		request.Args[i] = ""
	}
	request.Args = nil
	for i := range request.HelperPath {
		request.HelperPath[i] = ""
	}
	request.HelperPath = nil
	for name := range request.Passthrough {
		request.Passthrough[name] = ""
		delete(request.Passthrough, name)
	}
	request.Passthrough = nil
	clearCLIRunSpec(&request.Spec)
	*request = personal.RunBundleRequest{}
}

// clearCLIRunSpec empties every mutable container of a cliprofile.Spec,
// including the nested deny-argument slices, the environment map, and the
// file, directory, and passthrough name lists. String bytes stay immutable.
func clearCLIRunSpec(spec *cliprofile.Spec) {
	if spec == nil {
		return
	}
	for i := range spec.Slots {
		spec.Slots[i] = cliprofile.Slot{}
	}
	spec.Slots = nil
	for name := range spec.Env {
		spec.Env[name] = ""
		delete(spec.Env, name)
	}
	spec.Env = nil
	for i := range spec.Files {
		spec.Files[i] = cliprofile.FileSpec{}
	}
	spec.Files = nil
	for i := range spec.Dirs {
		spec.Dirs[i] = ""
	}
	spec.Dirs = nil
	for i := range spec.PassthroughEnv {
		spec.PassthroughEnv[i] = ""
	}
	spec.PassthroughEnv = nil
	for i := range spec.DenyArgs {
		for j := range spec.DenyArgs[i] {
			spec.DenyArgs[i][j] = ""
		}
		spec.DenyArgs[i] = nil
	}
	spec.DenyArgs = nil
	*spec = cliprofile.Spec{}
}

// writeCLIResponse writes exactly one classified reply. A response that pairs
// values with an error, or values without a canonical receipt, never reaches
// the wire: it is replaced by the explicit refusal. An oversized reply is also
// replaced by the refusal; a marshal failure writes nothing.
func writeCLIResponse(conn net.Conn, resp CLIRunBrokerResponse) error {
	raw, e := marshalCLIRunResponse(resp)
	if e != nil {
		return writeCLIRunRefusal(conn)
	}
	return writeCLIRunRaw(conn, raw)
}

// writeCLIRunRaw writes one already-encoded reply, replacing it with the fixed
// refusal when it is oversized, and zeroes the encoding afterwards.
func writeCLIRunRaw(conn net.Conn, raw []byte) error {
	defer clear(raw)
	if len(raw) == 0 || len(raw) > MaxOutput {
		return writeCLIRunRefusal(conn)
	}
	return writeFrame(conn, raw)
}

// writeCLIRunRefusal writes the fixed refusal reply.
func writeCLIRunRefusal(conn net.Conn) error {
	raw, e := marshalCLIRunResponse(CLIRunBrokerResponse{Error: cliRunErrorRefused})
	if e != nil {
		return e
	}
	defer clear(raw)
	return writeFrame(conn, raw)
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
	// The one-shot API never opts into delivery control, even if a caller set
	// the internal intent field. RequestCLIRunControl is the only opt-in path.
	req.DeliveryControl = false
	if ctx == nil {
		return CLIRunBrokerResponse{}, errCLIRunInvalid
	}
	if !validCLIRunRequest(req.V, req.VaultPath, req.Scope, req.Targets) {
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
	return classifyCLIRunResponse(ctx, respRaw, req.Targets)
}

// classifyCLIRunResponse accepts exactly one JSON object with unique keys and
// no trailing data. Only {"v":1,"error":"unavailable"} is fallback-eligible;
// only {"v":1,"error":"refused"} maps to ErrCLIRunRefused. A values reply is
// accepted only through decodeCLIRunResponse: no error member, a canonical
// receipt, and base64 values with exactly the requested target slots. A reply
// mixing success and error, an unknown token, or any malformed shape is a
// generic, non-fallback error.
func classifyCLIRunResponse(ctx context.Context, raw []byte, targets []personal.CLIBrokerTarget) (CLIRunBrokerResponse, error) {
	if ce := ctx.Err(); ce != nil {
		return CLIRunBrokerResponse{}, cliRunContextError(ce)
	}
	keys, values, ok := strictJSONObject(raw)
	if !ok {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	// The raw copies carry sensitive values and base64 strings; clear them on
	// every return. The caller-owned decoded byte slices are returned intact.
	defer clearCLIRunRawMessages(values)
	if _, hasError := keys["error"]; !hasError {
		return decodeCLIRunResponse(raw, targets)
	}
	if _, hasValues := keys[cliRunValuesField]; hasValues {
		return CLIRunBrokerResponse{}, errCLIRunResponse
	}
	if _, hasReceipt := keys[cliRunReceiptField]; hasReceipt {
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

// clearCLIRunRawMessages zeroes the bytes of every raw value in raws, releasing
// intermediate copies of sensitive values that were decoded only for
// validation.
func clearCLIRunRawMessages(raws map[string]json.RawMessage) {
	for _, raw := range raws {
		clear(raw)
	}
}

// clearCLIRunValues blanks and deletes every entry of the legacy
// map[string]string payload, so a callback that returned one leaves no secret
// string behind, whether or not it was transferred (it never is).
func clearCLIRunValues(values map[string]string) {
	for slot := range values {
		values[slot] = ""
		delete(values, slot)
	}
}

// clearCLIRunBundleTargets zeroes the temporary personal.BundleTarget copies
// built for one request check; the caller's CLIBrokerTarget values mirror them.
func clearCLIRunBundleTargets(targets []personal.BundleTarget) {
	for i := range targets {
		targets[i] = personal.BundleTarget{}
	}
}

// clearCLIRunTargets zeroes decoded target fields (slot names, IDs, revisions)
// on rejection paths. IDs and revisions are not secrets, but the request is
// discarded wholesale so a rejected frame leaves nothing inspectable behind.
func clearCLIRunTargets(targets []personal.CLIBrokerTarget) {
	for i := range targets {
		targets[i] = personal.CLIBrokerTarget{}
	}
}

// strictJSONObject validates that raw is exactly one JSON object (no trailing
// values), reports its top-level keys (rejecting duplicates and non-string
// keys), and returns each top-level value's raw bytes.
func strictJSONObject(raw []byte) (map[string]struct{}, map[string]json.RawMessage, bool) {
	// The locals below are what the deferred cleanup sees; the printed
	// rejection returns do not reset them before the defer runs.
	var (
		keys   map[string]struct{}
		values map[string]json.RawMessage
		valid  bool
	)
	// On rejection the caller never sees the raw copies, so clear the fields
	// collected before the failing token.
	defer func() {
		if !valid {
			clearCLIRunRawMessages(values)
		}
	}()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, e := dec.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, nil, false
	}
	keys = map[string]struct{}{}
	values = map[string]json.RawMessage{}
	for dec.More() {
		tok, e := dec.Token()
		if e != nil {
			return nil, nil, false
		}
		key, isString := tok.(string)
		if !isString {
			return nil, nil, false
		}
		if _, dup := keys[key]; dup {
			return nil, nil, false
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			// Clear the scratch copy that was never inserted into the map.
			clear(value)
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
	valid = true
	return keys, values, true
}
