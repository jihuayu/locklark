package remoteunlocktls

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// probeContext is a non-empty probe context used by ClientHandshake and
// ServerHandshake to prove, inside the handshake, that the key exporter
// works for this exact connection. It is never returned to callers.
const probeContext = "locklark/remote-unlock-tls/v1/handshake-probe"

// Channel is an established, pinned, mutually authenticated TLS 1.3
// connection to the expected peer.
//
// A Channel can only be obtained from ClientHandshake or ServerHandshake. It
// seals the underlying *tls.Conn and the expected peer pin from the options
// used for that handshake: there is no constructor, it does not embed or
// expose *tls.Conn or ConnectionState, and its zero value fails closed.
// Channel bindings can only be produced through its methods, each of which
// rechecks the completed TLS 1.3 handshake, the absence of resumption, the
// verified peer chain, and the expected peer SPKI pin.
//
// Data reads and writes are plain delegation to the underlying connection and
// carry no remote-unlock semantics.
//
// Once Close has been called the Channel is permanently closed: Check, and
// every binding method for valid inputs, fails with ErrChannelClosed even
// though closing TLS does not discard the exporter inputs of the completed
// handshake. Errors detected before the Channel check (a wrongly sized
// expected value, an invalid typed context or an uninitialized Channel) may
// take precedence over ErrChannelClosed. The exception is
// VerifyPeerDeviceTransportBinding, which always calls Check first, so on a
// closed Channel it returns ErrChannelClosed for every binding, context, device
// ID and key.
type Channel struct {
	conn   *tls.Conn
	pin    PeerSPKIPin
	closed atomic.Bool
}

// ClientHandshake performs the initiator side of the handshake over conn
// using ClientOptions and returns the established Channel. The handshake is
// bounded by ctx (a default HandshakeTimeout applies if ctx has no
// deadline). On any error, including a cancelled ctx, conn is closed and no
// Channel is returned.
func ClientHandshake(ctx context.Context, conn net.Conn, opts ClientOptions) (*Channel, error) {
	cfg, err := clientConfig(opts)
	if err != nil {
		closeConn(conn)
		return nil, err
	}
	return handshake(ctx, conn, tls.Client, cfg, opts.ServerPin)
}

// ServerHandshake performs the responder side of the handshake over conn
// using ServerOptions and returns the established Channel. The handshake is
// bounded by ctx (a default HandshakeTimeout applies if ctx has no
// deadline). On any error, including a cancelled ctx, conn is closed and no
// Channel is returned.
func ServerHandshake(ctx context.Context, conn net.Conn, opts ServerOptions) (*Channel, error) {
	cfg, err := serverConfig(opts)
	if err != nil {
		closeConn(conn)
		return nil, err
	}
	return handshake(ctx, conn, tls.Server, cfg, opts.ClientPin)
}

func closeConn(conn net.Conn) {
	if conn != nil {
		conn.Close()
	}
}

// handshake runs one side of the handshake and seals the resulting Channel
// with pin.
func handshake(ctx context.Context, conn net.Conn, newConn func(net.Conn, *tls.Config) *tls.Conn, cfg *tls.Config, pin PeerSPKIPin) (*Channel, error) {
	if conn == nil {
		return nil, errors.New("remoteunlocktls: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := handshakeContext(ctx)
	defer cancel()
	tc := newConn(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	ch := &Channel{conn: tc, pin: pin}
	if err := ch.Check(); err != nil {
		conn.Close()
		return nil, err
	}
	// The key exporter only works on this connection once the handshake has
	// fully completed, so a successful probe proves the wrapped connection
	// is complete, TLS 1.3 and usable for binding.
	if _, err := ch.ExportBinding([]byte(probeContext)); err != nil {
		conn.Close()
		return nil, err
	}
	return ch, nil
}

// handshakeContext applies the default handshake timeout when ctx carries no
// deadline of its own.
func handshakeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, HandshakeTimeout)
}

// Check re-verifies that the channel is an established, non-resumed,
// mutually authenticated TLS 1.3 connection whose verified peer certificate
// matches the expected pin. A zero or uninitialized Channel fails closed, and
// a closed Channel returns ErrChannelClosed.
func (c *Channel) Check() error {
	if c == nil || c.conn == nil || isZeroPin(c.pin) {
		return ErrUninitializedChannel
	}
	if c.closed.Load() {
		return ErrChannelClosed
	}
	cs := c.conn.ConnectionState()
	if !cs.HandshakeComplete {
		return ErrHandshakeIncomplete
	}
	if cs.Version != tls.VersionTLS13 {
		return fmt.Errorf("%w: negotiated version %#x", ErrNotTLS13, cs.Version)
	}
	if cs.DidResume {
		return ErrResumed
	}
	if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return ErrMissingCertificates
	}
	if got := PeerSPKIPinOf(cs.VerifiedChains[0][0]); got != c.pin {
		return ErrPeerPinMismatch
	}
	return nil
}

// ExportBinding derives the fixed-length channel binding for context on this
// channel. It refuses an uninitialized or closed channel, anything but a
// completed, non-resumed TLS 1.3 handshake with the pinned peer, and an empty
// context.
//
// context is opaque to this package: the caller's bytes are used verbatim as
// the exporter context and are not parsed, decoded or canonicalized here, so
// both peers must supply byte-identical context. ExportBinding returns a
// freshly derived binding of exactly ChannelBindingSize bytes; it does not
// echo or return context. Callers that hold a
// remoteunlock.ChannelBindingContext should use ExportBindingContext, which
// passes the canonical public codec output to this method. Because the
// context is mandatory, a binding for an empty context can never be produced
// silently.
//
// A binding is only meaningful for the connection it was derived from. A
// verifier must recompute it on the channel that carried the request (see
// VerifyBinding).
func (c *Channel) ExportBinding(context []byte) ([]byte, error) {
	if err := c.Check(); err != nil {
		return nil, err
	}
	if len(context) == 0 {
		return nil, ErrEmptyContext
	}
	cs := c.conn.ConnectionState()
	out, err := cs.ExportKeyingMaterial(exporterLabel, context, ChannelBindingSize)
	if err != nil {
		return nil, fmt.Errorf("remoteunlocktls: export keying material: %w", err)
	}
	return out, nil
}

// VerifyBinding checks that expected equals the channel binding derived for
// context on this channel. As with ExportBinding, context is opaque: the
// caller's bytes are used verbatim as the exporter context and are not
// parsed, decoded or canonicalized here.
//
// Error ordering: an expected value that is not exactly ChannelBindingSize
// bytes is rejected with a length error before the Channel is consulted. On
// a closed channel, a valid expected value reaches the Channel check and
// returns ErrChannelClosed; likewise an empty context on an open channel
// returns ErrEmptyContext. Otherwise it returns ErrBindingMismatch on
// mismatch, or the other channel refusals of ExportBinding (for example
// ErrUninitializedChannel).
func (c *Channel) VerifyBinding(context, expected []byte) error {
	if len(expected) != ChannelBindingSize {
		return fmt.Errorf("remoteunlocktls: expected binding must be %d bytes", ChannelBindingSize)
	}
	got, err := c.ExportBinding(context)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return ErrBindingMismatch
	}
	return nil
}

// Close marks the Channel closed and then closes the underlying connection.
// After a successful Close, Check, ExportBinding, VerifyBinding,
// ExportBindingContext and VerifyBindingContext fail with
// ErrChannelClosed even though the closed TLS connection would still allow
// keying material to be exported. Closing an already closed (or
// uninitialized) Channel returns net.ErrClosed.
func (c *Channel) Close() error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	return c.conn.Close()
}

// Delegation to the underlying connection. These are data-channel methods
// only; they carry no pin or binding checks.

// Read reads application data.
func (c *Channel) Read(p []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Read(p)
}

// Write writes application data.
func (c *Channel) Write(p []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Write(p)
}

// LocalAddr returns the local address.
func (c *Channel) LocalAddr() net.Addr {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote address.
func (c *Channel) RemoteAddr() net.Addr {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (c *Channel) SetDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *Channel) SetReadDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *Channel) SetWriteDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}
	return c.conn.SetWriteDeadline(t)
}

// compile-time proof that Channel is a net.Conn.
var _ net.Conn = (*Channel)(nil)
