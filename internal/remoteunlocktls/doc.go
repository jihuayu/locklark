// Package remoteunlocktls is the sealed mutual-TLS transport foundation for
// remote unlock.
//
// It exposes exactly two entry points, one per mTLS role:
// ClientHandshake(ctx, conn, ClientOptions) and
// ServerHandshake(ctx, conn, ServerOptions). Each runs the Go standard
// crypto/tls handshake over conn and returns a *Channel, or an error; on any
// error (including a cancelled ctx) conn is closed and no Channel is
// returned. There is no exported tls.Config builder and no constructor for
// Channel: the TLS configuration stays sealed inside the handshake, and the
// zero Channel fails closed.
//
// Channel is an established, pinned, mutually authenticated TLS 1.3
// connection. It implements net.Conn (Read, Write, Close, LocalAddr,
// RemoteAddr, SetDeadline, SetReadDeadline, SetWriteDeadline), which are plain
// delegation to the underlying connection and carry no remote-unlock
// semantics. Its other methods are:
//
//   - Check re-verifies that the connection is a completed, non-resumed
//     TLS 1.3 handshake with a verified peer chain whose leaf SPKI matches the
//     expected pin; an uninitialized Channel returns
//     ErrUninitializedChannel.
//   - ExportBinding(context) derives the fixed-length (ChannelBindingSize)
//     channel binding for the connection. It runs Check and rejects an empty
//     context with ErrEmptyContext.
//   - VerifyBinding(context, expected) recomputes the binding on this
//     connection and compares it with expected in constant time, returning
//     ErrBindingMismatch on mismatch.
//
// Close marks the Channel closed before closing the underlying connection. A
// closed Channel cannot export or verify bindings: although a closed TLS
// connection retains the exporter inputs of its completed handshake, Check,
// ExportBinding and VerifyBinding fail with ErrChannelClosed. Closing again
// returns net.ErrClosed; data reads and writes carry no remote-unlock
// semantics and keep their plain connection behaviour.
//
// Guarantees:
//
//   - Go standard crypto/tls only; no custom key exchange or bespoke
//     cryptography.
//   - TLS 1.3 only (MinVersion == MaxVersion == tls.VersionTLS13); a
//     connection that did not negotiate 1.3 is refused with ErrNotTLS13.
//   - Normal certificate chain and hostname verification is always on
//     (InsecureSkipVerify is never set); the client verifies the server name
//     against an explicit root pool, and the server requires and verifies a
//     client certificate from its root pool.
//   - On top of the standard verification, each role pins the expected peer
//     leaf certificate by its SHA-256 SPKI (PeerSPKIPin, PeerSPKIPinOf). A
//     zero pin is rejected up front and a mismatch aborts the handshake with
//     ErrPeerPinMismatch.
//   - Session tickets and PSK resumption are disabled on both roles and no
//     client session cache is configured, so every connection is a full
//     handshake; a resumed connection is refused with ErrResumed.
//   - Channels support no 0-RTT / early-data path; the standard TLS stream
//     offers none and this package adds none.
//   - A handshake with no caller deadline is bounded by HandshakeTimeout; a
//     deadline already present on the caller context takes precedence.
//
// Scope. This package provides only the transport foundation. It does not
// define the canonical wire or context encoding, the relay, pairing policy,
// request state or one-shot consumption, vault-key (VUK) handling or any
// decryption, nor the rest of the full #127 integration, and it makes no claim
// that #127 is complete. The context passed to ExportBinding and
// VerifyBinding is opaque to this package; it is expected to carry the
// canonical encoding of the request summary, pair/lock generation,
// vault/epoch/policy and deadline, but that encoding is defined by the caller,
// not here. A binding is only meaningful for the connection it was derived
// from, so a verifier must recompute it on the channel that carried the
// request.
package remoteunlocktls
