package remoteunlocktls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// PeerSPKIPin is the SHA-256 hash of a peer leaf certificate's DER-encoded
// SubjectPublicKeyInfo. It identifies the expected peer public key
// independently of the certificate chain. A zero pin is never accepted.
type PeerSPKIPin [sha256.Size]byte

const (
	// exporterLabel is the package-specific RFC 5705 / RFC 8446 exporter
	// label. Exported keying material from this package must never be reused
	// with a different label.
	exporterLabel = "EXPORTER-LockLark-Remote-Unlock-Channel-Binding-v1"

	// ChannelBindingSize is the fixed length, in bytes, of a channel binding.
	ChannelBindingSize = 32

	// HandshakeTimeout is the default bound applied to a handshake when the
	// caller context has no deadline of its own.
	HandshakeTimeout = 10 * time.Second
)

var (
	// ErrNotTLS13 is returned for a connection that did not negotiate TLS 1.3.
	ErrNotTLS13 = errors.New("remoteunlocktls: connection is not TLS 1.3")
	// ErrResumed is returned for a connection built on a resumed session.
	ErrResumed = errors.New("remoteunlocktls: connection used session resumption")
	// ErrMissingCertificates is returned for a connection without a verified
	// peer certificate.
	ErrMissingCertificates = errors.New("remoteunlocktls: connection has no verified peer certificate")
	// ErrPeerPinMismatch is reported when the verified peer leaf SPKI does
	// not match the expected pin.
	ErrPeerPinMismatch = errors.New("remoteunlocktls: peer SPKI pin mismatch")
	// ErrBindingMismatch is returned by Channel.VerifyBinding when the
	// channel binding does not equal the expected value.
	ErrBindingMismatch = errors.New("remoteunlocktls: channel binding mismatch")
	// ErrHandshakeIncomplete is returned when a channel binding is requested
	// before the TLS handshake has completed.
	ErrHandshakeIncomplete = errors.New("remoteunlocktls: TLS handshake has not completed")
	// ErrUninitializedChannel is returned when a zero or incomplete Channel
	// is used.
	ErrUninitializedChannel = errors.New("remoteunlocktls: channel is not initialized")
	// ErrEmptyContext is returned when no caller context is supplied. The
	// context carries the future canonical request/pair-generation/
	// vault-epoch-policy/deadline encoding and must never be omitted.
	ErrEmptyContext = errors.New("remoteunlocktls: channel binding context is required")
	// ErrChannelClosed is returned by Channel.Check, ExportBinding and
	// VerifyBinding once the Channel has been closed. A closed connection
	// keeps the exporter inputs of its completed handshake, so bindings must
	// not be derived or verified on it.
	ErrChannelClosed = errors.New("remoteunlocktls: channel is closed")
	// ErrDeviceTransportBindingSPKIMismatch is returned by
	// Channel.VerifyPeerDeviceTransportBinding when the SPKI digest inside
	// the device transport binding does not equal the SPKI pin of the
	// verified peer certificate on this channel. It is checked before the
	// binding signature or context, which are not inspected.
	ErrDeviceTransportBindingSPKIMismatch = errors.New("remoteunlocktls: device transport binding SPKI does not match the verified peer certificate")
)

// ClientOptions configures the initiator role.
type ClientOptions struct {
	// ServerName is the name verified in the server certificate (SNI and
	// hostname verification).
	ServerName string
	// Roots verifies the server chain. An explicit pool is required; the
	// system pool is never used implicitly.
	Roots *x509.CertPool
	// Certificate is the client identity presented for mutual auth.
	Certificate tls.Certificate
	// ServerPin pins the expected server leaf SPKI.
	ServerPin PeerSPKIPin
}

// ServerOptions configures the responder role.
type ServerOptions struct {
	// Roots verifies the client chain.
	Roots *x509.CertPool
	// Certificate is the server identity presented for mutual auth.
	Certificate tls.Certificate
	// ClientPin pins the expected client leaf SPKI.
	ClientPin PeerSPKIPin
}

// clientConfig builds the strict client configuration. It is private so that
// the only way to obtain a Channel is ClientHandshake.
func clientConfig(opts ClientOptions) (*tls.Config, error) {
	if opts.ServerName == "" {
		return nil, errors.New("remoteunlocktls: client server name is required")
	}
	if opts.Roots == nil {
		return nil, errors.New("remoteunlocktls: client root pool is required")
	}
	if len(opts.Certificate.Certificate) == 0 {
		return nil, errors.New("remoteunlocktls: client certificate is required")
	}
	if isZeroPin(opts.ServerPin) {
		return nil, errors.New("remoteunlocktls: server pin is required")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ServerName:   opts.ServerName,
		RootCAs:      opts.Roots,
		Certificates: []tls.Certificate{opts.Certificate},
		// No ClientSessionCache is configured, and tickets are disabled.
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
		VerifyConnection:       pinnedVerifier(opts.ServerPin),
	}, nil
}

// serverConfig builds the strict server configuration. It is private so
// that the only way to obtain a Channel is ServerHandshake.
func serverConfig(opts ServerOptions) (*tls.Config, error) {
	if opts.Roots == nil {
		return nil, errors.New("remoteunlocktls: server root pool is required")
	}
	if len(opts.Certificate.Certificate) == 0 {
		return nil, errors.New("remoteunlocktls: server certificate is required")
	}
	if isZeroPin(opts.ClientPin) {
		return nil, errors.New("remoteunlocktls: client pin is required")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{opts.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    opts.Roots,
		// Tickets/PSK resumption are disabled on this side too.
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
		VerifyConnection:       pinnedVerifier(opts.ClientPin),
	}, nil
}

// pinnedVerifier runs as VerifyConnection, i.e. after the standard chain and
// hostname verification (or after client-certificate verification on a
// server). It aborts the handshake when the verified peer leaf SPKI does not
// match the out-of-band pin, or when the connection is not a fresh TLS 1.3
// handshake.
//
// crypto/tls marks the handshake complete only after this callback returns,
// so ConnectionState.HandshakeComplete is not asserted here; Channel.Check
// enforces it on every export.
func pinnedVerifier(pin PeerSPKIPin) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if isZeroPin(pin) {
			return ErrUninitializedChannel
		}
		if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
			return ErrMissingCertificates
		}
		if cs.Version != tls.VersionTLS13 {
			return fmt.Errorf("%w: negotiated version %#x", ErrNotTLS13, cs.Version)
		}
		if cs.DidResume {
			return ErrResumed
		}
		if got := PeerSPKIPinOf(cs.VerifiedChains[0][0]); got != pin {
			return ErrPeerPinMismatch
		}
		return nil
	}
}

// PeerSPKIPinOf returns the SPKI pin for a certificate. A nil certificate
// yields the zero pin.
func PeerSPKIPinOf(cert *x509.Certificate) PeerSPKIPin {
	var pin PeerSPKIPin
	if cert == nil {
		return pin
	}
	return PeerSPKIPin(sha256.Sum256(cert.RawSubjectPublicKeyInfo))
}

func isZeroPin(p PeerSPKIPin) bool {
	return p == PeerSPKIPin{}
}
