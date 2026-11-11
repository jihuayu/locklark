package remoteunlocktls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testServerName     = "remote-unlock.test"
	testHandshakeLimit = 3 * time.Second
)

var testBindingContext = []byte("remote-unlock/smoke/v1/request=42;generation=7;epoch=1")

// TestMTLSSmoke is the positive end-to-end smoke: an in-memory PKI, a
// loopback TCP pair, a concurrent client/server handshake, and a channel
// binding exported and verified on both sides. It then closes the client
// Channel and asserts that Check, ExportBinding and VerifyBinding reject it
// and that a second Close reports net.ErrClosed.
func TestMTLSSmoke(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	clientRaw, serverRaw := loopbackPair(t)
	t.Cleanup(func() {
		// Close the raw endpoints directly so cleanup never waits on a TLS
		// close_notify exchange.
		clientRaw.Close()
		serverRaw.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), testHandshakeLimit)
	defer cancel()

	type result struct {
		ch  *Channel
		err error
	}
	clientRes := make(chan result, 1)
	serverRes := make(chan result, 1)
	go func() {
		ch, err := ClientHandshake(ctx, clientRaw, ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   serverPin,
		})
		clientRes <- result{ch, err}
	}()
	go func() {
		ch, err := ServerHandshake(ctx, serverRaw, ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   clientPin,
		})
		serverRes <- result{ch, err}
	}()
	gotClient := <-clientRes
	gotServer := <-serverRes

	if gotClient.err != nil {
		t.Fatalf("ClientHandshake: %v", gotClient.err)
	}
	if gotServer.err != nil {
		t.Fatalf("ServerHandshake: %v", gotServer.err)
	}
	if gotClient.ch == nil || gotServer.ch == nil {
		t.Fatalf("nil channel: client=%v server=%v", gotClient.ch == nil, gotServer.ch == nil)
	}
	for name, ch := range map[string]*Channel{"client": gotClient.ch, "server": gotServer.ch} {
		if err := ch.Check(); err != nil {
			t.Fatalf("%s Check: %v", name, err)
		}
		st := ch.conn.ConnectionState()
		if st.Version != tls.VersionTLS13 {
			t.Errorf("%s negotiated TLS version %#x, want TLS 1.3", name, st.Version)
		}
		if st.DidResume {
			t.Errorf("%s session was resumed", name)
		}
	}

	bindingCtx := []byte("remote-unlock/smoke/v1/request=42;generation=7;epoch=1")
	clientBinding, err := gotClient.ch.ExportBinding(bindingCtx)
	if err != nil {
		t.Fatalf("client ExportBinding: %v", err)
	}
	serverBinding, err := gotServer.ch.ExportBinding(bindingCtx)
	if err != nil {
		t.Fatalf("server ExportBinding: %v", err)
	}
	if len(clientBinding) != ChannelBindingSize {
		t.Fatalf("client binding length = %d, want %d", len(clientBinding), ChannelBindingSize)
	}
	if !bytes.Equal(clientBinding, serverBinding) {
		t.Fatal("client and server bindings for the same context differ")
	}
	if err := gotServer.ch.VerifyBinding(bindingCtx, clientBinding); err != nil {
		t.Fatalf("server VerifyBinding of client binding: %v", err)
	}
	if err := gotClient.ch.VerifyBinding(bindingCtx, serverBinding); err != nil {
		t.Fatalf("client VerifyBinding of server binding: %v", err)
	}

	// Closing a Channel must invalidate it for binding purposes: the closed
	// TLS connection would still export keying material, so the Channel has
	// to refuse it explicitly.
	if err := gotClient.ch.Close(); err != nil {
		t.Fatalf("client Close: %v", err)
	}
	if err := gotClient.ch.Check(); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("client Check after Close = %v, want ErrChannelClosed", err)
	}
	if b, err := gotClient.ch.ExportBinding(bindingCtx); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("client ExportBinding after Close = (%d bytes, %v), want ErrChannelClosed", len(b), err)
	}
	if err := gotClient.ch.VerifyBinding(bindingCtx, serverBinding); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("client VerifyBinding after Close = %v, want ErrChannelClosed", err)
	}
	if err := gotClient.ch.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second client Close = %v, want net.ErrClosed", err)
	}

	// The server Channel was never closed, so it remains usable.
	if err := gotServer.ch.Check(); err != nil {
		t.Fatalf("server Check after client Close: %v", err)
	}
}

// testCA is a synthetic certificate authority generated in memory. Neither
// certificate nor key bytes are written to disk or logged.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "remote-unlock test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue creates a leaf certificate signed by ca and returns its pin.
func (ca *testCA) issue(t *testing.T, serial int64, cn string, usage []x509.ExtKeyUsage, dnsNames []string) (tls.Certificate, PeerSPKIPin) {
	t.Helper()
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create %s certificate: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s certificate: %v", cn, err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}, PeerSPKIPinOf(cert)
}

// reissue signs a new certificate for the public key of source with ca, so the
// returned certificate keeps source's SPKI pin but chains to a different CA.
func (ca *testCA) reissue(t *testing.T, serial int64, cn string, source tls.Certificate, usage []x509.ExtKeyUsage) (tls.Certificate, PeerSPKIPin) {
	t.Helper()
	key, ok := source.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("test certificate key is %T, want *ecdsa.PrivateKey", source.PrivateKey)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("reissue %s certificate: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse reissued %s certificate: %v", cn, err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}, PeerSPKIPinOf(cert)
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}

// loopbackPair returns the two ends of a connected 127.0.0.1 TCP pair.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial loopback: %v", err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		client.Close()
		t.Fatalf("accept loopback: %v", err)
	case <-time.After(testHandshakeLimit):
		client.Close()
		t.Fatal("timed out accepting loopback connection")
	}
	return client, server
}

// handshakeResult is one side's handshake outcome.
type handshakeResult struct {
	ch  *Channel
	raw net.Conn
	err error
}

// runHandshakes runs the client and server handshake concurrently over a fresh
// loopback pair and waits for both outcomes. Each goroutine reports to its own
// buffered channel, so neither side can block the other. The raw endpoints are
// closed directly on cleanup: a failed handshake may leave the peer waiting
// for records, and a TLS close_notify exchange could hang.
func runHandshakes(t *testing.T, clientOpts ClientOptions, serverOpts ServerOptions) (handshakeResult, handshakeResult) {
	t.Helper()
	clientRaw, serverRaw := loopbackPair(t)
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), testHandshakeLimit)
	t.Cleanup(cancel)

	clientRes := make(chan handshakeResult, 1)
	serverRes := make(chan handshakeResult, 1)
	go func() {
		ch, err := ClientHandshake(ctx, clientRaw, clientOpts)
		clientRes <- handshakeResult{ch: ch, raw: clientRaw, err: err}
	}()
	go func() {
		ch, err := ServerHandshake(ctx, serverRaw, serverOpts)
		serverRes <- handshakeResult{ch: ch, raw: serverRaw, err: err}
	}()

	var clientGot, serverGot handshakeResult
	for i := 0; i < 2; i++ {
		select {
		case clientGot = <-clientRes:
		case serverGot = <-serverRes:
		case <-time.After(testHandshakeLimit):
			t.Fatal("timed out waiting for handshakes")
		}
	}
	return clientGot, serverGot
}

// mustChannel fails the test when a handshake did not produce a channel. A
// successful channel's raw endpoint is closed on cleanup, bypassing the TLS
// close_notify exchange deliberately.
func mustChannel(t *testing.T, name string, got handshakeResult) *Channel {
	t.Helper()
	if got.err != nil {
		t.Fatalf("%s: %v", name, got.err)
	}
	if got.ch == nil {
		t.Fatalf("%s: nil channel", name)
	}
	t.Cleanup(func() { got.raw.Close() })
	return got.ch
}

// wrongPin returns a pin that differs from pin in its last byte. If that
// happened to yield the all-zero pin (rejected as missing before the mismatch
// check can run), it flips the first byte as well.
func wrongPin(pin PeerSPKIPin) PeerSPKIPin {
	wrong := pin
	wrong[len(wrong)-1] ^= 0xff
	if isZeroPin(wrong) {
		wrong[0] ^= 0xff
	}
	return wrong
}

// TestWrongServerPinRejected asserts the client refuses a server whose SPKI
// does not match its out-of-band pin, even though the chain is valid.
func TestWrongServerPinRejected(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	client, server := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   wrongPin(serverPin),
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   clientPin,
		},
	)
	if !errors.Is(client.err, ErrPeerPinMismatch) {
		t.Fatalf("ClientHandshake = %v, want ErrPeerPinMismatch", client.err)
	}
	if client.ch != nil {
		t.Fatal("ClientHandshake returned a channel on pin mismatch")
	}
	if server.err == nil || server.ch != nil {
		t.Fatalf("ServerHandshake = (%v, %v), want rejection with no channel", server.ch, server.err)
	}
}

// TestWrongClientPinRejected asserts the server refuses a client whose SPKI
// does not match its out-of-band pin, though the client chain verifies.
func TestWrongClientPinRejected(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	client, server := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   serverPin,
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   wrongPin(clientPin),
		},
	)
	if !errors.Is(server.err, ErrPeerPinMismatch) {
		t.Fatalf("ServerHandshake = %v, want ErrPeerPinMismatch", server.err)
	}
	if server.ch != nil {
		t.Fatal("ServerHandshake returned a channel on pin mismatch")
	}
	if client.ch != nil {
		// TLS 1.3 lets the client finish before the server verifies the
		// client certificate, so its side may still report success; the
		// server rejection above is authoritative. Close its raw endpoint
		// directly so cleanup never waits on close_notify.
		client.raw.Close()
	}
}

// TestWrongServerNameRejected asserts hostname verification rejects a
// certificate issued for a different name, before pinning decides anything.
func TestWrongServerNameRejected(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"other-host.test"})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	client, server := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   serverPin,
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   clientPin,
		},
	)
	if client.err == nil {
		t.Fatal("ClientHandshake accepted a certificate for the wrong hostname")
	}
	if errors.Is(client.err, ErrPeerPinMismatch) {
		t.Fatalf("ClientHandshake failed on the pin, not hostname verification: %v", client.err)
	}
	var hostnameErr x509.HostnameError
	if !errors.As(client.err, &hostnameErr) {
		t.Fatalf("ClientHandshake = %v, want x509.HostnameError", client.err)
	}
	if client.ch != nil {
		t.Fatal("ClientHandshake returned a channel for the wrong hostname")
	}
	if server.err == nil || server.ch != nil {
		t.Fatalf("ServerHandshake = (%v, %v), want rejection with no channel", server.ch, server.err)
	}
}

// TestUntrustedClientCARejected asserts server chain verification wins over a
// matching client SPKI pin: a pin alone must never admit an unknown CA. The
// rogue client certificate reuses the trusted leaf's key so its SPKI pin is
// identical; only chain verification can reject it.
func TestUntrustedClientCARejected(t *testing.T) {
	ca := newTestCA(t)
	otherCA := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	rogueCert, roguePin := otherCA.reissue(t, 4, "client", clientCert, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if roguePin != clientPin {
		t.Fatal("test setup: rogue certificate must reuse the trusted SPKI pin")
	}

	client, server := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: rogueCert,
			ServerPin:   serverPin,
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   clientPin,
		},
	)
	if server.err == nil {
		t.Fatal("ServerHandshake accepted a client certificate from an untrusted CA")
	}
	var unknownCA x509.UnknownAuthorityError
	if !errors.As(server.err, &unknownCA) {
		t.Fatalf("ServerHandshake = %v, want x509.UnknownAuthorityError", server.err)
	}
	if server.ch != nil {
		t.Fatal("ServerHandshake returned a channel for an untrusted CA")
	}
	if client.ch != nil {
		// The client can complete TLS 1.3 before the server rejects its
		// certificate; the server-side chain failure above is the assertion.
		client.raw.Close()
	}
}

// TestFreshHandshakeRotatesBinding rebuilds both options into fresh configs and
// performs a second full handshake with the same certificate identities. The
// new channels derive a different exporter for the same context, reject the old
// binding, and neither side resumes. A closed old channel rejects its own
// binding too.
func TestFreshHandshakeRotatesBinding(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	clientOpts := ClientOptions{
		ServerName:  testServerName,
		Roots:       ca.pool,
		Certificate: clientCert,
		ServerPin:   serverPin,
	}
	serverOpts := ServerOptions{
		Roots:       ca.pool,
		Certificate: serverCert,
		ClientPin:   clientPin,
	}

	oldClientGot, oldServerGot := runHandshakes(t, clientOpts, serverOpts)
	oldClient := mustChannel(t, "old ClientHandshake", oldClientGot)
	oldServer := mustChannel(t, "old ServerHandshake", oldServerGot)
	oldClientBinding, err := oldClient.ExportBinding(testBindingContext)
	if err != nil {
		t.Fatalf("old client ExportBinding: %v", err)
	}
	if oldServerBinding, err := oldServer.ExportBinding(testBindingContext); err != nil {
		t.Fatalf("old server ExportBinding: %v", err)
	} else if !bytes.Equal(oldClientBinding, oldServerBinding) {
		t.Fatal("old channel bindings disagree")
	}

	// Both configs are rebuilt from scratch by the second handshake call;
	// there is no shared tls.Config, session cache or ticket state between
	// the old and new connections.
	newClientGot, newServerGot := runHandshakes(t, clientOpts, serverOpts)
	newClient := mustChannel(t, "new ClientHandshake", newClientGot)
	newServer := mustChannel(t, "new ServerHandshake", newServerGot)

	for name, ch := range map[string]*Channel{"new client": newClient, "new server": newServer} {
		st := ch.conn.ConnectionState()
		if st.DidResume {
			t.Errorf("%s resumed a session", name)
		}
		if st.Version != tls.VersionTLS13 {
			t.Errorf("%s negotiated version %#x, want TLS 1.3", name, st.Version)
		}
	}

	newClientBinding, err := newClient.ExportBinding(testBindingContext)
	if err != nil {
		t.Fatalf("new client ExportBinding: %v", err)
	}
	newServerBinding, err := newServer.ExportBinding(testBindingContext)
	if err != nil {
		t.Fatalf("new server ExportBinding: %v", err)
	}
	if !bytes.Equal(newClientBinding, newServerBinding) {
		t.Fatal("new client and server bindings for the same context differ")
	}
	if bytes.Equal(newClientBinding, oldClientBinding) {
		t.Fatal("fresh handshake reused the old channel exporter for the same context")
	}
	for name, ch := range map[string]*Channel{"new client": newClient, "new server": newServer} {
		if err := ch.VerifyBinding(testBindingContext, oldClientBinding); !errors.Is(err, ErrBindingMismatch) {
			t.Errorf("%s VerifyBinding(old binding) = %v, want ErrBindingMismatch", name, err)
		}
		if err := ch.VerifyBinding(testBindingContext, newClientBinding); err != nil {
			t.Errorf("%s VerifyBinding(new binding) = %v, want nil", name, err)
		}
	}

	// The old channel keeps exporting only until it is closed, and then fails
	// closed for Check and its own binding too.
	if err := oldClient.Check(); err != nil {
		t.Fatalf("old client Check before Close: %v", err)
	}
	if err := oldClient.Close(); err != nil {
		t.Fatalf("old client Close: %v", err)
	}
	if b, err := oldClient.ExportBinding(testBindingContext); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("old client ExportBinding after Close = (%d bytes, %v), want ErrChannelClosed", len(b), err)
	}
	if err := oldClient.VerifyBinding(testBindingContext, oldClientBinding); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("old client VerifyBinding after Close = %v, want ErrChannelClosed", err)
	}
	if err := oldClient.Check(); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("old client Check after Close = %v, want ErrChannelClosed", err)
	}
	if err := oldServer.Close(); err != nil {
		t.Fatalf("old server Close: %v", err)
	}
	if b, err := oldServer.ExportBinding(testBindingContext); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("old server ExportBinding after Close = (%d bytes, %v), want ErrChannelClosed", len(b), err)
	}
	if err := oldServer.Check(); !errors.Is(err, ErrChannelClosed) {
		t.Fatalf("old server Check after Close = %v, want ErrChannelClosed", err)
	}
}

// TestFailClosedAPIs covers the zero-value and missing-input edges of the
// Channel and the private config builders.
func TestFailClosedAPIs(t *testing.T) {
	var zero Channel
	if err := zero.Check(); !errors.Is(err, ErrUninitializedChannel) {
		t.Fatalf("zero Channel Check = %v, want ErrUninitializedChannel", err)
	}
	if b, err := zero.ExportBinding(testBindingContext); !errors.Is(err, ErrUninitializedChannel) {
		t.Fatalf("zero Channel ExportBinding = (%d bytes, %v), want ErrUninitializedChannel", len(b), err)
	}
	if err := zero.VerifyBinding(testBindingContext, make([]byte, ChannelBindingSize)); !errors.Is(err, ErrUninitializedChannel) {
		t.Fatalf("zero Channel VerifyBinding = %v, want ErrUninitializedChannel", err)
	}
	if err := zero.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("zero Channel Close = %v, want net.ErrClosed", err)
	}

	// An empty exporter context is refused even on a live channel.
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	clientGot, serverGot := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   serverPin,
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   clientPin,
		},
	)
	ch := mustChannel(t, "ClientHandshake", clientGot)
	mustChannel(t, "ServerHandshake", serverGot)
	if b, err := ch.ExportBinding(nil); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("ExportBinding(nil) = (%d bytes, %v), want ErrEmptyContext", len(b), err)
	}
	if b, err := ch.ExportBinding([]byte{}); !errors.Is(err, ErrEmptyContext) {
		t.Fatalf("ExportBinding(empty) = (%d bytes, %v), want ErrEmptyContext", len(b), err)
	}

	// Private config builders reject missing pins (and other missing inputs).
	if cfg, err := clientConfig(ClientOptions{ServerName: testServerName, Roots: ca.pool, Certificate: clientCert}); err == nil || cfg != nil {
		t.Fatalf("clientConfig without pin = (%v, %v), want error", cfg, err)
	}
	if cfg, err := serverConfig(ServerOptions{Roots: ca.pool, Certificate: serverCert}); err == nil || cfg != nil {
		t.Fatalf("serverConfig without pin = (%v, %v), want error", cfg, err)
	}

	clientCfg, err := clientConfig(ClientOptions{ServerName: testServerName, Roots: ca.pool, Certificate: clientCert, ServerPin: serverPin})
	if err != nil {
		t.Fatalf("clientConfig: %v", err)
	}
	if clientCfg.MinVersion != tls.VersionTLS13 || clientCfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("client TLS bounds = (%#x, %#x), want TLS 1.3 only", clientCfg.MinVersion, clientCfg.MaxVersion)
	}
	if clientCfg.ServerName != testServerName {
		t.Errorf("client ServerName = %q, want %q", clientCfg.ServerName, testServerName)
	}
	if clientCfg.RootCAs != ca.pool {
		t.Error("client RootCAs is not the explicit test pool")
	}
	if !clientCfg.SessionTicketsDisabled {
		t.Error("client session tickets are not disabled")
	}
	if clientCfg.ClientSessionCache != nil {
		t.Error("client session cache is not nil")
	}
	if clientCfg.InsecureSkipVerify {
		t.Error("client standard verification is disabled")
	}
	if clientCfg.VerifyConnection == nil {
		t.Error("client pin verifier is not installed")
	}

	serverCfg, err := serverConfig(ServerOptions{Roots: ca.pool, Certificate: serverCert, ClientPin: clientPin})
	if err != nil {
		t.Fatalf("serverConfig: %v", err)
	}
	if serverCfg.MinVersion != tls.VersionTLS13 || serverCfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("server TLS bounds = (%#x, %#x), want TLS 1.3 only", serverCfg.MinVersion, serverCfg.MaxVersion)
	}
	if !serverCfg.SessionTicketsDisabled {
		t.Error("server session tickets are not disabled")
	}
	if serverCfg.InsecureSkipVerify {
		t.Error("server standard verification is disabled")
	}
	if serverCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("server ClientAuth = %v, want tls.RequireAndVerifyClientCert", serverCfg.ClientAuth)
	}
	if serverCfg.ClientCAs != ca.pool {
		t.Error("server ClientCAs is not the explicit test pool")
	}
	if serverCfg.VerifyConnection == nil {
		t.Error("server pin verifier is not installed")
	}
}

// testBindingFixture is the single test-only exporter context of
// TestBindingRejectsContextMutation. Every field is independently variable so
// that the test can mutate exactly one of them at a time.
//
// The serialization in testBindingFixture.Context is TEST DATA ONLY. It is a
// deliberately trivial "key=value;" line chosen to be easy to mutate; it is
// NOT the remote-unlock wire format, NOT a canonical/authorization encoding,
// and nothing may depend on it. This test proves only the TLS
// exporter context-binding property: on one established connection, a
// binding derived for one context does not verify for any context that
// differs in a single field. The synthetic test certificates below are
// anonymous test keys only; they are not registered device identities, not
// policy proofs, and this is not a production relay handshake.
type testBindingFixture struct {
	requestSummaryDigest string
	lockGeneration       uint64
	pairGeneration       uint64
	vaultID              string
	epoch                uint64
	policySequence       uint64
	deadline             time.Time
}

// Context serializes the fixture. It is a fixture format, not a wire format;
// see the doc comment on testBindingFixture.
func (f testBindingFixture) Context() []byte {
	return []byte(strings.Join([]string{
		"request-summary-sha256=" + f.requestSummaryDigest,
		"lock-generation=" + strconv.FormatUint(f.lockGeneration, 10),
		"pair-generation=" + strconv.FormatUint(f.pairGeneration, 10),
		"vault-id=" + f.vaultID,
		"epoch=" + strconv.FormatUint(f.epoch, 10),
		"policy-sequence=" + strconv.FormatUint(f.policySequence, 10),
		"deadline-rfc3339nano=" + f.deadline.UTC().Format(time.RFC3339Nano),
	}, ";"))
}

// TestBindingRejectsContextMutation runs one real loopback TCP TLS 1.3
// mutual-authenticated handshake with the synthetic in-memory test CA, derives
// the channel binding for testBindingFixture's context, and then, for every
// single-field mutation, asserts that VerifyBinding on BOTH peers rejects the
// original binding with ErrBindingMismatch, while the unchanged context still
// validates on the opposite peer.
func TestBindingRejectsContextMutation(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	clientGot, serverGot := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   serverPin,
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   clientPin,
		},
	)
	client := mustChannel(t, "ClientHandshake", clientGot)
	server := mustChannel(t, "ServerHandshake", serverGot)

	// Fixture contexts are test data only; see testBindingFixture.
	base := testBindingFixture{
		requestSummaryDigest: "6f1c2a9b4d8e0f3a5c7b9d1e2f406182a3b4c5d6e7f8091a2b3c4d5e6f708192",
		lockGeneration:       11,
		pairGeneration:       3,
		vaultID:              "vault-vector-test",
		epoch:                5,
		policySequence:       8,
		deadline:             time.Date(2026, 11, 11, 12, 0, 0, 123456789, time.UTC),
	}
	baseCtx := base.Context()

	clientBinding, err := client.ExportBinding(baseCtx)
	if err != nil {
		t.Fatalf("client ExportBinding: %v", err)
	}
	serverBinding, err := server.ExportBinding(baseCtx)
	if err != nil {
		t.Fatalf("server ExportBinding: %v", err)
	}
	if !bytes.Equal(clientBinding, serverBinding) {
		t.Fatal("peers derived different bindings for the same context")
	}

	mutations := []struct {
		name   string
		mutate func(*testBindingFixture)
	}{
		{"request-summary-digest", func(f *testBindingFixture) { f.requestSummaryDigest = "00" + f.requestSummaryDigest[2:] }},
		{"lock-generation", func(f *testBindingFixture) { f.lockGeneration++ }},
		{"pair-generation", func(f *testBindingFixture) { f.pairGeneration++ }},
		{"vault-id", func(f *testBindingFixture) { f.vaultID += "-other" }},
		{"epoch", func(f *testBindingFixture) { f.epoch++ }},
		{"policy-sequence", func(f *testBindingFixture) { f.policySequence++ }},
		{"deadline", func(f *testBindingFixture) { f.deadline = f.deadline.Add(time.Nanosecond) }},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			mutatedCtx := mutated.Context()
			if bytes.Equal(mutatedCtx, baseCtx) {
				t.Fatalf("%s mutation did not change the fixture context", tc.name)
			}

			// Each peer verifies the binding exported by the other, so every
			// assertion crosses the actual TLS connection.
			for _, peer := range []struct {
				name string
				ch   *Channel
				got  []byte
			}{
				{name: "client", ch: client, got: serverBinding},
				{name: "server", ch: server, got: clientBinding},
			} {
				if err := peer.ch.VerifyBinding(mutatedCtx, peer.got); !errors.Is(err, ErrBindingMismatch) {
					t.Errorf("%s VerifyBinding(%s-mutated context, peer binding) = %v, want ErrBindingMismatch", peer.name, tc.name, err)
				}
				// The original binding still validates for the unchanged
				// context on this same channel: the rejection above is due to
				// the mutated context, not connection state.
				if err := peer.ch.VerifyBinding(baseCtx, peer.got); err != nil {
					t.Errorf("%s VerifyBinding(unchanged context, peer binding) = %v, want nil", peer.name, err)
				}
			}
		})
	}
}
