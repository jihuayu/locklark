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
	"testing"
	"time"
)

const (
	testServerName     = "remote-unlock.test"
	testHandshakeLimit = 3 * time.Second
)

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
