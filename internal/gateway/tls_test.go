package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise a real TLS connection using a synthetic endpoint with the expected
// certificate name. Only the test owns its local route and trusted certificate.
func TestFixedOriginTLSAndHostname(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{apiHost}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Host != apiHost || r.TLS == nil || r.TLS.ServerName != apiHost || r.Header.Get("Authorization") != "Bearer SYNTHETIC_PRIVATE" || r.URL.Path != "/repos/example/tools/pulls/7" {
			t.Error("unexpected wire request")
		}
		io.WriteString(w, githubResponse)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}
	srv.StartTLS()
	defer srv.Close()
	newLocal := func(trust bool) *pullReader {
		h, err := NewPullReader(bound, netip.MustParseAddr("1.1.1.1"))
		if err != nil {
			t.Fatal(err)
		}
		tr := h.transport.(*http.Transport)
		tr.TLSClientConfig.RootCAs = x509.NewCertPool()
		if trust {
			tr.TLSClientConfig.RootCAs.AddCert(leaf)
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != apiHost+":443" {
				t.Fatal("dialed outside fixed origin")
			}
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
		return h
	}
	load := func() ([]byte, error) { return []byte("SYNTHETIC_PRIVATE"), nil }
	if _, err := newLocal(false).ReadApproved(context.Background(), Target{"123", 7}, []byte(plan), load); err == nil || n.Load() != 0 {
		t.Fatal("untrusted endpoint received HTTP")
	}
	result, err := newLocal(true).ReadApproved(context.Background(), Target{"123", 7}, []byte(plan), load)
	if err != nil || result.State != "closed" || n.Load() != 1 {
		t.Fatal(result, err, n.Load())
	}
}
