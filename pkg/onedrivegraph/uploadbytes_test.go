package onedrivegraph

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// These tests use only synthetic sessions, IDs, tokens and payloads. The
// capability URL stays on the production *.up.1drv.com allowlist while a
// custom dialer routes every request to the loopback TLS fixture, so no live
// host is ever resolved.

const uploadBytesProviderSecret = "synthetic-upload-bytes-provider-response-secret"

type uploadBytesRequest struct {
	method        string
	host          string
	path          string
	query         string
	tls           bool
	authorization string
	contentRange  string
	contentLength string
	ifMatch       string
	body          []byte
}

type uploadBytesResponse struct {
	status   int
	body     []byte
	location string
}

type uploadBytesFixture struct {
	t       *testing.T
	server  *httptest.Server
	rootCAs *x509.CertPool

	mu       sync.Mutex
	response uploadBytesResponse
	hook     func(http.ResponseWriter, *http.Request) bool
	requests []uploadBytesRequest
	attempts int
}

func newUploadBytesFixture(t *testing.T) *uploadBytesFixture {
	t.Helper()
	f := &uploadBytesFixture{
		t: t,
		response: uploadBytesResponse{
			status: http.StatusAccepted,
			body:   uploadBytesAckJSON(time.Now().Add(time.Hour).UTC().Truncate(time.Second), []string{"0-"}),
		},
	}
	serverCertificate, rootCAs := newUploadBytesTLSMaterial(t)
	f.rootCAs = rootCAs
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		MinVersion:   tls.VersionTLS12,
	}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

// newUploadBytesTLSMaterial builds a private test root and a leaf certificate
// whose only DNS SAN is the allowlisted capability host. The returned pool
// contains only the test root, so the standard Go chain and hostname checks
// exercise the same path as production.
func newUploadBytesTLSMaterial(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "locklark synthetic upload test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create test root certificate: %v", err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse test root certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: uploadCapabilityHost},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{uploadCapabilityHost},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCertificate, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create test leaf certificate: %v", err)
	}
	leafCertificate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse test leaf certificate: %v", err)
	}
	if len(leafCertificate.DNSNames) != 1 || leafCertificate.DNSNames[0] != uploadCapabilityHost {
		t.Fatalf("test leaf DNS SANs = %q, want exactly %q", leafCertificate.DNSNames, uploadCapabilityHost)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCertificate)
	return tls.Certificate{
		Certificate: [][]byte{leafDER, rootDER},
		PrivateKey:  leafKey,
	}, rootCAs
}

func uploadBytesAckJSON(expiration time.Time, ranges []string) []byte {
	body, err := json.Marshal(map[string]any{
		"expirationDateTime": expiration.UTC().Format(time.RFC3339),
		"nextExpectedRanges": ranges,
	})
	if err != nil {
		panic(err)
	}
	return body
}

func (f *uploadBytesFixture) setResponse(status int, body []byte, location string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.response = uploadBytesResponse{status: status, body: body, location: location}
}

func (f *uploadBytesFixture) setHook(hook func(http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = hook
}

func (f *uploadBytesFixture) snapshot() ([]uploadBytesRequest, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uploadBytesRequest(nil), f.requests...), f.attempts
}

func (f *uploadBytesFixture) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, int64(vaultfilebackend.MaxValueSize)+1))
	record := uploadBytesRequest{
		method:        r.Method,
		host:          r.Host,
		path:          r.URL.Path,
		query:         r.URL.RawQuery,
		tls:           r.TLS != nil,
		authorization: r.Header.Get("Authorization"),
		contentRange:  r.Header.Get("Content-Range"),
		contentLength: r.Header.Get("Content-Length"),
		ifMatch:       r.Header.Get("If-Match"),
		body:          body,
	}
	f.mu.Lock()
	f.attempts++
	f.requests = append(f.requests, record)
	response := f.response
	hook := f.hook
	f.mu.Unlock()

	if hook != nil && hook(w, r) {
		return
	}
	if response.location != "" {
		w.Header().Set("Location", response.location)
	}
	w.Header().Set("Content-Type", "application/json")
	if response.body != nil {
		w.Header().Set("Content-Length", strconv.Itoa(len(response.body)))
	}
	w.WriteHeader(response.status)
	if response.body != nil {
		_, _ = w.Write(response.body)
	}
}

// client returns a TLS client that resolves the allowlisted capability host
// only to this fixture's loopback listener and verifies the fixture's private
// test chain using ordinary Go certificate and hostname checks.
func (f *uploadBytesFixture) client() *http.Client {
	f.t.Helper()
	return f.clientWithRootCAs(f.rootCAs)
}

// clientWithRootCAs is the client constructor used by the negative TLS test
// with an empty, untrusted pool.
func (f *uploadBytesFixture) clientWithRootCAs(rootCAs *x509.CertPool) *http.Client {
	f.t.Helper()
	base, ok := f.server.Client().Transport.(*http.Transport)
	if !ok {
		f.t.Fatalf("httptest client transport is not *http.Transport")
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}
	transport.Proxy = nil
	address := f.server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
	return &http.Client{Transport: transport}
}

func (f *uploadBytesFixture) uploader(t *testing.T, tokens AccessTokenSource, client *http.Client) *ConditionalUploader {
	t.Helper()
	if tokens == nil {
		tokens = &testTokenSource{token: uploadToken}
	}
	if client == nil {
		client = f.client()
	}
	u, err := newConditionalUploader(ConditionalUploaderConfig{
		DriveID: uploadDriveID,
		ItemID:  uploadItemID,
		Tokens:  tokens,
	}, nil, client)
	if err != nil {
		t.Fatalf("newConditionalUploader: %v", err)
	}
	return u
}

func uploadBytesSession(expiresAt time.Time) *UploadSession {
	return &UploadSession{
		driveID:   uploadDriveID,
		itemID:    uploadItemID,
		etag:      uploadETag,
		uploadURL: uploadCapabilityURL,
		expiresAt: expiresAt,
		state:     &uploadSessionState{},
	}
}

func assertUploadBytesNoRequest(t *testing.T, f *uploadBytesFixture) {
	t.Helper()
	requests, attempts := f.snapshot()
	if attempts != 0 || len(requests) != 0 {
		t.Errorf("upload attempts/requests = %d/%d, want 0/0", attempts, len(requests))
	}
}

func assertUploadBytesSecretsAbsent(t *testing.T, err error) {
	t.Helper()
	assertNoSecrets(t, err,
		uploadCapabilityURL,
		uploadCapabilityPath,
		uploadToken,
		uploadBytesProviderSecret,
	)
}

func TestConditionalUploaderUploadBytesContract(t *testing.T) {
	f := newUploadBytesFixture(t)
	tokens := &testTokenSource{token: uploadToken}
	session := uploadBytesSession(time.Now().Add(time.Hour).UTC().Truncate(time.Second))
	originalExpiry := session.expiresAt
	payload := []byte{0x00, 0x01, 0x7f, 0x80, 0xff, 'x'}
	originalPayload := append([]byte(nil), payload...)

	ackExpiry := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
	ranges := []string{"0-", "3-5"}
	f.setResponse(http.StatusAccepted, uploadBytesAckJSON(ackExpiry, ranges), "")

	u := f.uploader(t, tokens, nil)
	ack, err := u.UploadBytes(context.Background(), session, payload)
	if err != nil {
		t.Fatalf("UploadBytes: %v", err)
	}
	if !ack.ExpirationDateTime.Equal(ackExpiry) {
		t.Errorf("ack expiration = %v, want provider %v", ack.ExpirationDateTime, ackExpiry)
	}
	if !slicesEqualStrings(ack.NextExpectedRanges, ranges) {
		t.Errorf("nextExpectedRanges = %#v, want exact %#v", ack.NextExpectedRanges, ranges)
	}
	if !session.expiresAt.Equal(originalExpiry) {
		t.Errorf("session expiration = %v, want immutable %v", session.expiresAt, originalExpiry)
	}
	if !bytes.Equal(payload, originalPayload) {
		t.Errorf("UploadBytes mutated the caller-owned payload")
	}
	if tokens.callCount() != 0 {
		t.Errorf("token source calls = %d, want 0", tokens.callCount())
	}

	requests, attempts := f.snapshot()
	if attempts != 1 || len(requests) != 1 {
		t.Fatalf("upload attempts/requests = %d/%d, want exactly 1/1", attempts, len(requests))
	}
	req := requests[0]
	if req.method != http.MethodPut {
		t.Errorf("method = %q, want PUT", req.method)
	}
	if !req.tls {
		t.Errorf("upload request did not arrive over TLS")
	}
	if req.host != uploadCapabilityHost {
		t.Errorf("Host = %q, want allowlisted %q", req.host, uploadCapabilityHost)
	}
	if req.path != "/upload/"+uploadCapabilityPath || req.query != "" {
		t.Errorf("request target = %q?%q, want the capability path only", req.path, req.query)
	}
	if req.authorization != "" {
		t.Errorf("upload request carried an Authorization header")
	}
	if req.ifMatch != "" {
		t.Errorf("upload request carried an If-Match header")
	}
	wantRange := fmt.Sprintf("bytes 0-%d/%d", len(payload)-1, len(payload))
	if req.contentRange != wantRange {
		t.Errorf("Content-Range = %q, want %q", req.contentRange, wantRange)
	}
	if req.contentLength != strconv.Itoa(len(payload)) {
		t.Errorf("Content-Length header = %q, want %d", req.contentLength, len(payload))
	}
	if !bytes.Equal(req.body, originalPayload) {
		t.Errorf("request body = %x, want exact caller payload", req.body)
	}

	// The acknowledgement is not a commit result and must not expose the
	// capability or credentials.
	formatted := fmt.Sprintf("%+v", ack)
	for _, secret := range []string{uploadCapabilityURL, uploadCapabilityPath, uploadToken} {
		if strings.Contains(formatted, secret) {
			t.Errorf("formatted acknowledgement exposed sensitive text")
		}
	}

	// A value copy shares the one-use gate: a later call must not hand off
	// another request.
	copied := *session
	if _, err := u.UploadBytes(context.Background(), &copied, payload); !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("second UploadBytes error = %v, want ErrDenied", err)
	}
	requests, attempts = f.snapshot()
	if attempts != 1 || len(requests) != 1 {
		t.Errorf("upload attempts/requests after reuse = %d/%d, want exactly 1/1", attempts, len(requests))
	}
	if tokens.callCount() != 0 {
		t.Errorf("token source calls after reuse = %d, want 0", tokens.callCount())
	}
}

func TestConditionalUploaderUploadBytesRejectsUntrustedTLSRoot(t *testing.T) {
	f := newUploadBytesFixture(t)
	tokens := &testTokenSource{token: uploadToken}
	session := uploadBytesSession(time.Now().Add(time.Hour))
	u := f.uploader(t, tokens, f.clientWithRootCAs(x509.NewCertPool()))

	_, err := u.UploadBytes(context.Background(), session, []byte("synthetic-payload"))
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
	if errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("TLS verification failure was mapped to ErrDenied: %v", err)
	}
	assertUploadBytesSecretsAbsent(t, err)
	if !session.state.attempted.Load() {
		t.Errorf("TLS verification failure left the one-use session unconsumed")
	}
	// The handshake must fail before net/http can deliver a request to the
	// handler, so the fixture still observes no upload attempt.
	assertUploadBytesNoRequest(t, f)

	copied := *session
	if _, err := u.UploadBytes(context.Background(), &copied, []byte("synthetic-payload")); !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("retry error = %v, want ErrDenied", err)
	}
	assertUploadBytesNoRequest(t, f)
	if tokens.callCount() != 0 {
		t.Errorf("token source calls = %d, want 0", tokens.callCount())
	}
}

func TestConditionalUploaderUploadBytesBorrowedBody(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x7f, 0x80, 0xff, 'x'}
	original := append([]byte(nil), payload...)
	body := newBorrowedUploadBody(payload)

	// The body must alias the caller's slice rather than copy it.
	body.mu.Lock()
	aliasesCaller := len(body.sealed) == len(payload) && &body.sealed[0] == &payload[0]
	body.mu.Unlock()
	if !aliasesCaller {
		t.Errorf("borrowed body did not alias the caller's slice")
	}

	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read borrowed body: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("borrowed body bytes = %x, want exact %x", got, original)
	}
	if !bytes.Equal(payload, original) {
		t.Errorf("reading the borrowed body mutated the caller's slice")
	}

	if err := body.Close(); err != nil {
		t.Errorf("close borrowed body: %v", err)
	}
	body.mu.Lock()
	retained := body.sealed
	body.mu.Unlock()
	if retained != nil {
		t.Errorf("closed borrowed body still retains the caller's slice")
	}

	buffer := make([]byte, len(original))
	n, err := body.Read(buffer)
	if n != 0 {
		t.Errorf("read after Close returned %d payload bytes", n)
	}
	if err != io.EOF {
		t.Errorf("read after Close error = %v, want io.EOF", err)
	}

	// Cleanup stays safe and idempotent after the first Close.
	if err := body.Close(); err != nil {
		t.Errorf("second close borrowed body: %v", err)
	}
	body.mu.Lock()
	retained = body.sealed
	body.mu.Unlock()
	if retained != nil {
		t.Errorf("re-closed borrowed body retains the caller's slice")
	}
}

func slicesEqualStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestConditionalUploaderUploadBytesAcceptsValidAcknowledgement(t *testing.T) {
	expiration := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	cases := []struct {
		name      string
		body      []byte
		wantEmpty bool
	}{
		{
			name:      "empty range list is preserved",
			body:      uploadBytesAckJSON(expiration, []string{}),
			wantEmpty: true,
		},
		{
			name: "single open range",
			body: uploadBytesAckJSON(expiration, []string{"0-"}),
		},
		{
			name: "multiple exact ranges",
			body: uploadBytesAckJSON(expiration, []string{"10-", "0-4", "6-6"}),
		},
		{
			name: "fractional seconds",
			body: []byte(`{"expirationDateTime":"` + expiration.Format(time.RFC3339Nano) + `","nextExpectedRanges":["0-"]}`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadBytesFixture(t)
			f.setResponse(http.StatusAccepted, tc.body, "")
			tokens := &testTokenSource{token: uploadToken}
			session := uploadBytesSession(expiration)
			ack, err := f.uploader(t, tokens, nil).UploadBytes(context.Background(), session, []byte("synthetic-payload"))
			if err != nil {
				t.Fatalf("UploadBytes: %v", err)
			}
			if !ack.ExpirationDateTime.Equal(expiration) {
				t.Errorf("ack expiration = %v, want %v", ack.ExpirationDateTime, expiration)
			}
			if tc.wantEmpty {
				if ack.NextExpectedRanges == nil || len(ack.NextExpectedRanges) != 0 {
					t.Errorf("empty nextExpectedRanges = %#v, want a preserved empty, non-nil list", ack.NextExpectedRanges)
				}
			}
			if tokens.callCount() != 0 {
				t.Errorf("token source calls = %d, want 0", tokens.callCount())
			}
			if _, attempts := f.snapshot(); attempts != 1 {
				t.Errorf("upload attempts = %d, want 1", attempts)
			}
		})
	}
}

func TestConditionalUploaderUploadBytesRejectsPreflight(t *testing.T) {
	future := func() time.Time { return time.Now().Add(time.Hour) }
	cases := []struct {
		name    string
		build   func() (context.Context, *UploadSession, []byte)
		wantCtx error
	}{
		{
			name: "nil context",
			build: func() (context.Context, *UploadSession, []byte) {
				return nil, uploadBytesSession(future()), []byte("synthetic")
			},
			wantCtx: context.Canceled,
		},
		{
			name: "cancelled context",
			build: func() (context.Context, *UploadSession, []byte) {
				return canceledContext(), uploadBytesSession(future()), []byte("synthetic")
			},
			wantCtx: context.Canceled,
		},
		{
			name: "nil session",
			build: func() (context.Context, *UploadSession, []byte) {
				return context.Background(), nil, []byte("synthetic")
			},
		},
		{
			name: "expired session",
			build: func() (context.Context, *UploadSession, []byte) {
				return context.Background(), uploadBytesSession(time.Now().Add(-time.Second)), []byte("synthetic")
			},
		},
		{
			name: "zero expiration",
			build: func() (context.Context, *UploadSession, []byte) {
				session := uploadBytesSession(future())
				session.expiresAt = time.Time{}
				return context.Background(), session, []byte("synthetic")
			},
		},
		{
			name: "nil payload",
			build: func() (context.Context, *UploadSession, []byte) {
				return context.Background(), uploadBytesSession(future()), nil
			},
		},
		{
			name: "empty payload",
			build: func() (context.Context, *UploadSession, []byte) {
				return context.Background(), uploadBytesSession(future()), []byte{}
			},
		},
		{
			name: "oversize payload",
			build: func() (context.Context, *UploadSession, []byte) {
				return context.Background(), uploadBytesSession(future()), make([]byte, vaultfilebackend.MaxValueSize+1)
			},
		},
		{
			name: "mismatched drive",
			build: func() (context.Context, *UploadSession, []byte) {
				session := uploadBytesSession(future())
				session.driveID = "synthetic-other-drive"
				return context.Background(), session, []byte("synthetic")
			},
		},
		{
			name: "mismatched item",
			build: func() (context.Context, *UploadSession, []byte) {
				session := uploadBytesSession(future())
				session.itemID = "synthetic-other-item"
				return context.Background(), session, []byte("synthetic")
			},
		},
		{
			name: "invalid ETag",
			build: func() (context.Context, *UploadSession, []byte) {
				session := uploadBytesSession(future())
				session.etag = ""
				return context.Background(), session, []byte("synthetic")
			},
		},
		{
			name: "unsafe capability URL",
			build: func() (context.Context, *UploadSession, []byte) {
				session := uploadBytesSession(future())
				session.uploadURL = "https://attacker.example/" + uploadCapabilityPath
				return context.Background(), session, []byte("synthetic")
			},
		},
		{
			name: "missing one-use state",
			build: func() (context.Context, *UploadSession, []byte) {
				session := uploadBytesSession(future())
				session.state = nil
				return context.Background(), session, []byte("synthetic")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadBytesFixture(t)
			tokens := &testTokenSource{token: uploadToken}
			ctx, session, payload := tc.build()
			_, err := f.uploader(t, tokens, nil).UploadBytes(ctx, session, payload)
			assertErrorIs(t, err, vaultfilebackend.ErrDenied)
			if tc.wantCtx != nil && !errors.Is(err, tc.wantCtx) {
				t.Errorf("error = %v, want context cause %v", err, tc.wantCtx)
			}
			if errors.Is(err, vaultfilebackend.ErrUnknown) {
				t.Errorf("preflight refusal was mapped to ErrUnknown: %v", err)
			}
			assertUploadBytesSecretsAbsent(t, err)
			if tokens.callCount() != 0 {
				t.Errorf("token source calls = %d, want 0", tokens.callCount())
			}
			assertUploadBytesNoRequest(t, f)
		})
	}

	var nilUploader *ConditionalUploader
	if _, err := nilUploader.UploadBytes(context.Background(), uploadBytesSession(future()), []byte("synthetic")); !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("nil uploader error = %v, want ErrDenied", err)
	}
}

func TestConditionalUploaderUploadBytesPreflightLeavesSessionUnused(t *testing.T) {
	f := newUploadBytesFixture(t)
	tokens := &testTokenSource{token: uploadToken}
	u := f.uploader(t, tokens, nil)
	session := uploadBytesSession(time.Now().Add(time.Hour))

	if _, err := u.UploadBytes(context.Background(), session, nil); !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Fatalf("empty payload error = %v, want ErrDenied", err)
	}
	assertUploadBytesNoRequest(t, f)

	if _, err := u.UploadBytes(context.Background(), session, []byte("synthetic-payload")); err != nil {
		t.Fatalf("UploadBytes after preflight refusal: %v", err)
	}
	requests, attempts := f.snapshot()
	if attempts != 1 || len(requests) != 1 {
		t.Errorf("upload attempts/requests = %d/%d, want exactly 1/1", attempts, len(requests))
	}
	if tokens.callCount() != 0 {
		t.Errorf("token source calls = %d, want 0", tokens.callCount())
	}
}

func TestConditionalUploaderUploadBytesRejectsNon202(t *testing.T) {
	validBody := uploadBytesAckJSON(time.Now().Add(time.Hour), []string{"0-"})
	cases := []struct {
		name     string
		status   int
		location string
	}{
		{name: "200 ok", status: http.StatusOK},
		{name: "201 created", status: http.StatusCreated},
		{name: "204 no content", status: http.StatusNoContent},
		{name: "temporary redirect", status: http.StatusTemporaryRedirect, location: "/synthetic-follow-target"},
		{name: "permanent redirect", status: http.StatusPermanentRedirect, location: "https://attacker.example/synthetic-follow-target"},
		{name: "bad request", status: http.StatusBadRequest},
		{name: "not found", status: http.StatusNotFound},
		{name: "server error", status: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadBytesFixture(t)
			f.setResponse(tc.status, validBody, tc.location)
			tokens := &testTokenSource{token: uploadToken}
			u := f.uploader(t, tokens, nil)
			session := uploadBytesSession(time.Now().Add(time.Hour))
			_, err := u.UploadBytes(context.Background(), session, []byte("synthetic-payload"))
			assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
			if errors.Is(err, vaultfilebackend.ErrDenied) {
				t.Errorf("post-handoff status was mapped to ErrDenied: %v", err)
			}
			assertUploadBytesSecretsAbsent(t, err)
			requests, attempts := f.snapshot()
			if attempts != 1 || len(requests) != 1 {
				t.Errorf("upload attempts/requests = %d/%d, want exactly 1/1 with no follow or retry", attempts, len(requests))
			}

			copied := *session
			if _, err := u.UploadBytes(context.Background(), &copied, []byte("synthetic-payload")); !errors.Is(err, vaultfilebackend.ErrDenied) {
				t.Errorf("retry error = %v, want ErrDenied", err)
			}
			requests, attempts = f.snapshot()
			if attempts != 1 || len(requests) != 1 {
				t.Errorf("upload attempts/requests after retry = %d/%d, want exactly 1/1", attempts, len(requests))
			}
		})
	}
}

func TestConditionalUploaderUploadBytesRejectsMalformedAcknowledgement(t *testing.T) {
	expiration := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	expirationJSON, _ := json.Marshal(expiration.Format(time.RFC3339))
	cases := []struct {
		name string
		body []byte
	}{
		{name: "empty", body: nil},
		{name: "null", body: []byte(`null`)},
		{name: "array", body: []byte(`[]`)},
		{name: "malformed", body: []byte(`{"expirationDateTime":`)},
		{name: "missing expiration", body: []byte(`{"nextExpectedRanges":[]}`)},
		{name: "null expiration", body: []byte(`{"expirationDateTime":null,"nextExpectedRanges":[]}`)},
		{name: "numeric expiration", body: []byte(`{"expirationDateTime":7,"nextExpectedRanges":[]}`)},
		{name: "non RFC3339 expiration", body: []byte(`{"expirationDateTime":"tomorrow","nextExpectedRanges":[]}`)},
		{name: "missing ranges", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s}`, expirationJSON))},
		{name: "null ranges", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":null}`, expirationJSON))},
		{name: "string ranges", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":"0-"}`, expirationJSON))},
		{name: "object ranges", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":{}}`, expirationJSON))},
		{name: "numeric element", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":[7]}`, expirationJSON))},
		{name: "null element", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":[null]}`, expirationJSON))},
		{name: "empty element", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":[""]}`, expirationJSON))},
		{name: "non numeric", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":["abc"]}`, expirationJSON))},
		{name: "missing end dash", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":["123"]}`, expirationJSON))},
		{name: "extra separator", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":["1-2-3"]}`, expirationJSON))},
		{name: "negative start", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":["-1"]}`, expirationJSON))},
		{name: "descending range", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":["5-4"]}`, expirationJSON))},
		{name: "leading zero", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":["01-"]}`, expirationJSON))},
		{name: "whitespace in range", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":["1 -2"]}`, expirationJSON))},
		{name: "duplicate expiration", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"expirationDateTime":%s,"nextExpectedRanges":[]}`, expirationJSON, expirationJSON))},
		{name: "duplicate ranges", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":[],"nextExpectedRanges":[]}`, expirationJSON))},
		{name: "trailing data", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":[]} {}`, expirationJSON))},
		{name: "invalid utf8", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":[],"pad":"`+"\xff"+`"}`, expirationJSON))},
		{name: "oversize", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s,"nextExpectedRanges":[],"pad":%q}`, expirationJSON, strings.Repeat("a", maxUploadAcknowledgementJSONSize)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadBytesFixture(t)
			f.setResponse(http.StatusAccepted, tc.body, "")
			tokens := &testTokenSource{token: uploadToken}
			u := f.uploader(t, tokens, nil)
			session := uploadBytesSession(time.Now().Add(time.Hour))
			_, err := u.UploadBytes(context.Background(), session, []byte("synthetic-payload"))
			assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
			if errors.Is(err, vaultfilebackend.ErrDenied) {
				t.Errorf("post-handoff acknowledgement failure was mapped to ErrDenied: %v", err)
			}
			assertUploadBytesSecretsAbsent(t, err)
			if _, attempts := f.snapshot(); attempts != 1 {
				t.Errorf("upload attempts = %d, want exactly 1", attempts)
			}

			copied := *session
			if _, err := u.UploadBytes(context.Background(), &copied, []byte("synthetic-payload")); !errors.Is(err, vaultfilebackend.ErrDenied) {
				t.Errorf("retry error = %v, want ErrDenied", err)
			}
			requests, attempts := f.snapshot()
			if attempts != 1 || len(requests) != 1 {
				t.Errorf("upload attempts/requests after retry = %d/%d, want exactly 1/1", attempts, len(requests))
			}
			if tokens.callCount() != 0 {
				t.Errorf("token source calls = %d, want 0", tokens.callCount())
			}
		})
	}
}

type uploadBytesFailingTransport struct {
	attempts int32
}

func (t *uploadBytesFailingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&t.attempts, 1)
	return nil, errors.New("synthetic transport failure for " + req.URL.String() + " token=" + uploadToken + " body=" + uploadBytesProviderSecret)
}

func TestConditionalUploaderUploadBytesTransportFailureIsTerminal(t *testing.T) {
	transport := &uploadBytesFailingTransport{}
	tokens := &testTokenSource{token: uploadToken}
	u, err := newConditionalUploader(ConditionalUploaderConfig{
		DriveID: uploadDriveID,
		ItemID:  uploadItemID,
		Tokens:  tokens,
	}, nil, &http.Client{Transport: transport})
	if err != nil {
		t.Fatalf("newConditionalUploader: %v", err)
	}
	session := uploadBytesSession(time.Now().Add(time.Hour))
	_, err = u.UploadBytes(context.Background(), session, []byte("synthetic-payload"))
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
	if errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("transport failure was mapped to ErrDenied: %v", err)
	}
	assertUploadBytesSecretsAbsent(t, err)
	if got := atomic.LoadInt32(&transport.attempts); got != 1 {
		t.Errorf("transport attempts = %d, want exactly 1", got)
	}

	copied := *session
	if _, err := u.UploadBytes(context.Background(), &copied, []byte("synthetic-payload")); !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("retry error = %v, want ErrDenied", err)
	}
	if got := atomic.LoadInt32(&transport.attempts); got != 1 {
		t.Errorf("transport attempts after retry = %d, want exactly 1", got)
	}
	if tokens.callCount() != 0 {
		t.Errorf("token source calls = %d, want 0", tokens.callCount())
	}
}

func TestConditionalUploaderUploadBytesDeadlineIsSessionExpiry(t *testing.T) {
	f := newUploadBytesFixture(t)
	f.setHook(func(_ http.ResponseWriter, r *http.Request) bool {
		<-r.Context().Done()
		return true
	})
	tokens := &testTokenSource{token: uploadToken}
	u := f.uploader(t, tokens, nil)
	session := uploadBytesSession(time.Now().Add(200 * time.Millisecond))

	started := time.Now()
	_, err := u.UploadBytes(context.Background(), session, []byte("synthetic-payload"))
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("UploadBytes exceeded the session deadline by too much: %v", elapsed)
	}
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
	if errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("post-handoff timeout was mapped to ErrDenied: %v", err)
	}
	assertUploadBytesSecretsAbsent(t, err)
	if _, attempts := f.snapshot(); attempts != 1 {
		t.Errorf("upload attempts = %d, want exactly 1", attempts)
	}

	copied := *session
	if _, err := u.UploadBytes(context.Background(), &copied, []byte("synthetic-payload")); !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("retry error = %v, want ErrDenied", err)
	}
	requests, attempts := f.snapshot()
	if attempts != 1 || len(requests) != 1 {
		t.Errorf("upload attempts/requests after retry = %d/%d, want exactly 1/1", attempts, len(requests))
	}
	if tokens.callCount() != 0 {
		t.Errorf("token source calls = %d, want 0", tokens.callCount())
	}
}

func TestConditionalUploaderUploadBytesConcurrentOneUse(t *testing.T) {
	f := newUploadBytesFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.setHook(func(_ http.ResponseWriter, _ *http.Request) bool {
		once.Do(func() { close(entered) })
		<-release
		return false
	})

	tokens := &testTokenSource{token: uploadToken}
	u := f.uploader(t, tokens, nil)
	session := uploadBytesSession(time.Now().Add(time.Hour))
	const callers = 8
	var wg sync.WaitGroup
	results := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, results[index] = u.UploadBytes(context.Background(), session, []byte("synthetic-payload"))
		}(i)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no upload request reached the loopback server")
	}
	// Give concurrent losers time to observe the attempted gate.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	successes := 0
	for index, err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("caller %d error = %v, want ErrDenied", index, err)
		}
	}
	if successes != 1 {
		t.Errorf("successful concurrent uploads = %d, want exactly 1", successes)
	}
	requests, attempts := f.snapshot()
	if attempts != 1 || len(requests) != 1 {
		t.Errorf("upload attempts/requests = %d/%d, want exactly 1/1", attempts, len(requests))
	}
	if tokens.callCount() != 0 {
		t.Errorf("token source calls = %d, want 0", tokens.callCount())
	}

	copied := *session
	if _, err := u.UploadBytes(context.Background(), &copied, []byte("synthetic-payload")); !errors.Is(err, vaultfilebackend.ErrDenied) {
		t.Errorf("later copied-session error = %v, want ErrDenied", err)
	}
	requests, attempts = f.snapshot()
	if attempts != 1 || len(requests) != 1 {
		t.Errorf("upload attempts/requests after copied-session retry = %d/%d, want exactly 1/1", attempts, len(requests))
	}
}
