package vaultfilebackend

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	testS3Region = "test-region-1"
	testS3Bucket = "test-bucket"
	testS3Prefix = "vault"
)

// s3Mock is a minimal, in-process TLS S3 endpoint. It implements just enough
// of GetObject, PutObject and ListObjectsV2 to exercise the bridge, records
// every request, and enforces If-None-Match: * and If-Match the way S3 does.
// It is test scaffolding, not an S3 implementation.
type s3Mock struct {
	t      *testing.T
	server *httptest.Server

	mu      sync.Mutex
	objects map[string][]byte // key -> body
	etags   map[string]string // key -> quoted ETag, verbatim
	seq     atomic.Uint64

	// requests records "METHOD key" for every request that reached the
	// handler; putEtags records the conditional headers of each PUT.
	requests   []string
	putHeaders []http.Header

	// Hook controls behavior per request; nil means normal handling.
	Hook func(w http.ResponseWriter, r *http.Request) bool

	// addressed records request URLs seen by recordingTransport.
	addressed []url.URL
}

func newS3Mock(t *testing.T) *s3Mock {
	t.Helper()
	return newS3MockWith(t, nil)
}

// newS3MockWith returns an empty mock whose hook is installed before any
// request can arrive.
func newS3MockWith(t *testing.T, hook func(w http.ResponseWriter, r *http.Request) bool) *s3Mock {
	t.Helper()
	m := &s3Mock{
		t:       t,
		objects: map[string][]byte{},
		etags:   map[string]string{},
		Hook:    hook,
	}
	m.server = httptest.NewTLSServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}

// seed installs a committed object and returns its quoted ETag.
func (m *s3Mock) seed(key string, body []byte) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	etag := m.nextETag(body)
	m.objects[key] = append([]byte(nil), body...)
	m.etags[key] = etag
	return etag
}

func (m *s3Mock) nextETag(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%q", hex.EncodeToString(sum[:])+fmt.Sprintf("-%d", m.seq.Add(1)))
}

func (m *s3Mock) get(key string) ([]byte, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	return append([]byte(nil), b...), m.etags[key], ok
}

func (m *s3Mock) recorded() ([]string, []http.Header) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.requests...), append([]http.Header(nil), m.putHeaders...)
}

// setHook installs hook; the request path reads it under the same mutex that
// reset and recorded use, while the server may already be serving.
func (m *s3Mock) setHook(hook func(w http.ResponseWriter, r *http.Request) bool) {
	m.mu.Lock()
	m.Hook = hook
	m.mu.Unlock()
}

// reset clears the recording and the hook; hook must not be assigned
// directly because the server may read it concurrently.
func (m *s3Mock) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
	m.putHeaders = nil
	m.Hook = nil
}

// bucketAndKey parses both path-style and virtual-hosted requests. The mock
// always expects the test bucket.
func (m *s3Mock) bucketAndKey(r *http.Request) (string, string, bool) {
	if strings.HasPrefix(r.Host, testS3Bucket+".") {
		return testS3Bucket, strings.TrimPrefix(r.URL.Path, "/"), true
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/"+testS3Bucket+"/")
	return testS3Bucket, rest, ok
}

func (m *s3Mock) serve(w http.ResponseWriter, r *http.Request) {
	bucket, key, ok := m.bucketAndKey(r)
	if !ok || bucket != testS3Bucket {
		m.t.Errorf("unexpected request %s %s (host %s)", r.Method, r.URL.RequestURI(), r.Host)
		s3ErrorResponse(w, 404, "NoSuchBucket")
		return
	}
	m.mu.Lock()
	m.requests = append(m.requests, r.Method+" "+key)
	hook := m.Hook
	putHeaders := r.Header.Clone()
	m.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	// Routing uses the original destination, not the rewritten dial address:
	// path-style "/<bucket>/<key>" or virtual-hosted "<bucket>.<any host>".
	if !strings.HasPrefix(r.URL.Path, "/"+testS3Bucket+"/") {
		ok = strings.HasPrefix(r.Host, testS3Bucket+".")
	}
	switch r.Method {
	case http.MethodGet:
		m.mu.Lock()
		body, ok := m.objects[key]
		etag := m.etags[key]
		m.mu.Unlock()
		if !ok {
			s3ErrorResponse(w, 404, "NoSuchKey")
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		abortIfClientGone(w, r)
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			m.t.Errorf("mock read body: %v", err)
			s3ErrorResponse(w, 500, "InternalError")
			return
		}
		m.mu.Lock()
		m.putHeaders = append(m.putHeaders, putHeaders)
		_, exists := m.objects[key]
		curETag := m.etags[key]
		m.mu.Unlock()
		if inm := r.Header.Get("If-None-Match"); inm != "" {
			if inm != "*" {
				m.t.Errorf("If-None-Match = %q, mock only implements *", inm)
			}
			if exists {
				s3ErrorResponse(w, 412, "PreconditionFailed")
				return
			}
		}
		if im := r.Header.Get("If-Match"); im != "" {
			if !exists {
				s3ErrorResponse(w, 404, "NoSuchKey")
				return
			}
			if im != curETag {
				s3ErrorResponse(w, 412, "PreconditionFailed")
				return
			}
		}
		m.mu.Lock()
		etag := m.nextETag(body)
		m.objects[key] = body
		m.etags[key] = etag
		m.mu.Unlock()
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		abortIfClientGone(w, r)
	case http.MethodHead:
		m.t.Errorf("bridge issued a HEAD request for %q", key)
		w.WriteHeader(http.StatusOK)
	default:
		m.t.Errorf("unexpected method %s", r.Method)
		s3ErrorResponse(w, 405, "MethodNotAllowed")
	}
}

// abortIfClientGone tears the TCP connection down when the caller already
// gave up. net/http would otherwise retire the request and keep the TLS
// connection, which a test transport cannot tell from a healthy one, hiding
// the caller's deadline behind a pooled connection.
func abortIfClientGone(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() == nil {
		return
	}
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, _, err := hijacker.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

func s3ErrorResponse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><RequestId>test</RequestId></Error>`, code, code)
}

func (m *s3Mock) endpoint() string { return m.server.URL }

// staticProvider is the only credential source used by these tests.
// pinSDKEnv blanks the AWS SDK endpoint settings for the whole test process.
// The SDK's own config resolution (aws.NewCredentialsCache path via
// newConfig) lets AWS_ENDPOINT_URL / AWS_ENDPOINT_URL_S3 / the ignore flags
// override BaseEndpoint, which would send requests to a real service instead
// of the mock when this shell happens to export them. The bridge never reads
// them, but these tests must be hermetic regardless of the developer machine.
func TestMain(m *testing.M) {
	for _, key := range []string{
		"AWS_ENDPOINT_URL",
		"AWS_ENDPOINT_URL_S3",
		"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
		"AWS_S3_USE_ARN_REGION",
		"AWS_S3_US_EAST_1_REGIONAL_ENDPOINT",
	} {
		_ = os.Unsetenv(key)
	}
	os.Exit(m.Run())
}

func staticProvider() aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "TESTKEYID", SecretAccessKey: "testsecret", Source: "test"}, nil
	})
}

func mockConfig(m *s3Mock) S3Config {
	return S3Config{
		Endpoint:     m.endpoint(),
		Region:       testS3Region,
		Bucket:       testS3Bucket,
		Prefix:       testS3Prefix,
		Credentials:  staticProvider(),
		UsePathStyle: true,
		// Trust only the mock's own certificate: still a real TLS handshake
		// performed by the SDK transport, never a plain-HTTP bypass.
		HTTPClient: m.server.Client(),
	}
}

func newMockBackend(t *testing.T, m *s3Mock) Backend {
	t.Helper()
	b, err := NewS3(mockConfig(m))
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// fakeWriter is the conformance opener for the S3 bridge.
//
// RunConformance requires every opener to hand the suite an empty store: its
// create_read_roundtrip creates "vault.db" and requires that create to succeed
// and a second create to conflict. This opener therefore returns a fresh,
// unseeded mock backend and never pre-seeds a key; its conditional write
// machinery is exercised separately by TestS3ConditionalHeadersAreSentVerbatim
// and the race tests.
func fakeWriter(t *testing.T) openFunc {
	return func(t *testing.T) Backend {
		// A store that accepts a conditional PUT but then forgets the write
		// would break linearizability; the mock must keep it.
		return newMockBackend(t, newS3Mock(t))
	}
}

func TestS3Conformance(t *testing.T) {
	if testing.Short() {
		t.Skip("TLS S3 mock conformance is slower than the Memory suite")
	}
	RunConformance(t, fakeWriter(t), nil)
}

func TestS3ReadReturnsQuotedETagAndFullBytes(t *testing.T) {
	m := newS3Mock(t)
	m.reset()
	key := testS3Prefix + "/vault.db"
	body := []byte("complete encrypted payload")
	etag := m.seed(key, body)
	m.reset()
	b := newMockBackend(t, m)
	res, err := b.Read(context.Background(), "vault.db")
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Bytes) != string(body) {
		t.Fatalf("bytes = %q, want %q", res.Bytes, body)
	}
	if string(res.Revision) != etag {
		t.Fatalf("revision = %q, want verbatim ETag %q", res.Revision, etag)
	}
	if !strings.HasPrefix(string(res.Revision), `"`) || !strings.HasSuffix(string(res.Revision), `"`) {
		t.Fatalf("revision lost its quotes: %q", res.Revision)
	}
	reqs, _ := m.recorded()
	if len(reqs) != 1 || reqs[0] != "GET vault/vault.db" {
		t.Fatalf("requests = %v, want exactly one GET under the prefix", reqs)
	}
}

func TestS3Read32MiBBounded(t *testing.T) {
	m := newS3Mock(t)
	m.reset()
	body := make([]byte, MaxValueSize)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	m.seed(testS3Prefix+"/full", body)
	b := newMockBackend(t, m)
	res, err := b.Read(context.Background(), "full")
	if err != nil {
		t.Fatalf("read 32 MiB: %v", err)
	}
	if len(res.Bytes) != MaxValueSize || res.Revision.Zero() {
		t.Fatalf("read 32 MiB = %d bytes, zero revision %v", len(res.Bytes), res.Revision.Zero())
	}
	cur, _, _ := m.get(testS3Prefix + "/full")
	if string(cur) != string(res.Bytes) {
		t.Fatal("read bytes differ from stored bytes")
	}

	m.seed(testS3Prefix+"/huge", make([]byte, MaxValueSize+1))
	if _, err := b.Read(context.Background(), "huge"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("read 32 MiB + 1 = %v, want ErrCorrupt", err)
	}
}

func TestS3ConditionalHeadersAreSentVerbatim(t *testing.T) {
	m := newS3Mock(t)
	m.reset()
	b := newMockBackend(t, m)
	ctx := context.Background()
	m.reset()
	if err := b.CreateIfAbsent(ctx, "vault.db", []byte("v1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	cur, err := b.Read(ctx, "vault.db")
	if err != nil {
		t.Fatal(err)
	}
	m.reset()
	if err := b.ReplaceIfVersion(ctx, "vault.db", cur.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace: %v", err)
	}
	reqs, headers := m.recorded()
	if len(reqs) != 1 || reqs[0] != "PUT vault/vault.db" {
		t.Fatalf("requests = %v, want exactly one PUT (no HEAD, no fallback)", reqs)
	}
	if got := headers[0].Get("If-Match"); got != string(cur.Revision) {
		t.Fatalf("If-Match = %q, want %q", got, cur.Revision)
	}
	if got := headers[0].Get("If-None-Match"); got != "" {
		t.Fatalf("If-None-Match on replace = %q, want empty", got)
	}

	m.reset()
	if err := b.CreateIfAbsent(ctx, "other", []byte("v1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := b.CreateIfAbsent(ctx, "other", []byte("again")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create = %v, want ErrConflict", err)
	}
	reqs, headers = m.recorded()
	if len(reqs) != 2 {
		t.Fatalf("requests = %v, want two PUTs", reqs)
	}
	for i, h := range headers {
		if got := h.Get("If-None-Match"); got != "*" {
			t.Fatalf("If-None-Match on create #%d = %q, want *", i, got)
		}
		if h.Get("If-Match") != "" {
			t.Fatalf("If-Match on create #%d = %q, want empty", i, h.Get("If-Match"))
		}
	}
	if body, _, _ := m.get(testS3Prefix + "/other"); string(body) != "v1" {
		t.Fatalf("duplicate create overwrote stored bytes: %q", body)
	}
}

// singleWinner races cold writers callers, released together, that each read
// (for "replace") and then make exactly one conditional write. Exactly one
// must win and every other error must be ErrConflict. A caller whose
// transport fails while TLS sessions are still being established is
// tolerated as ErrUnknown (outcome unknown), but never as a second winner.
func singleWinner(t *testing.T, writers int, op string) {
	t.Helper()
	for round := range 10 {
		m := newS3Mock(t)
		if op == "replace" {
			m.seed(testS3Prefix+"/race", []byte("base"))
		}
		m.reset()
		b := newMockBackend(t, m)
		etagOfBase := m.etags[testS3Prefix+"/race"]
		var wins, conflicts, unknowns atomic.Int32
		var others sync.Map
		var start, done sync.WaitGroup
		start.Add(1)
		for i := range writers {
			done.Add(1)
			go func() {
				defer done.Done()
				ctx := context.Background()
				start.Wait()
				var err error
				if op == "replace" {
					base, rerr := b.Read(ctx, "race")
					if rerr != nil {
						err = rerr
					} else if string(base.Revision) != etagOfBase {
						// Another writer already replaced it.
						err = ErrConflict
					} else {
						err = b.ReplaceIfVersion(ctx, "race", base.Revision, []byte("winner"))
					}
				} else {
					err = b.CreateIfAbsent(ctx, "race", []byte{byte(i), byte(round)})
				}
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, ErrConflict):
					conflicts.Add(1)
				case errors.Is(err, ErrUnknown):
					unknowns.Add(1)
				default:
					others.Store(i, err)
				}
			}()
		}
		start.Done()
		done.Wait()
		others.Range(func(k, v any) bool {
			t.Errorf("round %d writer %v: %v", round, k, v)
			return true
		})
		if wins.Load() != 1 {
			t.Fatalf("round %d wins=%d conflicts=%d unknown=%d, want 1 winner", round, wins.Load(), conflicts.Load(), unknowns.Load())
		}
		if _, _, ok := m.get(testS3Prefix + "/race"); !ok {
			t.Fatalf("round %d: nothing stored", round)
		}
	}
}

func TestS3ConditionalOneWinner(t *testing.T) {
	const writers = 8
	t.Run("replace", func(t *testing.T) { singleWinner(t, writers, "replace") })
	t.Run("create", func(t *testing.T) { singleWinner(t, writers, "create") })
}

func TestS3ErrorClassification(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		op       string // "create", "replace", "read"
		deadline bool
		hook     func(w http.ResponseWriter, r *http.Request) bool
		want     error
		detail   string
	}{
		{
			name: "create_conflict_412",
			op:   "create",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 412, "PreconditionFailed")
				return true
			},
			want: ErrConflict,
		},
		{
			name: "replace_conflict_409",
			op:   "replace",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 409, "ConditionalRequestConflict")
				return true
			},
			want: ErrConflict,
		},
		{
			name: "replace_missing_404",
			op:   "replace",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 404, "NoSuchKey")
				return true
			},
			want: ErrConflict,
		},
		{
			name: "replace_missing_412",
			op:   "replace",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 412, "PreconditionFailed")
				return true
			},
			want: ErrConflict,
		},
		{
			name: "create_access_denied",
			op:   "create",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 403, "AccessDenied")
				return true
			},
			want: ErrDenied,
		},
		{
			name: "replace_access_denied",
			op:   "replace",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 403, "AccessDenied")
				return true
			},
			want: ErrDenied,
		},
		{
			name: "create_server_error",
			op:   "create",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 503, "ServiceUnavailable")
				return true
			},
			want: ErrUnknown,
		},
		{
			name: "replace_server_error",
			op:   "replace",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 500, "InternalError")
				return true
			},
			want: ErrUnknown,
		},
		{
			// The service hangs past the caller's deadline: the request may
			// have been executed, so the outcome is unknown, not a conflict.
			name:     "create_timeout",
			op:       "create",
			deadline: true,
			hook:     hangUntilDone,
			want:     ErrUnknown,
		},
		{
			name:     "replace_timeout",
			op:       "replace",
			deadline: true,
			hook:     hangUntilDone,
			want:     ErrUnknown,
		},
		{
			name: "replace_truncated_response",
			op:   "replace",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return true
				}
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nETag: \"x\"\r\nContent-Len"))
				_ = conn.Close()
				return true
			},
			want: ErrUnknown,
		},
		{
			name: "read_not_found",
			op:   "read",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 404, "NoSuchKey")
				return true
			},
			want: ErrNotFound,
		},
		{
			name: "read_not_found_no_body",
			op:   "read",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				w.WriteHeader(404)
				return true
			},
			want: ErrNotFound,
		},
		{
			name: "read_access_denied",
			op:   "read",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 403, "AccessDenied")
				return true
			},
			want: ErrDenied,
		},
		{
			name: "read_server_error",
			op:   "read",
			hook: func(w http.ResponseWriter, r *http.Request) bool {
				s3ErrorResponse(w, 502, "BadGateway")
				return true
			},
			want: ErrUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newS3Mock(t)
			m.seed(testS3Prefix+"/vault.db", []byte("committed"))
			m.reset()
			b := newMockBackend(t, m)
			seedBody, seedETag, ok := m.get(testS3Prefix + "/vault.db")
			if !ok {
				t.Fatal("seed missing")
			}
			cur := ReadResult{Bytes: seedBody, Revision: Revision(seedETag)}
			m.setHook(tc.hook)
			opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if tc.deadline {
				opCtx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
				defer cancel()
			}
			var got error
			switch tc.op {
			case "create":
				got = b.CreateIfAbsent(opCtx, "new", []byte("v"))
			case "replace":
				got = b.ReplaceIfVersion(opCtx, "vault.db", cur.Revision, []byte("v2"))
			case "read":
				_, got = b.Read(opCtx, "vault.db")
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("%s = %v, want %v", tc.name, got, tc.want)
			}
			// Exactly one attempt: no retry of a conditional PUT that may
			// already have committed.
			reqs, _ := m.recorded()
			if len(reqs) != 1 {
				t.Fatalf("requests = %v, want exactly one attempt", reqs)
			}
			if body, _, _ := m.get(testS3Prefix + "/vault.db"); string(body) != "committed" {
				t.Fatalf("failed %s changed stored bytes: %q", tc.name, body)
			}
		})
	}
}

// hangUntilDone simulates a service that received the request and never
// answers.
func hangUntilDone(w http.ResponseWriter, r *http.Request) bool {
	select {
	case <-r.Context().Done():
	case <-time.After(5 * time.Second):
	}
	return true
}

// TestS3TimeoutDuringBodyIsDenied pins the Read body-deadline outcome: Read
// never changes stored state and the caller asked to stop, so a deadline that
// ends a body read is the caller's cancellation (ErrDenied), not an unknown
// outcome. Only mutating calls report ErrUnknown on a deadline.
func TestS3TimeoutDuringBodyIsDenied(t *testing.T) {
	m := newS3MockWith(t, func(w http.ResponseWriter, r *http.Request) bool {
		// Send headers and part of the body, then stall: the caller deadline
		// ends the read.
		w.Header().Set("ETag", `"slow"`)
		w.Header().Set("Content-Length", "4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("bo"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		return true
	})
	m.seed(testS3Prefix+"/slow", []byte("body"))
	b := newMockBackend(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := b.Read(ctx, "slow")
	if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("timed-out body = %v, want ErrDenied about the caller's deadline", err)
	}
}

func TestS3CallerCancelBeforeSendIsDenied(t *testing.T) {
	m := newS3Mock(t)
	var hits atomic.Int32
	m.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		hits.Add(1)
		return true
	})
	b := newMockBackend(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.CreateIfAbsent(ctx, "x", []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("cancelled create = %v, want ErrDenied", err)
	}
	if _, err := b.Read(ctx, "x"); !errors.Is(err, ErrDenied) {
		t.Fatalf("cancelled read = %v, want ErrDenied", err)
	}
	reqs, _ := m.recorded()
	if hits.Load() != 0 || len(reqs) != 0 {
		t.Fatalf("cancelled calls reached the service: %v", reqs)
	}
}

func TestS3RequestTimeoutIsUnknown(t *testing.T) {
	m := newS3Mock(t)
	m.seed(testS3Prefix+"/vault.db", []byte("committed"))
	b := newMockBackend(t, m)
	cur, err := b.Read(context.Background(), "vault.db")
	if err != nil {
		t.Fatal(err)
	}
	m.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		return true
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := b.ReplaceIfVersion(ctx, "vault.db", cur.Revision, []byte("v2")); !errors.Is(err, ErrUnknown) {
		t.Fatalf("timed-out replace = %v, want ErrUnknown", err)
	}
}

func TestS3ConnectionRefusedIsDenied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	b, err := NewS3(S3Config{
		Endpoint:    "https://" + addr,
		Region:      testS3Region,
		Bucket:      testS3Bucket,
		Credentials: staticProvider(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.CreateIfAbsent(ctx, "x", []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("connection refused create = %v, want ErrDenied", err)
	}
	if _, err := b.Read(ctx, "x"); !errors.Is(err, ErrDenied) {
		t.Fatalf("connection refused read = %v, want ErrDenied", err)
	}
}

func TestS3ConditionalPutIsActuallySignedBySDK(t *testing.T) {
	// The bridge must let the SDK sign: the Authorization header carries a
	// SigV4 signature over signedHeaders that include the conditional header.
	m := newS3Mock(t)
	var signedHeaders string
	m.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut {
			signedHeaders = r.Header.Get("Authorization")
		}
		return false
	})
	b := newMockBackend(t, m)
	ctx := context.Background()
	if err := b.CreateIfAbsent(ctx, "a", []byte("v")); err != nil {
		t.Fatal(err)
	}
	cur, err := b.Read(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ReplaceIfVersion(ctx, "a", cur.Revision, []byte("w")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signedHeaders, "AWS4-HMAC-SHA256") || !strings.Contains(signedHeaders, "if-match") {
		t.Fatalf("put Authorization = %q, want SDK SigV4 covering if-match", signedHeaders)
	}
}

func TestS3ListUnsupported(t *testing.T) {
	m := newS3Mock(t)
	b := newMockBackend(t, m)
	if _, err := b.List(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("list = %v, want ErrUnsupported", err)
	}
	reqs, _ := m.recorded()
	if len(reqs) != 0 {
		t.Fatalf("list issued requests: %v", reqs)
	}
}

func TestS3Close(t *testing.T) {
	m := newS3Mock(t)
	b, err := NewS3(mockConfig(m))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
	ctx := context.Background()
	if err := b.CreateIfAbsent(ctx, "x", []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("create after close = %v", err)
	}
	if _, err := b.Read(ctx, "x"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read after close = %v", err)
	}
	if err := b.ReplaceIfVersion(ctx, "x", Revision(`"r"`), []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("replace after close = %v", err)
	}
	if _, err := b.List(ctx); !errors.Is(err, ErrDenied) {
		t.Fatalf("list after close = %v", err)
	}
	reqs, _ := m.recorded()
	if len(reqs) != 0 {
		t.Fatalf("closed backend issued requests: %v", reqs)
	}
}

func TestS3ConfigValidation(t *testing.T) {
	ok := S3Config{Endpoint: "https://s3.example.test", Region: "r", Bucket: "b", Credentials: staticProvider()}
	bad := []struct {
		name string
		mut  func(*S3Config)
	}{
		{"empty_endpoint", func(c *S3Config) { c.Endpoint = "" }},
		{"relative_endpoint", func(c *S3Config) { c.Endpoint = "s3.example.test" }},
		{"no_host", func(c *S3Config) { c.Endpoint = "https://" }},
		{"userinfo", func(c *S3Config) { c.Endpoint = "https://u:p@s3.example.test" }},
		{"query", func(c *S3Config) { c.Endpoint = "https://s3.example.test/?x=1" }},
		{"non_http_scheme", func(c *S3Config) { c.Endpoint = "ftp://s3.example.test" }},
		{"plain_http", func(c *S3Config) { c.Endpoint = "http://s3.example.test" }},
		{"no_region", func(c *S3Config) { c.Region = "" }},
		{"no_bucket", func(c *S3Config) { c.Bucket = "" }},
		{"no_credentials", func(c *S3Config) { c.Credentials = nil }},
	}
	if _, err := NewS3(ok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	// A prefix is legal only when Prefix + "/" + name fits one key.
	fits := ok
	fits.Prefix = strings.Repeat("p", MaxNameSize-2)
	if _, err := NewS3(fits); err != nil {
		t.Fatalf("prefix leaving no room for a name accepted: %v", err)
	}
	noRoom := ok
	noRoom.Prefix = strings.Repeat("p", MaxNameSize-1)
	if _, err := NewS3(noRoom); !errors.Is(err, ErrDenied) {
		t.Fatalf("prefix leaving no room for a name = %v, want ErrDenied", err)
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ok
			tc.mut(&cfg)
			if _, err := NewS3(cfg); !errors.Is(err, ErrDenied) {
				t.Fatalf("NewS3 = %v, want ErrDenied", err)
			}
		})
	}
}

func TestS3CredentialsComeOnlyFromProvider(t *testing.T) {
	// Environment AWS_* variables must not reach the client: the configured
	// provider is the only source.
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	t.Setenv("AWS_SESSION_TOKEN", "envtoken")
	var mu sync.Mutex
	var seen string
	m := newS3MockWith(t, func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		seen = r.Header.Get("Authorization")
		mu.Unlock()
		return false
	})
	b := newMockBackend(t, m)
	if err := b.CreateIfAbsent(context.Background(), "x", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(seen, "Credential=TESTKEYID/") {
		t.Fatalf("Authorization = %q, want the configured provider's key", seen)
	}
	if !strings.Contains(seen, "/"+testS3Region+"/s3/") {
		t.Fatalf("Authorization = %q, want region %s", seen, testS3Region)
	}
}

// TestS3EndpointAddressing pins what UsePathStyle does with a custom
// endpoint: true sends "<endpoint>/<bucket>/<key>", false lets the SDK place
// the bucket itself. The test helper endpoint must name only the service
// (mockServiceHost); the bucket label is the SDK's job, never pre-added.
func TestS3EndpointAddressing(t *testing.T) {
	for _, pathStyle := range []bool{true, false} {
		t.Run(fmt.Sprintf("path_style_%v", pathStyle), func(t *testing.T) {
			m := newS3Mock(t)
			cfg := mockConfig(m)
			cfg.UsePathStyle = pathStyle
			cfg.Endpoint = mockServiceHost(t, m.endpoint())
			if cfg.Endpoint != m.endpoint() {
				t.Fatalf("service host helper changed the endpoint: %q vs %q", cfg.Endpoint, m.endpoint())
			}
			cfg.HTTPClient = recordingClient(m.server.Client(), &m.addressed)
			b, err := NewS3(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			ctx := context.Background()
			if err := b.CreateIfAbsent(ctx, "x", []byte("v")); err != nil {
				t.Fatal(err)
			}
			if body, _, ok := m.get(testS3Prefix + "/x"); !ok || string(body) != "v" {
				t.Fatalf("create stored %q, exists=%v", body, ok)
			}
			got, err := b.Read(ctx, "x")
			if err != nil || string(got.Bytes) != "v" {
				t.Fatalf("read = %q %v", got.Bytes, err)
			}
			urls := m.addressedURLs()
			if len(urls) == 0 {
				t.Fatal("no request was addressed")
			}
			for _, u := range urls {
				want := "/" + testS3Bucket + "/"
				if pathStyle && !strings.HasPrefix(u.Path, want) {
					t.Fatalf("path-style request %s does not start with %s", u.String(), want)
				}
				if strings.HasPrefix(u.Host, testS3Bucket+"."+testS3Bucket+".") {
					t.Fatalf("bucket label was pre-added: %s", u.String())
				}
			}
		})
	}
}

func (m *s3Mock) addressedURLs() []url.URL {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]url.URL(nil), m.addressed...)
}

// recordingClient returns a client with the same transport and TLS trust as
// base that records each request URL after endpoint resolution.
func recordingClient(base *http.Client, recorded *[]url.URL) *http.Client {
	rt := recordingTransport{base: base.Transport, recorded: recorded}
	return &http.Client{Transport: rt, CheckRedirect: base.CheckRedirect, Timeout: base.Timeout}
}

// recordingTransport records each request URL after endpoint resolution and
// hands the request unchanged to the real transport.
type recordingTransport struct {
	base     http.RoundTripper
	recorded *[]url.URL
}

func (rt recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	*rt.recorded = append(*rt.recorded, *r.URL)
	return rt.base.RoundTrip(r)
}

// mockServiceHost returns the mock's scheme and host (no bucket label). The
// mock server serves every hostname through the same listener, so the SDK's
// bucket.<host> request lands on it (the mock ignores Host except for routing).
func mockServiceHost(t *testing.T, endpoint string) string {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("parse endpoint %q: %v", endpoint, err)
	}
	return u.Scheme + "://" + u.Host
}

func TestS3NamesStaysUnderPrefix(t *testing.T) {
	m := newS3Mock(t)
	b := newMockBackend(t, m)
	ctx := context.Background()
	for _, name := range []string{"", "../x", "a/b", ".hidden"} {
		if err := b.CreateIfAbsent(ctx, name, []byte("v")); !errors.Is(err, ErrDenied) {
			t.Fatalf("create %q = %v, want ErrDenied", name, err)
		}
	}
	if err := b.ReplaceIfVersion(ctx, "x", Revision(""), []byte("v")); !errors.Is(err, ErrDenied) {
		t.Fatalf("zero revision = %v, want ErrDenied", err)
	}
	if err := b.CreateIfAbsent(ctx, "x", nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("empty value = %v, want ErrDenied", err)
	}
	reqs, _ := m.recorded()
	if len(reqs) != 0 {
		t.Fatalf("rejected calls reached the service: %v", reqs)
	}
}

// validStrongETagCases is shared by the Read and Replace checks so both sides
// accept exactly the same shape as a revision.
var validStrongETagCases = []struct {
	etag string
	ok   bool
}{
	{`"abc"`, true},
	{`"9b2cf535f27731c974343645a3985328-3"`, true},
	{`""`, true},
	{"\"obs\x80text\"", true},
	{``, false},
	{`abc`, false},
	{`"abc`, false},
	{`abc"`, false},
	{`"a","b"`, false},
	{`*`, false},
	{`W/"abc"`, false},
	{`w/"abc"`, false},
	{`"abc" `, false},
	{` "abc"`, false},
	{"\"a\x00b\"", false},
	{"\"a\tb\"", false},
	{"\"a b\"", false},
	{"\"a\x7fb\"", false},
	{`"` + strings.Repeat("a", MaxRevisionSize) + `"`, false},
}

func TestS3ValidStrongETag(t *testing.T) {
	for _, tc := range validStrongETagCases {
		if got := validStrongETag(tc.etag); got != tc.ok {
			t.Errorf("validStrongETag(%q) = %v, want %v", tc.etag, got, tc.ok)
		}
	}
}

// TestS3ReplacePreflight: an expected Revision that is zero or over
// MaxRevisionSize is malformed (ErrDenied); a non-zero, in-bound one that
// cannot be a strong quoted ETag is ErrConflict. Both kinds are resolved
// locally: no request reaches the service and the stored version is unchanged.
func TestS3ReplacePreflight(t *testing.T) {
	m := newS3Mock(t)
	key := testS3Prefix + "/vault.db"
	etag := m.seed(key, []byte("committed"))
	b := newMockBackend(t, m)
	ctx := context.Background()
	m.reset()
	cases := []struct {
		name     string
		expected Revision
		want     error
	}{
		{"zero", "", ErrDenied},
		{"oversize_quoted", Revision(`"` + strings.Repeat("a", MaxRevisionSize) + `"`), ErrDenied},
		{"oversize_plain", Revision(strings.Repeat("a", MaxRevisionSize+1)), ErrDenied},
		{"oversize_weak", Revision(`W/"` + strings.Repeat("a", MaxRevisionSize) + `"`), ErrDenied},
		{"malformed_weak", Revision("W/" + etag), ErrConflict},
		{"malformed_unquoted", Revision("abc"), ErrConflict},
	}
	for _, tc := range cases {
		if err := b.ReplaceIfVersion(ctx, "vault.db", tc.expected, []byte("v2")); !errors.Is(err, tc.want) {
			t.Fatalf("replace with %s expected = %v, want %v", tc.name, err, tc.want)
		}
	}
	if reqs, _ := m.recorded(); len(reqs) != 0 {
		t.Fatalf("rejected revisions reached the service: %v", reqs)
	}
	if body, cur, _ := m.get(key); string(body) != "committed" || cur != etag {
		t.Fatalf("rejected replace changed stored state: %q %q", body, cur)
	}
	// A valid but stale ETag is the service's decision: exactly one
	// conditional PUT, and the service reports the conflict.
	stale := `"0000000000000000-0"`
	if err := b.ReplaceIfVersion(ctx, "vault.db", Revision(stale), []byte("v2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale replace = %v, want ErrConflict", err)
	}
	reqs, headers := m.recorded()
	if len(reqs) != 1 || reqs[0] != "PUT vault/vault.db" {
		t.Fatalf("requests = %v, want exactly one conditional PUT", reqs)
	}
	if got := headers[0].Get("If-Match"); got != stale || headers[0].Get("If-None-Match") != "" {
		t.Fatalf("If-Match = %q (If-None-Match %q), want only the expected revision verbatim", got, headers[0].Get("If-None-Match"))
	}
	if body, cur, _ := m.get(key); string(body) != "committed" || cur != etag {
		t.Fatalf("stale replace changed stored state: %q %q", body, cur)
	}
}

// TestS3ReplacePrecedence: a cancelled context or a closed backend is
// ErrDenied before the expected Revision is inspected, so a malformed
// revision does not turn those calls into ErrConflict. Neither sends a request.
func TestS3ReplacePrecedence(t *testing.T) {
	const malformed = "not-a-strong-etag"
	for _, afterClose := range []bool{false, true} {
		name := "cancelled"
		if afterClose {
			name = "closed"
		}
		t.Run(name, func(t *testing.T) {
			m := newS3Mock(t)
			key := testS3Prefix + "/vault.db"
			etag := m.seed(key, []byte("committed"))
			b, err := NewS3(mockConfig(m))
			if err != nil {
				t.Fatal(err)
			}
			if afterClose {
				if err := b.Close(); err != nil {
					t.Fatal(err)
				}
			}
			m.reset()
			ctx := context.Background()
			if !afterClose {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := b.ReplaceIfVersion(ctx, "vault.db", Revision(malformed), []byte("v2")); !errors.Is(err, ErrDenied) {
				t.Fatalf("%s replace with malformed expected = %v, want ErrDenied", name, err)
			}
			if reqs, _ := m.recorded(); len(reqs) != 0 {
				t.Fatalf("%s replace reached the service: %v", name, reqs)
			}
			if body, cur, _ := m.get(key); string(body) != "committed" || cur != etag {
				t.Fatalf("%s replace changed stored state: %q %q", name, body, cur)
			}
		})
	}
}

// TestS3ReplaceRejectsUnsafeExpectedWithoutRequest: a non-zero expected
// Revision that could never be a matching strong ETag is ErrConflict resolved
// locally; nothing is sent, including no HEAD and no unconditional fallback.
func TestS3ReplaceRejectsUnsafeExpectedWithoutRequest(t *testing.T) {
	m := newS3Mock(t)
	key := testS3Prefix + "/vault.db"
	etag := m.seed(key, []byte("committed"))
	b := newMockBackend(t, m)
	ctx := context.Background()
	m.reset()
	// Control characters are covered by TestS3ValidStrongETag; values here
	// are what a caller can plausibly carry over (headers or JSON).
	for _, unsafe := range []string{`*`, `"a","b"`, `"a", "b"`, `W/"abc"`, "\"a b\"", "\"abc\" ", `abc`, `""x`} {
		err := b.ReplaceIfVersion(ctx, "vault.db", Revision(unsafe), []byte("v2"))
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("replace with expected %q = %v, want ErrConflict", unsafe, err)
		}
	}
	// A well-formed but non-matching ETag conflicts too, after exactly one
	// conditional PUT; neither a weak prefix nor extra quotes match.
	for _, wrong := range []Revision{`"nope"`, `"a-b"`, Revision(`"` + etag + `"`), Revision("W/" + etag), Revision("w/" + etag)} {
		if err := b.ReplaceIfVersion(ctx, "vault.db", wrong, []byte("v2")); !errors.Is(err, ErrConflict) {
			t.Fatalf("replace with expected %q = %v, want ErrConflict", wrong, err)
		}
	}
	reqs, _ := m.recorded()
	if len(reqs) != 4 {
		t.Fatalf("requests = %v, want one PUT per well-formed expected and none for the rest", reqs)
	}
	for _, r := range reqs {
		if r != "PUT vault/vault.db" {
			t.Fatalf("unexpected request %q, want only conditional PUTs", r)
		}
	}
	if body, _, _ := m.get(key); string(body) != "committed" {
		t.Fatalf("rejected replace changed stored bytes: %q", body)
	}
	// The zero Revision stays malformed, not a conflict.
	if err := b.ReplaceIfVersion(ctx, "vault.db", Revision(""), []byte("v2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("zero expected = %v, want ErrDenied", err)
	}
	if reqs, _ := m.recorded(); len(reqs) != 0 {
		t.Fatalf("zero expected reached the service: %v", reqs)
	}
}

// TestS3ReadRejectsUnsafeETag: an ETag that cannot be handed back verbatim as
// a single strong If-Match is ErrCorrupt, and Read never rewrites it into an
// acceptable value. Every other control byte is listed only in
// TestS3ValidStrongETag: net/http's header parser rejects such a response
// before the bridge can inspect it, so it cannot be a stored-revision case.
func TestS3ReadRejectsUnsafeETag(t *testing.T) {
	m := newS3Mock(t)
	m.seed(testS3Prefix+"/vault.db", []byte("body"))
	b := newMockBackend(t, m)
	for _, etag := range []string{
		`*`,
		`"a","b"`,
		`W/"abc"`,
		`w/"abc"`,
		"\"a b\"",
		`abc`,
		`""x`,
		"",
	} {
		etag := etag
		m.setHook(func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("ETag", etag)
			w.Header().Set("Content-Length", "4")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("body"))
			return true
		})
		if _, err := b.Read(context.Background(), "vault.db"); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("read with ETag %q = %v, want ErrCorrupt", etag, err)
		}
	}
	// A legal quoted ETag is returned unmodified, quotes and all.
	const legal = `"a-b-c"`
	m.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("ETag", legal)
		w.Header().Set("Content-Length", "4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
		return true
	})
	res, err := b.Read(context.Background(), "vault.db")
	if err != nil || string(res.Revision) != legal || string(res.Bytes) != "body" {
		t.Fatalf("legal ETag read = %q %q, %v, want verbatim %q", res.Revision, res.Bytes, err, legal)
	}
	// The SDK deserializer trims external OWS off ETag, which can only turn a
	// legal tag into a legal tag; it can never hide an unsafe one.
	for _, v := range []string{`"abc"`, ` "abc"`, "\"abc\" \t", `W/ "a"`} {
		trimmed := strings.TrimSpace(v)
		if validStrongETag(v) && !validStrongETag(trimmed) {
			t.Errorf("header %q is accepted verbatim but its trimmed form %q is not", v, trimmed)
		}
	}
}

// TestS3Replace404DistinguishesConfigErrors: only NoSuchKey means the
// precondition failed; NoSuchBucket (or a 404 without an S3 code) is a
// configuration error and must not be reported as a version conflict.
func TestS3Replace404DistinguishesConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		hook func(w http.ResponseWriter, r *http.Request) bool
		want error
	}{
		{"no_such_key", func(w http.ResponseWriter, r *http.Request) bool {
			s3ErrorResponse(w, 404, "NoSuchKey")
			return true
		}, ErrConflict},
		{"no_such_bucket", func(w http.ResponseWriter, r *http.Request) bool {
			s3ErrorResponse(w, 404, "NoSuchBucket")
			return true
		}, ErrDenied},
		{"bare_404", func(w http.ResponseWriter, r *http.Request) bool {
			w.WriteHeader(404)
			return true
		}, ErrDenied},
		{"access_point_not_found", func(w http.ResponseWriter, r *http.Request) bool {
			s3ErrorResponse(w, 404, "NoSuchAccessPoint")
			return true
		}, ErrDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newS3Mock(t)
			etag := m.seed(testS3Prefix+"/vault.db", []byte("committed"))
			b := newMockBackend(t, m)
			m.setHook(tc.hook)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := b.ReplaceIfVersion(ctx, "vault.db", Revision(etag), []byte("v2"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("replace on 404 %s = %v, want %v", tc.name, err, tc.want)
			}
			if reqs, _ := m.recorded(); len(reqs) != 1 || reqs[0] != "PUT vault/vault.db" {
				t.Fatalf("requests = %v, want exactly one conditional PUT", reqs)
			}
		})
	}
}

func TestS3MockUsesTLSServer(t *testing.T) {
	// Guard: every test above talks to httptest.NewTLSServer, so the
	// conditional headers travel inside a TLS session the SDK's transport
	// negotiated itself, not through an injected fake.
	m := newS3Mock(t)
	if !strings.HasPrefix(m.endpoint(), "https://") {
		t.Fatalf("mock endpoint = %q, want https", m.endpoint())
	}
}
