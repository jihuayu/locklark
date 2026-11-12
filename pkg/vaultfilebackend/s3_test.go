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

	// PutPreflight, when set, is consulted by every PUT after its body has
	// been read and before the atomic conditional check. It receives the
	// current status of the key as observed outside the critical section and
	// the request context, so a test hook can stop waiting when the caller
	// gives up; that snapshot is only for the hook's observation and is never
	// consulted to decide the PUT. The commit re-reads the state under the
	// mutex, and only if the request context is still live.
	PutPreflight func(ctx context.Context, obs s3PutObservation)

	// addressed records request URLs seen by recordingTransport.
	addressed []url.URL
}

// s3PutObservation is the key's state passed to s3Mock.PutPreflight. It is an
// observation for test coordination, not a precondition snapshot: the mock
// never commits based on it.
type s3PutObservation struct {
	Method      string
	Key         string
	Exists      bool
	ETag        string
	IfNoneMatch string
	IfMatch     string
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

// setPutPreflight installs the PUT preflight observation hook, read under the
// same mutex for the same reason as Hook.
func (m *s3Mock) setPutPreflight(fn func(context.Context, s3PutObservation)) {
	m.mu.Lock()
	m.PutPreflight = fn
	m.mu.Unlock()
}

// observePut reports the key's current status to the installed preflight
// hook. The snapshot and the hook are taken under m.mu; the hook itself runs
// after it is released, so the PUT path never holds the mutex while the hook
// waits. A hook installed with setPutPreflight after the snapshot was taken is
// never called with a stale observation.
func (m *s3Mock) observePut(ctx context.Context, obs s3PutObservation) {
	m.mu.Lock()
	_, obs.Exists = m.objects[obs.Key]
	obs.ETag = m.etags[obs.Key]
	fn := m.PutPreflight
	m.mu.Unlock()
	if fn != nil {
		fn(ctx, obs)
	}
}

// reset clears the recording and the hooks; hooks must not be assigned
// directly because the server may read them concurrently.
func (m *s3Mock) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
	m.putHeaders = nil
	m.Hook = nil
	m.PutPreflight = nil
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
		// The observation hook runs here, outside m.mu and only to let a test
		// coordinate concurrent PUTs; the verdict below is taken under m.mu.
		m.observePut(r.Context(), s3PutObservation{
			Method:      r.Method,
			Key:         key,
			IfNoneMatch: r.Header.Get("If-None-Match"),
			IfMatch:     r.Header.Get("If-Match"),
		})
		// The hook may have waited for other participants or for the caller.
		// A request cancelled meanwhile ends here, before any state changes.
		if r.Context().Err() != nil {
			abortIfClientGone(w, r)
			return
		}
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm != "*" {
			m.t.Errorf("If-None-Match = %q, mock only implements *", inm)
		}
		m.mu.Lock()
		m.putHeaders = append(m.putHeaders, putHeaders)
		// Check every precondition against the state at commit time and, when
		// they all hold, commit the body in the same critical section. Two
		// concurrent conditional PUTs can therefore never both observe the
		// same old state and both succeed.
		_, exists := m.objects[key]
		curETag := m.etags[key]
		var status int
		var code string
		var etag string
		switch {
		case r.Header.Get("If-None-Match") != "" && exists:
			status, code = 412, "PreconditionFailed"
		case r.Header.Get("If-Match") != "" && !exists:
			status, code = 404, "NoSuchKey"
		case r.Header.Get("If-Match") != "" && r.Header.Get("If-Match") != curETag:
			status, code = 412, "PreconditionFailed"
		default:
			etag = m.nextETag(body)
			m.objects[key] = body
			m.etags[key] = etag
		}
		m.mu.Unlock()
		// No response I/O while m.mu is held.
		if code != "" {
			s3ErrorResponse(w, status, code)
			return
		}
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

// putBarrier holds every PUT handler at a fixed point until all of them have
// arrived and the test explicitly releases them. It is never used while the
// mock holds m.mu: the handler reports its observation, releases the mutex,
// and only then waits.
type putBarrier struct {
	participants int
	release      chan struct{}
	once         sync.Once

	arrived chan struct{} // one token per participant reaching the barrier

	obsMu sync.Mutex
	obs   []s3PutObservation
}

func newPutBarrier(participants int) *putBarrier {
	return &putBarrier{
		participants: participants,
		release:      make(chan struct{}),
		arrived:      make(chan struct{}, participants),
	}
}

// wait records obs and blocks until its request context ends or the test
// releases the barrier. The request context derives from the shared test
// context, so cancelling either one unblocks the handler. The last arrival
// never releases it automatically: only the test decides when the race
// starts.
func (b *putBarrier) wait(ctx context.Context, obs s3PutObservation) {
	b.obsMu.Lock()
	b.obs = append(b.obs, obs)
	b.obsMu.Unlock()
	b.arrived <- struct{}{}
	select {
	case <-ctx.Done():
	case <-b.release:
	}
}

// releaseAll frees every waiting participant; it is idempotent.
func (b *putBarrier) releaseAll() { b.once.Do(func() { close(b.release) }) }

// observations returns the initial state every participant saw.
func (b *putBarrier) observations() []s3PutObservation {
	b.obsMu.Lock()
	defer b.obsMu.Unlock()
	return append([]s3PutObservation(nil), b.obs...)
}

// putBarrierFailure is the typed failure of the barrier tests. It is reported
// only after the barrier is released and every writer goroutine has exited.
type putBarrierFailure struct {
	reason  string
	arrived int
	want    int
	err     error
}

func (e *putBarrierFailure) Error() string {
	return fmt.Sprintf("mock PUT barrier: %s (%d/%d arrived; err %v)", e.reason, e.arrived, e.want, e.err)
}

func (e *putBarrierFailure) Unwrap() error { return e.err }

// writerResult is what one write goroutine reports when it returns.
type writerResult struct {
	index int
	err   error
}

// writerRun owns the write goroutines of one race. Its fields are touched only
// by the test goroutine, so no lock is needed. results is buffered for every
// writer, so a writer never blocks reporting its outcome, even after the test
// stopped reading early.
type writerRun struct {
	results chan writerResult
	errs    []error
	pending int
	exited  sync.WaitGroup
	reaped  bool // every writer goroutine has exited; test goroutine only
}

// startWriters starts one goroutine per op and releases them together.
func startWriters(ops []func() error) *writerRun {
	r := &writerRun{
		results: make(chan writerResult, len(ops)),
		errs:    make([]error, len(ops)),
		pending: len(ops),
	}
	start := make(chan struct{})
	r.exited.Add(len(ops))
	for i, op := range ops {
		go func(i int) {
			defer r.exited.Done()
			<-start
			r.results <- writerResult{index: i, err: op()}
		}(i)
	}
	close(start)
	return r
}

// take records one result. Every result must pass through take exactly once,
// including one observed early while waiting for the barrier; otherwise the
// drain would wait for a writer that already reported.
func (r *writerRun) take(res writerResult) writerResult {
	r.errs[res.index] = res.err
	r.pending--
	return res
}

// complete waits for the remaining results while ctx is live. It reports
// false when ctx has ended with writers still outstanding, leaving pending
// intact for stop to drain, and on success waits for the writer goroutines,
// which have all reported by then. The ctx check at the top of each pass makes
// an already-ended deadline win over results that happened to arrive with it.
func (r *writerRun) complete(ctx context.Context) bool {
	for r.pending > 0 {
		if ctx.Err() != nil {
			return false
		}
		select {
		case res := <-r.results:
			r.take(res)
		case <-ctx.Done():
			return false
		}
	}
	r.exited.Wait()
	r.reaped = true
	return true
}

// drain collects every outstanding result and then waits for the writer
// goroutines to return. The caller must already have cancelled their contexts
// and released the barrier, so the drain cannot wait forever.
func (r *writerRun) drain() {
	for r.pending > 0 {
		r.take(<-r.results)
	}
	r.exited.Wait()
	r.reaped = true
}

// stop ends the race: cancel the writers, release the barrier, drain every
// result, and return the typed failure to report.
func (r *writerRun) stop(cancel context.CancelFunc, barrier *putBarrier, reason string, cause error) *putBarrierFailure {
	cancel()
	barrier.releaseAll()
	r.drain()
	return &putBarrierFailure{reason: reason, arrived: len(barrier.observations()), want: len(r.errs), err: cause}
}

// awaitBarrier waits until every writer is parked at the barrier. It fails
// fast if a writer returns first, the test context ends, or the bound
// expires, and always cleans up before returning the typed failure.
func awaitBarrier(ctx context.Context, cancel context.CancelFunc, barrier *putBarrier, run *writerRun, timeout time.Duration) *putBarrierFailure {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for arrived := 0; arrived < barrier.participants; arrived++ {
		select {
		case <-barrier.arrived:
		case res := <-run.results:
			run.take(res)
			return run.stop(cancel, barrier,
				fmt.Sprintf("writer %d returned before every writer reached the barrier", res.index), res.err)
		case <-ctx.Done():
			return run.stop(cancel, barrier, "test context ended before every writer reached the barrier", ctx.Err())
		case <-timer.C:
			return run.stop(cancel, barrier, "timeout waiting for every writer to reach the barrier", context.DeadlineExceeded)
		}
	}
	return nil
}

// TestS3MockConditionalPutIsAtomic pins the mock's conditional PUT: every
// precondition check and the commit it guards happen in one critical section.
//
// writers conditional PUTs are parked at the mock's preflight observation until
// all have arrived and each has seen the same initial state; the test then
// releases them together. Exactly one may commit, every other must get
// ErrConflict, and the stored bytes and ETag must be the winner's. An
// implementation that decides from an earlier snapshot, releases the mutex and
// writes later lets several writers pass and fails here deterministically.
//
// Every failure cancels the writers, releases the barrier and drains their
// results, so it is reported in bounded time rather than after a writer's
// request deadline.
func TestS3MockConditionalPutIsAtomic(t *testing.T) {
	const (
		writers = 8
		key     = testS3Prefix + "/atomic"
		// barrierTimeout bounds the wait for all arrivals; raceDeadline bounds
		// the whole race, including writers that stall after the release.
		barrierTimeout = 10 * time.Second
		raceDeadline   = 30 * time.Second
	)
	cases := []struct {
		name   string
		seed   []byte // nil: the key starts absent
		absent bool
	}{
		{name: "conditional_create", absent: true},
		{name: "conditional_replace", seed: []byte("base")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newS3Mock(t)
			baseETag := ""
			if !tc.absent {
				baseETag = m.seed(key, tc.seed)
			}
			m.reset()
			barrier := newPutBarrier(writers)
			m.setPutPreflight(barrier.wait)
			b := newMockBackend(t, m)

			// testCtx is the complete-race deadline; every request context
			// derives from it, and ending it ends every writer and every
			// waiting handler.
			testCtx, cancel := context.WithTimeout(context.Background(), raceDeadline)
			defer cancel()

			bodies := make([][]byte, writers)
			ops := make([]func() error, writers)
			for i := range writers {
				bodies[i] = []byte(fmt.Sprintf("%s-writer-%d", tc.name, i))
				reqCtx, reqCancel := context.WithCancel(testCtx)
				defer reqCancel()
				ops[i] = func() error {
					if tc.absent {
						return b.CreateIfAbsent(reqCtx, "atomic", bodies[i])
					}
					return b.ReplaceIfVersion(reqCtx, "atomic", Revision(baseETag), bodies[i])
				}
			}
			run := startWriters(ops)
			// Even an unexpected assertion failure below ends the race and
			// reaps the writers before the test returns.
			t.Cleanup(func() {
				cancel()
				barrier.releaseAll()
				run.drain()
			})

			if fail := awaitBarrier(testCtx, cancel, barrier, run, barrierTimeout); fail != nil {
				t.Fatal(fail)
			}

			// Every participant must have reached the barrier and seen the
			// same initial precondition state, or the race was not exercised.
			want := s3PutObservation{
				Method: http.MethodPut,
				Key:    key,
				Exists: !tc.absent,
				ETag:   baseETag,
			}
			if tc.absent {
				want.IfNoneMatch = "*"
			} else {
				want.IfMatch = baseETag
			}
			obs := barrier.observations()
			if len(obs) != writers {
				t.Fatal(run.stop(cancel, barrier, "wrong number of preflight observations", nil))
			}
			for _, o := range obs {
				if o != want {
					t.Fatal(run.stop(cancel, barrier,
						fmt.Sprintf("preflight observation = %+v, want every writer to see %+v", o, want), nil))
				}
			}

			// All eight are parked and agree: release them together and
			// collect under the complete-race deadline.
			barrier.releaseAll()
			if !run.complete(testCtx) {
				// A writer stalled after the release. Cancel it, reap every
				// writer, then report; no goroutine outlives this failure.
				t.Fatal(run.stop(cancel, barrier,
					"complete-race deadline ended before every released writer returned", testCtx.Err()))
			}

			wins, conflicts := []int(nil), []int(nil)
			for i, err := range run.errs {
				switch {
				case err == nil:
					wins = append(wins, i)
				case errors.Is(err, ErrConflict):
					conflicts = append(conflicts, i)
				default:
					t.Errorf("writer %d = %v, want nil or ErrConflict", i, err)
				}
			}
			if len(wins) != 1 || len(conflicts) != writers-1 {
				t.Fatalf("wins=%v conflicts=%v, want exactly one winner and %d ErrConflict", wins, conflicts, writers-1)
			}
			winner := wins[0]
			body, etag, ok := m.get(key)
			if !ok || string(body) != string(bodies[winner]) {
				t.Fatalf("stored = %q (exists %v), want winner %d's %q", body, ok, winner, bodies[winner])
			}
			if tc.absent && etag == "" {
				t.Fatal("winner left no ETag")
			}
			if !tc.absent && etag == baseETag {
				t.Fatal("committed replace did not change the ETag")
			}
			got, err := b.Read(context.Background(), "atomic")
			if err != nil || string(got.Bytes) != string(bodies[winner]) || got.Revision != Revision(etag) {
				t.Fatalf("read back = %q %q, %v; want winner %d's bytes and ETag %q", got.Bytes, got.Revision, err, winner, etag)
			}

			// Conditional semantics hold after the race: a create conflicts
			// and a replace from the base ETag conflicts.
			m.reset()
			if err := b.CreateIfAbsent(context.Background(), "atomic", []byte("late")); !errors.Is(err, ErrConflict) {
				t.Fatalf("create after race = %v, want ErrConflict", err)
			}
			if !tc.absent {
				if err := b.ReplaceIfVersion(context.Background(), "atomic", Revision(baseETag), []byte("stale")); !errors.Is(err, ErrConflict) {
					t.Fatalf("replace from base ETag after race = %v, want ErrConflict", err)
				}
			} else if err := b.ReplaceIfVersion(context.Background(), "atomic", Revision(etag), []byte("next")); err != nil {
				t.Fatalf("replace from winner ETag = %v", err)
			}
			// Each post-race call is a single conditional PUT: no HEAD, no
			// unconditional write, no retry.
			reqs, headers := m.recorded()
			if len(reqs) != 2 || len(headers) != 2 {
				t.Fatalf("requests = %v (%d PUTs), want exactly two conditional PUTs", reqs, len(headers))
			}
			for i, req := range reqs {
				if req != "PUT "+key {
					t.Fatalf("post-race request %d = %q, want a conditional PUT", i, req)
				}
			}
		})
	}
}

// TestS3MockPutBarrierUnblocksOnCancel pins the barrier's escape hatches: a
// handler parked at the barrier must end when its request context or the
// shared test context is cancelled, without committing the PUT and without
// leaving a writer goroutine behind.
func TestS3MockPutBarrierUnblocksOnCancel(t *testing.T) {
	const key = testS3Prefix + "/atomic"
	cases := []struct {
		name        string
		cancelWhich string // "request" or "test"
	}{
		{name: "request_context", cancelWhich: "request"},
		{name: "test_context", cancelWhich: "test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newS3Mock(t)
			m.reset()
			barrier := newPutBarrier(1)
			m.setPutPreflight(barrier.wait)
			b := newMockBackend(t, m)

			testCtx, cancelTest := context.WithCancel(context.Background())
			reqCtx, cancelReq := context.WithCancel(testCtx)
			run := startWriters([]func() error{func() error {
				return b.CreateIfAbsent(reqCtx, "atomic", []byte("cancelled"))
			}})
			t.Cleanup(func() {
				cancelTest()
				cancelReq()
				barrier.releaseAll()
				run.drain()
			})

			// Wait for the handler to park without reading its result, so the
			// result channel still holds it for the assertions below.
			select {
			case <-barrier.arrived:
			case res := <-run.results:
				run.take(res)
				t.Fatalf("writer returned before reaching the barrier: %v", res.err)
			case <-testCtx.Done():
				t.Fatal("test context ended before the handler reached the barrier")
			}

			if tc.cancelWhich == "request" {
				cancelReq()
			} else {
				cancelTest()
			}

			select {
			case res := <-run.results:
				run.take(res)
				if res.err == nil {
					t.Fatal("cancelled conditional PUT reported success")
				}
			case <-time.After(10 * time.Second):
				t.Fatal(run.stop(cancelTest, barrier, "writer did not return after cancellation", context.DeadlineExceeded))
			}
			// drain waits for the writer goroutine itself, not just its result.
			run.drain()
			if _, _, ok := m.get(key); ok {
				t.Fatal("cancelled conditional PUT committed an object")
			}
		})
	}
}

// TestS3MockPutBarrierReleasedWriterDeadline covers a writer that stalls after
// the barrier released it: the complete-race deadline must end the race, and
// the typed failure must be returned only after that writer was cancelled and
// reaped. Channels make the stall deterministic; the test signal replaces a
// real deadline without waiting for one.
func TestS3MockPutBarrierReleasedWriterDeadline(t *testing.T) {
	barrier := newPutBarrier(1)
	raceCtx, endRace := context.WithCancel(context.Background())
	defer endRace()

	var running atomic.Int32
	parked := make(chan struct{})
	ops := []func() error{
		func() error { return nil },
		func() error {
			running.Add(1)
			defer running.Add(-1)
			// Released by the barrier, this writer stays inside the request
			// until the complete-race deadline ends.
			close(parked)
			<-raceCtx.Done()
			return raceCtx.Err()
		},
	}
	run := startWriters(ops)
	<-parked
	endRace()

	if run.complete(raceCtx) {
		t.Fatal("complete reported success after the complete-race deadline ended")
	}
	fail := run.stop(endRace, barrier, "complete-race deadline ended before every released writer returned", raceCtx.Err())
	var typed *putBarrierFailure
	if !errors.As(fail, &typed) {
		t.Fatalf("failure is %T, want *putBarrierFailure", fail)
	}
	if !errors.Is(fail, context.Canceled) {
		t.Fatalf("failure cause = %v, want context.Canceled", fail.err)
	}
	if typed.want != len(ops) {
		t.Fatalf("failure counted %d writers, want %d", typed.want, len(ops))
	}
	if !run.reaped {
		t.Fatal("typed failure returned before every writer goroutine exited")
	}
	if got := running.Load(); got != 0 {
		t.Fatalf("%d writer goroutine(s) still running when the typed failure was returned", got)
	}
	if run.pending != 0 {
		t.Fatalf("%d writer result(s) not drained when the typed failure was returned", run.pending)
	}
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

// TestS3DeniedContextErrorsRemainDiscoverable pins the caller-context denial
// shape: every S3 path that observes a caller's own context error returns
// ErrDenied while keeping that cause in the error chain, so
// errors.Is(err, context.DeadlineExceeded) still holds. The denial happens
// before any request, so none of the calls reaches the service.
func TestS3DeniedContextErrorsRemainDiscoverable(t *testing.T) {
	m := newS3Mock(t)
	var hits atomic.Int32
	m.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		hits.Add(1)
		return true
	})
	b := newMockBackend(t, m)
	m.seed(testS3Prefix+"/vault.db", []byte("committed"))

	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("pre-expired context err = %v, want context.DeadlineExceeded", ctx.Err())
	}

	calls := []struct {
		name string
		call func() error
	}{
		{"CreateIfAbsent", func() error { return b.CreateIfAbsent(ctx, "new", []byte("v")) }},
		{"Read", func() error {
			_, err := b.Read(ctx, "vault.db")
			return err
		}},
		{"ReplaceIfVersion", func() error {
			return b.ReplaceIfVersion(ctx, "vault.db", Revision(`"etag"`), []byte("v2"))
		}},
		{"List", func() error {
			_, err := b.List(ctx)
			return err
		}},
	}
	for _, c := range calls {
		err := c.call()
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s = %v, want ErrDenied", c.name, err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s = %v, want errors.Is(err, context.DeadlineExceeded)", c.name, err)
		}
		if errors.Is(err, ErrUnknown) {
			t.Errorf("%s = %v, must not also report ErrUnknown", c.name, err)
		}
	}

	// mapS3ReadError's caller-context branch keeps the cause too, for a Get
	// that failed while the caller's context was already expired.
	if err := mapS3ReadError(ctx, errors.New("transport failure")); !errors.Is(err, ErrDenied) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("mapS3ReadError = %v, want ErrDenied wrapping context.DeadlineExceeded", err)
	}

	reqs, _ := m.recorded()
	if hits.Load() != 0 || len(reqs) != 0 {
		t.Fatalf("expired-context calls reached the service: %v", reqs)
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

// TestS3RejectedCertificateIsDenied pins the handshake outcome: the mock's
// self-signed certificate is not trusted by the default HTTP client, so the
// TLS handshake fails before any request byte is written. The mutation
// therefore certainly did not reach the service and is ErrDenied, not
// ErrUnknown.
func TestS3RejectedCertificateIsDenied(t *testing.T) {
	m := newS3Mock(t)
	var hits atomic.Int32
	m.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		hits.Add(1)
		return true
	})
	// No HTTPClient: the SDK's default client rejects the mock's certificate.
	b, err := NewS3(S3Config{
		Endpoint:    m.endpoint(),
		Region:      testS3Region,
		Bucket:      testS3Bucket,
		Prefix:      testS3Prefix,
		Credentials: staticProvider(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = b.CreateIfAbsent(ctx, "x", []byte("v"))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("rejected certificate create = %v, want ErrDenied", err)
	}
	reqs, _ := m.recorded()
	if hits.Load() != 0 || len(reqs) != 0 {
		t.Fatalf("rejected certificate reached the service: %v", reqs)
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
	// ',' is etagc (RFC 9110 §8.8.3): an opaque tag may contain it, and it
	// must not be mistaken for the list separator, which only ever sits
	// outside the quotes.
	{`"a,b"`, true},
	{`"provider,opaque"`, true},
	{`","`, true},
	{``, false},
	{`abc`, false},
	{`"abc`, false},
	{`abc"`, false},
	// Real lists have a DQUOTE inside the value (or after the closing one).
	{`"a","b"`, false},
	{`"a", "b"`, false},
	{`"a,b","c"`, false},
	{`"abc",`, false},
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
	// A non-matching ETag conflicts too. Only "nope" and "a-b" are strong
	// quoted tags, so only they reach the service, each as exactly one
	// conditional PUT that it refuses. Extra quotes and a weak prefix are not
	// strong tags and are rejected locally without a request.
	for _, wrong := range []Revision{`"nope"`, `"a-b"`, Revision(`"` + etag + `"`), Revision("W/" + etag), Revision("w/" + etag)} {
		if err := b.ReplaceIfVersion(ctx, "vault.db", wrong, []byte("v2")); !errors.Is(err, ErrConflict) {
			t.Fatalf("replace with expected %q = %v, want ErrConflict", wrong, err)
		}
	}
	reqs, headers := m.recorded()
	if len(reqs) != 2 {
		t.Fatalf("requests = %v, want two PUTs, one per well-formed non-matching expected, and none for the rest", reqs)
	}
	for i, r := range reqs {
		if r != "PUT vault/vault.db" {
			t.Fatalf("unexpected request %q, want only conditional PUTs", r)
		}
		if im := headers[i].Get("If-Match"); im != `"nope"` && im != `"a-b"` {
			t.Fatalf("PUT If-Match = %q, want the non-matching expected ETag", im)
		}
		if headers[i].Get("If-None-Match") != "" {
			t.Fatalf("PUT If-None-Match = %q, want an If-Match conditional PUT only", headers[i].Get("If-None-Match"))
		}
	}
	if body, _, _ := m.get(key); string(body) != "committed" {
		t.Fatalf("rejected replace changed stored bytes: %q", body)
	}
	// The zero Revision stays malformed, not a conflict, and is resolved
	// locally: the recording is cleared first so that is observable.
	m.reset()
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
	// A legal quoted ETag is returned unmodified, quotes and all, including
	// an opaque value containing ','.
	for _, legal := range []string{`"a-b-c"`, `"a,b"`} {
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

// TestS3ReadThenReplaceOpaqueCommaETag: a provider ETag that is one strong tag
// whose opaque value contains ',' is a valid revision. It round-trips
// verbatim from Read into ReplaceIfVersion, which sends exactly one
// conditional PUT carrying it byte for byte as If-Match, with no
// unconditional request.
func TestS3ReadThenReplaceOpaqueCommaETag(t *testing.T) {
	const etag = `"provider,opaque"`
	m := newS3Mock(t)
	key := testS3Prefix + "/vault.db"
	body := []byte("complete encrypted payload")
	m.seed(key, body)
	m.mu.Lock()
	m.etags[key] = etag
	m.mu.Unlock()
	b := newMockBackend(t, m)
	ctx := context.Background()
	m.reset()

	res, err := b.Read(ctx, "vault.db")
	if err != nil {
		t.Fatalf("read with ETag %q: %v", etag, err)
	}
	if string(res.Revision) != etag {
		t.Fatalf("revision = %q, want verbatim %q", res.Revision, etag)
	}
	if string(res.Bytes) != string(body) {
		t.Fatalf("bytes = %q, want %q", res.Bytes, body)
	}

	if err := b.ReplaceIfVersion(ctx, "vault.db", res.Revision, []byte("v2")); err != nil {
		t.Fatalf("replace with revision %q: %v", res.Revision, err)
	}
	// The mock records the requests and, separately, a header snapshot for
	// each PUT only. Two requests with one recorded PUT means the sole write
	// is the conditional one.
	reqs, puts := m.recorded()
	if len(reqs) != 2 || len(puts) != 1 {
		t.Fatalf("requests = %v (%d PUTs), want exactly one GET and one conditional PUT", reqs, len(puts))
	}
	if reqs[0] != "GET vault/vault.db" {
		t.Fatalf("first request = %q, want the GET", reqs[0])
	}
	if reqs[1] != "PUT vault/vault.db" {
		t.Fatalf("second request = %q, want one conditional PUT; no unconditional or HEAD request allowed", reqs[1])
	}
	put := puts[0]
	if got := put.Get("If-Match"); got != etag {
		t.Fatalf("If-Match = %q, want %q verbatim", got, etag)
	}
	if got := put.Get("If-None-Match"); got != "" {
		t.Fatalf("If-None-Match = %q, want only an If-Match conditional PUT", got)
	}
	if got, _, _ := m.get(key); string(got) != "v2" {
		t.Fatalf("stored bytes = %q, want %q", got, "v2")
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

// TestS3Read404DistinguishesMissingBucket: only NoSuchKey, or a 404 without
// an S3 code, means the requested name has no version; NoSuchBucket (and any
// other explicit 404 code) is a configuration error, never ErrNotFound.
func TestS3Read404DistinguishesConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		hook func(w http.ResponseWriter, r *http.Request) bool
		want error
	}{
		{"no_such_key", func(w http.ResponseWriter, r *http.Request) bool {
			s3ErrorResponse(w, 404, "NoSuchKey")
			return true
		}, ErrNotFound},
		{"bare_404", func(w http.ResponseWriter, r *http.Request) bool {
			w.WriteHeader(404)
			return true
		}, ErrNotFound},
		{"no_such_bucket", func(w http.ResponseWriter, r *http.Request) bool {
			s3ErrorResponse(w, 404, "NoSuchBucket")
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
			m.seed(testS3Prefix+"/vault.db", []byte("committed"))
			b := newMockBackend(t, m)
			m.setHook(tc.hook)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err := b.Read(ctx, "vault.db")
			if !errors.Is(err, tc.want) {
				t.Fatalf("read on 404 %s = %v, want %v", tc.name, err, tc.want)
			}
			if tc.want == ErrNotFound && errors.Is(err, ErrDenied) {
				t.Fatalf("read on 404 %s = %v, must not also be ErrDenied", tc.name, err)
			}
			if tc.want == ErrDenied && errors.Is(err, ErrNotFound) {
				t.Fatalf("read on 404 %s = %v, must not also be ErrNotFound", tc.name, err)
			}
			if reqs, puts := m.recorded(); len(reqs) != 1 || reqs[0] != "GET vault/vault.db" || len(puts) != 0 {
				t.Fatalf("requests = %v, PUT headers = %d, want exactly one GET and no write", reqs, len(puts))
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
