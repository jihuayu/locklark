package onedrivegraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	testDriveID            = "synthetic-drive-0001"
	testItemID             = "synthetic-item-0001"
	testETag               = `"synthetic,etag:0001"`
	testToken              = "synthetic-access-token-0001"
	testLocationSecret     = "synthetic-sensitive-download-path"
	testProviderBodySecret = "synthetic-provider-body-secret"
)

type testTokenSource struct {
	mu    sync.Mutex
	token string
	err   error
	calls int
}

func (s *testTokenSource) AccessToken(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.token, s.err
}

func (s *testTokenSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type blockingTokenSource struct {
	started chan struct{}
	once    sync.Once
}

func (s *blockingTokenSource) AccessToken(ctx context.Context) (string, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return "", ctx.Err()
}

type fixtureRequest struct {
	method        string
	path          string
	query         string
	authorization string
}

type fixtureConfig struct {
	itemID string
	etag   string
	size   int64
	file   bool

	content []byte

	metadataJSON      []byte
	metadataStatus    int
	metadataErrorBody string

	contentStatus    int
	contentErrorBody string

	location      string
	locationSet   bool
	locationCount int

	downloadStatus    int
	downloadErrorBody string
	downloadBody      []byte
	downloadLength    int64
	downloadChunked   bool
}

type graphFixture struct {
	t      *testing.T
	server *httptest.Server

	mu sync.Mutex
	// cfg and the hooks are read under mu by the server goroutine.
	cfg          fixtureConfig
	metadataHook func(call int, w http.ResponseWriter, r *http.Request) bool
	contentHook  func(w http.ResponseWriter, r *http.Request) bool
	downloadHook func(w http.ResponseWriter, r *http.Request) bool

	metadataCalls int
	requests      []fixtureRequest
}

func newGraphFixture(t *testing.T) *graphFixture {
	t.Helper()
	content := []byte("synthetic encrypted vault file body")
	f := &graphFixture{
		t: t,
		cfg: fixtureConfig{
			itemID:         testItemID,
			etag:           testETag,
			size:           int64(len(content)),
			file:           true,
			content:        content,
			metadataStatus: http.StatusOK,
			contentStatus:  http.StatusFound,
			locationCount:  1,
			downloadStatus: http.StatusOK,
			downloadLength: -1,
		},
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *graphFixture) setConfig(mutate func(*fixtureConfig)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate(&f.cfg)
}

func (f *graphFixture) config() fixtureConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

func (f *graphFixture) setMetadataHook(hook func(int, http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metadataHook = hook
}

func (f *graphFixture) setContentHook(hook func(http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contentHook = hook
}

func (f *graphFixture) setDownloadHook(hook func(http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downloadHook = hook
}

func (f *graphFixture) recordedRequests() []fixtureRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fixtureRequest(nil), f.requests...)
}

func (f *graphFixture) reader(t *testing.T, tokens AccessTokenSource) *Reader {
	t.Helper()
	if tokens == nil {
		tokens = &testTokenSource{token: testToken}
	}
	endpoint, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	r, err := newReader(ReaderConfig{
		DriveID: testDriveID,
		ItemID:  testItemID,
		Tokens:  tokens,
	}, endpoint, f.server.Client())
	if err != nil {
		t.Fatalf("newReader: %v", err)
	}
	return r
}

func testItemPath() string {
	return "/drives/" + url.PathEscape(testDriveID) + "/items/" + url.PathEscape(testItemID)
}

func (f *graphFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	cfg := f.cfg
	metadataHook := f.metadataHook
	contentHook := f.contentHook
	downloadHook := f.downloadHook
	itemPath := testItemPath()
	f.requests = append(f.requests, fixtureRequest{
		method:        r.Method,
		path:          r.URL.Path,
		query:         r.URL.RawQuery,
		authorization: r.Header.Get("Authorization"),
	})
	call := 0
	isMetadata := r.URL.Path == itemPath
	if isMetadata {
		f.metadataCalls++
		call = f.metadataCalls
	}
	f.mu.Unlock()

	if r.Method != http.MethodGet {
		f.t.Errorf("unexpected method %s", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch {
	case isMetadata:
		f.serveMetadata(w, r, cfg, metadataHook, call)
	case r.URL.Path == itemPath+"/content":
		f.serveContent(w, r, cfg, contentHook)
	case strings.HasPrefix(r.URL.Path, "/download/"):
		f.serveDownload(w, r, cfg, downloadHook)
	default:
		f.t.Errorf("unexpected request path %q", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *graphFixture) serveMetadata(w http.ResponseWriter, r *http.Request, cfg fixtureConfig, hook func(int, http.ResponseWriter, *http.Request) bool, call int) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
		f.t.Errorf("metadata request Authorization = redacted mismatch")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if got := r.URL.RawQuery; got != "$select="+graphMetadataSelect {
		f.t.Errorf("metadata query = %q, want the fixed select", got)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if hook != nil && hook(call, w, r) {
		return
	}
	if cfg.metadataStatus != http.StatusOK {
		w.WriteHeader(cfg.metadataStatus)
		_, _ = w.Write([]byte(cfg.metadataErrorBody))
		return
	}
	body := cfg.metadataJSON
	if body == nil {
		body = generatedMetadata(cfg)
	}
	writeJSONResponse(w, body)
}

func generatedMetadata(cfg fixtureConfig) []byte {
	m := map[string]any{
		"id":   cfg.itemID,
		"size": cfg.size,
	}
	if cfg.etag != "" {
		m["eTag"] = cfg.etag
	}
	if cfg.file {
		m["file"] = map[string]any{}
	}
	body, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return body
}

func writeJSONResponse(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (f *graphFixture) serveContent(w http.ResponseWriter, r *http.Request, cfg fixtureConfig, hook func(http.ResponseWriter, *http.Request) bool) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
		f.t.Errorf("content request Authorization = redacted mismatch")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if hook != nil && hook(w, r) {
		return
	}
	if cfg.contentStatus == http.StatusOK {
		writeBodyResponse(w, cfg.content, -1)
		return
	}
	if cfg.contentStatus != http.StatusFound {
		w.WriteHeader(cfg.contentStatus)
		_, _ = w.Write([]byte(cfg.contentErrorBody))
		return
	}
	location := cfg.location
	if !cfg.locationSet {
		location = f.server.URL + "/download/" + testLocationSecret
	}
	for i := 0; i < cfg.locationCount; i++ {
		w.Header().Add("Location", location)
	}
	w.WriteHeader(http.StatusFound)
}

func (f *graphFixture) serveDownload(w http.ResponseWriter, r *http.Request, cfg fixtureConfig, hook func(http.ResponseWriter, *http.Request) bool) {
	if got := r.Header.Get("Authorization"); got != "" {
		f.t.Errorf("download request carried an Authorization header")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if hook != nil && hook(w, r) {
		return
	}
	if cfg.downloadStatus != http.StatusOK {
		if cfg.downloadStatus >= 300 && cfg.downloadStatus < 400 && cfg.locationSet {
			w.Header().Set("Location", cfg.location)
		}
		w.WriteHeader(cfg.downloadStatus)
		_, _ = w.Write([]byte(cfg.downloadErrorBody))
		return
	}
	body := cfg.downloadBody
	if body == nil {
		body = cfg.content
	}
	if cfg.downloadChunked {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = w.Write(body)
		return
	}
	writeBodyResponse(w, body, cfg.downloadLength)
}

func writeBodyResponse(w http.ResponseWriter, body []byte, declared int64) {
	if declared >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(declared, 10))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func assertErrorIs(t *testing.T, err error, want ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error")
	}
	for _, target := range want {
		if !errors.Is(err, target) {
			t.Errorf("error %q does not match %v", err, target)
		}
	}
}

func assertNoSecrets(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error")
	}
	message := err.Error()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(message, secret) {
			t.Errorf("error message leaked sensitive text")
		}
	}
}

func TestNewReaderValidationAndFixedProductionEndpoint(t *testing.T) {
	tokens := &testTokenSource{token: testToken}
	good := ReaderConfig{DriveID: testDriveID, ItemID: testItemID, Tokens: tokens}
	r, err := NewReader(good)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.endpoint != nil || r.client != nil {
		t.Fatalf("production reader must not expose or set test seams")
	}
	raw, err := r.itemURL(true)
	if err != nil {
		t.Fatalf("itemURL: %v", err)
	}
	want := graphEndpoint + "/drives/" + testDriveID + "/items/" + testItemID + "?$select=" + graphMetadataSelect
	if raw != want {
		t.Fatalf("metadata URL = %q, want fixed production URL", raw)
	}

	bad := []ReaderConfig{
		{},
		{DriveID: testDriveID, ItemID: testItemID},
		{DriveID: "", ItemID: testItemID, Tokens: tokens},
		{DriveID: testDriveID, ItemID: "", Tokens: tokens},
		{DriveID: testDriveID + "\x00", ItemID: testItemID, Tokens: tokens},
	}
	for _, cfg := range bad {
		if _, err := NewReader(cfg); !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("NewReader(%+v) error = %v, want ErrDenied", cfg, err)
		}
	}

	endpoint, err := url.Parse("https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"http://example.test",
		"https://user:pass@example.test",
		"https://example.test/?query=1",
		"https://example.test/#fragment",
	} {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("parse %q: %v", target, err)
		}
		if _, err := newReader(good, u, nil); !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("newReader endpoint %q error = %v, want ErrDenied", target, err)
		}
	}
	if _, err := newReader(good, endpoint, nil); err != nil {
		t.Fatalf("valid injected endpoint rejected: %v", err)
	}
}

func TestReadSuccessPreservesExactETagAndOmitsAuthorizationOnDownload(t *testing.T) {
	f := newGraphFixture(t)
	f.setConfig(func(c *fixtureConfig) {
		c.content = []byte("synthetic encrypted vault file body")
		c.size = int64(len(c.content))
		c.etag = testETag
	})

	result, err := f.reader(t, nil).Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(result.Bytes) != "synthetic encrypted vault file body" {
		t.Fatalf("bytes = %q", result.Bytes)
	}
	if string(result.Revision) != testETag {
		t.Fatalf("Revision = %q, want exact opaque ETag %q", result.Revision, testETag)
	}

	requests := f.recordedRequests()
	if len(requests) != 4 {
		t.Fatalf("requests = %d, want metadata, content, download, metadata", len(requests))
	}
	wantPaths := []string{
		testItemPath(),
		testItemPath() + "/content",
		"/download/" + testLocationSecret,
		testItemPath(),
	}
	for i, wantPath := range wantPaths {
		if requests[i].path != wantPath {
			t.Errorf("request[%d].path = %q, want %q", i, requests[i].path, wantPath)
		}
	}
	for i, req := range requests {
		if i == 2 {
			if req.authorization != "" {
				t.Errorf("download request carried Authorization")
			}
			continue
		}
		if req.authorization != "Bearer "+testToken {
			t.Errorf("Graph request[%d] Authorization = redacted mismatch", i)
		}
	}
	for i, req := range requests {
		if i == 0 || i == 3 {
			if req.query != "$select="+graphMetadataSelect {
				t.Errorf("metadata request[%d] query = %q", i, req.query)
			}
		} else if req.query != "" {
			t.Errorf("non-metadata request[%d] had query %q", i, req.query)
		}
	}
}

func TestReadAcceptsDirectContentResponse(t *testing.T) {
	f := newGraphFixture(t)
	f.setConfig(func(c *fixtureConfig) {
		c.contentStatus = http.StatusOK
		c.content = []byte("direct synthetic body")
		c.size = int64(len(c.content))
	})
	result, err := f.reader(t, nil).Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(result.Bytes) != "direct synthetic body" || string(result.Revision) != testETag {
		t.Fatalf("result = %+v", result)
	}
}

func TestReadRejectsMetadataChangedDuringRead(t *testing.T) {
	base := newGraphFixture(t)
	baseCfg := base.config()
	cases := []struct {
		name string
		etag string
		size int64
	}{
		{name: "etag", etag: `"synthetic,etag-changed"`, size: baseCfg.size},
		{name: "size", etag: baseCfg.etag, size: baseCfg.size + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraphFixture(t)
			f.setMetadataHook(func(call int, w http.ResponseWriter, r *http.Request) bool {
				if call != 2 {
					return false
				}
				cfg := f.config()
				writeJSONResponse(w, generatedMetadata(fixtureConfig{
					itemID: cfg.itemID,
					etag:   tc.etag,
					size:   tc.size,
					file:   true,
				}))
				return true
			})
			_, err := f.reader(t, nil).Read(context.Background())
			assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
		})
	}
}

func TestReadRejectsInvalidMetadata(t *testing.T) {
	overlongJSON := []byte(fmt.Sprintf(
		`{"id":%q,"eTag":%q,"size":1,"file":{},"padding":"%s"}`,
		testItemID, testETag, strings.Repeat("a", maxMetadataJSONSize),
	))
	cases := []struct {
		name   string
		mutate func(*fixtureConfig)
		want   []error
	}{
		{
			name:   "missing file facet",
			mutate: func(c *fixtureConfig) { c.file = false },
			want:   []error{vaultfilebackend.ErrUnsupported, ErrInvalidMetadata},
		},
		{
			name:   "missing etag",
			mutate: func(c *fixtureConfig) { c.etag = "" },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name:   "mismatched id",
			mutate: func(c *fixtureConfig) { c.itemID = "synthetic-other-item" },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name: "missing size",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(fmt.Sprintf(`{"id":%q,"eTag":%q,"file":{}}`, testItemID, testETag))
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name:   "negative size",
			mutate: func(c *fixtureConfig) { c.size = -1 },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name:   "oversize size",
			mutate: func(c *fixtureConfig) { c.size = vaultfilebackend.MaxValueSize + 1 },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name:   "oversize etag",
			mutate: func(c *fixtureConfig) { c.etag = strings.Repeat("x", vaultfilebackend.MaxRevisionSize+1) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name:   "whitespace in etag",
			mutate: func(c *fixtureConfig) { c.etag = "bad etag" },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name: "control byte in etag",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(fmt.Sprintf(`{"id":%q,"eTag":"bad\u0000etag","size":1,"file":{}}`, testItemID))
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name:   "malformed json",
			mutate: func(c *fixtureConfig) { c.metadataJSON = []byte(`{"id":`) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
		{
			name:   "oversize json",
			mutate: func(c *fixtureConfig) { c.metadataJSON = overlongJSON },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidMetadata},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraphFixture(t)
			f.setConfig(tc.mutate)
			_, err := f.reader(t, nil).Read(context.Background())
			assertErrorIs(t, err, tc.want...)
			if got := contentRequestCount(f.recordedRequests()); got != 0 {
				t.Errorf("content requests = %d, want 0 for invalid metadata", got)
			}
		})
	}
}

func contentRequestCount(requests []fixtureRequest) int {
	count := 0
	for _, req := range requests {
		if strings.HasSuffix(req.path, "/content") {
			count++
		}
	}
	return count
}

func TestReadRejectsBodySizeProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fixtureConfig)
	}{
		{
			name: "declared length mismatch",
			mutate: func(c *fixtureConfig) {
				c.size = int64(len(c.content)) + 1
			},
		},
		{
			name: "truncated body",
			mutate: func(c *fixtureConfig) {
				c.downloadBody = append([]byte(nil), c.content[:len(c.content)/2]...)
				c.downloadLength = int64(len(c.content))
			},
		},
		{
			name: "oversize chunked body",
			mutate: func(c *fixtureConfig) {
				c.size = vaultfilebackend.MaxValueSize
				c.content = make([]byte, vaultfilebackend.MaxValueSize+1)
				c.downloadChunked = true
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraphFixture(t)
			f.setConfig(tc.mutate)
			_, err := f.reader(t, nil).Read(context.Background())
			assertErrorIs(t, err, vaultfilebackend.ErrCorrupt)
		})
	}
}

func TestReadRejectsNon200Statuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fixtureConfig)
		want   error
	}{
		{
			name:   "metadata 404",
			mutate: func(c *fixtureConfig) { c.metadataStatus = http.StatusNotFound },
			want:   vaultfilebackend.ErrNotFound,
		},
		{
			name:   "metadata 401",
			mutate: func(c *fixtureConfig) { c.metadataStatus = http.StatusUnauthorized },
			want:   vaultfilebackend.ErrDenied,
		},
		{
			name:   "metadata 429",
			mutate: func(c *fixtureConfig) { c.metadataStatus = http.StatusTooManyRequests },
			want:   vaultfilebackend.ErrUnknown,
		},
		{
			name:   "metadata 500",
			mutate: func(c *fixtureConfig) { c.metadataStatus = http.StatusInternalServerError },
			want:   vaultfilebackend.ErrUnknown,
		},
		{
			name:   "metadata 302",
			mutate: func(c *fixtureConfig) { c.metadataStatus = http.StatusFound },
			want:   vaultfilebackend.ErrUnknown,
		},
		{
			name:   "content 404",
			mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusNotFound },
			want:   vaultfilebackend.ErrNotFound,
		},
		{
			name:   "content 403",
			mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusForbidden },
			want:   vaultfilebackend.ErrDenied,
		},
		{
			name:   "content 429",
			mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusTooManyRequests },
			want:   vaultfilebackend.ErrUnknown,
		},
		{
			name:   "content 204",
			mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusNoContent },
			want:   vaultfilebackend.ErrUnknown,
		},
		{
			name:   "download 404",
			mutate: func(c *fixtureConfig) { c.downloadStatus = http.StatusNotFound },
			want:   vaultfilebackend.ErrNotFound,
		},
		{
			name:   "download 401",
			mutate: func(c *fixtureConfig) { c.downloadStatus = http.StatusUnauthorized },
			want:   vaultfilebackend.ErrDenied,
		},
		{
			name:   "download 500",
			mutate: func(c *fixtureConfig) { c.downloadStatus = http.StatusInternalServerError },
			want:   vaultfilebackend.ErrUnknown,
		},
		{
			name:   "download 204",
			mutate: func(c *fixtureConfig) { c.downloadStatus = http.StatusNoContent },
			want:   vaultfilebackend.ErrUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraphFixture(t)
			f.setConfig(func(c *fixtureConfig) {
				c.metadataErrorBody = testProviderBodySecret
				c.contentErrorBody = testProviderBodySecret
				c.downloadErrorBody = testProviderBodySecret
				tc.mutate(c)
			})
			_, err := f.reader(t, nil).Read(context.Background())
			assertErrorIs(t, err, tc.want)
			assertNoSecrets(t, err, testProviderBodySecret, testToken)
		})
	}
}

func TestReadRejectsUnsafeRedirectLocations(t *testing.T) {
	validLocation := func(f *graphFixture) string { return f.server.URL + "/download/" + testLocationSecret }
	cases := []struct {
		name     string
		location func(*graphFixture) string
		count    int
	}{
		{name: "relative", location: func(*graphFixture) string { return "/download/" + testLocationSecret }, count: 1},
		{name: "plain http", location: func(*graphFixture) string { return "http://example.test/" + testLocationSecret }, count: 1},
		{name: "userinfo", location: func(*graphFixture) string { return "https://user:pass@example.test/" + testLocationSecret }, count: 1},
		{name: "fragment", location: func(f *graphFixture) string { return validLocation(f) + "#fragment" }, count: 1},
		{name: "empty host", location: func(*graphFixture) string { return "https:///" + testLocationSecret }, count: 1},
		{name: "opaque", location: func(*graphFixture) string { return "https:example.test/" + testLocationSecret }, count: 1},
		{name: "empty", location: func(*graphFixture) string { return "" }, count: 1},
		{name: "whitespace", location: func(f *graphFixture) string { return validLocation(f) + " trailing" }, count: 1},
		{name: "oversize", location: func(*graphFixture) string {
			return "https://example.test/" + strings.Repeat("a", maxRedirectLocationSize)
		}, count: 1},
		{name: "multiple location headers", location: validLocation, count: 2},
		{name: "no location header", location: validLocation, count: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraphFixture(t)
			f.setConfig(func(c *fixtureConfig) {
				c.locationSet = true
				c.location = tc.location(f)
				c.locationCount = tc.count
			})
			_, err := f.reader(t, nil).Read(context.Background())
			assertErrorIs(t, err, ErrUnsafeRedirect, vaultfilebackend.ErrDenied)
			assertNoSecrets(t, err, testLocationSecret, "user:pass")
			if got := downloadRequestCount(f.recordedRequests()); got != 0 {
				t.Errorf("download requests = %d, want 0 for rejected Location", got)
			}
		})
	}
}

func TestReadRejectsFurtherRedirects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fixtureConfig)
		loop   bool
	}{
		{name: "content 301", mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusMovedPermanently }},
		{name: "content 303", mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusSeeOther }},
		{name: "content 307", mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusTemporaryRedirect }},
		{name: "content 308", mutate: func(c *fixtureConfig) { c.contentStatus = http.StatusPermanentRedirect }},
		{name: "download 302", mutate: func(c *fixtureConfig) { c.downloadStatus = http.StatusFound }, loop: true},
		{name: "download 301", mutate: func(c *fixtureConfig) { c.downloadStatus = http.StatusMovedPermanently }, loop: true},
		{name: "download 307", mutate: func(c *fixtureConfig) { c.downloadStatus = http.StatusTemporaryRedirect }, loop: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraphFixture(t)
			f.setConfig(func(c *fixtureConfig) {
				tc.mutate(c)
				if tc.loop {
					c.locationSet = true
					c.location = f.server.URL + "/download/" + testLocationSecret + "-loop"
				}
			})
			_, err := f.reader(t, nil).Read(context.Background())
			assertErrorIs(t, err, ErrUnsafeRedirect, vaultfilebackend.ErrDenied)
			wantDownloads := 0
			if tc.loop {
				wantDownloads = 1
			}
			if got := downloadRequestCount(f.recordedRequests()); got != wantDownloads {
				t.Errorf("download requests = %d, want %d", got, wantDownloads)
			}
		})
	}
}

func downloadRequestCount(requests []fixtureRequest) int {
	count := 0
	for _, req := range requests {
		if strings.HasPrefix(req.path, "/download/") {
			count++
		}
	}
	return count
}

func TestReadHonoursCancellation(t *testing.T) {
	t.Run("before token", func(t *testing.T) {
		f := newGraphFixture(t)
		source := &testTokenSource{token: testToken}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.reader(t, source).Read(ctx)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if source.callCount() != 0 {
			t.Errorf("token source calls = %d, want 0", source.callCount())
		}
		if got := len(f.recordedRequests()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("token source", func(t *testing.T) {
		f := newGraphFixture(t)
		source := &blockingTokenSource{started: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-source.started
			cancel()
		}()
		_, err := f.reader(t, source).Read(ctx)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if got := len(f.recordedRequests()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("content body", func(t *testing.T) {
		f := newGraphFixture(t)
		started := make(chan struct{})
		f.setContentHook(func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			close(started)
			<-r.Context().Done()
			return true
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			<-started
			cancel()
		}()
		_, err := f.reader(t, nil).Read(ctx)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
	})
}

func TestReadErrorsDoNotLeakSecrets(t *testing.T) {
	t.Run("token source error", func(t *testing.T) {
		f := newGraphFixture(t)
		source := &testTokenSource{
			token: testToken,
			err:   errors.New("token source included " + testToken),
		}
		_, err := f.reader(t, source).Read(context.Background())
		assertErrorIs(t, err, ErrAccessToken, vaultfilebackend.ErrDenied)
		assertNoSecrets(t, err, testToken)
	})

	t.Run("invalid token", func(t *testing.T) {
		f := newGraphFixture(t)
		source := &testTokenSource{token: "synthetic token with a space"}
		_, err := f.reader(t, source).Read(context.Background())
		assertErrorIs(t, err, ErrAccessToken, vaultfilebackend.ErrDenied)
		assertNoSecrets(t, err, "synthetic token with a space")
	})

	t.Run("metadata provider body", func(t *testing.T) {
		f := newGraphFixture(t)
		f.setConfig(func(c *fixtureConfig) {
			c.metadataStatus = http.StatusInternalServerError
			c.metadataErrorBody = testProviderBodySecret
		})
		_, err := f.reader(t, nil).Read(context.Background())
		assertNoSecrets(t, err, testProviderBodySecret, testToken)
	})

	t.Run("metadata malformed body", func(t *testing.T) {
		f := newGraphFixture(t)
		f.setConfig(func(c *fixtureConfig) {
			c.metadataJSON = []byte(`{"id":"` + testItemID + `","leak":"` + testProviderBodySecret + `"`)
		})
		_, err := f.reader(t, nil).Read(context.Background())
		assertErrorIs(t, err, ErrInvalidMetadata, vaultfilebackend.ErrCorrupt)
		assertNoSecrets(t, err, testProviderBodySecret, testToken)
	})

	t.Run("unsafe location", func(t *testing.T) {
		f := newGraphFixture(t)
		location := "http://example.test/" + testLocationSecret
		f.setConfig(func(c *fixtureConfig) {
			c.locationSet = true
			c.location = location
			c.locationCount = 1
		})
		_, err := f.reader(t, nil).Read(context.Background())
		assertErrorIs(t, err, ErrUnsafeRedirect)
		assertNoSecrets(t, err, location, testLocationSecret, testToken)
	})

	t.Run("download provider body", func(t *testing.T) {
		f := newGraphFixture(t)
		f.setConfig(func(c *fixtureConfig) {
			c.downloadStatus = http.StatusInternalServerError
			c.downloadErrorBody = testProviderBodySecret
		})
		_, err := f.reader(t, nil).Read(context.Background())
		assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
		assertNoSecrets(t, err, testProviderBodySecret, testLocationSecret, testToken)
	})

	t.Run("transport request URL", func(t *testing.T) {
		f := newGraphFixture(t)
		f.server.Close()
		_, err := f.reader(t, nil).Read(context.Background())
		assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
		assertNoSecrets(t, err, f.server.URL, testToken)
	})
}
