package onedrivegraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// These tests use only a loopback TLS server with synthetic IDs, tokens,
// ETags and capability URLs. No real account, tenant, credential store or
// configuration is read.

const (
	uploadDriveID        = "synthetic-upload-drive-0001"
	uploadItemID         = "synthetic-upload-item-0001"
	uploadETag           = `"synthetic-upload-etag,0001"`
	uploadToken          = "synthetic-upload-access-token-0001"
	uploadCapabilityPath = "synthetic-capability-path-secret"
	uploadProviderSecret = "synthetic-upload-provider-body-secret"
	uploadCapabilityHost = "synthetic-capability.up.1drv.com"
	uploadCapabilityURL  = "https://" + uploadCapabilityHost + "/upload/" + uploadCapabilityPath
)

type uploadFixtureRequest struct {
	method        string
	path          string
	query         string
	authorization string
	ifMatch       string
	contentType   string
	accept        string
	body          []byte
}

type uploadFixtureConfig struct {
	driveID       string
	driveType     string
	driveJSON     []byte
	driveStatus   int
	driveError    string
	driveLocation string

	sessionJSON     []byte
	sessionStatus   int
	sessionError    string
	sessionLocation string

	uploadURL  string
	expiration time.Time
}

type uploadFixture struct {
	t      *testing.T
	server *httptest.Server

	mu           sync.Mutex
	cfg          uploadFixtureConfig
	driveHook    func(http.ResponseWriter, *http.Request) bool
	sessionHook  func(http.ResponseWriter, *http.Request) bool
	driveCalls   int
	sessionCalls int
	requests     []uploadFixtureRequest
}

func newUploadFixture(t *testing.T) *uploadFixture {
	t.Helper()
	f := &uploadFixture{
		t: t,
		cfg: uploadFixtureConfig{
			driveID:       uploadDriveID,
			driveType:     "personal",
			driveStatus:   http.StatusOK,
			sessionStatus: http.StatusOK,
			uploadURL:     uploadCapabilityURL,
			expiration:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		},
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *uploadFixture) setConfig(mutate func(*uploadFixtureConfig)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate(&f.cfg)
}

func (f *uploadFixture) config() uploadFixtureConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

func (f *uploadFixture) setDriveHook(hook func(http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.driveHook = hook
}

func (f *uploadFixture) setSessionHook(hook func(http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessionHook = hook
}

func (f *uploadFixture) recordedRequests() []uploadFixtureRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uploadFixtureRequest(nil), f.requests...)
}

func (f *uploadFixture) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.driveCalls, f.sessionCalls
}

func (f *uploadFixture) uploader(t *testing.T, tokens AccessTokenSource) *ConditionalUploader {
	t.Helper()
	if tokens == nil {
		tokens = &testTokenSource{token: uploadToken}
	}
	endpoint, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	u, err := newConditionalUploader(ConditionalUploaderConfig{
		DriveID: uploadDriveID,
		ItemID:  uploadItemID,
		Tokens:  tokens,
	}, endpoint, f.server.Client())
	if err != nil {
		t.Fatalf("newConditionalUploader: %v", err)
	}
	return u
}

func uploadDrivePath() string {
	return "/drives/" + url.PathEscape(uploadDriveID)
}

func uploadSessionPath() string {
	return "/drives/" + url.PathEscape(uploadDriveID) + "/items/" + url.PathEscape(uploadItemID) + "/createUploadSession"
}

func (f *uploadFixture) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	record := uploadFixtureRequest{
		method:        r.Method,
		path:          r.URL.Path,
		query:         r.URL.RawQuery,
		authorization: r.Header.Get("Authorization"),
		ifMatch:       r.Header.Get("If-Match"),
		contentType:   r.Header.Get("Content-Type"),
		accept:        r.Header.Get("Accept"),
		body:          body,
	}

	f.mu.Lock()
	f.requests = append(f.requests, record)
	cfg := f.cfg
	driveHook := f.driveHook
	sessionHook := f.sessionHook
	f.mu.Unlock()

	if record.authorization != "Bearer "+uploadToken {
		f.t.Errorf("Graph request carried an unexpected Authorization header")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == uploadDrivePath():
		f.mu.Lock()
		f.driveCalls++
		f.mu.Unlock()
		if driveHook != nil && driveHook(w, r) {
			return
		}
		if cfg.driveStatus != http.StatusOK {
			if cfg.driveLocation != "" {
				w.Header().Set("Location", cfg.driveLocation)
			}
			w.WriteHeader(cfg.driveStatus)
			_, _ = w.Write([]byte(cfg.driveError))
			return
		}
		writeUploadJSON(w, uploadDriveResponse(cfg))
	case r.Method == http.MethodPost && r.URL.Path == uploadSessionPath():
		f.mu.Lock()
		f.sessionCalls++
		f.mu.Unlock()
		if sessionHook != nil && sessionHook(w, r) {
			return
		}
		if cfg.sessionStatus != http.StatusOK {
			if cfg.sessionLocation != "" {
				w.Header().Set("Location", cfg.sessionLocation)
			}
			w.WriteHeader(cfg.sessionStatus)
			_, _ = w.Write([]byte(cfg.sessionError))
			return
		}
		writeUploadJSON(w, uploadSessionResponse(cfg))
	default:
		f.t.Errorf("unexpected request %s %q", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func uploadDriveResponse(cfg uploadFixtureConfig) []byte {
	if cfg.driveJSON != nil {
		return cfg.driveJSON
	}
	body, err := json.Marshal(map[string]any{
		"@odata.context": "https://synthetic.test/$metadata#drive",
		"id":             cfg.driveID,
		"driveType":      cfg.driveType,
	})
	if err != nil {
		panic(err)
	}
	return body
}

func uploadSessionResponse(cfg uploadFixtureConfig) []byte {
	if cfg.sessionJSON != nil {
		return cfg.sessionJSON
	}
	body, err := json.Marshal(map[string]any{
		"@odata.context":     "https://synthetic.test/$metadata#uploadSession",
		"uploadUrl":          cfg.uploadURL,
		"expirationDateTime": cfg.expiration.Format(time.RFC3339),
	})
	if err != nil {
		panic(err)
	}
	return body
}

func writeUploadJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func assertUploadNoPost(t *testing.T, f *uploadFixture) {
	t.Helper()
	driveCalls, sessionCalls := f.counts()
	if sessionCalls != 0 {
		t.Errorf("session POST calls = %d, want 0", sessionCalls)
	}
	if driveCalls > 1 {
		t.Errorf("drive GET calls = %d, want at most 1", driveCalls)
	}
}

func TestConditionalUploaderBeginContract(t *testing.T) {
	f := newUploadFixture(t)
	tokens := &testTokenSource{token: uploadToken}
	session, err := f.uploader(t, tokens).Begin(context.Background(), uploadETag)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if session == nil {
		t.Fatal("Begin returned a nil session")
	}
	if session.driveID != uploadDriveID || session.itemID != uploadItemID || session.etag != uploadETag {
		t.Fatalf("session binding = %q/%q/%q, want exact drive/item/ETag", session.driveID, session.itemID, session.etag)
	}
	if session.uploadURL != uploadCapabilityURL {
		t.Fatalf("session upload URL was not stored byte-for-byte")
	}
	if !session.expiresAt.Equal(f.config().expiration) {
		t.Fatalf("session expiration = %v, want initial %v", session.expiresAt, f.config().expiration)
	}
	if tokens.callCount() != 1 {
		t.Fatalf("token source calls = %d, want exactly 1", tokens.callCount())
	}

	requests := f.recordedRequests()
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want exactly drive GET then session POST", len(requests))
	}
	driveReq, sessionReq := requests[0], requests[1]
	if driveReq.method != http.MethodGet || driveReq.path != uploadDrivePath() || driveReq.query != "$select="+graphDriveSelect {
		t.Errorf("drive request = %s %q?%q, want GET exactly /drives/{id}?$select=id,driveType", driveReq.method, driveReq.path, driveReq.query)
	}
	if driveReq.authorization != "Bearer "+uploadToken || driveReq.ifMatch != "" || driveReq.contentType != "" || len(driveReq.body) != 0 {
		t.Errorf("drive request carried unexpected headers or body")
	}
	if sessionReq.method != http.MethodPost || sessionReq.path != uploadSessionPath() || sessionReq.query != "" {
		t.Errorf("session request = %s %q?%q, want POST exactly /createUploadSession", sessionReq.method, sessionReq.path, sessionReq.query)
	}
	if sessionReq.authorization != "Bearer "+uploadToken {
		t.Errorf("session request Authorization mismatch")
	}
	if sessionReq.ifMatch != uploadETag {
		t.Errorf("If-Match = %q, want exact opaque ETag %q", sessionReq.ifMatch, uploadETag)
	}
	if sessionReq.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", sessionReq.contentType)
	}
	if string(sessionReq.body) != `{"deferCommit":true}` {
		t.Errorf("session body = %q, want exactly the deferred body", sessionReq.body)
	}
}

func TestConditionalUploaderBeginPreservesExactOpaqueETag(t *testing.T) {
	etags := []string{
		`"synthetic,etag:0001"`,
		`synthetic-etag-unquoted`,
		`W/"synthetic-weak,etag"`,
		`"synthetic,opaque;with=separators"`,
	}
	for index, etag := range etags {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			f := newUploadFixture(t)
			session, err := f.uploader(t, nil).Begin(context.Background(), etag)
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			if session.etag != etag {
				t.Fatalf("session ETag = %q, want exact %q", session.etag, etag)
			}
			requests := f.recordedRequests()
			if len(requests) != 2 {
				t.Fatalf("requests = %d, want 2", len(requests))
			}
			if requests[1].ifMatch != etag {
				t.Fatalf("If-Match = %q, want byte-for-byte %q", requests[1].ifMatch, etag)
			}
		})
	}
}

func TestConditionalUploaderBeginRejectsInvalidConfigurationAndPreflight(t *testing.T) {
	t.Run("configuration", func(t *testing.T) {
		tokens := &testTokenSource{token: uploadToken}
		overlong := strings.Repeat("a", maxItemIDSize+1)
		bad := []ConditionalUploaderConfig{
			{},
			{DriveID: uploadDriveID, ItemID: uploadItemID},
			{DriveID: "", ItemID: uploadItemID, Tokens: tokens},
			{DriveID: uploadDriveID, ItemID: "", Tokens: tokens},
			{DriveID: "bad drive", ItemID: uploadItemID, Tokens: tokens},
			{DriveID: "bad/drive", ItemID: uploadItemID, Tokens: tokens},
			{DriveID: "bad?drive", ItemID: uploadItemID, Tokens: tokens},
			{DriveID: "bad\x00drive", ItemID: uploadItemID, Tokens: tokens},
			{DriveID: overlong, ItemID: uploadItemID, Tokens: tokens},
			{DriveID: uploadDriveID, ItemID: "bad\nitem", Tokens: tokens},
		}
		for _, cfg := range bad {
			if _, err := NewConditionalUploader(cfg); !errors.Is(err, vaultfilebackend.ErrDenied) {
				t.Errorf("NewConditionalUploader(%+v) error = %v, want ErrDenied", cfg, err)
			}
		}
		if tokens.callCount() != 0 {
			t.Errorf("token source was called during configuration validation")
		}
	})

	t.Run("fixed production endpoint", func(t *testing.T) {
		u, err := NewConditionalUploader(ConditionalUploaderConfig{
			DriveID: uploadDriveID,
			ItemID:  uploadItemID,
			Tokens:  &testTokenSource{token: uploadToken},
		})
		if err != nil {
			t.Fatalf("NewConditionalUploader: %v", err)
		}
		if u.endpoint != nil || u.client != nil {
			t.Fatalf("production uploader must not set test-only seams")
		}
		raw, err := u.driveURL()
		if err != nil {
			t.Fatalf("driveURL: %v", err)
		}
		want := graphEndpoint + "/drives/" + uploadDriveID + "?$select=id,driveType"
		if raw != want {
			t.Fatalf("drive URL = %q, want %q", raw, want)
		}
		sessionRaw, err := u.sessionURL()
		if err != nil {
			t.Fatalf("sessionURL: %v", err)
		}
		wantSession := graphEndpoint + "/drives/" + uploadDriveID + "/items/" + uploadItemID + "/createUploadSession"
		if sessionRaw != wantSession {
			t.Fatalf("session URL = %q, want %q", sessionRaw, wantSession)
		}
	})

	t.Run("endpoint seam", func(t *testing.T) {
		cfg := ConditionalUploaderConfig{
			DriveID: uploadDriveID,
			ItemID:  uploadItemID,
			Tokens:  &testTokenSource{token: uploadToken},
		}
		for _, raw := range []string{
			"http://example.test",
			"https://user:pass@example.test",
			"https://example.test/?query=1",
			"https://example.test/#fragment",
		} {
			endpoint, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("parse %q: %v", raw, err)
			}
			if _, err := newConditionalUploader(cfg, endpoint, nil); !errors.Is(err, vaultfilebackend.ErrDenied) {
				t.Errorf("endpoint %q error = %v, want ErrDenied", raw, err)
			}
		}
	})

	t.Run("zero value uploader", func(t *testing.T) {
		var zero ConditionalUploader
		if _, err := zero.Begin(context.Background(), uploadETag); !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("zero-value Begin error = %v, want ErrDenied", err)
		}
		var nilUploader *ConditionalUploader
		if _, err := nilUploader.Begin(context.Background(), uploadETag); !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("nil Begin error = %v, want ErrDenied", err)
		}
	})

	t.Run("nil and canceled context", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			ctx  context.Context
		}{
			{name: "nil", ctx: nil},
			{name: "canceled", ctx: canceledContext()},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newUploadFixture(t)
				tokens := &testTokenSource{token: uploadToken}
				_, err := f.uploader(t, tokens).Begin(tc.ctx, uploadETag)
				assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
				if tokens.callCount() != 0 {
					t.Errorf("token source calls = %d, want 0", tokens.callCount())
				}
				if got := len(f.recordedRequests()); got != 0 {
					t.Errorf("requests = %d, want 0", got)
				}
			})
		}
	})

	t.Run("malformed ETag", func(t *testing.T) {
		bad := []string{
			"",
			" ",
			"bad etag",
			"bad\tetag",
			"bad\netag",
			"\x00",
			"\xff",
			strings.Repeat("x", vaultfilebackend.MaxRevisionSize+1),
		}
		for index, etag := range bad {
			t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
				f := newUploadFixture(t)
				tokens := &testTokenSource{token: uploadToken}
				_, err := f.uploader(t, tokens).Begin(context.Background(), etag)
				assertErrorIs(t, err, vaultfilebackend.ErrDenied)
				if tokens.callCount() != 0 {
					t.Errorf("token source calls = %d, want 0", tokens.callCount())
				}
				if got := len(f.recordedRequests()); got != 0 {
					t.Errorf("requests = %d, want 0", got)
				}
			})
		}
	})

	t.Run("token source failure is not retained", func(t *testing.T) {
		f := newUploadFixture(t)
		tokens := &testTokenSource{token: uploadToken, err: errors.New("source failure " + uploadToken)}
		_, err := f.uploader(t, tokens).Begin(context.Background(), uploadETag)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, ErrAccessToken)
		assertNoSecrets(t, err, uploadToken, "source failure")
		if tokens.callCount() != 1 {
			t.Errorf("token source calls = %d, want 1", tokens.callCount())
		}
		if got := len(f.recordedRequests()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		f := newUploadFixture(t)
		const invalid = "synthetic token with whitespace"
		tokens := &testTokenSource{token: invalid}
		_, err := f.uploader(t, tokens).Begin(context.Background(), uploadETag)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, ErrAccessToken)
		assertNoSecrets(t, err, invalid)
		if got := len(f.recordedRequests()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("canceled during token source", func(t *testing.T) {
		f := newUploadFixture(t)
		source := &blockingTokenSource{started: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-source.started
			cancel()
		}()
		_, err := f.uploader(t, source).Begin(ctx, uploadETag)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if got := len(f.recordedRequests()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("canceled after drive before session", func(t *testing.T) {
		f := newUploadFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.setDriveHook(func(w http.ResponseWriter, _ *http.Request) bool {
			cancel()
			writeUploadJSON(w, uploadDriveResponse(f.config()))
			return true
		})
		tokens := &testTokenSource{token: uploadToken}
		_, err := f.uploader(t, tokens).Begin(ctx, uploadETag)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if tokens.callCount() != 1 {
			t.Errorf("token source calls = %d, want 1", tokens.callCount())
		}
		if got := len(f.recordedRequests()); got != 1 {
			t.Errorf("requests = %d, want only the drive GET", got)
		}
		assertUploadNoPost(t, f)
	})
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestConditionalUploaderBeginRequiresPersonalDrive(t *testing.T) {
	cases := []struct {
		name      string
		driveType string
	}{
		{name: "business", driveType: "business"},
		{name: "document library", driveType: "documentLibrary"},
		{name: "unknown", driveType: "syntheticUnknown"},
		{name: "wrong case", driveType: "Personal"},
		{name: "empty", driveType: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadFixture(t)
			f.setConfig(func(c *uploadFixtureConfig) { c.driveType = tc.driveType })
			tokens := &testTokenSource{token: uploadToken}
			session, err := f.uploader(t, tokens).Begin(context.Background(), uploadETag)
			if session != nil {
				t.Fatalf("Begin returned a session for a non-personal drive")
			}
			assertErrorIs(t, err, vaultfilebackend.ErrUnsupported)
			if tokens.callCount() != 1 {
				t.Errorf("token source calls = %d, want 1", tokens.callCount())
			}
			assertUploadNoPost(t, f)
			if got := len(f.recordedRequests()); got != 1 {
				t.Errorf("requests = %d, want only the drive GET", got)
			}
		})
	}
}

func TestConditionalUploaderBeginRejectsMalformedDriveResponse(t *testing.T) {
	validID := uploadDriveID
	cases := []struct {
		name    string
		mutate  func(*uploadFixtureConfig)
		want    []error
		wantGet int
	}{
		{
			name:   "mismatched id",
			mutate: func(c *uploadFixtureConfig) { c.driveID = "synthetic-other-drive" },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name:   "missing id",
			mutate: func(c *uploadFixtureConfig) { c.driveJSON = []byte(`{"driveType":"personal"}`) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name:   "missing driveType",
			mutate: func(c *uploadFixtureConfig) { c.driveJSON = []byte(fmt.Sprintf(`{"id":%q}`, validID)) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name:   "null driveType",
			mutate: func(c *uploadFixtureConfig) { c.driveJSON = []byte(fmt.Sprintf(`{"id":%q,"driveType":null}`, validID)) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name:   "numeric driveType",
			mutate: func(c *uploadFixtureConfig) { c.driveJSON = []byte(fmt.Sprintf(`{"id":%q,"driveType":7}`, validID)) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name: "duplicate id",
			mutate: func(c *uploadFixtureConfig) {
				c.driveJSON = []byte(fmt.Sprintf(`{"id":%q,"id":%q,"driveType":"personal"}`, validID, validID))
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name:   "malformed json",
			mutate: func(c *uploadFixtureConfig) { c.driveJSON = []byte(`{"id":`) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name: "trailing data",
			mutate: func(c *uploadFixtureConfig) {
				c.driveJSON = []byte(fmt.Sprintf(`{"id":%q,"driveType":"personal"} {}`, validID))
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name:   "null body",
			mutate: func(c *uploadFixtureConfig) { c.driveJSON = []byte(`null`) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name:   "array body",
			mutate: func(c *uploadFixtureConfig) { c.driveJSON = []byte(`[]`) },
			want:   []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name: "invalid utf8",
			mutate: func(c *uploadFixtureConfig) {
				c.driveJSON = []byte(fmt.Sprintf(`{"id":%q,"driveType":"personal","pad":"`+"\xff"+`"}`, validID))
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
		{
			name: "oversize body",
			mutate: func(c *uploadFixtureConfig) {
				c.driveJSON = []byte(fmt.Sprintf(`{"id":%q,"driveType":"personal","pad":%q}`, validID, strings.Repeat("a", maxDriveJSONSize)))
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidDrive},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadFixture(t)
			f.setConfig(tc.mutate)
			_, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
			assertErrorIs(t, err, tc.want...)
			assertNoSecrets(t, err, uploadToken, uploadProviderSecret)
			assertUploadNoPost(t, f)
			if got := len(f.recordedRequests()); got != 1 {
				t.Errorf("requests = %d, want only the drive GET", got)
			}
		})
	}
}

func TestConditionalUploaderBeginMapsDriveStatuses(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		location string
		want     []error
	}{
		{name: "not found", status: http.StatusNotFound, want: []error{vaultfilebackend.ErrNotFound}},
		{name: "bad request", status: http.StatusBadRequest, want: []error{vaultfilebackend.ErrDenied}},
		{name: "unauthorized", status: http.StatusUnauthorized, want: []error{vaultfilebackend.ErrDenied}},
		{name: "forbidden", status: http.StatusForbidden, want: []error{vaultfilebackend.ErrDenied}},
		{name: "conflict", status: http.StatusConflict, want: []error{vaultfilebackend.ErrDenied}},
		{name: "timeout", status: http.StatusRequestTimeout, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "rate limited", status: http.StatusTooManyRequests, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "server error", status: http.StatusInternalServerError, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "unexpected success", status: http.StatusNoContent, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "redirect", status: http.StatusFound, location: "/synthetic-redirect-target", want: []error{ErrUnsafeRedirect, vaultfilebackend.ErrDenied}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadFixture(t)
			f.setConfig(func(c *uploadFixtureConfig) {
				c.driveStatus = tc.status
				c.driveLocation = tc.location
				c.driveError = uploadProviderSecret
			})
			_, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
			assertErrorIs(t, err, tc.want...)
			assertNoSecrets(t, err, uploadProviderSecret, uploadToken)
			assertUploadNoPost(t, f)
			if got := len(f.recordedRequests()); got != 1 {
				t.Errorf("requests = %d, want only the drive GET", got)
			}
		})
	}
}

func TestConditionalUploaderBeginMapsSessionStatuses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   []error
		not    []error
	}{
		{name: "precondition failed", status: http.StatusPreconditionFailed, want: []error{vaultfilebackend.ErrConflict}},
		{name: "generic conflict", status: http.StatusConflict, want: []error{vaultfilebackend.ErrDenied}, not: []error{vaultfilebackend.ErrConflict}},
		{name: "bad request", status: http.StatusBadRequest, want: []error{vaultfilebackend.ErrDenied}},
		{name: "unauthorized", status: http.StatusUnauthorized, want: []error{vaultfilebackend.ErrDenied}},
		{name: "forbidden", status: http.StatusForbidden, want: []error{vaultfilebackend.ErrDenied}},
		{name: "not found", status: http.StatusNotFound, want: []error{vaultfilebackend.ErrNotFound}},
		{name: "timeout", status: http.StatusRequestTimeout, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "rate limited", status: http.StatusTooManyRequests, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "server error", status: http.StatusInternalServerError, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "unexpected created", status: http.StatusCreated, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "unexpected no content", status: http.StatusNoContent, want: []error{vaultfilebackend.ErrUnknown}},
		{name: "redirect", status: http.StatusFound, want: []error{vaultfilebackend.ErrUnknown}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadFixture(t)
			f.setConfig(func(c *uploadFixtureConfig) {
				c.sessionStatus = tc.status
				c.sessionError = uploadProviderSecret
				c.sessionLocation = "/synthetic-session-redirect"
			})
			_, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
			assertErrorIs(t, err, tc.want...)
			for _, target := range tc.not {
				if errors.Is(err, target) {
					t.Errorf("error %q unexpectedly matches %v", err, target)
				}
			}
			assertNoSecrets(t, err, uploadProviderSecret, uploadToken)
			driveCalls, sessionCalls := f.counts()
			if driveCalls != 1 || sessionCalls != 1 {
				t.Errorf("drive/session calls = %d/%d, want exactly 1/1 (no retry)", driveCalls, sessionCalls)
			}
			if got := len(f.recordedRequests()); got != 2 {
				t.Errorf("requests = %d, want GET then POST with no redirect follow or retry", got)
			}
		})
	}
}

func TestConditionalUploaderBeginNeverFollowsOrRetries(t *testing.T) {
	t.Run("session redirect", func(t *testing.T) {
		f := newUploadFixture(t)
		f.setConfig(func(c *uploadFixtureConfig) {
			c.sessionStatus = http.StatusTemporaryRedirect
			c.sessionLocation = "/synthetic-followed-redirect"
		})
		_, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
		assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
		if len(f.recordedRequests()) != 2 {
			t.Fatalf("requests = %d, want GET then POST only", len(f.recordedRequests()))
		}
	})
	t.Run("session failure is not retried", func(t *testing.T) {
		f := newUploadFixture(t)
		f.setConfig(func(c *uploadFixtureConfig) {
			c.sessionStatus = http.StatusInternalServerError
		})
		_, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
		assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
		_, sessionCalls := f.counts()
		if sessionCalls != 1 {
			t.Errorf("session POST calls = %d, want exactly 1", sessionCalls)
		}
	})
}

type uploadPostFailingTransport struct {
	base     http.RoundTripper
	attempts int32
}

func (t *uploadPostFailingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		atomic.AddInt32(&t.attempts, 1)
		return nil, errors.New("synthetic transport failure for " + req.URL.String() + " token=" + uploadToken)
	}
	return t.base.RoundTrip(req)
}

func TestConditionalUploaderBeginPostTransportFailureIsUnknown(t *testing.T) {
	f := newUploadFixture(t)
	endpoint, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	transport := &uploadPostFailingTransport{base: f.server.Client().Transport}
	u, err := newConditionalUploader(ConditionalUploaderConfig{
		DriveID: uploadDriveID,
		ItemID:  uploadItemID,
		Tokens:  &testTokenSource{token: uploadToken},
	}, endpoint, &http.Client{Transport: transport})
	if err != nil {
		t.Fatalf("newConditionalUploader: %v", err)
	}
	_, err = u.Begin(context.Background(), uploadETag)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
	if errors.Is(err, vaultfilebackend.ErrDenied) || errors.Is(err, vaultfilebackend.ErrConflict) {
		t.Errorf("post-send transport failure was not mapped to a distinct unknown outcome: %v", err)
	}
	if got := atomic.LoadInt32(&transport.attempts); got != 1 {
		t.Errorf("POST attempts = %d, want exactly 1 and no retry", got)
	}
	assertNoSecrets(t, err, uploadToken, f.server.URL, uploadCapabilityURL, uploadCapabilityPath)
	if got := len(f.recordedRequests()); got != 1 {
		t.Errorf("server requests = %d, want only the drive GET", got)
	}
}

func TestConditionalUploaderBeginValidatesUploadURL(t *testing.T) {
	valid := []struct {
		name string
		url  string
	}{
		{name: "personal suffix", url: "https://synthetic.up.1drv.com/upload/" + uploadCapabilityPath},
		{name: "explicit 443", url: "https://synthetic.up.1drv.com:443/upload/" + uploadCapabilityPath},
		{name: "uppercase", url: "HTTPS://Synthetic.Up.1Drv.Com/upload/" + uploadCapabilityPath},
		{name: "multi label", url: "https://a.b.up.1drv.com/upload/" + uploadCapabilityPath},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadFixture(t)
			f.setConfig(func(c *uploadFixtureConfig) { c.uploadURL = tc.url })
			session, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			if session.uploadURL != tc.url {
				t.Fatalf("upload URL was not stored byte-for-byte")
			}
		})
	}

	invalid := []struct {
		name string
		url  string
	}{
		{name: "empty", url: ""},
		{name: "relative", url: "/upload/" + uploadCapabilityPath},
		{name: "plain http", url: "http://synthetic.up.1drv.com/upload/" + uploadCapabilityPath},
		{name: "arbitrary https host", url: "https://example.test/upload/" + uploadCapabilityPath},
		{name: "bare suffix", url: "https://up.1drv.com/upload/" + uploadCapabilityPath},
		{name: "suffix lookalike", url: "https://evilup.1drv.com/upload/" + uploadCapabilityPath},
		{name: "suffix as prefix", url: "https://synthetic.up.1drv.com.evil.test/upload/" + uploadCapabilityPath},
		{name: "trailing dot", url: "https://synthetic.up.1drv.com./upload/" + uploadCapabilityPath},
		{name: "ipv4", url: "https://127.0.0.1/upload/" + uploadCapabilityPath},
		{name: "ipv6", url: "https://[::1]/upload/" + uploadCapabilityPath},
		{name: "localhost", url: "https://localhost/upload/" + uploadCapabilityPath},
		{name: "userinfo", url: "https://user:pass@synthetic.up.1drv.com/upload/" + uploadCapabilityPath},
		{name: "fragment", url: "https://synthetic.up.1drv.com/upload/" + uploadCapabilityPath + "#fragment"},
		{name: "explicit non-default port", url: "https://synthetic.up.1drv.com:8443/upload/" + uploadCapabilityPath},
		{name: "port 80", url: "https://synthetic.up.1drv.com:80/upload/" + uploadCapabilityPath},
		{name: "empty port", url: "https://synthetic.up.1drv.com:/upload/" + uploadCapabilityPath},
		{name: "opaque", url: "https:synthetic.up.1drv.com/upload/" + uploadCapabilityPath},
		{name: "underscore label", url: "https://bad_host.up.1drv.com/upload/" + uploadCapabilityPath},
		{name: "whitespace", url: "https://synthetic.up.1drv.com/upload/" + uploadCapabilityPath + " trailing"},
		{name: "malformed", url: "://"},
		{name: "oversize", url: "https://synthetic.up.1drv.com/" + strings.Repeat("a", maxUploadURLSize)},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadFixture(t)
			f.setConfig(func(c *uploadFixtureConfig) { c.uploadURL = tc.url })
			tokens := &testTokenSource{token: uploadToken}
			session, err := f.uploader(t, tokens).Begin(context.Background(), uploadETag)
			if session != nil {
				t.Fatalf("Begin returned a session with an unsafe upload URL")
			}
			if tc.url == "" {
				assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrInvalidUploadSession)
			} else {
				assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrUnsafeUploadURL)
			}
			assertNoSecrets(t, err, tc.url, uploadCapabilityPath, uploadToken, "user:pass")
			if tokens.callCount() != 1 {
				t.Errorf("token source calls = %d, want 1", tokens.callCount())
			}
			_, sessionCalls := f.counts()
			if sessionCalls != 1 {
				t.Errorf("session POST calls = %d, want exactly 1", sessionCalls)
			}
		})
	}
}

func TestConditionalUploaderBeginRejectsInvalidSessionResponse(t *testing.T) {
	validURL, _ := json.Marshal(uploadCapabilityURL)
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	futureJSON, _ := json.Marshal(future.Format(time.RFC3339))
	past := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	pastJSON, _ := json.Marshal(past.Format(time.RFC3339))

	cases := []struct {
		name string
		body []byte
	}{
		{name: "empty", body: []byte(``)},
		{name: "null", body: []byte(`null`)},
		{name: "array", body: []byte(`[]`)},
		{name: "malformed", body: []byte(`{"uploadUrl":`)},
		{name: "missing uploadUrl", body: []byte(fmt.Sprintf(`{"expirationDateTime":%s}`, futureJSON))},
		{name: "null uploadUrl", body: []byte(fmt.Sprintf(`{"uploadUrl":null,"expirationDateTime":%s}`, futureJSON))},
		{name: "numeric uploadUrl", body: []byte(fmt.Sprintf(`{"uploadUrl":7,"expirationDateTime":%s}`, futureJSON))},
		{name: "missing expiration", body: []byte(fmt.Sprintf(`{"uploadUrl":%s}`, validURL))},
		{name: "null expiration", body: []byte(fmt.Sprintf(`{"uploadUrl":%s,"expirationDateTime":null}`, validURL))},
		{name: "malformed expiration", body: []byte(fmt.Sprintf(`{"uploadUrl":%s,"expirationDateTime":"tomorrow"}`, validURL))},
		{name: "past expiration", body: []byte(fmt.Sprintf(`{"uploadUrl":%s,"expirationDateTime":%s}`, validURL, pastJSON))},
		{name: "trailing data", body: []byte(fmt.Sprintf(`{"uploadUrl":%s,"expirationDateTime":%s} {}`, validURL, futureJSON))},
		{name: "duplicate uploadUrl", body: []byte(fmt.Sprintf(`{"uploadUrl":%s,"uploadUrl":%s,"expirationDateTime":%s}`, validURL, validURL, futureJSON))},
		{name: "invalid utf8", body: []byte(fmt.Sprintf(`{"uploadUrl":%s,"expirationDateTime":%s,"pad":"`+"\xff"+`"}`, validURL, futureJSON))},
		{name: "oversize", body: []byte(fmt.Sprintf(`{"uploadUrl":%s,"expirationDateTime":%s,"pad":%q}`, validURL, futureJSON, strings.Repeat("a", maxUploadSessionJSONSize)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUploadFixture(t)
			f.setConfig(func(c *uploadFixtureConfig) { c.sessionJSON = tc.body })
			session, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
			if session != nil {
				t.Fatalf("Begin returned a session for an invalid response")
			}
			assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrInvalidUploadSession)
			assertNoSecrets(t, err, uploadCapabilityURL, uploadCapabilityPath, uploadToken, uploadProviderSecret)
			_, sessionCalls := f.counts()
			if sessionCalls != 1 {
				t.Errorf("session POST calls = %d, want exactly 1", sessionCalls)
			}
		})
	}
}

func TestConditionalUploaderBeginRedactsCapabilityEverywhere(t *testing.T) {
	f := newUploadFixture(t)
	session, err := f.uploader(t, nil).Begin(context.Background(), uploadETag)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, formatted := range []string{
		fmt.Sprintf("%v", session),
		fmt.Sprintf("%+v", session),
		fmt.Sprintf("%#v", session),
		fmt.Sprintf("%s", session),
		fmt.Sprintf("%q", session),
		fmt.Sprintf("%p", session),
		fmt.Sprintf("%v", *session),
		fmt.Sprintf("%+v", *session),
		fmt.Sprintf("%#v", *session),
	} {
		if strings.Contains(formatted, uploadCapabilityPath) || strings.Contains(formatted, "up.1drv.com") {
			t.Errorf("formatted session exposed the upload capability")
		}
	}

	// The capability must not be reachable as an exported field or method.
	typ := reflect.TypeOf(UploadSession{})
	for i := 0; i < typ.NumField(); i++ {
		if field := typ.Field(i); field.PkgPath == "" {
			t.Errorf("UploadSession field %q is exported", field.Name)
		}
	}
	for i := 0; i < typ.NumMethod(); i++ {
		if method := typ.Method(i); method.Name != "Format" {
			t.Errorf("UploadSession has unexpected exported method %q", method.Name)
		}
	}

	// Unsafe URLs and provider responses are never echoed in errors.
	f2 := newUploadFixture(t)
	unsafe := "https://attacker.example/" + uploadCapabilityPath
	f2.setConfig(func(c *uploadFixtureConfig) { c.uploadURL = unsafe })
	_, err = f2.uploader(t, nil).Begin(context.Background(), uploadETag)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrUnsafeUploadURL)
	assertNoSecrets(t, err, unsafe, uploadCapabilityPath, uploadToken, uploadProviderSecret)

	f3 := newUploadFixture(t)
	f3.setConfig(func(c *uploadFixtureConfig) {
		c.sessionStatus = http.StatusInternalServerError
		c.sessionError = uploadProviderSecret
	})
	tokens := &testTokenSource{token: uploadToken, err: errors.New("token secret " + uploadToken)}
	_, err = f3.uploader(t, tokens).Begin(context.Background(), uploadETag)
	assertErrorIs(t, err, vaultfilebackend.ErrDenied, ErrAccessToken)
	assertNoSecrets(t, err, uploadToken, "token secret")
}
