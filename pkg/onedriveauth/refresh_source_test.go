package onedriveauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// Synthetic refresh-source values. Every one is an illustration, never a real
// credential, tenant, scope, label or peer; the markers let a leak check find
// them in errors and output.
const (
	sourceTestAccess      = "synthetic-source-access-5d1f-must-not-leak"
	sourceTestRefreshNew  = "synthetic-source-rotated-e7a2-must-not-leak"
	sourceTestBodyMark    = "synthetic-source-body-3b8c-must-not-leak"
	sourceTestStoreMarker = "synthetic-store-failure-9c4d-must-not-leak"
)

// logCapture records everything the package's standard logger writes.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// captureLog redirects the standard logger to a capture for the test and
// returns the text written so far. It restores the previous output and flags
// with t.Cleanup.
func captureLog(t *testing.T) func() string {
	t.Helper()
	c := &logCapture{}
	log.SetOutput(c)
	log.SetFlags(log.LstdFlags)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return func() string {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.buf.String()
	}
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// TestRefreshSourceRequestsStaySynthetic checks that the source config used by
// the tests carries no ambient value, that every request goes to a loopback
// peer, and that the source and the package logger write nothing.
func TestRefreshSourceRequestsStaySynthetic(t *testing.T) {
	logged := captureLog(t)
	for _, name := range []string{"ONEDRIVE_CLIENT_ID", "ONEDRIVE_TENANT", "ONEDRIVE_SCOPES", "ONEDRIVE_PROFILE", "LOCKLARK_ONEDRIVE_CLIENT_ID"} {
		if _, ok := os.LookupEnv(name); ok {
			t.Fatalf("a source test ran with %s set; tests must not read ambient configuration", name)
		}
	}
	cfg := sourceTestConfig()
	_, store := newSourceTestStore(t, cfg)
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
	})
	if !validEndpoint(p.url) || p.url.Hostname() != "127.0.0.1" || p.url.Scheme != "https" || p.url.Host == tokenHost {
		t.Fatalf("the synthetic peer is not a loopback HTTPS endpoint")
	}
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	if _, err := s.AccessToken(context.Background()); err != nil {
		t.Fatalf("the synthetic refresh failed")
	}
	s.Close()
	if got := logged(); got != "" {
		t.Fatalf("the package logged output")
	}
}

// sourceTestConfig is the caller's explicit configuration of one source.
func sourceTestConfig() RefreshSourceConfig {
	return RefreshSourceConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticTenant,
		Scopes:   []string{syntheticScopeA, syntheticScopeB},
		Profile:  []byte("synthetic profile"),
		Timeout:  5 * time.Second,
	}
}

// newSourceTestStore returns a fake in-memory credential store holding
// refreshTestOld under cfg's binding. The seed save is not counted.
func newSourceTestStore(t *testing.T, cfg RefreshSourceConfig) (*fakeSecrets, *RefreshTokenStore) {
	t.Helper()
	f := newFakeSecrets()
	if err := fakeStore(f).SaveRefreshToken(cfg.ClientID, cfg.Tenant, cfg.Profile, []byte(refreshTestOld)); err != nil {
		t.Fatalf("seeding the fake store failed")
	}
	f.sets, f.values = 0, nil
	f.keys = nil
	return f, fakeStore(f)
}

// errorAfterWriteSecrets is a fake store whose Set writes the new value and
// then fails, modeling a non-atomic backend that may have replaced the item
// even though the save was reported as failed.
type errorAfterWriteSecrets struct {
	*fakeSecrets
}

func (e *errorAfterWriteSecrets) Set(key string, value []byte) error {
	_ = e.fakeSecrets.Set(key, value)
	return errors.New(sourceTestStoreMarker)
}

// flakySecrets fails its first get with the synthetic store error and answers
// every later call as the embedded fake does.
type flakySecrets struct {
	*fakeSecrets
	mu    sync.Mutex
	fails int
}

func (f *flakySecrets) Get(key string) ([]byte, error) {
	f.mu.Lock()
	fail := f.fails
	f.fails++
	f.mu.Unlock()
	if fail == 0 {
		return nil, errors.New(sourceTestStoreMarker)
	}
	return f.fakeSecrets.Get(key)
}

// stored returns the refresh token the fake store holds for cfg's binding.
func stored(t *testing.T, f *fakeSecrets, cfg RefreshSourceConfig) (string, bool) {
	t.Helper()
	token, present, err := fakeStore(f).LoadRefreshToken(cfg.ClientID, cfg.Tenant, cfg.Profile)
	defer clear(token)
	if err != nil {
		t.Fatalf("reading the fake store failed")
	}
	return string(token), present
}

// jsonBody is a well-formed token answer with a fixed synthetic lifetime.
func jsonBody(access string, expiresIn int, refresh string) string {
	body := `{"token_type":"Bearer","access_token":"` + access + `","expires_in":` + fmt.Sprint(expiresIn)
	if refresh != "" {
		body += `,"refresh_token":"` + refresh + `"`
	}
	return body + `}`
}

// assertSourceFailure checks that a failed AccessToken returned no token and
// exactly the fixed sentinel text, and that the error carries no input, token,
// endpoint or store marker under any common format.
func assertSourceFailure(t *testing.T, token string, err, want error) {
	t.Helper()
	if token != "" {
		t.Fatalf("a failed AccessToken returned an access token")
	}
	if !errors.Is(err, want) {
		t.Fatalf("AccessToken returned the wrong sentinel (got %v, want %v)", err, want)
	}
	if err.Error() != want.Error() {
		t.Fatalf("AccessToken error text is not exactly the fixed sentinel text")
	}
	assertHidden(t, "AccessToken error", fmt.Sprintf("%v|%+v|%#v|%s|%q", err, err, err, err, err),
		syntheticClientID, syntheticTenant, syntheticScopeA, syntheticScopeB, "synthetic profile",
		refreshTestOld, refreshTestNew, sourceTestAccess, sourceTestRefreshNew, tokenTestAccess,
		sourceTestBodyMark, sourceTestStoreMarker, "login.microsoftonline.com",
		"refresh_token=", "invalid_grant", "client_secret")
}

// TestNewRefreshSourceValidatesBeforeStore checks every invalid configuration
// against a fake store that must not be touched at all.
func TestNewRefreshSourceValidatesBeforeStore(t *testing.T) {
	tooMany := make([]string, maxScopes+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("%s.%d", syntheticScopeA, i)
	}
	bad := func(mutate func(*RefreshSourceConfig)) RefreshSourceConfig {
		cfg := sourceTestConfig()
		mutate(&cfg)
		return cfg
	}
	cases := []struct {
		name string
		cfg  RefreshSourceConfig
	}{
		{"empty client ID", bad(func(c *RefreshSourceConfig) { c.ClientID = "" })},
		{"malformed client ID", bad(func(c *RefreshSourceConfig) { c.ClientID = "synthetic client id" })},
		{"empty tenant", bad(func(c *RefreshSourceConfig) { c.Tenant = "" })},
		{"tenant path escape", bad(func(c *RefreshSourceConfig) { c.Tenant = ".." })},
		{"nil scopes", bad(func(c *RefreshSourceConfig) { c.Scopes = nil })},
		{"empty scopes", bad(func(c *RefreshSourceConfig) { c.Scopes = []string{} })},
		{"empty scope entry", bad(func(c *RefreshSourceConfig) { c.Scopes = []string{syntheticScopeA, ""} })},
		{"scope with space", bad(func(c *RefreshSourceConfig) { c.Scopes = []string{syntheticScopeA + " " + syntheticScopeB} })},
		{"nil profile", bad(func(c *RefreshSourceConfig) { c.Profile = nil })},
		{"empty profile", bad(func(c *RefreshSourceConfig) { c.Profile = []byte{} })},
		{"profile control byte", bad(func(c *RefreshSourceConfig) { c.Profile = []byte("work\n") })},
		{"profile non-ASCII", bad(func(c *RefreshSourceConfig) { c.Profile = []byte("worké") })},
		{"profile too long", bad(func(c *RefreshSourceConfig) { c.Profile = []byte(strings.Repeat("p", MaxProfileLabelLen+1)) })},
		{"too many scopes", bad(func(c *RefreshSourceConfig) { c.Scopes = tooMany })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSecrets()
			s, err := newRefreshSource(tc.cfg, fakeStore(f))
			if s != nil {
				t.Fatalf("an invalid configuration created a source")
			}
			if !errors.Is(err, ErrRefreshSource) || err.Error() != ErrRefreshSource.Error() {
				t.Fatalf("an invalid configuration returned an unexpected error")
			}
			if f.sets+f.gets+f.dels != 0 {
				t.Fatalf("construction touched the store")
			}
			assertHidden(t, "constructor error", fmt.Sprintf("%v|%#v", err, err), tc.cfg.ClientID, tc.cfg.Tenant, string(tc.cfg.Profile))
		})
	}
	if _, err := newRefreshSource(sourceTestConfig(), nil); !errors.Is(err, ErrRefreshSource) {
		t.Fatalf("a nil store was accepted")
	}
}

// zSourceTest returns a throwaway buffer holding s. Test buffers the runtime
// frees may be marked as zeroed, so a cleared (rather than freed) buffer is
// what a test can observe.
func zSourceTest(value string) []byte {
	b := make([]byte, len(value)+1)
	copy(b, value)
	return b[:len(value)]
}

// TestRefreshSourceCopiesInputs checks that mutating the caller's config and
// slices after construction does not change the form the source sends.
func TestRefreshSourceCopiesInputs(t *testing.T) {
	cfg := sourceTestConfig()
	f, store := newSourceTestStore(t, cfg)
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
	})
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	defer s.Close()
	// The caller overwrites its own buffers; the source must still send its
	// copies.
	cfg.Scopes[0] = "mutated.scope"
	cfg.Scopes[1] = "mutated.scope.two"
	copy(cfg.Profile, zSourceTest("mutated-profile"))
	cfg.ClientID = "mutated-client"
	cfg.Tenant = "mutated.tenant"

	if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
		t.Fatalf("AccessToken failed after the caller mutated its config")
	}
	form := p.singleForm(t)
	if got := form.Get("scope"); got != syntheticScopeA+" "+syntheticScopeB {
		t.Fatalf("the refresh form does not carry the copied explicit scopes")
	}
	if got := form.Get("client_id"); got != syntheticClientID {
		t.Fatalf("the refresh form does not carry the copied client ID")
	}
	if got, present := stored(t, f, sourceTestConfig()); !present || got != refreshTestOld {
		t.Fatalf("the stored item moved after the caller mutated its config")
	}
	s.mu.Lock()
	for _, scope := range s.scopeSets {
		if string(scope) != syntheticScopeA && string(scope) != syntheticScopeB {
			s.mu.Unlock()
			t.Fatalf("the source did not keep its own copy of the explicit scopes")
		}
	}
	s.mu.Unlock()
}

// TestRefreshSourceCachesAndCoalesces checks the exact synthetic form, that
// concurrent first calls share one validated refresh, the cached in-memory
// token on later calls, and the successful persistence of a rotated token.
func TestRefreshSourceCachesAndCoalesces(t *testing.T) {
	cfg := sourceTestConfig()
	f, store := newSourceTestStore(t, cfg)
	release := make(chan struct{})
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, sourceTestRefreshNew))
	})
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}

	const callers = 8
	type outcome struct {
		token string
		err   error
	}
	// The leader starts the flight and is held at leaderGate, so the other
	// callers find the same flight instead of racing to start one.
	leaderGate := make(chan struct{})
	results := make(chan outcome, callers)
	go func() {
		<-leaderGate
		token, err := s.AccessToken(context.Background())
		results <- outcome{token, err}
	}()
	for range callers - 1 {
		go func() {
			token, err := s.AccessToken(context.Background())
			results <- outcome{token, err}
		}()
	}
	// The first request is held open, so a second flight would have to
	// arrive while it is in flight.
	waitFor(t, "the synthetic peer to receive one request", func() bool { return p.hits.Load() == 1 })
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("concurrent callers made %d requests before the refresh finished, want one", got)
	}
	// The other callers can attach only once the leader runs, so the leader
	// is released before they are awaited; the flight stays open until
	// every caller attached, so the test never depends on goroutine
	// scheduling and those callers are served from the cached token, never
	// from a second request.
	close(leaderGate)
	waitFor(t, "every caller to attach to the flight", func() bool { return sourceWaiters(s) == callers })
	close(release)
	for range callers {
		got := <-results
		if got.err != nil || got.token != sourceTestAccess {
			t.Fatalf("a coalesced caller did not receive the shared validated token")
		}
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("concurrent callers made %d requests, want exactly one", got)
	}
	form := p.singleForm(t)
	want := map[string]string{
		"client_id":     syntheticClientID,
		"scope":         syntheticScopeA + " " + syntheticScopeB,
		"grant_type":    "refresh_token",
		"refresh_token": refreshTestOld,
	}
	if len(form) != len(want) {
		t.Fatalf("refresh form has %d members, want exactly %d", len(form), len(want))
	}
	for key, value := range want {
		if form.Get(key) != value || len(form[key]) != 1 {
			t.Fatalf("refresh form member %q has an unexpected value", key)
		}
	}
	if got, present := stored(t, f, cfg); !present || got != sourceTestRefreshNew {
		t.Fatalf("the rotated refresh token was not persisted")
	}
	if f.sets != 1 || f.dels != 0 {
		t.Fatalf("a rotated token made %d saves and %d deletes, want one save and none", f.sets, f.dels)
	}
	if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
		t.Fatalf("a cached call did not return the in-memory token")
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("a cached call made a request (%d total), want none", got)
	}
	s.Close()
	assertSourceClosed(t, s, p)
}

// TestRefreshSourceOmittedReplacementKeepsOld checks that an answer without a
// refresh token persists nothing and keeps the stored old item.
func TestRefreshSourceOmittedReplacementKeepsOld(t *testing.T) {
	cfg := sourceTestConfig()
	f, store := newSourceTestStore(t, cfg)
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
	})
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
		t.Fatalf("a valid answer without a replacement refresh token failed")
	}
	if f.sets != 0 || f.dels != 0 {
		t.Fatalf("an omitted replacement touched the store (%d saves, %d deletes)", f.sets, f.dels)
	}
	if got, present := stored(t, f, cfg); !present || got != refreshTestOld {
		t.Fatalf("an omitted replacement did not keep the stored old refresh token")
	}
	s.Close()
}

// TestRefreshSourceFailuresKeepOldAndReturnNoAccess checks every refresh
// failure against the fake store: nothing saved or deleted, the old item kept,
// no token, exactly one post-send request and a fixed redacted error.
func TestRefreshSourceFailuresKeepOldAndReturnNoAccess(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"provider 400", http.StatusBadRequest, `{"error":"invalid_grant","error_description":"` + sourceTestBodyMark + `"}`, ErrRefreshStatus},
		{"provider 500", http.StatusInternalServerError, sourceTestBodyMark, ErrRefreshStatus},
		{"malformed JSON", http.StatusOK, `{"token_type":"Bearer","access_token":"` + sourceTestAccess + `"`, ErrRefreshResponse},
		{"missing access token", http.StatusOK, `{"token_type":"Bearer","expires_in":3600}`, ErrRefreshResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sourceTestConfig()
			f, store := newSourceTestStore(t, cfg)
			p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
			if err != nil {
				t.Fatalf("a valid configuration was rejected")
			}
			token, err := s.AccessToken(context.Background())
			assertSourceFailure(t, token, err, tc.want)
			if got := p.hits.Load(); got != 1 {
				t.Fatalf("a failed refresh made %d requests, want exactly one", got)
			}
			assertSourceStoreUntouched(t, f, cfg)
			s.Close()
		})
	}
}

// TestRefreshSourcePostSendFailureIsTerminal proves a failure after the
// request was sent is never sent again by a later AccessToken call in the same
// source, that the same fixed error is returned, and that the source stays
// closed even if a stored token looks usable.
func TestRefreshSourcePostSendFailureIsTerminal(t *testing.T) {
	a := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusBadRequest, `{"error":"invalid_grant","error_description":"`+sourceTestBodyMark+`"}`)
	})
	b := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
	})
	cfg := sourceTestConfig()
	_, store := newSourceTestStore(t, cfg)
	s, err := newRefreshSourceAt(cfg, store, a.url, a.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	_, first := s.AccessToken(context.Background())
	assertSourceFailure(t, "", first, ErrRefreshStatus)
	assertSourceTerminal(t, s, a, ErrRefreshStatus)

	// A different healthy peer cannot be reached either: the terminal state
	// is part of the source, not of the endpoint.
	s.mu.Lock()
	s.endpoint, s.client = b.url, b.srv.Client()
	s.mu.Unlock()
	token, err := s.AccessToken(context.Background())
	assertSourceFailure(t, token, err, ErrRefreshStatus)
	if got := a.hits.Load(); got != 1 {
		t.Fatalf("the failed refresh was sent %d times, want exactly one", got)
	}
	if got := b.hits.Load(); got != 0 {
		t.Fatalf("a terminal source contacted a second peer")
	}
	_, second := s.AccessToken(context.Background())
	if second != first {
		t.Fatalf("later calls did not return the same fixed terminal error")
	}
	s.Close()
}

// TestRefreshSourcePreCanceledContext makes no store or network operation: a
// context that is already done is answered before anything is read or sent.
func TestRefreshSourcePreCanceledContext(t *testing.T) {
	cfg := sourceTestConfig()
	f, store := newSourceTestStore(t, cfg)
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
	})
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	token, err := s.AccessToken(ctx)
	if token != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("a pre-canceled context did not return its own error")
	}
	if f.gets+f.sets+f.dels != 0 {
		t.Fatalf("a pre-canceled context touched the store")
	}
	if got := p.hits.Load(); got != 0 {
		t.Fatalf("a pre-canceled context made %d requests, want none", got)
	}
	if sourceWaiters(s) != 0 {
		t.Fatalf("a pre-canceled context started a refresh")
	}
	// The source itself is untouched: a later live call still succeeds.
	if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
		t.Fatalf("a pre-canceled call affected the source")
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("the source made %d requests, want exactly one", got)
	}
	s.Close()
}

// TestRefreshSourceTerminalCloseWipes uses real state only: a synthetic
// post-send failure makes the source unusable, and an explicit Close must still
// wipe it exactly once. The source-owned scope and label buffers, kept by
// reference for the check, are cleared, the client ID and tenant references are
// dropped and the state is closed and cleaned, while later AccessToken calls
// return the same fixed terminal error without another request. The terminal
// failure itself releases the source refresh context, so Close has nothing left
// to cancel.
func TestRefreshSourceTerminalCloseWipes(t *testing.T) {
	cfg := sourceTestConfig()
	f, store := newSourceTestStore(t, cfg)
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusBadRequest, `{"error":"invalid_grant","error_description":"`+sourceTestBodyMark+`"}`)
	})
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	scopes, label, sourceCtx := sourceBuffers(s), sourceLabel(s), sourceContext(s)
	if len(scopes) != len(cfg.Scopes) || string(label) != string(cfg.Profile) {
		t.Fatalf("the source does not own a copy of every scope and the profile label")
	}

	token, err := s.AccessToken(context.Background())
	assertSourceFailure(t, token, err, ErrRefreshStatus)
	retained := s.terminalError()
	if retained == nil || !errors.Is(retained, ErrRefreshStatus) {
		t.Fatalf("a post-send failure did not retain its fixed terminal error")
	}
	if sourceStateOf(s) != sourceUnusable {
		t.Fatalf("a post-send failure did not leave the source unusable")
	}
	if err := sourceCtx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("the terminal failure did not release the source refresh context")
	}
	if !bytes.Equal(label, cfg.Profile) || !scopesIntact(scopes, cfg.Scopes) {
		t.Fatalf("the terminal failure wiped the binding before Close")
	}
	assertSourceStoreUntouched(t, f, cfg)

	s.Close()
	for i, scope := range scopes {
		if !bytes.Equal(scope, make([]byte, len(scope))) {
			t.Fatalf("Close did not clear copied scope %d", i)
		}
	}
	if !bytes.Equal(label, make([]byte, len(label))) {
		t.Fatalf("Close did not clear the copied profile label")
	}
	if st := sourceStateOf(s); st != sourceClosed {
		t.Fatalf("Close did not leave the source closed (state %d)", st)
	}
	if !sourceCleaned(s) {
		t.Fatalf("Close did not mark the source cleaned")
	}
	s.mu.Lock()
	scopes, label = s.scopeSets, s.label
	clientID, tenant := s.clientID, s.tenant
	cancel := s.cancel
	s.mu.Unlock()
	if scopes != nil || label != nil {
		t.Fatalf("Close did not drop the source's own scope and label references")
	}
	if clientID != "" || tenant != "" {
		t.Fatalf("Close did not drop the client ID and tenant references")
	}
	if cancel != nil {
		t.Fatalf("Close did not release the source context cancel function")
	}

	// The retained terminal error wins over the ordinary close sentinel,
	// unchanged and without another request.
	before := p.hits.Load()
	for range 3 {
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrRefreshStatus)
		if err != retained {
			t.Fatalf("a closed terminal source returned a different error")
		}
	}
	if got := p.hits.Load(); got != before || got != 1 {
		t.Fatalf("a closed terminal source made %d requests, want exactly one total", got)
	}
	s.Close()
	assertSourceStoreUntouched(t, f, cfg)
}

// TestRefreshSourceFetchBindingSnapshot checks the one-critical-section
// binding: one call to binding returns the open source's client ID, tenant,
// scopes and a copy of the profile label, carrying no reference to the source's
// own buffers, so later cleanup cannot change it.
func TestRefreshSourceFetchBindingSnapshot(t *testing.T) {
	cfg := sourceTestConfig()
	_, store := newSourceTestStore(t, cfg)
	s, err := newRefreshSourceAt(cfg, store, nil, nil)
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	b, state := s.binding()
	defer clear(b.label)
	if state != sourceOpen {
		t.Fatalf("an open source did not report itself open")
	}
	if b.clientID != syntheticClientID || b.tenant != syntheticTenant {
		t.Fatalf("the binding does not carry the source's client ID and tenant")
	}
	if strings.Join(b.scopes, " ") != syntheticScopeA+" "+syntheticScopeB {
		t.Fatalf("the binding does not carry the explicit scopes exactly")
	}
	if string(b.label) != string(cfg.Profile) {
		t.Fatalf("the binding does not carry the profile label")
	}
	scopes, label := sourceBuffers(s), sourceLabel(s)
	if len(b.scopes) != len(scopes) || len(b.label) != len(label) {
		t.Fatalf("the binding and the source hold different field widths")
	}
	for i, scope := range b.scopes {
		if len(scope) != len(scopes[i]) || unsafePtr(scope) == unsafeBytesPtr(scopes[i]) {
			t.Fatalf("binding scope %d aliases the source's own buffer", i)
		}
	}
	if len(b.label) != 0 && unsafeBytesPtr(b.label) == unsafeBytesPtr(label) {
		t.Fatalf("the binding label aliases the source's own buffer")
	}

	// The source clears its own copies; the snapshot must be unchanged.
	s.Close()
	for i, scope := range scopes {
		if !bytes.Equal(scope, make([]byte, len(scope))) {
			t.Fatalf("Close did not clear the source's own scope %d", i)
		}
	}
	if !bytes.Equal(label, make([]byte, len(label))) {
		t.Fatalf("Close did not clear the source's own label")
	}
	if closed, after := s.binding(); after != sourceClosed || closed.clientID != "" || closed.tenant != "" || closed.scopes != nil || closed.label != nil {
		t.Fatalf("a closed source still hands out a binding")
	}
	if b.clientID != syntheticClientID || b.tenant != syntheticTenant || string(b.label) != string(cfg.Profile) {
		t.Fatalf("cleanup changed the binding snapshot")
	}
	if strings.Join(b.scopes, " ") != syntheticScopeA+" "+syntheticScopeB {
		t.Fatalf("cleanup changed the snapshot scopes")
	}
}

// TestRefreshSourceTransientStoreFailuresAreRetried checks that a store load
// failure or a missing item, for which no request was made, can be retried by a
// later call in the same source, unlike a post-send failure.
func TestRefreshSourceTransientStoreFailuresAreRetried(t *testing.T) {
	t.Run("load failure then success", func(t *testing.T) {
		cfg := sourceTestConfig()
		f := newFakeSecrets()
		if err := fakeStore(f).SaveRefreshToken(cfg.ClientID, cfg.Tenant, cfg.Profile, []byte(refreshTestOld)); err != nil {
			t.Fatalf("seeding the fake store failed")
		}
		flaky := &flakySecrets{fakeSecrets: f}
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
		})
		s, err := newRefreshSourceAt(cfg, &RefreshTokenStore{secrets: flaky}, p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrStoreUnsupported)
		if got := p.hits.Load(); got != 0 {
			t.Fatalf("a load failure made %d requests, want none", got)
		}
		if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
			t.Fatalf("a load failure was not retried by the next call")
		}
		if got := p.hits.Load(); got != 1 {
			t.Fatalf("the retried source made %d requests, want exactly one", got)
		}
		s.Close()
	})
	t.Run("missing item then present", func(t *testing.T) {
		cfg := sourceTestConfig()
		f := newFakeSecrets()
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
		})
		s, err := newRefreshSourceAt(cfg, fakeStore(f), p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrStoreNotFound)
		if err := fakeStore(f).SaveRefreshToken(cfg.ClientID, cfg.Tenant, cfg.Profile, []byte(refreshTestOld)); err != nil {
			t.Fatalf("enrolling the profile failed")
		}
		if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
			t.Fatalf("a missing item was not retried after enrollment")
		}
		if got := p.hits.Load(); got != 1 {
			t.Fatalf("the source made %d requests, want exactly one", got)
		}
		s.Close()
	})
}

// TestRefreshSourceTransportFailure checks the transport error and the
// post-send cancellation: one attempt, no retry, outcome unknown.
func TestRefreshSourceTransportFailure(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		cfg := sourceTestConfig()
		f, store := newSourceTestStore(t, cfg)
		tr := &refreshRoundTripper{}
		endpoint := &url.URL{Scheme: "https", Host: "token.invalid", Path: "/oauth2/v2.0/token"}
		s, err := newRefreshSourceAt(cfg, store, endpoint, &http.Client{Transport: tr})
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrRefreshOutcomeUnknown)
		if !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("a transport failure lost its base classification")
		}
		if got := tr.attempts.Load(); got != 1 {
			t.Fatalf("a transport failure made %d attempts, want exactly one", got)
		}
		assertSourceStoreUntouched(t, f, cfg)
		s.Close()
	})
	// A request cancelled while it is sent, by the source's own bound or by
	// Close, is outcome unknown: nothing is saved or deleted and no access
	// token is returned.
	t.Run("post-send cancel", func(t *testing.T) {
		cfg := sourceTestConfig()
		cfg.Timeout = 5 * time.Second
		f, store := newSourceTestStore(t, cfg)
		received := make(chan struct{})
		p := newTokenPeer(t, func(_ http.ResponseWriter, r *http.Request) {
			close(received)
			<-r.Context().Done()
		})
		s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		returned := make(chan error, 1)
		go func() {
			token, err := s.AccessToken(context.Background())
			if token != "" {
				t.Errorf("a cancelled refresh returned an access token")
			}
			returned <- err
		}()
		select {
		case <-received:
		case <-time.After(3 * time.Second):
			t.Fatalf("the synthetic peer did not receive the request")
		}
		s.Close()
		select {
		case err := <-returned:
			// Close cancelled a request that was already sent, so the
			// provider outcome is still unknown; that fact is kept and
			// not masked as a merely closed source.
			assertSourceFailure(t, "", err, ErrRefreshOutcomeUnknown)
			if errors.Is(err, ErrRefreshSource) {
				t.Fatalf("a post-send Close masked the unknown outcome as a closed source")
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("an in-flight refresh did not settle after Close")
		}
		if got := p.hits.Load(); got != 1 {
			t.Fatalf("a cancelled refresh made %d requests, want exactly one", got)
		}
		assertSourceStoreUntouched(t, f, cfg)
		// The source is closed, so later calls send nothing more.
		assertSourceClosed(t, s, p)
	})
}

// TestRefreshSourceStoreErrors checks that a failed save returns no access
// token and reports the possibly-unknown store state without claiming the old
// item is still stored, and that a load error or a missing item returns no
// token either.
func TestRefreshSourceStoreErrors(t *testing.T) {
	t.Run("save error before the write", func(t *testing.T) {
		cfg := sourceTestConfig()
		f, store := newSourceTestStore(t, cfg)
		f.setErr = func(string) error { return errors.New(sourceTestStoreMarker) }
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, sourceTestRefreshNew))
		})
		s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrSourceStoreUnknown)
		if !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("a save error does not say the store state is unknown")
		}
		if strings.Contains(err.Error(), "the old item was kept") {
			t.Fatalf("a save error claims the old item was kept")
		}
		if f.dels != 0 {
			t.Fatalf("a save error deleted the old item")
		}
		if got, present := stored(t, f, cfg); !present || got != refreshTestOld {
			t.Fatalf("a save that wrote nothing did not leave the old item")
		}
		assertSourceTerminal(t, s, p, ErrSourceStoreUnknown)
		s.Close()
	})
	t.Run("save error after the write", func(t *testing.T) {
		cfg := sourceTestConfig()
		f := &errorAfterWriteSecrets{fakeSecrets: newFakeSecrets()}
		if err := fakeStore(f.fakeSecrets).SaveRefreshToken(cfg.ClientID, cfg.Tenant, cfg.Profile, []byte(refreshTestOld)); err != nil {
			t.Fatalf("seeding the fake store failed")
		}
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, sourceTestRefreshNew))
		})
		s, err := newRefreshSourceAt(cfg, &RefreshTokenStore{secrets: f}, p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrSourceStoreUnknown)
		if strings.Contains(err.Error(), "the old item was kept") {
			t.Fatalf("a failed save claims the old item was kept")
		}
		if f.dels != 0 {
			t.Fatalf("a failed save deleted the item")
		}
		// The underlying store already holds the replacement, so the source
		// reports the unknown state instead of claiming the old value.
		if got, present := stored(t, f.fakeSecrets, cfg); !present || got != sourceTestRefreshNew {
			t.Fatalf("the error-after-write fake did not record the written replacement")
		}
		assertSourceTerminal(t, s, p, ErrSourceStoreUnknown)
		s.Close()
	})
	t.Run("missing item", func(t *testing.T) {
		cfg := sourceTestConfig()
		f := newFakeSecrets()
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
		})
		s, err := newRefreshSourceAt(cfg, fakeStore(f), p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrStoreNotFound)
		if got := p.hits.Load(); got != 0 {
			t.Fatalf("a missing item made %d requests, want none", got)
		}
		if f.sets != 0 || f.dels != 0 {
			t.Fatalf("a missing item touched the store (%d saves, %d deletes)", f.sets, f.dels)
		}
		s.Close()
	})
	t.Run("load error", func(t *testing.T) {
		cfg := sourceTestConfig()
		f := newFakeSecrets()
		f.getErr = func(string) error { return errors.New(sourceTestStoreMarker) }
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, ""))
		})
		s, err := newRefreshSourceAt(cfg, fakeStore(f), p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, ErrStoreUnsupported)
		if got := p.hits.Load(); got != 0 {
			t.Fatalf("a load error made %d requests, want none", got)
		}
		s.Close()
	})
}

// TestRefreshSourceCanceledWaiterDoesNotCancelLeader checks that a waiter
// canceled by its own context returns promptly with that context's error, that
// the leader's request is not cancelled, and that the result is cached for
// later callers with exactly one request.
func TestRefreshSourceCanceledWaiterDoesNotCancelLeader(t *testing.T) {
	cfg := sourceTestConfig()
	f, store := newSourceTestStore(t, cfg)
	received := make(chan struct{})
	release := make(chan struct{})
	p := newTokenPeer(t, func(w http.ResponseWriter, r *http.Request) {
		close(received)
		select {
		case <-release:
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 3600, sourceTestRefreshNew))
		case <-r.Context().Done():
		}
	})
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}

	leader := make(chan error, 1)
	go func() {
		token, err := s.AccessToken(context.Background())
		if err == nil && token != sourceTestAccess {
			err = fmt.Errorf("leader received an unexpected token")
		}
		leader <- err
	}()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatalf("the synthetic peer did not receive the leader's request")
	}

	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan error, 1)
	go func() {
		token, err := s.AccessToken(ctx)
		if token != "" {
			t.Errorf("a canceled waiter received an access token")
		}
		waiter <- err
	}()
	// The waiter must have joined the flight before it is canceled; the
	// leader's flight state proves it without a wall-clock wait.
	waitFor(t, "the canceled waiter to attach to the leader's flight", func() bool { return sourceWaiters(s) == 2 })
	cancel()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a canceled waiter did not return its context's error")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("a canceled waiter did not return promptly")
	}

	close(release)
	select {
	case err := <-leader:
		if err != nil {
			t.Fatalf("the leader's refresh failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("the canceled waiter cancelled the leader's request")
	}
	if got, present := stored(t, f, cfg); !present || got != sourceTestRefreshNew {
		t.Fatalf("the leader's rotated token was not persisted")
	}
	if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
		t.Fatalf("the leader's result was not cached for later callers")
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("the source made %d requests, want exactly one", got)
	}
	s.Close()
}

// TestRefreshSourceExpiryAndClose checks the lifecycle: a token is returned
// from memory until it is close to expiry, a short-lived token is not handed out
// once its usable lifetime passed, and Close cancels an in-flight refresh,
// rejects later calls and closes the cached token material.
func TestRefreshSourceExpiryAndClose(t *testing.T) {
	t.Run("short-lived token expires in memory", func(t *testing.T) {
		cfg := sourceTestConfig()
		_, store := newSourceTestStore(t, cfg)
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			// A one-second lifetime keeps only half of it.
			writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 1, ""))
		})
		s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
			t.Fatalf("the first call did not return the token")
		}
		expireNow(s)
		if token, err := s.AccessToken(context.Background()); err != nil || token != sourceTestAccess {
			t.Fatalf("a call after expiry did not mint a new token")
		}
		if got := p.hits.Load(); got != 2 {
			t.Fatalf("the source made %d requests, want one per expiry", got)
		}
		s.Close()
		assertSourceClosed(t, s, p)
	})
	t.Run("close cancels an active request", func(t *testing.T) {
		cfg := sourceTestConfig()
		_, store := newSourceTestStore(t, cfg)
		received := make(chan struct{})
		p := newTokenPeer(t, func(_ http.ResponseWriter, r *http.Request) {
			close(received)
			<-r.Context().Done()
		})
		s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
		if err != nil {
			t.Fatalf("a valid configuration was rejected")
		}
		returned := make(chan error, 1)
		go func() {
			s.AccessToken(context.Background())
			returned <- nil
		}()
		select {
		case <-received:
		case <-time.After(3 * time.Second):
			t.Fatalf("the synthetic peer did not receive the request")
		}
		s.Close()
		s.Close()
		select {
		case <-returned:
		case <-time.After(3 * time.Second):
			t.Fatalf("Close did not cancel the active request")
		}
		assertSourceClosed(t, s, p)
	})
}

// TestRefreshSourceDropsTokenMaterial checks that the cached token material is
// closed on replacement, on expiry and on Close.
func TestRefreshSourceDropsTokenMaterial(t *testing.T) {
	cfg := sourceTestConfig()
	_, store := newSourceTestStore(t, cfg)
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jsonBody(sourceTestAccess, 1, ""))
	})
	s, err := newRefreshSourceAt(cfg, store, p.url, p.srv.Client())
	if err != nil {
		t.Fatalf("a valid configuration was rejected")
	}
	if _, err := s.AccessToken(context.Background()); err != nil {
		t.Fatalf("the first call failed")
	}
	s.mu.Lock()
	first := s.current
	s.mu.Unlock()
	if first.isClosed() {
		t.Fatalf("the cached token was closed while cached")
	}
	expireNow(s)
	if _, err := s.AccessToken(context.Background()); err != nil {
		t.Fatalf("a call after expiry failed")
	}
	if !first.isClosed() {
		t.Fatalf("a replaced token was not closed")
	}
	s.mu.Lock()
	second := s.current
	s.mu.Unlock()
	s.Close()
	if !second.isClosed() {
		t.Fatalf("Close did not close the cached token")
	}
	s.mu.Lock()
	label, scopes := s.label, s.scopeSets
	s.mu.Unlock()
	if !bytes.Equal(label, make([]byte, len(label))) {
		t.Fatalf("Close did not clear the copied profile label")
	}
	for _, scope := range scopes {
		if !bytes.Equal(scope, make([]byte, len(scope))) {
			t.Fatalf("Close did not clear the copied scopes")
		}
	}
}

// sourceWaiters reports how many callers are currently attached to the active
// flight. A finished flight is forgotten, so its count reads as zero.
func sourceWaiters(s *RefreshSource) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flight == nil {
		return 0
	}
	return s.flight.waiters
}

// sourceBuffers returns the source's own scope buffers by reference, so a test
// can prove their bytes were cleared.
func sourceBuffers(s *RefreshSource) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopeSets
}

// sourceLabel returns the source's own profile label by reference.
func sourceLabel(s *RefreshSource) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.label
}

// sourceContext returns the source refresh context.
func sourceContext(s *RefreshSource) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx
}

// sourceStateOf returns the lifecycle state under the lock.
func sourceStateOf(s *RefreshSource) sourceState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// sourceCleaned reports whether cleanup ran, under the lock.
func sourceCleaned(s *RefreshSource) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleaned
}

// terminalError returns the retained terminal error, nil while none, under the
// lock.
func (s *RefreshSource) terminalError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal
}

// scopesIntact reports whether buffers still hold the configured scopes.
func scopesIntact(buffers [][]byte, scopes []string) bool {
	if len(buffers) != len(scopes) {
		return false
	}
	for i, scope := range scopes {
		if string(buffers[i]) != scope {
			return false
		}
	}
	return true
}

// unsafePtr returns the address of a non-empty string's bytes, so a test can
// show that two strings do not share storage.
func unsafePtr(v string) uintptr {
	if v == "" {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.StringData(v)))
}

// unsafeBytesPtr returns the address of a non-empty byte slice's storage, so a
// test can show that two slices do not alias.
func unsafeBytesPtr(v []byte) uintptr {
	if len(v) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(v)))
}

// expireNow ages the cached token past its usable lifetime, so an expiry test
// needs no wall-clock wait.
func expireNow(s *RefreshSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expires = time.Now()
}

// assertSourceClosed checks that a closed source rejects later calls and makes
// no request.
func assertSourceClosed(t *testing.T, s *RefreshSource, p *tokenPeer) {
	t.Helper()
	before := p.hits.Load()
	token, err := s.AccessToken(context.Background())
	assertSourceFailure(t, token, err, ErrRefreshSource)
	if got := p.hits.Load(); got != before {
		t.Fatalf("a closed source made a request")
	}
}

// assertSourceStoreUntouched checks that the store kept the old item and that no
// call wrote or deleted anything since the seed.
func assertSourceStoreUntouched(t *testing.T, f *fakeSecrets, cfg RefreshSourceConfig) {
	t.Helper()
	if f.sets != 0 || f.values != nil || f.dels != 0 {
		t.Fatalf("a failure touched the store (%d saves, %d deletes)", f.sets, f.dels)
	}
	if got, present := stored(t, f, cfg); !present || got != refreshTestOld {
		t.Fatalf("a failure did not keep the stored old refresh token")
	}
}

// assertSourceTerminal checks that a terminal failure closed the source and is
// returned, unchanged and redacted, by later calls without another request.
func assertSourceTerminal(t *testing.T, s *RefreshSource, p *tokenPeer, want error) {
	t.Helper()
	before := p.hits.Load()
	for range 3 {
		token, err := s.AccessToken(context.Background())
		assertSourceFailure(t, token, err, want)
	}
	if got := p.hits.Load(); got != before {
		t.Fatalf("a terminal failure was sent again (%d requests, want %d)", got, before)
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
