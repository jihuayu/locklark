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
	"sync/atomic"
	"testing"
	"time"
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
	// leaderGate holds the first caller past the flight's completion, while
	// the other callers are still attaching to it.
	leaderGate := make(chan struct{})
	var calls, entered atomic.Int32
	results := make(chan outcome, callers)
	for range callers {
		go func() {
			entered.Add(1)
			if calls.Add(1) == 1 {
				<-leaderGate
			}
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
	close(release)
	// The leader is released only once every other caller reached
	// AccessToken, so the test never depends on goroutine scheduling, and
	// those callers always attach before the flight completes, so they all
	// receive the lead refresh's token instead of starting a new flight.
	waitFor(t, "every caller to reach AccessToken", func() bool { return entered.Load() == callers })
	waitFor(t, "the other callers to attach to the flight", func() bool { return sourceWaiters(s) == callers-1 })
	close(leaderGate)
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
			// Close cancelled the request, so this flight was abandoned
			// and no result is returned; the sentinel conforms.
			assertSourceFailure(t, "", err, ErrRefreshSource)
		case <-time.After(3 * time.Second):
			t.Fatalf("an in-flight refresh did not settle after Close")
		}
		if got := p.hits.Load(); got != 1 {
			t.Fatalf("a cancelled refresh made %d requests, want exactly one", got)
		}
		assertSourceStoreUntouched(t, f, cfg)
	})
}

// TestRefreshSourceStoreErrors checks that a save error returns no access
// token, reports the possibly-unknown store state and does not delete the old
// item, and that a load error returns no token either.
func TestRefreshSourceStoreErrors(t *testing.T) {
	t.Run("save error", func(t *testing.T) {
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
		if !strings.Contains(err.Error(), "may be unknown") {
			t.Fatalf("a save error does not say the store state may be unknown")
		}
		if f.dels != 0 {
			t.Fatalf("a save error deleted the old item")
		}
		if got, present := stored(t, f, cfg); !present || got != refreshTestOld {
			t.Fatalf("a save error did not keep the stored old item")
		}
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
	// The waiter must have joined the flight before it is canceled.
	time.Sleep(20 * time.Millisecond)
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

// sourceWaiters reports how many callers are currently attached to a flight.
func sourceWaiters(s *RefreshSource) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flight == nil {
		return 0
	}
	return s.flight.waiters
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
