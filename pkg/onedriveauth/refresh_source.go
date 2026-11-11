package onedriveauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// RefreshSource sentinels. Each is a fixed text with no client ID, tenant,
// scope, profile label, token, endpoint, form, provider body or store error.
// Callers test them with errors.Is.
var (
	// ErrRefreshSource reports an invalid RefreshSourceConfig or a source
	// that is closed, in which case no store or network operation was made.
	ErrRefreshSource = errors.New("onedrive auth: invalid refresh token source")
	// ErrSourceStoreUnknown reports that a validated replacement refresh
	// token could not be saved. Nothing was deleted; whether the store
	// holds the old or the new value is unknown, because mygo's Set is not
	// atomic.
	ErrSourceStoreUnknown = errors.New("onedrive auth: refresh token store save failed; whether the store kept the old value or the new one is unknown")
)

// RefreshSourceConfig is the caller-supplied configuration of one
// RefreshSource. Every field is required: there is no default client ID,
// tenant, scope or profile, and no value is discovered from the environment or
// a file.
type RefreshSourceConfig struct {
	// ClientID is the public client that holds the stored refresh token. No
	// client secret exists or is ever sent.
	ClientID string
	// Tenant is the single tenant path segment of the token endpoint.
	Tenant string
	// Scopes is the exact, non-empty and explicit scope list sent with every
	// refresh grant. A nil or empty list is rejected; no scope is added.
	Scopes []string
	// Profile is the local profile label the refresh token is stored under.
	// It is not a verified account identity. The source copies it, uses it
	// only for the store key and never formats it.
	Profile []byte
	// Timeout bounds one refresh request. It defaults to TokenExchangeTimeout
	// when non-positive.
	Timeout time.Duration
}

// RefreshSource mints access tokens from the refresh token that the OS
// credential store holds for one (client ID, tenant, profile) binding. It reuses
// RefreshAccessToken for the grant and RefreshTokenStore for persistence:
//
//   - AccessToken returns the cached access token while it is safely before its
//     expiry, and otherwise performs one refresh grant. It loads the stored
//     refresh token into an owned copy, clears it on every path and sends it
//     once. A save of a validated replacement happens only after
//     RefreshAccessToken fully validated the answer; when the answer omitted
//     refresh_token the stored item is kept.
//   - A failure after the request was sent, or a failed save of a validated
//     replacement, makes the source unusable: the fixed redacted error is
//     retained, the source refresh context is released, and every later
//     AccessToken call returns the error without another token-endpoint
//     request. The caller recovers by closing the source and enrolling the
//     profile again; this checkpoint has no re-enrollment path.
//     Only a pre-send cancellation, or a store load failure or missing item
//     (no request was made), can be retried by a later call.
//   - Concurrent AccessToken calls share one in-flight refresh. A caller whose
//     own context ends stops waiting without cancelling the refresh; the
//     refresh keeps running on the source context so the cached token still
//     lands for later callers. Waiters never read a result from the flight:
//     a flight publishes only its error, and a successful waiter re-checks the
//     cache under the lock, so a result closed by Close or by expiry is never
//     returned as an empty token with no error.
//   - The TokenResult lives only in memory. It is closed on replacement, on a
//     failed refresh and on Close, as far as this package holds it. There is no
//     timer: a cached token is closed once a later call observes that it
//     expired, unless Close closes it first.
//   - Close stops later results from being returned, cancels an in-flight
//     refresh, closes the cached token material, clears the copied scopes and
//     profile label, and drops the source's client ID and tenant references. It
//     does that even after a terminal failure, which already released the
//     source refresh context, and its cleanup runs exactly once. Close does not
//     zeroize the backing bytes of the client ID and tenant strings: dropping
//     the references only makes them unreachable from this source. Close does
//     not delete the stored refresh token. When Close cancels a request that
//     was already sent, the refresh reports that the outcome is unknown.
//
// Every AccessToken string is a caller-owned immutable copy: a string cannot be
// zeroized, so the caller must drop it once it is no longer needed and must not
// log or persist it. Failures are fixed sentinels only. Nothing is logged.
type RefreshSource struct {
	// clientID, tenant and the explicit scopes are set once by the
	// constructor and dropped by cleanup, each under mu. They are copied
	// into a binding under one lock before any store or network call.
	clientID  string
	tenant    string
	scopeSets [][]byte
	// label is the caller's profile label bytes. It is read and cleared
	// under mu.
	label   []byte
	timeout time.Duration
	store   *RefreshTokenStore
	// endpoint and client are the test-only seam, nil in production.
	endpoint *url.URL
	client   *http.Client

	mu sync.Mutex
	// state is closed after Close, or after a terminal failure, which
	// forbids another token-endpoint request.
	state sourceState
	// cleaned reports that cleanup ran; it is kept apart from state,
	// because a terminal failure must not stop a later Close from wiping
	// the source.
	cleaned  bool
	terminal error
	ctx      context.Context
	cancel   context.CancelFunc
	current  TokenResult
	expires  time.Time
	flight   *refreshFlight
}

// sourceState is the lifecycle state of a RefreshSource. Both later states
// report no result; only an unusable source keeps a terminal error.
type sourceState int

const (
	sourceOpen sourceState = iota
	// sourceUnusable is the state after a failure that may have reached the
	// provider or the store; its terminal error is retained.
	sourceUnusable
	// sourceClosed is the state after Close, which wiped the source.
	sourceClosed
)

// refreshFlight is one in-flight refresh shared by every concurrent caller.
// It publishes only its error; a successful waiter re-checks the cache, so no
// token is ever read from a flight after its done channel closed. waiters
// counts the callers still attached, and is changed only under s.mu.
type refreshFlight struct {
	done    chan struct{}
	waiters int
	err     error
}

// sourceBinding is the input of one refresh: a snapshot of the client ID,
// tenant and explicit scopes, and a copy of the profile label. It is taken in
// one critical section, so Close cannot clear one field while another is
// copied; label belongs to the refresh and is cleared on every exit.
type sourceBinding struct {
	clientID string
	tenant   string
	scopes   []string
	label    []byte
}

// terminal reports whether err forbids another token-endpoint request from this
// source. A failed save may have reached the store, and every post-send failure
// may have reached the provider, so neither may be retried. Only a pre-send
// ErrRefreshCancelled, or a store load failure or missing item, may be.
func terminal(err error) bool {
	switch {
	case err == nil, errors.Is(err, ErrRefreshCancelled), errors.Is(err, ErrStoreNotFound), errors.Is(err, ErrStoreUnsupported), errors.Is(err, ErrStoreInput):
		return false
	}
	return true
}

// NewRefreshSource validates cfg before any store or network operation and
// returns a source bound to the profile store key of cfg's client ID, tenant and
// profile label. Malformed values are rejected with a fixed sentinel and never
// echoed.
func NewRefreshSource(cfg RefreshSourceConfig) (*RefreshSource, error) {
	s, err := newRefreshSource(cfg, NewRefreshTokenStore())
	if err != nil {
		return nil, err
	}
	return s, nil
}

// newRefreshSource is NewRefreshSource with the store injected by the tests.
func newRefreshSource(cfg RefreshSourceConfig, store *RefreshTokenStore) (*RefreshSource, error) {
	return newRefreshSourceAt(cfg, store, nil, nil)
}

// newRefreshSourceAt is newRefreshSource with the test-only endpoint/client
// seam of RefreshAccessToken; both are nil in production.
func newRefreshSourceAt(cfg RefreshSourceConfig, store *RefreshTokenStore, endpoint *url.URL, client *http.Client) (*RefreshSource, error) {
	clientID, err := validClientID(cfg.ClientID)
	if err != nil {
		return nil, wrap(ErrRefreshSource, nil)
	}
	tenant, err := validTenant(cfg.Tenant)
	if err != nil {
		return nil, wrap(ErrRefreshSource, nil)
	}
	if _, err := joinScopes(cfg.Scopes); err != nil {
		return nil, wrap(ErrRefreshSource, nil)
	}
	if !validProfileLabel(cfg.Profile) {
		return nil, wrap(ErrRefreshSource, nil)
	}
	if store == nil || store.secrets == nil {
		return nil, wrap(ErrRefreshSource, nil)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = TokenExchangeTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &RefreshSource{
		clientID: clientID,
		tenant:   tenant,
		label:    append([]byte(nil), cfg.Profile...),
		timeout:  timeout,
		store:    store,
		endpoint: endpoint,
		client:   client,
		ctx:      ctx,
		cancel:   cancel,
	}
	// Each refresh gets its own copy of the explicit scopes.
	for _, scope := range cfg.Scopes {
		s.scopeSets = append(s.scopeSets, []byte(scope))
	}
	return s, nil
}

// binding returns the state of the source and, when it is open, a snapshot of
// every binding field. All of it is read in one critical section, so Close
// cannot clear one field while another is copied. The label is a new copy owned
// by the caller, which must clear it.
func (s *RefreshSource) binding() (sourceBinding, sourceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != sourceOpen {
		return sourceBinding{}, s.state
	}
	b := sourceBinding{
		clientID: s.clientID,
		tenant:   s.tenant,
		scopes:   make([]string, len(s.scopeSets)),
		label:    make([]byte, len(s.label)),
	}
	for i, scope := range s.scopeSets {
		b.scopes[i] = string(scope)
	}
	copy(b.label, s.label)
	return b, sourceOpen
}

// AccessToken returns the cached access token while it is safely before its
// expiry, or the result of the one shared refresh grant that is in flight. The
// returned string is a caller-owned copy: it cannot be zeroized and must be
// dropped, never logged or persisted, once it is no longer needed.
//
// A failure returns "" and one of the fixed sentinels: a refresh sentinel, a
// store sentinel, ErrRefreshSource when the source is closed, a terminal sentinel
// after a failure that may have reached the provider or the store, or
// ErrSourceStoreUnknown when a validated replacement could
// not be saved. A failure that may have reached the provider or the store is
// terminal: later calls return it without a request. A nil ctx means
// context.Background(); when ctx ends first, AccessToken returns ctx.Err()
// without cancelling the shared refresh. A context that is already done makes
// no store or network operation.
func (s *RefreshSource) AccessToken(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	s.mu.Lock()
	if s.state != sourceOpen {
		token, err := s.unusableResult()
		s.mu.Unlock()
		return token, err
	}
	// A later call is the only thing that notices expiry and closes the
	// cached material before replacing it; no timer does.
	if !s.expired() {
		token := s.current.AccessToken()
		s.mu.Unlock()
		return token, nil
	}
	// An expired result is released before a new refresh starts.
	s.current.Close()
	s.current = TokenResult{}
	f := s.flight
	if f == nil {
		f = &refreshFlight{done: make(chan struct{})}
		s.flight = f
		go s.refresh(f)
	}
	f.waiters++
	s.mu.Unlock()

	select {
	case <-f.done:
		return s.settled(f)
	case <-ctx.Done():
		s.detach(f)
		return "", ctx.Err()
	}
}

// detach records that a canceled caller stopped waiting, so the flight counts
// only the callers still attached. A flight that already finished is left
// alone; refresh resets its count under the same lock before it closes done.
func (s *RefreshSource) detach(f *refreshFlight) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flight == f {
		f.waiters--
	}
}

// settled returns the caller's result once flight f finished. Only f.err is
// read from the flight; a successful waiter re-checks the cache under the
// lock, so a cached token that Close or expiry closed meanwhile is never
// returned as an empty string with a nil error. s.closed or s.flight is always
// visible here: both change under s.mu before f.done can close.
func (s *RefreshSource) settled(f *refreshFlight) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The error of this caller's own flight wins, even over a closed
	// source, so a request that Close cancelled after it was sent keeps
	// reporting its unknown outcome.
	if f.err != nil {
		return "", f.err
	}
	if s.state != sourceOpen {
		return s.unusableResult()
	}
	if s.expired() {
		return "", wrap(ErrRefreshSource, nil)
	}
	return s.current.AccessToken(), nil
}

// unusableResult reports the error of a closed or unusable source. With s.mu
// held, it is the retained terminal error, which keeps its own classification,
// or otherwise the fixed closed-source sentinel. It never returns a token.
func (s *RefreshSource) unusableResult() (string, error) {
	if s.terminal != nil {
		return "", s.terminal
	}
	return "", wrap(ErrRefreshSource, nil)
}

// Close closes the source and wipes it exactly once: later AccessToken calls
// return the retained terminal error, or ErrRefreshSource, an in-flight refresh
// is cancelled, and the cached token, copied scopes and profile label are
// cleared, and the client ID and tenant references are dropped. The cleanup
// runs even when a terminal failure closed the source first. A request already
// sent is reported to its waiters as outcome unknown; a pre-send cancellation or
// a result the refresh produced but could not publish is closed and reported as
// a closed source. Close does not delete the stored refresh token, and it is
// safe to call more than once.
func (s *RefreshSource) Close() {
	// The lock is held across the whole reset, so no concurrent AccessToken
	// can observe a half-cleared source.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup(sourceClosed)
}

// cleanup wipes the source once and moves it to next, which is sourceClosed for
// Close or sourceUnusable for a terminal failure. With s.mu held.
func (s *RefreshSource) cleanup(next sourceState) {
	if !s.cleaned {
		s.cleaned = true
		if s.cancel != nil {
			s.cancel()
			s.cancel = nil
		}
		s.current.Close()
		s.current = TokenResult{}
		clear(s.label)
		for _, scope := range s.scopeSets {
			clear(scope)
		}
		// Dropping the references makes the client ID and tenant
		// unreachable from the source; string backing bytes cannot be
		// zeroized.
		s.scopeSets = nil
		s.label = nil
		s.clientID = ""
		s.tenant = ""
	}
	if s.state == sourceOpen || next == sourceClosed {
		s.state = next
	}
}

// expired reports whether the cached token must be refreshed. A token is
// released early so it is never handed out close to its expiry. s.mu is held.
func (s *RefreshSource) expired() bool {
	return s.current.owned == nil || !time.Now().Before(s.expires)
}

// refresh performs the one shared refresh of flight f and publishes it to the
// waiters. It runs on the source context, so a canceled waiter never cancels
// it, and once for every flight, so no failure is retried here.
func (s *RefreshSource) refresh(f *refreshFlight) {
	res, err := s.fetch()
	published := false
	defer func() {
		if !published {
			res.Close()
		}
	}()

	s.mu.Lock()
	if s.state != sourceOpen {
		// Publish nothing to a closed source, but keep a post-send
		// failure's classification: the provider outcome is still
		// unknown, even though Close caused it.
		s.mu.Unlock()
		// A request that was sent keeps its classification, since the
		// provider outcome is unknown; otherwise a closed source is the
		// whole story.
		f.err = nil
		if err != nil && !errors.Is(err, ErrRefreshCancelled) {
			f.err = err
		}
		close(f.done)
		return
	}
	switch {
	case err == nil:
		s.current = res
		s.expires = time.Now().Add(usable(res.ExpiresIn()))
		published = true
	case terminal(err):
		// The source must never send the possibly-consumed refresh token
		// again. The retained error keeps its classification. The
		// terminal state releases the source refresh context now; the
		// copied binding and inputs are wiped by a later Close, which
		// stays available because cleaned is not set.
		s.state = sourceUnusable
		s.terminal = err
		s.cancel()
		s.cancel = nil
	}
	f.waiters = 0
	s.flight = nil
	f.err = err
	s.mu.Unlock()
	close(f.done)
}

// fetch performs one refresh grant with the stored refresh token. The binding
// and the stored token are copies owned here and cleared on every path, and the
// stored refresh token is read and sent from those copies only, so a concurrent
// Close cannot race the work. An already closed or unusable source is rejected
// before the store or the network is touched. A failure saves and deletes
// nothing; a validated replacement is saved before its access token is returned,
// and a save failure closes the token material and reports ErrSourceStoreUnknown
// without deleting anything.
func (s *RefreshSource) fetch() (TokenResult, error) {
	b, state := s.binding()
	defer clear(b.label)
	if state != sourceOpen {
		return TokenResult{}, wrap(ErrRefreshSource, nil)
	}
	old, present, err := s.store.LoadRefreshToken(b.clientID, b.tenant, b.label)
	defer clear(old)
	if err != nil {
		return TokenResult{}, err
	}
	if !present {
		return TokenResult{}, ErrStoreNotFound
	}
	cfg := TokenRefreshConfig{ClientID: b.clientID, Tenant: b.tenant, Scopes: b.scopes}
	res, err := refreshAccessToken(s.ctx, cfg, old, s.timeout, s.endpoint, s.client)
	if err != nil {
		return TokenResult{}, err
	}
	replacement := res.RefreshToken()
	defer clear(replacement)
	if len(replacement) != 0 {
		if err := s.store.SaveRefreshToken(b.clientID, b.tenant, b.label, replacement); err != nil {
			res.Close()
			return TokenResult{}, ErrSourceStoreUnknown
		}
	}
	return res, nil
}

// refreshSkew is how much of a token's lifetime is given up so a caller never
// receives a token close to expiry.
const refreshSkew = 60 * time.Second

// usable is the cache lifetime of a token reported to live lifetime: the whole
// lifetime, minus refreshSkew when that leaves half or more of it.
func usable(lifetime time.Duration) time.Duration {
	if skew := min(refreshSkew, lifetime/2); skew > 0 {
		return lifetime - skew
	}
	return lifetime
}
