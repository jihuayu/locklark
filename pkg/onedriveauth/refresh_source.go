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
//     replacement, is terminal for the source: the fixed redacted error is
//     retained and every later AccessToken call returns it without another
//     token-endpoint request. The caller recovers by discarding the source and
//     enrolling the profile again; this checkpoint has no re-enrollment path.
//     Only a pre-send cancellation, or a store load failure or missing item
//     (no request was made), can be retried by a later call.
//   - Concurrent AccessToken calls share one in-flight refresh. A caller whose
//     own context ends stops waiting without cancelling the refresh; the
//     refresh keeps running on the source context so the cached token still
//     lands for later callers. Waiters never read a result from the flight:
//     a flight publishes only its error, and a successful waiter re-checks the
//     cache under the lock, so a result closed by Close or by expiry is never
//     returned as an empty token with no error.
//   - The TokenResult lives only in memory. It is closed on replacement, on
//     expiry, on a failed refresh and on Close, as far as this package holds
//     it.
//   - Close stops later results from being returned, cancels an in-flight
//     refresh, clears the cached material and forgets the copied client ID,
//     tenant, scopes and profile. Close does not delete the stored refresh
//     token. When Close cancels a request that was already sent, the refresh
//     reports that the outcome is unknown and the source stays closed.
//
// Every AccessToken string is a caller-owned immutable copy: a string cannot be
// zeroized, so the caller must drop it once it is no longer needed and must not
// log or persist it. Failures are fixed sentinels only. Nothing is logged.
type RefreshSource struct {
	// clientID, tenant and the explicit scopes. They are read under mu,
	// because Close clears the scopes, and are copied into a binding before
	// any store or network call.
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

	mu     sync.Mutex
	closed bool
	ctx    context.Context
	cancel context.CancelFunc
	// terminal, when non-nil, is the fixed error of a failure that forbids
	// another token-endpoint request. It is always set together with
	// closed.
	terminal error
	current  TokenResult
	expires  time.Time
	flight   *refreshFlight
}

// refreshFlight is one in-flight refresh shared by every concurrent caller.
// It publishes only its error; a successful waiter re-checks the cache, so no
// token is ever read from a flight after its done channel closed. waiters
// counts the attached callers and is read under s.mu.
type refreshFlight struct {
	done    chan struct{}
	waiters int
	err     error
}

// sourceBinding is the source-owned input of one refresh: a safe snapshot of
// the client ID, tenant and explicit scopes, and a copy of the profile label.
// label may be cleared by the source only after it built this copy; the label
// belongs to the refresh and is cleared on every exit.
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

// binding returns a safe snapshot of the client ID, tenant and explicit scopes,
// taken under s.mu before Close can clear the source's copies. The label field
// is filled by the caller with a copy it owns and clears.
func (s *RefreshSource) binding() sourceBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := sourceBinding{
		clientID: s.clientID,
		tenant:   s.tenant,
		scopes:   make([]string, len(s.scopeSets)),
	}
	for i, scope := range s.scopeSets {
		b.scopes[i] = string(scope)
	}
	return b
}

// profileLabel returns a new copy of the source's profile label, taken under
// s.mu before Close can clear it. The caller owns it and must clear it.
func (s *RefreshSource) profileLabel() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.label...)
}

// AccessToken returns the cached access token while it is safely before its
// expiry, or the result of the one shared refresh grant that is in flight. The
// returned string is a caller-owned copy: it cannot be zeroized and must be
// dropped, never logged or persisted, once it is no longer needed.
//
// A failure returns "" and one of the fixed sentinels: a refresh sentinel, a
// store sentinel, ErrRefreshSource when the source is closed (including after a
// terminal failure), or ErrSourceStoreUnknown when a validated replacement could
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
	if s.closed {
		token, err := s.closedResult()
		s.mu.Unlock()
		return token, err
	}
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
		return "", ctx.Err()
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
	if s.closed {
		return s.closedResult()
	}
	if s.expired() {
		return "", wrap(ErrRefreshSource, nil)
	}
	return s.current.AccessToken(), nil
}

// closedResult reports the error of a closed source. With s.mu held, it is the
// retained terminal error, which keeps its own classification, or otherwise
// the fixed closed-source sentinel. It never returns a token.
func (s *RefreshSource) closedResult() (string, error) {
	if s.terminal != nil {
		return "", s.terminal
	}
	return "", wrap(ErrRefreshSource, nil)
}

// Close closes the source: later AccessToken calls return ErrRefreshSource, an
// in-flight refresh is cancelled, and the cached token, copied scopes and
// profile label are cleared. A request already sent is reported to its waiters
// as outcome unknown; a pre-send cancellation or a result the refresh produced
// but could not publish is closed and reported as a closed source. Close does
// not touch the stored refresh token and is safe to call more than once.
func (s *RefreshSource) Close() {
	// The lock is held across the whole reset, so no concurrent AccessToken
	// can observe a half-cleared source.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.cancel()
	s.current.Close()
	s.current = TokenResult{}
	clear(s.label)
	for _, scope := range s.scopeSets {
		clear(scope)
	}
	s.scopeSets = nil
	// A refresh goroutine may still be running with its own binding copy;
	// it publishes nothing once the source is closed.
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
	if s.closed {
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
		// again. The retained error keeps its classification.
		s.closed = true
		s.terminal = err
		s.cancel()
	}
	f.waiters = 0
	s.flight = nil
	f.err = err
	s.mu.Unlock()
	close(f.done)
}

// fetch performs one refresh grant with the stored refresh token. The binding
// and the stored token are copies owned here and cleared on every path. A
// failure saves and deletes nothing; a validated replacement is saved before its
// access token is returned, and a save failure closes the token material and
// reports ErrSourceStoreUnknown without deleting anything.
func (s *RefreshSource) fetch() (TokenResult, error) {
	b := s.binding()
	b.label = s.profileLabel()
	defer clear(b.label)
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
