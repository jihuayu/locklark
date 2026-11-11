package onedriveauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// RefreshSource sentinels. Each is a fixed text with no clients ID, tenant,
// scope, profile label, token, endpoint, form, provider body or store error.
// Callers test them with errors.Is.
var (
	// ErrRefreshSource reports an invalid RefreshSourceConfig or a closed or
	// unusable source. No store or network operation was made.
	ErrRefreshSource = errors.New("onedrive auth: invalid refresh token source")
	// ErrSourceStoreUnknown reports that a validated replacement refresh
	// token could not be saved. The old item was not deleted, but the store
	// state may be unknown, because mygo's Set is not atomic.
	ErrSourceStoreUnknown = errors.New("onedrive auth: refresh token store save failed; the old item was kept but the store state may be unknown")
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
//     refresh token into an owned copy, clears it on every path, sends it once
//     and never retries inside this source. A save of a validated replacement
//     happens only after RefreshAccessToken fully validated the answer; when
//     the answer omitted refresh_token the stored item is kept.
//   - Concurrent AccessToken calls share one in-flight refresh. A caller whose
//     own context ends stops waiting without cancelling the refresh; the
//     refresh keeps running on the source context so the cached token still
//     lands for later callers. A failed refresh is not repeated by the waiters
//     of the same flight: each receives its fixed error.
//   - The TokenResult lives only in memory. It is closed on replacement, on
//     expiry, on a failed refresh and on Close, as far as this package holds
//     it.
//   - Close stops later results from being returned, cancels an in-flight
//     refresh, clears the cached material and forgets the copied client ID,
//     tenant, scopes and profile. Close does not delete the stored refresh
//     token.
//
// Every AccessToken string is a caller-owned immutable copy: a string cannot be
// zeroized, so the caller must drop it once it is no longer needed and must not
// log or persist it. Failures are fixed sentinels only. Nothing is logged.
type RefreshSource struct {
	clientID string
	tenant   string
	// scopeSets holds the explicit scopes in bytes. It is read under mu,
	// because Close clears it.
	scopeSets [][]byte
	label     []byte
	timeout   time.Duration
	store     *RefreshTokenStore
	// endpoint and client are the test-only seam, nil in production.
	endpoint *url.URL
	client   *http.Client

	mu      sync.Mutex
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	current TokenResult
	expires time.Time
	flight  *refreshFlight
}

// refreshFlight is one in-flight refresh shared by every concurrent caller.
// waiters counts the callers attached to it; s.mu may be held in any order.
type refreshFlight struct {
	done    chan struct{}
	waiters int
	res     TokenResult
	err     error
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

// takeScopes returns the configured scopes as a new string list, taken
// under s.mu. Bytes are used between refreshes because a string cannot be
// cleared; the returned strings are owned by the refresh that asked.
func (s *RefreshSource) takeScopes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	scopes := make([]string, len(s.scopeSets))
	for i, scope := range s.scopeSets {
		scopes[i] = string(scope)
	}
	return scopes
}

// AccessToken returns the cached access token while it is safely before its
// expiry, or the result of the one shared refresh grant that is in flight. The
// returned string is a caller-owned copy: it cannot be zeroized and must be
// dropped, never logged or persisted, once it is no longer needed. A refresh
// failure returns "" and one of the refresh sentinels, ErrRefreshSource when the
// source is closed, or ErrSourceStoreUnknown when a validated replacement could
// not be saved. A nil ctx means context.Background(); when ctx ends first,
// AccessToken returns ctx.Err() without cancelling the shared refresh.
func (s *RefreshSource) AccessToken(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", wrap(ErrRefreshSource, nil)
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
		return f.res.AccessToken(), f.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close closes the source: later AccessToken calls return ErrRefreshSource,
// an in-flight refresh is cancelled, and the cached token, copied scopes and
// profile label are cleared. It does not touch the stored refresh token and is
// safe to call more than once.
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
	// A refresh goroutine that already read its inputs may still be
	// running; it holds its own copies and publishes nothing once closed.
}

// expired reports whether the cached token must be refreshed. A token is
// released early so it is never handed out close to its expiry. s.mu is held.
func (s *RefreshSource) expired() bool {
	return s.current.owned == nil || !time.Now().Before(s.expires)
}

// refresh performs the one shared refresh of flight f and publishes its result
// to the waiters. It runs on the source context, so a canceled waiter never
// cancels it, and once for every flight, so no failure is retried here.
func (s *RefreshSource) refresh(f *refreshFlight) {
	res, err := s.fetch()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		res.Close()
		f.err = wrap(ErrRefreshSource, nil)
		close(f.done)
		return
	}
	if err == nil {
		s.current = res
		s.expires = time.Now().Add(usable(res.ExpiresIn()))
	}
	f.waiters = 0
	s.flight = nil
	s.mu.Unlock()

	f.res = res
	f.err = err
	close(f.done)
}

// fetch performs one refresh grant with the stored refresh token. The stored
// token is copied into an owned buffer and cleared on every path. A failure
// saves and deletes nothing; a validated replacement is saved before its access
// token is returned, and a save failure closes the token material, leaves the
// old item in place and reports ErrSourceStoreUnknown.
func (s *RefreshSource) fetch() (TokenResult, error) {
	scopes := s.takeScopes()
	old, present, err := s.store.LoadRefreshToken(s.clientID, s.tenant, s.label)
	defer clear(old)
	if err != nil {
		return TokenResult{}, err
	}
	if !present {
		return TokenResult{}, ErrStoreNotFound
	}
	cfg := TokenRefreshConfig{ClientID: s.clientID, Tenant: s.tenant, Scopes: scopes}
	res, err := refreshAccessToken(s.ctx, cfg, old, s.timeout, s.endpoint, s.client)
	if err != nil {
		return TokenResult{}, err
	}
	replacement := res.RefreshToken()
	defer clear(replacement)
	if len(replacement) != 0 {
		if err := s.store.SaveRefreshToken(s.clientID, s.tenant, s.label, replacement); err != nil {
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
