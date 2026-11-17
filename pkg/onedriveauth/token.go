package onedriveauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Microsoft identity platform v2 token endpoint. Only the tenant path
// segment varies; the scheme, host and path are constants so the exchange
// cannot be pointed anywhere else. The tenant is checked by validTenant, which
// is the same check AuthorizationURL applies to the authorize URL.
const (
	tokenScheme = "https"
	tokenHost   = "login.microsoftonline.com"
	tokenPath   = "/oauth2/v2.0/token"
)

// Limitations of one token exchange. They bound how long a stuck peer can hold
// the caller and how many bytes its answer can cost. They are backstops, not
// security parameters.
const (
	// TokenExchangeTimeout is the maximum duration of one token endpoint
	// request, for the authorization-code exchange and the refresh grant
	// alike. A shorter context deadline or positive timeout takes precedence.
	TokenExchangeTimeout = 30 * time.Second
	// maxTokenResponseBytes is the most response body an exchange reads.
	maxTokenResponseBytes = 64 << 10
)

// redactedToken is the only text TokenResult ever formats to. It must not
// contain, name or hint at the access or refresh token.
const redactedToken = "onedriveauth.TokenResult{access_token:redacted, refresh_token:redacted}"

// Token exchange sentinels. Each one is a fixed text with no detail, so none
// can carry the client ID, tenant, scopes, redirect URI, code, verifier,
// endpoint, provider body or any token. Callers test them with errors.Is.
//
// Every sentinel returned once a request may have been sent states that the
// authorization code may have been consumed and that the exchange must not be
// retried; only ErrCancelled (nothing was sent) and the pre-send input errors
// leave the code untouched.
var (
	// ErrCode reports an empty or malformed authorization code passed to
	// ExchangeCode. It is returned before any request.
	ErrCode = errors.New("onedrive auth: invalid authorization code")
	// ErrRedirectURI reports a redirect URI that is not exactly the
	// http://127.0.0.1:<port>/oauth/native/callback form Start captured.
	// It is returned before any request.
	ErrRedirectURI = errors.New("onedrive auth: invalid redirect URI")
	// ErrCancelled reports that the caller's context was already done before
	// the token request was sent. No request was made and this call did not
	// present the authorization code to the token endpoint.
	ErrCancelled = errors.New("onedrive auth: token exchange cancelled before sending; no request was made")
	// ErrRequest reports that the request could not be built or the test-only
	// endpoint was not permitted. No network request was made.
	ErrRequest = errors.New("onedrive auth: token request could not be sent")
	// ErrOutcomeUnknown reports that an attempt ended without a usable
	// answer, including one rejected by the transport, so the provider may
	// have received and consumed the authorization code, and it may not be
	// reusable. The exchange is not retried.
	ErrOutcomeUnknown = errors.New("onedrive auth: token request outcome unknown; the authorization code may have been consumed and must not be reused; do not retry")
	// ErrProviderStatus reports an HTTP response with a status other than
	// 200. The provider body is discarded; the authorization code may have
	// been consumed and must not be reused, and the exchange is not retried.
	ErrProviderStatus = errors.New("onedrive auth: token endpoint returned a non-success status; the authorization code may have been consumed and must not be reused; do not retry")
	// ErrContentType reports a response whose media type is not
	// application/json; the code may have been consumed (no retry).
	ErrContentType = errors.New("onedrive auth: token response is not JSON; the authorization code may have been consumed; do not retry")
	// ErrOversized reports a token response body above the limit; the code
	// may have been consumed (no retry).
	ErrOversized = errors.New("onedrive auth: token response too large; the authorization code may have been consumed; do not retry")
	// ErrTokenResponse reports a truncated, malformed, trailing-data or
	// repeated-key JSON token response; the code may have been consumed (no
	// retry).
	ErrTokenResponse = errors.New("onedrive auth: malformed token response; the authorization code may have been consumed; do not retry")
	// ErrTokenMissing reports a 200 JSON response without exactly one bearer
	// token_type and a usable access_token and expires_in; the code may have
	// been consumed (no retry).
	ErrTokenMissing = errors.New("onedrive auth: token response lacks a usable bearer access token; the authorization code may have been consumed; do not retry")
)

// TokenExchangeConfig is the caller-supplied half of one authorization code
// token exchange. It holds the same public-client fields as AuthorizeConfig, so
// the client ID, tenant and scopes sent to the token endpoint are the ones the
// authorization request used, and it adds no secret: a public client has no
// client secret, and this type has no field for one.
type TokenExchangeConfig struct {
	// ClientID is the same public-client application (client) ID that
	// AuthorizationURL sent.
	ClientID string
	// Tenant is the same tenant AuthorizationURL sent; the token endpoint is
	// /{tenant}/oauth2/v2.0/token on the fixed official host.
	Tenant string
	// Scopes are the explicit delegated scopes of the authorization
	// request, sent exactly as listed, joined with single spaces.
	Scopes []string
}

// TokenResult is the transient, in-memory outcome of one successful token
// request, either an authorization-code exchange or a refresh-token grant: the
// bearer access token, its positive and bounded lifetime as a time.Duration,
// and, when the provider returned one, the refresh token. An authorization-code
// response includes a refresh_token only when the authorization request asked
// for offline_access; a refresh-grant response may include a replacement
// refresh token. In both grants the provider may omit the refresh token: this
// package adds no scope by itself and never requires one, so it may be absent,
// and the caller then keeps the refresh token it already has. The id_token,
// ext_expires_in and every other response member are discarded, and there is no
// way to obtain them from this package.
//
// The tokens are credentials held in unexported byte buffers. Every copy of a
// TokenResult, including the value returned to the caller, shares one owner: a
// mutex and the buffers it guards. AccessToken returns a string copy,
// RefreshToken returns a []byte copy, and Close zeroizes the shared buffers
// under their mutex; after Close both accessors return empty values. An accessor
// can never race Close, and closing any copy closes every copy, because they
// share the same owner. Close is idempotent, and it is the caller's lifecycle
// step: as soon as the tokens are no longer needed, call Close.
//
// Owned buffers. The owned token bytes are decoded straight from the response
// by the package's own token parser, and raw non-ASCII bytes, invalid UTF-8 and
// escaped characters that are not visible ASCII are rejected rather than
// replaced: a value that is not visible ASCII is never stored. This package
// cannot prove how the JSON
// decoder or the runtime handle internal copies of the response, so zeroizing
// the owned buffers is best effort: it clears what this package holds, not
// every copy that may exist in memory.
//
// The copies returned by the accessors are owned by the caller and are not
// cleared by Close; the caller must clear them. A []byte copy from RefreshToken
// can be cleared in place with clear. A Go string copy, such as the one
// AccessToken must return, cannot be modified in place, so it cannot be
// zeroized and can only be dropped by the caller. Nothing is persisted by this
// package.
//
// String and GoString exist so the common fmt verbs print a fixed placeholder
// instead of either token. Reflection-based marshallers are outside that
// guarantee, so callers must not marshal the result into logs.
type TokenResult struct {
	// owned is the shared, mutex-protected token material. It is the only
	// place the token bytes live, and every value copied from the result
	// points to the same owner, so Close reaches all of them.
	owned     *tokenMaterial
	expiresIn time.Duration
}

// tokenMaterial is the mutex-protected token state shared by every copy of one
// TokenResult. The token buffers are never exported: an exported field would be
// printed verbatim by %v and %+v. Owned bytes are used because a string cannot
// be zeroized in place.
type tokenMaterial struct {
	mu      sync.Mutex
	access  []byte
	refresh []byte
	closed  bool
}

// AccessToken returns a copy of the bearer access token, or "" once Close was
// called or the exchange carried none. The signature is kept for compatibility.
//
// The string is the only copy this call makes: the owned bytes are copied
// directly into it while the owner's mutex is held. A string cannot be zeroized,
// so the returned value is owned by the caller, is not cleared by Close, and can
// only be dropped. Treat it as a credential: do not log it, and do not place it
// in errors or files.
func (r TokenResult) AccessToken() string {
	if r.owned == nil {
		return ""
	}
	r.owned.mu.Lock()
	defer r.owned.mu.Unlock()
	if r.owned.closed || len(r.owned.access) == 0 {
		return ""
	}
	return string(r.owned.access)
}

// RefreshToken returns a defensive []byte copy of the OAuth refresh token the
// provider returned. It is nil when the response carried none, which both grants
// allow: an authorization-code response carries one only when offline_access was
// requested, and a refresh-grant response may omit the replacement, in which
// case the caller keeps the refresh token it already has. It is also nil once
// Close was called; a refresh_token that is present but not a well-formed token
// is an error, not an absence.
//
// Treat the returned copy as a credential: it is owned by the caller, is not
// cleared by Close, and must be cleared by the caller (with clear) once it is no
// longer needed. It must not be logged, persisted or placed in errors or files.
func (r TokenResult) RefreshToken() []byte {
	if r.owned == nil {
		return nil
	}
	r.owned.mu.Lock()
	defer r.owned.mu.Unlock()
	if r.owned.closed || len(r.owned.refresh) == 0 {
		return nil
	}
	copied := make([]byte, len(r.owned.refresh))
	copy(copied, r.owned.refresh)
	return copied
}

// ExpiresIn returns the positive access token lifetime the provider reported.
func (r TokenResult) ExpiresIn() time.Duration {
	return r.expiresIn
}

// Close zeroizes the access and refresh token buffers shared by every copy of
// this result, after which both accessors return empty values. It is idempotent
// and safe on a nil or zero TokenResult. It does not clear copies already
// returned by AccessToken or RefreshToken; the caller must clear those itself.
func (r *TokenResult) Close() {
	if r == nil || r.owned == nil {
		return
	}
	r.owned.mu.Lock()
	defer r.owned.mu.Unlock()
	clear(r.owned.access)
	clear(r.owned.refresh)
	// Release the buffers so no token bytes stay reachable through the
	// owner.
	r.owned.access = nil
	r.owned.refresh = nil
	r.owned.closed = true
}

// isClosed reports whether Close was called on this result or any value copied
// from it. A zero TokenResult has no owner and is not closed.
func (r TokenResult) isClosed() bool {
	if r.owned == nil {
		return false
	}
	r.owned.mu.Lock()
	defer r.owned.mu.Unlock()
	return r.owned.closed
}

// String implements fmt.Stringer and masks both tokens.
func (r TokenResult) String() string {
	return redactedToken
}

// GoString implements fmt.GoStringer and masks both tokens even for %#v.
func (r TokenResult) GoString() string {
	return redactedToken
}

// ExchangeCode redeems one authorization code for an access token at the
// Microsoft identity platform v2 token endpoint of cfg's tenant, using cfg's
// client ID and explicit scopes and this run's PKCE verifier.
//
// redirectURI must be the exact URI Start returned (and AuthorizationURL
// embedded) for the Callback that produced the code, before it closed: the
// http://127.0.0.1:<port>/oauth/native/callback form. It is passed explicitly
// because the Callback no longer yields it once the flow settled.
//
// The form carries exactly client_id, scope, code, redirect_uri,
// grant_type=authorization_code and code_verifier; it never carries a
// client_secret or any other member. The request is a single POST that is
// never retried, over verified TLS to the fixed official host only, with
// redirects, proxies and HTTP/2 refused; the response is bounded and the call
// returns no later than timeout (or TokenExchangeTimeout when non-positive or
// larger) after the request is sent. Post-send failures never imply the code
// is reusable: see ErrOutcomeUnknown and the response sentinels.
//
// Cancellation is classified honestly. A nil ctx means context.Background().
// If ctx is already done the exchange returns ErrCancelled and sends nothing,
// so the code was not presented. Once the request is sent, a transport error,
// cancellation or timeout returns ErrOutcomeUnknown because the provider may
// have consumed the code.
//
// All inputs are validated before any request; every failure is one of the
// package's fixed sentinels, so it never contains the provider's body,
// identifiers, URLs, code, verifier or tokens. A success returns only the
// transient TokenResult with the access token, its lifetime and, if the
// provider sent one, the refresh token; nothing is persisted. The bounded
// response body buffer and the temporary json.RawMessage buffers used for
// members other than the tokens are cleared before the call returns, on success
// and on every parse failure alike. The access_token and refresh_token are
// decoded by the package's byte Unmarshaler straight into owned buffers, which
// Close zeroizes; internal copies made by encoding/json or the runtime are not
// guaranteed to be wiped. The result keeps the tokens in
// memory until the caller calls TokenResult.Close, which zeroizes them, and
// every copy the accessors return is owned and must be cleared by the caller;
// a RefreshToken []byte can be cleared, an AccessToken string can only be
// dropped.
func ExchangeCode(ctx context.Context, cfg TokenExchangeConfig, redirectURI, code, verifier string, timeout time.Duration) (TokenResult, error) {
	return exchangeCode(ctx, cfg, redirectURI, code, verifier, timeout, nil, nil, nil)
}

// exchangeCode is ExchangeCode with the test seam: endpoint redirects the
// request to a synthetic peer and client supplies base to newTokenClient, whose
// transport trusts that peer. Both are nil in production, where the request goes
// to the derived Microsoft URL over the default transport. A non-nil endpoint
// must still pass validEndpoint. hooks is nil in production.
func exchangeCode(ctx context.Context, cfg TokenExchangeConfig, redirectURI, code, verifier string, timeout time.Duration, endpoint *url.URL, client *http.Client, hooks *exchangeHooks) (TokenResult, error) {
	form, err := tokenForm(cfg, redirectURI, code, verifier)
	if err != nil {
		return TokenResult{}, err
	}
	return tokenRun(ctx, cfg.Tenant, form, timeout, endpoint, client, hooks, nil)
}

// classifyTokenError is how tokenRun maps one failure, and returns it with the
// zero result. It receives every failure exactly once, in its original form: the
// base classification sentinel wrapped over the reason, or for an injected
// parser the error it returned. kind(base) returns base when the received error
// is base, classified exactly as errors.Is would, and nil otherwise. Without a
// classifier the authorization-code exchange keeps the base classification,
// so ExchangeCode returns its public sentinels unchanged. A classifier is the
// one place a grant rewords a failure, so each failure is mapped exactly once
// there; it must keep the original error in the chain whenever the base kind
// must still match. Returning err unchanged keeps the base error.
type classifyTokenError func(err error, kind func(error) error) error

// exchangeHooks are the test-only seams of tokenRun. Production passes nil:
// parse is readTokenResponse.
type exchangeHooks struct {
	// parse replaces readTokenResponse for the answer the worker read. Its
	// error is classified like the base parser's, but only by the matching
	// base sentinel.
	parse func(*http.Response) (TokenResult, error)
	// stalled, when non-nil, is called once the cancellation or bound
	// branch was selected and abort was called, before the worker is
	// awaited.
	stalled func()
}

// tokenRun is the one token request runner of this package, shared by the
// authorization-code exchange and the refresh grant: one bounded POST of the
// already validated and built form, never retried, over verified TLS to the
// fixed official host, with redirects, proxies and HTTP/2 refused by the
// request client and the answer read by the bounded parser. endpoint and client
// are the test-only seam described on exchangeCode; both are nil in production.
// classify maps every failure exactly once, from its original base
// classification; nil keeps the base sentinels (the exchange).
func tokenRun(ctx context.Context, tenant, form string, timeout time.Duration, endpoint *url.URL, client *http.Client, hooks *exchangeHooks, classify classifyTokenError) (TokenResult, error) {
	parse := readTokenResponse
	if hooks != nil && hooks.parse != nil {
		parse = hooks.parse
	}
	// fail maps the original error through classify exactly once, so no
	// pre-mapped sentinel reaches a classifier and no error is reworded
	// twice.
	fail := func(err error) (TokenResult, error) {
		if classify != nil {
			return TokenResult{}, classify(err, func(base error) error {
				if errors.Is(err, base) {
					return base
				}
				return nil
			})
		}
		return TokenResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	target, err := tokenURL(tenant)
	if err != nil {
		return fail(err)
	}
	if endpoint != nil {
		if !validEndpoint(endpoint) {
			return fail(wrap(ErrRequest, nil))
		}
		target = endpoint
	}
	// The bound is fixed: a caller may shorten it but never lengthen it
	// beyond TokenExchangeTimeout.
	if timeout <= 0 || timeout > TokenExchangeTimeout {
		timeout = TokenExchangeTimeout
	}

	// This is the only place ErrCancelled is returned, and the one step
	// that decides the error that was observed before any request. The form
	// (and with it the code, verifier or refresh token) is sent only past
	// it.
	early := ctx.Err()
	if early != nil {
		return fail(wrap(ErrCancelled, early))
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	// The request is cut at the deadline by its context even if the
	// transport ignores it, and the exchange gives up at the same bound.
	reqCtx, abort := context.WithTimeout(ctx, timeout)
	defer abort()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target.String(), strings.NewReader(form))
	if err != nil {
		return fail(wrap(ErrRequest, err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	httpClient := newTokenClient(transportOf(client))
	defer httpClient.CloseIdleConnections()

	// who records the first reason the exchange ended after the request
	// was sent: the request itself, the caller's context, or the bound. It
	// is set before the transport is called, so the direction of a failure
	// is known even when the transport reports nothing but a bare error.
	who := make(chan error, 1)
	note := func(src error) {
		select {
		case who <- src:
		default:
		}
	}

	type answer struct {
		res TokenResult
		err error
	}
	done := make(chan answer, 1)
	go func() {
		resp, err := httpClient.Do(req)
		if err != nil {
			// The request was sent: the provider may have processed
			// the credential or request (consumed the authorization
			// code or rotated the refresh token) whether or not it
			// answered. The raw transport error is intentionally
			// discarded and the fixed ErrOutcomeUnknown sentinel is
			// returned directly: the refresh classifier still reads
			// the base classification, while both provider and local
			// transport details stay redacted from the error text.
			note(early)
			done <- answer{err: ErrOutcomeUnknown}
			return
		}
		res, err := parse(resp)
		if err != nil {
			// An answer was observed, so the code was presented; the
			// error is the fixed sentinel for its kind.
			note(context.Canceled)
			done <- answer{err: err}
			return
		}
		done <- answer{res: res}
	}()

	bound := time.NewTimer(timeout)
	defer bound.Stop()
	select {
	case a := <-done:
		if a.err != nil {
			return fail(a.err)
		}
		return a.res, nil
	case <-ctx.Done():
		note(ctx.Err())
	case <-bound.C:
		note(context.DeadlineExceeded)
	}
	// The request was sent but this call stopped waiting: the outcome is
	// unknown and never retried. Abort waits for the request to unwind, so
	// no transport work outlives the returned error.
	abort()
	if hooks != nil && hooks.stalled != nil {
		hooks.stalled()
	}
	// The discarded answer is awaited, so no worker outlives this call. A
	// token result it carries is never returned, so it must be closed here
	// exactly like any other result the caller would own; Close is safe on
	// an empty result.
	a := <-done
	a.res.Close()
	return fail(wrap(ErrOutcomeUnknown, <-who))
}

// tokenForm builds the authorization-code form and validates every input
// before any request. It returns only fixed sentinels.
func tokenForm(cfg TokenExchangeConfig, redirectURI, code, verifier string) (string, error) {
	if _, err := validClientID(cfg.ClientID); err != nil {
		return "", err
	}
	if _, err := validTenant(cfg.Tenant); err != nil {
		return "", err
	}
	scope, err := joinScopes(cfg.Scopes)
	if err != nil {
		return "", err
	}
	if !validRedirectURI(redirectURI) {
		return "", wrap(ErrRedirectURI, nil)
	}
	if !validCode(code) {
		return "", wrap(ErrCode, nil)
	}
	if !ValidVerifier(verifier) {
		return "", wrap(ErrVerifier, nil)
	}
	v := url.Values{}
	v.Set("client_id", cfg.ClientID)
	v.Set("scope", scope)
	v.Set("code", code)
	v.Set("redirect_uri", redirectURI)
	v.Set("grant_type", "authorization_code")
	v.Set("code_verifier", verifier)
	return v.Encode(), nil
}

// tokenURL derives /{tenant}/oauth2/v2.0/token on the fixed official host. The
// tenant was validated by tokenForm first.
func tokenURL(tenant string) (*url.URL, error) {
	tenant, err := validTenant(tenant)
	if err != nil {
		return nil, err
	}
	return &url.URL{Scheme: tokenScheme, Host: tokenHost, Path: "/" + tenant + tokenPath}, nil
}

// validRedirectURI accepts exactly one http://127.0.0.1:<port>/oauth/native/callback
// URI: the form Start captures. No userinfo, query, fragment, explicit port
// that is not numeric, or other host or path is accepted.
func validRedirectURI(raw string) bool {
	if raw == "" || len(raw) > 256 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.Host != u.Hostname()+":"+u.Port() {
		return false
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return false
	}
	if u.Hostname() != LoopbackHost || u.Path != CallbackPath || u.RawPath != "" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port > 0 && port <= 65535 && strconv.Itoa(port) == u.Port()
}

// validEndpoint accepts only an HTTPS endpoint with a host, no userinfo, no
// query and no fragment. It is applied to the test seam as well, so even an
// injected endpoint cannot carry credentials, parameters or a redirect.
func validEndpoint(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return false
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return false
	}
	return true
}

// newTokenClient returns the fixed HTTP client policy of this package around
// the transport of base (nil for the default policy): no redirect, no proxy
// from this package, no HTTP/2, and the standard TLS verification. It never
// mutates the default or the caller's transport: every value is copied into a
// fresh Transport, and a base that is not an *http.Transport is used as an
// opaque round tripper without redirection.
func newTokenClient(base http.RoundTripper) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	tr, ok := base.(*http.Transport)
	if !ok {
		return &http.Client{Transport: base, CheckRedirect: noRedirect}
	}
	// Clone yields an independent transport; its TLS configuration is
	// nil when the base has none, which keeps the standard verification.
	clone := tr.Clone()
	tlsConfig := clone.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)
	return &http.Client{
		Transport: &http.Transport{
			DialContext:            clone.DialContext,
			TLSClientConfig:        tlsConfig,
			TLSHandshakeTimeout:    clone.TLSHandshakeTimeout,
			DisableKeepAlives:      true,
			DisableCompression:     true,
			MaxResponseHeaderBytes: maxHeaderBytes,
			ForceAttemptHTTP2:      false,
			// Proxy is nil: the fixed endpoint is reached directly.
		},
		CheckRedirect: noRedirect,
	}
}

// noRedirect refuses every redirect: the token endpoint answer must be final.
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// readTokenResponse validates one token endpoint answer and returns only the
// transient result. The response body is always drained within the bound and
// closed, and the bounded body buffer is wiped before this function returns on
// success and on every failure; nothing from it reaches an error.
func readTokenResponse(resp *http.Response) (TokenResult, error) {
	defer resp.Body.Close()
	// Read one byte past the limit, so an oversized body is detected
	// without reading all of it; the connection is not reused anyway.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	defer clear(body)
	switch {
	case err != nil:
		return TokenResult{}, wrap(ErrOutcomeUnknown, err)
	case int64(len(body)) > maxTokenResponseBytes:
		return TokenResult{}, wrap(ErrOversized, nil)
	case resp.StatusCode != http.StatusOK:
		return TokenResult{}, wrap(ErrProviderStatus, nil)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return TokenResult{}, wrap(ErrContentType, nil)
	}
	tok, err := decodeTokenJSON(body)
	if err != nil {
		return TokenResult{}, err
	}
	return tok, nil
}

// decodeTokenJSON decodes the strict object form of a token response: exactly
// one JSON object of syntactically valid members with no member name repeated,
// nothing after the object, exactly one token_type equal to "bearer", one
// access_token and one expires_in. It keeps only the access token, the lifetime
// and, when present, the refresh_token; every other member (id_token,
// ext_expires_in, error details, unknown names) is discarded unexamined apart
// from its JSON syntax.
//
// access_token and refresh_token must be JSON strings that decode to a
// non-empty, bounded visible-ASCII token. Their string escapes are decoded
// straight into owned []byte buffers, without an intermediate Go string. A
// malformed access_token, or a refresh_token present with any other type or an
// invalid value, is ErrTokenResponse; only an absent refresh_token is allowed
// to mean absence.
//
// access_token and refresh_token are decoded by the custom byte Unmarshaler
// (tokenStringDecoder) straight into owned bytes. Every other member goes
// through a temporary json.RawMessage that is cleared on every path out of its
// case. A failure mid-object wipes the body, any partially decoded token bytes
// and every owned token buffer already taken. The decoder's own internal copies
// of the response are outside this function's reach and are not wiped here.
//
// Every failure return must go through fail so no owned token bytes outlive the
// error.
func decodeTokenJSON(body []byte) (res TokenResult, err error) {
	owned := &tokenMaterial{}
	// fail wipes the body and every owned token buffer before returning the
	// fixed sentinel: no parse failure keeps token bytes.
	fail := func(sentinel error) (TokenResult, error) {
		clear(body)
		owned.mu.Lock()
		clear(owned.access)
		clear(owned.refresh)
		owned.access, owned.refresh = nil, nil
		owned.closed = true
		owned.mu.Unlock()
		return TokenResult{}, sentinel
	}
	jsonErr := wrap(ErrTokenResponse, nil)
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fail(jsonErr)
	}
	seen := make(map[string]bool)
	var (
		expiresIn  time.Duration
		hasBearer  bool
		hasToken   bool
		hasRefresh bool
		hasExpires bool
		// tokenBytes and tokenInvalid are the decode results of the
		// access or refresh member of the current iteration.
		tokenBytes   []byte
		tokenInvalid bool
	)
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok || seen[key] {
			return fail(jsonErr)
		}
		seen[key] = true
		keyErr := error(nil)
		switch key {
		case "access_token", "refresh_token":
			// The string is decoded straight from the stream into
			// owned bytes; a non-string value is drained and
			// rejected without being retained.
			tokenBytes, tokenInvalid = nil, false
			if err := dec.Decode(tokenStringDecoder(&tokenBytes, &tokenInvalid)); err != nil {
				keyErr = jsonErr
			}
			if keyErr == nil && tokenInvalid {
				clear(tokenBytes)
				keyErr = jsonErr
			}
			if key == "access_token" {
				hasToken = true
				clear(owned.access)
				owned.access = tokenBytes
			} else {
				hasRefresh = true
				clear(owned.refresh)
				owned.refresh = tokenBytes
			}
			tokenBytes = nil
			if keyErr != nil {
				return fail(keyErr)
			}
			continue
		}
		// Every other member goes through a temporary RawMessage, which
		// stays intact while the switch parses it; the clear below
		// covers every path out of it.
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			clear(value)
			return fail(jsonErr)
		}
		switch key {
		case "expires_in":
			hasExpires = true
			if secs, err := expiresSeconds(value); err == nil && secs > 0 && secs <= maxExpiresInSeconds {
				expiresIn = time.Duration(secs) * time.Second
			}
		case "token_type":
			var s string
			if json.Unmarshal(value, &s) != nil || !strings.EqualFold(s, "bearer") {
				keyErr = wrap(ErrTokenMissing, nil)
			} else {
				hasBearer = true
			}
		}
		clear(value)
		if keyErr != nil {
			return fail(keyErr)
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return fail(jsonErr)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fail(jsonErr)
	}
	if !hasBearer || !hasToken || len(owned.access) == 0 || !hasExpires || expiresIn == 0 {
		return fail(wrap(ErrTokenMissing, nil))
	}
	if !hasRefresh {
		// No refresh token was sent: offline_access was not requested
		// or the provider chose not to issue one.
		clear(owned.refresh)
		owned.refresh = nil
	}
	clear(body)
	return TokenResult{owned: owned, expiresIn: expiresIn}, nil
}

// tokenStringDecoder returns a json.Unmarshaler that decodes one JSON value
// straight into dst as visible-ASCII bytes, without an intermediate Go string:
// a JSON string and its escapes are written to dst, and dst is wiped first so no
// earlier bytes survive. Any other value, an unterminated string, or a token
// escape sequence that is not a printable ASCII byte marks invalid and stores
// nothing in dst. Escape sequences the token grammar cannot produce are skipped
// safely, and so is invalid UTF-8, which encoding/json's syntax scanner accepts
// for custom UnmarshalJSON input but which visibleASCII rejects. It reads the
// decoder-supplied bytes of one value and does not modify or retain them.
func tokenStringDecoder(dst *[]byte, invalid *bool) json.Unmarshaler {
	return &tokenStringValue{dst: dst, invalid: invalid}
}

// tokenStringValue is the json.Unmarshaler behind tokenStringDecoder. It is
// created for a single Decode and used once, so it holds no reusable state.
type tokenStringValue struct {
	dst     *[]byte
	invalid *bool
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *tokenStringValue) UnmarshalJSON(data []byte) error {
	*v.dst, *v.invalid = nil, false
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		*v.invalid = true
		return nil
	}
	// encoding/json's syntax scanner has already rejected raw control
	// characters and JSON syntax errors before this call, but it accepts raw
	// invalid UTF-8 inside a custom UnmarshalJSON input. The visibleASCII
	// check after the loop rejects anything outside visible ASCII, including
	// raw bytes >= 0x80 and their invalid UTF-8.
	//
	// out is allocated once at the largest decoded size (each byte of the
	// string body yields at most one output byte) so no growth-prefix
	// backing arrays keep copies of token bytes.
	out := make([]byte, 0, len(data)-2)
	valid := true
	for i := 1; i < len(data)-1 && valid; i++ {
		if data[i] != '\\' {
			// A raw quote is the final one handled above; bytes >=
			// 0x80 are raw UTF-8, which the ASCII check rejects
			// below, and their exact value does not matter because
			// the buffer is wiped.
			out = append(out, data[i])
			continue
		}
		out, i, valid = appendTokenEscape(out, data, i)
	}
	if !valid || len(out) == 0 || len(out) > maxCodeLen || !visibleASCII(out) {
		clear(out)
		*v.invalid = true
		return nil
	}
	// Success transfers the whole allocation, including its spare capacity,
	// to dst; the caller may clear up to cap and release it.
	*v.dst = out
	return nil
}

// appendTokenEscape decodes the JSON escape introduced by data[i] (an unescaped
// backslash), whose rendered byte is appended to out, and returns the index of
// its last byte. A token escape must denote a visible ASCII byte: \u0041 is
// accepted, while \n, \u00e9 or a surrogate escape is not, so a token is never
// decoded from control or non-ASCII characters. ok is false for such escapes
// and for malformed ones, which are skipped safely.
func appendTokenEscape(out, data []byte, i int) (out2 []byte, last int, ok bool) {
	if i+1 >= len(data)-1 {
		return out, i, false
	}
	switch e := data[i+1]; e {
	case '"', '\\', '/':
		// These escapes are always visible ASCII bytes.
		return append(out, e), i + 1, true
	case 'u':
		if i+6 > len(data)-1 {
			return out, i + 5, false
		}
		r, ok := hex4(data[i+2 : i+6])
		if !ok || r < 0x21 || r > 0x7e {
			return out, i + 5, false
		}
		return append(out, byte(r)), i + 5, true
	case 'b', 'f', 'n', 'r', 't':
		// A valid JSON escape that yields a control character.
		return out, i + 1, false
	default:
		return out, i, false
	}
}

// visibleASCII reports whether every byte is a visible ASCII byte, 0x21 to 0x7e.
func visibleASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// hex4 parses four hexadecimal digits.
func hex4(b []byte) (rune, bool) {
	var r rune
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// expiresSeconds reads an integral JSON number; the caller checks its bounds.
func expiresSeconds(raw json.RawMessage) (int64, error) {
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		return 0, err
	}
	return strconv.ParseInt(n.String(), 10, 64)
}

// maxExpiresInSeconds bounds a reported lifetime to about a year and keeps the
// conversion to time.Duration far from overflow.
const maxExpiresInSeconds = 366 * 24 * 60 * 60

// transportOf returns the transport of the test-only client, if any.
func transportOf(c *http.Client) http.RoundTripper {
	if c == nil {
		return nil
	}
	return c.Transport
}
