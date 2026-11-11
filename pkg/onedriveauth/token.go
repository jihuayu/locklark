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
	// TokenExchangeTimeout is the maximum duration of one exchange. A
	// shorter context deadline or positive timeout takes precedence.
	TokenExchangeTimeout = 30 * time.Second
	// maxTokenResponseBytes is the most response body an exchange reads.
	maxTokenResponseBytes = 64 << 10
)

// redactedToken is the only text TokenResult ever formats to. It must not
// contain, name or hint at the access token.
const redactedToken = "onedriveauth.TokenResult{access_token:redacted}"

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

// TokenResult is the transient outcome of one successful exchange: the bearer
// access token and its positive, bounded lifetime as a time.Duration. It
// carries nothing else. The refresh_token, id_token, ext_expires_in and any
// other response member are discarded, and there is no way to obtain them
// from this package.
//
// The access token is a credential held in an unexported field. It is readable
// only through AccessToken and is not persisted by this package; the caller
// holds it in memory only, for as long as it is needed. String and GoString
// exist so the common fmt verbs print a fixed placeholder instead of the
// token. Reflection-based marshallers are outside that guarantee, so callers
// must not marshal the result into logs.
type TokenResult struct {
	// token is never exported: an exported field would be printed verbatim
	// by %v and %+v.
	token     string
	expiresIn time.Duration
}

// AccessToken returns the bearer access token. Treat the returned value as a
// credential: do not log it, and do not place it in errors or files.
func (r TokenResult) AccessToken() string {
	return r.token
}

// ExpiresIn returns the positive access token lifetime the provider reported.
func (r TokenResult) ExpiresIn() time.Duration {
	return r.expiresIn
}

// String implements fmt.Stringer and masks the access token.
func (r TokenResult) String() string {
	return redactedToken
}

// GoString implements fmt.GoStringer and masks the access token even for %#v.
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
// transient TokenResult with the access token; nothing is persisted.
func ExchangeCode(ctx context.Context, cfg TokenExchangeConfig, redirectURI, code, verifier string, timeout time.Duration) (TokenResult, error) {
	return exchangeCode(ctx, cfg, redirectURI, code, verifier, timeout, nil, nil)
}

// exchangeCode is ExchangeCode with the test seam: endpoint redirects the
// request to a local synthetic HTTPS peer and supplies base to newTokenClient,
// whose transport trusts that peer. Both are nil in production, where the
// request goes to the derived Microsoft URL over the default transport. A
// non-nil endpoint must still pass validEndpoint.
func exchangeCode(ctx context.Context, cfg TokenExchangeConfig, redirectURI, code, verifier string, timeout time.Duration, endpoint *url.URL, client *http.Client) (TokenResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	form, err := tokenForm(cfg, redirectURI, code, verifier)
	if err != nil {
		return TokenResult{}, err
	}
	target, err := tokenURL(cfg.Tenant)
	if err != nil {
		return TokenResult{}, err
	}
	if endpoint != nil {
		if !validEndpoint(endpoint) {
			return TokenResult{}, wrap(ErrRequest, nil)
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
	// (and with it the code and verifier) is sent only past it.
	early := ctx.Err()
	if early != nil {
		return TokenResult{}, wrap(ErrCancelled, early)
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
		return TokenResult{}, wrap(ErrRequest, err)
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
			// The request was sent: the provider may have consumed
			// the code whether or not it answered.
			note(early)
			done <- answer{err: ErrOutcomeUnknown}
			return
		}
		res, err := readTokenResponse(resp)
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
		return a.res, a.err
	case <-ctx.Done():
		note(ctx.Err())
	case <-bound.C:
		note(context.DeadlineExceeded)
	}
	// The request was sent but this call stopped waiting: the outcome is
	// unknown and never retried. Abort waits for the request to unwind, so
	// no transport work outlives the returned error.
	abort()
	<-done
	return TokenResult{}, wrap(ErrOutcomeUnknown, <-who)
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
// closed; nothing from it reaches an error.
func readTokenResponse(resp *http.Response) (TokenResult, error) {
	defer resp.Body.Close()
	// Read one byte past the limit, so an oversized body is detected
	// without reading all of it; the connection is not reused anyway.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
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
// access_token and one expires_in. It keeps nothing but the access token and
// lifetime; every other member (refresh_token, id_token, ext_expires_in, error
// details, unknown names) is discarded unexamined apart from its JSON syntax.
func decodeTokenJSON(body []byte) (TokenResult, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return TokenResult{}, wrap(ErrTokenResponse, nil)
	}
	seen := make(map[string]bool)
	var (
		token      string
		expiresIn  time.Duration
		hasBearer  bool
		hasToken   bool
		hasExpires bool
	)
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok || seen[key] {
			return TokenResult{}, wrap(ErrTokenResponse, nil)
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return TokenResult{}, wrap(ErrTokenResponse, nil)
		}
		switch key {
		case "access_token":
			hasToken = true
			var s string
			if json.Unmarshal(value, &s) == nil && validAccessToken(s) {
				token = s
			}
			// An empty or ill-formed value is not retained; the
			// fixed outcome below is the same as for an absent one.
		case "expires_in":
			hasExpires = true
			if secs, err := expiresSeconds(value); err == nil && secs > 0 && secs <= maxExpiresInSeconds {
				expiresIn = time.Duration(secs) * time.Second
			}
		case "token_type":
			var s string
			if json.Unmarshal(value, &s) != nil || !strings.EqualFold(s, "bearer") {
				return TokenResult{}, wrap(ErrTokenMissing, nil)
			}
			hasBearer = true
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return TokenResult{}, wrap(ErrTokenResponse, nil)
	}
	if _, err := dec.Token(); err != io.EOF {
		return TokenResult{}, wrap(ErrTokenResponse, nil)
	}
	if !hasBearer || !hasToken || token == "" || !hasExpires || expiresIn == 0 {
		return TokenResult{}, wrap(ErrTokenMissing, nil)
	}
	return TokenResult{token: token, expiresIn: expiresIn}, nil
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

// validAccessToken accepts a non-empty, bounded visible-ASCII token without
// spaces or control characters.
func validAccessToken(s string) bool {
	if s == "" || len(s) > maxCodeLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// transportOf returns the transport of the test-only client, if any.
func transportOf(c *http.Client) http.RoundTripper {
	if c == nil {
		return nil
	}
	return c.Transport
}
