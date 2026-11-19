package onedriveauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// Refresh grant sentinels. Like the exchange sentinels each one is a fixed text
// that carries no client ID, tenant, scope, token, request form, endpoint or
// provider body, and none borrows the authorization-code wording. Each is
// returned together with its base classification when the failure has one, so
// errors.Is keeps working with both. None says the refresh token was invalid:
// the request may or may not have reached the provider.
var (
	// ErrRefreshInput reports a malformed TokenRefreshConfig or an empty or
	// malformed old refresh token. It is returned before any request, and
	// the caller's refresh token was neither sent nor modified. It describes
	// only those pre-send input failures; a cancellation, status, unknown or
	// response failure carries its own refresh sentinel instead.
	ErrRefreshInput = errors.New("onedrive auth: invalid refresh request input; no request was made")
	// ErrRefreshCancelled reports that the caller's context was already
	// done before the refresh request was sent. No request was made.
	ErrRefreshCancelled = errors.New("onedrive auth: token refresh cancelled before sending; no request was made")
	// ErrRefreshOutcomeUnknown reports that the refresh request was sent but
	// this call got no usable answer, including a transport error, a
	// cancellation or the bound once it was sent. The provider may have
	// rotated or revoked the old refresh token, so neither it nor the new
	// state is known. The request is not retried.
	ErrRefreshOutcomeUnknown = errors.New("onedrive auth: token refresh outcome unknown; the provider may have rotated the stored refresh token; do not retry")
	// ErrRefreshStatus reports a refresh answer with a status other than
	// 200. The provider body is discarded; the stored refresh token may have
	// been rotated, and the request is not retried.
	ErrRefreshStatus = errors.New("onedrive auth: token refresh endpoint returned a non-success status; the stored refresh token may have been rotated; do not retry")
	// ErrRefreshResponse reports a refresh answer that is not a bounded JSON
	// object, or that lacks exactly one usable bearer access token and
	// lifetime. Nothing of it is returned, including any new refresh token,
	// and the request is not retried.
	ErrRefreshResponse = errors.New("onedrive auth: malformed or unusable token refresh response; nothing was returned; do not retry")
)

// refreshKind returns the refresh-specific fixed sentinel of one base
// classification, so a caller sees no exchange wording and, for every
// post-send kind, no transport text either. Status is reported as
// ErrRefreshStatus even for a non-JSON error answer, and every malformed,
// oversized or unreadable body as ErrRefreshResponse. The input kind applies
// only to the pre-send ErrRequest.
func refreshKind(base error) error {
	switch base {
	case ErrRequest:
		return ErrRefreshInput
	case ErrCancelled:
		return ErrRefreshCancelled
	case ErrOutcomeUnknown:
		return ErrRefreshOutcomeUnknown
	case ErrProviderStatus:
		return ErrRefreshStatus
	case ErrContentType, ErrOversized, ErrTokenResponse, ErrTokenMissing:
		return ErrRefreshResponse
	}
	return nil
}

// refreshKinds maps an error the shared runner classified for the refresh grant
// to its refresh sentinel: it finds the original base classification with is,
// which tokenRun answers with errors.Is over the original error, and returns the
// refresh peer wrapped over the whole original error, so errors.Is keeps
// matching both the refresh sentinel and the base kind and the message never
// includes either base text. Anything else is returned unchanged. It is the
// classifier of the refresh run.
func refreshKinds(err error, is func(error) error) error {
	if err == nil {
		return nil
	}
	bases := []error{
		ErrCancelled,
		ErrOutcomeUnknown,
		ErrProviderStatus,
		ErrContentType,
		ErrOversized,
		ErrTokenResponse,
		ErrTokenMissing,
		ErrRequest,
	}
	for _, base := range bases {
		if is(base) != nil {
			return refreshClassified{own: refreshKind(base), base: err}
		}
	}
	return err
}

// TokenRefreshConfig is the caller-supplied half of one Microsoft v2
// refresh-token grant (RFC 6749 section 6) for this public client. There are no
// defaults: ClientID and Tenant are required and validated.
type TokenRefreshConfig struct {
	// ClientID is the application (client) ID of the public client that got
	// the refresh token. No client secret exists or is ever sent.
	ClientID string
	// Tenant is a single path segment, as for TokenExchangeConfig; the token
	// endpoint is /{tenant}/oauth2/v2.0/token on the fixed official host.
	Tenant string
	// Scopes is optional. When nil or empty, the optional scope field is
	// omitted from the request and the provider reissues the scopes of the
	// original consent. When non-empty, every scope is validated and sent
	// exactly as listed, joined with single spaces, and must be a subset or
	// the equivalent of what was consented to. This package never adds a
	// scope, and never adds offline_access.
	Scopes []string
}

// RefreshAccessToken performs one refresh-token grant at the Microsoft identity
// platform v2 token endpoint of cfg's tenant, using cfg's client ID and
// oldRefreshToken.
//
// The form carries exactly client_id, grant_type=refresh_token and
// refresh_token, plus scope only when cfg.Scopes is non-empty; it never carries
// a client_secret or any other member. The request is a single POST that is
// never retried, over verified TLS to the fixed official host only, with
// redirects, proxies and HTTP/2 refused; the response is bounded and the call
// returns no later than timeout (or TokenExchangeTimeout when non-positive or
// larger) after the request is sent. The caller's oldRefreshToken bytes are
// read, never modified or cleared.
//
// Cancellation is classified honestly. A nil ctx means context.Background(). If
// ctx is already done, the call returns ErrRefreshCancelled and sends nothing.
// Once the request is sent, a transport error, cancellation or timeout returns
// ErrRefreshOutcomeUnknown: the provider may have rotated the old token.
//
// Provider semantics: a successful answer may omit refresh_token, in which case
// the result carries none and the caller must keep its stored value; the
// provider docs note a new one is usually returned. A replacement is exposed
// only after the complete answer validated. A refresh_token that is present but
// malformed fails the whole answer. Nothing is persisted by this package.
//
// Every failure returns a zero TokenResult and one of the refresh-specific fixed
// sentinels, wrapped with its base kind when it has one, so no error carries the
// old token, the new tokens, the form or the provider body. A success returns
// only the transient TokenResult, with the access token, its lifetime and, only
// when the provider returned a valid one, the replacement refresh token; Close
// it once the tokens are no longer needed.
func RefreshAccessToken(ctx context.Context, cfg TokenRefreshConfig, oldRefreshToken []byte, timeout time.Duration) (TokenResult, error) {
	return refreshAccessToken(ctx, cfg, oldRefreshToken, timeout, nil, nil)
}

// refreshAccessToken is RefreshAccessToken with the test-only endpoint/client
// seam shared with exchangeCode. Both are nil in production. oldRefreshToken is
// only read: nothing here writes to its bytes.
func refreshAccessToken(ctx context.Context, cfg TokenRefreshConfig, oldRefreshToken []byte, timeout time.Duration, endpoint *url.URL, client *http.Client) (TokenResult, error) {
	form, err := refreshForm(cfg, oldRefreshToken)
	if err != nil {
		return TokenResult{}, err
	}
	return tokenRun(ctx, cfg.Tenant, form, timeout, endpoint, client, nil, refreshKinds)
}

// refreshForm builds the refresh grant form and validates every input before
// any request. It returns only the fixed input sentinels. The old refresh token
// is parsed as a visible-ASCII form value and sent as a copy in the encoded form;
// its bytes are not modified.
func refreshForm(cfg TokenRefreshConfig, oldRefreshToken []byte) (string, error) {
	if _, err := validClientID(cfg.ClientID); err != nil {
		return "", refreshInput(err)
	}
	if _, err := validTenant(cfg.Tenant); err != nil {
		return "", refreshInput(err)
	}
	// Only a nil or empty Scopes means "omit": any non-empty list is
	// validated and sent exactly, joined as the authorization request does.
	var scope string
	if len(cfg.Scopes) != 0 {
		s, err := joinScopes(cfg.Scopes)
		if err != nil {
			return "", refreshInput(err)
		}
		scope = s
	}
	token, err := refreshTokenValue(oldRefreshToken)
	if err != nil {
		return "", err
	}
	v := url.Values{}
	v.Set("client_id", cfg.ClientID)
	if scope != "" {
		v.Set("scope", scope)
	}
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", token)
	return v.Encode(), nil
}

// refreshTokenValue validates the caller's old refresh token and returns it as a
// string for the form. It is the format the OS store accepts: non-empty, at most
// maxRefreshTokenLen bytes, and visible ASCII only. The caller's slice is not
// modified.
func refreshTokenValue(old []byte) (string, error) {
	if !validRefreshToken(old) {
		return "", wrap(ErrRefreshInput, nil)
	}
	return string(old), nil
}

// refreshInput returns ErrRefreshInput wrapped over a pre-send validation error,
// so the error reads exactly as the input sentinel, keeps its base
// classification through err, and never formats the base text. err is nil for
// the old refresh token, whose only classification is ErrRefreshInput itself.
func refreshInput(err error) error {
	if err == nil {
		return ErrRefreshInput
	}
	return refreshClassified{own: ErrRefreshInput, base: err}
}

// refreshClassified keeps a classified error's place in the errors.Is tree while
// formatting as exactly the refresh sentinel, never the base exchange wording.
type refreshClassified struct {
	own  error
	base error
}

// Error is exactly the refresh sentinel text; the base text is never formatted.
func (e refreshClassified) Error() string { return e.own.Error() }

// Unwrap exposes both classifications for errors.Is and errors.As: the refresh
// sentinel and the original base error.
func (e refreshClassified) Unwrap() []error { return []error{e.own, e.base} }
