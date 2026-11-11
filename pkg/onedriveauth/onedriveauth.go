// Package onedriveauth implements the local half of a native desktop OAuth
// 2.0 authorization code flow with PKCE and state, for a public client that
// hands the authorization to the system browser:
//
//   - NewVerifier/NewState draw high-entropy random values from the system
//     CSPRNG; S256 derives the RFC 7636 S256 code challenge.
//   - Start opens a one-shot HTTP listener on an IPv4 loopback ephemeral port
//     and returns the exact http://127.0.0.1:<port>/oauth/native/callback
//     redirect URI to embed in the authorization request. There is no client
//     secret anywhere in this flow.
//   - Wait returns a CallbackResult only after the callback arrived on GET, at
//     the exact host, port and path, with exactly one matching state
//     (constant-time comparison) and either one well-formed code or the
//     provider's error parameter. The code is read with CallbackResult.Code()
//     and never appears in any text CallbackResult formats to. Anything else
//     is rejected and yields a fixed response page and a redacted sentinel
//     error.
//   - A successful callback writes the fixed success page and only then closes
//     the listener, so the page reaches the browser before the port goes away.
//     A cancellation or timeout closes the listener before Wait returns.
//   - AuthorizationURL builds the public-client v2 /authorize URL for one run
//     from the caller's client ID, tenant, explicit scopes and verifier, and
//     the redirect URI and state read from that same Callback. It never
//     contains a client secret, verifier or token, and the caller must not
//     log it.
//   - ExchangeCode redeems that code once: one POST of the authorization-code
//     form (client_id, scope, code, redirect_uri, grant_type and
//     code_verifier, never a client secret) to
//     https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token with the
//     exact loopback redirect URI Start captured. It returns only a transient
//     TokenResult (redacted when formatted) holding the access token and its
//     lifetime and, when the provider returned one, the refresh token; that
//     token exists only when the caller's explicit scopes include
//     offline_access, so no scope is added by default. id_token and every other
//     response member are discarded. Cancellation before sending is reported
//     as ErrCancelled with no request. After sending, a transport error,
//     cancellation or timeout is ErrOutcomeUnknown, and each response failure
//     has its own fixed sentinel; all of them say the code may be consumed, and
//     nothing is retried.
//
// Scope. This package receives and validates the callback, builds the
// authorization URL, but never opens it, and performs at most one token
// exchange per call. It does not refresh tokens, persist, store or reuse tokens
// or the code, call Microsoft Graph, Opendal or any account, upload or share
// files, and makes no account-capability claims. There is no default tenant,
// account or scope configuration: the caller supplies the client ID, tenant and
// explicit scopes. TokenResult may retain the access and refresh tokens in
// memory only, until the caller calls TokenResult.Close, which zeroizes the
// buffers shared by every copy of the result, as far as this package holds
// them; copies returned by its accessors are owned by the caller and must be
// cleared or dropped by it (a RefreshToken []byte can be cleared; an
// AccessToken string cannot be zeroized and can only be dropped). Before
// ExchangeCode returns, on success and on every parse failure, it clears the
// bounded response body buffer and the temporary json.RawMessage buffers used
// for members other than the tokens; the token members are decoded by the
// package's byte Unmarshaler into owned buffers, and internal copies made by
// encoding/json or the runtime are not guaranteed to be wiped.
// The authorization code and the tokens are returned to the caller as data and
// are never logged, persisted or included in any error or HTTP response by this
// package. Because they live in unexported fields, the common fmt formatting
// verbs print a fixed redacted placeholder; the caller must still avoid
// exporting or marshalling them into logs.
//
// The callback validation rules follow RFC 8252 (OAuth 2.0 for Native Apps):
// the redirect uses a literal loopback IP address, a dynamic port, and the
// http scheme, which the system browser can follow without a custom scheme.
// Loopback redirects are interceptable by other local processes in principle,
// which is why PKCE and exact state matching are mandatory here.
package onedriveauth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultTimeout bounds Start when the caller passes a non-positive timeout.
const DefaultTimeout = 10 * time.Minute

// Tunables for the loopback listener. They bound how long a stuck client, a
// flood of bytes, or a shutdown can hold resources; none is a security
// parameter.
const (
	headerTimeout  = 5 * time.Second
	requestTimeout = 10 * time.Second
	shutdownGrace  = 2 * time.Second
	maxHeaderBytes = 16 << 10
	maxCodeLen     = 4096
)

// Sentinel errors classify every failure. Callers test them with errors.Is.
// They never carry the callback query, state, verifier, code, client
// identifiers or redirect URI; underlying library errors are flattened away.
var (
	// ErrRandom reports that the system CSPRNG failed; nothing was generated.
	ErrRandom = errors.New("onedrive auth: random source failed")
	// ErrState reports an invalid state/verifier input to Start, a callback
	// whose state parameter does not match this run, or a wait with no
	// pending callback.
	ErrState = errors.New("onedrive auth: callback state mismatch")
	// ErrProvider reports a callback that carried the provider's error
	// parameter. The provider's error code and description are not retained.
	ErrProvider = errors.New("onedrive auth: authorization was not granted")
	// ErrMalformed reports a callback with a missing, duplicated or
	// malformed code, repeated parameters or unexpected parameters.
	ErrMalformed = errors.New("onedrive auth: malformed callback")
	// ErrListener reports that the loopback listener could not be opened or
	// failed while serving.
	ErrListener = errors.New("onedrive auth: callback listener failed")
	// ErrTimeout reports that the context was cancelled or the wait expired
	// before a valid callback arrived.
	ErrTimeout = errors.New("onedrive auth: callback not received in time")
	// ErrClientID reports an empty or malformed ClientID passed to
	// AuthorizationURL.
	ErrClientID = errors.New("onedrive auth: invalid client ID")
	// ErrTenant reports an empty or malformed Tenant, or one that is unsafe
	// as an authorization endpoint path segment.
	ErrTenant = errors.New("onedrive auth: invalid tenant")
	// ErrScope reports missing, too many, or malformed explicit Scopes.
	ErrScope = errors.New("onedrive auth: invalid scope")
	// ErrVerifier reports a verifier that is not well formed.
	ErrVerifier = errors.New("onedrive auth: invalid PKCE verifier")
	// ErrCallback reports a missing or unusable Callback passed to
	// AuthorizationURL.
	ErrCallback = errors.New("onedrive auth: callback unavailable")
)

// Start binds a fresh IPv4 loopback listener for one authorization request and
// returns its single-use Callback. state must be a value from NewState for this
// request; the caller sends it in the authorization request and must not log
// it. The listener closes when ctx is done, Wait returns, or the callback is
// handled.
//
// timeout bounds how long the callback may stay open; it defaults to
// DefaultTimeout when non-positive. It can be shortened per Wait call.
func Start(ctx context.Context, state string, timeout time.Duration) (*Callback, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !ValidState(state) {
		return nil, wrap(ErrState, nil)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	// The callback owns this cancel function and calls it exactly once
	// when it closes, so the timer and parent registration are released
	// whether the flow succeeds, fails or is abandoned.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	c, err := startCallback(ctx, cancel, state)
	if err != nil {
		cancel()
		return nil, err
	}
	return c, nil
}

// wrap attaches an opaque reason for errors.Is without copying any input. The
// detail is nil or a library error whose text is local and parameter-free; it
// is deliberately not formatted into the message.
func wrap(sentinel error, _ error) error {
	return fmt.Errorf("%w", sentinel)
}
