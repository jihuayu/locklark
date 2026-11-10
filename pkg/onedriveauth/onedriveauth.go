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
//
// Scope. This package only receives and validates the callback. It does not
// build or open authorization URLs, perform token exchange or refresh, call
// Microsoft Graph, Opendal or any account, upload or share files, and makes no
// account-capability claims. The authorization code is returned to the caller
// as data for a later, separate token exchange; it is never logged by this
// package and is absent from every error and HTTP response. Because the code
// lives in an unexported field, the common fmt formatting verbs print a fixed
// redacted placeholder; the caller must still avoid exporting or marshalling
// it into logs.
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
