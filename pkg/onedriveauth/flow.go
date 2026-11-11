package onedriveauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// CallbackPath is the only path the loopback redirect listener answers on. It
// is fixed at compile time; the port is always chosen by the OS and never
// hard-coded, so a stale registration or another local process cannot predict
// the redirect_uri of a run.
const CallbackPath = "/oauth/native/callback"

// The loopback redirect_uri therefore has the public-client "localhost" form
//
//	http://127.0.0.1:<ephemeral-port>/oauth/native/callback
//
// where both the host and the path are package constants and the port comes
// from the bound socket (see Callback.RedirectURI).
const (
	LoopbackHost    = "127.0.0.1"
	LoopbackBaseURL = "http://" + LoopbackHost
)

// abortGrace bounds how long Wait may wait for the listener to stop accepting
// connections after an abort, or for a client that won the race to finish
// writing its page. That step only records the outcome, writes a page that was
// already decided and closes the listener, so the bound is a backstop against a
// wedged implementation or a stalled peer, not a network wait.
const abortGrace = 500 * time.Millisecond

// redacted is the only text CallbackResult ever formats to. It must not
// contain, name or hint at the code.
const redacted = "onedriveauth.CallbackResult{code:redacted}"

// CallbackResult is the outcome of one validated authorization callback. It is
// the only carrier of the authorization code: the next, separate step (token
// exchange, not implemented here) takes Code together with the verifier whose
// S256 challenge was sent in the authorization request.
//
// The code is a credential held in an unexported field. It is readable only
// through Code(), and String/GoString exist so that the common fmt verbs (%v,
// %+v, %#v, %s, %q, %x) print a fixed placeholder instead of the code. The
// struct is deliberately not one of the fmt.Formatters that fmt would print
// field by field; reflection-based marshallers of the struct are outside that
// guarantee, so callers must not marshal the result into logs. fmt also uses
// these methods for a pointer to the result, for elements of slices and maps,
// and for an embedded struct value (one level deep).
type CallbackResult struct {
	// code is never exported: an exported field would be printed verbatim
	// by %v and %+v.
	code string
}

// Code returns the authorization code for the token exchange. Every non-nil
// result carries exactly one code; a zero result has none. Treat the returned
// value as a credential: do not log it, and do not place it in errors or pages.
func (r CallbackResult) Code() string {
	return r.code
}

// String implements fmt.Stringer and masks the code.
func (r CallbackResult) String() string {
	return redacted
}

// GoString implements fmt.GoStringer and masks the code even for %#v.
func (r CallbackResult) GoString() string {
	return redacted
}

// Callback is a single-use loopback listener bound to one authorization
// request. It verifies the provider's redirect and delivers the authorization
// code once; it never exchanges the code and never stores the verifier.
//
// Errors returned by Wait are sentinels from this package and are safe to log:
// they never contain the request query, state, verifier, code, client
// identifiers or the redirect URI.
type Callback struct {
	// ctx is derived from the Start context (and Start's timeout). Its
	// cancellation aborts the whole flow.
	ctx    context.Context
	cancel context.CancelFunc

	server   *http.Server
	listener net.Listener
	state    string
	watch    func() bool

	// mu guards out and closed. out is the zero value until the first final
	// outcome, which is never replaced.
	mu     sync.Mutex
	out    outcome
	closed bool
	// stopOnce releases the listener exactly once, whichever of settle and
	// Wait gets there first. After it runs, no new connection is accepted.
	stopOnce sync.Once

	// done is closed once an outcome is settled and the listener no longer
	// accepts connections; Wait then returns the settled outcome. A later
	// Shutdown of the idle connections runs in the background and cannot
	// change it.
	done     chan struct{}
	doneOnce sync.Once
	// endOnce runs finalize exactly once.
	endOnce sync.Once
}

// outcome is the first final result of the flow. For a callback that settled
// it rsp is the definitive page, which only the request that recorded the
// outcome (the winner) may write; every other request gets a rejection.
type outcome struct {
	settled bool
	code    string
	err     error
	rsp     *response
}

// response is the definitive page for an outcome.
type response struct {
	status int
	body   string
}

// startCallback binds an IPv4 loopback ephemeral port, answers redirects on
// CallbackPath only, and begins verifying the callback against state. ctx must
// be non-nil; cancel releases it once the listener is closed. The listener is
// closed when ctx is done or the flow settles.
func startCallback(ctx context.Context, cancel context.CancelFunc, state string) (*Callback, error) {
	ln, err := net.Listen("tcp4", LoopbackHost+":0")
	if err != nil {
		return nil, wrap(ErrListener, err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() || addr.IP.To4() == nil || addr.Port <= 0 {
		_ = ln.Close()
		return nil, wrap(ErrListener, nil)
	}
	c := &Callback{
		ctx:      ctx,
		cancel:   cancel,
		listener: ln,
		state:    state,
		done:     make(chan struct{}),
	}
	c.server = &http.Server{
		Handler:           c,
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       requestTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       requestTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	// One hook for both the caller's context and Start's timeout: it marks
	// the flow aborted and closes the listener so a late callback cannot be
	// accepted, even if Wait is never called.
	c.watch = context.AfterFunc(ctx, func() {
		c.settle("", wrap(ErrTimeout, ctx.Err()), nil)
	})
	go func() {
		err := c.server.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.settle("", wrap(ErrListener, err), nil)
		}
	}()
	return c, nil
}

// RedirectURI returns the loopback redirect URI for this run. It names
// 127.0.0.1 and the ephemeral port the listener actually holds.
func (c *Callback) RedirectURI() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return "", wrap(ErrState, nil)
	}
	addr, ok := c.listener.Addr().(*net.TCPAddr)
	if !ok {
		return "", wrap(ErrState, nil)
	}
	return LoopbackBaseURL + ":" + strconv.Itoa(addr.Port) + CallbackPath, nil
}

// Wait blocks until the callback is verified, rejected, the Start context is
// done, ctx is cancelled, or timeout elapses (when positive), whichever comes
// first. On success it returns the
// structured result exactly once. Every other return yields the zero result and
// a sentinel error; it never exposes request data.
//
// A nil ctx is treated as context.Background(). After the first final outcome,
// Wait returns that outcome again: a later callback cannot replace it. In every
// case the listener has stopped accepting connections before Wait returns, so
// no late callback can be accepted.
func (c *Callback) Wait(ctx context.Context, timeout time.Duration) (CallbackResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var expiry <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		expiry = timer.C
	}
	select {
	case <-c.done:
		return c.result()
	case <-expiry:
		return c.abort(wrap(ErrTimeout, nil))
	case <-ctx.Done():
		return c.abort(wrap(ErrTimeout, ctx.Err()))
	case <-c.ctx.Done():
		return c.abort(wrap(ErrTimeout, c.ctx.Err()))
	}
}

// abort settles the flow as aborted unless an outcome already exists, then
// returns within abortGrace even if the listener cannot be closed or a settled
// page cannot be written.
func (c *Callback) abort(err error) (CallbackResult, error) {
	c.settle("", err, nil)
	select {
	case <-c.done:
		return c.result()
	case <-time.After(abortGrace):
		// Wait still returns the settled outcome; the page the winner
		// could not write no longer holds it back.
		c.stopListening()
		return c.result()
	}
}

func (c *Callback) result() (CallbackResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.out.settled {
		return CallbackResult{}, wrap(ErrTimeout, nil)
	}
	if c.out.code == "" {
		return CallbackResult{}, c.out.err
	}
	return CallbackResult{code: c.out.code}, nil
}

// settle records an outcome that has no page of its own, which every later
// call cannot replace; it reports whether this call recorded it. The listener
// stops accepting connections and done is closed before settle returns.
func (c *Callback) settle(code string, err error, rsp *response) bool {
	return c.settleWith(func() outcome {
		return outcome{settled: true, code: code, err: err, rsp: rsp}
	})
}

// settleWith records the outcome build returns unless one is already settled.
// build runs under mu and must not echo request data into the outcome. It
// reports whether this call recorded the outcome, and that request is then the
// only one responsible for the outcome's page.
//
// The flow is final, and done is closed, once that page was written and the
// listener stopped accepting connections. An outcome without a page is
// final in the same call.
func (c *Callback) settleWith(build func() outcome) bool {
	c.mu.Lock()
	if c.out.settled {
		c.mu.Unlock()
		return false
	}
	c.out = build()
	page := c.out.rsp != nil
	c.mu.Unlock()
	if !page {
		c.finalize()
	}
	return true
}

// deliver writes the recorded outcome's page, if it has one, and then makes
// the flow final so Wait can return it. It is called by the request that
// recorded the outcome after its page was written or failed to be written.
func (c *Callback) deliver(w http.ResponseWriter) {
	c.mu.Lock()
	rsp := c.out.rsp
	c.mu.Unlock()
	if rsp != nil {
		writePage(w, rsp.status, rsp.body)
	}
	c.finalize()
}

// finalize stops the listener, releases the context hook and reports the flow
// done, exactly once, so Wait can return the settled outcome. The idle
// connections are drained in the background: that drain cannot change the
// outcome and can outlast the request that ended the flow.
func (c *Callback) finalize() {
	c.endOnce.Do(func() {
		c.stopListening()
		if c.watch != nil {
			c.watch()
		}
		c.closeDone()
		go c.drain()
	})
}

// drain releases whatever http.Server still holds once the listener is
// closed. It never waits longer than shutdownGrace, and Shutdown never cuts the
// connection whose handler is writing a page: it closes idle connections and
// lets active ones finish, unlike Close.
func (c *Callback) drain() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = c.server.Shutdown(ctx)
	c.cancel()
}

// stopListening stops the listener accepting new connections. It is
// idempotent and does not block; connections already accepted keep being
// served.
func (c *Callback) stopListening() {
	c.stopOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		_ = c.listener.Close()
	})
}

// close finalizes the flow with an abort if no outcome was settled yet, then
// releases the server in the background. It is idempotent and never blocks on
// an HTTP shutdown.
func (c *Callback) close() {
	c.stopListening()
	if c.settleWith(func() outcome { return outcome{settled: true, err: wrap(ErrTimeout, nil)} }) {
		<-c.done
	}
}

// closeDone closes done exactly once.
func (c *Callback) closeDone() {
	c.doneOnce.Do(func() { close(c.done) })
}

// rejected reports a fixed rejection page without settling the flow, so the
// session stays usable by the legitimate callback.
func (c *Callback) rejected(w http.ResponseWriter) {
	writePage(w, http.StatusBadRequest, pageRejected)
}

// ServeHTTP implements the redirect endpoint. The response body is always a
// fixed page; nothing from the request is echoed.
//
// Exactly two shapes are accepted: state + a non-empty valid code, or state +
// a non-empty error with at most one optional error_description. Every other
// request is rejected without consuming the session, including a query that
// does not parse, a missing, empty, repeated or extra parameter, a code
// together with an error, or a code with an error_description.
//
// Only the request that records the outcome (the winner) writes that outcome's
// page; its page is written before Wait returns. Requests that were admitted
// concurrently but lost the race, and every callback handled after the flow
// settled, get the fixed rejection page and cannot replace the outcome Wait
// returns.
func (c *Callback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query, ok := c.callbackQuery(w, r)
	if !ok {
		return
	}
	var settle func() outcome
	if query.Has("code") {
		code := query.Get("code")
		settle = func() outcome {
			return outcome{settled: true, code: code, rsp: &response{status: http.StatusOK, body: pageAuthorized}}
		}
	} else {
		// Record a stable reason only; the provider's error code and
		// error_description are untrusted and are neither retained nor
		// echoed. The winner of this form gets the same fixed rejection
		// page as the loser.
		settle = func() outcome {
			return outcome{settled: true, err: wrap(ErrProvider, nil), rsp: &response{status: http.StatusBadRequest, body: pageRejected}}
		}
	}
	// settleWith is the only gate: exactly one competing request wins and
	// writes the outcome's page, before Wait returns.
	if !c.settleWith(settle) {
		c.rejected(w)
		return
	}
	c.deliver(w)
}

// callbackQuery enforces the transport the redirect must arrive on and the
// shape of its query, and returns the validated query of an admitted callback.
// It writes the rejection page and returns false otherwise, without settling
// the flow, so a probe, a mismatched state, a malformed callback or a replay
// cannot consume the session.
func (c *Callback) callbackQuery(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if !c.admitted(w, r) {
		return nil, false
	}
	// The query is parsed again, from the raw request target, so a query
	// with a syntax error (for example a bad percent escape) is rejected as
	// a whole instead of being consumed by the parameters that parsed.
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || query == nil {
		c.rejected(w)
		return nil, false
	}
	if !c.matchesState(query.Get("state")) {
		c.rejected(w)
		return nil, false
	}
	// A callback that was admitted before the outcome settled, but asks
	// about a settled flow, loses here: the outcome is never reopened.
	if !c.ready() {
		c.rejected(w)
		return nil, false
	}
	return query, true
}

// ready reports whether the flow may still settle.
func (c *Callback) ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.out.settled
}

// admitted enforces the transport the redirect must arrive on and the shape of
// its query: GET in origin-form over a loopback connection, the exact
// 127.0.0.1:port this run bound, the exact path, and exactly one of the two
// accepted shapes:
//
//   - state, with a single non-empty well-formed code and nothing else;
//   - state and a single non-empty error, with at most one error_description.
//
// A query with a syntax error, a missing, empty or repeated parameter, a
// parameter outside this set, or a mixed code and error fails. The state value itself is compared by the
// caller. It writes the rejection page itself and returns false when the
// request is not admitted.
func (c *Callback) admitted(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.URL == nil {
		c.rejected(w)
		return false
	}
	// Go's server sets RequestURI to the raw origin-form target it parsed;
	// an absolute-form target (proxy style) or an empty one is not a browser
	// redirect.
	if r.Method != http.MethodGet || r.RequestURI == "" || r.RequestURI[0] != '/' {
		c.rejected(w)
		return false
	}
	// An absolute URI in the request line also fills URL.Host; a valid
	// loopback callback never carries it.
	if r.URL.Host != "" || r.URL.Scheme != "" || r.URL.Opaque != "" {
		c.rejected(w)
		return false
	}
	if r.URL.Path != CallbackPath || r.URL.RawPath != "" {
		c.rejected(w)
		return false
	}
	// r.Host is the Host header, exactly what the peer addressed; it must
	// be the 127.0.0.1:port this run bound. r.URL.Host is empty for an
	// origin-form request line, so it is never the comparison target.
	if !c.matchesRequestHost(r.Host) || !isLoopbackRemote(r.RemoteAddr) {
		c.rejected(w)
		return false
	}
	// Query parsing stays here for the parameter shape; a syntax error is
	// rejected by callbackQuery before the state is compared.
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		c.rejected(w)
		return false
	}
	for key, values := range query {
		switch key {
		case "state", "code", "error", "error_description":
			if len(values) != 1 {
				c.rejected(w)
				return false
			}
		default:
			c.rejected(w)
			return false
		}
	}
	if len(query["state"]) != 1 {
		c.rejected(w)
		return false
	}
	hasCode := query.Has("code")
	hasError := query.Has("error")
	switch {
	case hasCode && !hasError:
		// A code form carries nothing but the code. An empty, oversized
		// or non-ASCII code is never valid. The session is not consumed,
		// so the legitimate callback can still arrive.
		if query.Has("error_description") || !validCode(query.Get("code")) {
			c.rejected(w)
			return false
		}
		return true
	case hasError && !hasCode:
		// A provider error form carries a non-empty error and at most
		// one error_description, which it reduces to ErrProvider.
		if !validErrorCode(query.Get("error")) {
			c.rejected(w)
			return false
		}
		return true
	default:
		// Neither form, or a code and an error together, is ambiguous.
		c.rejected(w)
		return false
	}
}

// matchesRequestHost reports whether host is exactly 127.0.0.1:<bound port>.
func (c *Callback) matchesRequestHost(host string) bool {
	addr, ok := c.listener.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return false
	}
	if host != LoopbackHost+":"+strconv.Itoa(addr.Port) {
		return false
	}
	h, p, err := net.SplitHostPort(host)
	return err == nil && h == LoopbackHost && p == strconv.Itoa(addr.Port)
}

// isLoopbackRemote reports whether remoteAddr is a loopback TCP peer.
func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// matchesState compares the callback state with the run's state in constant
// time. Length is compared first because ConstantTimeCompare returns early on
// unequal lengths; the length of a random state is not a secret.
func (c *Callback) matchesState(got string) bool {
	if len(got) != len(c.state) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.state)) == 1
}

// validCode accepts a single non-empty, bounded authorization code from the
// RFC 6749 vschar set (%x20-7E except SP) that can be echoed into a form body.
func validCode(code string) bool {
	return validCallbackToken(code)
}

// validErrorCode accepts a single non-empty bounded provider error code from
// the same set. Its value is never retained or echoed; the check only keeps an
// empty "error=" from being read as a provider refusal.
func validErrorCode(code string) bool {
	return validCallbackToken(code)
}

// validCallbackToken reports whether v is a non-empty bounded RFC 6749
// vschar token: printable ASCII without SP. Callers must not echo v.
func validCallbackToken(v string) bool {
	if v == "" || len(v) > maxCodeLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// writePage writes a fixed English page. It sets headers explicitly so the
// response cannot be framed, cached, or rendered as attacker content, and it
// sets the Content-Length the success path relies on to flush a complete
// response before the listener is released.
func writePage(w http.ResponseWriter, status int, body string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

const pageAuthorized = `<!doctype html>
<title>Sign-in complete</title>
<p>Sign-in complete. You can close this window and return to the application.</p>
`

const pageRejected = `<!doctype html>
<title>Sign-in failed</title>
<p>Sign-in failed or was already completed. Return to the application to try again.</p>
`
