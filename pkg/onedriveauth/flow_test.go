package onedriveauth

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Failures in this file never print a callback URL, query, state or code: a
// failed assertion names the case and the observed status or sentinel only.
// That sentinel-free wording is deliberate so a failing run cannot leak a
// credential into CI logs.
const (
	// The authorization code used by the tests. It is recognizable so the
	// leak checks can search for it in pages and errors.
	testCode = "0.AAAA-test-code-with-distinctive-marker-9f3c"
	// testErrorDescription is a provider error_description that must never
	// surface in any error, page or formatted result.
	testErrorDescription = "distinctive-description-must-not-leak-7b2d"
)

// newFlow starts a Callback for a fresh state and returns it with that state.
func newFlow(t *testing.T) (*Callback, string) {
	t.Helper()
	state, err := NewState()
	if err != nil {
		t.Fatalf("NewState failed: %v", err)
	}
	c, err := Start(context.Background(), state, 5*time.Second)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() { c.close() })
	return c, state
}

func target(t *testing.T, c *Callback) string {
	t.Helper()
	uri, err := c.RedirectURI()
	if err != nil {
		t.Fatalf("RedirectURI failed: %v", err)
	}
	return uri
}

// get sends a GET to the callback listener with a fresh standard client.
func get(t *testing.T, rawURL string) (int, string) {
	t.Helper()
	client := &http.Client{
		Timeout: 3 * time.Second,
		// Never reuse a connection, so a replay is a new TCP exchange.
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("building request failed (details withheld)")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed to complete (details withheld)")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		t.Fatalf("reading response failed (details withheld)")
	}
	return resp.StatusCode, string(body)
}

// getDirect sends a GET to the callback listener through a raw TCP
// connection and reads the response with net/http, so the Host header can be
// chosen independently of the address. A transport failure is returned as an
// error, whose text is withheld from failure messages.
func getDirect(t *testing.T, addr, pathAndQuery, hostHeader string) (int, string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return 0, "", err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET " + pathAndQuery + " HTTP/1.1\r\nHost: " + hostHeader +
		"\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return 0, "", err
	}
	br := bufio.NewReader(io.LimitReader(conn, 256<<10))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return 0, "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	_ = conn.Close()
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}

func withQuery(t *testing.T, base string, q url.Values) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing redirect URI failed")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// waitResult runs Wait in the background and returns a channel with its result,
// so a test can assert on rejection without blocking.
func waitResult(ctx context.Context, c *Callback, timeout time.Duration) <-chan struct {
	res CallbackResult
	err error
} {
	ch := make(chan struct {
		res CallbackResult
		err error
	}, 1)
	go func() {
		res, err := c.Wait(ctx, timeout)
		ch <- struct {
			res CallbackResult
			err error
		}{res, err}
	}()
	return ch
}

func recv(t *testing.T, ch <-chan struct {
	res CallbackResult
	err error
}, within time.Duration) (CallbackResult, error) {
	t.Helper()
	select {
	case r := <-ch:
		return r.res, r.err
	case <-time.After(within):
		t.Fatalf("Wait did not return within the bound")
		return CallbackResult{}, nil
	}
}

// assertStillPending checks that Wait has not returned yet.
func assertStillPending(t *testing.T, ch <-chan struct {
	res CallbackResult
	err error
}) {
	t.Helper()
	select {
	case r := <-ch:
		_ = r
		t.Fatalf("flow settled on a request that must be rejected")
	default:
	}
}

// fireConcurrent sends one GET per query concurrently, each over its own TCP
// connection, released together by a barrier, and returns the observed status
// of each (0 when no reply arrived). It never reports through t from a
// goroutine, so a failing assertion leaves no blocked writer behind.
func fireConcurrent(base string, queries []url.Values) (statuses []int, bodies []string) {
	statuses = make([]int, len(queries))
	bodies = make([]string, len(queries))
	var wg, barrier sync.WaitGroup
	barrier.Add(1)
	for i, q := range queries {
		wg.Add(1)
		go func(i int, q url.Values) {
			defer wg.Done()
			barrier.Wait()
			statuses[i], bodies[i] = getStatus(withQueryRaw(base, q))
		}(i, q)
	}
	barrier.Done()
	wg.Wait()
	return statuses, bodies
}

// getStatus is get without t: it returns the status and body of the fixed
// page, or 0 if no reply arrived.
func getStatus(rawURL string) (int, string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Path != CallbackPath) {
		return 0, ""
	}
	conn, err := net.DialTimeout("tcp", u.Host, time.Second)
	if err != nil {
		return 0, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET " + u.RequestURI() + " HTTP/1.1\r\nHost: " + u.Host +
		"\r\nUser-Agent: test\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, ""
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 256<<10)), nil)
	if err != nil {
		return 0, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// withQueryRaw is withQuery without t, for use in goroutines.
func withQueryRaw(base string, q url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// countStatus counts the attempts that received status.
func countStatus(statuses []int, status int) int {
	n := 0
	for _, s := range statuses {
		if s == status {
			n++
		}
	}
	return n
}

func assertHidden(t *testing.T, what, text string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("%s contains a value that must not appear", what)
		}
	}
}

func TestCallbackSuccessPageThenWaitCode(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)

	status, body := get(t, withQuery(t, target(t, c), url.Values{"state": {state}, "code": {testCode}}))
	if status != http.StatusOK {
		t.Fatalf("success callback returned status %d", status)
	}
	if body != pageAuthorized {
		t.Fatalf("success callback did not return the fixed authorized page")
	}
	assertHidden(t, "success page", body, testCode, state)

	res, err := recv(t, ch, time.Second)
	if err != nil {
		t.Fatalf("Wait returned error %v", err)
	}
	if got := res.Code(); got != testCode {
		t.Fatalf("Wait returned an unexpected code (length %d, want %d)", len(got), len(testCode))
	}

	// The listener is closed after the page was written.
	if uri, err := c.RedirectURI(); err == nil || uri != "" {
		t.Fatalf("RedirectURI succeeded after the flow settled")
	}
}

func TestCallbackWrongStateThenCorrectSucceeds(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)

	other, err := NewState()
	if err != nil {
		t.Fatalf("NewState failed")
	}
	status, body := get(t, withQuery(t, target(t, c), url.Values{"state": {other}, "code": {testCode}}))
	if status != http.StatusBadRequest || body != pageRejected {
		t.Fatalf("wrong-state callback returned status %d with an unexpected page", status)
	}
	assertHidden(t, "rejection page", body, testCode, state, other)
	assertStillPending(t, ch)

	// A wrong-state provider error must not settle either.
	status, _ = get(t, withQuery(t, target(t, c), url.Values{
		"state": {other}, "error": {"access_denied"}, "error_description": {testErrorDescription},
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("wrong-state provider error returned status %d", status)
	}
	assertStillPending(t, ch)

	status, body = get(t, withQuery(t, target(t, c), url.Values{"state": {state}, "code": {testCode}}))
	if status != http.StatusOK || body != pageAuthorized {
		t.Fatalf("correct callback after wrong state returned status %d with an unexpected page", status)
	}
	res, err := recv(t, ch, time.Second)
	if err != nil {
		t.Fatalf("Wait returned error %v", err)
	}
	if res.Code() != testCode {
		t.Fatalf("Wait returned an unexpected code after wrong-state attempts")
	}
}

func TestCallbackRejectedRequestsDoNotConsume(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)
	base := target(t, c)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing redirect URI failed")
	}
	hostPort := u.Host
	port := u.Port()

	good := url.Values{"state": {state}, "code": {testCode}}

	cases := []struct {
		name string
		url  string
	}{
		{"wrong path", withQuery(t, LoopbackBaseURL+":"+port+"/oauth/callback", good)},
		{"path prefix", withQuery(t, LoopbackBaseURL+":"+port+CallbackPath+"/x", good)},
		{"wrong host", withQuery(t, "http://localhost:"+port+CallbackPath, good)},
		{"duplicate state", withQuery(t, base, url.Values{"state": {state, state}, "code": {testCode}})},
		{"duplicate code", withQuery(t, base, url.Values{"state": {state}, "code": {testCode, testCode}})},
		{"extra parameter", withQuery(t, base, url.Values{"state": {state}, "code": {testCode}, "scope": {"x"}})},
		{"empty code", withQuery(t, base, url.Values{"state": {state}, "code": {""}})},
		{"error and code", withQuery(t, base, url.Values{"state": {state}, "code": {testCode}, "error": {"access_denied"}})},
		{"state only", withQuery(t, base, url.Values{"state": {state}})},
		{"description only", withQuery(t, base, url.Values{"state": {state}, "error_description": {testErrorDescription}})},
		{"empty error", withQuery(t, base, url.Values{"state": {state}, "error": {""}})},
		{"non-ASCII error", withQuery(t, base, url.Values{"state": {state}, "error": {"denied\u00e9"}})},
		{"duplicate error", withQuery(t, base, url.Values{"state": {state}, "error": {"access_denied", "server_error"}})},
		{"duplicate error_description", withQuery(t, base, url.Values{"state": {state}, "error": {"access_denied"}, "error_description": {testErrorDescription, "x"}})},
		{"error with code and description", withQuery(t, base, url.Values{"state": {state}, "error": {"access_denied"}, "error_description": {testErrorDescription}, "code": {testCode}})},
		{"extra parameter beside error", withQuery(t, base, url.Values{"state": {state}, "error": {"access_denied"}, "scope": {""}})},
		{"empty code beside error", withQuery(t, base, url.Values{"state": {state}, "code": {""}, "error": {"access_denied"}})},
		{"missing state", withQuery(t, base, url.Values{"code": {testCode}})},
		{"no query", base},
	}
	for _, tc := range cases {
		status, body := get(t, tc.url)
		if status != http.StatusBadRequest || body != pageRejected {
			t.Fatalf("%s: status %d with an unexpected page", tc.name, status)
		}
		assertHidden(t, tc.name+" page", body, testCode, state, testErrorDescription)
		assertStillPending(t, ch)
	}

	// The Host header is what the handler checks, independent of the address
	// dialed: the bound host:port is admitted, anything else is rejected.
	goodQuery := CallbackPath + "?" + good.Encode()
	for _, hostHeader := range []string{"example.invalid:" + port, "localhost:" + port, LoopbackHost + ":1"} {
		status, body, err := getDirect(t, hostPort, goodQuery, hostHeader)
		if err != nil {
			t.Fatalf("wrong-Host request (case %d) failed to complete", len(hostHeader))
		}
		if status != http.StatusBadRequest || body != pageRejected {
			t.Fatalf("wrong Host header (case %d) returned status %d", len(hostHeader), status)
		}
		assertHidden(t, "wrong Host page", body, testCode, state)
		assertStillPending(t, ch)
	}

	// Only after every rejection does the legitimate direct callback over real
	// TCP succeed and settle the flow with the real code.
	status, body, err := getDirect(t, hostPort, goodQuery, hostPort)
	if err != nil {
		t.Fatalf("legitimate direct callback failed to complete")
	}
	if status != http.StatusOK || body != pageAuthorized {
		t.Fatalf("legitimate direct callback returned status %d with an unexpected page", status)
	}
	assertHidden(t, "authorized page", body, testCode, state)
	res, err := recv(t, ch, time.Second)
	if err != nil {
		t.Fatalf("Wait returned error %v", err)
	}
	if res.Code() != testCode {
		t.Fatalf("Wait returned an unexpected code after rejections")
	}
}

func TestCallbackProviderErrorIsRedacted(t *testing.T) {
	for _, withDescription := range []bool{false, true} {
		name := "error only"
		if withDescription {
			name = "error with description"
		}
		t.Run(name, func(t *testing.T) {
			c, state := newFlow(t)
			ch := waitResult(context.Background(), c, 0)

			q := url.Values{"state": {state}, "error": {"access_denied"}}
			if withDescription {
				q.Set("error_description", testErrorDescription)
			}
			status, body := get(t, withQuery(t, target(t, c), q))
			if status != http.StatusBadRequest || body != pageRejected {
				t.Fatalf("provider error callback returned status %d with an unexpected page", status)
			}
			assertHidden(t, "provider error page", body, state, testErrorDescription, "access_denied")

			res, err := recv(t, ch, time.Second)
			if !errors.Is(err, ErrProvider) {
				t.Fatalf("Wait did not return ErrProvider (got %v)", err)
			}
			if res.Code() != "" {
				t.Fatalf("Wait returned a code for a provider error")
			}
			text := fmt.Sprintf("%v|%+v|%#v|%s", res, res, res, err)
			assertHidden(t, "provider error text", text, state, testErrorDescription, testCode)
			assertHidden(t, "provider error message", err.Error(), state, testErrorDescription)
		})
	}
}

// TestCallbackCodeFormRejectsErrorDescription: the code form is exactly a
// valid code; an error_description beside it is an extra parameter.
func TestCallbackCodeFormRejectsErrorDescription(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)
	base := target(t, c)
	status, body := get(t, withQuery(t, base, url.Values{
		"state": {state}, "code": {testCode}, "error_description": {testErrorDescription},
	}))
	if status != http.StatusBadRequest || body != pageRejected {
		t.Fatalf("code with error_description returned status %d with an unexpected page", status)
	}
	assertStillPending(t, ch)
	if status, _ := get(t, withQuery(t, base, url.Values{"state": {state}, "code": {testCode}})); status != http.StatusOK {
		t.Fatalf("valid code after a rejected extra parameter returned status %d", status)
	}
	if res, err := recv(t, ch, 2*time.Second); err != nil || res.Code() != testCode {
		t.Fatalf("Wait did not return the code of the legitimate callback")
	}
}

// TestCallbackProviderErrorEmptyDescription: error_description is optional and
// not required to be non-empty; "error=x&error_description=" is still the error
// form and yields a redacted ErrProvider.
func TestCallbackProviderErrorEmptyDescription(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)
	status, body := get(t, withQuery(t, target(t, c), url.Values{
		"state": {state}, "error": {"access_denied"}, "error_description": {""},
	}))
	if status != http.StatusBadRequest || body != pageRejected {
		t.Fatalf("provider error with an empty description returned status %d with an unexpected page", status)
	}
	res, err := recv(t, ch, 2*time.Second)
	if !errors.Is(err, ErrProvider) || res.Code() != "" {
		t.Fatalf("Wait did not return ErrProvider for a provider error with an empty description")
	}
	assertHidden(t, "provider error text", err.Error(), state, testErrorDescription, testCode)
}

// TestCallbackStrictQueryShapeDoesNotConsume sends every malformed shape, one
// at a time, before a legitimate callback. Each is fixed-rejected, Wait stays
// pending, and the legitimate code callback still succeeds afterwards.
func TestCallbackStrictQueryShapeDoesNotConsume(t *testing.T) {
	cases := []struct {
		name string
		raw  string // appended after CallbackPath+"?"
	}{
		{"state only", "state=STATE"},
		{"description only", "state=STATE&error_description=" + url.QueryEscape(testErrorDescription)},
		{"empty description only", "state=STATE&error_description="},
		{"empty error", "state=STATE&error="},
		{"duplicate error", "state=STATE&error=access_denied&error=server_error"},
		{"duplicate error_description", "state=STATE&error=access_denied&error_description=a&error_description=b"},
		{"error and code", "state=STATE&error=access_denied&code=" + url.QueryEscape(testCode)},
		{"error, code and description", "state=STATE&error=access_denied&code=" + url.QueryEscape(testCode) + "&error_description=a"},
		{"code and description", "state=STATE&code=" + url.QueryEscape(testCode) + "&error_description=a"},
		{"extra parameter", "state=STATE&code=" + url.QueryEscape(testCode) + "&scope=files.read"},
		{"bare non-ASCII error", "state=STATE&error=%C3%A9"},
		{"missing code/error", "state=STATE&code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, state := newFlow(t)
			ch := waitResult(context.Background(), c, 0)
			base := target(t, c)
			u, err := url.Parse(base)
			if err != nil {
				t.Fatalf("parsing redirect URI failed")
			}
			raw := LoopbackBaseURL + ":" + u.Port() + CallbackPath + "?" + strings.ReplaceAll(tc.raw, "STATE", url.QueryEscape(state))
			status, body := get(t, raw)
			if status != http.StatusBadRequest || body != pageRejected {
				t.Fatalf("malformed callback returned status %d with an unexpected page", status)
			}
			assertHidden(t, "rejection page", body, testCode, state, testErrorDescription)
			assertStillPending(t, ch)

			status, _ = get(t, withQuery(t, base, url.Values{"state": {state}, "code": {testCode}}))
			if status != http.StatusOK {
				t.Fatalf("legitimate callback after a malformed one returned status %d", status)
			}
			res, err := recv(t, ch, 2*time.Second)
			if err != nil || res.Code() != testCode {
				t.Fatalf("Wait did not return the legitimate code after a malformed callback")
			}
		})
	}
}

// TestCallbackMalformedQuerySyntaxDoesNotConsume: a query with a syntax error
// (a bad percent escape) is rejected as a whole, even when its parsable
// parameters alone would be a valid callback, and the flow stays pending for
// the legitimate callback.
func TestCallbackMalformedQuerySyntaxDoesNotConsume(t *testing.T) {
	cases := []struct {
		name string
		raw  func(state string) string // appended after CallbackPath+"?"
	}{
		{"bad escape after code", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(testCode) + "&x=%zz"
		}},
		{"bad escape before state and code", func(state string) string {
			return "x=%zz&state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(testCode)
		}},
		{"bad escape in description", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&error=access_denied&error_description=%E0%A4%A"
		}},
		{"semicolon in query", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(testCode) + ";x"
		}},
		{"stray ampersand", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(testCode) + "&%"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, state := newFlow(t)
			ch := waitResult(context.Background(), c, 0)
			base := target(t, c)
			u, err := url.Parse(base)
			if err != nil {
				t.Fatalf("parsing redirect URI failed")
			}
			raw := LoopbackBaseURL + ":" + u.Port() + CallbackPath + "?" + tc.raw(state)
			status, body := get(t, raw)
			if status != http.StatusBadRequest || body != pageRejected {
				t.Fatalf("a malformed query returned status %d with an unexpected page", status)
			}
			assertHidden(t, "rejection page", body, testCode, state)
			assertStillPending(t, ch)

			status, body = get(t, withQuery(t, base, url.Values{"state": {state}, "code": {testCode}}))
			if status != http.StatusOK || body != pageAuthorized {
				t.Fatalf("legitimate callback after a malformed query returned status %d", status)
			}
			res, err := recv(t, ch, 2*time.Second)
			if err != nil || res.Code() != testCode {
				t.Fatalf("Wait did not return the legitimate code after a malformed query")
			}
		})
	}
}

// TestCallbackTokenValuesWithSpaceRejected: RFC 6749 vschar has no SP, so a
// code or error carrying an ASCII space (sent either as %20 or as "+") is
// fixed-rejected without consuming the flow.
func TestCallbackTokenValuesWithSpaceRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  func(state string) string
	}{
		{"code with %20", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&code=" + strings.ReplaceAll(url.QueryEscape(testCode), "-", "%20")
		}},
		{"code with +", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&code=" + strings.ReplaceAll(url.QueryEscape(testCode), "-", "+")
		}},
		{"leading space in code", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&code=%20" + url.QueryEscape(testCode)
		}},
		{"error with %20", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&error=access%20denied"
		}},
		{"error with +", func(state string) string {
			return "state=" + url.QueryEscape(state) + "&error=server_error+retry"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, state := newFlow(t)
			ch := waitResult(context.Background(), c, 0)
			base := target(t, c)
			u, err := url.Parse(base)
			if err != nil {
				t.Fatalf("parsing redirect URI failed")
			}
			raw := LoopbackBaseURL + ":" + u.Port() + CallbackPath + "?" + tc.raw(state)
			status, body := get(t, raw)
			if status != http.StatusBadRequest || body != pageRejected {
				t.Fatalf("a value with a space returned status %d with an unexpected page", status)
			}
			assertHidden(t, "rejection page", body, testCode, state)
			assertStillPending(t, ch)

			status, body = get(t, withQuery(t, base, url.Values{"state": {state}, "code": {testCode}}))
			if status != http.StatusOK || body != pageAuthorized {
				t.Fatalf("legitimate callback after a value with a space returned status %d", status)
			}
			res, err := recv(t, ch, 2*time.Second)
			if err != nil || res.Code() != testCode {
				t.Fatalf("Wait did not return the legitimate code after a value with a space")
			}
		})
	}
}

func TestCallbackReplayAfterSuccessRejected(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)
	base := target(t, c)

	status, body := get(t, withQuery(t, base, url.Values{"state": {state}, "code": {testCode}}))
	if status != http.StatusOK || body != pageAuthorized {
		t.Fatalf("success callback returned status %d", status)
	}
	res, err := recv(t, ch, time.Second)
	if err != nil || res.Code() != testCode {
		t.Fatalf("Wait did not return the code after success")
	}

	for i := 0; i < 3; i++ {
		_client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
		req, err := http.NewRequest(http.MethodGet, withQuery(t, base, url.Values{"state": {state}, "code": {testCode + "-replay"}}), nil)
		if err != nil {
			_client.CloseIdleConnections()
			t.Fatalf("building replay request failed")
		}
		resp, err := _client.Do(req)
		if err != nil {
			// The listener is closed; the replay cannot succeed.
			_client.CloseIdleConnections()
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		_client.CloseIdleConnections()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("replay returned 200 after the flow settled")
		}
	}

	// The original outcome is returned again and cannot be replaced.
	res2, err2 := c.Wait(context.Background(), 0)
	if err2 != nil || res2.Code() != res.Code() {
		t.Fatalf("Wait after replay did not return the original code")
	}
}

func TestCallbackReplayAfterProviderErrorRejected(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)

	status, _ := get(t, withQuery(t, target(t, c), url.Values{
		"state": {state}, "error": {"access_denied"}, "error_description": {testErrorDescription},
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("provider error callback returned status %d", status)
	}
	if _, err := recv(t, ch, time.Second); !errors.Is(err, ErrProvider) {
		t.Fatalf("Wait did not return ErrProvider")
	}

	// A late success would have to reopen the listener; it is closed, so even
	// if a request could be sent it can never settle with a code.
	if uri, err := c.RedirectURI(); err == nil || uri != "" {
		t.Fatalf("listener still reported a redirect URI after a provider error")
	}
	if _, err := c.Wait(context.Background(), 0); !errors.Is(err, ErrProvider) {
		t.Fatalf("Wait after provider error returned a different outcome")
	}
}

func TestCallbackWaitContextCancel(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatalf("NewState failed")
	}
	c, err := Start(context.Background(), state, time.Minute)
	if err != nil {
		t.Fatalf("Start failed")
	}
	defer c.close()
	base := target(t, c)

	ctx, cancel := context.WithCancel(context.Background())
	ch := waitResult(ctx, c, 0)
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	cancel()
	_, werr := recv(t, ch, time.Second)
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("Wait returned after %v on cancel", elapsed)
	}
	if !errors.Is(werr, ErrTimeout) {
		t.Fatalf("Wait on cancel did not return ErrTimeout")
	}
	assertPortClosed(t, base)
}

func TestCallbackWaitTimeout(t *testing.T) {
	c, _ := newFlow(t)
	base := target(t, c)

	start := time.Now()
	_, err := c.Wait(context.Background(), 100*time.Millisecond)
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("Wait returned after %v on timeout", elapsed)
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Wait on timeout did not return ErrTimeout")
	}
	assertPortClosed(t, base)
}

func TestCallbackStartContextCancel(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatalf("NewState failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := Start(ctx, state, time.Minute)
	if err != nil {
		t.Fatalf("Start failed")
	}
	defer c.close()
	base := target(t, c)

	start := time.Now()
	cancel()
	res, werr := c.Wait(context.Background(), 0)
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("Wait returned after %v after the Start context was cancelled", elapsed)
	}
	if !errors.Is(werr, ErrTimeout) {
		t.Fatalf("Wait after Start context cancellation did not return ErrTimeout")
	}
	if res.Code() != "" {
		t.Fatalf("Wait returned a code after the Start context was cancelled")
	}
	assertPortClosed(t, base)

	// A correct callback arriving after cancellation cannot be accepted:
	// either the connection fails or the flow still reports ErrTimeout.
	if status := probeStatusCode(t, strings.TrimPrefix(strings.TrimPrefix(base, "http://"), CallbackPath)); status != 0 && status == http.StatusOK {
		t.Fatalf("callback after Start context cancellation was served with 200")
	}
	if _, err := c.Wait(context.Background(), 0); !errors.Is(err, ErrTimeout) {
		t.Fatalf("outcome was replaced after Start context cancellation")
	}
}

// assertPortClosed checks that nothing accepts connections on the listener any
// more.
// probeStatusCode dials addr and sends a minimal request, returning the status
// of the reply, or 0 if the connection could not be made or read.
func probeStatusCode(t *testing.T, addr string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "GET "+CallbackPath+" HTTP/1.1\r\nHost: "+addr+"\r\n\r\n"); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 64<<10)), nil)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func assertPortClosed(t *testing.T, base string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing redirect URI failed")
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn, err := net.DialTimeout("tcp", u.Host, 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("listener port still accepts connections")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCallbackResultFormattingRedacted(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)
	status, _ := get(t, withQuery(t, target(t, c), url.Values{"state": {state}, "code": {testCode}}))
	if status != http.StatusOK {
		t.Fatalf("success callback returned status %d", status)
	}
	res, err := recv(t, ch, time.Second)
	if err != nil || res.Code() != testCode {
		t.Fatalf("Wait did not return the code")
	}

	pointers := []*CallbackResult{&res}
	wrapped := struct {
		R CallbackResult
	}{res}
	// %x of a Stringer prints the hex of its String result, so the check for
	// it is that the placeholder is present rather than verbatim.
	outputs := []struct {
		verb string
		text string
	}{
		{"%v", fmt.Sprintf("%v", res)},
		{"%+v", fmt.Sprintf("%+v", res)},
		{"%#v", fmt.Sprintf("%#v", res)},
		{"%s", fmt.Sprintf("%s", res)},
		{"%q", fmt.Sprintf("%q", res)},
		{"%x", fmt.Sprintf("%x", res)},
		{"Sprint", fmt.Sprint(res)},
		{"Sprintln", fmt.Sprintln(res)},
		{"%v pointer", fmt.Sprintf("%v", pointers[0])},
		{"%+v pointer slice", fmt.Sprintf("%+v", pointers)},
		{"%v slice", fmt.Sprintf("%v", []CallbackResult{res})},
		{"%+v slice", fmt.Sprintf("%+v", []CallbackResult{res})},
		{"%v map", fmt.Sprintf("%v", map[string]CallbackResult{"r": res})},
		{"%+v embedded", fmt.Sprintf("%+v", wrapped)},
		{"String", res.String()},
		{"GoString", res.GoString()},
	}
	for _, out := range outputs {
		assertHidden(t, "formatted CallbackResult", out.text, testCode)
		decoded := out.text
		if out.verb == "%x" {
			raw, err := hex.DecodeString(out.text)
			if err != nil {
				t.Fatalf("%s: hex output did not decode", out.verb)
			}
			decoded = string(raw)
			assertHidden(t, "hex of formatted CallbackResult", decoded, testCode)
		}
		if !strings.Contains(decoded, "redacted") {
			t.Fatalf("%s: formatted CallbackResult is not the redacted placeholder", out.verb)
		}
	}

	// The code stays readable for the later token exchange.
	if res.Code() != testCode {
		t.Fatalf("Code() does not return the received code")
	}
	var zero CallbackResult
	if zero.Code() != "" {
		t.Fatalf("zero CallbackResult has a code")
	}
}

// TestCallbackConcurrentSuccessHasSingleOutcome fires callbacks carrying the
// same state but different codes at once, many times. Each request that
// receives the success page is recorded with its code; exactly one may receive
// it, and Wait must return exactly that request's code.
func TestCallbackConcurrentSuccessHasSingleOutcome(t *testing.T) {
	const rounds = 8
	codes := []string{testCode, testCode + "-b", testCode + "-c"}
	for round := 0; round < rounds; round++ {
		c, state := newFlow(t)
		ch := waitResult(context.Background(), c, 0)
		base := target(t, c)
		queries := make([]url.Values, len(codes))
		for i, code := range codes {
			queries[i] = url.Values{"state": {state}, "code": {code}}
		}
		statuses, bodies := fireConcurrent(base, queries)
		secrets := append(append([]string{}, codes...), state)

		// Every attempt is accounted for: each either received the
		// success page, received the fixed rejection page, or received no
		// success response at all because the winner's callback had
		// already closed the listener (connection refused or reset).
		winners := make([]string, 0, 1)
		unreceived := 0
		for i, status := range statuses {
			switch status {
			case http.StatusOK:
				if bodies[i] != pageAuthorized {
					t.Fatalf("round %d: a success status carried an unexpected page", round)
				}
				assertHidden(t, "success page", bodies[i], secrets...)
				winners = append(winners, codes[i])
			case http.StatusBadRequest:
				if bodies[i] != pageRejected {
					t.Fatalf("round %d: a rejection carried an unexpected page", round)
				}
				assertHidden(t, "rejection page", bodies[i], secrets...)
			case 0:
				if bodies[i] != "" {
					t.Fatalf("round %d: an attempt without a status carried a body", round)
				}
				unreceived++
			default:
				t.Fatalf("round %d: an attempt observed status %d", round, status)
			}
		}
		if len(winners) != 1 {
			t.Fatalf("round %d: %d of %d competing requests received the success page", round, len(winners), len(codes))
		}
		if got := countStatus(statuses, http.StatusBadRequest) + unreceived; got != len(codes)-1 {
			t.Fatalf("round %d: %d of %d competing requests lost (want %d)", round, got, len(codes), len(codes)-1)
		}
		res, err := recv(t, ch, 2*time.Second)
		if err != nil {
			t.Fatalf("round %d: Wait returned an error", round)
		}
		if res.Code() != winners[0] {
			t.Fatalf("round %d: Wait did not return the code from the request that received the success page", round)
		}
		again, err := c.Wait(context.Background(), 0)
		if err != nil || again.Code() != winners[0] {
			t.Fatalf("round %d: Wait returned a different outcome afterwards", round)
		}
	}
}

// TestCallbackConcurrentDuplicateReplayRejected sends the same code twice at
// once. At most one request may receive the success page; the flow must settle
// with that code, and every later replay must be fixed-rejected without
// changing the outcome.
func TestCallbackConcurrentDuplicateReplayRejected(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)
	base := target(t, c)
	q := url.Values{"state": {state}, "code": {testCode}}
	statuses, _ := fireConcurrent(base, []url.Values{q, q, q})
	if n := countStatus(statuses, http.StatusOK); n > 1 {
		t.Fatalf("%d identical concurrent callbacks received the success page", n)
	}
	res, err := recv(t, ch, 2*time.Second)
	if err != nil || res.Code() != testCode {
		t.Fatalf("Wait did not return the code of the settled duplicate callback")
	}

	// Duplicate callbacks after the flow settled do not change Wait.
	before := res.Code()
	replays, bodies := fireConcurrent(base, []url.Values{q, q, q, q})
	if n := countStatus(replays, http.StatusOK); n != 0 {
		t.Fatalf("%d duplicate callbacks after settling received the success page", n)
	}
	for i, body := range bodies {
		if replays[i] != 0 && (replays[i] != http.StatusBadRequest || body != pageRejected) {
			t.Fatalf("a duplicate callback after settling observed status %d with an unexpected page", replays[i])
		}
	}
	again, err := c.Wait(context.Background(), 0)
	if err != nil || again.Code() != before {
		t.Fatalf("a duplicate callback changed the outcome Wait returns")
	}

	// The listener stopped accepting before Wait returned: a fresh probe
	// either cannot connect or, in the worst case, gets a fixed rejection,
	// never the success page.
	if status, _ := getStatus(withQueryRaw(base, q)); status == http.StatusOK {
		t.Fatalf("a callback after the flow settled was served with the success page")
	}
}

// TestCallbackConcurrentMixedForms: a well-formed code racing a well-formed
// provider error settles exactly once; the request whose page was shown is the
// one whose outcome Wait returns, and the other gets a fixed rejection.
func TestCallbackConcurrentMixedForms(t *testing.T) {
	for round := 0; round < 4; round++ {
		c, state := newFlow(t)
		ch := waitResult(context.Background(), c, 0)
		base := target(t, c)
		queries := []url.Values{
			{"state": {state}, "code": {testCode}},
			{"state": {state}, "error": {"access_denied"}, "error_description": {testErrorDescription}},
		}
		statuses, bodies := fireConcurrent(base, queries)
		if n := countStatus(statuses, http.StatusOK); n > 1 {
			t.Fatalf("round %d: %d requests received the success page", round, n)
		}
		res, err := recv(t, ch, 2*time.Second)
		if err != nil && !errors.Is(err, ErrProvider) {
			t.Fatalf("round %d: Wait returned an unexpected error", round)
		}
		for i, body := range bodies {
			switch statuses[i] {
			case http.StatusOK:
				if res.Code() != testCode {
					t.Fatalf("round %d: the success page was shown to a request whose outcome did not win", round)
				}
			case http.StatusBadRequest:
				if body != pageRejected {
					t.Fatalf("round %d: a rejection carried an unexpected page", round)
				}
			case 0:
			default:
				t.Fatalf("round %d: an attempt observed status %d", round, statuses[i])
			}
		}
		assertHidden(t, "provider error text", errString(err), testErrorDescription, state, testCode)
	}
}

// errString formats err without a nil special case, for leak checks.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestCallbackWaitReturnsAfterListenerStopped: the success callback returns its
// page without waiting for the HTTP shutdown, and by decision time the listener
// has already stopped accepting: a second client connected after Wait returned
// gets no reply or a fixed rejection, never the success page.
func TestCallbackWaitReturnsAfterListenerStopped(t *testing.T) {
	c, state := newFlow(t)
	ch := waitResult(context.Background(), c, 0)
	base := target(t, c)
	q := url.Values{"state": {state}, "code": {testCode}}
	status, body := get(t, withQuery(t, base, q))
	if status != http.StatusOK || body != pageAuthorized {
		t.Fatalf("success callback returned status %d with an unexpected page", status)
	}
	res, err := recv(t, ch, 2*time.Second)
	if err != nil || res.Code() != testCode {
		t.Fatalf("Wait did not return the code after the success page")
	}
	// The flow is final once Wait returned; the listener must not accept
	// new callbacks.
	if status, _ := getStatus(withQueryRaw(base, url.Values{"state": {state}, "code": {testCode + "-late"}})); status == http.StatusOK {
		t.Fatalf("a callback after Wait returned received the success page")
	}
	if again, err := c.Wait(context.Background(), 0); err != nil || again.Code() != testCode {
		t.Fatalf("the outcome changed after the flow settled")
	}
}
