package onedriveauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic token-exchange values. None is a real credential, tenant, scope or
// peer; the markers exist so a leak check can find them in errors and output.
const (
	tokenTestRedirect = "http://127.0.0.1:51000/oauth/native/callback"
	tokenTestVerifier = "synthetic-verifier-0123456789-abcdefghijklmnopqrstuvwx"
	tokenTestCode     = "synthetic-token-code-7c1d-must-not-leak"
	tokenTestAccess   = "synthetic-access-token-3e9a-must-not-leak"
	tokenTestRefresh  = "synthetic-refresh-token-8b2f-must-not-leak"
	tokenTestIDToken  = "synthetic-id-token-5a4c-must-not-leak"
	tokenTestBodyMark = "synthetic-provider-body-marker-2d6e-must-not-leak"
)

// tokenPeer is a local synthetic HTTPS token peer and the seam through which an
// exchange reaches it. It records every request so a test can assert the exact
// form and the request count.
type tokenPeer struct {
	srv  *httptest.Server
	url  *url.URL
	hits atomic.Int32

	mu    sync.Mutex
	forms []url.Values
}

// newTokenPeer starts a local TLS peer whose handler answers with handler. The
// peer is closed with the test.
func newTokenPeer(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *tokenPeer {
	t.Helper()
	p := &tokenPeer{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "unreadable", http.StatusBadRequest)
			return
		}
		form, err := url.ParseQuery(string(body))
		p.mu.Lock()
		if err == nil {
			p.forms = append(p.forms, form)
		}
		p.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(p.srv.Close)
	u, err := url.Parse(p.srv.URL)
	if err != nil {
		t.Fatalf("peer URL does not parse")
	}
	p.url = u
	return p
}

// exchange runs one exchange against the peer through the unexported seam.
func (p *tokenPeer) exchange(t *testing.T, ctx context.Context, timeout time.Duration) (TokenResult, error) {
	t.Helper()
	return exchangeCode(ctx, tokenTestConfig(), tokenTestRedirect, tokenTestCode, tokenTestVerifier, timeout, p.url, p.srv.Client())
}

func tokenTestConfig() TokenExchangeConfig {
	return TokenExchangeConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticTenant,
		Scopes:   []string{syntheticScopeA, syntheticScopeB},
	}
}

// writeJSON writes a fixed JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// assertTokenFailure checks a fixed, redacted sentinel and that every input
// and marker is absent from the error text and its common formats.
func assertTokenFailure(t *testing.T, err error, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("exchange returned the wrong sentinel (want %v)", want)
	}
	if err.Error() != want.Error() {
		t.Fatalf("error text is not the fixed sentinel text")
	}
	assertHidden(t, "token error", fmt.Sprintf("%v|%+v|%#v|%s|%q", err, err, err, err, err),
		tokenTestCode, tokenTestVerifier, tokenTestRedirect, tokenTestAccess,
		tokenTestRefresh, tokenTestIDToken, tokenTestBodyMark,
		syntheticClientID, syntheticTenant, syntheticScopeA, syntheticScopeB)
}

// TestExchangeCodeExactFormAndRedaction checks the exact six-member form, the
// absence of a client secret, one request, and the redacted transient result
// that retains the access and refresh tokens until Close and discards every
// other credential in the response.
func TestExchangeCodeExactFormAndRedaction(t *testing.T) {
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{
			"token_type":"Bearer",
			"access_token":"`+tokenTestAccess+`",
			"expires_in":3600,
			"refresh_token":"`+tokenTestRefresh+`",
			"id_token":"`+tokenTestIDToken+`",
			"ext_expires_in":7200,
			"scope":"`+syntheticScopeA+`",
			"unknown_member":"`+tokenTestBodyMark+`"
		}`)
	})

	res, err := p.exchange(t, context.Background(), 5*time.Second)
	if err != nil {
		t.Fatalf("a valid synthetic response returned an unexpected error")
	}
	defer res.Close()
	if got := res.AccessToken(); got != tokenTestAccess {
		t.Fatalf("the result does not carry the synthetic access token")
	}
	refresh := res.RefreshToken()
	defer clear(refresh)
	if got := refresh; string(got) != tokenTestRefresh {
		t.Fatalf("the result does not carry the synthetic refresh token")
	}
	if got := res.ExpiresIn(); got != time.Hour {
		t.Fatalf("the result does not carry the synthetic lifetime")
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("exchange made %d requests, want exactly one", got)
	}

	form := p.singleForm(t)

	want := map[string]string{
		"client_id":     syntheticClientID,
		"scope":         syntheticScopeA + " " + syntheticScopeB,
		"code":          tokenTestCode,
		"redirect_uri":  tokenTestRedirect,
		"grant_type":    "authorization_code",
		"code_verifier": tokenTestVerifier,
	}
	if len(form) != len(want) {
		t.Fatalf("token form has %d members, want exactly %d", len(form), len(want))
	}
	for key, value := range want {
		if got := form.Get(key); got != value {
			t.Fatalf("token form member %q has an unexpected value", key)
		}
		if len(form[key]) != 1 {
			t.Fatalf("token form member %q is repeated", key)
		}
	}
	for key := range form {
		if _, ok := want[key]; !ok {
			t.Fatalf("token form carries an unexpected member %q", key)
		}
	}
	if form.Has("client_secret") {
		t.Fatalf("token form carries a client secret")
	}

	// The result redacts the token under every common formatting verb that
	// honors Stringer/GoStringer, and the hex verb must not reveal it either.
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q", res, res, res, res, res)
	assertHidden(t, "formatted token result", formatted,
		tokenTestAccess, tokenTestRefresh, tokenTestIDToken, tokenTestBodyMark)
	if !strings.Contains(formatted, "redacted") {
		t.Fatalf("formatted token result carries no redaction marker")
	}
	assertHidden(t, "hex token result", fmt.Sprintf("%x", res), tokenTestAccess, tokenTestRefresh, tokenTestIDToken)
	res.Close()
	assertTokenResultCleared(t, res)
}

// singleForm checks, under the peer lock, that the peer recorded exactly one
// form, and returns a copy of it so the test can read it without the lock.
func (p *tokenPeer) singleForm(t *testing.T) url.Values {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.forms) != 1 {
		t.Fatalf("peer recorded %d forms, want exactly one", len(p.forms))
	}
	form := make(url.Values, len(p.forms[0]))
	for key, values := range p.forms[0] {
		form[key] = append([]string(nil), values...)
	}
	return form
}

// TestExchangeCodeValidatesBeforeAnyRequest checks every input sentinel with a
// zero-request peer: validation happens before the transport is reached.
func TestExchangeCodeValidatesBeforeAnyRequest(t *testing.T) {
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{}`)
	})
	good := tokenTestConfig()
	cases := []struct {
		name     string
		cfg      TokenExchangeConfig
		redirect string
		code     string
		verifier string
		want     error
	}{
		{"missing client ID", TokenExchangeConfig{Tenant: good.Tenant, Scopes: good.Scopes}, tokenTestRedirect, tokenTestCode, tokenTestVerifier, ErrClientID},
		{"bad client ID", TokenExchangeConfig{ClientID: "bad client", Tenant: good.Tenant, Scopes: good.Scopes}, tokenTestRedirect, tokenTestCode, tokenTestVerifier, ErrClientID},
		{"missing tenant", TokenExchangeConfig{ClientID: good.ClientID, Scopes: good.Scopes}, tokenTestRedirect, tokenTestCode, tokenTestVerifier, ErrTenant},
		{"bad tenant", TokenExchangeConfig{ClientID: good.ClientID, Tenant: "a/b", Scopes: good.Scopes}, tokenTestRedirect, tokenTestCode, tokenTestVerifier, ErrTenant},
		{"missing scope", TokenExchangeConfig{ClientID: good.ClientID, Tenant: good.Tenant}, tokenTestRedirect, tokenTestCode, tokenTestVerifier, ErrScope},
		{"bad scope", TokenExchangeConfig{ClientID: good.ClientID, Tenant: good.Tenant, Scopes: []string{"a b"}}, tokenTestRedirect, tokenTestCode, tokenTestVerifier, ErrScope},
		{"empty redirect", good, "", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"redirect with query", good, tokenTestRedirect + "?x=1", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"redirect with fragment", good, tokenTestRedirect + "#x", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"redirect with userinfo", good, "http://user@127.0.0.1:51000/oauth/native/callback", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"redirect other host", good, "http://localhost:51000/oauth/native/callback", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"redirect other path", good, "http://127.0.0.1:51000/oauth/callback", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"redirect https", good, "https://127.0.0.1:51000/oauth/native/callback", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"redirect no port", good, "http://127.0.0.1/oauth/native/callback", tokenTestCode, tokenTestVerifier, ErrRedirectURI},
		{"empty code", good, tokenTestRedirect, "", tokenTestVerifier, ErrCode},
		{"code with space", good, tokenTestRedirect, "a b", tokenTestVerifier, ErrCode},
		{"short verifier", good, tokenTestRedirect, tokenTestCode, "short", ErrVerifier},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := exchangeCode(context.Background(), tc.cfg, tc.redirect, tc.code, tc.verifier, time.Second, p.url, p.srv.Client())
			assertTokenFailure(t, err, tc.want)
		})
	}

	// The injected endpoint is held to the same transport rules.
	badEndpoints := []*url.URL{
		{Scheme: "http", Host: p.url.Host},
		{Scheme: "https", Host: p.url.Host, RawQuery: "x=1"},
		{Scheme: "https", Host: p.url.Host, Fragment: "x"},
		{Scheme: "https", Host: p.url.Host, User: url.UserPassword("u", "p")},
	}
	for i, endpoint := range badEndpoints {
		_, err := exchangeCode(context.Background(), good, tokenTestRedirect, tokenTestCode, tokenTestVerifier, time.Second, endpoint, p.srv.Client())
		assertTokenFailure(t, err, ErrRequest)
		if got := p.hits.Load(); got != 0 {
			t.Fatalf("invalid endpoint %d reached the peer", i)
		}
	}
	if got := p.hits.Load(); got != 0 {
		t.Fatalf("input validation made %d requests, want zero", got)
	}
}

// TestExchangeCodeResponseErrors checks every fixed response sentinel, that
// each is reached after one request that is never retried, and that no provider
// member leaks into an error.
func TestExchangeCodeResponseErrors(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        error
	}{
		{"non-200", http.StatusBadRequest, "application/json", `{"error":"` + tokenTestBodyMark + `","access_token":"` + tokenTestAccess + `"}`, ErrProviderStatus},
		{"server error", http.StatusInternalServerError, "text/plain", tokenTestBodyMark, ErrProviderStatus},
		{"redirect", http.StatusFound, "text/plain", "", ErrProviderStatus},
		{"wrong content type", http.StatusOK, "text/plain", `{"access_token":"` + tokenTestAccess + `"}`, ErrContentType},
		{"missing content type", http.StatusOK, "", `{"access_token":"` + tokenTestAccess + `"}`, ErrContentType},
		{"malformed JSON", http.StatusOK, "application/json", `{"access_token":`, ErrTokenResponse},
		{"not an object", http.StatusOK, "application/json", `["` + tokenTestBodyMark + `"]`, ErrTokenResponse},
		{"trailing data", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600}{}`, ErrTokenResponse},
		{"repeated access_token", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600}`, ErrTokenResponse},
		{"repeated unknown member", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600,"` + tokenTestBodyMark + `":1,"` + tokenTestBodyMark + `":2}`, ErrTokenResponse},
		{"repeated token_type", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","token_type":"Bearer","token_type":"Bearer","expires_in":3600}`, ErrTokenResponse},
		{"non-bearer", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","token_type":"MAC","expires_in":3600}`, ErrTokenMissing},
		{"missing token_type", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","expires_in":3600}`, ErrTokenMissing},
		{"missing access token", http.StatusOK, "application/json", `{"token_type":"Bearer","expires_in":3600}`, ErrTokenMissing},
		{"malformed access token", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `\n","token_type":"Bearer","expires_in":3600}`, ErrTokenResponse},
		{"non-string access token", http.StatusOK, "application/json", `{"access_token":42,"token_type":"Bearer","expires_in":3600}`, ErrTokenResponse},
		{"malformed refresh token", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600,"refresh_token":null}`, ErrTokenResponse},
		{"unknown member before a malformed refresh token", http.StatusOK, "application/json", `{"id_token":"` + tokenTestIDToken + `","access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600,"refresh_token":[1]}`, ErrTokenResponse},
		{"missing expiry", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","token_type":"Bearer"}`, ErrTokenMissing},
		{"bad expiry", http.StatusOK, "application/json", `{"access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":"soon"}`, ErrTokenMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTokenPeer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "https://example.invalid/elsewhere")
				}
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := p.exchange(t, context.Background(), 5*time.Second)
			assertTokenFailure(t, err, tc.want)
			if got := p.hits.Load(); got != 1 {
				t.Fatalf("%s made %d requests, want exactly one (no retry)", tc.name, got)
			}
		})
	}
}

// TestExchangeCodeOversizedResponse checks that a body above the bound is
// rejected without keeping it.
func TestExchangeCodeOversizedResponse(t *testing.T) {
	var body strings.Builder
	body.WriteString(`{"access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600,"padding":"`)
	body.WriteString(strings.Repeat("x", maxTokenResponseBytes))
	body.WriteString(`"}`)
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, body.String())
	})
	_, err := p.exchange(t, context.Background(), 5*time.Second)
	assertTokenFailure(t, err, ErrOversized)
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("oversized case made %d requests, want exactly one", got)
	}
}

// TestExchangeCodeCancelledBeforeSend checks the pre-send sentinel and that the
// peer is never contacted.
func TestExchangeCodeCancelledBeforeSend(t *testing.T) {
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.exchange(t, ctx, time.Second)
	assertTokenFailure(t, err, ErrCancelled)
	if got := p.hits.Load(); got != 0 {
		t.Fatalf("a cancelled exchange contacted the peer %d times, want zero", got)
	}
}

// TestExchangeCodeCancelledAfterSend checks that cancellation once the peer
// has the request is an outcome-unknown failure, never a retry or a refusal.
func TestExchangeCodeCancelledAfterSend(t *testing.T) {
	received := make(chan struct{})
	p := newTokenPeer(t, func(w http.ResponseWriter, r *http.Request) {
		close(received)
		// Hold the answer until the client gives up, then leave.
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := p.exchange(t, ctx, 5*time.Second)
		result <- err
	}()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatalf("the synthetic peer did not receive the request")
	}
	cancel()
	select {
	case err := <-result:
		assertTokenFailure(t, err, ErrOutcomeUnknown)
	case <-time.After(3 * time.Second):
		t.Fatalf("the exchange did not return after cancellation")
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("cancelled exchange made %d requests, want exactly one", got)
	}
}

// TestTokenURLForValidatedTenant checks that the production endpoint is derived
// only from the validated tenant and the fixed official host and path, with no
// query or userinfo, and that a malformed tenant is rejected before any URL is
// formed.
func TestTokenURLForValidatedTenant(t *testing.T) {
	u, err := tokenURL(syntheticTenant)
	if err != nil {
		t.Fatalf("tokenURL rejected a valid synthetic tenant")
	}
	if u.Scheme != "https" || u.Host != "login.microsoftonline.com" {
		t.Fatalf("token endpoint is not the fixed official HTTPS host")
	}
	if want := "/" + syntheticTenant + "/oauth2/v2.0/token"; u.EscapedPath() != want {
		t.Fatalf("token endpoint path is not /{tenant}/oauth2/v2.0/token")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		t.Fatalf("token endpoint carries a query, fragment or userinfo")
	}
	for _, bad := range []string{"", "a/b", "..", "a b", "a?x=1", "a#f"} {
		if _, err := tokenURL(bad); !errors.Is(err, ErrTenant) {
			t.Fatalf("tokenURL accepted or misclassified a malformed tenant")
		}
	}
}

// TestExchangeCodeRefreshTokenPresentOrAbsent checks that the refresh token is
// retained when present and omitted when absent, that a present refresh token
// passes the same token syntax as the access token (escapes included), and that
// requesting no offline_access scope adds nothing to the form.
func TestExchangeCodeRefreshTokenPresentOrAbsent(t *testing.T) {
	okPart := `"token_type":"Bearer","access_token":"` + tokenTestAccess + `","expires_in":3600`
	cases := []struct {
		name string
		body string
		want string
	}{
		{"present", `{` + okPart + `,"refresh_token":"` + tokenTestRefresh + `"}`, tokenTestRefresh},
		{"absent", `{` + okPart + `}`, ""},
		{"present with escapes", `{` + okPart + `,"refresh_token":"a\u0062c\\d\"e\/f"}`, `abc\d"e/f`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, tc.body)
			})
			res, err := p.exchange(t, context.Background(), 5*time.Second)
			if err != nil {
				t.Fatalf("a valid synthetic response returned an unexpected error")
			}
			defer res.Close()
			refresh := res.RefreshToken()
			defer clear(refresh)
			if got := string(refresh); got != tc.want {
				t.Fatalf("refresh token presence does not match the response (got %d bytes, want %d)", len(got), len(tc.want))
			}
			if tc.want == "" && refresh != nil {
				t.Fatalf("an absent refresh token returned a non-nil copy")
			}
			if got := res.AccessToken(); got != tokenTestAccess {
				t.Fatalf("the result does not carry the synthetic access token")
			}
			form := p.singleForm(t)
			if form.Has("offline_access") {
				t.Fatalf("the token form carries an offline_access member")
			}
			if got := form.Get("scope"); strings.Contains(got, "offline_access") {
				t.Fatalf("the token form scope gained offline_access")
			}
			assertTokenBuffersOwned(t, res, tc.want)
		})
	}
}

// TestExchangeCodeMalformedRefreshTokenRejected checks that a refresh_token
// present with any non-string type or an invalid value is the fixed
// ErrTokenResponse, never a silent absence, and that such a failure wipes the
// bounded body buffer, any partially decoded token bytes and the owned token
// buffers already taken, including the access token read before the refresh
// token.
func TestExchangeCodeMalformedRefreshTokenRejected(t *testing.T) {
	okPart := `"token_type":"Bearer","access_token":"` + tokenTestAccess + `","expires_in":3600`
	cases := []struct {
		name  string
		value string
	}{
		{"null", `null`},
		{"empty string", `""`},
		{"number", `42`},
		{"boolean", `true`},
		{"array", `["` + tokenTestRefresh + `"]`},
		{"object", `{"v":"` + tokenTestRefresh + `"}`},
		{"with a space", `"synthetic refresh"`},
		{"with a tab escape", `"a\tb"`},
		{"with a newline escape", `"a\nb"`},
		{"with a non-ASCII escape", `"a\u00e9b"`},
		{"with a surrogate escape", `"a\ud83d\ude00b"`},
		{"with raw non-ASCII", `"a` + "\u00e9" + `b"`},
		{"unterminated string", `"` + tokenTestRefresh},
		{"bad escape", `"a\qb"`},
		{"truncated unicode escape", `"a\u00"`},
		{"invalid unicode digit", `"a\u00zz"`},
		{"too long", `"` + strings.Repeat("r", maxCodeLen+1) + `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The refresh token comes after a valid access token, so a
			// failure must also wipe the token bytes already owned.
			body := []byte(`{` + okPart + `,"refresh_token":` + tc.value + `}`)
			res, err := decodeTokenJSON(body)
			assertTokenFailure(t, err, ErrTokenResponse)
			assertTokenResultCleared(t, res)
			for i, c := range body {
				if c != 0 {
					t.Fatalf("a malformed refresh token left byte %d of the body non-zero", i)
				}
			}

			// The same failure through a full exchange over the local
			// TLS peer.
			p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, `{`+okPart+`,"refresh_token":`+tc.value+`}`)
			})
			res, err = p.exchange(t, context.Background(), 5*time.Second)
			assertTokenFailure(t, err, ErrTokenResponse)
			assertTokenResultCleared(t, res)
			if got := p.hits.Load(); got != 1 {
				t.Fatalf("a malformed refresh token made %d requests, want exactly one (no retry)", got)
			}
		})
	}

	// A malformed access_token is rejected the same way, whether it comes
	// first or after a valid refresh token.
	body := []byte(`{"access_token":"a\tb","token_type":"Bearer","expires_in":3600,"refresh_token":"` + tokenTestRefresh + `"}`)
	res, err := decodeTokenJSON(body)
	assertTokenFailure(t, err, ErrTokenResponse)
	assertTokenResultCleared(t, res)
}

// TestTokenStringEscapeDecoding checks that token escapes are decoded straight
// into visible ASCII bytes, and that a syntactically valid JSON string which
// cannot spell such a token is rejected by the Unmarshaler with an empty
// destination.
func TestTokenStringEscapeDecoding(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		invalid bool
	}{
		{"plain", `"abc"`, "abc", false},
		{"empty", `""`, "", true},
		{"quote escape", `"a\"b"`, `a"b`, false},
		{"backslash escape", `"a\\b"`, `a\b`, false},
		{"slash escape", `"a\/b"`, "a/b", false},
		{"unicode ascii", `"\u0041\u0062"`, "Ab", false},
		{"mixed", `"\u0041x\\y"`, `Ax\y`, false},
		{"printable boundary", `"\u0021\u007e"`, "!~", false},
		{"tab escape", `"a\tb"`, "", true},
		{"newline escape", `"a\nb"`, "", true},
		{"backspace escape", `"\b"`, "", true},
		{"form feed escape", `"\f"`, "", true},
		{"carriage return escape", `"\r"`, "", true},
		{"space escape", `"\u0020"`, "", true},
		{"upper boundary escape", `"\u007f"`, "", true},
		{"non-ASCII escape", `"\u00e9"`, "", true},
		{"surrogate escape", `"\ud800"`, "", true},
		{"raw non-ASCII", "\"a\u00e9b\"", "", true},
		{"number", `42`, "", true},
		{"null", `null`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dst []byte
			var invalid bool
			dec := json.NewDecoder(strings.NewReader(tc.raw))
			// The value is valid JSON, so the decoder passes exactly
			// the member text to the Unmarshaler, whose verdict is
			// what this test checks.
			if err := dec.Decode(tokenStringDecoder(&dst, &invalid)); err != nil {
				t.Fatalf("the decoder rejected syntactically valid JSON: %v", err)
			}
			defer clear(dst)
			if invalid != tc.invalid {
				t.Fatalf("invalid = %v, want %v", invalid, tc.invalid)
			}
			if invalid {
				if dst != nil {
					t.Fatalf("a rejected token retained bytes")
				}
				return
			}
			if string(dst) != tc.want {
				t.Fatalf("decoded token has %d bytes, want %d", len(dst), len(tc.want))
			}
		})
	}
}

// TestTokenStringMalformedJSONRejected checks that input which is not
// syntactically valid JSON (a raw control character, a bad or short escape, an
// unterminated string) is rejected by the JSON decoder itself, so the
// Unmarshaler is never reached and no destination bytes are produced.
func TestTokenStringMalformedJSONRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"raw control", "\"a\x01b\""},
		{"raw newline", "\"a\nb\""},
		{"bad escape letter", `"a\qb"`},
		{"short unicode", `"a\u12"`},
		{"non-unicode hex", `"a\u12g4"`},
		{"unterminated", `"abc`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dst []byte
			var invalid bool
			dec := json.NewDecoder(strings.NewReader(tc.raw))
			err := dec.Decode(tokenStringDecoder(&dst, &invalid))
			clear(dst)
			if err == nil {
				t.Fatalf("the decoder accepted malformed JSON")
			}
			if dst != nil {
				t.Fatalf("malformed JSON produced destination bytes")
			}
			if invalid {
				t.Fatalf("the Unmarshaler verdict was set for input it never saw")
			}
		})
	}
}

// TestTokenResultCopiesAreIsolated checks that every accessor returns a copy
// independent of the shared owner and of other copies: changing a copy, or
// dropping the reference to it, never changes another value.
func TestTokenResultCopiesAreIsolated(t *testing.T) {
	var res TokenResult
	var err error
	func() {
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, `{"token_type":"Bearer","access_token":"`+tokenTestAccess+
				`","expires_in":3600,"refresh_token":"`+tokenTestRefresh+`"}`)
		})
		res, err = p.exchange(t, context.Background(), 5*time.Second)
	}()
	if err != nil {
		t.Fatalf("a valid synthetic response returned an unexpected error")
	}
	defer res.Close()

	// The result owns byte buffers rather than strings over the body.
	assertTokenBuffersOwned(t, res, tokenTestRefresh)

	first := res.AccessToken()
	second := res.AccessToken()
	if first != tokenTestAccess || second != tokenTestAccess {
		t.Fatalf("accessor copies do not carry the synthetic access token")
	}

	// A RefreshToken copy is the caller's to clear: clearing it does not
	// touch the owner or another copy.
	r1 := res.RefreshToken()
	defer clear(r1)
	if string(r1) != tokenTestRefresh {
		t.Fatalf("the refresh token copy does not carry the synthetic refresh token")
	}
	clear(r1)
	for _, c := range r1 {
		if c != 0 {
			t.Fatalf("a caller-side copy could not be cleared")
		}
	}
	if got := r1; got == nil {
		t.Fatalf("the cleared copy was unexpectedly replaced")
	}
	r2 := res.RefreshToken()
	defer clear(r2)
	if string(r2) != tokenTestRefresh {
		t.Fatalf("clearing a copy changed the owner")
	}
	r1 = r2
	r1[0] ^= 0xff
	got := res.RefreshToken()
	defer clear(got)
	if string(got) != tokenTestRefresh {
		t.Fatalf("altering a copy changed the owner")
	}
	if got := res.AccessToken(); got != tokenTestAccess {
		t.Fatalf("altering the refresh token changed the access token")
	}

	// Copies of the result value share one owner and cannot affect the
	// original through either accessor.
	other := res
	other.owned = nil
	if got := res.AccessToken(); got != tokenTestAccess {
		t.Fatalf("dropping a copy's owner changed the original")
	}
	if got := other.AccessToken(); got != "" || other.RefreshToken() != nil {
		t.Fatalf("a copy without an owner still returns a token")
	}

	// Close on a copy closes the owner, so every copy is closed and no
	// earlier caller-side copy is touched.
	other = res
	other.Close()
	if !res.isClosed() {
		t.Fatalf("a closed copy did not mark the result closed")
	}
	if got := res.AccessToken(); got != "" {
		t.Fatalf("a closed result still returns an access token")
	}
	if got := res.RefreshToken(); got != nil {
		t.Fatalf("a closed result still returns a refresh token")
	}
	if first != tokenTestAccess || second != tokenTestAccess {
		t.Fatalf("Close reached a caller copy")
	}
}

// TestTokenResultCloseZeroizes checks that Close zeroizes the shared buffers,
// releases them, is idempotent, and that the accessors and Close behave safely
// on zero and nil values.
func TestTokenResultCloseZeroizes(t *testing.T) {
	var res TokenResult
	func() {
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, `{"token_type":"Bearer","access_token":"`+tokenTestAccess+
				`","expires_in":3600,"refresh_token":"`+tokenTestRefresh+`"}`)
		})
		var err error
		res, err = p.exchange(t, context.Background(), 5*time.Second)
		if err != nil {
			t.Fatalf("a valid synthetic response returned an unexpected error")
		}
	}()
	if res.owned == nil {
		t.Fatalf("the result has no shared owner")
	}
	res.owned.mu.Lock()
	owned := [][]byte{res.owned.access, res.owned.refresh}
	res.owned.mu.Unlock()
	for i, b := range owned {
		if len(b) == 0 {
			t.Fatalf("the owner holds no token buffer %d", i)
		}
	}

	res.Close()
	res.owned.mu.Lock()
	released := res.owned.access != nil || res.owned.refresh != nil
	closed := res.owned.closed
	res.owned.mu.Unlock()
	if released {
		t.Fatalf("Close did not release the owned buffers")
	}
	if !closed {
		t.Fatalf("Close did not mark the owner closed")
	}
	if got := res.AccessToken(); got != "" {
		t.Fatalf("AccessToken after Close returned %d bytes, want none", len(got))
	}
	if got := res.RefreshToken(); got != nil {
		t.Fatalf("RefreshToken after Close returned %d bytes, want none", len(got))
	}
	for i, b := range owned {
		for j, c := range b {
			if c != 0 {
				t.Fatalf("Close left byte %d of owned buffer %d non-zero", j, i)
			}
		}
	}

	// Idempotent: a second Close is safe and keeps everything cleared.
	res.Close()
	res.Close()
	for i, b := range owned {
		for j, c := range b {
			if c != 0 {
				t.Fatalf("repeated Close left byte %d of owned buffer %d non-zero", j, i)
			}
		}
	}
	if got := res.AccessToken(); got != "" {
		t.Fatalf("AccessToken after repeated Close returned bytes")
	}

	// Zero values, nil pointers and copies without an owner are safe.
	var zero TokenResult
	if got := zero.AccessToken(); got != "" {
		t.Fatalf("a zero TokenResult returns an access token")
	}
	if got := zero.RefreshToken(); got != nil {
		t.Fatalf("a zero TokenResult returns a refresh token")
	}
	zero.Close()
	if got := fmt.Sprintf("%v|%#v", zero, zero); got != redactedToken+"|"+redactedToken {
		t.Fatalf("a zero TokenResult does not format redacted")
	}
	var nilResult *TokenResult
	nilResult.Close()
}

// TestTokenResultCloseWipesOwnedBytesWithinBody checks the ownership contract
// end to end: the body buffer handed to the decoder is wiped once it returns,
// the success result holds the tokens in its own owned buffers, and Close
// zeroizes those buffers.
func TestTokenResultCloseWipesOwnedBytesWithinBody(t *testing.T) {
	body := []byte(`{"token_type":"Bearer","access_token":"` + tokenTestAccess +
		`","expires_in":3600,"refresh_token":"` + tokenTestRefresh + `"}`)
	res, err := decodeTokenJSON(body)
	if err != nil {
		t.Fatalf("decodeTokenJSON rejected a valid synthetic body")
	}
	for i, c := range body {
		if c != 0 {
			t.Fatalf("decodeTokenJSON left byte %d of the body non-zero", i)
		}
	}
	if got := res.AccessToken(); got != tokenTestAccess {
		t.Fatalf("the decoded result does not carry the synthetic access token")
	}
	if got := res.RefreshToken(); string(got) != tokenTestRefresh {
		t.Fatalf("the decoded result does not carry the synthetic refresh token")
	} else {
		clear(got)
	}
	assertTokenBuffersOwned(t, res, tokenTestRefresh)
	res.Close()
}

// TestTokenResultCloseRacesAccessors checks that an accessor never observes a
// buffer being zeroized by Close: every byte it gets back while Close runs must
// match the token exactly or be an empty result.
func TestTokenResultCloseRacesAccessors(t *testing.T) {
	var res TokenResult
	func() {
		p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, `{"token_type":"Bearer","access_token":"`+tokenTestAccess+
				`","expires_in":3600,"refresh_token":"`+tokenTestRefresh+`"}`)
		})
		var err error
		res, err = p.exchange(t, context.Background(), 5*time.Second)
		if err != nil {
			t.Fatalf("a valid synthetic response returned an unexpected error")
		}
	}()
	if res.owned == nil {
		t.Fatalf("the result has no shared owner")
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	check := func(name string, got []byte, want string) {
		if len(got) != 0 && string(got) != want {
			t.Errorf("%s observed a partially zeroized token", name)
		}
		clear(got)
	}
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				check("AccessToken", []byte(res.AccessToken()), tokenTestAccess)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				check("RefreshToken", res.RefreshToken(), tokenTestRefresh)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		res.Close()
		res.Close()
	}()
	close(start)
	wg.Wait()

	if got := res.AccessToken(); got != "" {
		t.Fatalf("the result is not closed after the race")
	}
}

// assertTokenBuffersOwned checks that a result stores the synthetic access token
// and, when wantRefresh is non-empty, exactly that refresh token in byte
// buffers of their own, not string headers, so Close can zeroize them. An empty
// wantRefresh asserts that no refresh bytes are owned at all.
func assertTokenBuffersOwned(t *testing.T, res TokenResult, wantRefresh string) {
	t.Helper()
	if res.owned == nil {
		t.Fatalf("the result has no shared owner")
	}
	res.owned.mu.Lock()
	access, refresh := res.owned.access, res.owned.refresh
	res.owned.mu.Unlock()
	if string(access) != tokenTestAccess {
		t.Fatalf("the owned access buffer does not carry the synthetic access token")
	}
	if wantRefresh == "" {
		if len(refresh) != 0 {
			t.Fatalf("an absent refresh token left %d owned bytes", len(refresh))
		}
		return
	}
	if len(refresh) == 0 {
		t.Fatalf("a present refresh token left no owned bytes")
	}
	if string(refresh) != wantRefresh {
		t.Fatalf("the owned refresh buffer has %d bytes, want the %d expected bytes", len(refresh), len(wantRefresh))
	}
}

// TestExchangeCodeParseFailureWipesBody checks that every parse failure wipes
// the bounded body buffer, any partially decoded token bytes and the owned token
// buffers already taken, leaves no token bytes in the returned result, and keeps
// the error fixed and redacted.
func TestExchangeCodeParseFailureWipesBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want error
	}{
		{"trailing data after tokens", `{"token_type":"Bearer","access_token":"` + tokenTestAccess + `","expires_in":3600,"refresh_token":"` + tokenTestRefresh + `"} {`, ErrTokenResponse},
		{"repeated refresh_token", `{"token_type":"Bearer","access_token":"` + tokenTestAccess + `","expires_in":3600,"refresh_token":"` + tokenTestRefresh + `","refresh_token":"` + tokenTestRefresh + `"}`, ErrTokenResponse},
		{"refresh then repeated unknown", `{"refresh_token":"` + tokenTestRefresh + `","access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600,"` + tokenTestBodyMark + `":1,"` + tokenTestBodyMark + `":2}`, ErrTokenResponse},
		{"missing expiry after tokens", `{"refresh_token":"` + tokenTestRefresh + `","access_token":"` + tokenTestAccess + `","token_type":"Bearer"}`, ErrTokenMissing},
		{"non-bearer after tokens", `{"refresh_token":"` + tokenTestRefresh + `","access_token":"` + tokenTestAccess + `","expires_in":3600,"token_type":"MAC"}`, ErrTokenMissing},
		{"unterminated after tokens", `{"refresh_token":"` + tokenTestRefresh + `","access_token":"` + tokenTestAccess + `","token_type":"Bearer","expires_in":3600`, ErrTokenResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			res, err := decodeTokenJSON(body)
			assertTokenFailure(t, err, tc.want)
			assertTokenResultCleared(t, res)
			for i, c := range body {
				if c != 0 {
					t.Fatalf("a parse failure left byte %d of the body non-zero", i)
				}
			}
		})
	}

	// The same failure through a full exchange over the local TLS peer.
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"access_token":"`+tokenTestAccess+`","token_type":"Bearer","expires_in":3600,"refresh_token":"`+
			tokenTestRefresh+`"} trailing `+tokenTestBodyMark)
	})
	res, err := p.exchange(t, context.Background(), 5*time.Second)
	assertTokenFailure(t, err, ErrTokenResponse)
	assertTokenResultCleared(t, res)
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("a parse failure made %d requests, want exactly one (no retry)", got)
	}
}

// assertTokenResultCleared checks that a result carries no token bytes, whether
// it never had an owner or its owner was zeroized.
func assertTokenResultCleared(t *testing.T, res TokenResult) {
	t.Helper()
	if got := res.AccessToken(); got != "" {
		t.Fatalf("a cleared result returns an access token")
	}
	if got := res.RefreshToken(); got != nil {
		t.Fatalf("a cleared result returns a refresh token")
	}
	if res.owned == nil {
		return
	}
	res.owned.mu.Lock()
	defer res.owned.mu.Unlock()
	if res.owned.access != nil || res.owned.refresh != nil {
		t.Fatalf("a cleared result still owns token buffers")
	}
	if !res.owned.closed {
		t.Fatalf("a cleared result is not marked closed")
	}
}
