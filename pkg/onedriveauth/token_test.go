package onedriveauth

import (
	"context"
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
// that discards every other credential in the response.
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
	if got := res.AccessToken(); got != tokenTestAccess {
		t.Fatalf("the result does not carry the synthetic access token")
	}
	if got := res.ExpiresIn(); got != time.Hour {
		t.Fatalf("the result does not carry the synthetic lifetime")
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("exchange made %d requests, want exactly one", got)
	}

	p.mu.Lock()
	if len(p.forms) != 1 {
		p.mu.Unlock()
		t.Fatalf("peer did not record exactly one form")
	}
	form := p.forms[0]
	p.mu.Unlock()

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
