package onedriveauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic refresh grant values. None is a real credential; the markers let a
// leak check find them in errors and output.
const (
	refreshTestOld     = "synthetic-old-refresh-6f3d-must-not-leak"
	refreshTestNew     = "synthetic-new-refresh-1c8e-must-not-leak"
	refreshTestSecret  = "synthetic-client-secret-9d0b-must-not-leak"
	refreshTestMarker  = "synthetic-refresh-body-marker-4a7f-must-not-leak"
	refreshTestBadMark = "synthetic-refresh-input-2e5a-must-not-leak"
)

// refreshTestConfig is a public-client refresh configuration with explicit
// scopes.
func refreshTestConfig() TokenRefreshConfig {
	return TokenRefreshConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticTenant,
		Scopes:   []string{syntheticScopeA, syntheticScopeB},
	}
}

// refresh runs one refresh grant against the peer through the unexported seam.
func (p *tokenPeer) refresh(t *testing.T, ctx context.Context, cfg TokenRefreshConfig, old []byte, timeout time.Duration) (TokenResult, error) {
	t.Helper()
	return refreshAccessToken(ctx, cfg, old, timeout, p.url, p.srv.Client())
}

// assertRefreshFailure checks the refresh-specific fixed sentinel, that the
// error text is exactly that sentinel's, that only an input failure classifies
// as ErrRefreshInput, the base kind when given, the zero result, and that no
// input or marker appears in the error text or its common formats.
func assertRefreshFailure(t *testing.T, res TokenResult, err, want, base error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("refresh returned the wrong sentinel (want %v)", want)
	}
	if err.Error() != want.Error() {
		t.Fatalf("error text is not exactly the fixed sentinel text")
	}
	if want == ErrRefreshInput {
		if !errors.Is(err, ErrRefreshInput) {
			t.Fatalf("an input refresh failure does not classify as ErrRefreshInput")
		}
	} else if errors.Is(err, ErrRefreshInput) {
		t.Fatalf("a non-input refresh failure classifies as ErrRefreshInput")
	}
	if base != nil && !errors.Is(err, base) {
		t.Fatalf("refresh error does not keep the base classification (want %v)", base)
	}
	if strings.Contains(strings.ToLower(err.Error()), "authorization code") {
		t.Fatalf("refresh error uses exchange wording")
	}
	assertRefreshZero(t, res)
	text := fmt.Sprintf("%v|%+v|%#v|%s|%q", err, err, err, err, err)
	assertHidden(t, "refresh error", text,
		refreshTestOld, refreshTestNew, tokenTestAccess, tokenTestRefresh,
		refreshTestSecret, refreshTestMarker, tokenTestBodyMark, refreshTestBadMark,
		syntheticClientID, syntheticTenant, syntheticScopeA, syntheticScopeB,
		"login.microsoftonline.com", "refresh_token=")
}

// assertRefreshZero checks that a failed refresh returned no result at all.
func assertRefreshZero(t *testing.T, res TokenResult) {
	t.Helper()
	if res.owned != nil || res.expiresIn != 0 || res.AccessToken() != "" || res.RefreshToken() != nil {
		t.Fatalf("a failed refresh returned a non-zero result")
	}
}

// assertRefreshCallerBytes checks that the caller's old token bytes are exactly
// what they were.
func assertRefreshCallerBytes(t *testing.T, got []byte) {
	t.Helper()
	if string(got) != refreshTestOld {
		t.Fatalf("the caller's old refresh token bytes were modified")
	}
}

// TestRefreshExactForm checks the exact form, with and without explicit scopes,
// the absence of a client secret, one request each and the returned tokens.
func TestRefreshExactForm(t *testing.T) {
	body := `{"token_type":"Bearer","access_token":"` + tokenTestAccess + `","expires_in":1800,"refresh_token":"` + refreshTestNew + `"}`
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, body)
	})
	cases := []struct {
		name   string
		scopes []string
		want   map[string]string
	}{
		{
			name:   "explicit scopes",
			scopes: []string{syntheticScopeA, syntheticScopeB},
			want: map[string]string{
				"client_id":     syntheticClientID,
				"scope":         syntheticScopeA + " " + syntheticScopeB,
				"grant_type":    "refresh_token",
				"refresh_token": refreshTestOld,
			},
		},
		{
			name:   "nil scopes omit scope",
			scopes: nil,
			want: map[string]string{
				"client_id":     syntheticClientID,
				"grant_type":    "refresh_token",
				"refresh_token": refreshTestOld,
			},
		},
		{
			name:   "empty scopes omit scope",
			scopes: []string{},
			want: map[string]string{
				"client_id":     syntheticClientID,
				"grant_type":    "refresh_token",
				"refresh_token": refreshTestOld,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := p.hits.Load()
			old := []byte(refreshTestOld)
			cfg := refreshTestConfig()
			cfg.Scopes = tc.scopes
			res, err := p.refresh(t, context.Background(), cfg, old, 5*time.Second)
			if err != nil {
				t.Fatalf("refresh failed: %v", err)
			}
			defer res.Close()
			if got := p.hits.Load() - before; got != 1 {
				t.Fatalf("refresh made %d requests, want exactly one", got)
			}
			form := p.latestForm(t)
			if len(form) != len(tc.want) {
				t.Fatalf("form has %d members, want %d", len(form), len(tc.want))
			}
			for key, want := range tc.want {
				if got := form.Get(key); got != want {
					t.Fatalf("form member %q does not carry the expected value", key)
				}
			}
			if form.Has("client_secret") {
				t.Fatalf("the form carries a client secret")
			}
			if form.Has("code") || form.Has("redirect_uri") || form.Has("code_verifier") {
				t.Fatalf("the refresh form carries authorization-code members")
			}
			if got := res.AccessToken(); got != tokenTestAccess {
				t.Fatalf("the result does not carry the new access token")
			}
			if got := res.ExpiresIn(); got != 1800*time.Second {
				t.Fatalf("the result carries the wrong lifetime")
			}
			newToken := res.RefreshToken()
			defer clear(newToken)
			if string(newToken) != refreshTestNew {
				t.Fatalf("the result does not expose the replacement refresh token")
			}
			assertRefreshCallerBytes(t, old)
			assertHidden(t, "refresh result", res.GoString(), refreshTestNew, tokenTestAccess)
		})
	}
}

// TestRefreshReplacementAbsentOrPresent checks that an absent refresh_token is a
// success without one, and that a malformed replacement fails the whole answer:
// no access token and no refresh token is returned.
func TestRefreshReplacementAbsentOrPresent(t *testing.T) {
	okPart := `"token_type":"Bearer","access_token":"` + tokenTestAccess + `","expires_in":3600`
	cases := []struct {
		name    string
		body    string
		wantErr error
		wantNew string
	}{
		{"absent", `{` + okPart + `}`, nil, ""},
		{"present", `{` + okPart + `,"refresh_token":"` + refreshTestNew + `"}`, nil, refreshTestNew},
		{"malformed with a supplied replacement", `{` + okPart + `,"refresh_token":"bad value ` + refreshTestNew + `"}`, ErrRefreshResponse, ""},
		{"null with a supplied replacement", `{` + okPart + `,"refresh_token":null}`, ErrRefreshResponse, ""},
		{"unusable with a supplied replacement", `{"access_token":"` + tokenTestAccess + `","refresh_token":"` + refreshTestNew + `"}`, ErrRefreshResponse, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, body)
			})
			old := []byte(refreshTestOld)
			res, err := p.refresh(t, context.Background(), refreshTestConfig(), old, 5*time.Second)
			if got := p.hits.Load(); got != 1 {
				t.Fatalf("refresh made %d requests, want exactly one", got)
			}
			assertRefreshCallerBytes(t, old)
			if tc.wantErr != nil {
				assertRefreshFailure(t, res, err, tc.wantErr, nil)
				return
			}
			if err != nil {
				t.Fatalf("refresh failed: %v", err)
			}
			defer res.Close()
			if got := res.AccessToken(); got != tokenTestAccess {
				t.Fatalf("the result does not carry the access token")
			}
			got := res.RefreshToken()
			defer clear(got)
			if string(got) != tc.wantNew || (tc.wantNew == "" && got != nil) {
				t.Fatalf("the refresh token presence does not match the answer")
			}
			assertTokenBuffersOwned(t, res, tc.wantNew)
		})
	}
}

// TestRefreshInvalidInputMakesNoRequest checks every malformed input with a
// zero-request peer, and that the caller's bytes are untouched.
func TestRefreshInvalidInputMakesNoRequest(t *testing.T) {
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{}`)
	})
	good := refreshTestConfig()
	cases := []struct {
		name string
		cfg  TokenRefreshConfig
		old  []byte
		want error
	}{
		{"missing client ID", TokenRefreshConfig{Tenant: good.Tenant}, []byte(refreshTestOld), ErrClientID},
		{"bad client ID", TokenRefreshConfig{ClientID: "bad client", Tenant: good.Tenant}, []byte(refreshTestOld), ErrClientID},
		{"missing tenant", TokenRefreshConfig{ClientID: good.ClientID}, []byte(refreshTestOld), ErrTenant},
		{"bad tenant", TokenRefreshConfig{ClientID: good.ClientID, Tenant: "a/b"}, []byte(refreshTestOld), ErrTenant},
		{"empty scope entry", TokenRefreshConfig{ClientID: good.ClientID, Tenant: good.Tenant, Scopes: []string{""}}, []byte(refreshTestOld), ErrScope},
		{"bad scope", TokenRefreshConfig{ClientID: good.ClientID, Tenant: good.Tenant, Scopes: []string{"a b"}}, []byte(refreshTestOld), ErrScope},
		{"nil old token", good, nil, nil},
		{"empty old token", good, []byte{}, ErrRefreshInput},
		{"old token with space", good, []byte("a b"), ErrRefreshInput},
		{"old token with control", good, []byte("a\nb"), ErrRefreshInput},
		{"oversized old token", good, bytes.Repeat([]byte("a"), maxRefreshTokenLen+1), ErrRefreshInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := append([]byte(nil), tc.old...)
			before := p.hits.Load()
			res, err := p.refresh(t, context.Background(), tc.cfg, old, time.Second)
			if got := p.hits.Load() - before; got != 0 {
				t.Fatalf("invalid input made %d requests, want zero", got)
			}
			assertRefreshFailure(t, res, err, ErrRefreshInput, tc.want)
			if !bytes.Equal(old, tc.old) {
				t.Fatalf("invalid input modified the caller's bytes")
			}
		})
	}
}

// TestRefreshProviderErrors checks the fixed sentinels for a provider status and
// for every malformed or unusable answer, each after exactly one request and
// without leaking the body.
func TestRefreshProviderErrors(t *testing.T) {
	okPart := `"token_type":"Bearer","access_token":"` + tokenTestAccess + `","expires_in":3600,"refresh_token":"` + refreshTestNew + `"`
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        error
		base        error
	}{
		{"provider 400 with a replacement", http.StatusBadRequest, "application/json", `{"error":"invalid_grant","error_description":"` + refreshTestMarker + `","refresh_token":"` + refreshTestNew + `"}`, ErrRefreshStatus, ErrProviderStatus},
		{"provider 401", http.StatusUnauthorized, "application/json", `{"error":"` + refreshTestMarker + `"}`, ErrRefreshStatus, ErrProviderStatus},
		{"provider 500", http.StatusInternalServerError, "text/plain", refreshTestMarker, ErrRefreshStatus, ErrProviderStatus},
		{"truncated after a replacement", http.StatusOK, "application/json", `{` + okPart + `,`, ErrRefreshResponse, ErrTokenResponse},
		{"trailing data after a replacement", http.StatusOK, "application/json", `{` + okPart + `} {` + refreshTestMarker + `}`, ErrRefreshResponse, ErrTokenResponse},
		{"non-JSON", http.StatusOK, "text/html", refreshTestMarker, ErrRefreshResponse, ErrContentType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			old := []byte(refreshTestOld)
			res, err := p.refresh(t, context.Background(), refreshTestConfig(), old, 5*time.Second)
			if got := p.hits.Load(); got != 1 {
				t.Fatalf("refresh made %d requests, want exactly one (no retry)", got)
			}
			assertRefreshFailure(t, res, err, tc.want, tc.base)
			assertRefreshCallerBytes(t, old)
		})
	}
}

// TestRefreshCancelledBeforeSend checks the pre-send sentinel and that the peer
// is never contacted.
func TestRefreshCancelledBeforeSend(t *testing.T) {
	p := newTokenPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	old := []byte(refreshTestOld)
	res, err := p.refresh(t, ctx, refreshTestConfig(), old, time.Second)
	assertRefreshFailure(t, res, err, ErrRefreshCancelled, ErrCancelled)
	if got := p.hits.Load(); got != 0 {
		t.Fatalf("a cancelled refresh contacted the peer %d times, want zero", got)
	}
	assertRefreshCallerBytes(t, old)
}

// TestRefreshCancelledAfterSend checks that cancellation once the peer has the
// request is an outcome-unknown failure with exactly one request and unchanged
// caller bytes.
func TestRefreshCancelledAfterSend(t *testing.T) {
	received := make(chan struct{})
	p := newTokenPeer(t, func(_ http.ResponseWriter, r *http.Request) {
		close(received)
		<-r.Context().Done()
	})
	old := []byte(refreshTestOld)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		res TokenResult
		err error
	}
	returned := make(chan outcome, 1)
	go func() {
		res, err := p.refresh(t, ctx, refreshTestConfig(), old, 5*time.Second)
		returned <- outcome{res: res, err: err}
	}()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatalf("the synthetic peer did not receive the request")
	}
	cancel()
	select {
	case got := <-returned:
		assertRefreshFailure(t, got.res, got.err, ErrRefreshOutcomeUnknown, ErrOutcomeUnknown)
	case <-time.After(3 * time.Second):
		t.Fatalf("the refresh did not return after cancellation")
	}
	if got := p.hits.Load(); got != 1 {
		t.Fatalf("cancelled refresh made %d requests, want exactly one", got)
	}
	assertRefreshCallerBytes(t, old)
}

// TestRefreshErrorsStayDistinct checks that the refresh sentinels are distinct,
// that none aliases another, that none uses the exchange wording, and that every
// base classification the runner can produce is mapped to its refresh peer,
// which keeps the base classification for errors.Is and formats only the fixed
// refresh text.
func TestRefreshErrorsStayDistinct(t *testing.T) {
	all := []error{ErrRefreshInput, ErrRefreshCancelled, ErrRefreshOutcomeUnknown, ErrRefreshStatus, ErrRefreshResponse}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Fatalf("refresh sentinels %d and %d alias", i, j)
			}
		}
		if strings.Contains(strings.ToLower(a.Error()), "authorization code") {
			t.Fatalf("refresh sentinel %d uses exchange wording", i)
		}
	}
	for _, base := range []error{ErrCancelled, ErrOutcomeUnknown, ErrProviderStatus, ErrContentType, ErrOversized, ErrTokenResponse, ErrTokenMissing, ErrRequest} {
		own := refreshKind(base)
		if own == nil || own == base {
			t.Fatalf("a base classification has no refresh sentinel")
		}
		err := refreshKinds(base, func(target error) error {
			// The same answer tokenRun gives: the original error itself
			// when it is this base kind, nil otherwise.
			if errors.Is(base, target) {
				return base
			}
			return nil
		})
		if !errors.Is(err, base) || !errors.Is(err, own) {
			t.Fatalf("a classified refresh error lost a classification")
		}
		if strings.Contains(strings.ToLower(err.Error()), "authorization code") {
			t.Fatalf("a classified refresh error carries exchange wording")
		}
	}
}

// refreshTestTransportMarker and refreshTestRawError are the synthetic raw
// transport failure: the marker must never reach the caller in any format.
const (
	refreshTestTransportMarker = "synthetic-raw-transport-dial-7b2c-must-not-leak"
	refreshTestRawError        = refreshTestTransportMarker + ": dial tcp " + refreshTestOld
)

// refreshRoundTripper is an opaque http.RoundTripper that never touches the
// network: it counts the attempts and always fails with the synthetic raw
// transport error.
type refreshRoundTripper struct {
	attempts atomic.Int32
}

// RoundTrip fails every attempt.
func (r *refreshRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.attempts.Add(1)
	return nil, errors.New(refreshTestRawError)
}

// TestRefreshTransportErrorBaseClassification checks the regression where the
// httpClient.Do error branch handed the runner a plain ErrOutcomeUnknown that
// the refresh pre-mapping replaced before the base kind could be preserved:
// a transport error must classify as both ErrRefreshOutcomeUnknown and the base
// ErrOutcomeUnknown, and must never expose the raw transport text.
func TestRefreshTransportErrorBaseClassification(t *testing.T) {
	tr := &refreshRoundTripper{}
	endpoint := &url.URL{Scheme: "https", Host: "token.invalid", Path: "/oauth2/v2.0/token"}
	old := []byte(refreshTestOld)
	res, err := refreshAccessToken(context.Background(), refreshTestConfig(), old, 5*time.Second, endpoint, &http.Client{Transport: tr})
	if got := tr.attempts.Load(); got != 1 {
		t.Fatalf("a transport error made %d transport attempts, want exactly one (no retry)", got)
	}
	assertRefreshFailure(t, res, err, ErrRefreshOutcomeUnknown, ErrOutcomeUnknown)
	if err.Error() != ErrRefreshOutcomeUnknown.Error() {
		t.Fatalf("error text is not exactly the refresh sentinel text")
	}
	if strings.HasSuffix(err.Error(), "; ") || strings.HasSuffix(err.Error(), " ") {
		t.Fatalf("error text has a blank or empty suffix")
	}
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("a transport error does not keep the base ErrOutcomeUnknown classification")
	}
	if !errors.Is(err, ErrRefreshOutcomeUnknown) {
		t.Fatalf("a transport error does not classify as ErrRefreshOutcomeUnknown")
	}
	if errors.Is(err, ErrRefreshInput) {
		t.Fatalf("a post-send transport error classifies as ErrRefreshInput")
	}
	text := fmt.Sprintf("%v|%+v|%#v|%s|%q", err, err, err, err, err)
	assertHidden(t, "transport refresh error", text,
		refreshTestTransportMarker, "dial tcp", refreshTestOld, refreshTestNew, tokenTestAccess, tokenTestRefresh)
	assertRefreshCallerBytes(t, old)
}

// latestForm returns a copy of the most recent form the peer recorded, under
// the peer lock.
func (p *tokenPeer) latestForm(t *testing.T) url.Values {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.forms) == 0 {
		t.Fatalf("peer recorded no forms")
	}
	form := make(url.Values, len(p.forms[len(p.forms)-1]))
	for key, values := range p.forms[len(p.forms)-1] {
		form[key] = append([]string(nil), values...)
	}
	return form
}
