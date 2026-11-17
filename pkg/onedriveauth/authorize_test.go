package onedriveauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The values in this file are synthetic illustration inputs. They are not a
// real application registration, tenant or scope, and they select no product
// permission: any valid-looking scope token exercises the same builder code.
const (
	// Synthetic GUID-shaped application (client) ID and directory (tenant)
	// ID.
	syntheticClientID = "00000000-0000-0000-0000-0000000000aa"
	syntheticTenant   = "11111111-1111-1111-1111-1111111111bb"
	// A synthetic DNS-style tenant.
	syntheticDNSTenant = "tenant-name.invalid"
	// Obvious synthetic scope tokens; none is a OneDrive or Microsoft Graph
	// permission.
	syntheticScopeA = "example.scope-one"
	syntheticScopeB = "example.scope.two"
	syntheticScopeC = "example.scope-three"
	// A recognizable synthetic authorization code for the smoke test.
	syntheticCode = "synthetic-code-4d2e6c1a-must-not-leak"
)

// authorizeParams is the complete and only set of query parameters the
// authorization URL may carry.
var authorizeParams = []string{
	"client_id", "response_type", "response_mode", "redirect_uri", "scope",
	"state", "code_challenge", "code_challenge_method",
}

// forbiddenParams must never appear in the authorization URL.
var forbiddenParams = []string{
	"client_secret", "code_verifier", "token", "access_token", "id_token",
	"implicit", "refresh_token", "nonce", "prompt", "login_hint", "response",
}

// newURLFlow starts a Callback for a fresh verifier and state, the same values
// AuthorizationURL will read, and returns it with them.
func newURLFlow(t *testing.T) (*Callback, string, string) {
	t.Helper()
	verifier, err := NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier failed")
	}
	state, err := NewState()
	if err != nil {
		t.Fatalf("NewState failed")
	}
	c, err := Start(context.Background(), state, 5*time.Second)
	if err != nil {
		t.Fatalf("Start failed")
	}
	t.Cleanup(func() { c.close() })
	return c, verifier, state
}

// mustAuthorizationURL builds the URL or fails without echoing any input.
func mustAuthorizationURL(t *testing.T, c *Callback, cfg AuthorizeConfig, verifier string) *url.URL {
	t.Helper()
	raw, err := AuthorizationURL(c, cfg, verifier)
	if err != nil {
		t.Fatalf("AuthorizationURL returned an unexpected error (sentinels only)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path == "" {
		t.Fatalf("AuthorizationURL returned a URL that does not parse")
	}
	return u
}

// checkAuthorizeURL asserts every fixed property of the URL for one tenant.
func checkAuthorizeURL(t *testing.T, u *url.URL, tenant, redirectURI, state, scope, verifier string) {
	t.Helper()
	if u.Scheme != "https" {
		t.Fatalf("authorize scheme is not https")
	}
	if u.Host != "login.microsoftonline.com" {
		t.Fatalf("authorize host is not login.microsoftonline.com")
	}
	if u.EscapedPath() != "/"+tenant+"/oauth2/v2.0/authorize" {
		t.Fatalf("authorize path is not /{tenant}/oauth2/v2.0/authorize")
	}
	// A lone ".." as the tenant segment could be resolved by a proxy.
	if u.Path != u.EscapedPath() {
		t.Fatalf("authorize path needs escaping")
	}
	if u.User != nil {
		t.Fatalf("authorize URL carries userinfo")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		t.Fatalf("authorize URL carries a fragment")
	}
	if strings.Contains(u.String(), "#") {
		t.Fatalf("authorize URL contains a fragment marker")
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("authorize query does not parse")
	}
	gotKeys := make([]string, 0, len(query))
	for k := range query {
		gotKeys = append(gotKeys, k)
		if len(query[k]) != 1 {
			t.Fatalf("authorize parameter %q is repeated", k)
		}
	}
	want := append([]string(nil), authorizeParams...)
	sort.Strings(gotKeys)
	sort.Strings(want)
	if !reflect.DeepEqual(gotKeys, want) {
		t.Fatalf("authorize parameter set differs from the allowed set")
	}
	for _, k := range forbiddenParams {
		if query.Has(k) || strings.Contains(u.RawQuery, k+"=") {
			t.Fatalf("authorize URL carries forbidden parameter %q", k)
		}
	}

	checks := []struct {
		key  string
		want string
	}{
		{"client_id", syntheticClientID},
		{"response_type", "code"},
		{"response_mode", "query"},
		{"redirect_uri", redirectURI},
		{"scope", scope},
		{"state", state},
		{"code_challenge", S256(verifier)},
		{"code_challenge_method", "S256"},
	}
	for _, ck := range checks {
		if got := query.Get(ck.key); got != ck.want {
			t.Fatalf("authorize parameter %q has an unexpected value (length %d, want %d)", ck.key, len(got), len(ck.want))
		}
	}
	// The redirect_uri is the live loopback listener of this same Callback.
	ru, err := url.Parse(query.Get("redirect_uri"))
	if err != nil || ru.Scheme != "http" || ru.Hostname() != LoopbackHost || ru.Path != CallbackPath || ru.Port() == "" {
		t.Fatalf("redirect_uri is not the loopback callback of this run")
	}
	// The scope is exactly the explicit entries joined with single spaces,
	// in order, with nothing added.
	if strings.Contains(query.Get("scope"), "+") || strings.Contains(query.Get("scope"), "  ") {
		t.Fatalf("scope is not joined with single spaces")
	}
	// Decoding the query yields exactly the explicit entries: nothing added,
	// removed, reordered or case-changed, and separated by single spaces.
	if got, want := strings.Split(query.Get("scope"), " "), strings.Fields(scope); !reflect.DeepEqual(got, want) {
		t.Fatalf("scope entries differ from the explicit list")
	}
	// The PKCE verifier itself never appears; only its S256 challenge.
	if strings.Contains(u.String(), verifier) {
		t.Fatalf("authorize URL contains the PKCE verifier")
	}
}

func TestAuthorizationURLShape(t *testing.T) {
	c, verifier, state := newURLFlow(t)
	redirectURI, err := c.RedirectURI()
	if err != nil {
		t.Fatalf("RedirectURI failed")
	}
	scope := syntheticScopeA + " " + syntheticScopeB + " " + syntheticScopeC
	cfg := AuthorizeConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticTenant,
		Scopes:   []string{syntheticScopeA, syntheticScopeB, syntheticScopeC},
	}
	u := mustAuthorizationURL(t, c, cfg, verifier)
	checkAuthorizeURL(t, u, syntheticTenant, redirectURI, c.state, scope, verifier)
	// A call with the same Callback, config and verifier is deterministic.
	again := mustAuthorizationURL(t, c, cfg, verifier)
	if again.String() != u.String() {
		t.Fatalf("two calls for the same input produced different URLs")
	}

	// One run of the flow: the state carried in the URL is the private
	// state of this Callback, the one Wait verifies. A wrong state is
	// rejected and does not consume the flow; the URL's state succeeds.
	ch := waitResult(context.Background(), c, 0)
	other := state + "x"
	if status, _ := get(t, withQuery(t, redirectURI, url.Values{"state": {other}, "code": {syntheticCode}})); status != http.StatusBadRequest {
		t.Fatalf("a callback with a different state was not rejected")
	}
	assertStillPending(t, ch)
	if status, body := get(t, withQuery(t, redirectURI, url.Values{"state": {u.Query().Get("state")}, "code": {syntheticCode}})); status != http.StatusOK || body != pageAuthorized {
		t.Fatalf("a callback with the URL state was not accepted")
	}
	if res, err := recv(t, ch, 2*time.Second); err != nil || res.Code() != syntheticCode {
		t.Fatalf("Wait did not return the code of the callback carrying the URL state")
	}

	// A second Callback has its own state and redirect URI; the first one
	// settled above, so only the fresh Callback can build a URL now.
	c2, _, _ := newURLFlow(t)
	redirectURI2, err := c2.RedirectURI()
	if err != nil {
		t.Fatalf("RedirectURI failed")
	}
	u2 := mustAuthorizationURL(t, c2, cfg, verifier)
	checkAuthorizeURL(t, u2, syntheticTenant, redirectURI2, c2.state, scope, verifier)
	if u2.Query().Get("state") == state {
		t.Fatalf("a second Callback produced the same state")
	}
}

func TestAuthorizationURLSingleScopeAndDNSTenant(t *testing.T) {
	c, verifier, _ := newURLFlow(t)
	redirectURI, err := c.RedirectURI()
	if err != nil {
		t.Fatalf("RedirectURI failed")
	}
	u := mustAuthorizationURL(t, c, AuthorizeConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticDNSTenant,
		Scopes:   []string{syntheticScopeA},
	}, verifier)
	checkAuthorizeURL(t, u, syntheticDNSTenant, redirectURI, c.state, syntheticScopeA, verifier)

	// A scope entry that is already a space-free token is sent verbatim.
	u = mustAuthorizationURL(t, c, AuthorizeConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticTenant,
		Scopes:   []string{syntheticScopeA + "." + syntheticScopeB},
	}, verifier)
	checkAuthorizeURL(t, u, syntheticTenant, redirectURI, c.state, syntheticScopeA+"."+syntheticScopeB, verifier)
}

// TestAuthorizationURLNoDefaultScope checks that the builder adds nothing: the
// scope is exactly the explicit list, including when a sole entry is a lone
// token, and no implicit openid/offline_access appears.
func TestAuthorizationURLNoDefaultScope(t *testing.T) {
	c, verifier, _ := newURLFlow(t)
	for _, scopes := range [][]string{
		{syntheticScopeA},
		{syntheticScopeB, syntheticScopeA},
	} {
		u := mustAuthorizationURL(t, c, AuthorizeConfig{
			ClientID: syntheticClientID,
			Tenant:   syntheticTenant,
			Scopes:   scopes,
		}, verifier)
		got := u.Query().Get("scope")
		if got != strings.Join(scopes, " ") {
			t.Fatalf("scope differs from the explicit list")
		}
		if strings.Contains(got, "openid") || strings.Contains(got, "offline_access") ||
			strings.Contains(got, "profile") || strings.Contains(got, "email") {
			t.Fatalf("authorize URL carries an implicit scope")
		}
	}
}

func TestAuthorizationURLRejectsConfigErrors(t *testing.T) {
	// A tenant input with a query or fragment is rejected by the alphabet
	// check; their text must not be echoed.
	secretTenantQuery := "x?client_id=leak-6a1f"
	secretTenantFragment := "x#frag-leak-6a1f"
	cases := []struct {
		name   string
		tenant string
		scopes []string
		secret []string
	}{
		{"empty tenant", "", nil, nil},
		{"forward slash", "a/b", nil, nil},
		{"double slash", "a//b", nil, nil},
		{"leading slash", "/" + syntheticTenant, nil, nil},
		{"trailing slash", syntheticTenant + "/", nil, nil},
		{"backslash", `a\b`, nil, nil},
		{"trailing backslash", syntheticTenant + `\`, nil, nil},
		{"lone dot", ".", nil, nil},
		{"lone double dot", "..", nil, nil},
		{"double dot prefix", ".." + syntheticDNSTenant, nil, nil},
		{"double dot suffix", syntheticDNSTenant + "..", nil, nil},
		{"double dot middle", "a..b", nil, nil},
		{"double dot element", "a...b", nil, nil},
		{"double dot domain", "contoso..example", nil, nil},
		{"space", "a b", nil, nil},
		{"control", "a\tb", nil, nil},
		{"unicode", "t\u00e9n\u00e4nt", nil, nil},
		{"percent", "a%2fb", nil, nil},
		{"colon", "a:b", nil, nil},
		{"at", "a@b", nil, nil},
		{"plus", "a+b", nil, nil},
		{"query", secretTenantQuery, nil, []string{"leak-6a1f", "client_id"}},
		{"fragment", secretTenantFragment, nil, []string{"frag-leak-6a1f"}},
		{"query only", "?x=1", nil, []string{"x=1"}},
		{"fragment only", "#x", nil, []string{"#x"}},
		{"too long", strings.Repeat("a", maxTenantLen+1), nil, []string{strings.Repeat("a", 16)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, verifier, state := newURLFlow(t)
			cfg := AuthorizeConfig{ClientID: syntheticClientID, Tenant: tc.tenant, Scopes: []string{syntheticScopeA}}
			got, err := AuthorizationURL(c, cfg, verifier)
			if !errors.Is(err, ErrTenant) {
				t.Fatalf("tenant case returned the wrong sentinel, want ErrTenant")
			}
			if got != "" {
				t.Fatalf("tenant case returned a URL with an error")
			}
			// Only non-trivial inputs are leak-checked: a one-character
			// case such as "." could match the fixed sentinel text.
			secrets := []string{syntheticClientID, state, verifier, syntheticScopeA}
			if len(tc.tenant) >= 4 {
				secrets = append(secrets, tc.tenant)
			}
			secrets = append(secrets, tc.secret...)
			assertHidden(t, "tenant error", err.Error(), secrets...)
			assertHidden(t, "tenant error formatted", fmt.Sprintf("%+v|%#v|%s|%q", err, err, err, err), secrets...)
			if err.Error() != ErrTenant.Error() {
				t.Fatalf("tenant error message is not the fixed sentinel text")
			}
		})
	}
}

// TestAuthorizationURLRejectsConfigValueOtherErrors covers the remaining
// configuration sentinels, none of which may echo the configuration or the
// run's state and verifier.
func TestAuthorizationURLRejectsOtherConfigErrors(t *testing.T) {
	c, verifier, state := newURLFlow(t)
	badClient := "client id with space"
	badScopeSpace := "example.scope one"
	badScopeQuote := `example."scope`
	badVerifier := "too-short-verifier"
	scopes := maxScopes + 1
	tooMany := make([]string, scopes)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("%s.%d", syntheticScopeA, i)
	}

	cases := []struct {
		name     string
		cfg      AuthorizeConfig
		verifier string
		cb       bool
		want     error
		secret   []string
	}{
		{"empty client ID", AuthorizeConfig{Tenant: syntheticTenant, Scopes: []string{syntheticScopeA}}, verifier, true, ErrClientID, nil},
		{"malformed client ID", AuthorizeConfig{ClientID: badClient, Tenant: syntheticTenant, Scopes: []string{syntheticScopeA}}, verifier, true, ErrClientID, []string{badClient}},
		{"too long client ID", AuthorizeConfig{ClientID: strings.Repeat("c", maxClientIDLen+1), Tenant: syntheticTenant, Scopes: []string{syntheticScopeA}}, verifier, true, ErrClientID, []string{strings.Repeat("c", 32)}},
		{"missing scope", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant}, verifier, true, ErrScope, nil},
		{"nil scope", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{}}, verifier, true, ErrScope, nil},
		{"empty scope entry", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{""}}, verifier, true, ErrScope, nil},
		{"empty scope beside a good one", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{syntheticScopeA, ""}}, verifier, true, ErrScope, []string{syntheticScopeA}},
		{"scope with space", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{badScopeSpace}}, verifier, true, ErrScope, []string{badScopeSpace}},
		{"scope with tab", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{"a\tb"}}, verifier, true, ErrScope, []string{"a\tb"}},
		{"scope with quote", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{badScopeQuote}}, verifier, true, ErrScope, []string{badScopeQuote}},
		{"scope too long", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{strings.Repeat("s", maxScopeLen+1)}}, verifier, true, ErrScope, []string{strings.Repeat("s", 32)}},
		{"too many scopes", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: tooMany}, verifier, true, ErrScope, []string{tooMany[0], tooMany[len(tooMany)-1]}},
		{"empty verifier", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{syntheticScopeA}}, "", true, ErrVerifier, nil},
		{"short verifier", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{syntheticScopeA}}, badVerifier, true, ErrVerifier, []string{badVerifier}},
		{"nil callback", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{syntheticScopeA}}, verifier, false, ErrCallback, nil},
		{"closed callback", AuthorizeConfig{ClientID: syntheticClientID, Tenant: syntheticTenant, Scopes: []string{syntheticScopeA}}, "closed", false, ErrState, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb := c
			if !tc.cb {
				cb = nil
			}
			v := tc.verifier
			if v == "closed" {
				// A Callback whose listener already stopped no longer
				// yields a redirect URI; it is closed before use.
				closed, closeVerifier, closeState := newURLFlow(t)
				closed.close()
				cb, v = closed, closeVerifier
				state = closeState
			}
			got, err := AuthorizationURL(cb, tc.cfg, v)
			if !errors.Is(err, tc.want) {
				t.Fatalf("case returned an unexpected sentinel (is %v, want %v)", err, tc.want)
			}
			if got != "" {
				t.Fatalf("case returned a URL with an error")
			}
			secrets := []string{v, state, verifier}
			for _, secret := range append([]string{tc.cfg.ClientID, tc.cfg.Tenant}, tc.cfg.Scopes...) {
				if len(secret) >= 4 {
					secrets = append(secrets, secret)
				}
			}
			secrets = append(secrets, tc.secret...)
			assertHidden(t, "config error", err.Error(), secrets...)
			assertHidden(t, "config error formatted", fmt.Sprintf("%+v|%#v|%s|%q", err, err, err, err), secrets...)
			// The message is the sentinel text itself: no wrapped detail.
			if err.Error() != tc.want.Error() {
				t.Fatalf("config error message is not the fixed sentinel text")
			}
		})
	}
}

func TestAuthorizationURLClosedCallback(t *testing.T) {
	c, verifier, _ := newURLFlow(t)
	c.close()
	got, err := AuthorizationURL(c, AuthorizeConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticTenant,
		Scopes:   []string{syntheticScopeA},
	}, verifier)
	if !errors.Is(err, ErrState) || got != "" {
		t.Fatalf("a closed Callback did not yield ErrState")
	}
	assertHidden(t, "closed callback error", err.Error(), c.state, verifier, syntheticClientID, syntheticTenant, syntheticScopeA)
}

// TestAuthorizationURLToCallbackSmoke is the minimal synthetic end-to-end
// check: the state and redirect_uri are read from the built URL, and a plain
// http.Client sends the provider's redirect to the real TCP loopback listener
// of the same Callback. No browser, no httptest server and no network beyond
// 127.0.0.1 are involved.
func TestAuthorizationURLToCallbackSmoke(t *testing.T) {
	c, verifier, _ := newURLFlow(t)
	u := mustAuthorizationURL(t, c, AuthorizeConfig{
		ClientID: syntheticClientID,
		Tenant:   syntheticTenant,
		Scopes:   []string{syntheticScopeA, syntheticScopeB},
	}, verifier)

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("authorize query does not parse")
	}
	state := query.Get("state")
	redirectURI := query.Get("redirect_uri")
	if state == "" || redirectURI == "" {
		t.Fatalf("authorize URL lacks state or redirect_uri")
	}
	ru, err := url.Parse(redirectURI)
	if err != nil || ru.Hostname() != LoopbackHost || ru.Path != CallbackPath {
		t.Fatalf("redirect_uri is not the loopback callback")
	}

	ch := waitResult(context.Background(), c, 0)

	// Follow redirect_uri as the browser would, adding the authorization
	// response: this run's state and the synthetic code.
	follow := *ru
	follow.RawQuery = url.Values{"state": {state}, "code": {syntheticCode}}.Encode()
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			// Refuse to reach anything but the loopback listener.
			Proxy: nil,
		},
		// Never follow a redirect out of the loopback listener.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, follow.String(), nil)
	if err != nil {
		t.Fatalf("building the callback request failed (details withheld)")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("the callback request did not complete (details withheld)")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("reading the callback page failed (details withheld)")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback returned status %d", resp.StatusCode)
	}
	p := string(body)
	if p != pageAuthorized {
		t.Fatalf("callback did not return the fixed authorized page")
	}
	assertHidden(t, "callback page", p, syntheticCode, state, verifier, S256(verifier),
		syntheticClientID, syntheticTenant, syntheticScopeA, redirectURI)

	res, werr := recv(t, ch, 2*time.Second)
	if werr != nil {
		t.Fatalf("Wait returned an unexpected error")
	}
	if res.Code() != syntheticCode {
		t.Fatalf("Wait did not return the test code")
	}
	assertHidden(t, "code source", u.String(), syntheticCode, verifier)
}
