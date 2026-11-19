package onedriveauth

import (
	"net/url"
	"strings"
)

// The Microsoft identity platform v2 authorization endpoint. Only the tenant
// path segment varies; the scheme, host and path are constants so the builder
// cannot be pointed anywhere else.
const (
	authorizeScheme = "https"
	authorizeHost   = "login.microsoftonline.com"
	authorizePath   = "/oauth2/v2.0/authorize"
)

// Limits on the caller-supplied configuration. They are format bounds, not
// security parameters; they keep a URL and its parameters to a sane size.
const (
	maxClientIDLen = 256
	maxTenantLen   = 128
	maxScopes      = 32
	maxScopeLen    = 256
)

// AuthorizeConfig is the caller-supplied half of a public-client authorization
// request. It holds no secret: a public client has no client secret, and the
// PKCE verifier is passed separately to AuthorizationURL so it is never stored
// here.
//
// There are no defaults: ClientID, Tenant and Scopes must each be given
// explicitly. Scopes are sent exactly as listed, in order, joined with a
// single space; the builder does not add, remove, reorder or expand any scope,
// and in particular does not add offline_access or openid.
type AuthorizeConfig struct {
	// ClientID is the application (client) ID of an application registration
	// configured as a public client.
	ClientID string
	// Tenant is a single path segment: a GUID (directory or application
	// tenant ID) or a DNS-style domain name such as "contoso.example". The
	// documented aliases "common", "organizations" and "consumers" are not
	// special-cased, so each is sent as the literal tenant.
	Tenant string
	// Scopes are the delegated scopes to request, one entry per scope. An
	// entry must not contain white space.
	Scopes []string
}

// AuthorizationURL builds the Microsoft identity platform v2 authorization
// code URL for one run of c. It reads the redirect URI and the state that c
// currently holds; neither is a parameter, so the URL can only redirect to the
// listener c runs and can only carry the state c verifies in Wait.
//
// verifier is the caller's PKCE verifier and must be well formed
// (ValidVerifier); its S256 challenge is sent. The request is a fixed
// authorization code flow: response_type=code, response_mode=query,
// code_challenge_method=S256, the explicit ClientID and the explicit Scopes.
//
// Every error is a fixed, redacted sentinel from this package: no client ID,
// tenant, scope, state, verifier or URL text is included. The returned URL
// does contain the state and the challenge, so the caller must not log or
// echo it.
//
// This only builds a URL. It does not open a browser, perform token exchange,
// call Microsoft Graph or access any account.
func AuthorizationURL(c *Callback, cfg AuthorizeConfig, verifier string) (string, error) {
	clientID, err := validClientID(cfg.ClientID)
	if err != nil {
		return "", err
	}
	tenant, err := validTenant(cfg.Tenant)
	if err != nil {
		return "", err
	}
	scope, err := joinScopes(cfg.Scopes)
	if err != nil {
		return "", err
	}
	if !ValidVerifier(verifier) {
		return "", wrap(ErrVerifier, nil)
	}
	if c == nil {
		return "", wrap(ErrCallback, nil)
	}
	redirectURI, err := c.RedirectURI()
	if err != nil {
		return "", err
	}
	// Read the state from the same Callback, in this package, so the URL
	// can only carry the state Wait verifies; it needs no accessor.
	state := c.state
	if !ValidState(state) {
		return "", wrap(ErrState, nil)
	}

	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("response_mode", "query")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", S256(verifier))
	q.Set("code_challenge_method", "S256")

	endpoint := url.URL{
		Scheme:   authorizeScheme,
		Host:     authorizeHost,
		Path:     "/" + tenant + authorizePath,
		RawQuery: q.Encode(),
	}
	return endpoint.String(), nil
}

// validClientID checks the shape of a client ID and returns it.
func validClientID(clientID string) (string, error) {
	if clientID == "" || len(clientID) > maxClientIDLen || !printableVisible(clientID) {
		return "", wrap(ErrClientID, nil)
	}
	return clientID, nil
}

// validTenant checks that tenant is safe as exactly one endpoint path segment
// and returns it unchanged. A tenant-shaped value (a GUID or a domain name)
// must not contain a ".." substring, which is the path dot-segment in one
// segment, because net/url.URL.String would leave that sequence unescaped and
// the target server or an intermediary could then resolve it as a relative
// path segment. A lone "." is rejected as a dot segment too. Any other run of
// dots, such as "a.b" or "a..b", is not a dot segment and is allowed.
func validTenant(tenant string) (string, error) {
	if tenant == "" || len(tenant) > maxTenantLen || !printableVisible(tenant) {
		return "", wrap(ErrTenant, nil)
	}
	// Anything outside the tenant-shaped alphabet (for example a space or
	// "/") is rejected; "." is checked separately below.
	for i := 0; i < len(tenant); i++ {
		c := tenant[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return "", wrap(ErrTenant, nil)
		}
	}
	if hasDotSegment(tenant) {
		return "", wrap(ErrTenant, nil)
	}
	return tenant, nil
}

// hasDotSegment reports whether v is a "." path segment or contains a ".."
// path dot-segment. Splitting v on "." cannot find those, because the caller
// only checks elements against "..", so the substrings are checked directly.
func hasDotSegment(v string) bool {
	return v == "." || strings.Contains(v, "..")
}

// joinScopes validates every explicit scope and joins them with a single
// space. It never adds a scope.
func joinScopes(scopes []string) (string, error) {
	if len(scopes) == 0 || len(scopes) > maxScopes {
		return "", wrap(ErrScope, nil)
	}
	for _, s := range scopes {
		if s == "" || len(s) > maxScopeLen {
			return "", wrap(ErrScope, nil)
		}
		// A scope is a sequence of RFC 6749 scope-token characters
		// (%x21 / %x23-5B / %x5D-7E); any white space would split it.
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return "", wrap(ErrScope, nil)
			}
		}
	}
	return strings.Join(scopes, " "), nil
}

// printableVisible reports whether v is a non-empty string of printable ASCII
// without SP or control characters.
func printableVisible(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}
