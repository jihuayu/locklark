package onedrivegraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// This file adds a narrow Microsoft Graph permission transport for one
// explicit file item. It is transport only: it is not a
// vaultfilebackend.Backend, it does not share links, and it does not claim that
// an invited address belongs to a verified Microsoft identity.
//
// Before every Grant and Revoke, the configured drive/item pair is checked
// against the fixed Graph item metadata route. Only an item that reports the
// configured ID with a file facet and without a folder facet may be changed,
// so a folder or a drive root can never be shared by mistake.
//
// Grant sends exactly one recipient with one role (read or write) to the
// invite route with requireSignIn true and sendInvitation false. No other
// field is sent and there is no way to change those flags. Revoke deletes
// exactly one caller-supplied permission ID under the configured drive/item,
// sending the documented Content-Type application/json with no body;
// Graph only deletes non-inherited permissions, and every deletion failure is
// reported as such without provider detail.
//
// Every request is made with a fresh client whose redirects are disabled, so
// the bearer token is sent only to the explicit endpoint and never forwarded
// to another host. Response bodies are size-bounded, must be valid UTF-8 and
// must be valid JSON. Once a mutation request may have been sent, a transport
// or context failure, a redirect, 408/429/5xx, or an invalid or oversize success
// response is ErrUnknown: the change may or may not have happened. Nothing is
// retried.
//
// Errors wrap only fixed vaultfilebackend sentinels (and, for cancellation, the
// standard context sentinels) and the package's fixed sentinels. Tokens,
// recipient addresses, provider bodies, request URLs and raw transport errors
// are never placed in an error.

const (
	// PermissionRoleRead is the recipient role that grants read access.
	PermissionRoleRead PermissionRole = "read"
	// PermissionRoleWrite is the recipient role that grants read and write.
	PermissionRoleWrite PermissionRole = "write"

	// graphItemFacetSelect is the exact field set of the permission preflight.
	// Both facets are requested so that a folder can be told apart from a
	// file; the response is never interpreted as content metadata.
	graphItemFacetSelect = "id,file,folder"

	// maxPermissionJSONSize bounds the complete permission response body.
	maxPermissionJSONSize = 256 << 10

	// maxPermissionIDSize bounds an opaque Graph permission ID.
	maxPermissionIDSize = vaultfilebackend.MaxRevisionSize

	// maxInviteEmailSize bounds a recipient address before it is sent.
	maxInviteEmailSize = 320

	// maxInviteAddressLength is the RFC 5321 maximum length of the local part.
	maxInviteAddressLength = 64

	// maxInviteDomainLength is the RFC 1035 maximum length of a domain name.
	maxInviteDomainLength = 253
)

// PermissionRole is a Graph recipient role. Exactly PermissionRoleRead and
// PermissionRoleWrite are accepted.
type PermissionRole string

// PermissionGrant is the result of Manager.Grant: the Graph permission ID and
// the granted role. The recipient is not echoed, and nothing here proves that
// the address belongs to a verified Microsoft identity.
type PermissionGrant struct {
	// PermissionID is the opaque permission ID returned by Graph, byte-for-byte.
	PermissionID string
	// Role is the granted role, read or write.
	Role PermissionRole
}

// Permission manager sentinels. Like the package sentinels they are fixed
// values that never contain provider data.
var (
	// ErrInvalidPermission reports a malformed argument or an item metadata
	// preflight that is not exactly the configured file: a missing or
	// mismatched ID, a missing file facet or a folder facet.
	ErrInvalidPermission = errors.New("onedrive graph: invalid permission request")
	// ErrPermissionResponse reports a mutation response whose body is not
	// exactly one permission for the requested recipient and role, a missing
	// invitation.signInRequired, or any link permission. Such a response is
	// always also ErrUnknown and ErrPermissionOutcomeUnknown: the invite was
	// sent, so the permission may still exist.
	ErrPermissionResponse = errors.New("onedrive graph: invalid permission response")
	// ErrPermissionOutcomeUnknown reports a mutation whose effect cannot be
	// confirmed after the request may have been sent. Callers must verify the
	// file's permissions before retrying.
	ErrPermissionOutcomeUnknown = errors.New("onedrive graph: permission change outcome unknown")
	// ErrPermissionNotDeletable reports a refused deletion. Graph only deletes
	// non-inherited permissions, so the permission may be inherited or the
	// caller may lack access; the outcome is unchanged.
	ErrPermissionNotDeletable = errors.New("onedrive graph: permission cannot be deleted")
)

// PermissionConfig is the complete permission-manager configuration. Every
// value is explicit; there are no defaults, scopes or configuration files.
type PermissionConfig struct {
	// DriveID is the Graph drive that contains the file.
	DriveID string
	// ItemID is the Graph drive item to grant or revoke on. It must resolve
	// to a file, not a folder or a drive root.
	ItemID string
	// Tokens supplies the in-memory access token for each request. Graph
	// requires Files.ReadWrite (delegated) for this operation.
	Tokens AccessTokenSource
}

// Manager is a permission transport bound to one drive/item pair. It has no
// mutable state and is safe for concurrent use.
type Manager struct {
	driveID string
	itemID  string
	tokens  AccessTokenSource

	// endpoint and client are the test-only seam. Both are nil in production,
	// where graphEndpoint and a fresh no-redirect client are used.
	endpoint *url.URL
	client   *http.Client
}

// NewManager validates cfg and returns a Manager bound to the production
// Graph endpoint. It performs no network request.
func NewManager(cfg PermissionConfig) (*Manager, error) {
	return newManager(cfg, nil, nil)
}

// newManager is the unexported test seam. A nil endpoint or client selects the
// fixed production value, so production never depends on either argument.
func newManager(cfg PermissionConfig, endpoint *url.URL, client *http.Client) (*Manager, error) {
	if !validOpaqueID(cfg.DriveID) || !validOpaqueID(cfg.ItemID) || cfg.Tokens == nil {
		return nil, fmt.Errorf("%w: drive ID, item ID and access token source are required", vaultfilebackend.ErrDenied)
	}
	if endpoint != nil && !validEndpoint(endpoint) {
		return nil, fmt.Errorf("%w: endpoint must be an absolute https URL without userinfo, query or fragment", vaultfilebackend.ErrDenied)
	}
	m := &Manager{
		driveID: cfg.DriveID,
		itemID:  cfg.ItemID,
		tokens:  cfg.Tokens,
	}
	if endpoint != nil {
		u := *endpoint
		m.endpoint = &u
	}
	if client != nil {
		c := *client
		m.client = &c
	}
	return m, nil
}

// graphRole returns the provider spelling of role. The mapping is fixed in
// code: there are no other roles and no configuration that can add one.
func graphRole(role PermissionRole) (string, bool) {
	switch role {
	case PermissionRoleRead:
		return "read", true
	case PermissionRoleWrite:
		return "write", true
	default:
		return "", false
	}
}

// Grant directly grants role on the configured file to exactly one recipient.
// It sends requireSignIn true and sendInvitation false: per Microsoft's
// documentation the recipient receives no mail, and access is granted only
// when the signed-in recipient's identity matches the address. Granting does
// not verify that the address belongs to a Microsoft identity.
//
// Error mapping:
//   - A nil or cancelled context, a malformed recipient or role, or a
//     token-source failure is ErrDenied (with ErrAccessToken for a failed
//     source). Nothing was sent.
//   - A preflight that fails or does not describe the configured file is
//     ErrCorrupt with ErrInvalidPermission, ErrNotFound when the item is
//     missing, or ErrUnsupported with ErrInvalidPermission when the item is a
//     folder or lacks a file facet. Nothing was sent.
//   - A definite 4xx refusal other than 408 and 429 is ErrDenied. Nothing was
//     sent.
//   - After the invite may have been sent, a transport or context failure, a
//     redirect, 408, 429, 5xx, a 207 partial result, or a 200 body that is not
//     exactly one permission for the recipient and role (with
//     invitation.signInRequired true and no link permission) is ErrUnknown
//     with ErrPermissionOutcomeUnknown. The permission may or may not exist;
//     Grant does not retry and the caller must check the file's permissions.
func (m *Manager) Grant(ctx context.Context, recipientEmail string, role PermissionRole) (PermissionGrant, error) {
	// Recipient values are kept out of error messages: errors carry only a
	// fixed field name.
	if !validInviteEmail(recipientEmail) {
		return PermissionGrant{}, fmt.Errorf("%w: recipient address is malformed", vaultfilebackend.ErrDenied)
	}
	roleSpelling, ok := graphRole(role)
	if !ok {
		return PermissionGrant{}, fmt.Errorf("%w: role must be read or write", vaultfilebackend.ErrDenied)
	}
	body, err := json.Marshal(struct {
		Recipients     []map[string]string `json:"recipients"`
		Roles          []string            `json:"roles"`
		RequireSignIn  bool                `json:"requireSignIn"`
		SendInvitation bool                `json:"sendInvitation"`
	}{
		Recipients:     []map[string]string{{"email": recipientEmail}},
		Roles:          []string{roleSpelling},
		RequireSignIn:  true,
		SendInvitation: false,
	})
	if err != nil {
		return PermissionGrant{}, fmt.Errorf("%w: invite body could not be encoded", vaultfilebackend.ErrDenied)
	}

	token, err := m.prepare(ctx)
	if err != nil {
		return PermissionGrant{}, err
	}
	raw, err := m.itemURL()
	if err != nil {
		return PermissionGrant{}, err
	}
	invite := raw + "/invite"
	if err := checkContext(ctx); err != nil {
		return PermissionGrant{}, err
	}

	resp, err := m.do(ctx, token, http.MethodPost, invite, "application/json", body)
	if err != nil {
		return PermissionGrant{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch code := resp.StatusCode; {
	case code == http.StatusOK:
		// Validated below.
	case code >= 200 && code < 300:
		// Only 200 carries the permission collection; any other success is
		// not a confirmed grant.
		return PermissionGrant{}, unknownOutcome("invite")
	case code >= 300 && code < 400:
		return PermissionGrant{}, unknownOutcome("invite")
	case code >= 400 && code < 500 && code != http.StatusTooManyRequests && code != http.StatusRequestTimeout:
		return PermissionGrant{}, fmt.Errorf("%w: invite request was refused with HTTP %d", vaultfilebackend.ErrDenied, code)
	default:
		return PermissionGrant{}, unknownOutcome("invite")
	}

	permissionID, err := readGrantResponse(ctx, resp, recipientEmail, role)
	if err != nil {
		return PermissionGrant{}, err
	}
	return PermissionGrant{PermissionID: permissionID, Role: role}, nil
}

// Revoke deletes exactly the permission permissionID under the configured
// drive/item. Graph only deletes non-inherited permissions; an inherited,
// missing or forbidden permission is refused and reported safely.
//
// Error mapping:
//   - A nil or cancelled context, a malformed permission ID, or a token-source
//     failure is ErrDenied (with ErrAccessToken for a failed source). Nothing
//     was sent.
//   - A preflight failure is mapped as in Grant. Nothing was sent.
//   - A definite 4xx refusal other than 408 and 429 is ErrDenied; 404 is
//     ErrNotFound; 401 and 403 are ErrDenied with ErrPermissionNotDeletable.
//     Nothing was sent.
//   - After the request may have been sent, a transport or context failure, a
//     redirect, 408, 429, 5xx, or a status other than 204 is ErrUnknown with
//     ErrPermissionOutcomeUnknown. The caller must check the remaining
//     permissions before retrying.
func (m *Manager) Revoke(ctx context.Context, permissionID string) error {
	if !validPermissionID(permissionID) {
		return fmt.Errorf("%w: permission ID is missing, unsafe or too large", vaultfilebackend.ErrDenied)
	}

	token, err := m.prepare(ctx)
	if err != nil {
		return err
	}
	raw, err := m.itemURL()
	if err != nil {
		return err
	}
	target := raw + "/permissions/" + url.PathEscape(permissionID)
	if err := checkContext(ctx); err != nil {
		return err
	}

	// Microsoft's permission: delete documentation marks Content-Type
	// application/json as required, even though the request has no body.
	resp, err := m.do(ctx, token, http.MethodDelete, target, "application/json", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	switch code := resp.StatusCode; {
	case code == http.StatusNoContent:
		return nil
	case code == http.StatusUnauthorized, code == http.StatusForbidden:
		// The deletion was refused; Graph only deletes non-inherited
		// permissions, so the permission may be inherited or the caller may
		// lack access. Nothing changed.
		return fmt.Errorf("%w: %w: permission deletion was refused with HTTP %d", vaultfilebackend.ErrDenied, ErrPermissionNotDeletable, code)
	case code == http.StatusTooManyRequests || code == http.StatusRequestTimeout || code >= 500 || code >= 300 && code < 400:
		return unknownOutcome("permission deletion")
	case code == http.StatusNotFound:
		return fmt.Errorf("%w: permission was not found", vaultfilebackend.ErrNotFound)
	case code >= 400 && code < 500:
		return fmt.Errorf("%w: permission request was refused with HTTP %d", vaultfilebackend.ErrDenied, code)
	default:
		// A 2xx other than 204 is not the documented success.
		return unknownOutcome("permission deletion")
	}
}

// prepare checks the context, obtains one token, and runs the file preflight.
// It fails only before any mutation request is constructed. A nil context is
// reported as ErrDenied with context.Canceled.
func (m *Manager) prepare(ctx context.Context) (string, error) {
	if err := checkContext(ctx); err != nil {
		return "", err
	}
	token, err := m.tokens.AccessToken(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", deniedContext(ctxErr)
		}
		return "", fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}
	if err := checkContext(ctx); err != nil {
		return "", err
	}
	if !validAccessToken(token) {
		return "", fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}
	if err := m.preflight(ctx, token); err != nil {
		return "", err
	}
	return token, nil
}

// checkContext rejects a nil context and reports a caller-visible cancellation
// or expiry as ErrDenied, distinctly from any post-send outcome.
func checkContext(ctx context.Context) error {
	if ctx == nil {
		return deniedContext(context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return deniedContext(err)
	}
	return nil
}

// itemFacets holds exactly the fields requested by graphItemFacetSelect. Graph
// returns only selected fields, so an unselected field must not be validated.
type itemFacets struct {
	ID     string    `json:"id"`
	File   *struct{} `json:"file"`
	Folder *struct{} `json:"folder"`
}

// preflight loads exactly graphItemFacetSelect for the configured item and
// requires a file item: the requested ID, a non-nil file facet and a nil folder
// facet. A folder-only or facet-less item is refused with ErrUnsupported; the
// drive root can never pass because its ID differs from the configured item ID
// or because it has a folder facet.
func (m *Manager) preflight(ctx context.Context, token string) error {
	raw, err := m.itemURL()
	if err != nil {
		return err
	}
	raw += "?$select=" + graphItemFacetSelect
	req, err := newGraphRequest(ctx, token, http.MethodGet, raw, "", nil)
	if err != nil {
		return fmt.Errorf("%w: request could not be constructed", vaultfilebackend.ErrDenied)
	}
	resp, err := m.httpClient().Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return deniedContext(ctxErr)
		}
		return fmt.Errorf("%w: item metadata request failed", vaultfilebackend.ErrUnknown)
	}
	defer func() { _ = resp.Body.Close() }()

	switch code := resp.StatusCode; {
	case code == http.StatusOK:
		// Validated below.
	case code == http.StatusNotFound:
		return fmt.Errorf("%w: configured item was not found", vaultfilebackend.ErrNotFound)
	case code == http.StatusTooManyRequests || code >= 500:
		return fmt.Errorf("%w: item metadata request returned HTTP %d", vaultfilebackend.ErrUnknown, code)
	case code >= 300 && code < 400:
		return unsafeRedirectError()
	default:
		return fmt.Errorf("%w: item metadata request returned HTTP %d", vaultfilebackend.ErrDenied, code)
	}

	body, err := readBoundedBody(ctx, resp, maxMetadataJSONSize)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return deniedContext(ctxErr)
		}
		return invalidPermission("item metadata body could not be read within its bound")
	}
	if !utf8.Valid(body) {
		return invalidPermission("item metadata is not valid UTF-8")
	}
	if strings.TrimSpace(string(body)) == "null" {
		return invalidPermission("item metadata is empty")
	}
	var facets itemFacets
	if err := json.Unmarshal(body, &facets); err != nil {
		return invalidPermission("item metadata is not valid JSON")
	}
	if facets.ID == "" || facets.ID != m.itemID {
		return invalidPermission("item metadata ID does not match the configured item; a drive root is never shared")
	}
	if facets.File == nil {
		return fmt.Errorf("%w: %w: configured item has no file facet and cannot be shared", vaultfilebackend.ErrUnsupported, ErrInvalidPermission)
	}
	if facets.Folder != nil {
		return fmt.Errorf("%w: %w: configured item is a folder and cannot be shared", vaultfilebackend.ErrUnsupported, ErrInvalidPermission)
	}
	return nil
}

type permissionResponse struct {
	Value []permission `json:"value"`
}

type permission struct {
	ID         string                `json:"id"`
	Roles      []string              `json:"roles"`
	Invitation *permissionInvitation `json:"invitation"`
	// Link is kept raw so that any non-null link, whatever its shape, marks
	// the permission as a link permission.
	Link      json.RawMessage `json:"link"`
	GrantedTo *struct {
		User *permissionIdentity `json:"user"`
	} `json:"grantedTo"`
	GrantedToV2 *struct {
		User     *permissionIdentity `json:"user"`
		SiteUser *permissionIdentity `json:"siteUser"`
	} `json:"grantedToV2"`
}

type permissionInvitation struct {
	// Email is the invited address documented by driveItem: invite.
	Email          string `json:"email"`
	SignInRequired *bool  `json:"signInRequired"`
}

type permissionIdentity struct {
	Email string `json:"email"`
}

// readGrantResponse validates a 200 invite response. It accepts exactly one
// permission whose ID is a bounded opaque value, whose roles are exactly the
// requested role, whose invitation.signInRequired is true, and whose recipient
// (grantedToV2, then grantedTo user, then invitation.email as documented by
// driveItem: invite) email matches the requested address. Any link permission
// rejects the whole response. Success only shows that Graph
// recorded a sign-in-gated permission for that address; it does not verify
// that the address belongs to a Microsoft identity.
func readGrantResponse(ctx context.Context, resp *http.Response, recipientEmail string, role PermissionRole) (string, error) {
	// The invite was already sent: any unreadable, truncated or oversize body
	// leaves the outcome unconfirmed.
	body, err := readBoundedBody(ctx, resp, maxPermissionJSONSize)
	if err != nil {
		return "", unknownOutcome("invite")
	}
	if !utf8.Valid(body) {
		return "", invalidPermissionResponse("invite response is not valid UTF-8")
	}
	if strings.TrimSpace(string(body)) == "null" {
		return "", invalidPermissionResponse("invite response is empty")
	}
	var parsed permissionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", invalidPermissionResponse("invite response is not valid JSON")
	}
	if len(parsed.Value) != 1 {
		return "", invalidPermissionResponse("invite response must contain exactly one permission")
	}
	p := parsed.Value[0]
	if !validPermissionID(p.ID) {
		return "", invalidPermissionResponse("permission ID is missing, unsafe or too large")
	}
	if len(p.Link) > 0 && string(p.Link) != "null" {
		return "", invalidPermissionResponse("invite response contains a link permission")
	}
	if want, ok := graphRole(role); !ok || len(p.Roles) != 1 || p.Roles[0] != want {
		return "", invalidPermissionResponse("permission roles do not match the requested role")
	}
	if p.Invitation == nil || p.Invitation.SignInRequired == nil || !*p.Invitation.SignInRequired {
		return "", invalidPermissionResponse("permission invitation must require sign-in")
	}
	if !p.matchesRecipient(recipientEmail) {
		return "", invalidPermissionResponse("permission recipient does not match the request")
	}
	return p.ID, nil
}

// matchesRecipient compares the permission's recipient email with the
// requested address case-insensitively. The grantedToV2 user, the older
// grantedTo user and the documented invitation.email are each accepted when
// present. A returned recipient whose address disagrees is never accepted, so
// a conflicting recipient rejects the response.
func (p permission) matchesRecipient(email string) bool {
	if p.GrantedToV2 != nil {
		if user := p.GrantedToV2.User; user != nil && user.Email != "" && !strings.EqualFold(user.Email, email) {
			return false
		}
		if user := p.GrantedToV2.SiteUser; user != nil && user.Email != "" && !strings.EqualFold(user.Email, email) {
			return false
		}
	}
	if p.GrantedTo != nil && p.GrantedTo.User != nil && p.GrantedTo.User.Email != "" && !strings.EqualFold(p.GrantedTo.User.Email, email) {
		return false
	}
	if p.Invitation != nil && p.Invitation.Email != "" && !strings.EqualFold(p.Invitation.Email, email) {
		return false
	}
	if p.GrantedToV2 != nil {
		if user := p.GrantedToV2.User; user != nil && strings.EqualFold(user.Email, email) {
			return true
		}
		if user := p.GrantedToV2.SiteUser; user != nil && strings.EqualFold(user.Email, email) {
			return true
		}
	}
	if p.GrantedTo != nil && p.GrantedTo.User != nil && strings.EqualFold(p.GrantedTo.User.Email, email) {
		return true
	}
	return p.Invitation != nil && p.Invitation.Email != "" && strings.EqualFold(p.Invitation.Email, email)
}

// itemURL is the fixed drive/item route shared by the preflight and the
// permission routes. The URL is built from the configured IDs and the fixed
// endpoint only.
func (m *Manager) itemURL() (string, error) {
	base := graphEndpoint
	if m.endpoint != nil {
		base = strings.TrimRight(m.endpoint.String(), "/")
	}
	raw := base + "/drives/" + url.PathEscape(m.driveID) + "/items/" + url.PathEscape(m.itemID)
	u, err := url.Parse(raw)
	if err != nil || !validGraphRequestURL(u) {
		return "", fmt.Errorf("%w: request URL could not be constructed", vaultfilebackend.ErrDenied)
	}
	return raw, nil
}

// do sends exactly one request with a fresh no-redirect client and returns the
// response. The request is never retried. A failure after the request was
// handed to the transport is ErrUnknown, because it may already have reached
// Graph; the transport error is not retained.
func (m *Manager) do(ctx context.Context, token, method, raw, contentType string, body []byte) (*http.Response, error) {
	req, err := newGraphRequest(ctx, token, method, raw, contentType, body)
	if err != nil {
		return nil, fmt.Errorf("%w: request could not be constructed", vaultfilebackend.ErrDenied)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, unknownOutcome("permission request")
	}
	return resp, nil
}

// newGraphRequest builds one fresh request carrying only the bearer token, an
// Accept header, the given Content-Type (when set) and, when body is non-nil,
// the fixed body. No header or state is shared with another request.
func newGraphRequest(ctx context.Context, token, method, raw, contentType string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}

// httpClient returns a fresh client with redirects disabled for one request.
// The transport is cloned so that no pooled connection or state is shared
// between calls and any injected redirect policy is replaced.
func (m *Manager) httpClient() *http.Client {
	c := http.Client{}
	if m.client != nil {
		c = *m.client
		c.Transport = freshTransport(m.client.Transport)
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

// readBoundedBody reads a bounded body. It returns ctx's error once the
// context is done and errTooLarge for an oversize body; any other reader error
// is returned unchanged for the caller to map to a fixed sentinel, so reader
// text is never exposed.
func readBoundedBody(ctx context.Context, resp *http.Response, limit int64) ([]byte, error) {
	if resp.ContentLength > limit {
		return nil, errTooLarge
	}
	body, err := readCapped(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return body, nil
}

// validPermissionID requires a non-empty permission ID within
// maxPermissionIDSize whose bytes are drawn only from the base64url/hex-like
// alphabet Graph uses for permission IDs. It is stricter than validOpaqueID so
// that a path separator, whitespace, percent or query character can never be
// part of a deletion route segment.
func validPermissionID(s string) bool {
	if s == "" || len(s) > maxPermissionIDSize {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '=' || c == '.' || c == '~' {
			continue
		}
		return false
	}
	return true
}

func validInviteEmail(email string) bool {
	if email == "" || len(email) > maxInviteEmailSize || !utf8.ValidString(email) {
		return false
	}
	for i := 0; i < len(email); i++ {
		if email[i] <= 0x20 || email[i] == 0x7f {
			return false
		}
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	local, domain := email[:at], email[at+1:]
	if len(local) > maxInviteAddressLength || len(domain) > maxInviteDomainLength {
		return false
	}
	if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", rune(c)) {
			return false
		}
	}
	if domain[0] == '.' || domain[len(domain)-1] == '.' || strings.Contains(domain, "..") {
		return false
	}
	labels := 0
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		labels++
	}
	return labels >= 2
}

func invalidPermission(reason string) error {
	return fmt.Errorf("%w: %w: %s", vaultfilebackend.ErrCorrupt, ErrInvalidPermission, reason)
}

// invalidPermissionResponse reports a success response that cannot prove
// exactly the requested permission. Because the invite was already sent, the
// permission may still have been created, so the result is ErrUnknown and
// keeps ErrPermissionResponse and ErrPermissionOutcomeUnknown.
func invalidPermissionResponse(reason string) error {
	return fmt.Errorf("%w: %w: %w: %s", vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown, ErrPermissionResponse, reason)
}

// unknownOutcome reports a mutation whose effect cannot be confirmed. The
// fixed operation name never contains provider data.
func unknownOutcome(operation string) error {
	return fmt.Errorf("%w: %w: %s may or may not have been applied", vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown, operation)
}
