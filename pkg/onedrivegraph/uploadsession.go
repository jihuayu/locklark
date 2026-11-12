// This file adds the first step of a conditional Graph upload: establishing a
// deferred upload session for one explicit drive item. It does not upload any
// bytes and does not commit or publish anything. There is no backend,
// ReadResult, revision, FetchCandidate conversion or /content request here.
//
// Begin first reads the configured drive through the fixed Graph route
// /drives/{driveID}?$select=id,driveType and accepts only a personal drive
// whose ID is exactly the configured one. Business and documentLibrary drives
// (and any unknown driveType) are refused before a session request exists.
//
// Begin then sends exactly one createUploadSession request to the fixed Graph
// item route. The caller's opaque ETag is placed in If-Match byte-for-byte,
// without quoting, parsing or normalization, and the body is exactly
// {"deferCommit":true}. Redirects are never followed and nothing is retried.
//
// The resulting session contains a pre-authenticated upload URL. That URL is a
// capability: it confers write access to the session without an Authorization
// header. It is kept only in an unexported UploadSession field, is never placed
// in an error or in formatted output, and is only accepted when its host is a
// documented Personal OneDrive upload host of the form *.up.1drv.com. The
// initial expirationDateTime is captured once as a fixed local deadline.
package onedrivegraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	// graphDriveSelect is the exact field set of the drive preflight.
	graphDriveSelect = "id,driveType"

	// maxDriveJSONSize bounds the complete drive preflight response body.
	maxDriveJSONSize = 64 << 10

	// maxUploadSessionJSONSize bounds the complete createUploadSession body.
	maxUploadSessionJSONSize = 64 << 10

	// maxUploadURLSize is the defensive bound on a pre-authenticated upload
	// capability URL. It is larger than an ordinary Graph URL because the
	// capability may carry provider state in its path and query.
	maxUploadURLSize = 8 << 10
)

// Upload-session sentinels. Like the other package sentinels they are fixed
// values and never contain a token, provider body, URL or ETag.
var (
	// ErrInvalidDrive reports a drive preflight response that is not valid,
	// bounded UTF-8 JSON describing exactly the configured drive ID.
	ErrInvalidDrive = errors.New("onedrive graph: invalid drive metadata")
	// ErrInvalidUploadSession reports a createUploadSession response that was
	// not the documented HTTP 200 with exactly one usable session.
	ErrInvalidUploadSession = errors.New("onedrive graph: invalid upload session")
	// ErrUnsafeUploadURL reports a session uploadUrl that is not a bounded,
	// HTTPS, non-userinfo, fragment-free URL on a *.up.1drv.com host with the
	// default port. Such a capability is never stored or returned.
	ErrUnsafeUploadURL = errors.New("onedrive graph: unsafe upload URL")
)

// ConditionalUploaderConfig is the complete uploader configuration. Every
// value is explicit; there are no defaults and nothing is read from files or
// the environment.
type ConditionalUploaderConfig struct {
	// DriveID is the Graph drive that contains the item.
	DriveID string
	// ItemID is the Graph drive item whose session is created.
	ItemID string
	// Tokens supplies one in-memory access token for each Begin call.
	Tokens AccessTokenSource
}

// ConditionalUploader establishes deferred upload sessions for one explicit
// drive item. It has no mutable state and is safe for concurrent use.
type ConditionalUploader struct {
	driveID string
	itemID  string
	tokens  AccessTokenSource

	// endpoint and client are the test-only seam. Both are nil in production,
	// where graphEndpoint and a fresh no-redirect client are used.
	endpoint *url.URL
	client   *http.Client
}

// UploadSession is a deferred upload session bound to one drive, item and
// expected ETag. Its upload capability URL is unexported: there is no public
// field or accessor for it, and formatting redacts it. The expiration captured
// from Graph is fixed when Begin returns and is never extended.
type UploadSession struct {
	driveID   string
	itemID    string
	etag      string
	uploadURL string
	expiresAt time.Time
}

// Format writes a fixed, redacted representation. It exists so that ordinary
// fmt verbs cannot print the pre-authenticated upload capability URL that the
// session holds in unexported state.
func (s UploadSession) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, "onedrivegraph.UploadSession{redacted}")
}

// NewConditionalUploader validates cfg and returns an uploader bound to the
// fixed production Graph endpoint. It performs no network request.
func NewConditionalUploader(cfg ConditionalUploaderConfig) (*ConditionalUploader, error) {
	return newConditionalUploader(cfg, nil, nil)
}

// newConditionalUploader is the unexported test seam. A nil endpoint or client
// selects the fixed production value, so production never depends on either
// argument.
func newConditionalUploader(cfg ConditionalUploaderConfig, endpoint *url.URL, client *http.Client) (*ConditionalUploader, error) {
	if !validUploadID(cfg.DriveID) || !validUploadID(cfg.ItemID) || cfg.Tokens == nil {
		return nil, fmt.Errorf("%w: a well-formed drive ID, item ID and access token source are required", vaultfilebackend.ErrDenied)
	}
	if endpoint != nil && !validEndpoint(endpoint) {
		return nil, fmt.Errorf("%w: endpoint must be an absolute https URL without userinfo, query or fragment", vaultfilebackend.ErrDenied)
	}
	u := &ConditionalUploader{
		driveID: cfg.DriveID,
		itemID:  cfg.ItemID,
		tokens:  cfg.Tokens,
	}
	if endpoint != nil {
		endpointCopy := *endpoint
		u.endpoint = &endpointCopy
	}
	if client != nil {
		clientCopy := *client
		u.client = &clientCopy
	}
	return u, nil
}

// Begin establishes one deferred upload session for expectedETag.
//
// Error mapping:
//   - A nil or cancelled context, a malformed/empty/oversize ETag, or a token
//     source failure is ErrDenied (with ErrAccessToken for a failed source);
//     nothing was sent and the source error is not retained.
//   - A drive preflight that is missing or not valid bounded UTF-8 JSON is
//     ErrCorrupt with ErrInvalidDrive. A missing drive is ErrNotFound and a
//     definite 4xx refusal is ErrDenied. Nothing was sent.
//   - A drive whose driveType is not exactly "personal" is ErrUnsupported, and
//     no createUploadSession request is sent.
//   - A createUploadSession 412 is ErrConflict; any other definite 4xx refusal
//     (including a generic 409) is ErrDenied, never ErrConflict.
//   - After the session POST has been handed to the transport, a transport or
//     context failure, redirect, 408, 429, 5xx, an unexpected status, or a 200
//     body that is not exactly one bounded session with a future RFC3339
//     expiration and a safe *.up.1drv.com capability is ErrUnknown (with
//     ErrInvalidUploadSession or ErrUnsafeUploadURL where applicable). The
//     session may or may not exist; Begin does not retry.
func (u *ConditionalUploader) Begin(ctx context.Context, expectedETag string) (*UploadSession, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if u == nil || !validUploadID(u.driveID) || !validUploadID(u.itemID) || u.tokens == nil {
		return nil, fmt.Errorf("%w: uploader is not configured", vaultfilebackend.ErrDenied)
	}
	if !validOpaqueETag(expectedETag) {
		return nil, fmt.Errorf("%w: expected ETag is empty, unsafe or too large", vaultfilebackend.ErrDenied)
	}

	token, err := u.tokens.AccessToken(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, deniedContext(ctxErr)
		}
		return nil, fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if !validAccessToken(token) {
		return nil, fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}

	if err := u.verifyPersonalDrive(ctx, token); err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return u.createSession(ctx, token, expectedETag)
}

// verifyPersonalDrive performs the fixed drive preflight and refuses every
// driveType other than exactly "personal".
func (u *ConditionalUploader) verifyPersonalDrive(ctx context.Context, token string) error {
	raw, err := u.driveURL()
	if err != nil {
		return err
	}
	req, err := newGraphRequest(ctx, token, http.MethodGet, raw, "", nil)
	if err != nil {
		return fmt.Errorf("%w: drive request could not be constructed", vaultfilebackend.ErrDenied)
	}
	resp, err := u.httpClient().Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return deniedContext(ctxErr)
		}
		return fmt.Errorf("%w: drive request failed", vaultfilebackend.ErrUnknown)
	}
	defer func() { _ = resp.Body.Close() }()

	switch code := resp.StatusCode; {
	case code == http.StatusOK:
		// Validated below.
	case code == http.StatusNotFound:
		return fmt.Errorf("%w: configured drive was not found", vaultfilebackend.ErrNotFound)
	case code >= 300 && code < 400:
		return unsafeRedirectError()
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		return fmt.Errorf("%w: drive request returned HTTP %d", vaultfilebackend.ErrUnknown, code)
	case code >= 400 && code < 500:
		return fmt.Errorf("%w: drive request returned HTTP %d", vaultfilebackend.ErrDenied, code)
	default:
		return fmt.Errorf("%w: drive request returned unexpected HTTP %d", vaultfilebackend.ErrUnknown, code)
	}

	body, err := readBoundedBody(ctx, resp, maxDriveJSONSize)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return deniedContext(ctxErr)
		}
		return invalidDrive("drive response body could not be read within its bound")
	}
	if !utf8.Valid(body) {
		return invalidDrive("drive response is not valid UTF-8")
	}
	fields, ok := decodeStrictJSONObject(body)
	if !ok {
		return invalidDrive("drive response is not one valid JSON object")
	}

	var id string
	if !decodeExactString(fields["id"], &id) || id != u.driveID {
		return invalidDrive("drive response ID does not match the configured drive")
	}
	var driveType string
	if !decodeExactString(fields["driveType"], &driveType) {
		return invalidDrive("drive response driveType is missing or not a string")
	}
	if driveType != "personal" {
		return fmt.Errorf("%w: configured drive is not a personal drive", vaultfilebackend.ErrUnsupported)
	}
	return nil
}

// createSession sends exactly one deferred session request and validates its
// success response. The caller's ETag is placed in If-Match exactly as given.
func (u *ConditionalUploader) createSession(ctx context.Context, token, expectedETag string) (*UploadSession, error) {
	raw, err := u.sessionURL()
	if err != nil {
		return nil, err
	}
	// The body is a fixed literal rather than an encoded struct so the bytes
	// on the wire are exactly the documented {"deferCommit":true}.
	req, err := newGraphRequest(ctx, token, http.MethodPost, raw, "application/json", []byte(`{"deferCommit":true}`))
	if err != nil {
		return nil, fmt.Errorf("%w: upload session request could not be constructed", vaultfilebackend.ErrDenied)
	}
	// The ETag is opaque: no quoting, parsing, trimming or normalization.
	req.Header.Set("If-Match", expectedETag)
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	resp, err := u.httpClient().Do(req)
	if err != nil {
		// The request may have reached Graph. The transport error can contain
		// the request URL or token; it is not retained.
		return nil, fmt.Errorf("%w: upload session request failed", vaultfilebackend.ErrUnknown)
	}
	defer func() { _ = resp.Body.Close() }()

	switch code := resp.StatusCode; {
	case code == http.StatusOK:
		// Validated below.
	case code == http.StatusPreconditionFailed:
		return nil, fmt.Errorf("%w: item ETag did not match", vaultfilebackend.ErrConflict)
	case code == http.StatusNotFound:
		return nil, fmt.Errorf("%w: configured item was not found", vaultfilebackend.ErrNotFound)
	case code >= 300 && code < 400:
		// A redirect is never followed and the POST may already have created a
		// session.
		return nil, fmt.Errorf("%w: upload session request was redirected", vaultfilebackend.ErrUnknown)
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		return nil, fmt.Errorf("%w: upload session request returned HTTP %d", vaultfilebackend.ErrUnknown, code)
	case code >= 400 && code < 500:
		// This includes a generic 409: only the documented 412 means the
		// conditional request definitely lost the ETag comparison.
		return nil, fmt.Errorf("%w: upload session request was refused with HTTP %d", vaultfilebackend.ErrDenied, code)
	default:
		// Only HTTP 200 is the documented createUploadSession success.
		return nil, fmt.Errorf("%w: upload session request returned unexpected HTTP %d", vaultfilebackend.ErrUnknown, code)
	}

	body, err := readBoundedBody(ctx, resp, maxUploadSessionJSONSize)
	if err != nil {
		return nil, invalidUploadSession("upload session response body could not be read within its bound")
	}
	if !utf8.Valid(body) {
		return nil, invalidUploadSession("upload session response is not valid UTF-8")
	}
	fields, ok := decodeStrictJSONObject(body)
	if !ok {
		return nil, invalidUploadSession("upload session response is not one valid JSON object")
	}

	var uploadURL string
	if !decodeExactString(fields["uploadUrl"], &uploadURL) || uploadURL == "" {
		return nil, invalidUploadSession("uploadUrl is missing, empty or not a string")
	}
	capability, ok := safePersonalUploadURL(uploadURL)
	if !ok {
		return nil, fmt.Errorf("%w: %w: uploadUrl is not a safe personal upload URL",
			vaultfilebackend.ErrUnknown, ErrUnsafeUploadURL)
	}

	var expiration string
	if !decodeExactString(fields["expirationDateTime"], &expiration) || expiration == "" {
		return nil, invalidUploadSession("expirationDateTime is missing, empty or not a string")
	}
	expiresAt, err := time.Parse(time.RFC3339, expiration)
	if err != nil {
		return nil, invalidUploadSession("expirationDateTime is not an RFC3339 timestamp")
	}
	if !expiresAt.After(time.Now()) {
		return nil, invalidUploadSession("expirationDateTime is not in the future")
	}

	return &UploadSession{
		driveID:   u.driveID,
		itemID:    u.itemID,
		etag:      expectedETag,
		uploadURL: capability,
		expiresAt: expiresAt,
	}, nil
}

func (u *ConditionalUploader) baseURL() string {
	if u.endpoint != nil {
		return strings.TrimRight(u.endpoint.String(), "/")
	}
	return graphEndpoint
}

func (u *ConditionalUploader) driveURL() (string, error) {
	raw := u.baseURL() + "/drives/" + url.PathEscape(u.driveID) + "?$select=" + graphDriveSelect
	return validateRequestURL(raw)
}

func (u *ConditionalUploader) sessionURL() (string, error) {
	raw := u.baseURL() + "/drives/" + url.PathEscape(u.driveID) + "/items/" + url.PathEscape(u.itemID) + "/createUploadSession"
	return validateRequestURL(raw)
}

func validateRequestURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !validGraphRequestURL(parsed) {
		return "", fmt.Errorf("%w: request URL could not be constructed", vaultfilebackend.ErrDenied)
	}
	return raw, nil
}

// httpClient returns a fresh client with redirects disabled for one request.
// The transport is cloned so that no pooled connection or state is shared
// between calls and any injected redirect policy is replaced.
func (u *ConditionalUploader) httpClient() *http.Client {
	c := http.Client{}
	if u.client != nil {
		c = *u.client
		c.Transport = freshTransport(u.client.Transport)
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

// validUploadID bounds an explicit Graph drive or item ID and restricts it to
// a conservative opaque path-segment alphabet. In particular a separator,
// whitespace, percent, query or fragment character can never be part of the
// fixed route, and the dot segments "." and ".." are rejected because
// url.PathEscape leaves them unescaped.
func validUploadID(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > maxItemIDSize || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '=' || c == '~' || c == '!' {
			continue
		}
		return false
	}
	return true
}

// decodeStrictJSONObject decodes exactly one bounded JSON object, rejecting
// duplicate top-level keys and any trailing data. Unknown fields are retained
// so that a documented Graph envelope such as @odata.context does not make a
// valid response unusable. Valid UTF-8 is checked by the caller before this
// decoder runs.
func decodeStrictJSONObject(body []byte) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	token, err := dec.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, false
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		fields[key] = raw
	}
	token, err = dec.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := token.(json.Delim); !ok || delim != '}' {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

// decodeExactString accepts a present JSON string and nothing else. A null,
// number, object, array or absent field is rejected.
func decodeExactString(raw json.RawMessage, out *string) bool {
	if len(raw) == 0 {
		return false
	}
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return false
	}
	*out = *value
	return true
}

// safePersonalUploadURL validates the pre-authenticated capability. It accepts
// only absolute HTTPS URLs on a documented Personal OneDrive upload host of
// the form *.up.1drv.com, with no userinfo, fragment, opaque form or explicit
// non-443 port. The value is sensitive and is never returned in an error.
func safePersonalUploadURL(raw string) (string, bool) {
	if raw == "" || len(raw) > maxUploadURLSize {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return "", false
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil ||
		!parsed.IsAbs() ||
		!strings.EqualFold(parsed.Scheme, "https") ||
		parsed.Opaque != "" ||
		parsed.User != nil ||
		parsed.Host == "" ||
		parsed.Hostname() == "" ||
		parsed.Fragment != "" ||
		parsed.RawFragment != "" {
		return "", false
	}
	port := parsed.Port()
	if port != "" && port != "443" {
		return "", false
	}
	if port == "" && strings.Contains(parsed.Host, ":") {
		// A colon without a parseable port is never acceptable, even if the
		// suffix check happens to pass.
		return "", false
	}
	if !validPersonalUploadHost(parsed.Hostname()) {
		return "", false
	}
	return raw, true
}

// validPersonalUploadHost requires a DNS name under the documented Personal
// OneDrive upload suffix. IP literals, localhost, the bare suffix and any
// arbitrary HTTPS host are refused.
func validPersonalUploadHost(host string) bool {
	host = strings.ToLower(host)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	const suffix = ".up.1drv.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(host, suffix)
	if prefix == "" {
		return false
	}
	for _, label := range strings.Split(prefix, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func invalidDrive(reason string) error {
	return fmt.Errorf("%w: %w: %s", vaultfilebackend.ErrCorrupt, ErrInvalidDrive, reason)
}

// invalidUploadSession reports a 200 createUploadSession response that cannot
// prove exactly one usable session. The POST was already sent, so the outcome
// is ErrUnknown: a session may exist.
func invalidUploadSession(reason string) error {
	return fmt.Errorf("%w: %w: %s", vaultfilebackend.ErrUnknown, ErrInvalidUploadSession, reason)
}
