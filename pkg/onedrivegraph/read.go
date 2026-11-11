// Package onedrivegraph provides a narrow, read-only Microsoft Graph adapter
// for one vault file.
//
// A Reader is bound to one explicit drive ID and item ID and to a caller-owned
// in-memory access-token source. It never stores, refreshes or logs a token,
// and it never reads provider, account or application configuration from a
// file or the environment. The production endpoint is fixed at
// https://graph.microsoft.com/v1.0; the endpoint and HTTP client seams used by
// the tests are unexported and are nil in production.
//
// Read fetches item metadata before and after the content. Both metadata
// responses must describe the same file: the requested item ID, a file facet,
// a non-empty bounded opaque ETag, and a size between zero and
// vaultfilebackend.MaxValueSize. The ETag is returned byte-for-byte as the
// Revision; it is never parsed, quoted, unquoted or otherwise normalized.
//
// The /content route is requested from the fixed Graph item. Exactly one 302
// redirect is accepted and is followed manually: the Location must be an
// absolute HTTPS URL without userinfo or a fragment and no longer than
// maxRedirectLocationSize. The Location is treated as sensitive: it is never
// included in an error. The redirected request is freshly constructed with no
// Authorization header, and every further redirect is rejected. Consequently
// the access token is sent only to the fixed Graph endpoint, never to the
// pre-authenticated download host.
//
// Read is a read-only backend operation. Its errors wrap only fixed
// vaultfilebackend sentinels and the package's fixed sentinels; transport,
// JSON, token-source and provider errors are deliberately not placed in the
// error chain, because their messages can contain a token, a provider body, a
// request URL or a redirect Location.
package onedrivegraph

import (
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

const (
	// graphEndpoint is the only endpoint a production Reader ever contacts.
	graphEndpoint = "https://graph.microsoft.com/v1.0"

	// graphMetadataSelect is the exact field set requested by both metadata
	// reads. itemMetadata keeps only these four fields.
	graphMetadataSelect = "id,eTag,size,file"

	// maxMetadataJSONSize bounds the complete metadata response body. The four
	// selected fields are tiny; this bound leaves ample room for Graph's JSON
	// envelope while preventing an unbounded allocation.
	maxMetadataJSONSize = 64 << 10

	// maxRedirectLocationSize is the defensive bound on a /content Location.
	// A pre-authenticated download URL is long, but an unbounded header is
	// neither needed nor safe to retain and request.
	maxRedirectLocationSize = 8 << 10

	// maxAccessTokenSize bounds the caller-supplied bearer token before it is
	// placed in a header. It is a local usage bound, not a token format check.
	maxAccessTokenSize = 16 << 10

	// maxItemIDSize bounds an explicit Graph drive or item ID.
	maxItemIDSize = 1024
)

// Package sentinels classify failures that do not have a more precise
// vaultfilebackend meaning. They are fixed values and never contain provider
// data.
var (
	// ErrAccessToken reports that the token source failed or supplied a token
	// that cannot safely be placed in an Authorization header. The source's
	// own error is intentionally not wrapped: it may contain a token.
	ErrAccessToken = errors.New("onedrive graph: access token unavailable")
	// ErrInvalidMetadata reports metadata that cannot satisfy the single-file
	// read contract: a malformed body, a mismatched ID, a missing or unsafe
	// ETag, or a missing or out-of-range size.
	ErrInvalidMetadata = errors.New("onedrive graph: invalid item metadata")
	// ErrUnsafeRedirect reports a /content response that is not exactly one
	// acceptable 302, or a redirect on the download request.
	ErrUnsafeRedirect = errors.New("onedrive graph: unsafe redirect")
)

// AccessTokenSource is the narrow token seam. AccessToken must return a
// short-lived access token held only in memory. A Reader calls it once per
// Read and never stores or logs the result. An error is not wrapped by Read.
type AccessTokenSource interface {
	AccessToken(ctx context.Context) (string, error)
}

// AccessTokenProvider is an alias kept for callers that name the seam after
// the operation it supplies rather than the source of the value.
type AccessTokenProvider = AccessTokenSource

// Reader is a single-file, read-only Graph adapter. It has no mutable state
// and is safe for concurrent use.
type Reader struct {
	driveID string
	itemID  string
	tokens  AccessTokenSource

	// endpoint and client are the test-only seam. Both are nil in production,
	// where graphEndpoint and a fresh no-redirect client are used.
	endpoint *url.URL
	client   *http.Client
}

// ReaderConfig is the complete production configuration. Every value is
// explicit; there are no defaults and nothing is read from files or the
// environment.
type ReaderConfig struct {
	// DriveID is the Graph drive that contains the file.
	DriveID string
	// ItemID is the Graph drive item to read. It must identify a file.
	ItemID string
	// Tokens supplies the in-memory access token for each Read.
	Tokens AccessTokenSource
}

// Config is an alias for ReaderConfig.
type Config = ReaderConfig

// NewReader validates cfg and returns a Reader bound to the fixed production
// Graph endpoint. It performs no network request.
func NewReader(cfg ReaderConfig) (*Reader, error) {
	return newReader(cfg, nil, nil)
}

// New is an alias for NewReader.
func New(cfg ReaderConfig) (*Reader, error) { return NewReader(cfg) }

// newReader is the unexported test seam. A nil endpoint or client selects the
// fixed production value, so production never depends on either argument.
func newReader(cfg ReaderConfig, endpoint *url.URL, client *http.Client) (*Reader, error) {
	if !validOpaqueID(cfg.DriveID) || !validOpaqueID(cfg.ItemID) || cfg.Tokens == nil {
		return nil, fmt.Errorf("%w: drive ID, item ID and access token source are required", vaultfilebackend.ErrDenied)
	}
	if endpoint != nil && !validEndpoint(endpoint) {
		return nil, fmt.Errorf("%w: endpoint must be an absolute https URL without userinfo, query or fragment", vaultfilebackend.ErrDenied)
	}
	r := &Reader{
		driveID: cfg.DriveID,
		itemID:  cfg.ItemID,
		tokens:  cfg.Tokens,
	}
	if endpoint != nil {
		u := *endpoint
		r.endpoint = &u
	}
	if client != nil {
		c := *client
		r.client = &c
	}
	return r, nil
}

// Read obtains one access token, reads the item metadata, downloads the
// content through the documented /content route, and reads the metadata again.
// It returns the downloaded bytes and the exact ETag of the version that both
// metadata reads agree on.
//
// Error mapping:
//   - A cancelled context is ErrDenied and keeps the context cause in the
//     chain.
//   - A token-source failure is ErrAccessToken and ErrDenied; the source error
//     is not retained.
//   - A missing item is ErrNotFound. Other 4xx responses are ErrDenied. 429,
//     5xx, unexpected statuses, transport failures and a version that changes
//     between the two metadata reads are ErrUnknown.
//   - Missing/invalid metadata is ErrCorrupt and ErrInvalidMetadata. A missing
//     file facet is ErrUnsupported and ErrInvalidMetadata.
//   - Content larger than MaxValueSize, or content whose declared or actual
//     length disagrees with metadata, is ErrCorrupt.
//   - A malformed, non-HTTPS, userinfo-bearing, fragment-bearing or oversize
//     Location, and any redirect after the accepted one, is ErrUnsafeRedirect
//     and ErrDenied.
func (r *Reader) Read(ctx context.Context) (vaultfilebackend.ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return vaultfilebackend.ReadResult{}, deniedContext(err)
	}

	token, err := r.tokens.AccessToken(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return vaultfilebackend.ReadResult{}, deniedContext(ctxErr)
		}
		return vaultfilebackend.ReadResult{}, fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return vaultfilebackend.ReadResult{}, deniedContext(ctxErr)
	}
	if !validAccessToken(token) {
		return vaultfilebackend.ReadResult{}, fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}

	before, err := r.readMetadata(ctx, token)
	if err != nil {
		return vaultfilebackend.ReadResult{}, err
	}

	data, err := r.readContent(ctx, token, before.size)
	if err != nil {
		return vaultfilebackend.ReadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return vaultfilebackend.ReadResult{}, deniedContext(err)
	}

	after, err := r.readMetadata(ctx, token)
	if err != nil {
		return vaultfilebackend.ReadResult{}, err
	}
	if before.etag != after.etag || before.size != after.size {
		// The bytes and the metadata no longer describe one committed version.
		// Read is side-effect free, so the caller may simply retry.
		return vaultfilebackend.ReadResult{}, fmt.Errorf("%w: item changed while it was being read", vaultfilebackend.ErrUnknown)
	}
	if int64(len(data)) != after.size {
		return vaultfilebackend.ReadResult{}, fmt.Errorf("%w: content length does not match the final metadata size", vaultfilebackend.ErrCorrupt)
	}
	if err := ctx.Err(); err != nil {
		return vaultfilebackend.ReadResult{}, deniedContext(err)
	}
	return vaultfilebackend.ReadResult{Bytes: data, Revision: vaultfilebackend.Revision(before.etag)}, nil
}

type itemMetadata struct {
	ID   string    `json:"id"`
	ETag *string   `json:"eTag"`
	Size *int64    `json:"size"`
	File *struct{} `json:"file"`
}

type validatedMetadata struct {
	etag string
	size int64
}

func (r *Reader) readMetadata(ctx context.Context, token string) (validatedMetadata, error) {
	raw, err := r.itemURL(true)
	if err != nil {
		return validatedMetadata{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return validatedMetadata{}, fmt.Errorf("%w: metadata request could not be constructed", vaultfilebackend.ErrDenied)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient().Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return validatedMetadata{}, deniedContext(ctxErr)
		}
		// The transport error can contain the request URL; do not retain it.
		return validatedMetadata{}, fmt.Errorf("%w: metadata request failed", vaultfilebackend.ErrUnknown)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return validatedMetadata{}, statusError("metadata", resp.StatusCode)
	}
	if resp.ContentLength > maxMetadataJSONSize {
		return validatedMetadata{}, invalidMetadata("metadata body is too large")
	}
	body, err := readCapped(ctx, resp.Body, maxMetadataJSONSize)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return validatedMetadata{}, deniedContext(ctxErr)
		}
		return validatedMetadata{}, invalidMetadata("metadata body could not be read")
	}
	if err := ctx.Err(); err != nil {
		return validatedMetadata{}, deniedContext(err)
	}

	var md itemMetadata
	if err := json.Unmarshal(body, &md); err != nil {
		return validatedMetadata{}, invalidMetadata("metadata body is not valid JSON")
	}
	if md.ID != r.itemID || md.ID == "" {
		return validatedMetadata{}, invalidMetadata("metadata item ID does not match the configured item")
	}
	if md.File == nil {
		return validatedMetadata{}, fmt.Errorf("%w: %w: item has no file facet", vaultfilebackend.ErrUnsupported, ErrInvalidMetadata)
	}
	if md.ETag == nil || !validOpaqueETag(*md.ETag) {
		return validatedMetadata{}, invalidMetadata("metadata ETag is missing, unsafe or too large")
	}
	if md.Size == nil || *md.Size < 0 || *md.Size > vaultfilebackend.MaxValueSize {
		return validatedMetadata{}, invalidMetadata("metadata size is missing or outside the supported bound")
	}
	return validatedMetadata{etag: *md.ETag, size: *md.Size}, nil
}

func (r *Reader) readContent(ctx context.Context, token string, expectedSize int64) ([]byte, error) {
	raw, err := r.itemURL(false)
	if err != nil {
		return nil, err
	}
	raw += "/content"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: content request could not be constructed", vaultfilebackend.ErrDenied)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient().Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, deniedContext(ctxErr)
		}
		return nil, fmt.Errorf("%w: content request failed", vaultfilebackend.ErrUnknown)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return readContentResponse(ctx, resp, expectedSize)
	case http.StatusFound:
		// Exactly one redirect is handled here, manually.
	default:
		_ = resp.Body.Close()
		return nil, unsafeOrStatusError("content", resp.StatusCode)
	}

	locations := resp.Header.Values("Location")
	_ = resp.Body.Close()
	if len(locations) != 1 {
		return nil, unsafeRedirectError()
	}
	location := locations[0]
	downloadURL, ok := safeDownloadURL(location)
	if !ok {
		return nil, unsafeRedirectError()
	}
	if err := ctx.Err(); err != nil {
		return nil, deniedContext(err)
	}

	// A fresh request carries no Authorization header and no headers copied
	// from the Graph request. The client also refuses to follow any redirect.
	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, unsafeRedirectError()
	}
	downloadResp, err := r.httpClient().Do(downloadReq)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, deniedContext(ctxErr)
		}
		// The transport error can contain the redirect Location; do not retain
		// it.
		return nil, fmt.Errorf("%w: download request failed", vaultfilebackend.ErrUnknown)
	}
	if downloadResp.StatusCode != http.StatusOK {
		_ = downloadResp.Body.Close()
		return nil, unsafeOrStatusError("download", downloadResp.StatusCode)
	}
	return readContentResponse(ctx, downloadResp, expectedSize)
}

func readContentResponse(ctx context.Context, resp *http.Response, expectedSize int64) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength > int64(vaultfilebackend.MaxValueSize) {
		return nil, fmt.Errorf("%w: content exceeds the maximum value size", vaultfilebackend.ErrCorrupt)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != expectedSize {
		return nil, fmt.Errorf("%w: declared content length does not match metadata", vaultfilebackend.ErrCorrupt)
	}
	data, err := readCapped(ctx, resp.Body, int64(vaultfilebackend.MaxValueSize))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, deniedContext(ctxErr)
		}
		if errors.Is(err, errTooLarge) {
			return nil, fmt.Errorf("%w: content exceeds the maximum value size", vaultfilebackend.ErrCorrupt)
		}
		return nil, fmt.Errorf("%w: content body could not be read", vaultfilebackend.ErrCorrupt)
	}
	if int64(len(data)) != expectedSize {
		return nil, fmt.Errorf("%w: content length does not match metadata", vaultfilebackend.ErrCorrupt)
	}
	if err := ctx.Err(); err != nil {
		return nil, deniedContext(err)
	}
	return data, nil
}

func (r *Reader) itemURL(metadata bool) (string, error) {
	base := graphEndpoint
	if r.endpoint != nil {
		base = strings.TrimRight(r.endpoint.String(), "/")
	}
	raw := base + "/drives/" + url.PathEscape(r.driveID) + "/items/" + url.PathEscape(r.itemID)
	if metadata {
		raw += "?$select=" + graphMetadataSelect
	}
	u, err := url.Parse(raw)
	if err != nil || !validGraphRequestURL(u) {
		return "", fmt.Errorf("%w: request URL could not be constructed", vaultfilebackend.ErrDenied)
	}
	return raw, nil
}

func (r *Reader) httpClient() *http.Client {
	base := r.client
	if base == nil {
		base = &http.Client{}
	}
	c := *base
	// Override any injected policy: redirects are handled exactly once and
	// manually, never by net/http.
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

func validEndpoint(u *url.URL) bool {
	return validGraphRequestURL(u) && u.RawQuery == ""
}

func validGraphRequestURL(u *url.URL) bool {
	return u != nil &&
		strings.EqualFold(u.Scheme, "https") &&
		u.Host != "" &&
		u.Hostname() != "" &&
		u.User == nil &&
		u.Fragment == "" &&
		u.RawFragment == "" &&
		u.Opaque == ""
}

func validOpaqueID(s string) bool {
	if s == "" || len(s) > maxItemIDSize || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

func validAccessToken(s string) bool {
	if s == "" || len(s) > maxAccessTokenSize || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// validOpaqueETag requires a non-empty, bounded, valid-UTF-8 value with no
// ASCII control bytes or whitespace. It deliberately does not require or
// remove quotes and does not otherwise interpret the tag: Graph ETags are
// opaque and are returned exactly as received.
func validOpaqueETag(s string) bool {
	if s == "" || len(s) > vaultfilebackend.MaxRevisionSize || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// safeDownloadURL validates a /content Location. The value is sensitive and is
// never returned in an error. It must fit the defensive length bound, contain
// no raw whitespace or control bytes, be absolute HTTPS with a host, and have
// no userinfo, fragment or opaque form.
func safeDownloadURL(raw string) (string, bool) {
	if raw == "" || len(raw) > maxRedirectLocationSize {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return "", false
		}
	}
	u, err := url.Parse(raw)
	if err != nil ||
		!u.IsAbs() ||
		!strings.EqualFold(u.Scheme, "https") ||
		u.Host == "" ||
		u.Hostname() == "" ||
		u.User != nil ||
		u.Fragment != "" ||
		u.RawFragment != "" ||
		u.Opaque != "" {
		return "", false
	}
	return raw, true
}

func unsafeOrStatusError(scope string, code int) error {
	if code >= 300 && code < 400 {
		return unsafeRedirectError()
	}
	return statusError(scope, code)
}

func statusError(scope string, code int) error {
	switch {
	case code == http.StatusNotFound:
		return fmt.Errorf("%w: %s request returned HTTP %d", vaultfilebackend.ErrNotFound, scope, code)
	case code == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s request returned HTTP %d", vaultfilebackend.ErrUnknown, scope, code)
	case code >= 400 && code < 500:
		return fmt.Errorf("%w: %s request returned HTTP %d", vaultfilebackend.ErrDenied, scope, code)
	default:
		return fmt.Errorf("%w: %s request returned HTTP %d", vaultfilebackend.ErrUnknown, scope, code)
	}
}

func invalidMetadata(reason string) error {
	return fmt.Errorf("%w: %w: %s", vaultfilebackend.ErrCorrupt, ErrInvalidMetadata, reason)
}

func unsafeRedirectError() error {
	return fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrUnsafeRedirect)
}

func deniedContext(err error) error {
	return fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, err)
}

// errTooLarge is internal only; its message is never returned directly.
var errTooLarge = errors.New("body larger than limit")

// readCapped reads at most limit bytes and fails with errTooLarge as soon as
// the body is longer. The caller maps the error to a fixed sentinel, so a
// transport or provider error is never exposed.
func readCapped(ctx context.Context, body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: body}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge
	}
	return data, nil
}

// contextReader makes a body read observe the caller's cancellation even when
// the underlying reader does not. The response body is closed by the caller,
// which unblocks an abandoned read.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := c.r.Read(p)
		done <- result{n: n, err: err}
	}()
	select {
	case res := <-done:
		return res.n, res.err
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}
