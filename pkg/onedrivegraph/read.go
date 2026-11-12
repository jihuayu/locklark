// Package onedrivegraph provides a narrow Microsoft Graph adapter for one
// vault file: a read transport that fetches a non-atomic fetch candidate, and
// a permission transport that grants or revokes one recipient permission on
// that file.
//
// A Reader is bound to one explicit drive ID and item ID and to a caller-owned
// in-memory access-token source. It never stores, refreshes or logs a token,
// and it never reads provider, account or application configuration from a
// file or the environment. The production endpoint is fixed at
// https://graph.microsoft.com/v1.0; the endpoint and HTTP client seams used by
// the tests are unexported and are nil in production.
//
// FetchCandidate observes item metadata before and after the content. Both
// metadata responses must describe the same file: the requested item ID, a
// file facet, a non-empty bounded opaque eTag, and a size between zero and
// vaultfilebackend.MaxValueSize. The observed eTag is returned byte-for-byte;
// it is never parsed, quoted, unquoted or otherwise normalized.
//
// The result is deliberately a candidate, not a verified snapshot. Graph has
// no atomic metadata-plus-content read, so the before/after observations are
// change detection only: an A -> B -> A change between them is undetectable,
// and equal eTags never prove that the bytes belong to the observed version.
// The package therefore exposes no backend, no ReadResult, no Revision and no
// verified-snapshot API; FetchCandidate's observed metadata must not be used
// as a conditional-write revision.
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
// FetchCandidate is a read transport operation. Its errors wrap only fixed
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
// FetchCandidate and never stores or logs the result. The source's error is
// not wrapped by FetchCandidate.
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
	// Tokens supplies the in-memory access token for each FetchCandidate.
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

// FetchCandidate obtains one access token, observes the item metadata,
// downloads the content through the documented /content route, and observes
// the metadata again.
//
// The returned FetchCandidate is an explicitly non-atomic transport result. It
// does not prove that Bytes belong to ObservedGraphETag or
// ObservedGraphSize: the two metadata observations bracket the download, but
// they cannot detect an A -> B -> A change in which both observations see A
// while the download returned B. Equal observations are therefore not a
// version proof.
//
// A disagreement between the two observations (ETag or size) is treated as
// change detection only and fails with ErrUnknown; it is never a success.
//
// Error mapping:
//   - A nil or cancelled context is ErrDenied and keeps the context cause in
//     the chain.
//   - A token-source failure is ErrAccessToken and ErrDenied; the source error
//     is not retained.
//   - A missing item is ErrNotFound. Other 4xx responses are ErrDenied. 429,
//     5xx, unexpected statuses, transport failures and a metadata change
//     between the two observations are ErrUnknown.
//   - Missing/invalid metadata is ErrCorrupt and ErrInvalidMetadata. A missing
//     file facet is ErrUnsupported and ErrInvalidMetadata.
//   - Metadata or content larger than its bound, or content whose declared or
//     actual length disagrees with metadata, is ErrCorrupt.
//   - A malformed, non-HTTPS, userinfo-bearing, fragment-bearing or oversize
//     Location, and any redirect after the accepted one, is ErrUnsafeRedirect
//     and ErrDenied.
func (r *Reader) FetchCandidate(ctx context.Context) (FetchCandidate, error) {
	if ctx == nil {
		return FetchCandidate{}, deniedContext(context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return FetchCandidate{}, deniedContext(err)
	}

	token, err := r.tokens.AccessToken(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return FetchCandidate{}, deniedContext(ctxErr)
		}
		return FetchCandidate{}, fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return FetchCandidate{}, deniedContext(ctxErr)
	}
	if !validAccessToken(token) {
		return FetchCandidate{}, fmt.Errorf("%w: %w", vaultfilebackend.ErrDenied, ErrAccessToken)
	}

	before, err := r.readMetadata(ctx, token)
	if err != nil {
		return FetchCandidate{}, err
	}

	data, err := r.readContent(ctx, token, before.size)
	if err != nil {
		return FetchCandidate{}, err
	}
	if err := ctx.Err(); err != nil {
		return FetchCandidate{}, deniedContext(err)
	}

	after, err := r.readMetadata(ctx, token)
	if err != nil {
		return FetchCandidate{}, err
	}
	if before.etag != after.etag || before.size != after.size {
		// Change detection only: the observations disagree, so nothing
		// candidate-shaped is returned. The inverse does not hold; agreement
		// does not prove that Bytes match the observed version.
		return FetchCandidate{}, fmt.Errorf("%w: item changed while it was being fetched", vaultfilebackend.ErrUnknown)
	}
	if int64(len(data)) != after.size {
		return FetchCandidate{}, fmt.Errorf("%w: content length does not match the final metadata size", vaultfilebackend.ErrCorrupt)
	}
	if err := ctx.Err(); err != nil {
		return FetchCandidate{}, deniedContext(err)
	}
	return FetchCandidate{
		Bytes:             data,
		ObservedGraphETag: after.etag,
		ObservedGraphSize: after.size,
	}, nil
}

// FetchCandidate is the result of Reader.FetchCandidate: downloaded bytes
// together with metadata observed immediately before and after the download.
//
// It is not a verified snapshot and not a vaultfilebackend.Revision. The
// observed metadata is not a verified version token, is not a
// compare-and-swap revision, and must not be passed to a backend conditional
// write such as ReplaceIfVersion. The observations cannot exclude a change
// that reverted to the observed value between them, so Bytes may belong to a
// different version than ObservedGraphETag describes. Callers that need a
// verified version must authenticate the content and verify the version by a
// mechanism that does not rely on these observations.
type FetchCandidate struct {
	// Bytes is a private copy of the downloaded content.
	Bytes []byte
	// ObservedGraphETag is the opaque Graph eTag observed by both metadata
	// reads, byte-for-byte as received. It is neither parsed nor normalized.
	ObservedGraphETag string
	// ObservedGraphSize is the size in bytes reported by Graph.
	ObservedGraphSize int64
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
	body, err := readCapped(resp.Body, maxMetadataJSONSize)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return validatedMetadata{}, deniedContext(ctxErr)
		}
		return validatedMetadata{}, invalidMetadata("metadata body could not be read")
	}
	if err := ctx.Err(); err != nil {
		return validatedMetadata{}, deniedContext(err)
	}
	// encoding/json replaces invalid UTF-8 in strings with U+FFFD, which would
	// silently alter an opaque eTag or ID. Reject the body before that happens.
	if !utf8.Valid(body) {
		return validatedMetadata{}, invalidMetadata("metadata body is not valid UTF-8")
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
	data, err := readCapped(resp.Body, int64(vaultfilebackend.MaxValueSize))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, deniedContext(ctxErr)
		}
		if errors.Is(err, errTooLarge) {
			return nil, fmt.Errorf("%w: content exceeds the maximum value size", vaultfilebackend.ErrCorrupt)
		}
		return nil, fmt.Errorf("%w: content body could not be read", vaultfilebackend.ErrCorrupt)
	}
	// A context cancelled at the end of a short body makes the next read
	// return io.EOF. That is cancellation, not a malformed body, so it is
	// checked before the length is classified.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, deniedContext(ctxErr)
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

// httpClient returns a fresh client for one request. The transport is also
// fresh so that no pooled connection or state is shared between calls, and any
// injected redirect policy is replaced: redirects are handled exactly once and
// manually, never by net/http.
func (r *Reader) httpClient() *http.Client {
	c := http.Client{}
	if r.client != nil {
		c = *r.client
		c.Transport = freshTransport(r.client.Transport)
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

func freshTransport(rt http.RoundTripper) http.RoundTripper {
	switch t := rt.(type) {
	case nil:
		return &http.Transport{}
	case *http.Transport:
		fresh := t.Clone()
		if fresh.TLSClientConfig != nil {
			fresh.TLSClientConfig = fresh.TLSClientConfig.Clone()
		}
		return fresh
	default:
		return rt
	}
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

// readCapped reads at most limit bytes synchronously and fails with
// errTooLarge as soon as the body is longer. It does not wrap the reader in a
// goroutine: the request context cancels and closes the response body, which
// unblocks the read, so no abandoned goroutine can write into a returned
// buffer. The caller maps the error to a fixed sentinel, so a transport or
// provider error is never exposed.
func readCapped(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge
	}
	return data, nil
}
