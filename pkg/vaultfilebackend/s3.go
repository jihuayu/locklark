package vaultfilebackend

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Config is the explicit configuration of an S3 backend. Every field is
// caller-supplied: the bridge never reads environment variables, shared
// config/credential files, instance metadata or other machine state, and
// never falls back to the real AWS endpoints.
type S3Config struct {
	// Endpoint is the absolute https URL of the S3-compatible service, for
	// example "https://s3.example.test:443". HTTPS is the default and the only
	// accepted scheme: plain http is rejected with ErrDenied, because
	// conditional writes and the ETags they depend on would travel unencrypted
	// and be open to tampering. The URL is used verbatim; no AWS endpoint
	// resolution is applied.
	Endpoint string
	// Region is the SigV4 signing region.
	Region string
	// Bucket is the bucket holding the objects.
	Bucket string
	// Prefix is prepended to every name as "Prefix/Name". It may be empty.
	// It may contain '/', must not start with '/', and both Prefix and every
	// resulting object key must be at most MaxNameSize bytes and free of
	// control characters, so List can invert the mapping unambiguously.
	Prefix string
	// Credentials is the only credential source. It is required; the bridge
	// never chains to other providers.
	Credentials aws.CredentialsProvider
	// UsePathStyle selects "Endpoint/Bucket/Key" addressing instead of
	// virtual-hosted "Bucket.Endpoint/Key". Most non-AWS services need true.
	UsePathStyle bool
	// HTTPClient is optional. The SDK signs and transports every request with
	// it, so custom transports keep the SDK's SigV4 path.
	HTTPClient *http.Client
}

// s3Backend is the conditional-write S3 bridge (#112 foundation).
//
// Read is one GetObject with ChecksumMode=ENABLED; the returned bytes are the
// full body (bounded by MaxValueSize) and the Revision is the response ETag
// verbatim, quotes included. CreateIfAbsent is one PutObject with
// If-None-Match: *; ReplaceIfVersion is one PutObject with If-Match set to the
// expected revision verbatim. There is no Head-then-Put sequence and no
// unconditional fallback: the bridge only ever issues the conditional write.
//
// The bridge supports only services that enforce S3 conditional-write
// semantics for PutObject (If-None-Match: * and If-Match, including ETag-based
// If-Match). It does not detect a service that accepts the headers but
// silently ignores them: the outcome of an ignored precondition is not
// observable by this driver (a put that was let through looks like a normal
// committed put). Such a service is unsupported, not merely untested.
//
// The SDK retryer is fixed to MaxAttempts=1. A retry of an already committed
// conditional Put could observe the 412/409 that the first attempt caused and
// misreport a committed write as ErrConflict, so the bridge never retries
// inside one call. Callers that want to retry resolve the outcome with Read.
//
// Error mapping (mutations):
//   - 412 PreconditionFailed and 409 ConditionalRequestConflict mean the
//     service refused the write; nothing was committed: ErrConflict.
//   - A 404 whose error code is NoSuchKey means the precondition failed
//     because the name has no committed version: ErrConflict.
//   - A 404 whose code is NoSuchBucket (or any other 404) means the
//     configuration is wrong, not a version conflict: ErrDenied.
//   - 403, 400, and other 4xx handled by the service return ErrDenied.
//   - ReplaceIfVersion checks the caller's context and Close first (ErrDenied
//     once cancelled or closed, whatever the expected Revision), then the
//     zero and over MaxRevisionSize expected Revisions (malformed:
//     ErrDenied). A non-zero, in-bound expected Revision that is not one
//     well-formed strong quoted ETag (see validStrongETag) is refused with
//     ErrConflict before any request is sent: no committed version can carry
//     such a revision. These checks never issue a request.
//   - Transport failures whose request did not reach the service, and local
//     cancellation before any bytes were sent, are ErrDenied.
//   - Transport failures after the request was (possibly) sent, timeouts,
//     5xx responses, 429, and unparseable or ambiguous responses are
//     ErrUnknown: the write may or may not have committed.
//
// Error mapping (Read). Read never writes: ErrUnknown here means only that
// the bytes and revision were not reliably obtained, and the caller may retry
// Read.
//   - A 404 whose error code is NoSuchKey, or a 404 carrying no service code
//     (including the SDK's status-derived NotFound), is ErrNotFound.
//   - A 404 whose code is NoSuchBucket or another explicit service code (for
//     example NoSuchAccessPoint) means the configuration is wrong: ErrDenied.
//   - Any other 4xx response (authorization, malformed request) is ErrDenied;
//     a 5xx, 429, or any response whose status is neither 4xx nor 5xx is
//     ErrUnknown.
//   - Transport failures whose request definitely did not reach the service
//     (DNS lookup, dial/connect, certificate verification; see notSent), and
//     a caller cancellation that the SDK reports as not sent, are ErrDenied:
//     nothing was read or written. A caller cancellation observed before any
//     request or after the body was read is ErrDenied.
//   - Transport failures after the request was (possibly) sent, timeouts,
//     5xx responses, 429, and unparseable or ambiguous responses are
//     ErrUnknown: no reliable bytes or revision were obtained, and the caller
//     may retry Read.
//   - An ETag that cannot be safely handed back as an If-Match value (see
//     validStrongETag: weak, list, OWS-padded, control characters, empty or
//     over MaxRevisionSize; an opaque tag containing ',' is valid) is
//     ErrCorrupt.
//   - A body larger than MaxValueSize, or a body whose length does not match
//     Content-Length, is ErrCorrupt.
//
// List returns ErrUnsupported.
//
// This bridge is only verified against an in-process TLS S3 mock. It is not
// wired to product or account code and has not been accepted against any real
// account or service.
type s3Backend struct {
	client *s3.Client
	bucket string
	prefix string

	mu     sync.Mutex
	closed bool
}

// NewS3 returns an S3 backend configured exactly by cfg. It performs no
// network or credential resolution; the first request reports configuration
// problems that cannot be checked locally.
func NewS3(cfg S3Config) (Backend, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	endpoint := cfg.Endpoint
	opts := s3.Options{
		Region:                     cfg.Region,
		BaseEndpoint:               &endpoint,
		Credentials:                aws.NewCredentialsCache(cfg.Credentials),
		UsePathStyle:               cfg.UsePathStyle,
		Retryer:                    aws.NopRetryer{},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	// A nil HTTPClient on this field panics inside the SDK transport.
	if cfg.HTTPClient != nil {
		opts.HTTPClient = cfg.HTTPClient
	}
	client := s3.New(opts)
	return &s3Backend{client: client, bucket: cfg.Bucket, prefix: cfg.Prefix}, nil
}

func (cfg S3Config) validate() error {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("%w: s3 endpoint must be an absolute https URL without user info, query or fragment", ErrDenied)
	}
	if cfg.Region == "" || cfg.Bucket == "" || cfg.Credentials == nil {
		return fmt.Errorf("%w: s3 region, bucket and credentials provider are required", ErrDenied)
	}
	if cfg.Prefix != "" {
		// Reserve room for "/" and at least one name byte.
		if strings.HasPrefix(cfg.Prefix, "/") || !s3KeySegment(cfg.Prefix) || len(cfg.Prefix)+2 > MaxNameSize {
			return fmt.Errorf("%w: s3 prefix is malformed", ErrDenied)
		}
	}
	return nil
}

// s3KeySegment reports whether s may appear in an object key: non-empty
// UTF-8, no NUL or other control characters, within MaxNameSize bytes.
func s3KeySegment(s string) bool {
	if s == "" || len(s) > MaxNameSize || !validUTF8NoNUL(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (b *s3Backend) key(name string) (string, error) {
	if !ValidName(name) {
		return "", ErrDenied
	}
	if b.prefix == "" {
		return name, nil
	}
	key := b.prefix + "/" + name
	if !s3KeySegment(key) {
		return "", ErrDenied
	}
	return key, nil
}

func (b *s3Backend) live() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.closed
}

func (b *s3Backend) Read(ctx context.Context, name string) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, classified(ErrDenied, err)
	}
	if !b.live() {
		return ReadResult{}, ErrDenied
	}
	key, err := b.key(name)
	if err != nil {
		return ReadResult{}, err
	}
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:       aws.String(b.bucket),
		Key:          aws.String(key),
		ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil {
		return ReadResult{}, mapS3ReadError(ctx, err)
	}
	// The body must be closed before the response is discarded, so its error
	// is captured and classified like a body read error.
	defer func() { _ = out.Body.Close() }()
	data, bodyErr := readBounded(io.LimitReader(&ctxReader{ctx: ctx, r: out.Body}, MaxValueSize+1), MaxValueSize)
	// Read the server-declared length before Close: some transports surface a
	// truncated body only when the stream ends.
	declared := out.ContentLength
	if bodyErr != nil {
		return ReadResult{}, mapS3ReadError(ctx, fmt.Errorf("read body: %w", bodyErr))
	}
	// The ETag is handed back byte-for-byte, so it must also be a value that
	// can be sent back unmodified as a single strong If-Match. Anything else
	// could never be a matching revision (or would be reinterpreted on the
	// way back), so it is corrupt state rather than a usable version.
	etag := out.ETag
	if etag == nil {
		etag = aws.String("")
	}
	// Only ASCII graphic bytes excluded from validStrongETag are reportable:
	// net/http refuses to parse a response carrying any other control byte
	// in a header, so such a response never reaches this point.
	if !validStrongETag(*etag) {
		return ReadResult{}, fmt.Errorf("%w: response ETag %q is not one strong quoted ETag usable as a revision", ErrCorrupt, *etag)
	}
	if declared != nil && *declared != int64(len(data)) {
		return ReadResult{}, fmt.Errorf("%w: body length %d does not match Content-Length %d", ErrCorrupt, len(data), *declared)
	}
	if err := ctx.Err(); err != nil {
		return ReadResult{}, classified(ErrDenied, err)
	}
	return ReadResult{Bytes: data, Revision: Revision(*etag)}, nil
}

// ctxReader makes a body read observe the caller's cancellation. The SDK's
// transport checks ctx only before sending the request and while waiting for
// response headers, so without this an already-flushed body that stalls would
// block past the deadline.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
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
		done <- result{n, err}
	}()
	select {
	case res := <-done:
		return res.n, res.err
	case <-c.ctx.Done():
		// Abandon the blocked read; the deferred Body.Close cancels the
		// underlying transfer and unblocks it.
		return 0, c.ctx.Err()
	}
}

// readBounded reads r to EOF into memory, failing with ErrCorrupt as soon as
// it holds more than limit bytes. At most limit+1 bytes are retained.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: object exceeds %d bytes", ErrCorrupt, limit)
	}
	return data, nil
}

// validStrongETag reports whether s is exactly one strong-entity-tag
// (RFC 9110 §8.8.3): a pair of DQUOTE characters enclosing etagc bytes, with
// no surrounding optional whitespace and no weak ("W/") prefix. etagc is
// %x21 / %x23-7E / obs-text, so it is opaque: every byte except SP, DQUOTE
// and CTLs is allowed inside, including ','. A header field combining tags
// uses ',' only outside the quotes, so a tag list ("a","b", "a", "b") always
// has a DQUOTE inside the value and is rejected. '*' and the "W/" weak prefix
// carry bytes outside etagc, so they are rejected too, as are an unquoted
// value, a control character and surrounding OWS. It is what Read may return
// as a Revision and the only shape ReplaceIfVersion accepts as expected.
func validStrongETag(s string) bool {
	if len(s) < 2 || len(s) > MaxRevisionSize || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	// Inner bytes are etagc = %x21 / %x23-7E / obs-text: every byte that is
	// not a C0 control, SP or DEL, except DQUOTE, which ends the tag. A comma
	// is a legal part of the opaque tag value.
	for i := 1; i < len(s)-1; i++ {
		if c := s[i]; !(c > 0x20 && c != '"' && c != 0x7f) {
			return false
		}
	}
	return true
}

func (b *s3Backend) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	return b.put(ctx, name, "", value)
}

func (b *s3Backend) ReplaceIfVersion(ctx context.Context, name string, expected Revision, value []byte) error {
	// Preflight, in contract precedence: caller cancellation and Close first,
	// so a cancelled or closed call is ErrDenied whatever the revision; then
	// the zero and oversize revisions, which are malformed (ErrDenied); then a
	// non-zero, in-bound revision that cannot be a Revision this driver ever
	// returned, which can never match a committed version, so it is a version
	// conflict (ErrConflict). All of these are resolved without a request.
	//
	// A well-formed revision is not checked here: whether it matches is the
	// service's decision, made by the single conditional Put that put sends.
	if err := ctx.Err(); err != nil {
		return classified(ErrDenied, err)
	}
	if !b.live() {
		return ErrDenied
	}
	if !validExpectedRevision(expected) {
		return ErrDenied
	}
	if !validStrongETag(string(expected)) {
		return fmt.Errorf("%w: expected revision is not one strong quoted ETag", ErrConflict)
	}
	return b.put(ctx, name, string(expected), value)
}

// put performs the single conditional PutObject shared by CreateIfAbsent
// (expected == "", sent as If-None-Match: *) and ReplaceIfVersion (expected
// sent verbatim as If-Match). It never issues a Head or an unconditional
// PutObject.
func (b *s3Backend) put(ctx context.Context, name, expected string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return classified(ErrDenied, err)
	}
	if !b.live() {
		return ErrDenied
	}
	key, err := b.key(name)
	if err != nil {
		return err
	}
	if !validValue(value) {
		return ErrDenied
	}
	in := &s3.PutObjectInput{
		Bucket:        aws.String(b.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(value),
		ContentLength: aws.Int64(int64(len(value))),
	}
	if expected == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(expected)
	}
	if _, err := b.client.PutObject(ctx, in); err != nil {
		return mapS3WriteError(err)
	}
	return nil
}

func (b *s3Backend) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, classified(ErrDenied, err)
	}
	if !b.live() {
		return nil, ErrDenied
	}
	return nil, ErrUnsupported
}

func (b *s3Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

// mapS3WriteError classifies the outcome of a conditional PutObject. err may
// wrap an aws.ResponseError with a zero status, so the SDK's generic
// HTTPStatusCode() adapter (also implemented by operation errors) is used.
func mapS3WriteError(err error) error {
	if respErr, ok := asS3Response(err); ok {
		code := respErr.HTTPStatusCode()
		if code >= 500 || code == httpStatusTooManyRequests {
			return unknown(err)
		}
		if code == 412 || code == 409 {
			return classified(ErrConflict, err)
		}
		if code == 404 {
			// Only a missing key says anything about the precondition. A
			// missing bucket, or a 404 without an S3 code, is a configuration
			// error and must not be reported as a version conflict.
			if s3ErrorCode(err) == "NoSuchKey" {
				return classified(ErrConflict, err)
			}
			return classified(ErrDenied, err)
		}
		if code >= 400 {
			return classified(ErrDenied, err)
		}
		return unknown(err)
	}
	if !sent(err) && notSent(err) {
		return classified(ErrDenied, err)
	}
	return unknown(err)
}

// mapS3ReadError classifies a failed GetObject or body read. It distinguishes
// a missing key from a misconfigured bucket the same way mapS3WriteError does:
// with s3ErrorCode, which reads the service's error code through the API error.
func mapS3ReadError(ctx context.Context, err error) error {
	if errors.Is(err, ErrCorrupt) {
		return err
	}
	// Once response headers arrived the caller's own deadline means the body
	// read was interrupted. Read has no side effect on the stored version and
	// the caller asked to stop, so this is the caller's cancellation:
	// ErrDenied (the cause stays in the message). A deadline reached while
	// still connecting or waiting for headers is likewise ErrDenied. Read is
	// not a mutation, so there is no "unknown outcome" to report.
	if ctxErr := ctx.Err(); ctxErr != nil && !sent(err) {
		return classified(ErrDenied, ctxErr)
	}
	if respErr, ok := asS3Response(err); ok {
		code := respErr.HTTPStatusCode()
		switch {
		case code == 404:
			// Only a missing key says the requested name has no version. A
			// missing bucket, or another explicit 404 code (for example
			// NoSuchAccessPoint), is a configuration error. A 404 without a
			// service code, or the SDK's status-derived NotFound, is a bare
			// 404 and means the key is absent.
			if c := s3ErrorCode(err); c == "" || c == "NoSuchKey" || c == "NotFound" {
				return classified(ErrNotFound, err)
			}
			return classified(ErrDenied, err)
		case code >= 400 && code < 500:
			return classified(ErrDenied, err)
		}
		return unknown(err)
	}
	if !sent(err) && notSent(err) {
		return classified(ErrDenied, err)
	}
	return unknown(err)
}

const httpStatusTooManyRequests = 429

// s3ErrorCode returns the S3 error code of the service's error response, or ""
// when the error carries none.
func s3ErrorCode(err error) string {
	var withCode interface{ ErrorCode() string }
	if errors.As(err, &withCode) {
		return withCode.ErrorCode()
	}
	return ""
}

// asS3Response reports whether err came from the service and returns the
// error carrying the HTTP status. Transport failures surface as a
// ResponseError with status 0; service errors surface as the operation error
// (which also implements HTTPStatusCode). A status of 0 is not a response.
func asS3Response(err error) (interface{ HTTPStatusCode() int }, bool) {
	var withStatus interface{ HTTPStatusCode() int }
	if errors.As(err, &withStatus) && withStatus.HTTPStatusCode() != 0 {
		return withStatus, true
	}
	return nil, false
}

// notSent reports whether err is a transport failure that happened before any
// byte of the request could have reached the service: DNS lookup or connect
// (including connection refused) failed, or the server's certificate was
// rejected during the TLS handshake. A certificate that fails verification
// can only be seen on a fresh handshake, which happens before any HTTP request
// bytes are written, so no publication can have started. Other TLS errors
// (for example a failed renegotiation or a broken handshake midway) are
// deliberately not included: they can arise after request bytes were written,
// so they stay conservatively unknown.
func notSent(err error) bool {
	var connErr *net.OpError
	if errors.As(err, &connErr) && (connErr.Op == "dial" || connErr.Op == "connect") {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
}

// sent reports whether the SDK observed the request leaving the client, for
// example a non-zero HTTP status on an error that is not a ResponseError.
func sent(err error) bool {
	_, ok := asS3Response(err)
	return ok
}

func unknown(err error) error { return classified(ErrUnknown, err) }

// classified wraps a transport or service error under a sentinel. The cause is
// kept as a message, not in the chain, so callers cannot mistake the
// transport's own context errors for the bridge outcome.
func classified(sentinel error, err error) error {
	return fmt.Errorf("%w: %v", sentinel, err)
}
