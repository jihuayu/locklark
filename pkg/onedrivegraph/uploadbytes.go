// This file adds the byte-upload step of a deferred Graph upload session. It
// sends exactly one PUT of the complete non-empty sealed payload and validates
// the provider's 202 acknowledgement. It does not commit or publish the item,
// does not implement a ReadResult, Revision or backend, and does not query or
// resume a session.
//
// The pre-authenticated upload URL is a capability: it grants write access to
// the session without an Authorization header. UploadBytes therefore sends no
// Graph credentials, never calls the access-token source and never places the
// URL, token or payload in an error.
package onedrivegraph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// maxUploadAcknowledgementJSONSize bounds the complete 202 upload response
// body. The acknowledgement is small; the bound only prevents unbounded reads.
const maxUploadAcknowledgementJSONSize = 64 << 10

// uploadSessionState is shared by every copy of an UploadSession. It makes a
// session one-use across value copies and concurrent callers: the first call
// that reaches the transport marks the session attempted before handing the
// request over, and no later or concurrent call may do so again.
type uploadSessionState struct {
	attempted atomic.Bool
}

// UploadAcknowledgement is the validated body of exactly one HTTP 202 upload
// response. It represents only the provider's response to the uploaded byte
// range: it is not a commit or publish result, and it does not prove that the
// item was committed. It also does not prove that NextExpectedRanges is a
// complete snapshot of the missing byte ranges.
//
// The provider expiration is validated and returned in ExpirationDateTime. It
// never changes the session's local immutable deadline.
type UploadAcknowledgement struct {
	// ExpirationDateTime is the provider's RFC3339 upload-session expiration
	// from this 202 response.
	ExpirationDateTime time.Time
	// NextExpectedRanges holds the provider-reported missing ranges exactly as
	// returned, in provider order and without normalization. The service may
	// omit some gaps, so this list is not a complete snapshot. An empty list is
	// preserved as empty and never interpreted as a successful commit.
	NextExpectedRanges []string
}

// UploadBytes uploads the complete non-empty sealed payload in exactly one
// range. The request is:
//
//	PUT <session upload URL>
//	Content-Length: len(sealed)
//	Content-Range: bytes 0-(len(sealed)-1)/len(sealed)
//
// No Authorization header or other Graph credential is sent, and the access
// token source is never called. The caller owns sealed: it is borrowed only
// for the synchronous call, is not mutated, is not copied by this method, and
// is not retained after UploadBytes returns.
//
// Error mapping:
//   - A nil or cancelled context, an unusable or already-attempted session, a
//     mismatched drive/item binding, an expired session, an empty payload, or
//     a payload larger than vaultfilebackend.MaxValueSize is ErrDenied before
//     any request is handed to the transport. Such a refusal leaves the
//     session unused.
//   - After the PUT has been handed to the transport, every outcome other than
//     exactly HTTP 202 with a fully validated acknowledgement is ErrUnknown,
//     including transport and context failures, redirects, 200/201, other
//     statuses and malformed responses. The request is never retried.
//   - The request deadline is never later than the session's original
//     immutable expiration. A returned acknowledgement never extends it.
func (u *ConditionalUploader) UploadBytes(ctx context.Context, session *UploadSession, sealed []byte) (UploadAcknowledgement, error) {
	var ack UploadAcknowledgement
	if err := checkContext(ctx); err != nil {
		return ack, err
	}
	if u == nil || !validUploadID(u.driveID) || !validUploadID(u.itemID) {
		return ack, fmt.Errorf("%w: uploader is not configured", vaultfilebackend.ErrDenied)
	}
	if !usableUploadSession(u, session) {
		return ack, fmt.Errorf("%w: upload session is not usable by this uploader", vaultfilebackend.ErrDenied)
	}
	if len(sealed) == 0 {
		return ack, fmt.Errorf("%w: upload payload is empty", vaultfilebackend.ErrDenied)
	}
	if len(sealed) > vaultfilebackend.MaxValueSize {
		return ack, fmt.Errorf("%w: upload payload is larger than the maximum value size", vaultfilebackend.ErrDenied)
	}
	if !time.Now().Before(session.expiresAt) {
		return ack, fmt.Errorf("%w: upload session has expired", vaultfilebackend.ErrDenied)
	}
	if session.state.attempted.Load() {
		return ack, fmt.Errorf("%w: upload session was already used", vaultfilebackend.ErrDenied)
	}

	// The immutable session expiry caps the request, even when the caller's
	// context has no deadline or a later one.
	requestCtx, cancel := context.WithDeadline(ctx, session.expiresAt)
	defer cancel()

	length := len(sealed)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPut, session.uploadURL, bytes.NewReader(sealed))
	if err != nil {
		return ack, fmt.Errorf("%w: upload request could not be constructed", vaultfilebackend.ErrDenied)
	}
	// bytes.NewReader borrows the caller's slice. GetBody would retain that
	// slice and could also let net/http replay the PUT; neither is allowed.
	req.GetBody = nil
	req.ContentLength = int64(length)
	req.Header.Set("Content-Range", "bytes 0-"+strconv.Itoa(length-1)+"/"+strconv.Itoa(length))

	if err := checkContext(requestCtx); err != nil {
		return ack, err
	}
	client := u.httpClient()
	// This check and the swap below are the last preflight. The session is
	// marked attempted under synchronization immediately before Do, so no
	// concurrent copy or later retry can hand off a second request.
	if !time.Now().Before(session.expiresAt) {
		return ack, fmt.Errorf("%w: upload session has expired", vaultfilebackend.ErrDenied)
	}
	if !session.state.attempted.CompareAndSwap(false, true) {
		return ack, fmt.Errorf("%w: upload session was already used", vaultfilebackend.ErrDenied)
	}

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		// The transport error may contain the capability URL, credentials or
		// provider text. None of it is retained.
		return ack, fmt.Errorf("%w: upload request failed", vaultfilebackend.ErrUnknown)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return ack, fmt.Errorf("%w: upload request was redirected", vaultfilebackend.ErrUnknown)
		}
		return ack, fmt.Errorf("%w: upload request returned unexpected HTTP %d", vaultfilebackend.ErrUnknown, resp.StatusCode)
	}

	body, err := readBoundedBody(requestCtx, resp, maxUploadAcknowledgementJSONSize)
	if err != nil {
		return ack, fmt.Errorf("%w: upload acknowledgement could not be read within its bound", vaultfilebackend.ErrUnknown)
	}
	parsed, ok := parseUploadAcknowledgement(body)
	if !ok {
		return ack, fmt.Errorf("%w: upload acknowledgement is invalid", vaultfilebackend.ErrUnknown)
	}
	return parsed, nil
}

// usableUploadSession checks the binding and the capability without touching
// the token source. The state pointer is required so every value copy shares
// the same one-use gate.
func usableUploadSession(u *ConditionalUploader, session *UploadSession) bool {
	if session == nil || session.state == nil {
		return false
	}
	if session.driveID != u.driveID || session.itemID != u.itemID {
		return false
	}
	if !validOpaqueETag(session.etag) || session.expiresAt.IsZero() {
		return false
	}
	_, ok := safePersonalUploadURL(session.uploadURL)
	return ok
}

// parseUploadAcknowledgement accepts exactly one bounded, valid-UTF-8 JSON
// object with an RFC3339 expiration and a JSON array of documented range
// strings. It does not modify the session or normalize any returned value.
func parseUploadAcknowledgement(body []byte) (UploadAcknowledgement, bool) {
	var ack UploadAcknowledgement
	if !utf8.Valid(body) {
		return ack, false
	}
	fields, ok := decodeStrictJSONObject(body)
	if !ok {
		return ack, false
	}

	var expiration string
	if !decodeExactString(fields["expirationDateTime"], &expiration) || expiration == "" {
		return ack, false
	}
	expiresAt, err := time.Parse(time.RFC3339, expiration)
	if err != nil {
		return ack, false
	}

	rawRanges, present := fields["nextExpectedRanges"]
	if !present {
		return ack, false
	}
	ranges, ok := decodeNextExpectedRanges(rawRanges)
	if !ok {
		return ack, false
	}

	return UploadAcknowledgement{
		ExpirationDateTime: expiresAt,
		NextExpectedRanges: ranges,
	}, true
}

// decodeNextExpectedRanges accepts exactly a JSON array whose elements are
// documented range strings. Each string keeps its provider spelling; an empty
// array stays an empty, non-nil slice and is never treated as a complete
// snapshot or as a commit.
func decodeNextExpectedRanges(raw json.RawMessage) ([]string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	var ranges []string
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if err := dec.Decode(&ranges); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	for _, value := range ranges {
		if !validNextExpectedRange(value) {
			return nil, false
		}
	}
	if ranges == nil {
		ranges = []string{}
	}
	return ranges, true
}

// validNextExpectedRange accepts the documented "start-end" form, including an
// omitted end ("start-"), as canonical non-negative decimal byte offsets. It
// verifies only the shape; it deliberately does not reinterpret a range as a
// chunk size, a complete gap list or a commit indicator.
func validNextExpectedRange(value string) bool {
	dash := strings.IndexByte(value, '-')
	if dash <= 0 {
		return false
	}
	startText := value[:dash]
	if !validByteOffset(startText) {
		return false
	}
	start, err := strconv.ParseUint(startText, 10, 64)
	if err != nil {
		return false
	}
	endText := value[dash+1:]
	if endText == "" {
		return true
	}
	if !validByteOffset(endText) {
		return false
	}
	end, err := strconv.ParseUint(endText, 10, 64)
	if err != nil || end < start {
		return false
	}
	return true
}

// validByteOffset requires canonical unsigned decimal ASCII with no sign,
// whitespace or redundant leading zero.
func validByteOffset(value string) bool {
	if value == "" {
		return false
	}
	if len(value) > 1 && value[0] == '0' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
