// Command item_metadata is a private, metadata-only probe binary.
//
// It reads one bounded JSON request from stdin, unlocks the vault through the
// shipped personal session (normal UnlockSession plus the non-revealing
// GetItemDetail), and prints ONLY safe metadata projections: category, tags,
// favorite, URLs (label/url/primary/match mode), section ids and per-section
// field counts.  Attachment entries are projected as public metadata only
// (id, file_name, mime_type, size, sha256); an explicit verification request
// additionally reads each attachment body through the native GetAttachment,
// hashes the exact bytes, clears the body and reports ONLY the digest and byte
// count.  Titles, usernames, notes, concealment, attachment bodies/paths and
// all key/record material are never emitted, and every failure is one fixed
// message that never echoes the request, a path or a parser diagnostic.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

const maxRequest = 64 << 10

// Fixed, input-independent failures.  They never wrap parser output.
var (
	errRequest   = errors.New("request refused")
	errUnlock    = errors.New("vault unlock failed")
	errMetadata  = errors.New("item metadata unavailable")
	errInternals = errors.New("probe unavailable")
)

type request struct {
	Path      string `json:"path"`
	Password  string `json:"password"`
	SecretKey string `json:"secret_key"`
	ID        string `json:"id"`
	Revision  string `json:"revision"`
	// VerifyAttachments asks the probe to read every attachment body back and
	// hash it.  It is optional, so an ordinary metadata request keeps the
	// exact same stdin shape as before.
	VerifyAttachments bool `json:"verify_attachments"`
}

type urlMeta struct {
	Label     string `json:"label,omitempty"`
	URL       string `json:"url"`
	Primary   bool   `json:"primary"`
	MatchMode string `json:"match_mode,omitempty"`
}

// attachmentMeta is the public projection of one encrypted attachment: the
// stored size and digest are reported, the body never is.
type attachmentMeta struct {
	ID       string `json:"id"`
	FileName string `json:"file_name"`
	MIMEType string `json:"mime_type"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// attachmentRead is a digest-only proof that the stored bytes decode exactly.
type attachmentRead struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type metadata struct {
	ID                     string           `json:"id"`
	Revision               string           `json:"revision"`
	Category               string           `json:"category"`
	Tags                   []string         `json:"tags"`
	Favorite               bool             `json:"favorite"`
	URLs                   []urlMeta        `json:"urls"`
	SectionIDs             []string         `json:"section_ids"`
	SectionFieldCounts     map[string]int   `json:"section_field_counts"`
	Attachments            []attachmentMeta `json:"attachments"`
	AttachmentReadVerified bool             `json:"attachment_read_verified"`
	AttachmentReads        []attachmentRead `json:"attachment_reads"`
}

// readRequest consumes exactly one bounded JSON object and nothing else.
func readRequest(stdin io.Reader) (request, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(stdin, maxRequest+1))
	if err != nil || len(raw) == 0 || len(raw) > maxRequest {
		return request{}, raw, errRequest
	}
	var req request
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return request{}, raw, errRequest
	}
	if _, err := dec.Token(); err != io.EOF {
		return request{}, raw, errRequest
	}
	if req.Path == "" || req.Password == "" || req.SecretKey == "" ||
		req.ID == "" || req.Revision == "" {
		return request{}, raw, errRequest
	}
	return req, raw, nil
}

func project(detail personal.ItemDetail) metadata {
	out := metadata{
		ID:                 detail.ID,
		Revision:           detail.Revision,
		Category:           string(detail.Category),
		Tags:               append([]string{}, detail.Tags...),
		Favorite:           detail.Favorite,
		URLs:               make([]urlMeta, 0, len(detail.URLs)),
		SectionIDs:         make([]string, 0, len(detail.Sections)),
		SectionFieldCounts: make(map[string]int, len(detail.Sections)),
		Attachments:        make([]attachmentMeta, 0, len(detail.Attachments)),
		AttachmentReads:    make([]attachmentRead, 0, len(detail.Attachments)),
	}
	for _, u := range detail.URLs {
		out.URLs = append(out.URLs, urlMeta{
			Label: u.Label, URL: u.URL, Primary: u.Primary, MatchMode: u.MatchMode,
		})
	}
	for _, s := range detail.Sections {
		out.SectionIDs = append(out.SectionIDs, s.ID)
		out.SectionFieldCounts[s.ID] = len(s.Fields)
	}
	for _, a := range detail.Attachments {
		out.Attachments = append(out.Attachments, attachmentMeta{
			ID: a.ID, FileName: a.FileName, MIMEType: a.MIMEType, Size: a.Size, SHA256: a.SHA256,
		})
	}
	return out
}

// readAttachments proves the stored bytes decode to the declared metadata by
// reading each body through GetAttachment, hashing it, and clearing it.  Only
// the digest and length leave this function.
func readAttachments(session *personal.Session, detail personal.ItemDetail) ([]attachmentRead, error) {
	out := make([]attachmentRead, 0, len(detail.Attachments))
	var readErr error
	for _, a := range detail.Attachments {
		meta, body, err := session.GetAttachment(detail.ID, detail.Revision, a.ID)
		if err != nil {
			readErr = err
			clear(body)
			break
		}
		sum := sha256.Sum256(body)
		out = append(out, attachmentRead{
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  len(body),
		})
		if meta.ID != a.ID || int64(len(body)) != a.Size {
			readErr = errMetadata
			clear(body)
			break
		}
		clear(body)
	}
	return out, readErr
}

func quit(code int) {
	os.Exit(code)
}

func main() {
	req, raw, err := readRequest(os.Stdin)
	wipe(raw)
	if err != nil {
		os.Stderr.WriteString("item_metadata: request refused\n")
		quit(2)
	}
	key, keyErr := personal.ParseSecret(req.SecretKey)
	req.SecretKey = ""
	pw := []byte(req.Password)
	req.Password = ""
	if keyErr != nil {
		wipe(pw)
		os.Stderr.WriteString("item_metadata: request refused\n")
		quit(2)
	}
	session, err := personal.UnlockSession(req.Path, pw, key, 2*time.Minute)
	wipe(pw)
	wipe(key)
	req.Path, req.Password, req.SecretKey = "", "", ""
	if err != nil || session == nil {
		os.Stderr.WriteString("item_metadata: vault unlock failed\n")
		quit(3)
	}
	detail, err := session.GetItemDetail(req.ID, req.Revision, false)
	if err != nil {
		session.Lock()
		os.Stderr.WriteString("item_metadata: item metadata unavailable\n")
		quit(4)
	}
	out := project(detail)
	if req.VerifyAttachments {
		reads, readErr := readAttachments(session, detail)
		if readErr != nil {
			session.Lock()
			os.Stderr.WriteString("item_metadata: attachment bytes unavailable\n")
			quit(4)
		}
		out.AttachmentReadVerified = true
		out.AttachmentReads = reads
	}
	session.Lock()
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		os.Stderr.WriteString("item_metadata: probe unavailable\n")
		quit(5)
	}
}

// wipe drops best-effort references to owned request material.  It makes no
// zeroization claim: Go strings and the runtime may retain copies.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
