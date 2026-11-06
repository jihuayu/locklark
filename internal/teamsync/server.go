package teamsync

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
)

type server struct {
	mu      sync.Mutex // Local verification/commit/anchor only, never network writes.
	path    string
	config  *directory.Config
	key     ed25519.PrivateKey
	minimum directory.Checkpoint
	anchors AnchorStore
	slots   chan struct{}
}

func NewHandler(path string, c *directory.Config, key ed25519.PrivateKey, minimum directory.Checkpoint, anchors AnchorStore) (http.Handler, error) {
	if !c.WriterACLPolicy() || !c.ValidCheckpoint(minimum) || !validPrivate(key) || !bytes.Equal(key.Public().(ed25519.PublicKey), c.SequencerSigningKey()) || anchors == nil {
		return nil, ErrInvalid
	}
	cp, e := anchors.Load()
	if e != nil || !c.ValidCheckpoint(cp) || cp.Version < minimum.Version || cp.Version == minimum.Version && cp != minimum {
		return nil, ErrAnchor
	}
	if _, e = directory.Read(path, c, cp); e != nil {
		return nil, mapDirectoryError(e)
	}
	if _, e = directory.Read(path, c, minimum); e != nil {
		return nil, ErrInvalid
	}
	return &server{path: path, config: c, key: bytes.Clone(key), minimum: minimum, anchors: anchors, slots: make(chan struct{}, 4)}, nil
}
func mapDirectoryError(e error) error {
	switch {
	case errors.Is(e, directory.ErrConflict):
		return ErrConflict
	case errors.Is(e, directory.ErrCapacity):
		return ErrCapacity
	case errors.Is(e, directory.ErrStorage):
		return ErrTransport
	default:
		return ErrInvalid
	}
}
func errorStatus(e error) string {
	switch {
	case errors.Is(e, ErrDenied):
		return "denied"
	case errors.Is(e, ErrConflict):
		return "conflict"
	case errors.Is(e, ErrCapacity):
		return "capacity"
	case errors.Is(e, ErrAnchor):
		return "anchor"
	case errors.Is(e, ErrUnknown):
		return "unknown"
	case errors.Is(e, ErrTransport):
		return "unavailable"
	default:
		return "invalid"
	}
}
func statusError(status string) error {
	switch status {
	case "denied":
		return ErrDenied
	case "conflict":
		return ErrConflict
	case "capacity":
		return ErrCapacity
	case "anchor":
		return ErrAnchor
	case "unknown":
		return ErrUnknown
	case "unavailable":
		return ErrTransport
	default:
		return ErrInvalid
	}
}
func refuseHTTP(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"refused"}`))
}
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.User != nil || r.URL.IsAbs() || r.Header.Get("Content-Type") != "application/json" {
		refuseHTTP(w, http.StatusBadRequest)
		return
	}
	control := http.NewResponseController(w)
	if control.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || control.SetWriteDeadline(time.Now().Add(15*time.Second)) != nil {
		refuseHTTP(w, http.StatusServiceUnavailable)
		return
	}
	action, limit := "", int64(MaxReadBytes)
	switch r.URL.Path {
	case ReadPath:
		action = "read"
	case PublishPath:
		action = "publish"
		limit = MaxPublishBytes
	default:
		refuseHTTP(w, http.StatusNotFound)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		refuseHTTP(w, http.StatusServiceUnavailable)
		return
	}
	if r.ContentLength > limit {
		refuseHTTP(w, http.StatusRequestEntityTooLarge)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		refuseHTTP(w, http.StatusBadRequest)
		return
	}
	var q request
	if decode(raw, &q) != nil || !q.valid(s.config, action) {
		refuseHTTP(w, http.StatusBadRequest)
		return
	}
	out := s.handle(r, q)
	out.Protocol, out.RequestDigest, out.Nonce = protocol, digest("request", q), q.Proof.Nonce
	if out.History != nil {
		out.HistoryDigest = digest("history", out.History)
	}
	if out.Receipt != nil {
		out.ReceiptDigest = digest("receipt", out.Receipt)
	}
	out.Signature = ed25519.Sign(s.key, out.signingBytes())
	encoded := encode(out)
	if len(encoded) > MaxResponseBytes {
		out = response{Protocol: protocol, RequestDigest: out.RequestDigest, Nonce: out.Nonce, Status: "capacity"}
		out.Signature = ed25519.Sign(s.key, out.signingBytes())
		encoded = encode(out)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(encoded) // A lost write is unknown to a publisher; never retry it.
}

func authorize(c *directory.Config, q request, view directory.View) error {
	var key ed25519.PublicKey
	if q.Proof.Kind == "owner" {
		key = c.OwnerSigningKey(q.Proof.ID)
	} else {
		if view.Receipt.Proposal.Mode != "active" {
			return ErrDenied
		}
		for _, member := range view.Receipt.Proposal.Members {
			for _, device := range member.Devices {
				if device.ID == q.Proof.ID {
					if q.Proof.Action == "publish" && (member.Role != "writer" || q.Publication == nil || q.Publication.Proposal.AuthorDevice != device.ID || q.Publication.Proposal.Owner != "") {
						return ErrDenied
					}
					decoded, e := hex.DecodeString(device.Signing)
					if e != nil {
						return ErrDenied
					}
					key = ed25519.PublicKey(decoded)
				}
			}
		}
	}
	if len(key) != 32 || !ed25519.Verify(key, q.Proof.signingBytes(), q.Proof.Signature) {
		return ErrDenied
	}
	if q.Proof.Action == "publish" && q.Proof.Kind == "owner" && (q.Publication.Proposal.Owner != q.Proof.ID || q.Publication.Proposal.AuthorDevice != "") {
		return ErrDenied
	}
	return nil
}
func (s *server) handle(r *http.Request, q request) response {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(e error) response { return response{Status: errorStatus(e)} }
	if r.Context().Err() != nil {
		return fail(ErrTransport)
	}
	anchor, e := s.anchors.Load()
	if e != nil || !s.config.ValidCheckpoint(anchor) {
		return fail(ErrAnchor)
	}
	view, e := directory.Read(s.path, s.config, anchor)
	if e != nil {
		return fail(mapDirectoryError(e))
	}
	if e = authorize(s.config, q, view); e != nil {
		return fail(e)
	}
	h, e := directory.ExportHistory(s.path, s.config, anchor)
	if e != nil {
		return fail(mapDirectoryError(e))
	}
	view, e = directory.VerifyHistory(s.config, s.minimum, h)
	if e != nil {
		return fail(ErrInvalid)
	}
	if _, e = directory.VerifyHistory(s.config, q.Proof.Anchor, h); e != nil {
		return fail(ErrInvalid)
	}
	if e = authorize(s.config, q, view); e != nil {
		return fail(e)
	}
	head := view.Receipt.Checkpoint()
	if head != anchor {
		if s.anchors.Advance(anchor, head) != nil {
			return fail(ErrAnchor)
		}
		anchor = head
	}
	if q.Proof.Action == "read" {
		return response{Status: "current", Head: head, History: &h}
	}
	p := q.Publication
	if p.Proposal.Parent != head {
		return fail(ErrConflict)
	}
	if r.Context().Err() != nil {
		return fail(ErrTransport)
	}
	receipt, e := directory.Commit(s.path, s.config, s.key, p.Proposal, p.Snapshot)
	if e != nil {
		if errors.Is(e, directory.ErrStorage) {
			return fail(ErrUnknown)
		}
		return fail(mapDirectoryError(e))
	}
	if s.anchors.Advance(anchor, receipt.Checkpoint()) != nil {
		return fail(ErrUnknown)
	}
	return response{Status: "committed", Head: receipt.Checkpoint(), Receipt: &receipt}
}
