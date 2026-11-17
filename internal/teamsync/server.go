package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
)

type server struct {
	mu      sync.Mutex // Local verification/commit/anchor only, never network writes.
	keyMu   sync.Mutex // Short commit/sign/output grants only, never storage or network.
	closed  atomic.Bool
	ctx     context.Context
	cancel  context.CancelFunc
	hooks   *serverLifecycleHooks
	path    string
	config  *directory.Config
	key     ed25519.PrivateKey
	minimum directory.Checkpoint
	anchors AnchorStore
	slots   chan struct{}
}

func NewHandler(path string, c *directory.Config, key ed25519.PrivateKey, minimum directory.Checkpoint, anchors AnchorStore) (http.Handler, error) {
	return NewManagedHandler(path, c, key, minimum, anchors)
}

// NewManagedHandler verifies the trusted local history and owns a private copy
// of the sequencer key. The caller must Close it when that authority ends.
func NewManagedHandler(path string, c *directory.Config, key ed25519.PrivateKey, minimum directory.Checkpoint, anchors AnchorStore) (ManagedHandler, error) {
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
	ctx, cancel := context.WithCancel(context.Background())
	return &server{path: path, config: c, key: bytes.Clone(key), minimum: minimum, anchors: anchors, slots: make(chan struct{}, 4), ctx: ctx, cancel: cancel}, nil
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
	if s == nil || s.closed.Load() || r == nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	if !s.live(ctx) {
		return
	}
	if r.Body != nil {
		stopBody := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
		defer stopBody()
	}
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.User != nil || r.URL.IsAbs() || r.Header.Get("Content-Type") != "application/json" {
		s.refuse(ctx, w, http.StatusBadRequest)
		return
	}
	control := http.NewResponseController(w)
	if control.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || control.SetWriteDeadline(time.Now().Add(15*time.Second)) != nil {
		s.refuse(ctx, w, http.StatusServiceUnavailable)
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
		s.refuse(ctx, w, http.StatusNotFound)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.refuse(ctx, w, http.StatusServiceUnavailable)
		return
	}
	if r.ContentLength > limit {
		s.refuse(ctx, w, http.StatusRequestEntityTooLarge)
		return
	}
	if !s.live(ctx) {
		return
	}
	if r.Body == nil {
		s.refuse(ctx, w, http.StatusBadRequest)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if !s.live(ctx) {
		return
	}
	if e != nil || int64(len(raw)) > limit {
		s.refuse(ctx, w, http.StatusBadRequest)
		return
	}
	var q request
	if decode(raw, &q) != nil || !q.valid(s.config, action) {
		s.refuse(ctx, w, http.StatusBadRequest)
		return
	}
	// The response this request returns, capacity refusal included, is decided
	// and signed while the handler still holds s.mu: only then does an anchor
	// advance know the caller will receive the full committed answer.
	out, e := s.handle(r, q, MaxResponseBytes)
	if !s.live(ctx) {
		return
	}
	if e != nil {
		// Not even the capacity refusal fits its budget: no writable answer is
		// possible, and no anchor moved.
		s.refuse(ctx, w, http.StatusServiceUnavailable)
		return
	}
	// The preflighted decision is final: handle signed and measured this exact
	// envelope under s.mu, and no later size check may turn it into a refusal
	// after an anchor moved.
	if !s.grantWrite(ctx) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(encode(out)) // A lost write is unknown to a publisher; never retry it.
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

// handle validates, decides the complete signed response within budget, and
// only then advances the persistent anchor, all under s.mu. budget is the
// per-call limit on the exact encoded signed envelope: ServeHTTP always passes
// MaxResponseBytes and only package tests pass a smaller one. A non-nil error
// means no response may be granted; it never follows an anchor advance.
func (s *server) handle(r *http.Request, q request, budget int) (response, error) {
	if !s.live(r.Context()) {
		return response{Status: errorStatus(ErrTransport)}, ErrTransport
	}
	// Every answer, refusal included, is measured against this call's budget.
	fail := func(e error) (response, error) {
		out := response{Status: errorStatus(e)}
		if !s.prepare(r.Context(), q, &out, budget) {
			return response{}, ErrTransport
		}
		return out, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.live(r.Context()) {
		return fail(ErrTransport)
	}
	anchor, e := s.anchors.Load()
	if !s.live(r.Context()) {
		return fail(ErrTransport)
	}
	if e != nil || !s.config.ValidCheckpoint(anchor) {
		return fail(ErrAnchor)
	}
	if s.hooks != nil && s.hooks.beforeRead != nil {
		s.hooks.beforeRead()
	}
	if !s.live(r.Context()) {
		return fail(ErrTransport)
	}
	// One BoltDB read advances every receipt once and requires both the
	// persistent rollback anchor and this request's proof anchor on that chain.
	// The sealed result is this request's only evidence: nothing re-verifies it.
	trusted, e := directory.ReadTrusted(s.path, s.config, anchor, q.Proof.Anchor)
	if s.hooks != nil && s.hooks.afterRead != nil {
		s.hooks.afterRead()
	}
	if !s.live(r.Context()) {
		return fail(ErrTransport)
	}
	if e != nil {
		return fail(mapDirectoryError(e))
	}
	headView, e := trusted.HeadView()
	if e != nil {
		return fail(ErrInvalid)
	}
	if e = authorize(s.config, q, headView); e != nil {
		return fail(e)
	}
	// The proof anchor was proven on the same pass. Its view keeps head
	// authority: it authorizes against the head receipt, exactly like the
	// former AssembleHistory head view, not against ancestor membership.
	proofView, e := trusted.ProvenAnchorView(q.Proof.Anchor)
	if e != nil {
		return fail(ErrInvalid)
	}
	if e = authorize(s.config, q, proofView); e != nil {
		return fail(e)
	}
	if !s.live(r.Context()) {
		return fail(ErrTransport)
	}
	// Every read and publish answers from the retained history, so the one
	// ReadHistory size budget applies to both sides before anything moves: an
	// oversized chain leaves the anchor and the database exactly as they were.
	h, e := trusted.History()
	if e != nil {
		return fail(mapDirectoryError(e))
	}
	head := trusted.Checkpoint()
	if q.Proof.Action == "read" {
		// The exact signed envelope, fixed-size signature included, is decided
		// before the anchor moves: a caller told capacity never saw progress.
		out := response{Status: "current", Head: head, History: &h}
		if !s.prepare(r.Context(), q, &out, budget) {
			return fail(ErrTransport)
		}
		if out.Status == "capacity" {
			return out, nil
		}
		if anchor != head && s.anchors.Advance(anchor, head) != nil {
			return fail(ErrAnchor)
		}
		return out, nil
	}
	p := q.Publication
	if p.Proposal.Parent != head {
		return fail(ErrConflict)
	}
	// Project the committed response before the anchor moves or anything is
	// written. Commit stores the proposal verbatim and the sequencer signs the
	// receipt, not the proposal, so digests and signatures have fixed lengths.
	// Only values whose serialized length depends on the outcome are replaced:
	// the epoch that Commit derives from the parent, the scope and the
	// versioned parent hash of the stored receipt. Equal-length placeholders
	// predict the serialized envelope length; they are not the real parent.
	// The projection still carries the real snapshot and names the parent the
	// commit must extend.
	projection := directory.Receipt{Proposal: p.Proposal, Signature: make([]byte, ed25519.SignatureSize)}
	projection.Proposal.Epoch = head.Version + 1
	projection.Proposal.Scope = strings.Repeat("0", len(s.config.Genesis().Scope))
	if head.Version > 0 {
		projection.Proposal.Parent.Hash = strings.Repeat("0", 64)
	}
	projected := response{Status: "committed", Head: projection.Checkpoint(), Receipt: &projection}
	if !s.prepare(r.Context(), q, &projected, budget) {
		return fail(ErrTransport)
	}
	if projected.Status == "capacity" {
		return projected, nil
	}
	// A commit whose receipt response fits must not leave a history no read can
	// return. Before anything is durable, project the exact post-commit read
	// response from the history this pass already verified, the projected
	// receipt and the candidate snapshot, and subject it to the same per-call
	// budget. The projected read is signed as an answer to this request: its
	// request digest and nonce, and its own history digest with no receipt.
	// Over budget its signed capacity refusal is returned, never the earlier
	// signed committed receipt answer. A signed capacity refusal, or a
	// projection that cannot be prepared, reaches neither directory.Commit nor
	// the anchor; an error after commitKey was granted is still an unknown,
	// durable outcome.
	var receipt directory.Receipt
	var fullRefusal response
	e = func() error {
		h, e := trusted.ProjectHistory(projection, p.Snapshot)
		if e != nil {
			return mapDirectoryError(e)
		}
		full := response{Status: "current", Head: projection.Checkpoint(), History: &h}
		if !s.prepare(r.Context(), q, &full, budget) {
			return ErrTransport
		}
		if full.Status == "capacity" {
			fullRefusal = full
			return nil
		}
		key, granted := s.commitKey(r.Context())
		if !granted {
			return ErrTransport
		}
		defer clear(key)
		if s.hooks != nil && s.hooks.afterCommitGrant != nil {
			s.hooks.afterCommitGrant()
		}
		receipt, e = directory.Commit(s.path, s.config, key, p.Proposal, p.Snapshot)
		return e
	}()
	if fullRefusal.Status == "capacity" {
		return fullRefusal, nil // No commit: the anchor stays where it was.
	}
	if e != nil {
		if errors.Is(e, directory.ErrStorage) {
			return fail(ErrUnknown)
		}
		return fail(mapDirectoryError(e))
	}
	if !s.live(r.Context()) {
		return fail(ErrUnknown)
	}
	// The commit is durable: from here on the only answer is the signed actual
	// result: neither a length mismatch nor an unexpected capacity refusal from
	// prepare may tell the caller that the commit hit a budget. Either way the
	// answer is the small signed unknown error and the anchor does not move.
	out := response{Status: "committed", Head: receipt.Checkpoint(), Receipt: &receipt}
	if len(receipt.Proposal.Scope) != len(projection.Proposal.Scope) || receipt.Proposal.Epoch != projection.Proposal.Epoch || len(receipt.Proposal.Parent.Hash) != len(projection.Proposal.Parent.Hash) || !s.prepare(r.Context(), q, &out, budget) {
		return fail(ErrUnknown)
	}
	if out.Status == "capacity" {
		// prepare replaced out with a signed capacity refusal, which must never
		// tell the caller that a durable commit hit a budget. Return the small
		// signed unknown error instead and leave the anchor where it was.
		return fail(ErrUnknown)
	}
	if s.anchors.Advance(anchor, receipt.Checkpoint()) != nil {
		return fail(ErrUnknown)
	}
	return out, nil
}

// prepare fills the fixed response metadata, computes the digests of the
// history or receipt it carries and signs it. Over budget, out becomes the
// signed capacity refusal instead and is reported with success when that
// refusal fits: callers must check for that status before advancing the anchor
// or committing. It reports false only when no response may be signed any
// more, including a capacity refusal that itself exceeds budget.
func (s *server) prepare(ctx context.Context, q request, out *response, budget int) bool {
	out.Protocol, out.RequestDigest, out.Nonce = protocol, digest("request", q), q.Proof.Nonce
	out.HistoryDigest, out.ReceiptDigest, out.Signature = "", "", nil
	if out.History != nil {
		out.HistoryDigest = digest("history", out.History)
	}
	if out.Receipt != nil {
		out.ReceiptDigest = digest("receipt", out.Receipt)
	}
	if !s.signResponse(ctx, out) {
		return false
	}
	if len(encode(*out)) <= budget {
		return true
	}
	*out = response{Protocol: protocol, RequestDigest: out.RequestDigest, Nonce: out.Nonce, Status: "capacity"}
	if !s.signResponse(ctx, out) {
		return false
	}
	return len(encode(*out)) <= budget
}
