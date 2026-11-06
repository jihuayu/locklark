package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/vault"
)

type Endpoint struct {
	URL   string
	Roots *x509.CertPool
}
type VerifiedState struct {
	view    directory.View
	history directory.History
}

func (s VerifiedState) View() directory.View       { return cloneView(s.view) }
func (s VerifiedState) History() directory.History { return cloneHistory(s.history) }
func (s VerifiedState) Checkpoint() directory.Checkpoint {
	if s.view.Receipt.Proposal.Epoch == 0 {
		return directory.Checkpoint{}
	}
	return s.view.Receipt.Checkpoint()
}

type PublishState string

const (
	PublishCommitted  PublishState = "committed"
	PublishConflicted PublishState = "conflicted"
	PublishUnknown    PublishState = "unknown"
)

type Reconciliation struct {
	State   PublishState
	Receipt directory.Receipt
	Current directory.Checkpoint
}

type Client struct {
	op             sync.Mutex
	keyMu          sync.Mutex
	stateMu        sync.Mutex
	closed         atomic.Bool
	key            ed25519.PrivateKey
	kind, id, base string
	config         *directory.Config
	anchors        AnchorStore
	cp             directory.Checkpoint
	http           *http.Client
	cancel         context.CancelFunc
}

func NewDeviceClient(c *directory.Config, ep Endpoint, device directory.Device, key ed25519.PrivateKey, anchors AnchorStore) (*Client, error) {
	if !canonicalHex(device.ID, 16) || !validPrivate(key) || device.Signing != hex.EncodeToString(key.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	r, e := age.ParseX25519Recipient(device.Encryption)
	if e != nil || r.String() != device.Encryption {
		return nil, ErrInvalid
	}
	return newClient(c, ep, "device", device.ID, key, anchors)
}
func NewOwnerClient(c *directory.Config, ep Endpoint, key ed25519.PrivateKey, anchors AnchorStore) (*Client, error) {
	if !validPrivate(key) {
		return nil, ErrInvalid
	}
	id := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if !bytes.Equal(c.OwnerSigningKey(id), key.Public().(ed25519.PublicKey)) {
		return nil, ErrDenied
	}
	return newClient(c, ep, "owner", id, key, anchors)
}
func newClient(c *directory.Config, ep Endpoint, kind, id string, key ed25519.PrivateKey, anchors AnchorStore) (*Client, error) {
	if !c.WriterACLPolicy() || anchors == nil {
		return nil, ErrInvalid
	}
	u, e := url.Parse(ep.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" {
		return nil, ErrInvalid
	}
	cp, e := anchors.Load()
	if e != nil || !c.ValidCheckpoint(cp) {
		return nil, ErrAnchor
	}
	var roots *x509.CertPool
	if ep.Roots != nil {
		roots = ep.Roots.Clone()
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname()}}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransport }}
	return &Client{key: bytes.Clone(key), kind: kind, id: id, base: "https://" + u.Host, config: c, anchors: anchors, cp: cp, http: client}, nil
}
func (c *Client) Checkpoint() directory.Checkpoint {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.cp
}
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.closed.Store(true)
	c.stateMu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.stateMu.Unlock()
	c.keyMu.Lock()
	clear(c.key)
	c.key = nil
	c.keyMu.Unlock()
	c.http.CloseIdleConnections()
}
func (c *Client) begin(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || c.closed.Load() {
		return nil, nil, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	c.stateMu.Lock()
	if c.closed.Load() {
		c.stateMu.Unlock()
		cancel()
		return nil, nil, ErrClosed
	}
	c.cancel = cancel
	c.stateMu.Unlock()
	return ctx, func() { cancel(); c.stateMu.Lock(); c.cancel = nil; c.stateMu.Unlock() }, nil
}
func (c *Client) request(ctx context.Context, action string, anchor directory.Checkpoint, p *publication) (response, error) {
	started := time.Now()
	ctx, cancel, e := c.begin(ctx)
	if e != nil {
		return response{}, e
	}
	defer cancel()
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return response{}, ErrTransport
	}
	q := request{Proof: requestProof{Protocol: protocol, Scope: c.config.Genesis().Scope, Action: action, Kind: c.kind, ID: c.id, Nonce: hex.EncodeToString(nonce), Anchor: anchor, BodyDigest: digest("payload", p)}, Publication: p}
	c.keyMu.Lock()
	if c.closed.Load() {
		c.keyMu.Unlock()
		return response{}, ErrClosed
	}
	q.Proof.Signature = ed25519.Sign(c.key, q.Proof.signingBytes())
	c.keyMu.Unlock()
	raw := encode(q)
	limit, path := MaxReadBytes, ReadPath
	if action == "publish" {
		limit, path = MaxPublishBytes, PublishPath
	}
	if len(raw) > limit {
		return response{}, ErrCapacity
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if e != nil {
		return response{}, ErrTransport
	}
	r.Header.Set("Content-Type", "application/json")
	reply, e := c.http.Do(r)
	if e != nil {
		return response{}, ErrTransport
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK || reply.Header.Get("Content-Type") != "application/json" || reply.Header.Get("Content-Encoding") != "" || reply.ContentLength > MaxResponseBytes {
		return response{}, ErrTransport
	}
	raw, e = io.ReadAll(io.LimitReader(reply.Body, MaxResponseBytes+1))
	if e != nil {
		return response{}, ErrTransport
	}
	if len(raw) > MaxResponseBytes {
		return response{}, ErrCapacity
	}
	if time.Since(started) > 15*time.Second || ctx.Err() != nil {
		return response{}, ErrFreshness
	}
	var out response
	if decode(raw, &out) != nil || out.Protocol != protocol || out.RequestDigest != digest("request", q) || out.Nonce != q.Proof.Nonce || !ed25519.Verify(c.config.SequencerSigningKey(), out.signingBytes(), out.Signature) {
		return response{}, ErrInvalid
	}
	if out.History != nil {
		if out.HistoryDigest != digest("history", out.History) {
			return response{}, ErrInvalid
		}
	} else if out.HistoryDigest != "" {
		return response{}, ErrInvalid
	}
	if out.Receipt != nil {
		if out.ReceiptDigest != digest("receipt", out.Receipt) {
			return response{}, ErrInvalid
		}
	} else if out.ReceiptDigest != "" {
		return response{}, ErrInvalid
	}
	if out.Status != "current" && out.Status != "committed" {
		if out.History != nil || out.Receipt != nil || out.Head != (directory.Checkpoint{}) {
			return response{}, ErrInvalid
		}
		return response{}, &signedRefusal{statusError(out.Status)}
	}
	if action == "read" && (out.Status != "current" || out.History == nil || out.Receipt != nil) || action == "publish" && (out.Status != "committed" || out.Receipt == nil || out.History != nil) {
		return response{}, ErrInvalid
	}
	if c.closed.Load() {
		return response{}, ErrClosed
	}
	return out, nil
}
func (c *Client) loadAnchor() (directory.Checkpoint, error) {
	cp, e := c.anchors.Load()
	if e != nil || !c.config.ValidCheckpoint(cp) {
		return directory.Checkpoint{}, ErrAnchor
	}
	known := c.Checkpoint()
	if cp.Version < known.Version || cp.Version == known.Version && cp != known {
		return directory.Checkpoint{}, ErrAnchor
	}
	return cp, nil
}
func (c *Client) persist(old, next directory.Checkpoint) error {
	if c.closed.Load() {
		return ErrClosed
	}
	if c.anchors.Advance(old, next) != nil {
		return ErrAnchor
	}
	if c.closed.Load() {
		return ErrClosed
	}
	c.stateMu.Lock()
	c.cp = next
	c.stateMu.Unlock()
	return nil
}
func (c *Client) fetch(ctx context.Context) (VerifiedState, error) {
	started := time.Now()
	anchor, e := c.loadAnchor()
	if e != nil {
		return VerifiedState{}, e
	}
	r, e := c.request(ctx, "read", anchor, nil)
	if e != nil {
		var refusal *signedRefusal
		if errors.As(e, &refusal) {
			e = refusal.err
		}
		return VerifiedState{}, e
	}
	v, e := directory.VerifyHistory(c.config, anchor, *r.History)
	if e != nil {
		return VerifiedState{}, mapDirectoryError(e)
	}
	if v.Receipt.Checkpoint() != r.Head {
		return VerifiedState{}, ErrInvalid
	}
	if time.Since(started) > 15*time.Second {
		return VerifiedState{}, ErrFreshness
	}
	if e = c.persist(anchor, r.Head); e != nil {
		return VerifiedState{}, e
	}
	if time.Since(started) > 15*time.Second {
		return VerifiedState{}, ErrFreshness
	}
	return VerifiedState{view: v, history: cloneHistory(*r.History)}, nil
}
func (c *Client) Fetch(ctx context.Context) (VerifiedState, error) {
	c.op.Lock()
	defer c.op.Unlock()
	return c.fetch(ctx)
}
func (c *Client) Publish(ctx context.Context, p directory.Proposal, s vault.Snapshot) (directory.Receipt, error) {
	c.op.Lock()
	defer c.op.Unlock()
	if len(s.Database) > 8<<20 || len(s.Envelope) > 128<<10 || len(p.Members) > 64 || len(p.Admissions) > 64 {
		return directory.Receipt{}, ErrCapacity
	}
	raw := encode(publication{p, s})
	if len(raw) > MaxPublishBytes {
		return directory.Receipt{}, ErrCapacity
	}
	var owned publication
	if decode(raw, &owned) != nil {
		return directory.Receipt{}, ErrInvalid
	}
	state, e := c.fetch(ctx)
	if e != nil {
		return directory.Receipt{}, e
	}
	if owned.Proposal.Parent != state.Checkpoint() {
		return directory.Receipt{}, ErrConflict
	}
	started := time.Now()
	r, e := c.request(ctx, "publish", state.Checkpoint(), &owned)
	if e != nil {
		var refusal *signedRefusal
		if errors.As(e, &refusal) {
			return directory.Receipt{}, refusal.err
		}
		return directory.Receipt{}, ErrUnknown
	}
	if !bytes.Equal(encode(r.Receipt.Proposal), encode(owned.Proposal)) || r.Receipt.Checkpoint() != r.Head {
		return directory.Receipt{}, ErrUnknown
	}
	h := state.history
	h.Receipts = append(h.Receipts, *r.Receipt)
	h.Snapshot = owned.Snapshot
	if _, e = directory.VerifyHistory(c.config, state.Checkpoint(), h); e != nil {
		return directory.Receipt{}, ErrUnknown
	}
	if time.Since(started) > 15*time.Second {
		return directory.Receipt{}, ErrUnknown
	}
	if e = c.persist(state.Checkpoint(), r.Head); e != nil {
		return directory.Receipt{}, ErrUnknown
	}
	if time.Since(started) > 15*time.Second {
		return directory.Receipt{}, ErrUnknown
	}
	var receipt directory.Receipt
	_ = json.Unmarshal(encode(r.Receipt), &receipt)
	return receipt, nil
}
func (c *Client) Reconcile(ctx context.Context, p directory.Proposal) (Reconciliation, error) {
	c.op.Lock()
	defer c.op.Unlock()
	if p.Scope != c.config.Genesis().Scope || !c.config.ValidCheckpoint(p.Parent) || p.Epoch != p.Parent.Version+1 {
		return Reconciliation{}, ErrInvalid
	}
	state, e := c.fetch(ctx)
	if e != nil {
		return Reconciliation{}, e
	}
	out := Reconciliation{State: PublishUnknown, Current: state.Checkpoint()}
	for _, receipt := range state.history.Receipts {
		if receipt.Proposal.Epoch == p.Epoch {
			if digest("proposal", receipt.Proposal) == digest("proposal", p) {
				out.State = PublishCommitted
				out.Receipt = receipt
			} else {
				out.State = PublishConflicted
			}
			break
		}
	}
	return out, nil
}
