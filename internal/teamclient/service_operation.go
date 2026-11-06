package teamclient

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
)

type ServiceOperation struct{ inner *serviceOperation }
type serviceOperation struct {
	guard   bootstrapGuard
	handler teamsync.ManagedHandler
	stop    func() bool
}

func (ServiceOperation) String() string               { return "[protected team service]" }
func (ServiceOperation) GoString() string             { return "[protected team service]" }
func (ServiceOperation) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }
func OpenService(ctx context.Context, path string, expected SequencerDescriptor, pins directory.Pins, s SystemStore) (out *ServiceOperation, err error) {
	if ctx == nil || ctx.Err() != nil || s == nil {
		return nil, ErrCancelled
	}
	lease, e := openProfile(path)
	if e != nil {
		return nil, e
	}
	defer func() {
		if lease.close() != nil {
			if out != nil {
				out.Close()
			}
			out = nil
			err = ErrProfile
		}
	}()
	r, e := lease.load()
	if e != nil || r.Kind != "sequencer" || r.Phase != BootstrapActive || r.Init == nil || r.Init.Receipt == nil {
		return nil, ErrProfile
	}
	a, e := DecodeBootstrapArtifact(r.Init.Artifact)
	if e != nil {
		return nil, e
	}
	q, raw, e := checkedInit(r.Path, r, ServiceInitRequest{Expected: expected, TrustedPins: pins, Artifact: a, Directory: r.Init.Directory, Anchor: r.Init.Anchor})
	if e != nil || artifactDigest(raw) != r.Init.Digest {
		return nil, ErrBootstrapConflict
	}
	anchors, e := teamsync.OpenFileAnchorStore(q.Anchor)
	if e != nil {
		return nil, ErrProfile
	}
	c, _ := directory.NewConfigWithWriterACL(q.TrustedPins)
	if _, e = exactInitialization(r, c, a); e != nil {
		return nil, e
	}
	sealed, e := loadRaw(ctx, s, r, "sequencer")
	if e != nil {
		return nil, e
	}
	defer clear(sealed)
	b, _, _ := bindingFor(r, "sequencer")
	seed, target, e := decodeSequencer(b, sealed)
	if e != nil {
		return nil, e
	}
	defer clear(seed)
	if target != serviceTarget(q.TrustedPins, a.Proposal.Scope, r.Init.Digest, q.Directory, q.Anchor) {
		return nil, ErrBootstrapConflict
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	h, e := teamsync.NewManagedHandler(q.Directory, c, key, r.Init.Receipt.Checkpoint(), anchors)
	if e != nil {
		return nil, ErrProfile
	}
	op := &ServiceOperation{&serviceOperation{handler: h}}
	stop := context.AfterFunc(ctx, op.Close)
	op.inner.guard.mu.Lock()
	if op.inner.guard.closed || ctx.Err() != nil {
		op.inner.guard.mu.Unlock()
		stop()
		h.Close()
		return nil, ErrCancelled
	}
	op.inner.stop = stop
	op.inner.guard.mu.Unlock()
	return op, nil
}
func (o *ServiceOperation) Handler() http.Handler {
	if o == nil || o.inner == nil {
		return http.NotFoundHandler()
	}
	return o
}
func (o *ServiceOperation) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if o == nil || o.inner == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	x := o.inner
	x.guard.mu.Lock()
	closed := x.guard.closed
	h := x.handler
	x.guard.mu.Unlock()
	if closed {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	h.ServeHTTP(w, r)
}
func (o *ServiceOperation) Close() {
	if o == nil || o.inner == nil {
		return
	}
	x := o.inner
	x.guard.mu.Lock()
	if x.guard.closed {
		x.guard.mu.Unlock()
		return
	}
	x.guard.closed = true
	stop := x.stop
	x.stop = nil
	h := x.handler
	x.guard.mu.Unlock()
	if stop != nil {
		stop()
	}
	h.Close()
}
