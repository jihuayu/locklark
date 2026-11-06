package teamclient

import (
	"context"
	"crypto/ed25519"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
	"github.com/jihuayu/locklark/internal/vault"
)

// BuildInitial claims the protected owner before any challenge/signature and
// seals the exact durable outbox digest before export. Claimed crash recovery
// never generates another artifact or retries an ambiguous OS transition.
func (o *OwnerBootstrap) BuildInitial(ctx context.Context, s SystemStore) (out BootstrapArtifact, err error) {
	if o == nil || o.inner == nil || s == nil || !o.inner.guard.valid(ctx) {
		return out, ErrCancelled
	}
	x := o.inner
	workCtx, cancel := context.WithCancel(ctx)
	x.guard.mu.Lock()
	if x.guard.closed || x.used {
		x.guard.mu.Unlock()
		cancel()
		return out, ErrConsumed
	}
	x.used = true
	x.cancel = cancel
	x.guard.mu.Unlock()
	ctx = workCtx
	defer o.Close()
	lease, e := openProfile(x.path)
	if e != nil {
		return out, e
	}
	defer func() {
		if lease.close() != nil {
			out = BootstrapArtifact{}
			err = ErrBootstrapUnknown
		}
	}()
	r, e := lease.load()
	if e != nil || r.Kind != "owner" {
		return out, ErrProfile
	}
	c, _ := directory.NewConfigWithWriterACL(r.Owner.Pins)
	if len(r.Artifact) == 0 {
		anchors, e := teamsync.OpenFileAnchorStore(r.Owner.Anchor)
		if e != nil {
			return out, ErrProfile
		}
		checkpoint, e := anchors.Load()
		if e != nil || checkpoint != c.Genesis() {
			return out, ErrBootstrapConflict
		}
	}
	if r.Roles["owner"] == BootstrapPreparing {
		return out, ErrBootstrapUnknown
	}
	sealed, e := loadRaw(ctx, s, r, "owner")
	if e != nil {
		return out, e
	}
	defer clear(sealed)
	b, id, _ := bindingFor(r, "owner")
	seed, marker, e := decodeOwnerRole(b, sealed)
	if e != nil {
		return out, e
	}
	defer clear(seed)
	if len(r.Artifact) > 0 {
		a, e := DecodeBootstrapArtifact(r.Artifact)
		if e != nil || !artifactMatchesOwner(a, *r.Owner) {
			return out, ErrBootstrapConflict
		}
		if marker.Stage != "built" || marker.BuildID != r.BuildID || marker.ArtifactDigest != artifactDigest(r.Artifact) {
			return out, ErrBootstrapUnknown
		}
		return finishOwnerOriginal(ctx, x, lease, &r, a)
	}
	if marker.Stage != "unbuilt" || r.BuildAttempt {
		return out, ErrBootstrapUnknown
	}
	for _, role := range []string{"publisher", "device"} {
		if r.Roles[role] == BootstrapPreparing {
			return out, ErrBootstrapUnknown
		}
	}
	pubSeed, e := loadSeed(ctx, s, r, "publisher")
	if e != nil {
		return out, e
	}
	defer clear(pubSeed)
	device, e := NewDeviceOperation(r.Owner.Pins, r.Owner.Device)
	if e != nil {
		return out, e
	}
	defer device.Close()
	if e = device.Load(ctx, s); e != nil {
		return out, e
	}
	buildID, e := newID(map[string]bool{})
	if e != nil {
		return out, e
	}
	claim, e := encodeOwnerRole(b, seed, ownerMarker{Stage: "claimed", BuildID: buildID})
	if e != nil {
		return out, e
	}
	defer clear(claim)
	if !x.guard.valid(ctx) {
		return out, ErrCancelled
	}
	r.BuildID = buildID
	r.BuildAttempt = true
	r.Phase = BootstrapUnknown
	if lease.save(&r) != nil {
		return out, ErrBootstrapUnknown
	}
	if s.Store(id, claim) != nil {
		return out, ErrBootstrapUnknown
	}
	if !x.guard.valid(ctx) {
		return out, ErrCancelled
	}
	// Only the worker whose fresh claim Store succeeded can reach a signer.
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	pubKey := ed25519.NewKeyFromSeed(pubSeed)
	defer clear(pubKey)
	expected := directory.Enrollment{Parent: c.Genesis(), Member: r.Owner.MemberID, Device: r.Owner.Device.Device}
	challenge, e := directory.IssueChallenge(c, key, expected)
	if e != nil {
		return out, ErrBootstrapUnknown
	}
	proof, e := device.AnswerChallenge(expected, challenge)
	if e != nil || directory.VerifyAdmission(c, expected, proof) != nil {
		return out, ErrAdmission
	}
	if !x.guard.valid(ctx) {
		return out, ErrCancelled
	}
	proposal, snapshot, e := directory.Build(c, key, pubKey, c.Genesis(), []directory.Member{{ID: r.Owner.MemberID, Role: "writer", Devices: []directory.Device{r.Owner.Device.Device}}}, []vault.Item{}, proof)
	if e != nil {
		return out, ErrBootstrapUnknown
	}
	a := BootstrapArtifact{Version: 1, Service: r.Owner.Service, Pins: clonePins(r.Owner.Pins), Proposal: proposal, Snapshot: snapshot}
	raw, e := EncodeBootstrapArtifact(a)
	if e != nil {
		return out, e
	}
	if !x.guard.valid(ctx) {
		return out, ErrCancelled
	}
	r.Artifact = raw
	for _, role := range []string{"owner", "publisher", "device"} {
		r.Roles[role] = BootstrapPending
	}
	if lease.save(&r) != nil {
		return out, ErrBootstrapUnknown
	}
	built, e := encodeOwnerRole(b, seed, ownerMarker{Stage: "built", BuildID: buildID, ArtifactDigest: artifactDigest(raw)})
	if e != nil {
		return out, e
	}
	defer clear(built)
	if !x.guard.valid(ctx) {
		return out, ErrCancelled
	}
	r.FinalizeAttempt = true
	if lease.save(&r) != nil {
		return out, ErrBootstrapUnknown
	}
	if s.Store(id, built) != nil {
		return out, ErrBootstrapUnknown
	}
	if !x.guard.valid(ctx) {
		return out, ErrCancelled
	}
	return finishOwnerOriginal(ctx, x, lease, &r, a)
}
func finishOwnerOriginal(ctx context.Context, x *ownerBootstrap, lease *profileLease, r *profileRecord, a BootstrapArtifact) (BootstrapArtifact, error) {
	if !x.guard.valid(ctx) {
		return BootstrapArtifact{}, ErrCancelled
	}
	if r.Phase != BootstrapActive {
		r.Phase = BootstrapPending
	}
	r.BuildAttempt = true
	r.FinalizeAttempt = true
	if lease.save(r) != nil {
		return BootstrapArtifact{}, ErrBootstrapUnknown
	}
	x.guard.mu.Lock()
	defer x.guard.mu.Unlock()
	if x.guard.closed || ctx.Err() != nil {
		return BootstrapArtifact{}, ErrCancelled
	}
	return a, nil
}
