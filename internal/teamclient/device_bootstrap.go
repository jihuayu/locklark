package teamclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
	"github.com/jihuayu/locklark/internal/vault"
)

// ConfirmInitial is worker-only. It uses the first device's own HTTP signature,
// not owner read authority. The only creation of its independent anchor occurred
// in PrepareOwnerBootstrap, before OS role storage; missing anchors never reset.
func ConfirmInitial(ctx context.Context, path string, trusted directory.Pins, s SystemStore, ep teamsync.Endpoint) (out InitialResult, err error) {
	if ctx == nil || ctx.Err() != nil || s == nil {
		return out, ErrCancelled
	}
	lease, e := openProfile(path)
	if e != nil {
		return out, e
	}
	defer func() {
		if lease.close() != nil {
			out = InitialResult{}
			err = ErrBootstrapUnknown
		}
	}()
	r, e := lease.load()
	if e != nil || r.Kind != "owner" || len(r.Artifact) == 0 {
		return out, ErrProfile
	}
	p, c, e := normalizedPins(trusted)
	if e != nil || !samePins(p, r.Owner.Pins) {
		return out, ErrBootstrapConflict
	}
	a, e := DecodeBootstrapArtifact(r.Artifact)
	if e != nil || !samePins(p, a.Pins) || !artifactMatchesOwner(a, *r.Owner) {
		return out, ErrIdentity
	}
	anchors, e := teamsync.OpenFileAnchorStore(r.Owner.Anchor)
	if e != nil {
		return out, ErrProfile
	}
	// Check the protected management profile binding (including fixed anchor
	// path) without using its signer or owner HTTP privileges.
	publicBinding, e := loadRaw(ctx, s, r, "owner")
	if e == nil {
		binding, _, _ := bindingFor(r, "owner")
		seed, marker, decodeErr := decodeOwnerRole(binding, publicBinding)
		clear(seed)
		if decodeErr != nil || marker.Stage != "built" || marker.BuildID != r.BuildID || marker.ArtifactDigest != artifactDigest(r.Artifact) {
			e = ErrBootstrapUnknown
		}
	}
	clear(publicBinding)
	if e != nil {
		return out, e
	}
	o, e := NewDeviceOperation(p, r.Owner.Device)
	if e != nil {
		return out, e
	}
	defer o.Close()
	if e = o.Load(ctx, s); e != nil {
		return out, e
	}
	x := o.inner
	x.mu.Lock()
	if x.closed || x.used || ctx.Err() != nil {
		x.mu.Unlock()
		return out, ErrCancelled
	}
	x.used = true
	m := x.material
	x.material = nil
	x.mu.Unlock()
	defer m.clear()
	if m == nil {
		return out, ErrIdentity
	}
	key := ed25519.NewKeyFromSeed(m.signingSeed)
	defer clear(key)
	client, e := teamsync.NewDeviceClient(c, ep, r.Owner.Device.Device, key, anchors)
	if e != nil {
		return out, ErrProfile
	}
	defer client.Close()
	state, e := client.Fetch(ctx)
	if e != nil {
		return out, ErrBootstrapUnknown
	}
	history := state.History()
	if len(history.Receipts) == 0 {
		return out, ErrIdentity
	}
	one, _ := json.Marshal(history.Receipts[0].Proposal)
	want, _ := json.Marshal(a.Proposal)
	if !bytes.Equal(one, want) {
		return out, ErrBootstrapConflict
	}
	view := state.View()
	if view.Receipt.Proposal.Mode != "active" {
		return out, ErrAdmission
	}
	id, e := age.ParseX25519Identity(string(m.ageEncoded))
	if e != nil {
		return out, ErrIdentity
	}
	data, items, e := vault.OpenItems(view.Snapshot, id, view.SnapshotSigner, view.Receipt.Proposal.Epoch)
	defer clear(data)
	defer func() {
		for n := range items {
			clear(items[n].Attachment)
			clear(items[n].ImportSource)
			clear(items[n].SSHSeed)
			clear(items[n].Passkey)
			items[n] = vault.Item{}
		}
	}()
	if e != nil || items == nil || len(items) != 0 || !bytes.Equal(data, []byte("locklark/team/items/v1/"+c.Genesis().Scope)) {
		return out, ErrIdentity
	}
	// This slice only activates an empty bootstrap. No plaintext item or key
	// ever leaves this operation; later item workflows need separate approval.
	x.mu.Lock()
	cancelled := x.closed || ctx.Err() != nil
	x.mu.Unlock()
	if cancelled {
		return out, ErrCancelled
	}
	r.Phase = BootstrapActive
	if lease.save(&r) != nil {
		return out, ErrBootstrapUnknown
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed || ctx.Err() != nil {
		return out, ErrCancelled
	}
	return InitialResult{State: BootstrapActive, Checkpoint: state.Checkpoint(), DeviceID: r.Owner.Device.Device.ID, ItemCount: 0}, nil
}
