package teamclient

import (
	"context"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
)

type OwnerPlan struct{ inner *bootstrapPlan }

func (OwnerPlan) String() string               { return "[protected owner bootstrap preparation]" }
func (OwnerPlan) GoString() string             { return "[protected owner bootstrap preparation]" }
func (OwnerPlan) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }
func PrepareOwnerBootstrap(path string, reviewed SequencerDescriptor, anchor string) (*OwnerPlan, error) {
	if !validSequencer(reviewed) || reviewed.State != BootstrapPending {
		return nil, ErrIdentity
	}
	path, e := canonicalProfilePath(path)
	if e != nil {
		return nil, e
	}
	anchor, e = canonicalProfilePath(anchor)
	if e != nil || !distinctPaths(path, anchor, path+".identity-lease") || !absent(anchor) {
		return nil, ErrProfile
	}
	used := map[string]bool{}
	profile, e := newID(used)
	if e != nil {
		return nil, e
	}
	install, e := newID(used)
	if e != nil {
		return nil, e
	}
	member, e := newID(used)
	if e != nil {
		return nil, e
	}
	team, e := newID(used)
	if e != nil {
		return nil, e
	}
	vaultID, e := newID(used)
	if e != nil {
		return nil, e
	}
	ownerSeed, ownerPub, e := newSeed()
	if e != nil {
		return nil, e
	}
	defer clear(ownerSeed)
	pubSeed, pubPub, e := newSeed()
	if e != nil {
		return nil, e
	}
	defer clear(pubSeed)
	pins := directory.Pins{Team: team, Vault: vaultID, Owners: []string{ownerPub}, Publisher: pubPub, Sequencer: reviewed.Signing}
	pins, c, e := normalizedPins(pins)
	if e != nil {
		return nil, e
	}
	device, e := PrepareDevice(pins)
	if e != nil {
		return nil, e
	}
	defer device.Close()
	d := OwnerDescriptor{Service: reviewed, Version: 1, ProfileID: profile, InstallID: install, MemberID: member, Pins: pins, Anchor: anchor, State: BootstrapPreparing, Device: device.Descriptor(), Owner: RoleDescriptor{Version: 1, Role: "owner", ProfileID: profile, InstallID: install, Scope: c.Genesis().Scope, Signing: ownerPub}, Publisher: RoleDescriptor{Version: 1, Role: "publisher", ProfileID: profile, InstallID: install, Scope: c.Genesis().Scope, Signing: pubPub}}
	r := profileRecord{Path: path, Version: 1, Revision: 1, Kind: "owner", Phase: BootstrapPreparing, Owner: &d, Roles: map[string]BootstrapPhase{"owner": BootstrapPreparing, "publisher": BootstrapPreparing, "device": BootstrapPreparing}}
	material := map[string][]byte{}
	defer func() {
		for _, raw := range material {
			clear(raw)
		}
	}()
	for role, seed := range map[string][]byte{"owner": ownerSeed, "publisher": pubSeed} {
		b, _, _ := bindingFor(r, role)
		var raw []byte
		if role == "owner" {
			raw, e = encodeOwnerRole(b, seed, ownerMarker{Stage: "unbuilt"})
		} else {
			raw, e = encodeRole(b, seed)
		}
		if e != nil {
			return nil, e
		}
		material[role] = raw
	}
	raw, e := encodeDevice(d.Device, device.inner.material)
	if e != nil || len(raw) > maxProtectedRoleBytes {
		clear(raw)
		return nil, ErrIdentity
	}
	material["device"] = raw
	if e = createProfile(path, r); e != nil {
		return nil, e
	}
	// This is the only client-anchor creation permission, before any role Store.
	// Later entries only Open, regardless of a restored public workflow phase.
	if _, e = teamsync.CreateFileAnchorStore(anchor, c.Genesis()); e != nil {
		return nil, ErrBootstrapUnknown
	}
	result := &OwnerPlan{&bootstrapPlan{path: path, record: r, secrets: material}}
	material = nil
	return result, nil
}
func (p *OwnerPlan) Descriptor() OwnerDescriptor {
	if p == nil || p.inner == nil {
		return OwnerDescriptor{}
	}
	x := p.inner
	x.guard.mu.Lock()
	defer x.guard.mu.Unlock()
	d := cloneOwner(*x.record.Owner)
	d.State = x.record.Phase
	return d
}
func (p *OwnerPlan) Protect(ctx context.Context, s SystemStore) (OwnerDescriptor, error) {
	if p == nil || p.inner == nil {
		return OwnerDescriptor{}, ErrIdentity
	}
	r, e := p.inner.protect(ctx, s)
	d := cloneOwner(*r.Owner)
	d.State = r.Phase
	return d, e
}
func (p *OwnerPlan) Close() {
	if p != nil {
		p.inner.close()
	}
}

type OwnerBootstrap struct{ inner *ownerBootstrap }
type ownerBootstrap struct {
	guard      bootstrapGuard
	path       string
	descriptor OwnerDescriptor
	cancel     context.CancelFunc
	used       bool
}

func (OwnerBootstrap) String() string               { return "[protected owner bootstrap operation]" }
func (OwnerBootstrap) GoString() string             { return "[protected owner bootstrap operation]" }
func (OwnerBootstrap) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }
func OpenOwnerBootstrap(path string) (*OwnerBootstrap, error) {
	lease, e := openProfile(path)
	if e != nil {
		return nil, e
	}
	r, e := lease.load()
	closed := lease.close()
	if e != nil || closed != nil || r.Kind != "owner" {
		return nil, ErrProfile
	}
	d := cloneOwner(*r.Owner)
	d.State = r.Phase
	return &OwnerBootstrap{&ownerBootstrap{path: r.Path, descriptor: d}}, nil
}
func (o *OwnerBootstrap) Descriptor() OwnerDescriptor {
	if o == nil || o.inner == nil {
		return OwnerDescriptor{}
	}
	return cloneOwner(o.inner.descriptor)
}
func (o *OwnerBootstrap) Close() {
	if o != nil && o.inner != nil {
		x := o.inner
		x.guard.mu.Lock()
		x.guard.closed = true
		cancel := x.cancel
		x.cancel = nil
		x.guard.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}
