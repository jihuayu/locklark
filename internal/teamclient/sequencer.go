package teamclient

import "context"

type SequencerPlan struct{ inner *bootstrapPlan }

func (SequencerPlan) String() string               { return "[protected sequencer preparation]" }
func (SequencerPlan) GoString() string             { return "[protected sequencer preparation]" }
func (SequencerPlan) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }
func PrepareSequencer(path string) (*SequencerPlan, error) {
	path, e := canonicalProfilePath(path)
	if e != nil {
		return nil, e
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
	service, e := newID(used)
	if e != nil {
		return nil, e
	}
	seed, pub, e := newSeed()
	if e != nil {
		return nil, e
	}
	defer clear(seed)
	d := SequencerDescriptor{Version: 1, ProfileID: profile, InstallID: install, ServiceID: service, Signing: pub, State: BootstrapPreparing}
	r := profileRecord{Path: path, Version: 1, Revision: 1, Kind: "sequencer", Phase: BootstrapPreparing, Sequencer: &d, Roles: map[string]BootstrapPhase{"sequencer": BootstrapPreparing}}
	b, _, _ := bindingFor(r, "sequencer")
	raw, e := encodeSequencer(b, seed, "")
	if e != nil {
		return nil, e
	}
	if e = createProfile(path, r); e != nil {
		clear(raw)
		return nil, e
	}
	return &SequencerPlan{&bootstrapPlan{path: path, record: r, secrets: map[string][]byte{"sequencer": raw}}}, nil
}
func (p *SequencerPlan) Descriptor() SequencerDescriptor {
	if p == nil || p.inner == nil {
		return SequencerDescriptor{}
	}
	x := p.inner
	x.guard.mu.Lock()
	defer x.guard.mu.Unlock()
	d := *x.record.Sequencer
	d.State = x.record.Phase
	return d
}
func (p *SequencerPlan) Protect(ctx context.Context, s SystemStore) (SequencerDescriptor, error) {
	if p == nil || p.inner == nil {
		return SequencerDescriptor{}, ErrIdentity
	}
	r, e := p.inner.protect(ctx, s)
	d := *r.Sequencer
	d.State = r.Phase
	return d, e
}
func (p *SequencerPlan) Close() {
	if p != nil {
		p.inner.close()
	}
}
