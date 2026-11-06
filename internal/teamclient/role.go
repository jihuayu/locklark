package teamclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/jihuayu/locklark/internal/directory"
)

const roleDomain = "locklark/teamclient/protected-role/v1\x00"
const maxProtectedRoleBytes = 1400

type roleBinding struct {
	Descriptor   RoleDescriptor
	ServiceID    string
	Pins         directory.Pins
	ProfilePath  string
	OwnerContext string
}

func validSequencer(d SequencerDescriptor) bool {
	return d.Version == 1 && validHex(d.ProfileID, 16) && validHex(d.InstallID, 16) && validHex(d.ServiceID, 16) && d.ProfileID != d.InstallID && d.ServiceID != d.ProfileID && d.ServiceID != d.InstallID && validDeviceSigning(d.Signing) && validPhase(d.State)
}
func sameSequencer(a, b SequencerDescriptor) bool { a.State = ""; b.State = ""; return a == b }
func seqRole(d SequencerDescriptor) roleBinding {
	return roleBinding{Descriptor: RoleDescriptor{Version: 1, Role: "sequencer", ProfileID: d.ProfileID, InstallID: d.InstallID, Signing: d.Signing}, ServiceID: d.ServiceID}
}
func validOwner(d OwnerDescriptor) bool {
	p, c, e := normalizedPins(d.Pins)
	if e != nil || len(p.Owners) != 1 || !validSequencer(d.Service) || d.Service.State != BootstrapPending || d.Service.Signing != p.Sequencer || d.Version != 1 || !validHex(d.ProfileID, 16) || !validHex(d.InstallID, 16) || d.ProfileID == d.InstallID || !validHex(d.MemberID, 16) || d.MemberID == d.Device.Device.ID || !validPhase(d.State) || !distinctPaths(d.Anchor) {
		return false
	}
	if _, _, e = validateDescriptor(p, d.Device); e != nil {
		return false
	}
	for role, x := range map[string]RoleDescriptor{"owner": d.Owner, "publisher": d.Publisher} {
		if x.Version != 1 || x.Role != role || x.ProfileID != d.ProfileID || x.InstallID != d.InstallID || x.Scope != c.Genesis().Scope {
			return false
		}
	}
	return d.Owner.Signing == p.Owners[0] && d.Publisher.Signing == p.Publisher
}
func cloneOwner(d OwnerDescriptor) OwnerDescriptor {
	d.Pins = clonePins(d.Pins)
	d.Device = cloneDescriptor(d.Device)
	return d
}
func roleID(b roleBinding) string {
	b.ProfilePath = ""
	raw, _ := json.Marshal(b)
	h := sha256.Sum256(append([]byte("locklark/teamclient/role-store-id/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}
func encodeRole(b roleBinding, seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrIdentity
	}
	out := appendFrame([]byte(roleDomain), []byte(roleDigest(b)))
	return appendFrame(out, seed), nil
}
func roleDigest(b roleBinding) string {
	raw, _ := json.Marshal(b)
	h := sha256.Sum256(append([]byte("locklark/teamclient/role-binding/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}
func decodeRole(b roleBinding, raw []byte) ([]byte, error) {
	if len(raw) > maxDeviceEnvelope || !bytes.HasPrefix(raw, []byte(roleDomain)) {
		return nil, ErrIdentity
	}
	// Compare the complete bounded framing, including exact canonical binding.
	if len(raw) < len(roleDomain)+8+ed25519.SeedSize {
		return nil, ErrIdentity
	}
	seed := raw[len(raw)-ed25519.SeedSize:]
	expected, _ := encodeRole(b, seed)
	defer clear(expected)
	if !bytes.Equal(expected, raw) {
		return nil, ErrIdentity
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != b.Descriptor.Signing {
		return nil, ErrIdentity
	}
	return bytes.Clone(seed), nil
}
func newSeed() (seed []byte, public string, err error) {
	seed = make([]byte, 32)
	if _, e := rand.Read(seed); e != nil {
		clear(seed)
		return nil, "", ErrIdentity
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	return seed, hex.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}
func bindingFor(r profileRecord, role string) (roleBinding, string, error) {
	if r.Kind == "sequencer" && role == "sequencer" {
		b := seqRole(*r.Sequencer)
		b.ProfilePath = r.Path
		return b, roleID(b), nil
	}
	if r.Kind == "owner" && role != "device" {
		d := r.Owner.Owner
		if role == "publisher" {
			d = r.Owner.Publisher
		} else if role != "owner" {
			return roleBinding{}, "", ErrIdentity
		}
		public := cloneOwner(*r.Owner)
		public.State = ""
		public.Device.State = ""
		public.Service.State = ""
		encoded, _ := json.Marshal(public)
		digest := sha256.Sum256(append([]byte("locklark/teamclient/owner-context/v1\x00"), encoded...))
		b := roleBinding{Descriptor: d, Pins: clonePins(r.Owner.Pins), ProfilePath: r.Path, OwnerContext: hex.EncodeToString(digest[:])}
		return b, roleID(b), nil
	}
	if r.Kind == "owner" && role == "device" {
		id, e := deviceStoreID(r.Owner.Device)
		return roleBinding{}, id, e
	}
	return roleBinding{}, "", ErrIdentity
}
func validateRoleRaw(r profileRecord, role string, raw []byte) error {
	if len(raw) > maxProtectedRoleBytes {
		return ErrIdentity
	}
	if role == "device" {
		m, e := decodeDevice(r.Owner.Device, raw)
		if m != nil {
			m.clear()
		}
		return e
	}
	b, _, e := bindingFor(r, role)
	if e != nil {
		return e
	}
	var seed []byte
	if role == "sequencer" {
		seed, _, e = decodeSequencer(b, raw)
	} else if role == "owner" {
		seed, _, e = decodeOwnerRole(b, raw)
	} else {
		seed, e = decodeRole(b, raw)
	}
	clear(seed)
	return e
}
func loadRaw(ctx context.Context, store SystemStore, r profileRecord, role string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || store == nil {
		return nil, ErrCancelled
	}
	_, id, e := bindingFor(r, role)
	if e != nil {
		return nil, e
	}
	raw, e := store.Load(id)
	if e != nil {
		clear(raw)
		return nil, ErrProtection
	}
	if ctx.Err() != nil {
		clear(raw)
		return nil, ErrCancelled
	}
	if e = validateRoleRaw(r, role, raw); e != nil {
		clear(raw)
		return nil, e
	}
	return raw, nil
}
func loadSeed(ctx context.Context, store SystemStore, r profileRecord, role string) ([]byte, error) {
	raw, e := loadRaw(ctx, store, r, role)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	b, _, _ := bindingFor(r, role)
	if role == "sequencer" {
		seed, _, e := decodeSequencer(b, raw)
		return seed, e
	}
	if role == "owner" {
		seed, _, e := decodeOwnerRole(b, raw)
		return seed, e
	}
	return decodeRole(b, raw)
}

type bootstrapGuard struct {
	mu     sync.Mutex
	closed bool
}

func (g *bootstrapGuard) valid(ctx context.Context) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.closed && ctx != nil && ctx.Err() == nil
}
func (g *bootstrapGuard) close() { g.mu.Lock(); g.closed = true; g.mu.Unlock() }

type bootstrapPlan struct {
	guard     bootstrapGuard
	path      string
	record    profileRecord
	secrets   map[string][]byte
	attempted bool
}

func (p *bootstrapPlan) startStore(ctx context.Context) bool {
	p.guard.mu.Lock()
	defer p.guard.mu.Unlock()
	if p.guard.closed || ctx == nil || ctx.Err() != nil {
		return false
	}
	p.record.Phase = BootstrapUnknown
	return true
}

func (p *bootstrapPlan) close() {
	if p == nil {
		return
	}
	p.guard.mu.Lock()
	defer p.guard.mu.Unlock()
	p.guard.closed = true
	for _, b := range p.secrets {
		clear(b)
	}
	p.secrets = nil
}
func (p *bootstrapPlan) protect(ctx context.Context, store SystemStore) (out profileRecord, err error) {
	p.guard.mu.Lock()
	if p.guard.closed {
		out = p.record
		p.guard.mu.Unlock()
		return out, ErrCancelled
	}
	if p.attempted {
		out = p.record
		p.guard.mu.Unlock()
		return out, ErrConsumed
	}
	p.attempted = true
	material := p.secrets
	p.secrets = nil
	out = p.record
	p.guard.mu.Unlock()
	defer func() { p.guard.mu.Lock(); p.record = out; p.guard.mu.Unlock() }()
	defer func() {
		for _, b := range material {
			clear(b)
		}
	}()
	if ctx == nil || store == nil {
		return out, ErrIdentity
	}
	stop := context.AfterFunc(ctx, p.close)
	defer stop()
	lease, e := openProfile(p.path)
	if e != nil {
		return out, e
	}
	defer func() {
		if lease.close() != nil {
			err = ErrBootstrapUnknown
			out.Phase = BootstrapUnknown
		}
	}()
	r, e := lease.load()
	if e != nil {
		return out, e
	}
	roles := []string{"sequencer"}
	if r.Kind == "owner" {
		roles = []string{"owner", "publisher", "device"}
	}
	for _, role := range roles {
		if !p.guard.valid(ctx) {
			return r, ErrCancelled
		}
		if r.Roles[role] != BootstrapPreparing {
			raw, e := loadRaw(ctx, store, r, role)
			clear(raw)
			if e != nil {
				return r, ErrBootstrapUnknown
			}
		} else {
			raw := material[role]
			if validateRoleRaw(r, role, raw) != nil {
				return r, ErrIdentity
			}
			// The start grant precedes durable unknown; no OS mutation is allowed
			// until that record commits. Close after this grant cannot undo it.
			if !p.startStore(ctx) {
				return r, ErrCancelled
			}
			r.Roles[role] = BootstrapUnknown
			r.Phase = BootstrapUnknown
			if lease.save(&r) != nil {
				return r, ErrBootstrapUnknown
			}
			_, id, _ := bindingFor(r, role)
			if e = store.Store(id, raw); e != nil {
				return r, ErrBootstrapUnknown
			}
			if !p.guard.valid(ctx) {
				return r, ErrCancelled
			}
		}
		r.Roles[role] = BootstrapPending
		if lease.save(&r) != nil {
			return r, ErrBootstrapUnknown
		}
	}
	r.Phase = BootstrapPending
	if lease.save(&r) != nil {
		return r, ErrBootstrapUnknown
	}
	p.guard.mu.Lock()
	defer p.guard.mu.Unlock()
	if p.guard.closed || ctx.Err() != nil {
		return r, ErrCancelled
	}
	p.record = r
	return r, nil
}
