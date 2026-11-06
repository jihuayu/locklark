package teamclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
)

// Public handles are copy-safe: all ownership and arbitration is shared.
type DevicePlan struct{ inner *devicePlan }
type devicePlan struct {
	mu                                  sync.Mutex
	descriptor                          DeviceDescriptor
	material                            *deviceMaterial
	attempted, started, settled, closed bool
}

func (DevicePlan) String() string               { return "[team device preparation]" }
func (DevicePlan) GoString() string             { return "[team device preparation]" }
func (DevicePlan) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }

// PrepareDevice creates an independent identity only in memory. The descriptor
// is exposed before OS I/O so a future coordinator can persist preparing. This
// foundation deliberately provides no durable public-profile implementation.
func PrepareDevice(trusted directory.Pins) (*DevicePlan, error) {
	p, c, e := normalizedPins(trusted)
	if e != nil {
		return nil, e
	}
	used := make(map[string]bool)
	install, e := newID(used)
	if e != nil {
		return nil, e
	}
	profile, e := newID(used)
	if e != nil {
		return nil, e
	}
	device, e := newID(used)
	if e != nil {
		return nil, e
	}
	identity, e := age.GenerateX25519Identity()
	if e != nil {
		return nil, ErrIdentity
	}
	m := &deviceMaterial{ageEncoded: []byte(identity.String()), signingSeed: make([]byte, ed25519.SeedSize)}
	if _, e = rand.Read(m.signingSeed); e != nil {
		m.clear()
		return nil, ErrIdentity
	}
	key := ed25519.NewKeyFromSeed(m.signingSeed)
	defer clear(key)
	d := DeviceDescriptor{Version: deviceVersion, Role: deviceRole, ProfileID: profile, InstallID: install, Scope: c.Genesis().Scope, Pins: p, Device: directory.Device{ID: device, Encryption: identity.Recipient().String(), Signing: hex.EncodeToString(key.Public().(ed25519.PublicKey))}, State: DevicePreparing}
	return &DevicePlan{&devicePlan{descriptor: d, material: m}}, nil
}
func (p *DevicePlan) Descriptor() DeviceDescriptor {
	if p == nil || p.inner == nil {
		return DeviceDescriptor{}
	}
	x := p.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	return cloneDescriptor(x.descriptor)
}
func (p *DevicePlan) Close() {
	if p == nil || p.inner == nil {
		return
	}
	x := p.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return
	}
	x.closed = true
	if x.material != nil {
		x.material.clear()
		x.material = nil
	}
	if x.started && !x.settled {
		x.descriptor.State = DeviceUnknown
	}
}

// Protect permits one Store attempt. The short start grant, not a lock around
// the OS call, is the irreversible attempt boundary. Cancellation after it is
// unknown even if the goroutine has not physically entered Store yet.
// It never retries/deletes. Pending acknowledges only local OS protection.
// Closing after a completed acknowledgement cannot undo that OS write.
func (p *DevicePlan) Protect(ctx context.Context, store SystemStore) (DeviceDescriptor, error) {
	if p == nil || p.inner == nil {
		return DeviceDescriptor{}, ErrIdentity
	}
	x := p.inner
	x.mu.Lock()
	if x.closed {
		d := cloneDescriptor(x.descriptor)
		x.mu.Unlock()
		return d, ErrCancelled
	}
	if x.attempted {
		d := cloneDescriptor(x.descriptor)
		x.mu.Unlock()
		return d, ErrConsumed
	}
	x.attempted = true
	m := x.material
	x.material = nil
	x.mu.Unlock()
	defer m.clear()
	if ctx == nil || store == nil {
		p.Close()
		return p.Descriptor(), ErrIdentity
	}
	stop := context.AfterFunc(ctx, p.Close)
	defer stop()
	raw, e := encodeDevice(p.Descriptor(), m)
	if e != nil {
		p.Close()
		return p.Descriptor(), e
	}
	defer clear(raw)
	x.mu.Lock()
	if x.closed || ctx.Err() != nil {
		x.mu.Unlock()
		p.Close()
		return p.Descriptor(), ErrCancelled
	}
	id, e := deviceStoreID(x.descriptor)
	if e != nil {
		x.mu.Unlock()
		p.Close()
		return p.Descriptor(), e
	}
	x.started = true
	x.descriptor.State = DeviceUnknown
	x.mu.Unlock()
	e = store.Store(id, raw)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed || ctx.Err() != nil {
		return cloneDescriptor(x.descriptor), ErrCancelled
	}
	if e != nil {
		return cloneDescriptor(x.descriptor), ErrProtection
	}
	x.settled = true
	x.descriptor.State = DevicePending
	return cloneDescriptor(x.descriptor), nil
}
