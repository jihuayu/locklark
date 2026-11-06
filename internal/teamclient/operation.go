package teamclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"sync"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
)

type DeviceOperation struct{ inner *deviceOperation }
type deviceOperation struct {
	mu                          sync.Mutex
	descriptor                  DeviceDescriptor
	config                      *directory.Config
	material                    *deviceMaterial
	ctx                         context.Context
	stop                        func() bool
	loadAttempted, used, closed bool
}

func (DeviceOperation) String() string               { return "[team device operation]" }
func (DeviceOperation) GoString() string             { return "[team device operation]" }
func (DeviceOperation) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }
func NewDeviceOperation(trusted directory.Pins, expected DeviceDescriptor) (*DeviceOperation, error) {
	d, c, e := validateDescriptor(trusted, expected)
	if e != nil {
		return nil, e
	}
	return &DeviceOperation{&deviceOperation{descriptor: d, config: c}}, nil
}
func (o *DeviceOperation) Descriptor() DeviceDescriptor {
	if o == nil || o.inner == nil {
		return DeviceDescriptor{}
	}
	x := o.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	return cloneDescriptor(x.descriptor)
}
func (x *deviceOperation) closeLocked() func() bool {
	if x.closed {
		return nil
	}
	x.closed = true
	if x.material != nil {
		x.material.clear()
		x.material = nil
	}
	stop := x.stop
	x.stop = nil
	x.ctx = nil
	return stop
}

// Close immediately invalidates output without waiting for an OS method. A
// worker owns in-flight private buffers and clears them when the OS returns.
func (o *DeviceOperation) Close() {
	if o == nil || o.inner == nil {
		return
	}
	x := o.inner
	x.mu.Lock()
	stop := x.closeLocked()
	x.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// Load is one explicit OS authentication attempt. OS buffers are consumed and
// cleared, and a late result cannot install private keys into a closed handle.
func (o *DeviceOperation) Load(ctx context.Context, store SystemStore) (err error) {
	if o == nil || o.inner == nil {
		return ErrIdentity
	}
	x := o.inner
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return ErrCancelled
	}
	if x.loadAttempted {
		x.mu.Unlock()
		return ErrConsumed
	}
	x.loadAttempted = true
	x.mu.Unlock()
	success := false
	defer func() {
		if !success {
			o.Close()
		}
	}()
	if ctx == nil || store == nil {
		return ErrIdentity
	}
	stop := context.AfterFunc(ctx, o.Close)
	x.mu.Lock()
	if x.closed || ctx.Err() != nil {
		x.mu.Unlock()
		stop()
		return ErrCancelled
	}
	x.stop = stop
	x.ctx = ctx
	d := cloneDescriptor(x.descriptor)
	id, e := deviceStoreID(d)
	x.mu.Unlock()
	if e != nil {
		return e
	}
	raw, e := store.Load(id)
	defer clear(raw)
	if e != nil {
		return ErrProtection
	}
	m, e := decodeDevice(d, raw)
	if e != nil {
		return e
	}
	defer func() { m.clear() }()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed || ctx.Err() != nil {
		return ErrCancelled
	}
	x.material = m
	m = nil
	x.descriptor.State = DevicePending
	success = true
	return nil
}

func clearAdmission(a *directory.Admission) {
	clear(a.Nonce)
	clear(a.Signature)
	clear(a.Challenge.Ciphertext)
	clear(a.Challenge.Signature)
	*a = directory.Admission{}
}

// AnswerChallenge consumes its handle on the first attempt, including refusal.
// expected must be independently reviewed, never blindly copied from ch.
// Its parent must come from trusted bootstrap or an independently anchored owner;
// this local proof is not membership, role, current-head or network authorization.
func (o *DeviceOperation) AnswerChallenge(expected directory.Enrollment, ch directory.Challenge) (directory.Admission, error) {
	return o.answerChallengeWith(expected, ch, nil)
}
func (o *DeviceOperation) answerChallengeWith(expected directory.Enrollment, ch directory.Challenge, beforeGrant func()) (directory.Admission, error) {
	if o == nil || o.inner == nil {
		return directory.Admission{}, ErrIdentity
	}
	x := o.inner
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return directory.Admission{}, ErrCancelled
	}
	if x.used {
		x.mu.Unlock()
		return directory.Admission{}, ErrConsumed
	}
	x.used = true
	m := x.material
	x.material = nil
	ctx := x.ctx
	d := x.descriptor
	x.mu.Unlock()
	defer o.Close()
	defer m.clear()
	if m == nil || ctx == nil || ctx.Err() != nil || expected.Device != d.Device || !x.config.ValidCheckpoint(expected.Parent) || !validHex(expected.Member, 16) || len(ch.Ciphertext) == 0 || len(ch.Ciphertext) > 1024 || len(ch.Signature) != ed25519.SignatureSize || !validHex(ch.Owner, ed25519.PublicKeySize) || !validHex(ch.NonceDigest, 32) {
		return directory.Admission{}, ErrAdmission
	}
	ch.Ciphertext = bytes.Clone(ch.Ciphertext)
	ch.Signature = bytes.Clone(ch.Signature)
	defer clear(ch.Ciphertext)
	defer clear(ch.Signature)
	identity, e := age.ParseX25519Identity(string(m.ageEncoded))
	if e != nil {
		return directory.Admission{}, ErrAdmission
	}
	key := ed25519.NewKeyFromSeed(m.signingSeed)
	defer clear(key)
	a, e := directory.AnswerChallenge(x.config, expected, ch, identity, key)
	if e != nil {
		return directory.Admission{}, ErrAdmission
	}
	if beforeGrant != nil {
		beforeGrant()
	}
	x.mu.Lock()
	if x.closed || ctx.Err() != nil {
		x.mu.Unlock()
		clearAdmission(&a)
		return directory.Admission{}, ErrCancelled
	}
	stop := x.closeLocked()
	x.mu.Unlock()
	if stop != nil {
		stop()
	}
	return a, nil
}
