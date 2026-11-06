package teamclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
)

type functionalStore struct {
	store func(string, []byte) error
	load  func(string) ([]byte, error)
}

func (s functionalStore) Store(id string, b []byte) error { return s.store(id, b) }
func (s functionalStore) Load(id string) ([]byte, error)  { return s.load(id) }
func (functionalStore) Delete(string) error               { panic("unexpected identity deletion") }

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("bounded operation timed out")
	}
	var zero T
	return zero
}
func zeroBytes(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

func protectedFixture(t *testing.T) (directory.Pins, DeviceDescriptor, *memoryStore, directory.Enrollment, directory.Challenge) {
	t.Helper()
	pins, owner := fixturePins(t)
	p, e := PrepareDevice(pins)
	if e != nil {
		t.Fatal("prepare fixture")
	}
	t.Cleanup(p.Close)
	s := newMemoryStore()
	d, e := p.Protect(context.Background(), s)
	if e != nil {
		t.Fatal("protect fixture")
	}
	c, _ := directory.NewConfigWithWriterACL(pins)
	expected := directory.Enrollment{Parent: c.Genesis(), Member: "33333333333333333333333333333333", Device: d.Device}
	ch, e := directory.IssueChallenge(c, owner, expected)
	if e != nil {
		t.Fatal("challenge fixture")
	}
	return pins, d, s, expected, ch
}
func loadedFixture(t *testing.T, pins directory.Pins, d DeviceDescriptor, s SystemStore) *DeviceOperation {
	t.Helper()
	o, e := NewDeviceOperation(pins, d)
	if e != nil || o.Load(context.Background(), s) != nil {
		t.Fatal("load fixture")
	}
	t.Cleanup(o.Close)
	return o
}

func TestDeviceProtectionUnknownIsRecoverableWithoutRewrite(t *testing.T) {
	pins, _ := fixturePins(t)
	p, e := PrepareDevice(pins)
	if e != nil {
		t.Fatal("prepare")
	}
	defer p.Close()
	original := p.Descriptor()
	s := newMemoryStore()
	s.storeErr = errors.New("private backend error must not escape")
	d, e := p.Protect(context.Background(), s)
	if e != ErrProtection || d.State != DeviceUnknown {
		t.Fatal("failed Store must be unknown")
	}
	want := original
	want.State = DeviceUnknown
	if !reflect.DeepEqual(d, want) {
		t.Fatal("unknown lost original public identity")
	}
	if _, e = p.Protect(context.Background(), s); e != ErrConsumed || s.writes != 1 || s.deletes != 0 {
		t.Fatal("uncertain Store was retried or deleted")
	}
	// An error may follow a completed OS write. Only an explicit fresh Load may
	// recover this exact descriptor; no new identity is generated here.
	o := loadedFixture(t, pins, d, s)
	if o.Descriptor().State != DevicePending || o.Descriptor().Device != original.Device {
		t.Fatal("explicit recovery did not retain identity")
	}
}

func TestDeviceProtectionCancellationArbitration(t *testing.T) {
	for _, mode := range []string{"cancel-before", "close-before", "cancel-in-store", "close-in-store"} {
		t.Run(mode, func(t *testing.T) {
			pins, _ := fixturePins(t)
			p, _ := PrepareDevice(pins)
			defer p.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			var writes atomic.Int32
			var borrowed []byte
			store := functionalStore{store: func(_ string, b []byte) error {
				writes.Add(1)
				borrowed = b
				close(entered)
				<-release
				if zeroBytes(b) {
					return errors.New("buffer cleared during OS ownership")
				}
				return nil
			}}
			if mode == "cancel-before" {
				cancel()
			}
			if mode == "close-before" {
				p.Close()
			}
			type result struct {
				d DeviceDescriptor
				e error
			}
			done := make(chan result, 1)
			go func() { d, e := p.Protect(ctx, store); done <- result{d, e} }()
			if strings.HasSuffix(mode, "-before") {
				r := await(t, done)
				if r.e != ErrCancelled || r.d.State != DevicePreparing || writes.Load() != 0 {
					t.Fatal("pre-start cancellation touched OS")
				}
				return
			}
			await(t, entered)
			closed := make(chan struct{})
			go func() {
				if mode == "cancel-in-store" {
					cancel()
				} else {
					p.Close()
				}
				close(closed)
			}()
			await(t, closed)
			// Close is synchronous and never waits for the blocked backend.
			p.Close()
			if p.Descriptor().State != DeviceUnknown {
				t.Fatal("in-flight Store cancellation lost unknown")
			}
			close(release)
			r := await(t, done)
			if r.e != ErrCancelled || r.d.State != DeviceUnknown || writes.Load() != 1 || !zeroBytes(borrowed) {
				t.Fatal("late Store result revived plan or retained worker buffer")
			}
		})
	}
}

func TestDeviceLoadCancellationAndErrorClearOwnedBuffers(t *testing.T) {
	pins, d, s, _, _ := protectedFixture(t)
	id, _ := deviceStoreID(d)
	for _, mode := range []string{"close", "cancel", "backend-error", "binding-error"} {
		t.Run(mode, func(t *testing.T) {
			o, e := NewDeviceOperation(pins, d)
			if e != nil {
				t.Fatal("operation")
			}
			defer o.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			borrowed := bytes.Clone(s.records[id])
			if mode == "binding-error" {
				borrowed[len(borrowed)-1] ^= 1
			}
			backend := functionalStore{load: func(string) ([]byte, error) {
				close(entered)
				<-release
				if mode == "backend-error" {
					return borrowed, errors.New("private backend error")
				}
				return borrowed, nil
			}}
			done := make(chan error, 1)
			go func() { done <- o.Load(ctx, backend) }()
			await(t, entered)
			if mode == "close" {
				o.Close()
			}
			if mode == "cancel" {
				cancel()
				o.Close()
			}
			close(release)
			e = await(t, done)
			want := ErrCancelled
			if mode == "backend-error" {
				want = ErrProtection
			}
			if mode == "binding-error" {
				want = ErrIdentity
			}
			if e != want || !zeroBytes(borrowed) {
				t.Fatal("Load failure retained OS buffer or returned backend details")
			}
			o.inner.mu.Lock()
			if !o.inner.closed || o.inner.material != nil {
				t.Fatal("late Load installed identity")
			}
			o.inner.mu.Unlock()
		})
	}
}

func TestDeviceLoadPreCancellationNeverCallsOS(t *testing.T) {
	pins, d, _, _, _ := protectedFixture(t)
	for _, mode := range []string{"cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			o, _ := NewDeviceOperation(pins, d)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			} else {
				o.Close()
			}
			var calls atomic.Int32
			e := o.Load(ctx, functionalStore{load: func(string) ([]byte, error) { calls.Add(1); return nil, nil }})
			if e != ErrCancelled || calls.Load() != 0 {
				t.Fatal("revoked Load reached OS")
			}
		})
	}
}

func TestDeviceChallengeCloseWinsBeforeOutputAndAttemptIsSingleUse(t *testing.T) {
	pins, d, s, expected, ch := protectedFixture(t)
	o := loadedFixture(t, pins, d, s)
	copyHandle := *o
	entered, release := make(chan struct{}), make(chan struct{})
	type result struct {
		a directory.Admission
		e error
	}
	done := make(chan result, 1)
	go func() {
		a, e := o.answerChallengeWith(expected, ch, func() { close(entered); <-release })
		done <- result{a, e}
	}()
	await(t, entered)
	if a, e := copyHandle.AnswerChallenge(expected, ch); e == nil || !reflect.DeepEqual(a, directory.Admission{}) {
		t.Fatal("copied handle admitted concurrent attempt")
	}
	copyHandle.Close()
	close(release)
	r := await(t, done)
	if r.e != ErrCancelled || !reflect.DeepEqual(r.a, directory.Admission{}) {
		t.Fatal("Close lost output arbitration")
	}
	// Once an output grant wins, Close cannot retract the public admission.
	o = loadedFixture(t, pins, d, s)
	a, e := o.AnswerChallenge(expected, ch)
	o.Close()
	c, _ := directory.NewConfigWithWriterACL(pins)
	if e != nil || directory.VerifyAdmission(c, expected, a) != nil {
		t.Fatal("granted public proof changed after Close")
	}
}

func TestDeviceChallengeRejectsIndependentExpectedMismatchAndConsumes(t *testing.T) {
	pins, d, s, expected, ch := protectedFixture(t)
	for _, name := range []string{"scope", "parent", "member", "device-id", "encryption", "signer", "ciphertext", "owner-signature", "oversized-ciphertext", "missing-ciphertext", "signature-shape", "owner-shape", "digest-shape"} {
		t.Run(name, func(t *testing.T) {
			o := loadedFixture(t, pins, d, s)
			x, y := expected, ch
			y.Ciphertext = bytes.Clone(ch.Ciphertext)
			y.Signature = bytes.Clone(ch.Signature)
			switch name {
			case "scope":
				x.Parent.Scope = strings.Repeat("0", 64)
			case "parent":
				x.Parent.Version = 1
				x.Parent.Hash = strings.Repeat("a", 64)
			case "member":
				x.Member = strings.Repeat("b", 32)
			case "device-id":
				x.Device.ID = strings.Repeat("c", 32)
			case "encryption":
				other, _ := PrepareDevice(pins)
				defer other.Close()
				x.Device.Encryption = other.Descriptor().Device.Encryption
			case "signer":
				x.Device.Signing = pins.Sequencer
			case "ciphertext":
				y.Ciphertext[len(y.Ciphertext)-1] ^= 1
			case "owner-signature":
				y.Signature[0] ^= 1
			case "oversized-ciphertext":
				y.Ciphertext = make([]byte, 1025)
			case "missing-ciphertext":
				y.Ciphertext = nil
			case "signature-shape":
				y.Signature = append(y.Signature, 0)
			case "owner-shape":
				y.Owner = strings.Repeat("A", 64)
			case "digest-shape":
				y.NonceDigest = strings.Repeat("z", 64)
			}
			if a, e := o.AnswerChallenge(x, y); e != ErrAdmission || !reflect.DeepEqual(a, directory.Admission{}) {
				t.Fatal("mismatched independent enrollment accepted")
			}
			if a, e := o.AnswerChallenge(expected, ch); e == nil || !reflect.DeepEqual(a, directory.Admission{}) {
				t.Fatal("refused attempt could be replayed")
			}
		})
	}
}

func TestDeviceHandlesAreRedactedAndCloseClearsKeys(t *testing.T) {
	pins, d, s, _, _ := protectedFixture(t)
	p, _ := PrepareDevice(pins)
	defer p.Close()
	o := loadedFixture(t, pins, d, s)
	m := o.inner.material
	ageBuffer, signBuffer := m.ageEncoded, m.signingSeed
	for _, v := range []any{p, *p, o, *o, m, *m} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, v)
			if text != "[team device preparation]" && text != "[team device operation]" && text != "[protected team device material]" {
				t.Fatal("private handle formatting was not fixed redaction")
			}
		}
		if _, e := json.Marshal(v); e == nil {
			t.Fatal("private handle JSON was allowed")
		}
	}
	o.Close()
	if !zeroBytes(ageBuffer) || !zeroBytes(signBuffer) {
		t.Fatal("Close retained operation-owned key buffer")
	}
}

func TestDeviceConcurrentAnswerHasOnePublicGrant(t *testing.T) {
	pins, d, s, expected, ch := protectedFixture(t)
	o := loadedFixture(t, pins, d, s)
	var wg sync.WaitGroup
	var wins atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := o.AnswerChallenge(expected, ch)
			if e == nil {
				c, _ := directory.NewConfigWithWriterACL(pins)
				if directory.VerifyAdmission(c, expected, a) == nil {
					wins.Add(1)
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	await(t, done)
	if wins.Load() != 1 {
		t.Fatal("concurrent challenge did not have one public grant")
	}
}
