package teamclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
)

func TestDeviceIdentitiesAndDescriptorsHaveIndependentOwnedBindings(t *testing.T) {
	pins, _ := fixturePins(t)
	originalOwner := pins.Owners[0]
	p, e := PrepareDevice(pins)
	if e != nil {
		t.Fatal("prepare")
	}
	defer p.Close()
	q, e := PrepareDevice(pins)
	if e != nil {
		t.Fatal("second prepare")
	}
	defer q.Close()
	d, other := p.Descriptor(), q.Descriptor()
	if d.ProfileID == other.ProfileID || d.InstallID == other.InstallID || d.Device == other.Device || d.Device.Encryption == other.Device.Encryption || d.Device.Signing == other.Device.Signing {
		t.Fatal("independent preparation reused identity")
	}
	if d.ProfileID == d.InstallID || d.ProfileID == d.Device.ID || d.InstallID == d.Device.ID {
		t.Fatal("ID roles were aliased")
	}
	pins.Owners[0] = strings.Repeat("0", 64)
	d.Pins.Owners[0] = strings.Repeat("f", 64)
	if p.Descriptor().Pins.Owners[0] != originalOwner {
		t.Fatal("descriptor retained caller-owned pins")
	}
	id, e := deviceStoreID(p.Descriptor())
	if e != nil || !validHex(id, 32) {
		t.Fatal("OS record identifier is not bounded domain-separated hex")
	}
	x := p.Descriptor()
	x.State = DeviceUnknown
	if next, _ := deviceStoreID(x); next != id {
		t.Fatal("workflow state changed immutable identity")
	}
	o, e := NewDeviceOperation(p.Descriptor().Pins, x)
	if e != nil {
		t.Fatal("descriptor operation")
	}
	defer o.Close()
	x.Pins.Owners[0] = strings.Repeat("0", 64)
	returned := o.Descriptor()
	returned.Pins.Owners[0] = strings.Repeat("0", 64)
	if o.Descriptor().Pins.Owners[0] != originalOwner {
		t.Fatal("operation descriptor did not own pins")
	}
}

func TestDeviceDescriptorRejectsInvalidShapesAndIndependentPinMismatch(t *testing.T) {
	pins, d, _, _, _ := protectedFixture(t)
	other, _ := PrepareDevice(pins)
	defer other.Close()
	cases := map[string]func(*DeviceDescriptor){
		"version":           func(x *DeviceDescriptor) { x.Version++ },
		"role":              func(x *DeviceDescriptor) { x.Role = "owner" },
		"scope":             func(x *DeviceDescriptor) { x.Scope = strings.Repeat("0", 64) },
		"profile-short":     func(x *DeviceDescriptor) { x.ProfileID = "ab" },
		"profile-upper":     func(x *DeviceDescriptor) { x.ProfileID = strings.Repeat("A", 32) },
		"install-invalid":   func(x *DeviceDescriptor) { x.InstallID = strings.Repeat("z", 32) },
		"device-id":         func(x *DeviceDescriptor) { x.Device.ID = "" },
		"aliased-id":        func(x *DeviceDescriptor) { x.InstallID = x.ProfileID },
		"active-state":      func(x *DeviceDescriptor) { x.State = "active" },
		"empty-state":       func(x *DeviceDescriptor) { x.State = "" },
		"signing-size":      func(x *DeviceDescriptor) { x.Device.Signing = "ab" },
		"signing-low-order": func(x *DeviceDescriptor) { x.Device.Signing = "01" + strings.Repeat("00", 31) },
		"role-key-reuse":    func(x *DeviceDescriptor) { x.Device.Signing = pins.Publisher },
		"age-invalid":       func(x *DeviceDescriptor) { x.Device.Encryption = "AGE-SECRET-KEY-invalid" },
		"pin-team":          func(x *DeviceDescriptor) { x.Pins.Team = strings.Repeat("a", 32) },
		"pin-vault":         func(x *DeviceDescriptor) { x.Pins.Vault = strings.Repeat("a", 32) },
		"pin-owner":         func(x *DeviceDescriptor) { x.Pins.Owners[0] = other.Descriptor().Device.Signing },
		"pin-sequencer":     func(x *DeviceDescriptor) { x.Pins.Sequencer = other.Descriptor().Device.Signing },
		"pin-publisher":     func(x *DeviceDescriptor) { x.Pins.Publisher = other.Descriptor().Device.Signing },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			x := cloneDescriptor(d)
			mutate(&x)
			if o, e := NewDeviceOperation(pins, x); e != ErrIdentity || o != nil {
				t.Fatal("untrusted descriptor accepted")
			}
		})
	}
	for _, state := range []DeviceState{DevicePreparing, DeviceUnknown, DevicePending} {
		x := cloneDescriptor(d)
		x.State = state
		o, e := NewDeviceOperation(pins, x)
		if e != nil {
			t.Fatal("recoverable public state refused")
		}
		o.Close()
	}
}

func TestDeviceEnvelopeRejectsTamperAndRederivesBothPublicKeys(t *testing.T) {
	pins, d, s, _, _ := protectedFixture(t)
	id, _ := deviceStoreID(d)
	raw := bytes.Clone(s.records[id])
	defer clear(raw)
	m, e := decodeDevice(d, raw)
	if e != nil {
		t.Fatal("valid envelope")
	}
	defer m.clear()
	other, _ := PrepareDevice(pins)
	defer other.Close()
	cases := map[string]func() []byte{
		"header":    func() []byte { b := bytes.Clone(raw); b[0] ^= 1; return b },
		"trailing":  func() []byte { return append(bytes.Clone(raw), 0) },
		"oversized": func() []byte { return make([]byte, maxDeviceEnvelope+1) },
		"truncated": func() []byte { return bytes.Clone(raw[:len(raw)-1]) },
		"frame-overflow": func() []byte {
			b := bytes.Clone(raw)
			binary.BigEndian.PutUint32(b[len(envelopeDomain):], ^uint32(0))
			return b
		},
		"wrong-seed": func() []byte { b := bytes.Clone(raw); b[len(b)-1] ^= 1; return b },
		"wrong-age-private": func() []byte {
			x := &deviceMaterial{ageEncoded: bytes.Clone(other.inner.material.ageEncoded), signingSeed: bytes.Clone(m.signingSeed)}
			defer x.clear()
			b, _ := encodeDevice(d, x)
			return b
		},
		"wrong-signing-private": func() []byte {
			x := &deviceMaterial{ageEncoded: bytes.Clone(m.ageEncoded), signingSeed: bytes.Clone(other.inner.material.signingSeed)}
			defer x.clear()
			b, _ := encodeDevice(d, x)
			return b
		},
		"unknown-binding-field": func() []byte {
			binding, _ := deviceBinding(d)
			binding = append(binding[:len(binding)-1], []byte(",\"unexpected\":true}")...)
			b := appendFrame([]byte(envelopeDomain), binding)
			b = appendFrame(b, m.ageEncoded)
			return appendFrame(b, m.signingSeed)
		},
		"duplicate-binding-key": func() []byte {
			binding, _ := deviceBinding(d)
			binding = append(binding[:len(binding)-1], []byte(",\"Version\":1}")...)
			b := appendFrame([]byte(envelopeDomain), binding)
			b = appendFrame(b, m.ageEncoded)
			return appendFrame(b, m.signingSeed)
		},
	}
	for name, makeRaw := range cases {
		t.Run(name, func(t *testing.T) {
			b := makeRaw()
			defer clear(b)
			o, _ := NewDeviceOperation(pins, d)
			defer o.Close()
			if e := o.Load(context.Background(), functionalStore{load: func(string) ([]byte, error) { return b, nil }}); e != ErrIdentity || !zeroBytes(b) {
				t.Fatal("invalid protected envelope accepted or not cleared")
			}
		})
	}
	for _, name := range []string{"profile", "install", "scope", "device", "pins"} {
		t.Run("binding-"+name, func(t *testing.T) {
			x := cloneDescriptor(d)
			switch name {
			case "profile":
				x.ProfileID = other.Descriptor().ProfileID
			case "install":
				x.InstallID = other.Descriptor().InstallID
			case "scope":
				x.Scope = strings.Repeat("f", 64)
			case "device":
				x.Device = other.Descriptor().Device
			case "pins":
				x.Pins.Team = strings.Repeat("a", 32)
			}
			if material, e := decodeDevice(x, raw); e != ErrIdentity || material != nil {
				t.Fatal("envelope detached from immutable public bindings")
			}
		})
	}
	if len(m.signingSeed) != ed25519.SeedSize {
		t.Fatal("valid secret ownership altered by refused decodes")
	}
}

func TestDeviceCancelledContextInvalidatesLoadedChallenge(t *testing.T) {
	pins, d, s, expected, ch := protectedFixture(t)
	o, e := NewDeviceOperation(pins, d)
	if e != nil {
		t.Fatal("operation")
	}
	defer o.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if o.Load(ctx, s) != nil {
		t.Fatal("load")
	}
	cancel()
	if a, e := o.AnswerChallenge(expected, ch); e == nil || !reflect.DeepEqual(a, directory.Admission{}) {
		t.Fatal("cancelled operation returned public admission")
	}
}

func TestDeviceSuccessfulProtectionCloseDoesNotPretendRollback(t *testing.T) {
	pins, _ := fixturePins(t)
	p, _ := PrepareDevice(pins)
	s := newMemoryStore()
	d, e := p.Protect(context.Background(), s)
	p.Close()
	if e != nil || d.State != DevicePending || !reflect.DeepEqual(p.Descriptor(), d) || s.writes != 1 || s.deletes != 0 {
		t.Fatal("Close rewrote acknowledged protection result")
	}
	encoded, e := json.Marshal(d)
	if e != nil || bytes.Contains(encoded, []byte("AGE-SECRET-KEY")) {
		t.Fatal("public descriptor was not public")
	}
}
