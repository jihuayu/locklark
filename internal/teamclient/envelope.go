package teamclient

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"

	"filippo.io/age"
)

const maxDeviceEnvelope = 4096
const envelopeDomain = "locklark/teamclient/device-envelope/v1\x00"

// ageEncoded and signingSeed are owned mutable buffers. The age library also
// creates private objects/strings that Go does not offer a physical wipe API for.
type deviceMaterial struct{ ageEncoded, signingSeed []byte }

func (m *deviceMaterial) clear() {
	if m != nil {
		clear(m.ageEncoded)
		clear(m.signingSeed)
		m.ageEncoded = nil
		m.signingSeed = nil
	}
}
func (deviceMaterial) String() string               { return "[protected team device material]" }
func (deviceMaterial) GoString() string             { return "[protected team device material]" }
func (deviceMaterial) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }

func appendFrame(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}
func encodeDevice(d DeviceDescriptor, m *deviceMaterial) ([]byte, error) {
	if m == nil || len(m.ageEncoded) == 0 || len(m.ageEncoded) > 128 || len(m.signingSeed) != ed25519.SeedSize {
		return nil, ErrIdentity
	}
	b, e := deviceBinding(d)
	if e != nil {
		return nil, ErrIdentity
	}
	raw := appendFrame([]byte(envelopeDomain), b)
	raw = appendFrame(raw, m.ageEncoded)
	raw = appendFrame(raw, m.signingSeed)
	if len(raw) > maxDeviceEnvelope {
		clear(raw)
		return nil, ErrIdentity
	}
	return raw, nil
}
func decodeDevice(d DeviceDescriptor, raw []byte) (material *deviceMaterial, err error) {
	if len(raw) == 0 || len(raw) > maxDeviceEnvelope || !bytes.HasPrefix(raw, []byte(envelopeDomain)) {
		return nil, ErrIdentity
	}
	b := raw[len(envelopeDomain):]
	read := func() ([]byte, bool) {
		if len(b) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint64(n) > uint64(len(b)) {
			return nil, false
		}
		part := b[:n]
		b = b[n:]
		return part, true
	}
	bound, ok := read()
	if !ok {
		return nil, ErrIdentity
	}
	expected, e := deviceBinding(d)
	if e != nil || !bytes.Equal(bound, expected) {
		return nil, ErrIdentity
	}
	a, ok := read()
	if !ok || len(a) == 0 || len(a) > 128 {
		return nil, ErrIdentity
	}
	s, ok := read()
	if !ok || len(s) != ed25519.SeedSize || len(b) != 0 {
		return nil, ErrIdentity
	}
	m := &deviceMaterial{bytes.Clone(a), bytes.Clone(s)}
	defer func() {
		if err != nil {
			m.clear()
		}
	}()
	identity, e := age.ParseX25519Identity(string(m.ageEncoded))
	if e != nil || identity.String() != string(m.ageEncoded) || identity.Recipient().String() != d.Device.Encryption {
		return nil, ErrIdentity
	}
	key := ed25519.NewKeyFromSeed(m.signingSeed)
	defer clear(key)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != d.Device.Signing {
		return nil, ErrIdentity
	}
	return m, nil
}
