package teamclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"filippo.io/age"
	"filippo.io/edwards25519"
	"github.com/jihuayu/locklark/internal/directory"
)

const deviceVersion = 1
const deviceRole = "device"
const storeDomain = "locklark/teamclient/system-store/device/v1\x00"

func clonePins(p directory.Pins) directory.Pins           { p.Owners = slices.Clone(p.Owners); return p }
func cloneDescriptor(d DeviceDescriptor) DeviceDescriptor { d.Pins = clonePins(d.Pins); return d }
func normalizedPins(p directory.Pins) (directory.Pins, *directory.Config, error) {
	p = clonePins(p)
	c, e := directory.NewConfigWithWriterACL(p)
	if e != nil || !c.WriterACLPolicy() {
		return directory.Pins{}, nil, ErrIdentity
	}
	slices.Sort(p.Owners)
	return p, c, nil
}
func samePins(a, b directory.Pins) bool {
	return a.Team == b.Team && a.Vault == b.Vault && a.Sequencer == b.Sequencer && a.Publisher == b.Publisher && slices.Equal(a.Owners, b.Owners)
}
func validHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}
func validDeviceSigning(s string) bool {
	if !validHex(s, ed25519.PublicKeySize) {
		return false
	}
	b, _ := hex.DecodeString(s)
	p, e := new(edwards25519.Point).SetBytes(b)
	return e == nil && bytes.Equal(p.Bytes(), b) && new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1
}
func validateDescriptor(trusted directory.Pins, d DeviceDescriptor) (DeviceDescriptor, *directory.Config, error) {
	p, c, e := normalizedPins(trusted)
	if e != nil {
		return DeviceDescriptor{}, nil, e
	}
	stored, _, e := normalizedPins(d.Pins)
	if e != nil || !samePins(p, stored) || d.Version != deviceVersion || d.Role != deviceRole || d.Scope != c.Genesis().Scope || !validHex(d.ProfileID, 16) || !validHex(d.InstallID, 16) || !validHex(d.Device.ID, 16) || d.ProfileID == d.InstallID || d.ProfileID == d.Device.ID || d.InstallID == d.Device.ID {
		return DeviceDescriptor{}, nil, ErrIdentity
	}
	if d.State != DevicePreparing && d.State != DevicePending && d.State != DeviceUnknown {
		return DeviceDescriptor{}, nil, ErrIdentity
	}
	if len(d.Device.Encryption) > 128 || !validDeviceSigning(d.Device.Signing) {
		return DeviceDescriptor{}, nil, ErrIdentity
	}
	r, e := age.ParseX25519Recipient(d.Device.Encryption)
	if e != nil || r.String() != d.Device.Encryption || d.Device.Signing == p.Sequencer || d.Device.Signing == p.Publisher || slices.Contains(p.Owners, d.Device.Signing) {
		return DeviceDescriptor{}, nil, ErrIdentity
	}
	d.Pins = p
	return d, c, nil
}

// Only immutable, public bindings enter the record ID and secret envelope.
// Workflow state can change after a write without changing identity or scope.
func deviceBinding(d DeviceDescriptor) ([]byte, error) {
	return json.Marshal(struct {
		Version                           int
		Role, ProfileID, InstallID, Scope string
		Pins                              directory.Pins
		Device                            directory.Device
	}{d.Version, d.Role, d.ProfileID, d.InstallID, d.Scope, d.Pins, d.Device})
}
func deviceStoreID(d DeviceDescriptor) (string, error) {
	b, e := deviceBinding(d)
	if e != nil {
		return "", ErrIdentity
	}
	h := sha256.New()
	h.Write([]byte(storeDomain))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func newID(used map[string]bool) (string, error) {
	var b [16]byte
	for range 8 {
		if _, e := rand.Read(b[:]); e != nil {
			return "", ErrIdentity
		}
		id := hex.EncodeToString(b[:])
		if !used[id] {
			used[id] = true
			return id, nil
		}
	}
	return "", ErrIdentity
}
