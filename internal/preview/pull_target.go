package preview

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/gateway"
)

// Only the fixture writer, which already owns this plaintext and the authority
// signing key, issues this descriptor. Keep it encrypted to the approval inbox;
// do not publish an archive digest (or slot metadata) alongside server ciphertext.
type pullTarget struct {
	Epoch                        uint64
	Slot, Audience, Pin, Archive string
	Sig                          []byte
}

func (c pullTarget) proof() []byte { c.Sig = nil; return message("locklark/fixture-slot/v1\x00", c) }
func issuePullTarget(device, bundle string, archive []byte, key ed25519.PrivateKey) error {
	id, err := mailIdentity(device)
	if err != nil {
		return err
	}
	encrypted, err := readEncrypted(bundle, device, 3)
	if err != nil {
		return err
	}
	slot, err := fixturePasswordField(archive)
	if err != nil {
		return err
	}
	clear(slot)
	digest := sha256.Sum256(archive)
	c := pullTarget{Epoch: 3, Slot: gateway.PullSlot, Audience: id.Recipient().String(), Pin: encrypted.pin(), Archive: hex.EncodeToString(digest[:])}
	c.Sig = ed25519.Sign(key, c.proof())
	data, err := sealJSON(id.Recipient(), c)
	if err != nil {
		return err
	}
	return write(device, "pull-target.age", data)
}
func verifyPullTarget(device, bundle string, q Request, id *age.X25519Identity) (pullTarget, error) {
	var cert pullTarget
	snapshot, err := readEncrypted(bundle, device, q.Epoch)
	if err != nil {
		return cert, errChanged
	}
	raw, err := read(device, "pull-target.age", 4096)
	if err != nil {
		return cert, errChanged
	}
	if unsealJSON(id, raw, 2048, &cert) != nil || cert.Audience != id.Recipient().String() || cert.Slot != q.Ref || cert.Epoch != q.Epoch || cert.Pin != snapshot.pin() || !hexSize(cert.Archive, 32) || !ed25519.Verify(snapshot.authority, cert.proof(), cert.Sig) {
		return pullTarget{}, errChanged
	}
	return cert, nil
}
