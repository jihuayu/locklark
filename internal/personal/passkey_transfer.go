package personal

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkeytransfer"
)

const (
	passkeyTransferInviteAction  = "vault.passkey.transfer.invite"
	passkeyTransferRevokeAction  = "vault.passkey.transfer.revoke"
	passkeyTransferConsumeAction = "vault.passkey.transfer.consume"

	passkeyTransferInviteLinkDomain = "locklark/personal/passkey-transfer/invite/v1\x00"
	maxPasskeyTransferInvitation    = 16 << 10
)

func passkeyTransferAction(action string) bool {
	switch action {
	case passkeyTransferInviteAction, passkeyTransferRevokeAction, passkeyTransferConsumeAction:
		return true
	}
	return false
}

// publicTransferIdentity is the explicit public output of the receiver's own
// unlocked device identity. It deliberately contains no private key, seed or
// user handle.
type publicTransferIdentity struct {
	Recipient   string `json:"recipient"`
	AuditPublic string `json:"audit_public"`
	Fingerprint string `json:"fingerprint"`
}

func (p publicTransferIdentity) String() string { return p.Fingerprint }
func (p publicTransferIdentity) GoString() string {
	return "[public transfer identity " + p.Fingerprint + "]"
}

// transferPublicIdentity derives the receiver's public invitation identity from
// the authenticated vault identity. The audit identity is the existing Ed25519
// audit seed, not the snapshot signing seed.
func transferPublicIdentity(i identity) (publicTransferIdentity, error) {
	var out publicTransferIdentity
	device, err := age.ParseX25519Identity(i.Device)
	if err != nil {
		return out, invalid
	}
	recipient := device.Recipient().String()
	if _, err = age.ParseX25519Recipient(recipient); err != nil {
		return out, invalid
	}
	auditPriv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(auditPriv)
	auditPublic := auditPriv.Public().(ed25519.PublicKey)
	fingerprint, err := passkeytransfer.PublicFingerprint(recipient, auditPublic)
	if err != nil {
		return out, invalid
	}
	out = publicTransferIdentity{
		Recipient:   recipient,
		AuditPublic: base64.StdEncoding.EncodeToString(auditPublic),
		Fingerprint: fingerprint,
	}
	return out, nil
}

// passkeyTransferInviteLink is the keyed link stored in both the creation and
// revocation audit rows. It binds the exact canonical signed invitation bytes
// with a domain separator and an eight-byte length frame.
func passkeyTransferInviteLink(key []byte, inv *passkeytransfer.Invitation) (string, error) {
	if len(key) == 0 || inv == nil {
		return "", invalid
	}
	canonical, err := json.Marshal(inv)
	if err != nil || len(canonical) == 0 || len(canonical) > maxPasskeyTransferInvitation {
		return "", invalid
	}
	defer clear(canonical)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(passkeyTransferInviteLinkDomain))
	var frame [8]byte
	binary.BigEndian.PutUint64(frame[:], uint64(len(canonical)))
	mac.Write(frame[:])
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

type passkeyTransferState struct {
	creation string
	link     string
	revoked  bool
	consumed bool
}

// scanPasskeyTransferRows validates invitation creation/revocation/consumption
// ordering only against the complete authenticated current audit chain. It
// never creates item revisions and never consults a mutable side bucket.
func scanPasskeyTransferRows(rows []Event, targetID, expectedLink string) (string, error) {
	state := make(map[string]*passkeyTransferState)
	for _, ev := range rows {
		if !passkeyTransferAction(ev.Action) {
			continue
		}
		switch ev.Action {
		case passkeyTransferInviteAction:
			if state[ev.Item] != nil {
				return "", invalid
			}
			state[ev.Item] = &passkeyTransferState{creation: ev.hash(), link: ev.Link}
		case passkeyTransferRevokeAction, passkeyTransferConsumeAction:
			current := state[ev.Item]
			if current == nil || ev.BaseRevision != current.creation || ev.Link != current.link {
				return "", invalid
			}
			if ev.Action == passkeyTransferRevokeAction {
				if current.revoked || current.consumed {
					return "", invalid
				}
				current.revoked = true
			} else {
				if current.revoked || current.consumed {
					return "", invalid
				}
				current.consumed = true
			}
		}
	}
	current := state[targetID]
	if current == nil || expectedLink != "" && current.link != expectedLink || current.revoked || current.consumed {
		return "", invalid
	}
	return current.creation, nil
}

// PasskeyTransferInvitation is the public invitation output. Raw is the signed
// canonical invitation and Public is the receiver's explicit public identity.
type PasskeyTransferInvitation struct {
	Raw       []byte
	Public    publicTransferIdentity
	ExpiresAt time.Time
	ID        string
}

func (PasskeyTransferInvitation) String() string   { return "[passkey transfer invitation]" }
func (PasskeyTransferInvitation) GoString() string { return "[passkey transfer invitation]" }
