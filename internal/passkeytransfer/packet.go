package passkeytransfer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"filippo.io/age"
)

// packetHeader is the canonical signed outer header without the signature.
type packetHeader struct {
	Version           int    `json:"v"`
	ID                string `json:"id"`
	InvitationID      string `json:"invitation_id"`
	InvitationDigest  string `json:"invitation_digest"`
	SourceRecipient   string `json:"source_recipient"`
	SourceAuditPublic string `json:"source_audit_public"`
	TargetFingerprint string `json:"target_fingerprint"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
	Ciphertext        string `json:"ciphertext_base64"`
}

// Packet is the signed v1 transfer packet. It is public ciphertext plus public
// audit identities and pins; it never carries plaintext record material.
type Packet struct {
	Version           int    `json:"v"`
	ID                string `json:"id"`
	InvitationID      string `json:"invitation_id"`
	InvitationDigest  string `json:"invitation_digest"`
	SourceRecipient   string `json:"source_recipient"`
	SourceAuditPublic string `json:"source_audit_public"`
	TargetFingerprint string `json:"target_fingerprint"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
	Ciphertext        string `json:"ciphertext_base64"`
	Signature         string `json:"signature"`
}

func (p *Packet) header() packetHeader {
	return packetHeader{p.Version, p.ID, p.InvitationID, p.InvitationDigest,
		p.SourceRecipient, p.SourceAuditPublic, p.TargetFingerprint,
		p.IssuedAt, p.ExpiresAt, p.Ciphertext}
}

// packetMessage domain-separates and canonicalizes the whole header including
// the ciphertext, so the signature verifies before any decryption attempt.
func packetMessage(h packetHeader) ([]byte, error) {
	body, err := json.Marshal(h)
	if err != nil {
		return nil, ErrRefused
	}
	msg := make([]byte, 0, len(packetDomain)+len(body))
	msg = append(msg, packetDomain...)
	msg = append(msg, body...)
	return msg, nil
}

// SealSelection creates a signed packet for the explicitly selected records.
// It re-verifies the invitation, the mandatory target pin and expiry, and the
// mandatory canonical source identity before encrypting to the invitation
// recipient only.
func SealSelection(rawInvitation []byte, targetPin string, source *age.X25519Recipient, sourceAuditSeed []byte, records []Selection, now time.Time) ([]byte, error) {
	inv, err := VerifyInvitation(rawInvitation, targetPin, now)
	if err != nil {
		return nil, ErrRefused
	}
	sourceRecipient, ok := recipientString(source)
	if !ok {
		return nil, ErrRefused
	}
	key, ok := auditKey(sourceAuditSeed)
	if !ok {
		return nil, ErrRefused
	}
	defer clear(key)
	pub := auditPublic(key)
	id, err := newID()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(rawInvitation)
	h := packetHeader{
		Version:           version,
		ID:                id,
		InvitationID:      inv.ID,
		InvitationDigest:  hex.EncodeToString(digest[:]),
		SourceRecipient:   sourceRecipient,
		SourceAuditPublic: encodeStd(pub),
		TargetFingerprint: targetPin,
		IssuedAt:          now.Unix(),
		ExpiresAt:         inv.ExpiresAt,
	}
	if h.ExpiresAt <= h.IssuedAt {
		return nil, ErrRefused
	}
	plaintext, err := newPayload(h, records)
	if err != nil {
		return nil, ErrRefused
	}
	defer clear(plaintext)
	ciphertext, err := encryptTo(inv.Recipient, plaintext)
	if err != nil {
		return nil, ErrRefused
	}
	h.Ciphertext = encodeStd(ciphertext)
	msg, err := packetMessage(h)
	if err != nil {
		return nil, err
	}
	p := Packet{h.Version, h.ID, h.InvitationID, h.InvitationDigest, h.SourceRecipient,
		h.SourceAuditPublic, h.TargetFingerprint, h.IssuedAt, h.ExpiresAt, h.Ciphertext,
		encodeStd(ed25519.Sign(key, msg))}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) == 0 || len(raw) > maxPacket {
		return nil, ErrRefused
	}
	return raw, nil
}
