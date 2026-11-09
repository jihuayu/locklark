package passkeytransfer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"filippo.io/age"
)

// Invitation is the signed, short-lived v1 invitation created by the receiving
// device. It is public material: it carries no user handle or private key.
type Invitation struct {
	Version     int    `json:"v"`
	ID          string `json:"id"`
	Recipient   string `json:"recipient"`
	AuditPublic string `json:"audit_public"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	Signature   string `json:"signature"`
}

// signedInvitation is the canonical invitation with the signature omitted; the
// Ed25519 signature covers exactly these fields under invitationDomain.
type signedInvitation struct {
	Version     int    `json:"v"`
	ID          string `json:"id"`
	Recipient   string `json:"recipient"`
	AuditPublic string `json:"audit_public"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
}

func (i *Invitation) signed() signedInvitation {
	return signedInvitation{i.Version, i.ID, i.Recipient, i.AuditPublic, i.IssuedAt, i.ExpiresAt}
}

// signingMessage is the domain-separated canonical byte string that is signed.
func invitationMessage(i *Invitation) ([]byte, error) {
	body, err := json.Marshal(i.signed())
	if err != nil {
		return nil, ErrRefused
	}
	msg := make([]byte, 0, len(invitationDomain)+len(body))
	msg = append(msg, invitationDomain...)
	msg = append(msg, body...)
	return msg, nil
}

// Fingerprint returns the public target fingerprint of this invitation, or ""
// when the invitation fields are not canonical. Callers compare it out of band.
func (i *Invitation) Fingerprint() string {
	if i == nil {
		return ""
	}
	pub, ok := decodeStd(i.AuditPublic, ed25519.PublicKeySize)
	if !ok || !validPin(fingerprint(i.Recipient, pub)) {
		return ""
	}
	return fingerprint(i.Recipient, pub)
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrRefused
	}
	return hex.EncodeToString(raw[:]), nil
}

func encodeStd(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// CreateInvite signs a new v1 invitation using the receiver's existing age
// public recipient and existing Ed25519 audit seed. It does not create or load
// any user identity, and refuses TTLs above 15 minutes.
func CreateInvite(own *age.X25519Recipient, auditSeed []byte, now time.Time, ttl time.Duration) ([]byte, *Invitation, error) {
	recipient, ok := recipientString(own)
	if !ok || ttl <= 0 || ttl > maxInvitationTTL {
		return nil, nil, ErrRefused
	}
	key, ok := auditKey(auditSeed)
	if !ok {
		return nil, nil, ErrRefused
	}
	defer clear(key)
	id, err := newID()
	if err != nil {
		return nil, nil, err
	}
	issued := now.Unix()
	expires := issued + int64(ttl/time.Second)
	if ttl < time.Second || expires <= issued || expires-issued > int64(maxInvitationTTL/time.Second) {
		return nil, nil, ErrRefused
	}
	inv := &Invitation{
		Version:     version,
		ID:          id,
		Recipient:   recipient,
		AuditPublic: encodeStd(auditPublic(key)),
		IssuedAt:    issued,
		ExpiresAt:   expires,
	}
	msg, err := invitationMessage(inv)
	if err != nil {
		return nil, nil, err
	}
	inv.Signature = encodeStd(ed25519.Sign(key, msg))
	raw, err := json.Marshal(inv)
	if err != nil || len(raw) > maxInvitation {
		return nil, nil, ErrRefused
	}
	return raw, inv, nil
}
