package passkeytransfer

import (
	"crypto/ed25519"
	"time"
)

// VerifyInvitation checks the invitation's own signature, canonical encoding,
// version and expiry, and requires the caller's explicit nonempty 64-hex
// expectedTargetFingerprint pin. The self-signature proves integrity only; the
// pin is what establishes which peer the user actually verified.
func VerifyInvitation(raw []byte, expectedTargetFingerprint string, now time.Time) (*Invitation, error) {
	if !validPin(expectedTargetFingerprint) {
		return nil, ErrRefused
	}
	var inv Invitation
	if decodeCanonical(raw, maxInvitation, &inv) != nil {
		return nil, ErrRefused
	}
	if inv.Version != version || !decodeHex32(inv.ID) {
		return nil, ErrRefused
	}
	if _, ok := parseRecipient(inv.Recipient); !ok {
		return nil, ErrRefused
	}
	pub, ok := decodeStd(inv.AuditPublic, ed25519.PublicKeySize)
	if !ok {
		return nil, ErrRefused
	}
	sig, ok := decodeStd(inv.Signature, ed25519.SignatureSize)
	if !ok {
		return nil, ErrRefused
	}
	stamp := now.Unix()
	ttl := inv.ExpiresAt - inv.IssuedAt
	if inv.IssuedAt > stamp || inv.ExpiresAt <= stamp || ttl <= 0 || ttl > int64(maxInvitationTTL/time.Second) {
		return nil, ErrRefused
	}
	msg, err := invitationMessage(&inv)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return nil, ErrRefused
	}
	if fingerprint(inv.Recipient, pub) != expectedTargetFingerprint {
		return nil, ErrRefused
	}
	return &inv, nil
}
