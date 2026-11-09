package passkeytransfer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// OpenSelection verifies the signed packet and every identity pin before it
// decrypts with the caller's already-unlocked existing age identity. The
// source key is trusted only through the mandatory expectedSourceFingerprint;
// the packet's self-declared source identity is never trusted on its own.
func OpenSelection(packetRaw, invitationRaw []byte, own RecipientIdentity, targetPin, expectedSourceFingerprint string, now time.Time) ([]Decoded, error) {
	if !validPin(targetPin) || !validPin(expectedSourceFingerprint) || own == nil {
		return nil, ErrRefused
	}
	var p Packet
	if decodeCanonical(packetRaw, maxPacket, &p) != nil {
		return nil, ErrRefused
	}
	if p.Version != version || !decodeHex32(p.ID) || !decodeHex32(p.InvitationID) || !isDigest(p.InvitationDigest) {
		return nil, ErrRefused
	}
	if p.TargetFingerprint != targetPin {
		return nil, ErrRefused
	}
	sourceRecipient, ok := parseRecipient(p.SourceRecipient)
	if !ok {
		return nil, ErrRefused
	}
	pub, ok := decodeStd(p.SourceAuditPublic, ed25519.PublicKeySize)
	if !ok || fingerprint(sourceRecipient.String(), pub) != expectedSourceFingerprint {
		return nil, ErrRefused
	}
	signature, ok := decodeStd(p.Signature, ed25519.SignatureSize)
	if !ok {
		return nil, ErrRefused
	}
	stamp := now.Unix()
	if p.IssuedAt > stamp || p.ExpiresAt <= stamp || p.IssuedAt > p.ExpiresAt {
		return nil, ErrRefused
	}
	msg, err := packetMessage(p.header())
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), msg, signature) {
		return nil, ErrRefused
	}
	inv, err := VerifyInvitation(invitationRaw, targetPin, now)
	if err != nil || inv.ID != p.InvitationID || p.ExpiresAt > inv.ExpiresAt {
		return nil, ErrRefused
	}
	digest := sha256.Sum256(invitationRaw)
	if hex.EncodeToString(digest[:]) != p.InvitationDigest {
		return nil, ErrRefused
	}
	ownRecipient, ok := recipientString(own.Recipient())
	if !ok || ownRecipient != inv.Recipient {
		return nil, ErrRefused
	}
	ciphertext, ok := decodeStdAny(p.Ciphertext)
	if !ok || len(ciphertext) > maxPacket {
		return nil, ErrRefused
	}
	plaintext, err := decryptFrom(own, ciphertext)
	if err != nil {
		return nil, ErrRefused
	}
	defer clear(plaintext)
	parsed, err := parsePayload(plaintext)
	if err != nil || !payloadMatchesHeader(parsed, p.header()) {
		return nil, ErrRefused
	}
	records, err := convertPayload(parsed)
	if err != nil {
		return nil, ErrRefused
	}
	return records, nil
}
