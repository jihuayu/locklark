package passkeytransfer

import "crypto/ed25519"

// parsePayload strictly decodes decrypted plaintext and validates every
// structural field except the passkey records themselves.
func parsePayload(raw []byte) (*payload, error) {
	var p payload
	if decodeCanonical(raw, maxPlaintext, &p) != nil {
		return nil, ErrRefused
	}
	if p.Version != version || !decodeHex32(p.PacketID) || !decodeHex32(p.InvitationID) {
		return nil, ErrRefused
	}
	if !isDigest(p.InvitationDigest) || !validPin(p.TargetFingerprint) {
		return nil, ErrRefused
	}
	if _, ok := parseRecipient(p.SourceRecipient); !ok {
		return nil, ErrRefused
	}
	if _, ok := decodeStd(p.SourceAuditPublic, ed25519.PublicKeySize); !ok {
		return nil, ErrRefused
	}
	if len(p.Records) == 0 || len(p.Records) > maxRecords {
		return nil, ErrRefused
	}
	return &p, nil
}

// convertPayload validates and detaches the selected records into owned
// decoded values. Any failure clears everything decoded so far.
func convertPayload(p *payload) ([]Decoded, error) {
	seenCredential := make(map[string]bool, len(p.Records))
	seenSelector := make(map[string]bool, len(p.Records))
	out := make([]Decoded, 0, len(p.Records))
	for _, r := range p.Records {
		record, err := validateWireRecord(r, seenCredential, seenSelector)
		if err != nil {
			clearDecoded(out)
			return nil, ErrRefused
		}
		out = append(out, Decoded{
			SourceItemID:       r.SourceItemID,
			SourceRevision:     r.SourceRevision,
			CredentialID:       r.CredentialID,
			CredentialRevision: r.CredentialRevision,
			Title:              r.Title,
			Record:             record,
		})
	}
	return out, nil
}

// payloadMatchesHeader requires every bound identity field to match exactly.
func payloadMatchesHeader(p *payload, h packetHeader) bool {
	return p.PacketID == h.ID &&
		p.InvitationID == h.InvitationID &&
		p.InvitationDigest == h.InvitationDigest &&
		p.SourceRecipient == h.SourceRecipient &&
		p.SourceAuditPublic == h.SourceAuditPublic &&
		p.TargetFingerprint == h.TargetFingerprint
}
