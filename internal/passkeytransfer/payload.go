package passkeytransfer

import (
	"encoding/base64"
	"encoding/json"
)

const redactedSelection = "[private passkey transfer record]"

// Selection is one explicitly chosen source credential record. Record is the
// native passkey JSON and never a browser DTO.
//
// SourceRevision and CredentialRevision are opaque revision digests: exactly 64
// lowercase hex characters produced by the existing personal-layer HMAC. They
// are not version counters and carry no ordering or arithmetic meaning. The
// codec only checks the canonical 64-lowercase-hex format and transports the
// strings byte-for-byte; a native future session export must still re-read the
// current parent and per-credential revisions and compare both strings exactly
// (compare-and-swap) before it applies anything.
//
// Record is borrowed from the caller: the codec never clears, retains or
// mutates it. Only the caller, when it owns the copy, may release the bytes via
// Clear.
type Selection struct {
	SourceItemID       string
	SourceRevision     string
	CredentialID       string
	CredentialRevision string
	Title              string
	Record             []byte
}

// String and GoString redact the borrowed private record bytes so that fmt's
// %v, %+v and %#v can never print them.
func (Selection) String() string   { return redactedSelection }
func (Selection) GoString() string { return redactedSelection }

// MarshalJSON refuses accidental plaintext export of the private record bytes.
// The encrypted wire form is built field by field in newPayload, so no
// legitimate plaintext JSON encoding is lost by this refusal.
func (Selection) MarshalJSON() ([]byte, error) { return nil, ErrRefused }

// Clear zeroes Record. Call it only when Record is a caller-owned copy: the
// codec borrows caller buffers and never clears them itself, and clearing a
// buffer the caller still owns or shares would corrupt the caller's data.
func (s *Selection) Clear() {
	if s != nil {
		clear(s.Record)
		s.Record = nil
	}
}

// payload is the encrypted v1 plaintext. It binds the same packet ID,
// invitation ID/digest, source public identity and target pin carried in the
// signed outer header, so a header/payload mismatch is always refused. It is
// intentionally unexported so it cannot be formatted or logged.
type payload struct {
	Version           int          `json:"v"`
	PacketID          string       `json:"packet_id"`
	InvitationID      string       `json:"invitation_id"`
	InvitationDigest  string       `json:"invitation_digest"`
	SourceRecipient   string       `json:"source_recipient"`
	SourceAuditPublic string       `json:"source_audit_public"`
	TargetFingerprint string       `json:"target_fingerprint"`
	Records           []wireRecord `json:"records"`
}

// wireRecord carries the opaque revision digests as plain strings: no
// truncation, parsing or numeric conversion is allowed on this path.
type wireRecord struct {
	SourceItemID       string `json:"source_item_id"`
	SourceRevision     string `json:"source_revision"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision string `json:"credential_revision"`
	Title              string `json:"title,omitempty"`
	Record             string `json:"record_base64"`
}

// newPayload validates the selection and returns canonical plaintext bytes
// bound to the signed header. The caller owns the returned bytes and must
// clear them after encryption. Selection records stay caller-owned: the
// caller buffers are only read, never cleared, here.
func newPayload(h packetHeader, records []Selection) ([]byte, error) {
	if len(records) == 0 || len(records) > maxRecords {
		return nil, ErrRefused
	}
	seenCredential := make(map[string]bool, len(records))
	seenSelector := make(map[string]bool, len(records))
	out := payload{
		Version:           version,
		PacketID:          h.ID,
		InvitationID:      h.InvitationID,
		InvitationDigest:  h.InvitationDigest,
		SourceRecipient:   h.SourceRecipient,
		SourceAuditPublic: h.SourceAuditPublic,
		TargetFingerprint: h.TargetFingerprint,
		Records:           make([]wireRecord, 0, len(records)),
	}
	for _, s := range records {
		if validateSelection(s, seenCredential, seenSelector) != nil {
			return nil, ErrRefused
		}
		out.Records = append(out.Records, wireRecord{
			SourceItemID:       s.SourceItemID,
			SourceRevision:     s.SourceRevision,
			CredentialID:       s.CredentialID,
			CredentialRevision: s.CredentialRevision,
			Title:              s.Title,
			Record:             base64.StdEncoding.EncodeToString(s.Record),
		})
	}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) == 0 || len(raw) > maxPlaintext {
		return nil, ErrRefused
	}
	return raw, nil
}
