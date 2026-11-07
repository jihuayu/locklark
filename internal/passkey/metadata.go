package passkey

import "encoding/json"

// Metadata is the public, browser-safe projection of a persisted passkey
// record. It deliberately contains no private key, raw record, user handle or
// other secret material and is safe to serialize into list/detail frames.
type Metadata struct {
	CredentialID string `json:"credential_id"`
	RPID         string `json:"rp_id"`
	UserName     string `json:"user_name"`
	DisplayName  string `json:"display_name"`
}

// String/GoString keep accidental diagnostics from dumping mutable record
// fields. Metadata itself is public and may be serialized explicitly.
func (Metadata) String() string   { return "[passkey metadata]" }
func (Metadata) GoString() string { return "[passkey metadata]" }

// MetadataFromRecord validates the complete durable record and returns only its
// public selector and account metadata. Invalid or unreadable records yield an
// error instead of a partially trusted projection.
func MetadataFromRecord(raw []byte) (Metadata, error) {
	record, err := Load(raw)
	if err != nil {
		return Metadata{}, ErrRefused
	}
	defer record.Clear()
	return Metadata{
		CredentialID: record.ID,
		RPID:         record.RPID,
		UserName:     record.Name,
		DisplayName:  record.DisplayName,
	}, nil
}

// ValidCredentialID accepts exactly the canonical base64url encoding of the
// 32-byte public credential identifier stored in the record. Alternative
// encodings, padding, whitespace and differently sized IDs are refused so a
// selector can never match by an ambiguous textual representation.
func ValidCredentialID(value string) bool {
	decoded, ok := decode(value, 32, 32)
	return ok && len(decoded) == 32
}

// MarshalJSON is explicit: only the four public fields can ever be emitted.
func (m Metadata) MarshalJSON() ([]byte, error) {
	type public struct {
		CredentialID string `json:"credential_id"`
		RPID         string `json:"rp_id"`
		UserName     string `json:"user_name"`
		DisplayName  string `json:"display_name"`
	}
	return json.Marshal(public{m.CredentialID, m.RPID, m.UserName, m.DisplayName})
}
