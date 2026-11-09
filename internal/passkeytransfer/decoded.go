package passkeytransfer

// Decoded is an owned, decrypted selection record returned to the native
// caller. The caller must call Clear. It is deliberately redacted for fmt/log
// and refuses JSON export: the bytes belong inside the encrypted payload only.
//
// SourceRevision and CredentialRevision are the exact opaque 64-lowercase-hex
// revision digests that were sealed: the codec never parses, truncates or
// converts them. A native future session export must compare both strings
// exactly against freshly read parent/per-credential revisions (compare-and-
// swap) before it writes anything; the codec only enforces the canonical
// format, not the current value.
type Decoded struct {
	SourceItemID       string
	SourceRevision     string
	CredentialID       string
	CredentialRevision string
	Title              string
	Record             []byte
}

// Clear zeroes the owned native passkey JSON bytes.
func (d *Decoded) Clear() {
	if d != nil {
		clear(d.Record)
		d.Record = nil
	}
}

func (d Decoded) String() string   { return "[private passkey transfer record]" }
func (d Decoded) GoString() string { return "[private passkey transfer record]" }

// MarshalJSON refuses accidental export of decrypted record bytes.
func (Decoded) MarshalJSON() ([]byte, error) { return nil, ErrRefused }
