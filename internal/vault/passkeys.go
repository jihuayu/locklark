package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/jihuayu/locklark/internal/passkey"
)

// itemPasskeysSlot is the protected KDBX slot holding the versioned passkey
// collection. It is deliberately distinct from the legacy "Locklark.Passkey"
// single-record slot: KDBX readers that predate this slot reject unknown
// protected fields, so a collection is never silently hidden inside the legacy
// blob and never silently dropped by an older client.
const itemPasskeysSlot = "Locklark.Passkeys"

// passkeyCollectionVersion is the only accepted collection envelope version.
const passkeyCollectionVersion = 1

// MaxPasskeys bounds one item's passkey collection.
const MaxPasskeys = 16

// itemPasskeyCollection is the exact JSON envelope persisted in
// itemPasskeysSlot. Fields must not be added or renamed without a version bump.
type itemPasskeyCollection struct {
	Version int      `json:"v"`
	Records [][]byte `json:"records"`
}

// validPasskeyCollection accepts 1..MaxPasskeys canonical ES256 WebAuthn
// records with unique credential identifiers. An empty collection is invalid:
// absence of the collection is expressed by omitting the slot entirely.
func validPasskeyCollection(records [][]byte) bool {
	if len(records) == 0 || len(records) > MaxPasskeys {
		return false
	}
	seen := make(map[string]bool, len(records))
	total := 0
	for _, raw := range records {
		if len(raw) == 0 || len(raw) > 8192 || !passkey.ValidRecord(raw) {
			return false
		}
		meta, err := passkey.MetadataFromRecord(raw)
		if err != nil || meta.CredentialID == "" || seen[meta.CredentialID] {
			return false
		}
		seen[meta.CredentialID] = true
		total += len(raw)
		if total > MaxPayload {
			return false
		}
	}
	return true
}

// encodePasskeyCollection renders the canonical base64 envelope for
// itemPasskeysSlot. Invalid collections are refused rather than persisted.
func encodePasskeyCollection(records [][]byte) (string, error) {
	if !validPasskeyCollection(records) {
		return "", ErrSnapshot
	}
	raw, err := json.Marshal(itemPasskeyCollection{Version: passkeyCollectionVersion, Records: records})
	if len(raw) > 0 {
		defer clear(raw)
	}
	if err != nil || len(raw) == 0 || len(raw) > MaxPayload {
		return "", ErrSnapshot
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// decodePasskeyCollection strictly parses itemPasskeysSlot: canonical base64,
// no unknown fields, no trailing data, exact version and exact record bounds.
func decodePasskeyCollection(content string) ([][]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(content)
	if len(raw) > 0 {
		defer clear(raw)
	}
	if err != nil || len(raw) == 0 || len(raw) > MaxPayload || base64.StdEncoding.EncodeToString(raw) != content {
		return nil, ErrSnapshot
	}
	var env itemPasskeyCollection
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		clearPasskeyRecords(env.Records)
		return nil, ErrSnapshot
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		clearPasskeyRecords(env.Records)
		return nil, ErrSnapshot
	}
	if env.Version != passkeyCollectionVersion || !validPasskeyCollection(env.Records) {
		clearPasskeyRecords(env.Records)
		return nil, ErrSnapshot
	}
	return env.Records, nil
}

// PasskeyRecords returns the item's native passkey records (collection first,
// otherwise the legacy single record) for internal native use only. The
// returned slices are borrowed from the item, never a copy and never a public
// DTO; callers that mutate must operate on a CloneItem copy.
func (it Item) PasskeyRecords() [][]byte {
	if len(it.Passkeys) > 0 {
		return it.Passkeys
	}
	if len(it.Passkey) > 0 {
		return [][]byte{it.Passkey}
	}
	return nil
}

// SetPasskeyRecords replaces the collection with a validated deep copy and
// clears the legacy single-record field so both persisted forms can never
// coexist. Invalid or empty collections are refused.
func (it *Item) SetPasskeyRecords(records [][]byte) error {
	if !validPasskeyCollection(records) {
		return ErrSnapshot
	}
	// Clone the accepted data before clearing either persisted form, so the
	// input may alias the receiver's own records: the clear must never zero
	// what was just validated and stored.
	next := clonePasskeyRecords(records)
	it.ClearPasskeys()
	it.Passkeys = next
	return nil
}

// SetLegacyPasskey replaces the legacy single record and clears the collection,
// keeping the two persisted forms mutually exclusive.
func (it *Item) SetLegacyPasskey(raw []byte) error {
	if len(raw) == 0 || !passkey.ValidRecord(raw) {
		return ErrSnapshot
	}
	// Clone before clearing: raw may alias the legacy field being replaced.
	next := cloneBytes(raw)
	it.ClearPasskeys()
	it.Passkey = next
	return nil
}

// ClearPasskeys zeroes and drops both persisted passkey forms.
func (it *Item) ClearPasskeys() {
	clearPasskeyRecords(it.Passkeys)
	clearPasskeyBytes(it.Passkey)
	it.Passkeys = nil
	it.Passkey = nil
}

// clonePasskeyRecords deep-copies every record so clones share no buffers.
func clonePasskeyRecords(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = cloneBytes(in[i])
	}
	return out
}

// clearPasskeyRecords zeroes every record buffer in place before dropping it.
func clearPasskeyRecords(in [][]byte) {
	for i := range in {
		clearPasskeyBytes(in[i])
	}
}

// clearPasskeyBytes zeroes record bytes in place before they are dropped.
func clearPasskeyBytes(in []byte) {
	for i := range in {
		in[i] = 0
	}
}
