package passkeytransfer

import (
	"encoding/base64"

	"github.com/jihuayu/locklark/internal/passkey"
)

// validateRevision accepts only the canonical opaque revision digest: exactly
// 64 lowercase hex characters. A revision is an HMAC digest, never a version
// counter, so no numeric form, sign, leading zero trimming, truncation or
// parsing is accepted or performed here.
func validateRevision(rev string) bool { return isDigest(rev) }

// validateSelection checks one caller-supplied selection and records it for
// duplicate refusal. Record bytes stay caller-owned; the codec only reads them
// and must never clear a borrowed caller buffer.
func validateSelection(s Selection, seenCredential, seenSelector map[string]bool) error {
	if !decodeHex32(s.SourceItemID) || !validateRevision(s.SourceRevision) {
		return ErrRefused
	}
	if _, ok := decodeURL(s.CredentialID, 32); !ok || !validateRevision(s.CredentialRevision) || !textOK(s.Title) {
		return ErrRefused
	}
	if len(s.Record) == 0 || len(s.Record) > passkey.MaxOptions {
		return ErrRefused
	}
	rec, err := passkey.Load(s.Record)
	if err != nil {
		return ErrRefused
	}
	defer rec.Clear()
	if rec.ID != s.CredentialID {
		return ErrRefused
	}
	return noteSelector(s.SourceItemID, s.CredentialID, seenCredential, seenSelector)
}

// validateWireRecord checks one decrypted payload record and returns the owned
// native passkey JSON bytes.
func validateWireRecord(r wireRecord, seenCredential, seenSelector map[string]bool) ([]byte, error) {
	if !decodeHex32(r.SourceItemID) || !validateRevision(r.SourceRevision) {
		return nil, ErrRefused
	}
	if _, ok := decodeURL(r.CredentialID, 32); !ok || !validateRevision(r.CredentialRevision) || !textOK(r.Title) {
		return nil, ErrRefused
	}
	if len(r.Record) > base64.StdEncoding.EncodedLen(passkey.MaxOptions) {
		return nil, ErrRefused
	}
	record, ok := decodeStdAny(r.Record)
	if !ok || len(record) > passkey.MaxOptions {
		clear(record)
		return nil, ErrRefused
	}
	rec, err := passkey.Load(record)
	if err != nil {
		clear(record)
		return nil, ErrRefused
	}
	rec.Clear()
	if rec.ID != r.CredentialID {
		clear(record)
		return nil, ErrRefused
	}
	if noteSelector(r.SourceItemID, r.CredentialID, seenCredential, seenSelector) != nil {
		clear(record)
		return nil, ErrRefused
	}
	return record, nil
}

// noteSelector enforces unique global credential IDs and unique
// (source item, credential) selectors.
func noteSelector(item, credential string, seenCredential, seenSelector map[string]bool) error {
	selector := item + "\x00" + credential
	if seenCredential[credential] || seenSelector[selector] {
		return ErrRefused
	}
	seenCredential[credential] = true
	seenSelector[selector] = true
	return nil
}

func clearDecoded(records []Decoded) {
	for i := range records {
		records[i].Clear()
	}
}
