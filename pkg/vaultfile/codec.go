package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// The codec is strict on purpose:
//   - the whole input must be exactly one complete object;
//   - unknown and duplicate members are rejected at every depth;
//   - nesting depth, array lengths, string lengths and byte lengths are
//     limited before anything is decoded;
//   - numbers must be positive integers (no fractions, exponents, negatives
//     or leading zeros);
//   - binary values are base64url without padding, canonical for the value.
//
// Encoding never uses json.Marshal on a struct: output member order is the
// schema order below so fixed vectors are byte-stable.

// fileMembers is the exact, ordered member set of a vault file. Any other
// member is rejected as unknown; header_sig is not a member of v1.
var fileMembers = []string{
	"format", "version", "header", "signed_policy_proofs",
	"content_encoding", "kdbx_ciphertext", "vuk_device_slots", "cek_slot",
	"content_signature",
}

// ParseFile strictly parses and validates one complete vault file.
func ParseFile(data []byte) (*File, error) {
	if len(data) > MaxFileBytes {
		return nil, &Error{Code: CodeTooLarge, Path: ""}
	}
	v, err := decodeCanonical(data, fileMembers, MaxJSONDepth)
	if err != nil {
		return nil, err
	}
	f, err := fileFromValue(v)
	if err != nil {
		return nil, err
	}
	if err := ValidateFile(f); err != nil {
		return nil, err
	}
	return f, nil
}

// EncodeFile validates f and returns its canonical encoding.
func EncodeFile(f *File) ([]byte, error) {
	if f == nil {
		return nil, &Error{Code: CodeInvalidValue}
	}
	if err := ValidateFile(f); err != nil {
		return nil, err
	}
	return encodeFileWire(f, fileEncoding{})
}

// fileEncoding selects which derived values the internal canonical encoder
// writes, independently of the fields f carries. It never validates: it
// writes the member shapes only, so a preimage can name members that are not
// yet derivable from f.
type fileEncoding struct {
	// revisionID, when non-nil, is written as header.revision_id.
	revisionID *string
	// omitRevision drops the header member revision_id entirely. It takes
	// precedence over revisionID; the two are never set together.
	omitRevision bool
	// omitSignature drops the file member content_signature entirely.
	omitSignature bool
}

// encodeFileWire writes the canonical encoding of f under enc without
// validating it. Without an omission option the encoding is exactly
// EncodeFile's: header.revision_id as f carries it (including "" for an
// unsigned draft) and content_signature as f carries it (sig null for an
// unsigned draft). With enc.omitRevision or enc.omitSignature set, the named
// member is absent rather than empty, so a derived preimage is literally the
// canonical file minus that member.
func encodeFileWire(f *File, enc fileEncoding) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	writeStr(&b, "format", f.Format)
	b.WriteByte(',')
	writeInt(&b, "version", uint64(f.Version))
	b.WriteString(`,"header":`)
	switch {
	case enc.omitRevision:
		writeHeaderWithoutRevision(&b, &f.Header)
	case enc.revisionID != nil:
		writeHeaderWithRevision(&b, &f.Header, *enc.revisionID)
	default:
		writeHeader(&b, &f.Header)
	}
	b.WriteString(`,"signed_policy_proofs":`)
	writeArray(&b, len(f.SignedPolicyProofs), func(i int) {
		sp := &f.SignedPolicyProofs[i]
		b.WriteString(`{"document":`)
		writeBytes(&b, sp.Document)
		b.WriteString(`,"policy":`)
		writePolicy(&b, &sp.Policy)
		b.WriteString(`,"signer_id":`)
		b.WriteString(quote(sp.SignerID))
		b.WriteString(`,"alg":`)
		b.WriteString(quote(sp.Alg))
		b.WriteString(`,"sig":`)
		writeBytes(&b, sp.Sig)
		b.WriteByte('}')
	})
	b.WriteString(`,"content_encoding":`)
	b.WriteString(quote(f.ContentEncoding))
	b.WriteString(`,"kdbx_ciphertext":`)
	writeBytes(&b, f.KDBXCiphertext)
	b.WriteString(`,"vuk_device_slots":`)
	writeArray(&b, len(f.VUKDeviceSlots), func(i int) {
		s := &f.VUKDeviceSlots[i]
		b.WriteString(`{"device_id":`)
		b.WriteString(quote(s.DeviceID))
		b.WriteString(`,"recipient":`)
		b.WriteString(quote(s.Recipient))
		b.WriteString(`,"wrapped_vuk":`)
		writeBytes(&b, s.WrappedVUK)
		b.WriteByte('}')
	})
	b.WriteString(`,"cek_slot":{"key_epoch":`)
	b.WriteString(itoa(f.CEKSlot.KeyEpoch))
	b.WriteString(`,"wrapped_cek":`)
	writeBytes(&b, f.CEKSlot.WrappedCEK)
	b.WriteByte('}')
	if !enc.omitSignature {
		b.WriteString(`,"content_signature":`)
		writeSignature(&b, &f.ContentSignature)
	}
	b.WriteByte('}')
	if b.Len() > MaxFileBytes {
		return nil, &Error{Code: CodeTooLarge}
	}
	return b.Bytes(), nil
}

// EncodePolicyDocument returns the canonical encoding of a policy document
// as it appears inside SignedPolicy.Document.
func EncodePolicyDocument(p *Policy) ([]byte, error) {
	if err := ValidatePolicy(p); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writePolicy(&b, p)
	return b.Bytes(), nil
}

// ParsePolicyDocument strictly parses a policy document.
func ParsePolicyDocument(data []byte) (*Policy, error) {
	if len(data) > MaxSignedPolicyProofBytes {
		return nil, &Error{Code: CodeTooLarge}
	}
	v, err := decodeCanonical(data, []string{
		"format", "version", "vault_id", "policy_seq", "prev_policy_digest",
		"owner_root", "readers", "writers", "admins", "owners",
		"admin_delegations", "devices",
	}, MaxJSONDepth)
	if err != nil {
		return nil, err
	}
	p, err := policyFromValue(v)
	if err != nil {
		return nil, err
	}
	if err := ValidatePolicy(p); err != nil {
		return nil, err
	}
	return p, nil
}

func writeHeader(b *bytes.Buffer, h *Header) {
	writeHeaderWithRevision(b, h, h.RevisionID)
}

// writeHeaderWithRevision writes h exactly as writeHeader does, except that
// revision_id is the given value. Preimages name a revision that the header
// field does not carry yet (or must not carry), without rewriting h.
func writeHeaderWithRevision(b *bytes.Buffer, h *Header, revisionID string) {
	writeHeaderMembers(b, h, true, func(b *bytes.Buffer) { b.WriteString(quote(revisionID)) })
}

// writeHeaderWithoutRevision writes h exactly as writeHeader does, except that
// the revision_id member is absent entirely. This is the RevisionID preimage
// form: the derived revision is never named by its own input.
func writeHeaderWithoutRevision(b *bytes.Buffer, h *Header) {
	writeHeaderMembers(b, h, false, nil)
}

// writeHeaderMembers writes the header in schema order. With withRevision set,
// writeRev writes the revision value after its member name; otherwise the
// member and its name are both skipped.
func writeHeaderMembers(b *bytes.Buffer, h *Header, withRevision bool, writeRev func(*bytes.Buffer)) {
	b.WriteString(`{"vault_id":`)
	b.WriteString(quote(h.VaultID))
	b.WriteString(`,"key_epoch":`)
	b.WriteString(itoa(h.KeyEpoch))
	b.WriteString(`,"content_seq":`)
	b.WriteString(itoa(h.ContentSeq))
	if withRevision {
		b.WriteString(`,"revision_id":`)
		writeRev(b)
	}
	b.WriteString(`,"prev_digest":`)
	writeBytes(b, h.PrevDigest)
	b.WriteString(`,"op_id":`)
	b.WriteString(quote(h.OpID))
	b.WriteString(`,"policy_seq":`)
	b.WriteString(itoa(h.PolicySeq))
	b.WriteString(`,"policy_digest":`)
	writeBytes(b, h.PolicyDigest)
	b.WriteString(`,"author_device_id":`)
	b.WriteString(quote(h.AuthorDeviceID))
	b.WriteByte('}')
}

func writeSignature(b *bytes.Buffer, s *Signature) {
	b.WriteString(`{"signer_id":`)
	b.WriteString(quote(s.SignerID))
	b.WriteString(`,"alg":`)
	b.WriteString(quote(s.Alg))
	b.WriteString(`,"sig":`)
	writeBytes(b, s.Sig)
	b.WriteByte('}')
}

func writePolicy(b *bytes.Buffer, p *Policy) {
	// Canonical member order is not semantic; policy documents are signed as
	// opaque bytes and re-parsed, so a stable order is enough.
	b.WriteString(`{"format":`)
	b.WriteString(quote(p.Format))
	b.WriteString(`,"version":`)
	b.WriteString(itoa(uint64(p.Version)))
	b.WriteString(`,"vault_id":`)
	b.WriteString(quote(p.VaultID))
	b.WriteString(`,"policy_seq":`)
	b.WriteString(itoa(p.PolicySeq))
	b.WriteString(`,"prev_policy_digest":`)
	writeBytes(b, p.PrevPolicyDigest)
	b.WriteString(`,"owner_root":{"key_id":`)
	b.WriteString(quote(p.OwnerRoot.KeyID))
	b.WriteString(`,"alg":`)
	b.WriteString(quote(p.OwnerRoot.Alg))
	b.WriteString(`,"public_key":`)
	writeBytes(b, p.OwnerRoot.PublicKey)
	b.WriteString(`,"owners":`)
	writeArray(b, len(p.OwnerRoot.Owners), func(i int) {
		o := &p.OwnerRoot.Owners[i]
		b.WriteString(`{"principal_id":`)
		b.WriteString(quote(o.PrincipalID))
		b.WriteString(`,"label":`)
		b.WriteString(quote(o.Label))
		b.WriteByte('}')
	})
	b.WriteByte('}')
	for _, arr := range []struct {
		name    string
		members []Member
	}{
		{"readers", p.Readers}, {"writers", p.Writers},
		{"admins", p.Admins}, {"owners", p.Owners},
	} {
		b.WriteString(`,"`)
		b.WriteString(arr.name)
		b.WriteString(`":`)
		writeArray(b, len(arr.members), func(i int) {
			m := &arr.members[i]
			b.WriteString(`{"principal_id":`)
			b.WriteString(quote(m.PrincipalID))
			b.WriteString(`,"label":`)
			b.WriteString(quote(m.Label))
			b.WriteByte('}')
		})
	}
	b.WriteString(`,"admin_delegations":`)
	writeArray(b, len(p.AdminDelegations), func(i int) {
		d := &p.AdminDelegations[i]
		b.WriteString(`{"delegation_id":`)
		b.WriteString(quote(d.DelegationID))
		b.WriteString(`,"delegate_device_id":`)
		b.WriteString(quote(d.DelegateDevice))
		b.WriteString(`,"granted_by":`)
		b.WriteString(quote(d.GrantedBy))
		b.WriteString(`,"scope":{"invite_readers":`)
		b.WriteString(boolStr(d.Scope.InviteReaders))
		b.WriteString(`,"invite_writers":`)
		b.WriteString(boolStr(d.Scope.InviteWriters))
		b.WriteString(`,"remove_members":`)
		b.WriteString(boolStr(d.Scope.RemoveMembers))
		b.WriteString(`,"remove_devices":`)
		b.WriteString(boolStr(d.Scope.RemoveDevices))
		b.WriteString(`,"promote_admin":`)
		b.WriteString(boolStr(d.Scope.PromoteAdmin))
		b.WriteString(`,"promote_owner":`)
		b.WriteString(boolStr(d.Scope.PromoteOwner))
		b.WriteString(`,"replace_root":`)
		b.WriteString(boolStr(d.Scope.ReplaceRoot))
		b.WriteString(`},"scope_note":`)
		b.WriteString(quote(d.ScopeNote))
		b.WriteString(`,"expires_policy_seq":`)
		b.WriteString(itoa(d.ExpiresPolicySeq))
		b.WriteByte('}')
	})
	b.WriteString(`,"devices":`)
	writeArray(b, len(p.Devices), func(i int) {
		d := &p.Devices[i]
		b.WriteString(`{"device_id":`)
		b.WriteString(quote(d.DeviceID))
		b.WriteString(`,"principal_id":`)
		b.WriteString(quote(d.PrincipalID))
		b.WriteString(`,"label":`)
		b.WriteString(quote(d.Label))
		b.WriteString(`,"content_signing_key":{"alg":`)
		b.WriteString(quote(d.ContentSigningKey.Alg))
		b.WriteString(`,"public_key":`)
		writeBytes(b, d.ContentSigningKey.PublicKey)
		b.WriteString(`},"policy_signing_key":`)
		if d.PolicySigningKey == nil {
			b.WriteString("null")
		} else {
			b.WriteString(`{"alg":`)
			b.WriteString(quote(d.PolicySigningKey.Alg))
			b.WriteString(`,"public_key":`)
			writeBytes(b, d.PolicySigningKey.PublicKey)
			b.WriteByte('}')
		}
		b.WriteString(`,"age_encryption_key":`)
		b.WriteString(quote(d.AgeEncryptionKey))
		b.WriteByte('}')
	})
	b.WriteByte('}')
}

func writeArray(b *bytes.Buffer, n int, item func(i int)) {
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		item(i)
	}
	b.WriteByte(']')
}

func writeStr(b *bytes.Buffer, k, v string) {
	b.WriteString(quote(k))
	b.WriteString(`:`)
	b.WriteString(quote(v))
}

func writeInt(b *bytes.Buffer, k string, v uint64) {
	b.WriteString(quote(k))
	b.WriteString(`:`)
	b.WriteString(itoa(v))
}

func writeBytes(b *bytes.Buffer, v []byte) {
	if v == nil {
		b.WriteString("null")
		return
	}
	b.WriteByte('"')
	b.WriteString(base64.RawURLEncoding.EncodeToString(v))
	b.WriteByte('"')
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func itoa(v uint64) string {
	return fmt.Sprintf("%d", v)
}

// quote encodes a string as JSON with stable escaping of control characters.
func quote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// ---- strict value tree ----

type valueKind int

const (
	kindNull valueKind = iota
	kindBool
	kindInt
	kindString
	kindArray
	kindObject
)

type value struct {
	kind valueKind
	b    bool
	i    uint64
	s    string
	arr  []*value
	keys []string
	obj  map[string]*value
}

var reInt = regexp.MustCompile(`\A(?:0|[1-9][0-9]*)\z`)

// reBinaryCarrier matches paths of base64url string members other than the
// encrypted content.
var reBinaryCarrier = regexp.MustCompile(`(?:\.document|\.sig|\.public_key|\.prev_digest|\.policy_digest|\.wrapped_vuk|\.wrapped_cek)$`)

// maxIntegerDigits is the digit count of the largest uint64.
const maxIntegerDigits = 20

// reCanonicalString rejects numbers written as strings; numbers are only
// accepted in bare JSON form.
var reNumberString = regexp.MustCompile(`\A-?[0-9][0-9eE+.]*\z`)

// decodeCanonical parses data into a value tree. Numbers never arrive as
// float64 (UseNumber), so precision is never silently lost.
func decodeCanonical(data []byte, allowed []string, maxDepth int) (*value, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, 0, maxDepth, true, "", allowed)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, &Error{Code: CodeTrailingData}
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth, maxDepth int, top bool, path string, allowed []string) (*value, error) {
	if depth > maxDepth {
		return nil, &Error{Code: CodeTooDeep, Path: path}
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, &Error{Code: CodeInvalidJSON, Path: path}
	}
	switch t := tok.(type) {
	case nil:
		return &value{kind: kindNull}, nil
	case bool:
		return &value{kind: kindBool, b: t}, nil
	case json.Number:
		if !reInt.MatchString(string(t)) {
			return nil, &Error{Code: CodeInvalidValue, Path: path}
		}
		if len(t) > maxIntegerDigits {
			return nil, &Error{Code: CodeLimitExceeded, Path: path}
		}
		var n uint64
		for _, c := range []byte(t) {
			d := uint64(c - '0')
			if n > (^uint64(0)-d)/10 {
				return nil, &Error{Code: CodeLimitExceeded, Path: path}
			}
			n = n*10 + d
		}
		return &value{kind: kindInt, i: n}, nil
	case string:
		if reNumberString.MatchString(t) {
			return nil, &Error{Code: CodeWrongType, Path: path}
		}
		if path == "kdbx_ciphertext" {
			// The binary carrier has its own byte budget, which is below the
			// generic string token bound, so it is reported as bytes_too_long.
			if len(t) > MaxStringTokenBytes {
				return nil, &Error{Code: CodeBytesTooLong, Path: path}
			}
		} else if reBinaryCarrier.MatchString(path) {
			if len(t) > MaxBinaryStringBytes {
				return nil, &Error{Code: CodeBytesTooLong, Path: path}
			}
		} else if len(t) > MaxTextStringBytes {
			return nil, &Error{Code: CodeStringTooLong, Path: path}
		}
		return &value{kind: kindString, s: t}, nil
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]*value{}
			keys := []string{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, &Error{Code: CodeInvalidJSON, Path: path}
				}
				key, ok := kt.(string)
				if !ok {
					return nil, &Error{Code: CodeInvalidJSON, Path: path}
				}
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				if _, dup := obj[key]; dup {
					return nil, &Error{Code: CodeDuplicateField, Path: childPath}
				}
				if top && !contains(allowed, key) {
					return nil, &Error{Code: CodeUnknownField, Path: childPath}
				}
				child, err := decodeValue(dec, depth+1, maxDepth, false, childPath, nil)
				if err != nil {
					return nil, err
				}
				obj[key] = child
				keys = append(keys, key)
			}
			if _, err := dec.Token(); err != nil {
				return nil, &Error{Code: CodeInvalidJSON, Path: path}
			}
			return &value{kind: kindObject, keys: keys, obj: obj}, nil
		case '[':
			arr := []*value{}
			for dec.More() {
				if len(arr) >= MaxArrayItems {
					return nil, &Error{Code: CodeTooManyItems, Path: path}
				}
				child, err := decodeValue(dec, depth+1, maxDepth, false, path+"[]", nil)
				if err != nil {
					return nil, err
				}
				arr = append(arr, child)
			}
			if _, err := dec.Token(); err != nil {
				return nil, &Error{Code: CodeInvalidJSON, Path: path}
			}
			return &value{kind: kindArray, arr: arr}, nil
		}
	}
	return nil, &Error{Code: CodeInvalidJSON, Path: path}
}

func listField(v *value, name string, max int) ([]*value, error) {
	if v.kind != kindArray {
		return nil, &Error{Code: CodeWrongType, Path: name}
	}
	if len(v.arr) > max {
		return nil, &Error{Code: CodeTooManyItems, Path: name}
	}
	return v.arr, nil
}

func checkSignature(s *Signature) error {
	if s == nil || len(s.Sig) != ed25519.SignatureSize {
		return Err("", CodeSignatureInvalid)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- typed shape conversion ----

// obj converts an object value and checks that it carries exactly the
// members in want (no unknown, no duplicate, none missing).
func obj(v *value, want ...string) (map[string]*value, error) {
	if v.kind != kindObject {
		return nil, &Error{Code: CodeWrongType}
	}
	for _, w := range want {
		if _, ok := v.obj[w]; !ok {
			return nil, &Error{Code: CodeMissingField, Path: w}
		}
	}
	if len(v.keys) != len(want) {
		for _, k := range v.keys {
			if !contains(want, k) {
				return nil, &Error{Code: CodeUnknownField, Path: k}
			}
		}
		return nil, &Error{Code: CodeInvalidValue}
	}
	return v.obj, nil
}

// str reads a string member with a length limit.
func str(m map[string]*value, k string, maxLen int) (string, error) {
	v := m[k]
	if v.kind != kindString {
		return "", &Error{Code: CodeWrongType, Path: k}
	}
	if len(v.s) > maxLen {
		return "", &Error{Code: CodeStringTooLong, Path: k}
	}
	return v.s, nil
}

// num reads a non-negative integer member.
func num(m map[string]*value, k string) (uint64, error) {
	v := m[k]
	if v.kind != kindInt {
		return 0, &Error{Code: CodeWrongType, Path: k}
	}
	return v.i, nil
}

// bin reads a binary member encoded as canonical base64url without padding.
func bin(m map[string]*value, k string, maxLen int, nullable bool) ([]byte, error) {
	v := m[k]
	if v.kind == kindNull && nullable {
		return nil, nil
	}
	if v.kind != kindString {
		return nil, &Error{Code: CodeWrongType, Path: k}
	}
	// Each 4 characters decode to at most 3 bytes.
	if len(v.s) > maxLen*4/3+4 {
		return nil, &Error{Code: CodeBytesTooLong, Path: k}
	}
	errTooLong := &Error{Code: CodeBytesTooLong, Path: k}
	out, err := base64.RawURLEncoding.Strict().DecodeString(v.s)
	if err != nil {
		// Decoders may report an incomplete group before an overflow.
		if len(v.s) > maxLen*4/3+4 {
			return nil, errTooLong
		}
		return nil, &Error{Code: CodeInvalidValue, Path: k}
	}
	if len(out) > maxLen {
		return nil, &Error{Code: CodeBytesTooLong, Path: k}
	}
	if v.s != base64.RawURLEncoding.EncodeToString(out) {
		return nil, &Error{Code: CodeInvalidValue, Path: k}
	}
	return out, nil
}

// boolVal reads a boolean member.
func boolVal(m map[string]*value, k string) (bool, error) {
	v := m[k]
	if v.kind != kindBool {
		return false, &Error{Code: CodeWrongType, Path: k}
	}
	return v.b, nil
}

// list reads an array member with a length limit.
func list(m map[string]*value, k string, max int) ([]*value, error) {
	v := m[k]
	if v.kind != kindArray {
		return nil, &Error{Code: CodeWrongType, Path: k}
	}
	if len(v.arr) > max {
		return nil, &Error{Code: CodeTooManyItems, Path: k}
	}
	return v.arr, nil
}

func fileFromValue(v *value) (*File, error) {
	// The content signature size is checked before any other member of the
	// file is decoded; sig null is the unsigned-draft state.
	if err := checkSignatureMember(v, "content_signature"); err != nil {
		return nil, err
	}
	m, err := obj(v, fileMembers...)
	if err != nil {
		return nil, err
	}
	f := &File{}
	if f.Format, err = str(m, "format", len(Format)); err != nil {
		return nil, err
	}
	if err = version(m, &f.Version); err != nil {
		return nil, err
	}
	if f.Header, err = headerFromValue(m["header"]); err != nil {
		return nil, err
	}
	proofs, err := list(m, "signed_policy_proofs", MaxArrayItems)
	if err != nil {
		return nil, err
	}
	f.SignedPolicyProofs = make([]SignedPolicy, len(proofs))
	for i, pv := range proofs {
		if f.SignedPolicyProofs[i], err = signedPolicyFromValue(pv); err != nil {
			return nil, err
		}
	}
	if f.ContentEncoding, err = str(m, "content_encoding", len(ContentEncoding)); err != nil {
		return nil, err
	}
	if f.KDBXCiphertext, err = bin(m, "kdbx_ciphertext", MaxKDBXCiphertextBytes, false); err != nil {
		return nil, err
	}
	slots, err := list(m, "vuk_device_slots", MaxDeviceSlots)
	if err != nil {
		return nil, err
	}
	f.VUKDeviceSlots = make([]DeviceSlot, len(slots))
	for i, sv := range slots {
		if f.VUKDeviceSlots[i], err = deviceSlotFromValue(sv); err != nil {
			return nil, err
		}
	}
	if f.CEKSlot, err = cekSlotFromValue(m["cek_slot"]); err != nil {
		return nil, err
	}
	if f.ContentSignature, err = signatureFromValue(m["content_signature"]); err != nil {
		return nil, err
	}
	return f, nil
}

// checkSignatureMember checks the declared length of one signature without
// decoding the whole document.
func checkSignatureMember(v *value, k string) error {
	if v.kind != kindObject {
		return Err("", CodeWrongType)
	}
	sv, ok := v.obj[k]
	if !ok {
		return Err(k, CodeMissingField)
	}
	if sv.kind != kindObject {
		return Err(k, CodeWrongType)
	}
	sig, ok := sv.obj["sig"]
	if !ok {
		return Err(k+".sig", CodeMissingField)
	}
	if sig.kind == kindNull {
		return nil
	}
	if sig.kind != kindString || len(sig.s) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return Err(k+".sig", CodeSignatureInvalid)
	}
	return nil
}

func headerFromValue(v *value) (Header, error) {
	var h Header
	m, err := obj(v,
		"vault_id", "key_epoch", "content_seq", "revision_id", "prev_digest",
		"op_id", "policy_seq", "policy_digest", "author_device_id",
	)
	if err != nil {
		return h, err
	}
	if h.VaultID, err = str(m, "vault_id", MaxIDLength); err != nil {
		return h, err
	}
	if h.KeyEpoch, err = num(m, "key_epoch"); err != nil {
		return h, err
	}
	if h.ContentSeq, err = num(m, "content_seq"); err != nil {
		return h, err
	}
	if h.RevisionID, err = str(m, "revision_id", MaxIDLength); err != nil {
		return h, err
	}
	if h.PrevDigest, err = bin(m, "prev_digest", 64, true); err != nil {
		return h, err
	}
	if h.OpID, err = str(m, "op_id", MaxIDLength); err != nil {
		return h, err
	}
	if h.PolicySeq, err = num(m, "policy_seq"); err != nil {
		return h, err
	}
	if h.PolicyDigest, err = bin(m, "policy_digest", 64, false); err != nil {
		return h, err
	}
	if h.AuthorDeviceID, err = str(m, "author_device_id", MaxDeviceIDLength); err != nil {
		return h, err
	}
	return h, nil
}

func signedPolicyFromValue(v *value) (SignedPolicy, error) {
	var sp SignedPolicy
	m, err := obj(v, "document", "policy", "signer_id", "alg", "sig")
	if err != nil {
		return sp, err
	}
	if sp.Document, err = bin(m, "document", MaxSignedPolicyProofBytes, false); err != nil {
		return sp, err
	}
	if sp.SignerID, err = str(m, "signer_id", MaxKeyIDLength); err != nil {
		return sp, err
	}
	if sp.Alg, err = str(m, "alg", len(PolicySigAlgEd25519)); err != nil {
		return sp, err
	}
	if sp.Sig, err = bin(m, "sig", MaxSignatureLength, false); err != nil {
		return sp, err
	}
	p, err := policyFromValue(m["policy"])
	if err != nil {
		return sp, err
	}
	sp.Policy = *p
	return sp, nil
}

func policyFromValue(v *value) (*Policy, error) {
	m, err := obj(v,
		"format", "version", "vault_id", "policy_seq", "prev_policy_digest",
		"owner_root", "readers", "writers", "admins", "owners",
		"admin_delegations", "devices",
	)
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	if p.Format, err = str(m, "format", len(Format)); err != nil {
		return nil, err
	}
	if err = version(m, &p.Version); err != nil {
		return nil, err
	}
	if p.VaultID, err = str(m, "vault_id", MaxIDLength); err != nil {
		return nil, err
	}
	if p.PolicySeq, err = num(m, "policy_seq"); err != nil {
		return nil, err
	}
	if p.PrevPolicyDigest, err = bin(m, "prev_policy_digest", 64, true); err != nil {
		return nil, err
	}
	if p.OwnerRoot, err = ownerRootFromValue(m["owner_root"]); err != nil {
		return nil, err
	}
	if p.Readers, err = principalsFromValue(m["readers"]); err != nil {
		return nil, err
	}
	if p.Writers, err = principalsFromValue(m["writers"]); err != nil {
		return nil, err
	}
	if p.Admins, err = principalsFromValue(m["admins"]); err != nil {
		return nil, err
	}
	if p.Owners, err = principalsFromValue(m["owners"]); err != nil {
		return nil, err
	}
	del, err := list(m, "admin_delegations", MaxDelegations)
	if err != nil {
		return nil, err
	}
	p.AdminDelegations = make([]AdminDelegation, len(del))
	for i, dv := range del {
		if p.AdminDelegations[i], err = delegationFromValue(dv); err != nil {
			return nil, err
		}
	}
	devs, err := list(m, "devices", MaxArrayItems)
	if err != nil {
		return nil, err
	}
	p.Devices = make([]Device, len(devs))
	for i, dv := range devs {
		if p.Devices[i], err = deviceFromValue(dv); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func ownerRootFromValue(v *value) (OwnerRoot, error) {
	var r OwnerRoot
	m, err := obj(v, "key_id", "alg", "public_key", "owners")
	if err != nil {
		return r, err
	}
	if r.KeyID, err = str(m, "key_id", MaxKeyIDLength); err != nil {
		return r, err
	}
	if r.Alg, err = str(m, "alg", len(PolicySigAlgEd25519)); err != nil {
		return r, err
	}
	if r.PublicKey, err = bin(m, "public_key", MaxPublicKeyLength, false); err != nil {
		return r, err
	}
	owners, err := list(m, "owners", MaxPolicyArrayItems)
	if err != nil {
		return r, err
	}
	for _, ov := range owners {
		om, err := obj(ov, "principal_id", "label")
		if err != nil {
			return r, err
		}
		var p Principal
		if p.PrincipalID, err = str(om, "principal_id", MaxIDLength); err != nil {
			return r, err
		}
		if p.Label, err = str(om, "label", MaxLabelLength); err != nil {
			return r, err
		}
		r.Owners = append(r.Owners, p)
	}
	return r, nil
}

// principalsFromValue decodes a role array (readers/writers/admins/owners).
func principalsFromValue(v *value) ([]Member, error) {
	items, err := listField(v, "principals", MaxPolicyArrayItems)
	if err != nil {
		return nil, err
	}
	out := make([]Member, len(items))
	for i := range items {
		m, err := obj(items[i], "principal_id", "label")
		if err != nil {
			return nil, err
		}
		if out[i].PrincipalID, err = str(m, "principal_id", MaxIDLength); err != nil {
			return nil, err
		}
		if out[i].Label, err = str(m, "label", MaxLabelLength); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func delegationFromValue(v *value) (AdminDelegation, error) {
	var d AdminDelegation
	m, err := obj(v, "delegation_id", "delegate_device_id", "granted_by", "scope", "scope_note", "expires_policy_seq")
	if err != nil {
		return d, err
	}
	if d.DelegationID, err = str(m, "delegation_id", MaxIDLength); err != nil {
		return d, err
	}
	if d.DelegateDevice, err = str(m, "delegate_device_id", MaxDeviceIDLength); err != nil {
		return d, err
	}
	if d.GrantedBy, err = str(m, "granted_by", MaxKeyIDLength); err != nil {
		return d, err
	}
	sm, err := obj(m["scope"],
		"invite_readers", "invite_writers", "remove_members", "remove_devices",
		"promote_admin", "promote_owner", "replace_root",
	)
	if err != nil {
		return d, err
	}
	for _, f := range []struct {
		key string
		dst *bool
	}{
		{"invite_readers", &d.Scope.InviteReaders},
		{"invite_writers", &d.Scope.InviteWriters},
		{"remove_members", &d.Scope.RemoveMembers},
		{"remove_devices", &d.Scope.RemoveDevices},
		{"promote_admin", &d.Scope.PromoteAdmin},
		{"promote_owner", &d.Scope.PromoteOwner},
		{"replace_root", &d.Scope.ReplaceRoot},
	} {
		if *f.dst, err = boolVal(sm, f.key); err != nil {
			return d, err
		}
	}
	if d.ScopeNote, err = str(m, "scope_note", MaxRoleScopeLength); err != nil {
		return d, err
	}
	if d.ExpiresPolicySeq, err = num(m, "expires_policy_seq"); err != nil {
		return d, err
	}
	return d, nil
}

func deviceFromValue(v *value) (Device, error) {
	var d Device
	m, err := obj(v, "device_id", "principal_id", "label", "content_signing_key", "policy_signing_key", "age_encryption_key")
	if err != nil {
		return d, err
	}
	if d.DeviceID, err = str(m, "device_id", MaxDeviceIDLength); err != nil {
		return d, err
	}
	if d.PrincipalID, err = str(m, "principal_id", MaxIDLength); err != nil {
		return d, err
	}
	if d.Label, err = str(m, "label", MaxLabelLength); err != nil {
		return d, err
	}
	if d.ContentSigningKey, err = publicKeyFromValue(m["content_signing_key"], false); err != nil {
		return d, err
	}
	pk, err := publicKeyFromValue(m["policy_signing_key"], true)
	if err != nil {
		return d, err
	}
	if m["policy_signing_key"].kind != kindNull {
		d.PolicySigningKey = &pk
	}
	if d.AgeEncryptionKey, err = str(m, "age_encryption_key", MaxPublicKeyLength); err != nil {
		return d, err
	}
	return d, nil
}

func publicKeyFromValue(v *value, nullable bool) (PublicKey, error) {
	var k PublicKey
	if v.kind == kindNull && nullable {
		return k, nil
	}
	m, err := obj(v, "alg", "public_key")
	if err != nil {
		return k, err
	}
	if k.Alg, err = str(m, "alg", len(SigAlgEd25519)); err != nil {
		return k, err
	}
	if k.PublicKey, err = bin(m, "public_key", MaxPublicKeyLength, false); err != nil {
		return k, err
	}
	return k, nil
}

func signatureFromValue(v *value) (Signature, error) {
	var s Signature
	m, err := obj(v, "signer_id", "alg", "sig")
	if err != nil {
		return s, err
	}
	if s.SignerID, err = str(m, "signer_id", MaxDeviceIDLength); err != nil {
		return s, err
	}
	if s.Alg, err = str(m, "alg", len(SigAlgEd25519)); err != nil {
		return s, err
	}
	// sig null is the unsigned-draft content signature; every other
	// signature member requires a value.
	if s.Sig, err = bin(m, "sig", MaxSignatureLength, true); err != nil {
		return s, err
	}
	return s, nil
}

func deviceSlotFromValue(v *value) (DeviceSlot, error) {
	var s DeviceSlot
	m, err := obj(v, "device_id", "recipient", "wrapped_vuk")
	if err != nil {
		return s, err
	}
	if s.DeviceID, err = str(m, "device_id", MaxDeviceIDLength); err != nil {
		return s, err
	}
	if s.Recipient, err = str(m, "recipient", MaxPublicKeyLength); err != nil {
		return s, err
	}
	if s.WrappedVUK, err = bin(m, "wrapped_vuk", MaxWrappedKeyLength, false); err != nil {
		return s, err
	}
	return s, nil
}

func cekSlotFromValue(v *value) (CEKSlot, error) {
	var s CEKSlot
	m, err := obj(v, "key_epoch", "wrapped_cek")
	if err != nil {
		return s, err
	}
	if s.KeyEpoch, err = num(m, "key_epoch"); err != nil {
		return s, err
	}
	if s.WrappedCEK, err = bin(m, "wrapped_cek", MaxWrappedKeyLength, false); err != nil {
		return s, err
	}
	return s, nil
}

func version(m map[string]*value, dst *int) error {
	n, err := num(m, "version")
	if err != nil {
		return err
	}
	if n != Version {
		return &Error{Code: CodeInvalidValue, Path: "version"}
	}
	*dst = int(n)
	return nil
}
