package vaultfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func mustEncode(t *testing.T) []byte {
	t.Helper()
	b, err := EncodeFile(buildFile(t))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// currentPolicy returns a copy of p paired with its document.
func currentPolicy(p *Policy, doc []byte) *Policy {
	return clonePolicy(p)
}

// docFor serializes a policy for a binding test without validating it; the
// mutation under test is what validation must reject.
func docFor(p *Policy) []byte {
	var b bytes.Buffer
	writePolicy(&b, p)
	return b.Bytes()
}

// clonePolicy deep-copies p so rebinding one copy never aliases another.
func clonePolicy(p *Policy) *Policy {
	q := *p
	q.PrevPolicyDigest = bytes.Clone(q.PrevPolicyDigest)
	q.OwnerRoot.PublicKey = bytes.Clone(q.OwnerRoot.PublicKey)
	q.OwnerRoot.Owners = append([]Principal(nil), p.OwnerRoot.Owners...)
	q.Devices = append([]Device(nil), p.Devices...)
	for i := range q.Devices {
		q.Devices[i].ContentSigningKey.PublicKey = bytes.Clone(p.Devices[i].ContentSigningKey.PublicKey)
		if p.Devices[i].PolicySigningKey != nil {
			k := *p.Devices[i].PolicySigningKey
			k.PublicKey = bytes.Clone(k.PublicKey)
			q.Devices[i].PolicySigningKey = &k
		}
	}
	q.Readers = append([]Member(nil), p.Readers...)
	q.Writers = append([]Member(nil), p.Writers...)
	q.Admins = append([]Member(nil), p.Admins...)
	q.Owners = append([]Member(nil), p.Owners...)
	q.AdminDelegations = append([]AdminDelegation(nil), p.AdminDelegations...)
	return &q
}

func encodePolicyPanic(p *Policy) []byte {
	doc, err := EncodePolicyDocument(p)
	if err != nil {
		panic(err)
	}
	return doc
}

// setPolicy replaces every proof with a fresh copy of p and rebinds the
// header policy seq/digest to it.
func setPolicy(f *File, p *Policy) {
	doc := docFor(p)
	cur := currentPolicy(p, doc)
	f.Header.PolicySeq = cur.PolicySeq
	f.SignedPolicyProofs[0].Document = doc
	f.SignedPolicyProofs[0].Policy = *clonePolicy(cur)
	// The header binds the domain-separated digest of the carried document.
	f.Header.PolicyDigest = policyDigest(&f.SignedPolicyProofs[0])
}

// rebind proof with a fresh document that is not paired and binds header
// policy digest to it, so later checks see a consistent header.
func rebindProof(f *File, doc []byte, signer string, alg string) {
	sp := &f.SignedPolicyProofs[0]
	sp.Document = doc
	sp.SignerID = signer
	sp.Alg = alg
	f.Header.PolicyDigest = policyDigest(sp)
}

// mustEncodeWith encodes a possibly invalid file by trusting only its wire
// shape, so that decode limits can be tested independently of validation.
func mustEncodeWith(t *testing.T, f *File) string {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(`{"format":`)
	b.WriteString(quote(f.Format))
	b.WriteString(`,"version":` + itoa(uint64(Version)) + `,"header":`)
	writeHeader(&b, &f.Header)
	b.WriteString(`,"signed_policy_proofs":`)
	writeArray(&b, len(f.SignedPolicyProofs), func(i int) {
		sp := &f.SignedPolicyProofs[i]
		b.WriteString(`{"document":`)
		writeBytesRaw(&b, sp.Document)
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
	writeBytesRaw(&b, f.KDBXCiphertext)
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
	b.WriteString(`},"content_signature":`)
	writeSignature(&b, &f.ContentSignature)
	b.WriteByte('}')
	return b.String()
}

func writeBytesRaw(b *bytes.Buffer, v []byte) {
	if v == nil {
		b.WriteString("null")
		return
	}
	b.WriteByte('"')
	b.WriteString(base64.RawURLEncoding.EncodeToString(v))
	b.WriteByte('"')
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q, got nil", code)
	}
	e, ok := AsError(err)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if e.Code != code {
		t.Fatalf("expected code %q, got %q (%v)", code, e.Code, err)
	}
}

func TestRoundTrip(t *testing.T) {
	enc := mustEncode(t)
	f, err := ParseFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(f); err != nil {
		t.Fatal(err)
	}
	again, err := EncodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, again) {
		t.Fatal("round trip is not byte-stable")
	}
}

func TestStrictJSON(t *testing.T) {
	enc := mustEncode(t)
	ref := buildPolicy()
	doc, err := EncodePolicyDocument(ref)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		in   []byte
		code string
	}{
		{"trailing object", append(append([]byte{}, enc...), []byte(`{}`)...), CodeTrailingData},
		{"trailing value", append(append([]byte{}, enc...), []byte(` 1`)...), CodeTrailingData},
		{"trailing garbage", append(append([]byte{}, enc...), []byte(` x`)...), CodeTrailingData},
		{"leading junk", append([]byte(`x`), enc...), CodeInvalidJSON},
		{"unknown top-level", []byte(strings.Replace(string(enc), `"format":`, `"extra":1,"format":`, 1)), CodeUnknownField},
		{"duplicate top-level", []byte(strings.Replace(string(enc), `"format":`, `"format":"locklark.vault-file","format":`, 1)), CodeDuplicateField},
		{"unknown nested", []byte(strings.Replace(string(enc), `"vault_id":`, `"nope":1,"vault_id":`, 1)), CodeUnknownField},
		{"duplicate nested", []byte(strings.Replace(string(enc), `"vault_id":`, `"vault_id":"vault-01","vault_id":`, 1)), CodeDuplicateField},
		{"missing member", []byte(strings.Replace(string(enc), `,"op_id":"op-0042"`, ``, 1)), CodeMissingField},
		{"wrong wire version", []byte(strings.Replace(string(enc), `"version":1`, `"version":3`, 1)), CodeInvalidValue},
		{"not an object", []byte(`[]`), CodeWrongType},
		{"empty", nil, CodeInvalidJSON},
		{"truncated", enc[:len(enc)/2], CodeInvalidJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseFile(c.in)
			wantCode(t, err, c.code)
			if codeIs(c.code, CodeTrailingData, CodeInvalidJSON) &&
				!strings.Contains(err.Error(), "vaultfile: ") {
				t.Fatalf("error message shape: %v", err)
			}
		})
	}
	// The same strict rules hold for policy documents.
	_, err = ParsePolicyDocument(append(append([]byte{}, doc...), []byte("{}")...))
	wantCode(t, err, CodeTrailingData)
	_, err = ParsePolicyDocument([]byte(strings.Replace(string(doc), `"vault_id":`, `"x":1,"vault_id":`, 1)))
	wantCode(t, err, CodeUnknownField)
	_, err = ParsePolicyDocument([]byte(strings.Replace(string(doc), `"policy_seq":7`, `"policy_seq":7.0`, 1)))
	wantCode(t, err, CodeInvalidValue)
}

func codeIs(c string, opts ...string) bool {
	for _, o := range opts {
		if o == c {
			return true
		}
	}
	return false
}

func TestJSONValueRules(t *testing.T) {
	enc := string(mustEncode(t))
	for _, bad := range []string{`"key_epoch":3.0`, `"key_epoch":3.5`, `"key_epoch":-1`, `"key_epoch":1e3`} {
		_, err := ParseFile([]byte(strings.Replace(enc, `"key_epoch":3`, bad, 1)))
		wantCode(t, err, CodeInvalidValue)
	}
	// Numbers written as strings are rejected as the wrong type.
	_, err := ParseFile([]byte(strings.Replace(enc, `"key_epoch":3`, `"key_epoch":"3"`, 1)))
	wantCode(t, err, CodeWrongType)
	_, err = ParseFile([]byte(strings.Replace(enc, `"key_epoch":3`, `"key_epoch":18446744073709551616`, 1)))
	wantCode(t, err, CodeLimitExceeded)
	// base64 member must be canonical unpadded base64url.
	wrapped := base64.RawURLEncoding.EncodeToString([]byte("synthetic-vuk-wrapped-cek"))
	_, err = ParseFile([]byte(strings.Replace(enc, wrapped, wrapped+"==", 1)))
	wantCode(t, err, CodeInvalidValue)
	// The same holds for the policy document's own binary members: a standard
	// base64 alphabet must not stand in for canonical base64url.
	standard := base64.StdEncoding.EncodeToString([]byte{0xfb, 0xef})
	doc := string(mustEncodeDoc(t))
	prev := base64.RawURLEncoding.EncodeToString(digest("policy-6"))
	_, err = ParsePolicyDocument([]byte(strings.Replace(doc, `"prev_policy_digest":"`+prev+`"`, `"prev_policy_digest":"`+standard+`"`, 1)))
	wantCode(t, err, CodeInvalidValue)
}

func TestLimitsBeforeUse(t *testing.T) {
	enc := mustEncode(t)
	// Whole file over 32 MiB.
	big := append(append([]byte{}, enc...), make([]byte, MaxFileBytes)...)
	_, err := ParseFile(big)
	wantCode(t, err, CodeTooLarge)

	// Content above the ciphertext budget fails on the typed path ...
	f := buildFile(t)
	f.KDBXCiphertext = make([]byte, MaxKDBXCiphertextBytes+1)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeLimitExceeded)
	// ... and on decode before anything is copied far past the budget.
	_, err = ParseFile([]byte(mustEncodeWith(t, f)))
	wantCode(t, err, CodeBytesTooLong)
	if MaxKDBXCiphertextBytes > MaxPlaintextBytes && MaxKDBXCiphertextBytes-MaxPlaintextBytes > MaxKDBXCiphertextOverhead {
		t.Fatal("overhead budget exceeded")
	}

	// String over its type limit before decode.
	long := strings.Repeat("a", MaxIDLength+1)
	_, err = ParseFile([]byte(strings.Replace(string(enc), `"op_id":"op-0042"`, `"op_id":"`+long+`"`, 1)))
	wantCode(t, err, CodeStringTooLong)

	// Array over limit.
	many := strings.Repeat(`{"principal_id":"p","label":"P"},`, MaxPolicyArrayItems)
	badPolicy := strings.Replace(string(mustEncodeDoc(t)), `"readers":[`, `"readers":[`+many, 1)
	_, err = ParsePolicyDocument([]byte(badPolicy))
	wantCode(t, err, CodeTooManyItems)

	// Nesting over limit.
	deep := strings.Repeat(`[`, MaxJSONDepth+2) + strings.Repeat(`]`, MaxJSONDepth+2)
	_, err = ParseFile([]byte(`["k",` + deep + `]`))
	wantCode(t, err, CodeTooDeep)
}

func mustEncodeDoc(t *testing.T) []byte {
	t.Helper()
	b, err := EncodePolicyDocument(buildPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPolicyDocumentBinding(t *testing.T) {
	f := buildFile(t)
	p := f.SignedPolicyProofs[0].Policy
	p.Readers = append(p.Readers, Member{PrincipalID: "dave", Label: "Dave"})
	rebindProof(f, docFor(&p), "owner-root-01", PolicySigAlgEd25519)
	_, err := EncodeFile(f)
	wantCode(t, err, CodePolicyMismatch)

	f = buildFile(t)
	rebindProof(f, []byte(`{"format":"locklark.vault-file","version":1}`), "owner-root-01", PolicySigAlgEd25519)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeMissingField)

	// A proof must name a signer and a supported algorithm.
	f = buildFile(t)
	rebindProof(f, f.SignedPolicyProofs[0].Document, "owner-root-01", "rsa")
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)
}

func TestHeaderBinding(t *testing.T) {
	mutate := func(f *File) { f.Header.PolicySeq = 6 }
	f := buildFile(t)
	mutate(f)
	_, err := EncodeFile(f)
	wantCode(t, err, CodeHeaderMismatch)

	f = buildFile(t)
	f.Header.PolicyDigest = digest("other")
	_, err = EncodeFile(f)
	wantCode(t, err, CodeHeaderMismatch)
}

func TestSignerShape(t *testing.T) {
	// Content signature must name a valid device with a content key.
	f := buildFile(t)
	f.ContentSignature.SignerID = "device-9"
	_, err := EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	f = buildFile(t)
	f.ContentSignature.Sig = f.ContentSignature.Sig[:63]
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	// A null sig is never a wire value: a sealed file with a null sig is
	// rejected, and an in-memory draft is not encodable at all.
	f = buildFile(t)
	f.ContentSignature.Sig = nil
	_, err = EncodeFile(f)
	wantCodeAt(t, err, CodeInvalidValue, "content_signature")
	_, err = EncodeFile(buildDraft(t))
	wantCodeAt(t, err, CodeInvalidValue, "content_signature")

	// The content signature must have the author device's content key shape.
	f = buildFile(t)
	f.ContentSignature.Alg = "rsa"
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	// The signer must be the authoring device itself.
	f = buildFile(t)
	f.ContentSignature.SignerID = "device-2"
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)
}

func TestPurposeSeparatedKeys(t *testing.T) {
	// The same bytes in the content role and the policy role must be rejected.
	f := buildFile(t)
	p := f.SignedPolicyProofs[0].Policy
	p.Devices[0].PolicySigningKey.PublicKey =
		append([]byte(nil), p.Devices[0].ContentSigningKey.PublicKey...)
	setPolicy(f, &p)
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// An age key slot whose recipient is not the device's key is rejected.
	f = buildFile(t)
	f.VUKDeviceSlots = f.VUKDeviceSlots[:1]
	f.VUKDeviceSlots[0].Recipient = f.SignedPolicyProofs[0].Policy.Devices[1].AgeEncryptionKey
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// Delegations may never delegate owner promotion or root replacement.
	f = buildFile(t)
	p = f.SignedPolicyProofs[0].Policy
	p.AdminDelegations[0].Scope.PromoteOwner = true
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// A policy without any owner is rejected.
	f = buildFile(t)
	p = f.SignedPolicyProofs[0].Policy
	p.Owners = nil
	p.OwnerRoot.Owners = nil
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
}

func TestGenesisPrevDigest(t *testing.T) {
	f := buildFile(t)
	f.Header.ContentSeq = 0
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
	f.Header.PrevDigest = nil
	reseal(t, f)
	if _, err := EncodeFile(f); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyDigestContract pins the single policy digest definition: it is
// computed outside the policy, referenced by Header.PolicyDigest, and the next
// policy's PrevPolicyDigest is the same value.
func TestPolicyDigestContract(t *testing.T) {
	f := buildFile(t)
	sp := &f.SignedPolicyProofs[0]

	// SHA-256(domain || NUL || canonical document bytes), computed by hand.
	h := sha256.New()
	h.Write([]byte(UsagePolicyDocument))
	h.Write([]byte{0})
	doc, err := EncodePolicyDocument(&sp.Policy)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(doc)
	want := h.Sum(nil)
	if got := PolicyDigest(&sp.Policy); !bytes.Equal(got, want) {
		t.Fatalf("PolicyDigest = %x, want %x", got, want)
	}
	if !bytes.Equal(f.Header.PolicyDigest, want) {
		t.Fatal("Header.PolicyDigest does not reference the policy digest")
	}

	// The digest is not carried inside the policy, neither on the wire nor
	// as a member of the carried document.
	if strings.Contains(string(doc), `"policy_digest"`) {
		t.Fatal("policy document carries a policy_digest member")
	}
	_, err = ParsePolicyDocument([]byte(strings.Replace(string(doc), `"policy_seq":7,`, `"policy_seq":7,"policy_digest":"`+base64.RawURLEncoding.EncodeToString(want)+`",`, 1)))
	wantCode(t, err, CodeUnknownField)

	// The next policy references the same value as its predecessor.
	next := clonePolicy(&sp.Policy)
	next.PolicySeq = 8
	next.PrevPolicyDigest = PolicyDigest(&sp.Policy)
	nextDoc, err := EncodePolicyDocument(next)
	if err != nil {
		t.Fatalf("policy chained to the digest rejected: %v", err)
	}
	if strings.Contains(string(nextDoc), `"policy_digest":"`+base64.RawURLEncoding.EncodeToString(next.PrevPolicyDigest)+`"`) {
		t.Fatal("next policy carries its predecessor digest inside the document instead of only in prev_policy_digest")
	}
	if prev := next.PrevPolicyDigest; !bytes.Equal(prev, want) {
		t.Fatalf("next PrevPolicyDigest = %x, want %x", prev, want)
	}
	// Genesis: no predecessor. A genesis policy with a predecessor digest is
	// rejected; a later policy without one is rejected too.
	next.PolicySeq = 0
	_, err = EncodePolicyDocument(next)
	wantCode(t, err, CodeInvalidValue)
	next.PolicySeq = 8
	next.PrevPolicyDigest = nil
	_, err = EncodePolicyDocument(next)
	wantCode(t, err, CodeInvalidValue)
}

func TestFineGrantedWithoutCrypto(t *testing.T) {
	// Shape-only validation is on purpose: random signature bytes pass
	// ValidateFile. No cryptographic verification happens here.
	f, err := ParseFile(mustEncode(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(f); err != nil {
		t.Fatal(err)
	}
}

// deviceByID returns a copy of the given device of p.
func deviceByID(t *testing.T, p *Policy, id string) Device {
	t.Helper()
	d := findDevice(p, id)
	if d == nil {
		t.Fatalf("device %q not in policy", id)
	}
	return *d
}

func TestDevicePrincipalRequired(t *testing.T) {
	// The principal is mandatory on the typed path ...
	f := buildFile(t)
	f.SignedPolicyProofs[0].Policy.Devices[0].PrincipalID = ""
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
	if _, err := EncodePolicyDocument(buildPolicy()); err != nil {
		t.Fatal(err)
	}

	// ... and on the wire: a device without principal_id is rejected before
	// validation, and a device that names one the policy does not know is
	// rejected by validation.
	enc := string(mustEncode(t))
	noPrincipal := strings.Replace(enc, `"principal_id":"alice","label":"Alice laptop"`, `"label":"Alice laptop"`, 1)
	_, err = ParseFile([]byte(noPrincipal))
	wantCode(t, err, CodeMissingField)

	unknown := strings.Replace(enc, `"device_id":"device-2","principal_id":"bob"`, `"device_id":"device-2","principal_id":"mallory"`, 1)
	_, err = ParseFile([]byte(unknown))
	wantCode(t, err, CodeInvalidValue)

	// A principal in the owner root but in no role array grants no device.
	f = buildFile(t)
	p := f.SignedPolicyProofs[0].Policy
	p.OwnerRoot.Owners = append(p.OwnerRoot.Owners, Principal{PrincipalID: "dave", Label: "Dave"})
	p.Devices[1].PrincipalID = "dave"
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
}

func TestRoleImplication(t *testing.T) {
	// A writer implicitly reads; it is not listed under readers.
	p := buildPolicy()
	if !p.hasRole("bob", RoleReader) || !p.hasRole("bob", RoleWriter) || p.hasRole("bob", RoleAdmin, RoleOwner) {
		t.Fatal("role implication for writer is wrong")
	}
	// An owner implicitly writes and administers.
	if !p.hasRole("alice", RoleReader, RoleWriter, RoleAdmin) {
		t.Fatal("role implication for owner is wrong")
	}
	// A reader reads and nothing more.
	if !p.hasRole("carol", RoleReader) || p.hasRole("carol", RoleWriter, RoleAdmin, RoleOwner) {
		t.Fatal("role implication for reader is wrong")
	}
	if p.hasRole("nobody", RoleReader, RoleWriter, RoleAdmin, RoleOwner) {
		t.Fatal("unknown principal has a role")
	}
}

func TestAuthorRole(t *testing.T) {
	// A device whose principal is only a reader may not author a file.
	f := buildFile(t)
	p := f.SignedPolicyProofs[0].Policy
	p.Devices[1].PrincipalID = "carol"
	setPolicy(f, &p)
	f.Header.AuthorDeviceID = "device-2"
	f.ContentSignature.SignerID = "device-2"
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// An owner may author.
	f = buildFile(t)
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("owner-authored file rejected: %v", err)
	}

	// A writer may author though it is not listed under readers.
	f = buildFile(t)
	f.Header.AuthorDeviceID = "device-2"
	f.ContentSignature.SignerID = "device-2"
	reseal(t, f)
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("writer-authored file rejected: %v", err)
	}

	// A device not in the policy holds no role and is rejected, in either
	// signature state.
	f = buildFile(t)
	f.Header.AuthorDeviceID = "device-9"
	f.ContentSignature.SignerID = "device-9"
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
	_, err = SealFile(fdraftWithAuthor(t, "device-9"), &f.ContentSignature)
	wantCode(t, err, CodeInvalidValue)
}

func TestVUKSlots(t *testing.T) {
	slotOf := func(p *Policy, id string) DeviceSlot {
		d := deviceByID(t, p, id)
		return DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("synthetic")}
	}

	// A slot for a device whose principal has no read role is rejected,
	// even with a matching recipient: that would hand it the vault key.
	f := buildFile(t)
	p := f.SignedPolicyProofs[0].Policy
	p.Writers = nil
	p.Devices[1].PrincipalID = "bob" // bob now has no role at all
	setPolicy(f, &p)
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	f = buildFile(t)
	p = f.SignedPolicyProofs[0].Policy
	p.Devices[1].PrincipalID = "dave"
	p.OwnerRoot.Owners = append(p.OwnerRoot.Owners, Principal{PrincipalID: "dave", Label: "Dave"})
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// An approved device with a read role must have a slot.
	f = buildFile(t)
	f.VUKDeviceSlots = f.VUKDeviceSlots[:1]
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// A slot may only name a policy device; unknown and duplicate ids fail.
	f = buildFile(t)
	f.VUKDeviceSlots[1].DeviceID = "device-9"
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	f = buildFile(t)
	f.VUKDeviceSlots[1].DeviceID = f.VUKDeviceSlots[0].DeviceID
	_, err = EncodeFile(f)
	wantCodeAt(t, err, CodeUnsortedCollection, "vuk_device_slots[1]")

	// A device added to the policy needs its slot in the same file.
	f = buildFile(t)
	p = f.SignedPolicyProofs[0].Policy
	// carol already holds a device, so the new one goes to another reader.
	p.Readers = append(p.Readers, Member{PrincipalID: "erin", Label: "Erin"})
	p.Devices = append(p.Devices, Device{
		DeviceID:          "device-3",
		PrincipalID:       "erin",
		Label:             "Erin desktop",
		ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x61, 32)},
		AgeEncryptionKey:  ageRecipient(clientKey("device-3")),
	})
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
	f.VUKDeviceSlots = append(f.VUKDeviceSlots, slotOf(&f.SignedPolicyProofs[0].Policy, "device-3"))
	reseal(t, f)
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("complete slot set rejected: %v", err)
	}

	// Slot membership is a set, but its wire order is frozen: exactly
	// strictly increasing device_id. A reordering of the same slots is not
	// accepted, and is reported before the revision id can matter.
	base := mustEncode(t)
	enc := string(base)
	s0, s1 := string(mustSlotJSON(t, buildFile(t), 0)), string(mustSlotJSON(t, buildFile(t), 1))
	if !strings.Contains(enc, s0+","+s1) {
		t.Fatal("unexpected slot encoding in vector")
	}
	swapped := strings.Replace(enc, s0+","+s1, s1+","+s0, 1)
	if swapped == enc {
		t.Fatal("slots were not reordered")
	}
	if _, err := ParseFile([]byte(swapped)); err != nil {
		wantCodeAt(t, err, CodeUnsortedCollection, "vuk_device_slots[1]")
	} else {
		t.Fatal("reordered slots accepted")
	}
	// The same slot set in a type value is still rejected: no encoder sorts
	// it into the frozen order. The file is not resealed, because SealFile
	// validates first and rejects the order before deriving a revision id,
	// so no sealed file can carry it.
	reordered := buildFile(t)
	reordered.VUKDeviceSlots[0], reordered.VUKDeviceSlots[1] = reordered.VUKDeviceSlots[1], reordered.VUKDeviceSlots[0]
	_, err = EncodeFile(reordered)
	wantCodeAt(t, err, CodeUnsortedCollection, "vuk_device_slots[1]")
	// Equal device ids are rejected by the same rule, before the duplicate
	// membership check the slot set already had. As above, this defect cannot
	// be resealed, so the file keeps its original revision id.
	duplicated := buildFile(t)
	duplicated.VUKDeviceSlots[1].DeviceID = duplicated.VUKDeviceSlots[0].DeviceID
	_, err = EncodeFile(duplicated)
	wantCodeAt(t, err, CodeUnsortedCollection, "vuk_device_slots[1]")
}

func mustSlotJSON(t *testing.T, f *File, i int) []byte {
	t.Helper()
	var b bytes.Buffer
	s := &f.VUKDeviceSlots[i]
	b.WriteString(`{"device_id":`)
	b.WriteString(quote(s.DeviceID))
	b.WriteString(`,"recipient":`)
	b.WriteString(quote(s.Recipient))
	b.WriteString(`,"wrapped_vuk":`)
	writeBytes(&b, s.WrappedVUK)
	b.WriteByte('}')
	return b.Bytes()
}

// fdraftWithAuthor returns the in-memory draft authored by device id.
func fdraftWithAuthor(t *testing.T, id string) *File {
	f := buildDraft(t)
	f.Header.AuthorDeviceID = id
	return f
}

func TestValidWriterRoundTrip(t *testing.T) {
	// Bob is only a writer. His device authors the file and keeps exactly
	// its own slot beside the owner's; the encoding round-trips unchanged.
	f := buildFile(t)
	f.Header.AuthorDeviceID = "device-2"
	f.ContentSignature.SignerID = "device-2"
	reseal(t, f)
	enc, err := EncodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, again) {
		t.Fatal("writer round trip is not byte-stable")
	}
	p := &got.SignedPolicyProofs[0].Policy
	for _, d := range p.Devices {
		if got.Header.AuthorDeviceID == d.DeviceID && d.PrincipalID != "bob" {
			t.Fatalf("author device principal = %q, want bob", d.PrincipalID)
		}
	}
	if len(got.VUKDeviceSlots) != 2 {
		t.Fatalf("slots = %d, want 2", len(got.VUKDeviceSlots))
	}
}

// twoProofFile returns f authored by device-3: a new writer device that only
// the current policy knows. The current policy is otherwise the vector policy
// (policy_seq 7), so f is a valid sealed file:
//
//	proofs[0]: policy_seq 6, the genuine predecessor of the current policy
//	proofs[1]: policy_seq 7, the current policy, not first
//
// Proof order is frozen to strictly increasing policy_seq, so this old-then-
// current file is valid.
func twoProofFile(t *testing.T) *File {
	t.Helper()
	f := buildFile(t)
	// reseal replaces the revision id of a stale one, it never accepts it.
	f.Header.RevisionID = ""
	cur := clonePolicy(&f.SignedPolicyProofs[0].Policy)
	old := clonePolicy(cur)
	// The older proof's own sequence, never the header's: the shared
	// fixtures may leave a zero header behind. Both digests are fresh
	// slices: clonePolicy does not copy PrevPolicyDigest.
	old.PolicySeq = cur.PolicySeq - 1
	old.PrevPolicyDigest = digest("policy-5")
	cur.PrevPolicyDigest = bytes.Clone(PolicyDigest(old))
	// device-3 is a new device of bob, a writer, added in the current
	// policy only.
	cur.Devices = append(cur.Devices, Device{
		DeviceID:          "device-3",
		PrincipalID:       "bob",
		Label:             "Bob tablet",
		ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x61, 32)},
		AgeEncryptionKey:  ageRecipient(clientKey("device-3")),
	})
	f.VUKDeviceSlots = append(f.VUKDeviceSlots,
		DeviceSlot{DeviceID: "device-3", Recipient: ageRecipient(clientKey("device-3")), WrappedVUK: []byte("synthetic-age-wrapped-vuk-3")})
	f.Header.AuthorDeviceID = "device-3"
	f.ContentSignature.SignerID = "device-3"
	return sealTwoProof(t, f, old, cur)
}

// sealTwoProof writes old then cur as the two proofs of f, binds the header to
// cur and reseals f. It fails if the fixture is not itself a valid file.
func sealTwoProof(t *testing.T, f *File, old, cur *Policy) *File {
	t.Helper()
	f.SignedPolicyProofs = []SignedPolicy{
		{Document: docFor(old), Policy: *old, SignerID: "owner-root-01", Alg: PolicySigAlgEd25519, Sig: pf(0x43, 64)},
		{Document: docFor(cur), Policy: *cur, SignerID: "owner-root-01", Alg: PolicySigAlgEd25519, Sig: pf(0x44, 64)},
	}
	f.Header.PolicySeq = cur.PolicySeq
	f.Header.PolicyDigest = policyDigest(&f.SignedPolicyProofs[1])
	reseal(t, f)
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("two-proof fixture is not a valid file: %v", err)
	}
	return f
}

// modifyCurrent returns a mutable copy of the current (second) proof policy
// of a twoProofFile.
func modifyCurrent(f *File) *Policy {
	return clonePolicy(&f.SignedPolicyProofs[1].Policy)
}

// writeCurrent installs cur as the current (second) proof of f and rebinds the
// header policy digest to it, leaving the older first proof in place. The
// older proof stays the predecessor cur chains to.
func writeCurrent(t *testing.T, f *File, cur *Policy) {
	t.Helper()
	cur.PrevPolicyDigest = bytes.Clone(PolicyDigest(&f.SignedPolicyProofs[0].Policy))
	f.SignedPolicyProofs[1] = SignedPolicy{
		Document: docFor(cur), Policy: *cur,
		SignerID: "owner-root-01", Alg: PolicySigAlgEd25519, Sig: pf(0x44, 64),
	}
	f.Header.PolicySeq = cur.PolicySeq
	f.Header.PolicyDigest = policyDigest(&f.SignedPolicyProofs[1])
}

// sealNegativeFixture binds f.Header.RevisionID to the direct internal
// revisionHash of f, so a wire-rejected fixture still carries a
// well-formed revision id and fails on the rule under test, not on a stale
// one. It never goes through SealFile: that validates first and rejects the
// very rule this fixture is about to test.
func sealNegativeFixture(t *testing.T, f *File) {
	t.Helper()
	rev, err := revisionHash(f)
	if err != nil {
		t.Fatalf("negative fixture revision hash: %v", err)
	}
	f.Header.RevisionID = hex.EncodeToString(rev)
}

// TestCurrentPolicyNotFirstProof is the regression for a file whose current
// policy proof is not the first one: the author device and the slots are
// checked against the policy at header policy_seq, not proofs[0]. A new
// writer device known only to the current proof may author such a file, and
// an author without the writer role in the current policy is still rejected.
func TestCurrentPolicyNotFirstProof(t *testing.T) {
	f := twoProofFile(t)
	if f.SignedPolicyProofs[0].Policy.PolicySeq == f.Header.PolicySeq || len(f.SignedPolicyProofs) != 2 {
		t.Fatalf("fixture proofs are not old-then-current: %d vs %d",
			f.SignedPolicyProofs[0].Policy.PolicySeq, f.Header.PolicySeq)
	}
	enc, err := EncodeFile(f)
	if err != nil {
		t.Fatalf("valid file with a non-leading current proof rejected: %v", err)
	}
	got, err := ParseFile(enc)
	if err != nil {
		t.Fatalf("parsing valid file with a non-leading current proof: %v", err)
	}
	if got.Header.AuthorDeviceID != "device-3" || findDevice(&got.SignedPolicyProofs[0].Policy, "device-3") != nil {
		t.Fatal("fixture no longer authors from a device outside the first proof")
	}

	// The current policy is not required to be the first proof, but proofs
	// must be strictly increasing by policy_seq: a swapped (current-first)
	// sequence is rejected. It is not resealed: reseal validates first and
	// cannot produce a sealed invalid-order file, so order is rejected before
	// the stale revision id is even reached.
	swapped := twoProofFile(t)
	swapped.SignedPolicyProofs[0], swapped.SignedPolicyProofs[1] = swapped.SignedPolicyProofs[1], swapped.SignedPolicyProofs[0]
	_, err = EncodeFile(swapped)
	wantCodeAt(t, err, CodeUnsortedCollection, "signed_policy_proofs[1].policy.policy_seq")

	// A truly unauthorized author is still rejected: device-4 is a new device
	// of carol, a reader, known to the current policy only.
	f = twoProofFile(t)
	cur := modifyCurrent(f)
	cur.Devices = append(cur.Devices, Device{
		DeviceID:          "device-4",
		PrincipalID:       "carol",
		Label:             "Carol tablet",
		ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x62, 32)},
		AgeEncryptionKey:  ageRecipient(clientKey("device-4")),
	})
	f.VUKDeviceSlots = append(f.VUKDeviceSlots,
		DeviceSlot{DeviceID: "device-4", Recipient: ageRecipient(clientKey("device-4")), WrappedVUK: []byte("synthetic-age-wrapped-vuk-4")})
	f.Header.AuthorDeviceID = "device-4"
	f.ContentSignature.SignerID = "device-4"
	writeCurrent(t, f, cur)
	// A negative fixture cannot be sealed: SealFile rejects the unauthorized
	// author before the wire path is reached. Bind the revision directly and
	// check the wire entry points instead.
	sealNegativeFixture(t, f)
	wantCode(t, ValidateFile(f), CodeInvalidValue)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
	_, err = RevisionID(f)
	wantCode(t, err, CodeInvalidValue)

	// An author device the older proof lists as bob's stays rejected when the
	// current policy no longer grants bob the writer role.
	f = twoProofFile(t)
	cur = modifyCurrent(f)
	cur.Writers = nil
	f.Header.AuthorDeviceID = "device-2"
	f.ContentSignature.SignerID = "device-2"
	writeCurrent(t, f, cur)
	sealNegativeFixture(t, f)
	if findDevice(&f.SignedPolicyProofs[0].Policy, "device-2") == nil || !f.SignedPolicyProofs[0].Policy.hasRole("bob", RoleWriter) {
		t.Fatal("fixture: older proof must still list device-2 for bob as a writer")
	}
	wantCode(t, ValidateFile(f), CodeInvalidValue)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
	_, err = RevisionID(f)
	wantCode(t, err, CodeInvalidValue)

	// bob still a writer in the current policy: the same file is valid, so
	// the rejection above is the current author role and not the fixture.
	f = twoProofFile(t)
	f.Header.AuthorDeviceID = "device-2"
	f.ContentSignature.SignerID = "device-2"
	reseal(t, f)
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("writer-authored two-proof file rejected: %v", err)
	}
}
