package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func mustEncode(t *testing.T) []byte {
	t.Helper()
	b, err := EncodeFile(buildFile())
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
	if q.PolicyDigest == nil {
		q.PolicyDigest = make([]byte, 32)
	} else {
		q.PolicyDigest = bytes.Clone(q.PolicyDigest)
	}
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
	f.SignedPolicyProofs[0].Policy = *cur
	// The header binds the domain-separated digest of the carried document,
	// not the opaque digest member inside it.
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
	b.WriteString(`,"header_sig":`)
	writeSignature(&b, &f.HeaderSig)
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
	standard := base64.StdEncoding.EncodeToString([]byte{0xfb, 0xef})
	_, err = ParseFile([]byte(strings.Replace(enc, `"policy_digest":"`+base64.RawURLEncoding.EncodeToString(digest("policy-7"))+`"`, `"policy_digest":"`+standard+`"`, 1)))
	wantCode(t, err, CodeInvalidValue)
}

func TestLimitsBeforeUse(t *testing.T) {
	enc := mustEncode(t)
	// Whole file over 32 MiB.
	big := append(append([]byte{}, enc...), make([]byte, MaxFileBytes)...)
	_, err := ParseFile(big)
	wantCode(t, err, CodeTooLarge)

	// Content above the ciphertext budget fails on the typed path ...
	f := buildFile()
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
	f := buildFile()
	p := f.SignedPolicyProofs[0].Policy
	p.Readers = append(p.Readers, Member{PrincipalID: "dave", Label: "Dave"})
	rebindProof(f, docFor(&p), "owner-root-01", PolicySigAlgEd25519)
	_, err := EncodeFile(f)
	wantCode(t, err, CodePolicyMismatch)

	f = buildFile()
	rebindProof(f, []byte(`{"format":"locklark.vault-file","version":1}`), "owner-root-01", PolicySigAlgEd25519)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeMissingField)

	// A proof must name a signer and a supported algorithm.
	f = buildFile()
	rebindProof(f, f.SignedPolicyProofs[0].Document, "owner-root-01", "rsa")
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)
}

func TestHeaderBinding(t *testing.T) {
	mutate := func(f *File) { f.Header.PolicySeq = 6 }
	f := buildFile()
	mutate(f)
	_, err := EncodeFile(f)
	wantCode(t, err, CodeHeaderMismatch)

	f = buildFile()
	f.Header.PolicyDigest = digest("other")
	_, err = EncodeFile(f)
	wantCode(t, err, CodeHeaderMismatch)
}

func TestSignerShape(t *testing.T) {
	// Content signature must name a valid device with a content key.
	f := buildFile()
	f.ContentSignature.SignerID = "device-9"
	_, err := EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	f = buildFile()
	f.ContentSignature.Sig = f.ContentSignature.Sig[:63]
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	f = buildFile()
	f.ContentSignature.Sig = nil
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	// Header signature must come from a device holding a policy key.
	f = buildFile()
	f.HeaderSig.Alg = "rsa"
	f.HeaderSig.Sig = f.HeaderSig.Sig[:32]
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	f = buildFile()
	f.HeaderSig.SignerID = "owner-root-01"
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)

	f = buildFile()
	f.HeaderSig.Sig = f.HeaderSig.Sig[:32]
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)
}

func TestPurposeSeparatedKeys(t *testing.T) {
	// The same bytes in the content role and the policy role must be rejected.
	f := buildFile()
	p := f.SignedPolicyProofs[0].Policy
	p.Devices[0].PolicySigningKey.PublicKey =
		append([]byte(nil), p.Devices[0].ContentSigningKey.PublicKey...)
	setPolicy(f, &p)
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// An age key slot whose recipient is not the device's key is rejected.
	f = buildFile()
	f.VUKDeviceSlots = f.VUKDeviceSlots[:1]
	f.VUKDeviceSlots[0].Recipient = f.SignedPolicyProofs[0].Policy.Devices[1].AgeEncryptionKey
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// A private key is never valid in a public-key member.
	f = buildFile()
	p = f.SignedPolicyProofs[0].Policy
	p.Devices[0].ContentSigningKey.PublicKey = make([]byte, ed25519.PrivateKeySize)
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// Delegations may never delegate owner promotion or root replacement.
	f = buildFile()
	p = f.SignedPolicyProofs[0].Policy
	p.AdminDelegations[0].Scope.PromoteOwner = true
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// A policy without any owner is rejected.
	f = buildFile()
	p = f.SignedPolicyProofs[0].Policy
	p.Owners = nil
	p.OwnerRoot.Owners = nil
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
}

func TestGenesisPrevDigest(t *testing.T) {
	f := buildFile()
	f.Header.ContentSeq = 0
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)
	f.Header.PrevDigest = nil
	if _, err := EncodeFile(f); err != nil {
		t.Fatal(err)
	}
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
	f := buildFile()
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
	f = buildFile()
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
	f := buildFile()
	p := f.SignedPolicyProofs[0].Policy
	p.Devices[1].PrincipalID = "carol"
	setPolicy(f, &p)
	f.Header.AuthorDeviceID = "device-2"
	f.HeaderSig.SignerID = "device-2"
	f.ContentSignature.SignerID = "device-2"
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// An owner may author.
	f = buildFile()
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("owner-authored file rejected: %v", err)
	}

	// A writer may author though it is not listed under readers.
	f = buildFile()
	f.Header.AuthorDeviceID = "device-2"
	f.HeaderSig.SignerID = "device-2"
	f.ContentSignature.SignerID = "device-2"
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("writer-authored file rejected: %v", err)
	}

	// A device not in the policy is still a signature-shape error.
	f = buildFile()
	f.Header.AuthorDeviceID = "device-9"
	_, err = EncodeFile(f)
	wantCode(t, err, CodeSignatureInvalid)
}

func TestVUKSlots(t *testing.T) {
	slotOf := func(p *Policy, id string) DeviceSlot {
		d := deviceByID(t, p, id)
		return DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("synthetic")}
	}

	// A slot for a device whose principal has no read role is rejected,
	// even with a matching recipient: that would hand it the vault key.
	f := buildFile()
	p := f.SignedPolicyProofs[0].Policy
	p.Writers = nil
	p.Devices[1].PrincipalID = "bob" // bob now has no role at all
	setPolicy(f, &p)
	_, err := EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	f = buildFile()
	p = f.SignedPolicyProofs[0].Policy
	p.Devices[1].PrincipalID = "dave"
	p.OwnerRoot.Owners = append(p.OwnerRoot.Owners, Principal{PrincipalID: "dave", Label: "Dave"})
	setPolicy(f, &p)
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// An approved device with a read role must have a slot.
	f = buildFile()
	f.VUKDeviceSlots = f.VUKDeviceSlots[:1]
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// A slot may only name a policy device; unknown and duplicate ids fail.
	f = buildFile()
	f.VUKDeviceSlots[1].DeviceID = "device-9"
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	f = buildFile()
	f.VUKDeviceSlots[1] = f.VUKDeviceSlots[0]
	_, err = EncodeFile(f)
	wantCode(t, err, CodeInvalidValue)

	// A device added to the policy needs its slot in the same file.
	f = buildFile()
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
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("complete slot set rejected: %v", err)
	}

	// Slots are matched as a set, not by position: an order-preserving
	// reordering of the same slots is still valid.
	base := mustEncode(t)
	enc := string(base)
	s0, s1 := string(mustSlotJSON(t, buildFile(), 0)), string(mustSlotJSON(t, buildFile(), 1))
	if !strings.Contains(enc, s0+","+s1) {
		t.Fatal("unexpected slot encoding in vector")
	}
	swapped := strings.Replace(enc, s0+","+s1, s1+","+s0, 1)
	if _, err := ParseFile([]byte(swapped)); err != nil {
		t.Fatalf("reordered slots rejected: %v", err)
	}
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

func TestValidWriterRoundTrip(t *testing.T) {
	// Bob is only a writer. His device authors the file and keeps exactly
	// its own slot beside the owner's; the encoding round-trips unchanged.
	f := buildFile()
	f.Header.AuthorDeviceID = "device-2"
	f.HeaderSig.SignerID = "device-2"
	f.ContentSignature.SignerID = "device-2"
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
