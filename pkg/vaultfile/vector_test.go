package vaultfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

var updateVectors = flag.Bool("update", false, "rewrite testdata/vaultfile-v1-vectors.json")

// pf is a deterministic filler so every vector is reproducible.
func pf(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7) ^ byte(i>>3)
	}
	return b
}

// clientKey is a deterministic X25519 scalar. The clamp is the one RFC 7748
// applies, so age's secret-key encoding and the scalar here carry the same
// 32 bytes.
func clientKey(label string) []byte {
	k := DomainSeparated(UsageVaultID, []byte("vector-key/"+label))
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

// ageRecipient derives the real age1 recipient (62 characters, genuine
// Bech32 checksum) for an X25519 scalar through filippo.io/age: the secret
// key is parsed by age and the recipient is what age itself emits. No
// checksum is computed in this package.
func ageRecipient(scalar []byte) string {
	id, err := age.ParseX25519Identity(ageSecretKey(scalar))
	if err != nil {
		panic(err)
	}
	return id.Recipient().String()
}

// ageSecretKey is the age identity text for scalar: the bech32 secret-key
// encoding of filippo.io/age, upper-cased exactly as age prints it.
func ageSecretKey(scalar []byte) string {
	s, err := bech32Encode("AGE-SECRET-KEY-", scalar)
	if err != nil {
		panic(err)
	}
	return strings.ToUpper(s)
}

// bech32Encode is the BIP-173 bech32 encoding that age uses (checksum
// constant 1), ported verbatim from age's internal bech32 package because
// that package is not importable from outside age. It is used only in tests
// and only to turn a scalar into the secret-key text age accepts; every
// recipient in the vectors comes out of age's own encoder.
func bech32Encode(hrp string, payload []byte) (string, error) {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	generator := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	polymod := func(values []byte) uint32 {
		chk := uint32(1)
		for _, v := range values {
			top := chk >> 25
			chk = (chk & 0x1ffffff) << 5
			chk = chk ^ uint32(v)
			for i := 0; i < 5; i++ {
				if top>>i&1 == 1 {
					chk ^= generator[i]
				}
			}
		}
		return chk
	}
	var data []byte
	acc := uint32(0)
	bits := byte(0)
	for _, value := range payload {
		acc = acc<<8 | uint32(value)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data = append(data, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		data = append(data, byte(acc<<(5-bits))&31)
	}
	hrp = strings.ToLower(hrp)
	if len(hrp) < 1 {
		return "", fmt.Errorf("invalid HRP")
	}
	for _, c := range []byte(hrp) {
		if c < 33 || c > 126 {
			return "", fmt.Errorf("invalid HRP character")
		}
	}
	var expansion []byte
	for _, c := range []byte(hrp) {
		expansion = append(expansion, c>>5)
	}
	expansion = append(expansion, 0)
	for _, c := range []byte(hrp) {
		expansion = append(expansion, c&31)
	}
	values := append([]byte{}, expansion...)
	values = append(values, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, p := range data {
		sb.WriteByte(charset[p])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(charset[mod>>uint(5*(5-i))&31])
	}
	return sb.String(), nil
}

// ageRecipientCorruptChecksum flips one data character of r; the 32 key bytes
// are unchanged, so only a checksum check can reject the result.
func ageRecipientCorruptChecksum(r string) string {
	const b64 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	s := []byte(r)
	i := strings.IndexByte(r, '1') + 10
	s[i] = b64[(strings.IndexByte(b64, s[i])+1)%len(b64)]
	return string(s)
}

func digest(label string) []byte {
	return DomainSeparated(UsagePolicyDocument, []byte(label))
}

func buildPolicy() *Policy {
	dev1 := clientKey("device-1")
	dev2 := clientKey("device-2")
	p := &Policy{
		Format:           Format,
		Version:          Version,
		VaultID:          "vault-01",
		PolicySeq:        7,
		PrevPolicyDigest: digest("policy-6"),
		OwnerRoot: OwnerRoot{
			KeyID:     "owner-root-01",
			Alg:       PolicySigAlgEd25519,
			PublicKey: pf(0x01, 32),
			Owners:    []Principal{{PrincipalID: "alice", Label: "Alice"}},
		},
		Readers: []Member{{PrincipalID: "carol", Label: "Carol"}},
		Writers: []Member{{PrincipalID: "bob", Label: "Bob"}},
		Admins:  []Member{{PrincipalID: "alice", Label: "Alice"}},
		Owners:  []Member{{PrincipalID: "alice", Label: "Alice"}},
		AdminDelegations: []AdminDelegation{{
			DelegationID:     "deleg-01",
			DelegateDevice:   "device-2",
			GrantedBy:        "owner-root-01",
			Scope:            DelegationScope{InviteReaders: true, InviteWriters: true, RemoveMembers: true, RemoveDevices: true},
			ScopeNote:        "restricted: members and devices only",
			ExpiresPolicySeq: 12,
		}},
		Devices: []Device{
			{
				DeviceID:          "device-1",
				PrincipalID:       "alice",
				Label:             "Alice laptop",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x21, 32)},
				PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x22, 32)},
				AgeEncryptionKey:  ageRecipient(dev1),
			},
			{
				DeviceID:          "device-2",
				PrincipalID:       "bob",
				Label:             "Bob phone",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x31, 32)},
				PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x32, 32)},
				AgeEncryptionKey:  ageRecipient(dev2),
			},
		},
	}
	return p
}

// buildFile builds the sealed vector file. The content signature bytes are
// shaped, not real; revision_id is derived by SealFile from exactly this.
func buildFile(t *testing.T) *File {
	f := draftWithSignature(t)
	return sealFile(t, f, &f.ContentSignature)
}

// buildDraft builds the in-memory builder draft of the vector file: the
// sealed content with a null content signature and an empty revision id. It
// is never a wire record; only ContentSigningBytes and RevisionID accept it.
func buildDraft(t *testing.T) *File {
	// The header digest of the current policy is PolicyDigest over the
	// canonical policy document bytes held in the proof; the policy carries
	// no digest of itself.
	p := clonePolicy(buildPolicy())
	doc := docFor(p)
	f := &File{
		Format:  Format,
		Version: Version,
		Header: Header{
			VaultID:    "vault-01",
			KeyEpoch:   3,
			ContentSeq: 42,
			PrevDigest: digest("content-41"),
			OpID:       "op-0042",
			PolicySeq:  7,
			// Placeholder; the digest is bound to the proof below.
			PolicyDigest:   make([]byte, sha256.Size),
			AuthorDeviceID: "device-1",
		},
		SignedPolicyProofs: []SignedPolicy{{
			Document: doc,
			Policy:   *p,
			SignerID: "owner-root-01",
			Alg:      PolicySigAlgEd25519,
			Sig:      pf(0x42, 64),
		}},
		ContentEncoding: ContentEncoding,
		KDBXCiphertext:  []byte("synthetic-kdbx-ciphertext-not-a-real-kdbx"),
		VUKDeviceSlots: []DeviceSlot{
			{DeviceID: "device-1", Recipient: p.Devices[0].AgeEncryptionKey, WrappedVUK: []byte("synthetic-age-wrapped-vuk-1")},
			{DeviceID: "device-2", Recipient: p.Devices[1].AgeEncryptionKey, WrappedVUK: []byte("synthetic-age-wrapped-vuk-2")},
		},
		CEKSlot: CEKSlot{KeyEpoch: 3, WrappedCEK: []byte("synthetic-vuk-wrapped-cek")},
	}
	f.Header.PolicyDigest = policyDigest(&f.SignedPolicyProofs[0])
	return f
}

// draftWithSignature returns the in-memory draft carrying the shaped signature
// it is about to be sealed with, still without a revision id.
func draftWithSignature(t *testing.T) *File {
	f := buildDraft(t)
	f.ContentSignature = Signature{SignerID: "device-1", Alg: SigAlgEd25519, Sig: shapedSignature()}
	return f
}

// shapedSignature is the synthetic content signature of the vector. Its
// bytes only have the shape of an ed25519 signature: they are not a
// signature, and nothing in this package verifies one.
func shapedSignature() []byte { return pf(0x51, 64) }

// sealFile runs SealFile (no signature is computed), parses the sealed bytes
// back and returns the parsed file.
func sealFile(t *testing.T, f *File, sig *Signature) *File {
	t.Helper()
	enc, err := SealFile(f, sig)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// seal is sealFile, replacing f with the parsed canonical result.
func seal(t *testing.T, f *File, sig *Signature) []byte {
	t.Helper()
	enc, err := SealFile(f, sig)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	*f = *parsed
	return enc
}

// reseal re-derives the revision id of a sealed file after its content
// changed, keeping its (shaped) content signature. Every edit to a sealed
// file's preimage-covered fields must go through it: a stale revision id is
// rejected by ValidateFile.
func reseal(t *testing.T, f *File) {
	t.Helper()
	sig := f.ContentSignature
	f.Header.RevisionID = ""
	*f = *sealFile(t, f, &sig)
}

// encodedHeader is the canonical header of a file exactly as it appears on
// the wire (revision_id included), so vectors stay auditable without base64.
func encodedHeader(f *File) string {
	var b bytes.Buffer
	writeHeader(&b, &f.Header)
	return b.String()
}

func canonicalJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// encodedNestedJSON rewrites the header and the current policy as their
// canonical strings so vectors stay auditable without base64.
func encodedNestedJSON(f *File) string {
	b, err := json.Marshal(encodedFile{T: f})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// encodedFile is the human-facing vector form of File: header and current
// policy appear as their canonical strings, binary members stay base64url.
type encodedFile struct{ T *File }

func (e encodedFile) MarshalJSON() ([]byte, error) {
	f := e.T
	p := f.SignedPolicyProofs[0]
	out := map[string]any{
		"format":  f.Format,
		"version": f.Version,
		"header":  encodedHeader(f),
		"signed_policy_proofs": []map[string]any{{
			"document":  string(p.Document),
			"policy":    string(p.Document),
			"signer_id": p.SignerID,
			"alg":       p.Alg,
			"sig":       p.Sig,
		}},
		"content_encoding":  f.ContentEncoding,
		"kdbx_ciphertext":   f.KDBXCiphertext,
		"vuk_device_slots":  f.VUKDeviceSlots,
		"cek_slot":          f.CEKSlot,
		"content_signature": f.ContentSignature,
	}
	b, err := json.MarshalIndent(out, "    ", "  ")
	if err != nil {
		return nil, err
	}
	return b, nil
}

func TestVectors(t *testing.T) {
	path := filepath.Join("testdata", "vaultfile-v1-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name                 string `json:"name"`
			State                string `json:"state"`
			File                 string `json:"file"`
			FileSHA256           string `json:"file_sha256"`
			RevisionID           string `json:"revision_id"`
			ContentSigning       string `json:"content_signing_input"`
			ContentSigningSHA256 string `json:"content_signing_input_sha256"`
			RevisionDomainInput  string `json:"revision_domain_input"`
			FileDigest           string `json:"file_digest"`
			PolicyDocument       string `json:"policy_document"`
			PolicyDocumentSHA256 string `json:"policy_document_sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range doc.Vectors {
		f, err := ParseFile([]byte(v.File))
		if err != nil {
			t.Fatalf("%s: parse: %v", v.Name, err)
		}
		enc, err := EncodeFile(f)
		if err != nil {
			t.Fatalf("%s: encode: %v", v.Name, err)
		}
		if string(enc) != v.File {
			t.Fatalf("%s: re-encoding differs from vector", v.Name)
		}
		if got := sha256Hex(enc); got != v.FileSHA256 {
			t.Fatalf("%s: file sha256 = %s, want %s", v.Name, got, v.FileSHA256)
		}

		// Revision identity: the vector pins both the input (canonical file
		// without revision_id and content_signature) and the derived id.
		rev, err := RevisionID(f)
		if err != nil {
			t.Fatalf("%s: revision id: %v", v.Name, err)
		}
		if rev != v.RevisionID {
			t.Fatalf("%s: revision id = %s, want %s", v.Name, rev, v.RevisionID)
		}
		// Every vector is a sealed wire file and carries exactly its
		// derived revision id.
		if v.State != "sealed" {
			t.Fatalf("%s: state = %q; only sealed files are wire vectors", v.Name, v.State)
		}
		if f.Header.RevisionID != rev {
			t.Fatalf("%s: sealed revision_id = %s, want derived %s", v.Name, f.Header.RevisionID, rev)
		}
		input, err := revisionDomainInput(f)
		if err != nil {
			t.Fatalf("%s: revision domain input: %v", v.Name, err)
		}
		if string(input) != v.RevisionDomainInput {
			t.Fatalf("%s: revision domain input differs from vector", v.Name)
		}
		want, err := hex.DecodeString(v.RevisionID)
		if err != nil {
			t.Fatalf("%s: vector revision_id: %v", v.Name, err)
		}
		if !bytes.Equal(DomainSeparated(DomainRevision, input), want) {
			t.Fatalf("%s: revision domain hash does not reproduce revision_id", v.Name)
		}

		// Content signing preimage: no content_signature member at all.
		csb, err := ContentSigningBytes(f)
		if err != nil {
			t.Fatalf("%s: content signing bytes: %v", v.Name, err)
		}
		if string(csb) != v.ContentSigning {
			t.Fatalf("%s: content signing input differs from vector", v.Name)
		}
		if got := sha256Hex(csb); got != v.ContentSigningSHA256 {
			t.Fatalf("%s: content signing sha256 = %s, want %s", v.Name, got, v.ContentSigningSHA256)
		}

		// File digest: the complete canonical sealed file.
		fd, err := FileDigest(f)
		if err != nil {
			t.Fatalf("%s: file digest: %v", v.Name, err)
		}
		if fd != v.FileDigest {
			t.Fatalf("%s: file digest = %s, want %s", v.Name, fd, v.FileDigest)
		}

		sp := &f.SignedPolicyProofs[0]
		if string(sp.Document) != v.PolicyDocument {
			t.Fatalf("%s: policy document differs", v.Name)
		}
		if got := sha256Hex(sp.Document); got != v.PolicyDocumentSHA256 {
			t.Fatalf("%s: policy document sha256 = %s, want %s", v.Name, got, v.PolicyDocumentSHA256)
		}
		// The carried document must be exactly the canonical bytes of the
		// typed policy it is paired with.
		canon, _ := EncodePolicyDocument(&sp.Policy)
		if !bytes.Equal(canon, []byte(v.PolicyDocument)) {
			t.Fatalf("%s: policy document not canonical", v.Name)
		}
		// Policy digest keeps its one external definition.
		if !bytes.Equal(f.Header.PolicyDigest, PolicyDigest(&sp.Policy)) {
			t.Fatalf("%s: header does not reference the policy digest", v.Name)
		}
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// vectorEntry records f as one sealed wire vector. The in-memory draft is
// never recorded: it has no wire bytes.
func vectorEntry(t *testing.T, name, state string, f *File) map[string]any {
	t.Helper()
	enc, err := EncodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := RevisionID(f)
	if err != nil {
		t.Fatal(err)
	}
	if rev != f.Header.RevisionID {
		t.Fatalf("%s: revision id %s, header %s", name, rev, f.Header.RevisionID)
	}
	input, err := revisionDomainInput(f)
	if err != nil {
		t.Fatal(err)
	}
	csb, err := ContentSigningBytes(f)
	if err != nil {
		t.Fatal(err)
	}
	entry := map[string]any{
		"file_json":                    encodedNestedJSON(f),
		"name":                         name,
		"state":                        state,
		"file":                         string(enc),
		"file_sha256":                  sha256Hex(enc),
		"revision_id":                  rev,
		"revision_domain_input":        string(input),
		"content_signing_input":        string(csb),
		"content_signing_input_sha256": sha256Hex(csb),
		"policy_document":              string(f.SignedPolicyProofs[0].Document),
		"policy_document_sha256":       sha256Hex(f.SignedPolicyProofs[0].Document),
	}
	fd, err := FileDigest(f)
	if err != nil {
		t.Fatal(err)
	}
	entry["file_digest"] = fd
	return entry
}

func writeVectors(t *testing.T) {
	sealed := buildFile(t)

	// The draft is checked against the sealed file, not written: it is an
	// in-memory builder state with no wire bytes. Both must derive the one
	// identity and the one content-signing preimage recorded in the vector.
	draft := buildDraft(t)
	sealedRev, err := RevisionID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	draftRev, err := RevisionID(draft)
	if err != nil {
		t.Fatal(err)
	}
	if draftRev != sealedRev {
		t.Fatalf("draft revision id %s, sealed %s", draftRev, sealedRev)
	}
	sealedCSB, err := ContentSigningBytes(sealed)
	if err != nil {
		t.Fatal(err)
	}
	draftCSB, err := ContentSigningBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(draftCSB, sealedCSB) {
		t.Fatal("draft content signing preimage differs from the sealed vector")
	}
	// The draft is not a wire file.
	if _, err := EncodeFile(draft); err == nil {
		t.Fatal("draft encodes as a wire file")
	}
	if _, err := FileDigest(draft); err == nil {
		t.Fatal("draft has a file digest")
	}

	doc := map[string]any{
		"$comment": "Synthetic locklark.vault-file/v1 encoding vectors (see docs/vaultfile-wire-v1.md). Only sealed files are wire records: every vector has state \"sealed\", a non-null content signature and a header.revision_id equal to revision_id. There is no unsigned-draft fixture; a draft is an in-memory builder state with no wire bytes (see docs/vaultfile-wire-v1.md). Signature and wrapped-key bytes are shaped, not valid, and no signature is verified. revision_id is the v1 RevisionID hash of revision_domain_input (the canonical file with header.revision_id and content_signature omitted); content_signing_input is the canonical file with content_signature omitted and header.revision_id set to revision_id; file_digest is the v1 FileDigest of the sealed file. Generated by TestWriteVectors; verify with TestVectors.",
		"vectors": []map[string]any{
			vectorEntry(t, "v1-canonical", "sealed", sealed),
		},
	}
	b := []byte(canonicalJSON(doc))
	if *updateVectors {
		if err := os.WriteFile(filepath.Join("testdata", "vaultfile-v1-vectors.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(filepath.Join("testdata", "vaultfile-v1-vectors.json"))
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("vectors differ from generator output; run go test -run TestWriteVectors -update")
	}
}

func TestWriteVectors(t *testing.T) { writeVectors(t) }
