package vaultfile

import (
	"bytes"
	"crypto/sha256"
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
		PolicyDigest:     digest("policy-7"),
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
				Label:             "Alice laptop",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x21, 32)},
				PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x22, 32)},
				AgeEncryptionKey:  ageRecipient(dev1),
			},
			{
				DeviceID:          "device-2",
				Label:             "Bob phone",
				ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x31, 32)},
				PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x32, 32)},
				AgeEncryptionKey:  ageRecipient(dev2),
			},
		},
	}
	return p
}

func buildFile() *File {
	// The header digest of the current policy is a function of the policy
	// document bytes. Policy.PolicyDigest is an opaque member carried inside
	// those bytes; it is set here to a fixed value so the vector is stable.
	base := buildPolicy()
	p := clonePolicy(base)
	doc := docFor(p)
	f := &File{
		Format:  Format,
		Version: Version,
		Header: Header{
			VaultID:        "vault-01",
			KeyEpoch:       3,
			ContentSeq:     42,
			RevisionID:     "rev-0042",
			PrevDigest:     digest("content-41"),
			OpID:           "op-0042",
			PolicySeq:      7,
			PolicyDigest:   policyDigest(&SignedPolicy{Document: doc}),
			AuthorDeviceID: "device-1",
		},
		HeaderSig: Signature{SignerID: "device-1", Alg: SigAlgEd25519, Sig: pf(0x41, 64)},
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
		CEKSlot:          CEKSlot{KeyEpoch: 3, WrappedCEK: []byte("synthetic-vuk-wrapped-cek")},
		ContentSignature: Signature{SignerID: "device-1", Alg: SigAlgEd25519, Sig: pf(0x51, 64)},
	}
	return f
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
		"format":     f.Format,
		"version":    f.Version,
		"header":     string(HeaderBytes(&f.Header)),
		"header_sig": f.HeaderSig,
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
			File                 string `json:"file"`
			FileSHA256           string `json:"file_sha256"`
			Header               string `json:"header"`
			HeaderSHA256         string `json:"header_sha256"`
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
		sum := sha256.Sum256(enc)
		if fmt.Sprintf("%x", sum) != v.FileSHA256 {
			t.Fatalf("%s: sha256 mismatch", v.Name)
		}
		if hb := HeaderBytes(&f.Header); string(hb) != v.Header {
			t.Fatalf("%s: header bytes differ", v.Name)
		}
		sum = sha256.Sum256(HeaderBytes(&f.Header))
		if fmt.Sprintf("%x", sum) != v.HeaderSHA256 {
			t.Fatalf("%s: header sha256 mismatch", v.Name)
		}
		sp := &f.SignedPolicyProofs[0]
		if string(sp.Document) != v.PolicyDocument {
			t.Fatalf("%s: policy document differs", v.Name)
		}
		sum = sha256.Sum256(sp.Document)
		if fmt.Sprintf("%x", sum) != v.PolicyDocumentSHA256 {
			t.Fatalf("%s: policy document sha256 mismatch", v.Name)
		}
		// The carried document must be exactly the canonical bytes of the
		// typed policy it is paired with.
		canon, _ := EncodePolicyDocument(&sp.Policy)
		if !bytes.Equal(canon, []byte(v.PolicyDocument)) {
			t.Fatalf("%s: policy document not canonical", v.Name)
		}
	}
}

func writeVectors(t *testing.T) {
	f := buildFile()
	enc, err := EncodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(enc)
	hh := sha256.Sum256(HeaderBytes(&f.Header))
	pd := sha256.Sum256(f.SignedPolicyProofs[0].Document)
	doc := map[string]any{
		"$comment": "Synthetic locklark.vault-file/v1 encoding vectors. Signatures and wrapped keys are shaped, not valid; no cryptographic verification applies. Generated by TestWriteVectors; verify with TestVectors.",
		"vectors": []map[string]any{{
			"file_json":              encodedNestedJSON(f),
			"name":                   "v1-canonical",
			"file":                   string(enc),
			"file_sha256":            fmt.Sprintf("%x", h),
			"header":                 string(HeaderBytes(&f.Header)),
			"header_sha256":          fmt.Sprintf("%x", hh),
			"policy_document":        string(f.SignedPolicyProofs[0].Document),
			"policy_document_sha256": fmt.Sprintf("%x", pd),
		}},
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
