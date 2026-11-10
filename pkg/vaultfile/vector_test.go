package vaultfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var updateVectors = flag.Bool("update", false, "rewrite testdata/vaultfile-v3-vectors.json")

// pf is a deterministic filler so every vector is reproducible.
func pf(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7) ^ byte(i>>3)
	}
	return b
}

func clientKey(label string) []byte {
	k := DomainSeparated(UsageVaultID, []byte("vector-key/"+label))
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

const (
	ageB64 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

func ageRecipient(key []byte) string {
	out := make([]byte, 0, 58)
	var acc, bits uint32
	for _, b := range key {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, ageB64[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		out = append(out, ageB64[(acc<<(5-bits))&31])
	}
	// 4 checksum characters in the same alphabet (not an age bech32 checksum).
	for _, c := range pf(9, 4) {
		out = append(out, ageB64[c&31])
	}
	return "age1" + string(out)
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
	path := filepath.Join("testdata", "vaultfile-v3-vectors.json")
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
		"$comment": "Synthetic locklark.vault-file/v3 encoding vectors. Signatures and wrapped keys are shaped, not valid; no cryptographic verification applies. Generated by TestWriteVectors; verify with TestVectors.",
		"vectors": []map[string]any{{
			"file_json":              encodedNestedJSON(f),
			"name":                   "v3-canonical",
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
		if err := os.WriteFile(filepath.Join("testdata", "vaultfile-v3-vectors.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(filepath.Join("testdata", "vaultfile-v3-vectors.json"))
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("vectors differ from generator output; run go test -run TestWriteVectors -update")
	}
}

func TestWriteVectors(t *testing.T) { writeVectors(t) }
