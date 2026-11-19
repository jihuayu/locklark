package remoteunlock

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// Every key, identity, policy, vault-file content byte and timestamp in this
// file is synthetic. The Ed25519 keys come from the deterministic seed spans
// declared in authorization_test.go and in this file, and every signature and
// policy proof is real Ed25519 output over the documented preimages, but none
// belongs to a person, device, vault, enrollment, owner root or admin. The
// delegation path is exercised with real cryptographic values so it is
// demonstrably crypto-valid; it proves nothing about production identity,
// enrollment, live TLS, durable replay, VUK delivery or a real unlock.
//
// The vault-file fixture is the synthetic one in authorization_test.go: a
// sealed file whose current policy (the final carried proof at policy_seq 2)
// lists alice as an owner and carol as an admin with device-outsider, and
// member-0001 (the requester) as a reader and writer with device-source and
// device-target. The fixed binding vectors are signed by exactly those two
// devices. The file is authored by the requester's own device-source, whose
// principal is a writer.

// ---------------------------------------------------------------------------
// Fixed synthetic vectors.
// ---------------------------------------------------------------------------

const (
	// adminDelegationVectorPolicySeq and adminDelegationVectorPolicyDigest
	// are the fixture's current policy anchor.
	adminDelegationVectorPolicySeq    = uint64(2)
	adminDelegationVectorPolicyDigest = "j5HDbfdIdI5sDh0y6NAxn7XZ6vPiGNXlZefjJ9dV4vY"

	// adminDelegationVectorKey is the synthetic Ed25519 policy signing key of
	// the delegated device (seed span 0x80), a key role separate from that
	// device's content signing key.
	adminDelegationVectorKey = "bw8O6z-_-SXGbQPhnc5I1e3J_-5RzSaucd055W9_3aI"

	// adminDelegationSignedJSON is the canonical JSON of members 1..19, the
	// owner-root signed preimage without its domain.
	adminDelegationSignedJSON = `{"format":"locklark.remote-unlock","version":1,"kind":"owner-admin-delegation","owner_root_key_id":"owner-root-0001","delegate_member_id":"carol","delegate_device_id":"device-outsider","delegate_policy_signing_key":"bw8O6z-_-SXGbQPhnc5I1e3J_-5RzSaucd055W9_3aI","vault_id":"vault-0001","requester_member_id":"member-0001","source_device_id":"device-source","target_device_id":"device-target","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","pair_generation":0,"key_epoch":7,"policy_seq":2,"policy_digest":"j5HDbfdIdI5sDh0y6NAxn7XZ6vPiGNXlZefjJ9dV4vY","not_before_unix_ms":1799999900000,"expires_unix_ms":1800000001000}`

	// adminDelegationVectorSignature is the fixed synthetic owner-root
	// signature over the domain and adminDelegationSignedJSON, by the synthetic
	// root of seed span 0x20.
	adminDelegationVectorSignature = "7zsUu-9zDLf7LNOMKpGFBk1tqhqZgctUzNBQFFd6S4A8GO2-WAUpRKwXSx_ejkkxI7Snk3fmSa9Qymz1n90UDg"

	// adminDelegationVectorDigest is AdminDelegationDigest of the complete
	// vector.
	adminDelegationVectorDigest = "BqJKqhv9FaINZWmGD_eRraFGFosPn6ZfocLgr0mZZZU"
)

// adminDelegationVectorJSON is the complete canonical 810-byte delegation.
var adminDelegationVectorJSON = adminDelegationSignedJSON[:len(adminDelegationSignedJSON)-1] +
	`,"signature":"` + adminDelegationVectorSignature + `"}`

// adminDelegationVector returns the fixed synthetic delegation.
func adminDelegationVector() OwnerRootAdminRemoteUnlockDelegation {
	var key [AdminDelegationPublicKeySize]byte
	copy(key[:], seedPublic(0xd0))
	return OwnerRootAdminRemoteUnlockDelegation{
		OwnerRootKeyID:           authOwnerRootKeyID,
		DelegateMemberID:         "carol",
		DelegateDeviceID:         "device-outsider",
		DelegatePolicySigningKey: key,
		VaultID:                  authVaultID,
		RequesterMemberID:        authMemberID,
		SourceDeviceID:           authSourceDeviceID,
		TargetDeviceID:           authTargetDeviceID,
		SourceBindingSHA256:      mustDigest(authSourceDigestVector),
		TargetBindingSHA256:      mustDigest(authTargetDigestVector),
		PolicySeq:                adminDelegationVectorPolicySeq,
		KeyEpoch:                 authKeyEpoch,
		PolicyDigest:             mustDigest(adminDelegationVectorPolicyDigest),
		NotBeforeUnixMS:          1799999900000,
		ExpiresUnixMS:            1800000001000,
		Signature:                mustDelegationSignature(adminDelegationVectorSignature),
	}
}

func mustDelegationSignature(s string) [AdminDelegationSignatureSize]byte {
	var sig [AdminDelegationSignatureSize]byte
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != AdminDelegationSignatureSize {
		panic("bad delegation vector signature")
	}
	copy(sig[:], raw)
	return sig
}

func mustEncodeDelegation(t *testing.T, d OwnerRootAdminRemoteUnlockDelegation) []byte {
	t.Helper()
	b, err := EncodeOwnerRootAdminRemoteUnlockDelegation(d)
	if err != nil {
		t.Fatalf("EncodeOwnerRootAdminRemoteUnlockDelegation: %v", err)
	}
	return b
}

func mustDelegationPreimage(t *testing.T, d OwnerRootAdminRemoteUnlockDelegation) []byte {
	t.Helper()
	b, err := AdminDelegationSigningBytes(d)
	if err != nil {
		t.Fatalf("AdminDelegationSigningBytes: %v", err)
	}
	return b
}

// signDelegation signs d's members 1..19 with priv.
func signDelegation(t *testing.T, d OwnerRootAdminRemoteUnlockDelegation, priv ed25519.PrivateKey) OwnerRootAdminRemoteUnlockDelegation {
	t.Helper()
	d.Signature = [AdminDelegationSignatureSize]byte{}
	copy(d.Signature[:], ed25519.Sign(priv, mustDelegationPreimage(t, d)))
	return d
}

func requireDelegationField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error naming %q, got nil", field)
	}
	var fe *AdminDelegationFieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error is not an *AdminDelegationFieldError: %v", err)
	}
	if fe.Field != field {
		t.Fatalf("AdminDelegationFieldError.Field = %q, want %q (%v)", fe.Field, field, err)
	}
}

// TestAdminDelegationFixedSyntheticVectors pins the exact preimage, signature,
// complete digest and encoding, and proves the signing domain is distinct from
// the owner-root authorization and device-binding domains.
func TestAdminDelegationFixedSyntheticVectors(t *testing.T) {
	fx := newDelegationFixture(t, nil)
	d := adminDelegationVector()
	cur := fx.currentPolicy()

	if got := base64.RawURLEncoding.EncodeToString(vaultfile.PolicyDigest(cur)); got != adminDelegationVectorPolicyDigest {
		t.Fatalf("fixture policy digest = %s, want the pinned %s", got, adminDelegationVectorPolicyDigest)
	}
	if cur.PolicySeq != adminDelegationVectorPolicySeq {
		t.Fatalf("fixture policy_seq = %d, want %d", cur.PolicySeq, adminDelegationVectorPolicySeq)
	}
	var key [AdminDelegationPublicKeySize]byte
	copy(key[:], seedPublic(0xd0))
	if d.DelegatePolicySigningKey != key {
		t.Fatal("vector delegate key differs from the declared seed span")
	}
	dev := authDeviceByID(t, cur, d.DelegateDeviceID)
	if dev.PolicySigningKey == nil || !bytes.Equal(dev.PolicySigningKey.PublicKey, d.DelegatePolicySigningKey[:]) {
		t.Fatal("vector delegate key differs from the fixture device policy signing key")
	}
	if bytes.Equal(dev.ContentSigningKey.PublicKey, d.DelegatePolicySigningKey[:]) {
		t.Fatal("vector reuses the device content key as its policy key")
	}

	if got, want := string(mustDelegationPreimage(t, d)), AdminDelegationSignatureDomain+adminDelegationSignedJSON; got != want {
		t.Fatalf("signing preimage mismatch\n got: %q\nwant: %q", got, want)
	}
	if !ed25519.Verify(seedPublic(authRootSeedSpan), mustDelegationPreimage(t, d), d.Signature[:]) {
		t.Fatal("fixed owner-root signature does not verify")
	}
	// Domain separation: the same key does not verify under another domain,
	// and no domain collides.
	if ed25519.Verify(seedPublic(authRootSeedSpan),
		append([]byte(OwnerRootAuthorizationSignatureDomain), adminDelegationSignedJSON...), d.Signature[:]) {
		t.Fatal("delegation signature verifies under the owner-root authorization domain")
	}
	if ed25519.Verify(seedPublic(authRootSeedSpan),
		append([]byte(BindingSignatureDomain), adminDelegationSignedJSON...), d.Signature[:]) {
		t.Fatal("delegation signature verifies under the binding domain")
	}
	if dom := [3]string{AdminDelegationSignatureDomain, OwnerRootAuthorizationSignatureDomain, BindingSignatureDomain}; dom[0] == dom[1] || dom[0] == dom[2] || dom[1] == dom[2] {
		t.Fatal("signing domains are not distinct")
	}

	digest, err := AdminDelegationDigest(d)
	if err != nil {
		t.Fatalf("AdminDelegationDigest: %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != adminDelegationVectorDigest {
		t.Fatalf("delegation digest = %s, want %s", got, adminDelegationVectorDigest)
	}
	// The digest covers the signature: a re-signed grant has a new digest.
	resigned := signDelegation(t, d, seedKey(authForeignSeedSpan))
	if again, _ := AdminDelegationDigest(resigned); again == digest {
		t.Fatal("delegation digest ignores the signature")
	}
	// And it is domain-separated from a bare hash of the encoding.
	if digestOf(mustEncodeDelegation(t, d)) == digest {
		t.Fatal("delegation digest does not include its domain prefix")
	}

	encoded := mustEncodeDelegation(t, d)
	if string(encoded) != adminDelegationVectorJSON || len(encoded) != 810 {
		t.Fatalf("canonical encoding is %d bytes, want the pinned 810-byte vector\n got: %s", len(encoded), encoded)
	}
	parsed, err := ParseOwnerRootAdminRemoteUnlockDelegation(encoded)
	if err != nil || parsed != d {
		t.Fatalf("Parse = %+v, %v; want %+v, nil", parsed, err, d)
	}
	marshaled, err := d.MarshalJSON()
	if err != nil || !bytes.Equal(marshaled, encoded) {
		t.Fatalf("MarshalJSON = %s, %v; want %s, nil", marshaled, err, encoded)
	}
	var decoded OwnerRootAdminRemoteUnlockDelegation
	if err := decoded.UnmarshalJSON(encoded); err != nil || decoded != d {
		t.Fatalf("UnmarshalJSON = %+v, %v; want %+v, nil", decoded, err, d)
	}

	// The reusable grant carries no per-request member.
	for _, banned := range []string{"request_id", "request_digest", "lock_generation", "deadline", "context_sha256"} {
		if bytes.Contains(encoded, []byte(`"`+banned+`"`)) {
			t.Fatalf("delegation carries a per-request member %q", banned)
		}
	}
}

// TestAdminDelegationMaximumLegalBudget pins the documented maximum size.
func TestAdminDelegationMaximumLegalBudget(t *testing.T) {
	d := adminDelegationVector()
	ids := &[7]*string{&d.OwnerRootKeyID, &d.DelegateMemberID, &d.DelegateDeviceID, &d.VaultID, &d.RequesterMemberID, &d.SourceDeviceID, &d.TargetDeviceID}
	for i, p := range ids {
		*p = strings.Repeat(string(rune('a'+i)), MaxIdentifierLen)
	}
	d.SourceDeviceID = strings.Repeat("a", MaxIdentifierLen)
	d.TargetDeviceID = strings.Repeat("b", MaxIdentifierLen)
	d.PairGeneration, d.KeyEpoch, d.PolicySeq = 1<<64-1, 1<<64-1, 1<<64-1
	d.NotBeforeUnixMS, d.ExpiresUnixMS = 1, 1<<63-1
	d = signDelegation(t, d, seedKey(authRootSeedSpan))
	encoded := mustEncodeDelegation(t, d)

	// Seven identifiers at 128 bytes, three uint64 maxima (20 digits), two
	// timestamps (1 and 19 digits), the constants and the fixed-width key,
	// digests and signature.
	const fixed = 810 - len("owner-root-0001") - len("carol") - len("device-outsider") - len("vault-0001") -
		len("member-0001") - len("device-source") - len("device-target") - len("0") - len("7") - len("2") -
		len("1799999900000") - len("1800000001000")
	want := fixed + 7*MaxIdentifierLen + 3*20 + 1 + 19
	if len(encoded) != want {
		t.Fatalf("maximum legal delegation is %d bytes, want %d", len(encoded), want)
	}
	if want > MaxAdminDelegationSize {
		t.Fatalf("maximum legal delegation %d exceeds the %d-byte cap", want, MaxAdminDelegationSize)
	}
	if _, err := ParseOwnerRootAdminRemoteUnlockDelegation(encoded); err != nil {
		t.Fatalf("maximum legal delegation does not parse: %v", err)
	}
}

func TestEncodeAdminDelegationRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*OwnerRootAdminRemoteUnlockDelegation)
		field  string
	}{
		{"owner root key id empty", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.OwnerRootKeyID = "" }, "owner_root_key_id"},
		{"owner root key id uppercase", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.OwnerRootKeyID = "OWNER-ROOT-0001" }, "owner_root_key_id"},
		{"owner root key id too long", func(d *OwnerRootAdminRemoteUnlockDelegation) {
			d.OwnerRootKeyID = strings.Repeat("a", MaxIdentifierLen+1)
		}, "owner_root_key_id"},
		{"delegate member id empty", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.DelegateMemberID = "" }, "delegate_member_id"},
		{"delegate device id non ascii", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.DelegateDeviceID = "device-é" }, "delegate_device_id"},
		{"vault id empty", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.VaultID = "" }, "vault_id"},
		{"requester member id space", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.RequesterMemberID = "member 0001" }, "requester_member_id"},
		{"source device id empty", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.SourceDeviceID = "" }, "source_device_id"},
		{"target device id control", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.TargetDeviceID = "tgt\x00" }, "target_device_id"},
		{"source equals target", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.TargetDeviceID = d.SourceDeviceID }, "target_device_id"},
		{"key epoch zero", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.KeyEpoch = 0 }, "key_epoch"},
		{"not before zero", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.NotBeforeUnixMS = 0 }, "not_before_unix_ms"},
		{"not before negative", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.NotBeforeUnixMS = -1 }, "not_before_unix_ms"},
		{"expires equal to not before", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.ExpiresUnixMS = d.NotBeforeUnixMS }, "expires_unix_ms"},
		{"expires before not before", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.ExpiresUnixMS = d.NotBeforeUnixMS - 1 }, "expires_unix_ms"},
		{"expires zero", func(d *OwnerRootAdminRemoteUnlockDelegation) { d.ExpiresUnixMS = 0 }, "expires_unix_ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := adminDelegationVector()
			tt.mutate(&d)
			_, err := EncodeOwnerRootAdminRemoteUnlockDelegation(d)
			if !errors.Is(err, ErrInvalidAdminDelegation) {
				t.Fatalf("encode error does not wrap ErrInvalidAdminDelegation: %v", err)
			}
			requireDelegationField(t, err, tt.field)
			if _, err := AdminDelegationSigningBytes(d); !errors.Is(err, ErrInvalidAdminDelegation) {
				t.Fatalf("AdminDelegationSigningBytes error does not wrap ErrInvalidAdminDelegation: %v", err)
			}
			if _, err := AdminDelegationDigest(d); !errors.Is(err, ErrInvalidAdminDelegation) {
				t.Fatalf("AdminDelegationDigest error does not wrap ErrInvalidAdminDelegation: %v", err)
			}
		})
	}
}

// TestAdminDelegationParseRejectsNonCanonicalInput covers missing, unknown,
// duplicate and reordered members, structural damage, bad constants, types,
// identifiers, integers, keys, digests and signature, escapes, trailing data
// and the size cap.
func TestAdminDelegationParseRejectsNonCanonicalInput(t *testing.T) {
	canonical := []byte(adminDelegationVectorJSON)
	sig := `"signature":"` + adminDelegationVectorSignature + `"`
	key := `"` + adminDelegationVectorKey + `"`
	ctx := `"` + adminDelegationVectorPolicyDigest + `"`
	src := `"` + authSourceDigestVector + `"`

	type tc struct {
		name   string
		mutate func(t *testing.T, b []byte) []byte
		field  string
	}
	var tests []tc
	for i, name := range adminDelegationMembers {
		next := ""
		if i+1 < len(adminDelegationMembers) {
			next = adminDelegationMembers[i+1]
		}
		if i == 0 {
			// removeMember cannot drop the first member; the first name then
			// appears where the object start was expected.
			next = name
		}
		name := name
		tests = append(tests, tc{name: "missing " + name, mutate: func(t *testing.T, b []byte) []byte {
			return removeMember(t, b, name)
		}, field: next})
	}
	tests = append(tests,
		tc{name: "empty object", mutate: func(t *testing.T, b []byte) []byte { return []byte(`{}`) }, field: ""},
		tc{name: "unknown member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `}`, `,"admin":true}`)
		}, field: ""},
		tc{name: "per-request member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"vault_id"`, `"request_id":"req-0001","vault_id"`)
		}, field: ""},
		tc{name: "duplicate signature", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, sig+`,`+sig)
		}, field: ""},
		tc{name: "duplicate delegate key", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, key, key+`,`+key)
		}, field: "vault_id"},
		tc{name: "members reordered", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0,"key_epoch":7`, `"key_epoch":7,"pair_generation":0`)
		}, field: ""},
		tc{name: "leading space", mutate: func(t *testing.T, b []byte) []byte { return append([]byte(" "), b...) }, field: ""},
		tc{name: "trailing newline", mutate: func(t *testing.T, b []byte) []byte { return append(b, '\n') }, field: ""},
		tc{name: "trailing second value", mutate: func(t *testing.T, b []byte) []byte { return append(b, canonical...) }, field: ""},
		tc{name: "internal whitespace", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version": 1`)
		}, field: "version"},
		tc{name: "missing comma", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1,"kind"`, `"version":1"kind"`)
		}, field: ""},
		tc{name: "missing closing brace", mutate: func(t *testing.T, b []byte) []byte { return b[:len(b)-1] }, field: ""},
		tc{name: "empty input", mutate: func(t *testing.T, b []byte) []byte { return nil }, field: ""},
		tc{name: "not an object", mutate: func(t *testing.T, b []byte) []byte { return []byte(`[]`) }, field: ""},
		tc{name: "invalid utf8", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"carol"`, "\"car\xffol\"")
		}, field: ""},
		tc{name: "escaped identifier", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, `"owner\u002droot-0001"`)
		}, field: "owner_root_key_id"},
		tc{name: "escaped member name", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"format"`, `"\u0066ormat"`)
		}, field: "format"},
		tc{name: "wrong format", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"locklark.remote-unlock"`, `"locklark.remote-unlock.v2"`)
		}, field: "format"},
		tc{name: "owner authorization kind", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-admin-delegation"`, `"owner-authorization"`)
		}, field: "kind"},
		tc{name: "wrong version", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":2`)
		}, field: "version"},
		tc{name: "version as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":"1"`)
		}, field: "version"},
		tc{name: "identifier too long", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"carol"`, `"`+strings.Repeat("a", MaxIdentifierLen+1)+`"`)
		}, field: "delegate_member_id"},
		tc{name: "pair generation leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":00`)
		}, field: "pair_generation"},
		tc{name: "pair generation negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":-1`)
		}, field: "pair_generation"},
		tc{name: "pair generation fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":0.0`)
		}, field: "pair_generation"},
		tc{name: "pair generation exponent", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":0e0`)
		}, field: "pair_generation"},
		tc{name: "pair generation overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":0`, `"pair_generation":18446744073709551616`)
		}, field: "pair_generation"},
		tc{name: "key epoch zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"key_epoch":7`, `"key_epoch":0`)
		}, field: "key_epoch"},
		tc{name: "policy seq overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"policy_seq":2`, `"policy_seq":18446744073709551616`)
		}, field: "policy_seq"},
		tc{name: "not before zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"not_before_unix_ms":1799999900000`, `"not_before_unix_ms":0`)
		}, field: "not_before_unix_ms"},
		tc{name: "not before negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"not_before_unix_ms":1799999900000`, `"not_before_unix_ms":-1799999900000`)
		}, field: "not_before_unix_ms"},
		tc{name: "not before int64 overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"not_before_unix_ms":1799999900000`, `"not_before_unix_ms":9223372036854775808`)
		}, field: "not_before_unix_ms"},
		tc{name: "expires equal to not before", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1800000001000`, `"expires_unix_ms":1799999900000`)
		}, field: "expires_unix_ms"},
		tc{name: "expires before not before", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1800000001000`, `"expires_unix_ms":1799999899999`)
		}, field: "expires_unix_ms"},
		tc{name: "expires zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1800000001000`, `"expires_unix_ms":0`)
		}, field: "expires_unix_ms"},
		tc{name: "policy digest padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, ctx, `"`+adminDelegationVectorPolicyDigest+`="`)
		}, field: "policy_digest"},
		tc{name: "source digest short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, src, `"`+authSourceDigestVector[:42]+`"`)
		}, field: "source_binding_sha256"},
		tc{name: "target digest noncanonical trailing bits", mutate: func(t *testing.T, b []byte) []byte {
			last := authTargetDigestVector[len(authTargetDigestVector)-1]
			alt := map[byte]byte{'M': 'N', 'N': 'M'}[last]
			return replaceOnce(t, b, `"`+authTargetDigestVector+`"`, `"`+authTargetDigestVector[:len(authTargetDigestVector)-1]+string(alt)+`"`)
		}, field: "target_binding_sha256"},
		tc{name: "delegate key short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, key, `"`+adminDelegationVectorKey[:42]+`"`)
		}, field: "delegate_policy_signing_key"},
		tc{name: "delegate key padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, key, `"`+adminDelegationVectorKey+`="`)
		}, field: "delegate_policy_signing_key"},
		tc{name: "delegate key standard alphabet", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, key, `"`+strings.ReplaceAll(adminDelegationVectorKey, "-", "+")+`"`)
		}, field: "delegate_policy_signing_key"},
		tc{name: "signature short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, sig[:len(sig)-2]+`"`)
		}, field: "signature"},
		tc{name: "signature padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, sig[:len(sig)-1]+`="`)
		}, field: "signature"},
		tc{name: "signature as null", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, `"signature":null`)
		}, field: "signature"},
		tc{name: "input over budget", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxAdminDelegationSize+1)...)
		}, field: ""},
		tc{name: "exactly the budget with trailing data", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxAdminDelegationSize-len(b))...)
		}, field: ""},
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.mutate(t, append([]byte(nil), canonical...))
			_, err := ParseOwnerRootAdminRemoteUnlockDelegation(data)
			if err == nil {
				t.Fatal("Parse accepted non-canonical input")
			}
			if !errors.Is(err, ErrInvalidAdminDelegationEncoding) {
				t.Fatalf("error does not wrap ErrInvalidAdminDelegationEncoding: %v", err)
			}
			if tt.field != "" {
				requireDelegationField(t, err, tt.field)
			}
		})
	}
	for _, size := range []int{MaxAdminDelegationSize + 1, MaxAdminDelegationSize * 4} {
		if _, err := ParseOwnerRootAdminRemoteUnlockDelegation(bytes.Repeat([]byte(" "), size)); !errors.Is(err, ErrInvalidAdminDelegationEncoding) {
			t.Fatalf("%d bytes: error does not wrap ErrInvalidAdminDelegationEncoding: %v", size, err)
		}
	}
}

func TestAdminDelegationErrorsNeverContainValues(t *testing.T) {
	const secret = "UPPERSECRETDELEGATE"
	d := adminDelegationVector()
	d.DelegateMemberID = secret
	_, err := EncodeOwnerRootAdminRemoteUnlockDelegation(d)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("encode error leaked or missed the identifier: %v", err)
	}
	data := replaceOnce(t, []byte(adminDelegationVectorJSON), `}`, `,"`+strings.ToLower(secret)+`":1}`)
	_, err = ParseOwnerRootAdminRemoteUnlockDelegation(data)
	if err == nil || strings.Contains(err.Error(), strings.ToLower(secret)) {
		t.Fatalf("parse error leaked an unknown key: %v", err)
	}
	bad := "+" + adminDelegationVectorSignature[1:]
	data = replaceOnce(t, []byte(adminDelegationVectorJSON), `"signature":"`+adminDelegationVectorSignature+`"`, `"signature":"`+bad+`"`)
	_, err = ParseOwnerRootAdminRemoteUnlockDelegation(data)
	if err == nil || strings.Contains(err.Error(), bad[1:20]) {
		t.Fatalf("parse error leaked signature bytes: %v", err)
	}
	err = VerifyOwnerRootAdminRemoteUnlockDelegation(nil, nil, adminDelegationVector(), 1)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), adminDelegationVectorPolicyDigest) ||
		strings.Contains(err.Error(), adminDelegationVectorSignature[:20]) {
		t.Fatalf("verification error leaked a value: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Synthetic fixture for the delegation verifier.
// ---------------------------------------------------------------------------

// delegationNowMS is the synthetic caller clock of every verification test. It
// lies inside the fixed vector's interval and before the fixture's policy.
const delegationNowMS int64 = 1_800_000_000_000

// delegateFixturePolicy is the current fixture policy with the mutation
// applied. Devices and principals must stay in the vault file's frozen order;
// variants rename or re-own existing devices rather than adding new ones.
func delegateFixturePolicy(mutate func(*vaultfile.Policy)) *vaultfile.Policy {
	p := authPolicy()
	p.Writers = sortedDelegationMembers(p.Writers, vaultfile.Member{PrincipalID: authAuthorPrincipalID, Label: "Writer"})
	// The delegated admin device carries a distinct policy signing key: no
	// policy role may reuse another role's key material.
	delegateDevice := policyDevice(p, "device-outsider")
	if delegateDevice == nil {
		panic("fixture delegate device is missing")
	}
	delegateDevice.PolicySigningKey = &vaultfile.PublicKey{Alg: vaultfile.PolicySigAlgEd25519, PublicKey: bytes.Clone(seedPublic(delegationDelegateSeed))}
	// An independent writer authors the file, so the requester and the
	// delegate never sign content.
	p.Devices = append(p.Devices, vaultfile.Device{
		DeviceID:          "device-author",
		PrincipalID:       authAuthorPrincipalID,
		Label:             "Synthetic author",
		ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(seedPublic(authAuthorSeedSpan))},
		AgeEncryptionKey:  ageRecipientFor(authTestX25519Scalar("author")),
	})
	sort.Slice(p.Devices, func(i, j int) bool { return p.Devices[i].DeviceID < p.Devices[j].DeviceID })
	if mutate != nil {
		mutate(p)
	}
	return p
}

// delegationAuthorDevice is the independent writer that authors every fixture
// file.
const delegationAuthorDevice = "device-author"

// The fixed delegate of every fixture delegation.
const (
	delegationDelegateMember = "carol"
	delegationDelegateDevice = "device-outsider"
	delegationDelegateSeed   = byte(0xd0)
)

func dropDelegationDevices(p *vaultfile.Policy, ids ...string) []vaultfile.Device {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	var out []vaultfile.Device
	for _, d := range p.Devices {
		if !drop[d.DeviceID] {
			out = append(out, d)
		}
	}
	return out
}

func sortedDelegationMembers(ms []vaultfile.Member, add ...vaultfile.Member) []vaultfile.Member {
	out := append(append([]vaultfile.Member(nil), ms...), add...)
	sort.Slice(out, func(i, j int) bool { return out[i].PrincipalID < out[j].PrincipalID })
	return out
}

// newDelegationFixture seals a three-proof chain whose current policy is the
// fixture policy with mutate applied, every proof root-signed, and whose
// content is authored by the independent writer device-author. Its checkpoint
// pins the genesis proof.
func newDelegationFixture(t *testing.T, mutate func(*vaultfile.Policy)) *authFixture {
	t.Helper()
	current := delegateFixturePolicy(mutate)
	if err := vaultfile.ValidatePolicy(current); err != nil {
		t.Fatalf("fixture current policy is not structurally valid: %v", err)
	}
	// The genesis policy exists before any delegate or optional device: the
	// requester holds both roles, its two fixed devices are registered, and
	// no admin delegation exists yet.
	genesis := &vaultfile.Policy{
		Format:    vaultfile.Format,
		Version:   vaultfile.Version,
		VaultID:   authVaultID,
		PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID:     authOwnerRootKeyID,
			Alg:       vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(seedPublic(0x20)),
			Owners:    []vaultfile.Principal{{PrincipalID: "alice", Label: "Alice"}},
		},
		Readers: []vaultfile.Member{{PrincipalID: authMemberID, Label: "Alice"}},
		Writers: []vaultfile.Member{{PrincipalID: authMemberID, Label: "Alice"}},
		Owners:  []vaultfile.Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []vaultfile.Device{
			{
				DeviceID:          authSourceDeviceID,
				PrincipalID:       authMemberID,
				Label:             "Synthetic source",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(seedPublic(0x60))},
				AgeEncryptionKey:  authSourceVectorRecipient,
			},
			{
				DeviceID:          authTargetDeviceID,
				PrincipalID:       authMemberID,
				Label:             "Synthetic target",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(seedPublic(0x70))},
				AgeEncryptionKey:  authTargetVectorRecipient,
			},
		},
	}
	if err := vaultfile.ValidatePolicy(genesis); err != nil {
		t.Fatalf("fixture genesis policy is not structurally valid: %v", err)
	}
	f := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version}
	carryProof(f, genesis)
	prior := delegateFixturePolicy(nil)
	carryProof(f, prior)
	cur := *current
	cur.Format, cur.Version, cur.VaultID = vaultfile.Format, vaultfile.Version, authVaultID
	// Policy sequences must be contiguous: the current policy is the proof
	// after the prior one.
	cur.PolicySeq = f.SignedPolicyProofs[1].Policy.PolicySeq + 1
	cur.PrevPolicyDigest = vaultfile.PolicyDigest(&f.SignedPolicyProofs[1].Policy)
	doc, err := vaultfile.EncodePolicyDocument(&cur)
	if err != nil {
		t.Fatalf("current policy is not encodable: %v", err)
	}
	f.SignedPolicyProofs = append(f.SignedPolicyProofs, vaultfile.SignedPolicy{
		Policy: cur, Document: doc, SignerID: authOwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
		Sig: make([]byte, ed25519.SignatureSize),
	})
	root := seedKey(authRootSeedSpan)
	for i := range f.SignedPolicyProofs {
		signProof(f, i, root)
	}
	return sealDelegationFixture(t, f)
}

// sealDelegationFixture derives the header and VUK slots from the current
// policy, signs the content as the independent writer device-author and seals,
// leaving the checkpoint pinning proof 0. Unlike sealAuthFile it never names
// the requester's own device as the content author, so a variant may remove
// that device.
func sealDelegationFixture(t *testing.T, f *vaultfile.File) *authFixture {
	t.Helper()
	cur := &f.SignedPolicyProofs[len(f.SignedPolicyProofs)-1].Policy
	f.Header = vaultfile.Header{
		VaultID:        authVaultID,
		KeyEpoch:       authKeyEpoch,
		ContentSeq:     0,
		PrevDigest:     nil,
		OpID:           "op-0001",
		PolicySeq:      cur.PolicySeq,
		PolicyDigest:   vaultfile.PolicyDigest(cur),
		AuthorDeviceID: delegationAuthorDevice,
	}
	f.ContentEncoding = vaultfile.ContentEncoding
	f.KDBXCiphertext = []byte("synthetic-kdbx-ciphertext-not-a-real-kdbx")
	var slots []vaultfile.DeviceSlot
	for _, d := range cur.Devices {
		slots = append(slots, vaultfile.DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("synthetic-wrapped-vuk")})
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].DeviceID < slots[j].DeviceID })
	f.VUKDeviceSlots = slots
	f.CEKSlot = vaultfile.CEKSlot{KeyEpoch: authKeyEpoch, WrappedCEK: []byte("synthetic-wrapped-cek")}
	sealed := signAndSeal(t, f, delegationAuthorDevice)
	fx := &authFixture{file: sealed, anchorSeq: sealed.SignedPolicyProofs[0].Policy.PolicySeq}
	fx.checkpoint = &vaultfile.PolicyCheckpoint{
		VaultID:            authVaultID,
		OwnerRootKeyID:     authOwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(seedPublic(authRootSeedSpan)),
		PolicySeq:          fx.anchorSeq,
		PolicyDigest:       vaultfile.PolicyDigest(&sealed.SignedPolicyProofs[0].Policy),
	}
	if err := vaultfile.VerifyPolicyCheckpoint(sealed, fx.checkpoint); err != nil {
		t.Fatalf("synthetic delegation fixture is not checkpoint-authentic: %v", err)
	}
	return fx
}

func (fx *authFixture) currentDelegationPolicy() *vaultfile.Policy {
	return &fx.file.SignedPolicyProofs[len(fx.file.SignedPolicyProofs)-1].Policy
}

// delegationFor builds a fresh owner-root-signed delegation for the fixture's
// current policy anchor and the fixed delegate and requester scope. The
// delegate key is the declared synthetic policy key of device-outsider, not a
// value re-derived from whatever the current policy happens to say.
func (fx *authFixture) delegationFor(t *testing.T) OwnerRootAdminRemoteUnlockDelegation {
	t.Helper()
	var key [AdminDelegationPublicKeySize]byte
	copy(key[:], seedPublic(delegationDelegateSeed))
	anchor := fx.currentDelegationPolicy()
	return signDelegation(t, OwnerRootAdminRemoteUnlockDelegation{
		OwnerRootKeyID:           authOwnerRootKeyID,
		DelegateMemberID:         delegationDelegateMember,
		DelegateDeviceID:         delegationDelegateDevice,
		DelegatePolicySigningKey: key,
		VaultID:                  fx.file.Header.VaultID,
		RequesterMemberID:        authMemberID,
		SourceDeviceID:           authSourceDeviceID,
		TargetDeviceID:           authTargetDeviceID,
		SourceBindingSHA256:      mustDigest(authSourceDigestVector),
		TargetBindingSHA256:      mustDigest(authTargetDigestVector),
		PairGeneration:           vectorContext().PairGeneration,
		KeyEpoch:                 fx.file.Header.KeyEpoch,
		PolicySeq:                anchor.PolicySeq,
		PolicyDigest:             [DigestSize]byte(vaultfile.PolicyDigest(anchor)),
		NotBeforeUnixMS:          delegationNowMS - 100_000,
		ExpiresUnixMS:            delegationNowMS + 1_000,
	}, seedKey(authRootSeedSpan))
}

func (fx *authFixture) verifyDelegation(d OwnerRootAdminRemoteUnlockDelegation, now int64) error {
	return VerifyOwnerRootAdminRemoteUnlockDelegation(fx.file, fx.cloneCheckpoint(), d, now)
}

// TestVerifyDelegationSyntheticFullPath is the real positive path: the owner
// root's reusable delegation verifies against an independently checkpointed
// file authored by a separate writer, at every instant of its interval, and
// leaves the policy untouched.
func TestVerifyDelegationSyntheticFullPath(t *testing.T) {
	fx := newDelegationFixture(t, nil)
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.cloneCheckpoint()); err != nil {
		t.Fatalf("fixture is not checkpoint-authentic: %v", err)
	}
	if fx.file.Header.AuthorDeviceID != delegationAuthorDevice || fx.file.ContentSignature.SignerID != delegationAuthorDevice {
		t.Fatalf("fixture file is not authored by the independent writer")
	}
	cur := fx.currentDelegationPolicy()
	if !policyAdminQualified("carol", cur) || !policyReadQualified(authMemberID, cur) {
		t.Fatal("fixture roles are wrong")
	}
	// The requester is not an admin or an owner: read qualification alone
	// does not let it delegate.
	for _, roles := range [2][]vaultfile.Member{cur.Admins, cur.Owners} {
		for _, m := range roles {
			if m.PrincipalID == authMemberID {
				t.Fatal("fixture requester is an admin or owner")
			}
		}
	}
	d := fx.delegationFor(t)
	if _, err := ParseOwnerRootAdminRemoteUnlockDelegation(mustEncodeDelegation(t, d)); err != nil {
		t.Fatalf("fixture delegation is not canonical: %v", err)
	}
	before := vaultfile.PolicyDigest(cur)
	for _, now := range []int64{d.NotBeforeUnixMS, delegationNowMS, d.ExpiresUnixMS - 1} {
		if err := fx.verifyDelegation(d, now); err != nil {
			t.Fatalf("valid delegation rejected at %d: %v", now, err)
		}
	}
	// The grant is reusable: the same bytes verify for a later request in the
	// interval without any per-request member and without a new signature.
	if err := fx.verifyDelegation(d, d.ExpiresUnixMS-2); err != nil {
		t.Fatalf("reused delegation rejected: %v", err)
	}
	if err := fx.verifyDelegation(adminDelegationVector(), delegationNowMS); err != nil {
		t.Fatalf("fixed vector rejected: %v", err)
	}
	if !bytes.Equal(vaultfile.PolicyDigest(fx.currentDelegationPolicy()), before) {
		t.Fatal("verification mutated the authenticated policy")
	}
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.cloneCheckpoint()); err != nil {
		t.Fatalf("verification changed the fixture: %v", err)
	}
}

// appendDelegationPolicy adds one more root-signed current policy proof and
// re-seals the file as the independent writer (a root-signed policy update,
// which the checkpoint accepts).
func appendDelegationPolicy(t *testing.T, fx *authFixture) *authFixture {
	t.Helper()
	out := *fx.file
	out.SignedPolicyProofs = append([]vaultfile.SignedPolicy(nil), fx.file.SignedPolicyProofs...)
	last := out.SignedPolicyProofs[len(out.SignedPolicyProofs)-1]
	next := last.Policy
	next.PolicySeq = last.Policy.PolicySeq + 1
	next.PrevPolicyDigest = vaultfile.PolicyDigest(&last.Policy)
	next.Writers = sortedDelegationMembers(next.Writers, vaultfile.Member{PrincipalID: "zara", Label: "Zara"})
	doc, err := vaultfile.EncodePolicyDocument(&next)
	if err != nil {
		t.Fatalf("successor policy is not encodable: %v", err)
	}
	out.SignedPolicyProofs = append(out.SignedPolicyProofs, vaultfile.SignedPolicy{
		Policy: next, Document: doc, SignerID: authOwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
		Sig: make([]byte, ed25519.SignatureSize),
	})
	signProof(&out, len(out.SignedPolicyProofs)-1, seedKey(authRootSeedSpan))
	return sealDelegationFixture(t, &out)
}

// TestVerifyDelegationInvalidatedByPolicyUpdate proves the policy anchor rule:
// a delegation that verified against the policy it was issued for stops
// verifying once the vault adopts a later policy, even when the update adds
// only an unrelated writer. Only a new owner-root-signed delegation can cover
// the new policy.
func TestVerifyDelegationInvalidatedByPolicyUpdate(t *testing.T) {
	fx := newDelegationFixture(t, nil)
	d := fx.delegationFor(t)
	if err := fx.verifyDelegation(d, delegationNowMS); err != nil {
		t.Fatalf("delegation rejected against its own policy: %v", err)
	}
	updated := appendDelegationPolicy(t, fx)
	if err := vaultfile.VerifyPolicyCheckpoint(updated.file, updated.cloneCheckpoint()); err != nil {
		t.Fatalf("updated fixture is not checkpoint-authentic: %v", err)
	}
	if updated.currentDelegationPolicy().PolicySeq != d.PolicySeq+1 {
		t.Fatalf("fixture update did not advance the policy sequence")
	}
	err := updated.verifyDelegation(d, delegationNowMS)
	if err == nil {
		t.Fatal("delegation survived a policy update")
	}
	requireDelegationField(t, err, "policy_seq")
	// A fresh delegation for the new anchor verifies, including the same
	// delegate and requester scope.
	fresh := updated.delegationFor(t)
	if fresh.PolicySeq != d.PolicySeq+1 || fresh.PolicyDigest == d.PolicyDigest {
		t.Fatal("fresh delegation did not adopt the new policy anchor")
	}
	if err := updated.verifyDelegation(fresh, delegationNowMS); err != nil {
		t.Fatalf("fresh delegation rejected: %v", err)
	}
}

// TestVerifyDelegationDoesNotVerifyBindings pins the boundary of this
// checkpoint: the delegation records exact binding digests, but verifying it
// reads no binding and proves nothing about a binding signature or recipient.
func TestVerifyDelegationDoesNotVerifyBindings(t *testing.T) {
	fx := newDelegationFixture(t, nil)
	d := fx.delegationFor(t)
	for _, mutate := range []func(*OwnerRootAdminRemoteUnlockDelegation){
		func(d *OwnerRootAdminRemoteUnlockDelegation) { d.SourceBindingSHA256 = [DigestSize]byte{} },
		func(d *OwnerRootAdminRemoteUnlockDelegation) { d.TargetBindingSHA256 = descendingDigest() },
		func(d *OwnerRootAdminRemoteUnlockDelegation) {
			d.SourceBindingSHA256, d.TargetBindingSHA256 = d.TargetBindingSHA256, d.SourceBindingSHA256
		},
	} {
		m := d
		mutate(&m)
		m = signDelegation(t, m, seedKey(authRootSeedSpan))
		if err := fx.verifyDelegation(m, delegationNowMS); err != nil {
			t.Fatalf("binding digest scope change rejected by the delegation verifier: %v", err)
		}
	}
}

type delegationCase struct {
	name string
	fx   func(t *testing.T) *authFixture
	// apply mutates the delegation and/or inputs. Unless keepSignature is
	// set, the harness re-signs the mutated members 1..19 with the root.
	apply         func(t *testing.T, in *delegationInputs)
	keepSignature bool
	now           int64
	// explicitNow applies now even when it is zero.
	explicitNow bool
	field       string
	wrap        error
}

type delegationInputs struct {
	file *vaultfile.File
	cp   *vaultfile.PolicyCheckpoint
	del  OwnerRootAdminRemoteUnlockDelegation
	now  int64
}

// TestVerifyDelegationRejectsMutations mutates every input the verifier
// depends on and requires it to fail closed with a stable field error naming
// the member, or a wrapped vaultfile error.
func TestVerifyDelegationRejectsMutations(t *testing.T) {
	root := seedKey(authRootSeedSpan)
	variant := func(mutate func(*vaultfile.Policy)) func(*testing.T) *authFixture {
		return func(t *testing.T) *authFixture { return newDelegationFixture(t, mutate) }
	}
	tests := []delegationCase{
		// Owner-root signature and pin.
		{name: "signature mutated", apply: unary(func(in *delegationInputs) { in.del.Signature[0] ^= 0x01 }), keepSignature: true, field: "signature"},
		{name: "signature zeroed", apply: unary(func(in *delegationInputs) { in.del.Signature = [AdminDelegationSignatureSize]byte{} }), keepSignature: true, field: "signature"},
		{name: "signature by a foreign root", apply: func(t *testing.T, in *delegationInputs) {
			in.del = signDelegation(t, in.del, seedKey(authForeignSeedSpan))
		}, keepSignature: true, field: "signature"},
		{name: "signature over a different member", apply: unary(func(in *delegationInputs) {
			// The owner root signs one scope; another expires field is sent.
			signed := signDelegation(t, in.del, root)
			in.del.ExpiresUnixMS = signed.ExpiresUnixMS - 1
			in.del.Signature = signed.Signature
		}), keepSignature: true, field: "signature"},
		{name: "signature over another domain", apply: unary(func(in *delegationInputs) {
			in.del = signDelegation(t, in.del, root)
			in.del.Signature = [AdminDelegationSignatureSize]byte{}
			copy(in.del.Signature[:], ed25519.Sign(root, append([]byte(OwnerRootAuthorizationSignatureDomain), mustDelegationPreimage(t, in.del)[len(AdminDelegationSignatureDomain):]...)))
		}), keepSignature: true, field: "signature"},
		{name: "owner root key id differs", apply: unary(func(in *delegationInputs) { in.del.OwnerRootKeyID = "owner-root-0002" }), field: "owner_root_key_id"},
		{name: "checkpoint pins a foreign root", apply: unary(func(in *delegationInputs) { in.cp.OwnerRootPublicKey = bytes.Clone(seedPublic(authForeignSeedSpan)) }), keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "checkpoint pins a different root key id", apply: unary(func(in *delegationInputs) { in.cp.OwnerRootKeyID = "owner-root-0002" }), keepSignature: true, wrap: ErrInvalidAdminDelegation},

		// Policy anchor: any policy update invalidates the grant.
		{name: "policy anchor digest differs", apply: unary(func(in *delegationInputs) { in.del.PolicyDigest[0] ^= 0x01 }), field: "policy_digest"},
		{name: "policy anchor from an older sequence", apply: unary(func(in *delegationInputs) { in.del.PolicySeq-- }), field: "policy_seq"},
		{name: "key epoch differs", apply: unary(func(in *delegationInputs) { in.del.KeyEpoch++ }), field: "key_epoch"},
		{name: "vault differs", apply: unary(func(in *delegationInputs) { in.del.VaultID = "vault-0002" }), field: "vault_id"},
		{name: "checkpoint digest points elsewhere", apply: unary(func(in *delegationInputs) { in.cp.PolicyDigest[0] ^= 0x01 }), keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "checkpoint points past the file", apply: unary(func(in *delegationInputs) { in.cp.PolicySeq = 9 }), keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "content signature broken after sealing", apply: unary(func(in *delegationInputs) {
			c := *in.file
			c.ContentSignature.Sig = bytes.Clone(c.ContentSignature.Sig)
			c.ContentSignature.Sig[0] ^= 0x01
			in.file = &c
		}), keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "policy proof signature broken", apply: unary(func(in *delegationInputs) {
			c := *in.file
			c.SignedPolicyProofs = append([]vaultfile.SignedPolicy(nil), c.SignedPolicyProofs...)
			c.SignedPolicyProofs[2].Sig = bytes.Clone(c.SignedPolicyProofs[2].Sig)
			c.SignedPolicyProofs[2].Sig[0] ^= 0x01
			in.file = &c
		}), keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "nil file", apply: unary(func(in *delegationInputs) { in.file = nil }), keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "nil checkpoint", apply: unary(func(in *delegationInputs) { in.cp = nil }), keepSignature: true, wrap: ErrInvalidAdminDelegation},

		// Delegate: removed, demoted, role not admin/owner, key missing or
		// different.
		{name: "delegate device removed", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, "device-outsider").DeviceID = "device-outsider-gone"
			sort.Slice(p.Devices, func(i, j int) bool { return p.Devices[i].DeviceID < p.Devices[j].DeviceID })
		}), field: "delegate_device_id"},
		{name: "delegate device re-owned to another principal", fx: variant(func(p *vaultfile.Policy) { authDeviceByID(t, p, "device-outsider").PrincipalID = "bob" }), field: "delegate_member_id"},
		{name: "delegate principal demoted to writer", fx: variant(func(p *vaultfile.Policy) {
			p.Admins = []vaultfile.Member{}
			p.Writers = sortedDelegationMembers(p.Writers, vaultfile.Member{PrincipalID: "carol", Label: "Carol"})
		}), apply: unary(func(in *delegationInputs) {}), field: "delegate_member_id"},
		{name: "delegate principal reader only", fx: variant(func(p *vaultfile.Policy) {
			p.Admins = []vaultfile.Member{}
			p.Readers = sortedDelegationMembers(p.Readers, vaultfile.Member{PrincipalID: "carol", Label: "Carol"})
		}), field: "delegate_member_id"},
		{name: "delegate principal only in the owner-root list", apply: unary(func(in *delegationInputs) { in.del.DelegateMemberID = "alice-nobody" }), field: "delegate_member_id"},
		{name: "delegate device has no policy signing key", fx: variant(func(p *vaultfile.Policy) { authDeviceByID(t, p, "device-outsider").PolicySigningKey = nil }), field: "delegate_policy_signing_key"},
		{name: "delegate policy signing key differs", apply: unary(func(in *delegationInputs) {
			copy(in.del.DelegatePolicySigningKey[:], seedPublic(0x90))
		}), field: "delegate_policy_signing_key"},
		{name: "delegate policy signing key rotated in the policy", fx: variant(func(p *vaultfile.Policy) {
			// A key no other role uses.
			authDeviceByID(t, p, "device-outsider").PolicySigningKey.PublicKey = bytes.Clone(seedPublic(0x30))
		}), field: "delegate_policy_signing_key"},
		{name: "delegate named another admin's device", fx: variant(func(p *vaultfile.Policy) {
			// carol's device is removed and bob's appears as an admin device.
			p.Admins = sortedDelegationMembers(p.Admins, vaultfile.Member{PrincipalID: "bob", Label: "Bob"})
			authDeviceByID(t, p, authTargetDeviceID).PolicySigningKey = &vaultfile.PublicKey{Alg: vaultfile.PolicySigAlgEd25519, PublicKey: bytes.Clone(seedPublic(0x91))}
		}), apply: unary(func(in *delegationInputs) {
			in.del.DelegateMemberID = "bob"
			in.del.DelegateDeviceID = authTargetDeviceID
			copy(in.del.DelegatePolicySigningKey[:], seedPublic(0x91))
		}), field: "delegate_member_id"},

		// Requester read role and scoped endpoint registration.
		{name: "requester member without a read role", fx: variant(func(p *vaultfile.Policy) {
			p.Readers = []vaultfile.Member{{PrincipalID: "prior-reader", Label: "Prior reader"}}
			p.Writers = []vaultfile.Member{{PrincipalID: "bob", Label: "Bob"}, {PrincipalID: authAuthorPrincipalID, Label: "Writer"}}
			p.Devices = dropDelegationDevices(p, authSourceDeviceID, authTargetDeviceID)
		}), field: "requester_member_id"},
		{name: "requester names an unknown member", apply: unary(func(in *delegationInputs) { in.del.RequesterMemberID = "nobody" }), field: "requester_member_id"},
		{name: "source device unknown", apply: unary(func(in *delegationInputs) { in.del.SourceDeviceID = "device-unknown" }), field: "source_device_id"},
		{name: "target device unknown", apply: unary(func(in *delegationInputs) { in.del.TargetDeviceID = "device-unknown" }), field: "target_device_id"},
		{name: "target device belongs to another member", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, authTargetDeviceID).PrincipalID = "carol"
		}), field: "target_device_id"},
		{name: "source device moved to another member", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, authSourceDeviceID).PrincipalID = "bob"
		}), field: "source_device_id"},
		{name: "scoped endpoints swapped", apply: unary(func(in *delegationInputs) {
			// Both endpoints still resolve to the requester, so this is a
			// different but well-formed scope: the verifier accepts it.
			in.del.SourceDeviceID, in.del.TargetDeviceID = in.del.TargetDeviceID, in.del.SourceDeviceID
		})},
		{name: "source and target equal", apply: unary(func(in *delegationInputs) { in.del.TargetDeviceID = in.del.SourceDeviceID }), keepSignature: true, field: "target_device_id"},

		// Scope changes that stay within valid policy.
		{name: "source binding digest changed", apply: unary(func(in *delegationInputs) { in.del.SourceBindingSHA256[0] ^= 0x01 })},
		{name: "target binding digest changed", apply: unary(func(in *delegationInputs) { in.del.TargetBindingSHA256[0] ^= 0x01 })},
		{name: "binding digests swapped", apply: unary(func(in *delegationInputs) {
			in.del.SourceBindingSHA256, in.del.TargetBindingSHA256 = in.del.TargetBindingSHA256, in.del.SourceBindingSHA256
		})},
		{name: "pair generation changed", apply: unary(func(in *delegationInputs) { in.del.PairGeneration = 1 })},

		// Validity interval and caller clock.
		{name: "one millisecond before not before", now: delegationNowMS - 100_000 - 1, keepSignature: true, field: "not_before_unix_ms"},
		{name: "expires at now", now: delegationNowMS + 1_000, keepSignature: true, field: "expires_unix_ms"},
		{name: "one millisecond after expiry", now: delegationNowMS + 1_001, keepSignature: true, field: "expires_unix_ms"},
		{name: "caller clock zero", now: 0, explicitNow: true, keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "caller clock negative", now: -1, keepSignature: true, wrap: ErrInvalidAdminDelegation},
		{name: "not before zero in the grant", apply: unary(func(in *delegationInputs) { in.del.NotBeforeUnixMS = 0 }), keepSignature: true, field: "not_before_unix_ms"},
		{name: "expires not after not before", apply: unary(func(in *delegationInputs) { in.del.ExpiresUnixMS = in.del.NotBeforeUnixMS }), keepSignature: true, field: "expires_unix_ms"},
		{name: "key epoch zero in the grant", apply: unary(func(in *delegationInputs) { in.del.KeyEpoch = 0 }), keepSignature: true, field: "key_epoch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newDelegationFixture(t, nil)
			if tt.fx != nil {
				fx = tt.fx(t)
			}
			in := &delegationInputs{file: fx.file, cp: fx.cloneCheckpoint(), del: fx.delegationFor(t), now: delegationNowMS}
			if tt.now != 0 || tt.explicitNow {
				in.now = tt.now
			}
			if tt.apply != nil {
				tt.apply(t, in)
			}
			if !tt.keepSignature {
				in.del = signDelegation(t, in.del, root)
			}
			if t.Failed() {
				return
			}
			if tt.field == "" && tt.wrap == nil {
				// The change is a different but well-formed scope that the
				// current policy still supports: verification accepts it. In
				// particular the binding digests are recorded scope only;
				// this verifier never reads a binding.
				if _, err := ParseOwnerRootAdminRemoteUnlockDelegation(mustEncodeDelegation(t, in.del)); err != nil {
					t.Fatalf("mutated delegation is not canonical: %v", err)
				}
				if err := VerifyOwnerRootAdminRemoteUnlockDelegation(in.file, in.cp, in.del, in.now); err != nil {
					t.Fatalf("well-formed re-scoped delegation rejected: %v", err)
				}
				return
			}
			err := VerifyOwnerRootAdminRemoteUnlockDelegation(in.file, in.cp, in.del, in.now)
			if err == nil {
				t.Fatal("verifier accepted a mutated input")
			}
			if !errors.Is(err, ErrInvalidAdminDelegation) {
				t.Fatalf("error does not wrap ErrInvalidAdminDelegation: %v", err)
			}
			if tt.wrap != nil && !errors.Is(err, tt.wrap) {
				t.Fatalf("error does not wrap %v: %v", tt.wrap, err)
			}
			if tt.field != "" {
				requireDelegationField(t, err, tt.field)
			}
			for _, v := range []string{in.del.OwnerRootKeyID, in.del.DelegateMemberID, in.del.DelegateDeviceID,
				base64.RawURLEncoding.EncodeToString(in.del.DelegatePolicySigningKey[:]),
				base64.RawURLEncoding.EncodeToString(in.del.PolicyDigest[:]),
				base64.RawURLEncoding.EncodeToString(in.del.Signature[:])} {
				if strings.Contains(err.Error(), v) {
					t.Fatalf("error echoed an input value: %v", err)
				}
			}
		})
	}
}

// unary adapts a delegation mutation to delegationCase.apply.
func unary(f func(in *delegationInputs)) func(t *testing.T, in *delegationInputs) {
	return func(t *testing.T, in *delegationInputs) { f(in) }
}
