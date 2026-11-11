package remoteunlock

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// Every key, identity, policy, vault-file content byte and timestamp in this
// file is synthetic. Ed25519 keys come from deterministic seeds so the vectors
// are reproducible, but they belong to no person, device, vault, enrollment or
// owner root, and the vault-file content, wrapped keys and VUK slots are
// placeholders that no real crypto produced. The owner-root verification path
// is exercised with real Ed25519 values so it is demonstrably crypto-valid, but
// it proves nothing about any production identity, enrollment, policy or
// unlock. It makes no production unlock, policy-mutation, durable replay or
// identity-enrollment claim.

// ---------------------------------------------------------------------------
// Fixed synthetic vectors.
// ---------------------------------------------------------------------------

// Every Ed25519 key in this file originates from a declared deterministic
// seed: seedKey(s) is the Ed25519 key of the bytes s, s+1, ... These spans are
// the only sources of fixture key material; every fixed public key, binding
// signature, binding digest and authorization signature below is derived from
// them and pinned by TestAuthorizationKeyMaterialIsDeclaredAndPinned.
const (
	authRootSeedSpan      byte = 0x20 // synthetic owner root, mutated nowhere
	authForeignSeedSpan   byte = 0xa0 // synthetic owner root that is never pinned
	authSourceSeedSpan    byte = 0x60 // synthetic source device content key
	authTargetSeedSpan    byte = 0x70 // synthetic target device content key
	authOutsiderSeedSpan  byte = 0x80 // synthetic outsider device content key
	authReaderSeedSpan    byte = 0x90 // synthetic reader-only device content key
	authAuthorSeedSpan    byte = 0xb0 // synthetic writer-author device content key
	authReaderTgtSeedSpan byte = 0xc0 // synthetic second reader device content key
)

// authorizationVectorPublicKey is the synthetic owner-root public key derived
// from authRootSeedSpan.
const authorizationVectorPublicKey = "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc"

// The source and target binding vectors are fixed canonical
// device-transport-binding objects with real Ed25519 signatures: the source
// under the synthetic seed 0x60..0x7f, the target under 0x70..0x8f. Their
// diff (device, install, SPKI digest, recipient, signature) illustrates that
// a source digest never equals a target digest.
const (
	// authSourceVectorPublicKey and authTargetVectorPublicKey are the
	// synthetic device content-signing keys of the two binding vectors.
	authSourceVectorPublicKey = "F0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9U"
	authTargetVectorPublicKey = "HOVqSMgv-ZFioUvFRGEmdOXWH7kxfmXUBVeA_by03DU"
)

const (
	authSourceVectorJSON = `{"format":"locklark.remote-unlock","version":1,"kind":"device-transport-binding","member_id":"member-0001","device_id":"device-source","install_id":"install-0001","vault_id":"vault-0001","pair_generation":0,"spki_sha256":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","recipient_public_key":"age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea","signature":"uroxw4IlNDuKaRvqabPBbnpE_AHH7NNXqKi6EzCrG3mRbMHrm8qqKjoKGHzrGHN2s9MIbkmkWAn43EPrPOiVDQ"}`

	authTargetVectorJSON = `{"format":"locklark.remote-unlock","version":1,"kind":"device-transport-binding","member_id":"member-0001","device_id":"device-target","install_id":"install-0002","vault_id":"vault-0001","pair_generation":0,"spki_sha256":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","recipient_public_key":"age174eluezwt4dz6f3pj7mt520y6m9n85lgpnezw4j9e266m763vp6suajx3z","signature":"xBQxwub1OV2wW3NfmTaRLWOlZoidOvieEVUcGxFzcc6SuqI3L2Pn76eEbyr0wwagj_nXcWZeCIg4Ime33htADQ"}`

	// authContextDigestVector is SHA-256(AuthorizationContextDomain ||
	// EncodeChannelBindingContext(vectorContext())).
	authContextDigestVector = "SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU"
	// authSourceDigestVector and authTargetDigestVector are
	// DeviceTransportBindingDigest of the two bindings above.
	authSourceDigestVector = "H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U"
	authTargetDigestVector = "yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM"

	// authSignedJSONVector is the authorization without its signature member.
	authSignedJSONVector = `{"format":"locklark.remote-unlock","version":1,"kind":"owner-authorization","owner_root_key_id":"owner-root-0001","context_sha256":"SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","expires_unix_ms":1799999999000}`

	// authVectorJSON is the full canonical authorization, pinned literally so
	// authVector() and its JSON spelling are checked against one value.
	authVectorJSONPin = `{"format":"locklark.remote-unlock","version":1,"kind":"owner-authorization","owner_root_key_id":"owner-root-0001","context_sha256":"SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","expires_unix_ms":1799999999000,"signature":"uo_poPoCLDqh7YE2gdpH8reRMVu7uDpHJ4sq3EMZVorh8kY04hFDfLpPrHEyDYK0tWZCPCPGogc-LwYFG0jeAw"}`

	// authVectorSignature is the fixed synthetic owner-root signature.
	authVectorSignature = "uo_poPoCLDqh7YE2gdpH8reRMVu7uDpHJ4sq3EMZVorh8kY04hFDfLpPrHEyDYK0tWZCPCPGogc-LwYFG0jeAw"
)

// authVectorJSON is the complete canonical authorization: the signed JSON with
// the signature member appended.
var authVectorJSON = authSignedJSONVector[:len(authSignedJSONVector)-1] + `,"signature":"` + authVectorSignature + `"` + "}"

// seedKey derives a synthetic Ed25519 private key from seed bytes
// seed, seed+1, ... so every vector and fixture is reproducible.
func seedKey(seed byte) ed25519.PrivateKey {
	k := make([]byte, ed25519.SeedSize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return ed25519.NewKeyFromSeed(k)
}

func seedPublic(seed byte) ed25519.PublicKey {
	return seedKey(seed).Public().(ed25519.PublicKey)
}

// The fixture keys, all originated from the declared seed spans above. The
// fixed binding vectors are signed by exactly the keys the synthetic policy
// registers for the source and target devices.
var (
	authRootKey         = seedKey(authRootSeedSpan)
	authForeignKey      = seedKey(authForeignSeedSpan)
	authSourceKey       = seedKey(authSourceSeedSpan)
	authTargetKey       = seedKey(authTargetSeedSpan)
	authOutsider        = seedKey(authOutsiderSeedSpan)
	authReaderKey       = seedKey(authReaderSeedSpan)
	authAuthorKey       = seedKey(authAuthorSeedSpan)
	authReaderTargetKey = seedKey(authReaderTgtSeedSpan)
)

func ascendingTargetSPKI() [BindingSPKIDigestSize]byte {
	var d [BindingSPKIDigestSize]byte
	for i := range d {
		d[i] = byte(0x20 + i)
	}
	return d
}

func authSourceVector(t *testing.T) DeviceTransportBinding {
	t.Helper()
	b, err := ParseDeviceTransportBinding([]byte(authSourceVectorJSON))
	if err != nil {
		t.Fatalf("source vector does not parse: %v", err)
	}
	return b
}

func authTargetVector(t *testing.T) DeviceTransportBinding {
	t.Helper()
	b, err := ParseDeviceTransportBinding([]byte(authTargetVectorJSON))
	if err != nil {
		t.Fatalf("target vector does not parse: %v", err)
	}
	return b
}

// authVector returns the fixed synthetic authorization of the vectors above.
func authVector() OwnerRootAuthorization {
	return OwnerRootAuthorization{
		OwnerRootKeyID:      "owner-root-0001",
		ContextSHA256:       mustDigest(authContextDigestVector),
		SourceBindingSHA256: mustDigest(authSourceDigestVector),
		TargetBindingSHA256: mustDigest(authTargetDigestVector),
		ExpiresUnixMS:       1799999999000,
		Signature:           mustSignature(authVectorSignature),
	}
}

func mustSignature(s string) [AuthorizationSignatureSize]byte {
	var sig [AuthorizationSignatureSize]byte
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != AuthorizationSignatureSize {
		panic("bad vector signature")
	}
	copy(sig[:], raw)
	return sig
}

func mustDigest(s string) [DigestSize]byte {
	var d [DigestSize]byte
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	copy(d[:], raw)
	return d
}

func mustEncodeAuthorization(t *testing.T, a OwnerRootAuthorization) []byte {
	t.Helper()
	b, err := EncodeOwnerRootAuthorization(a)
	if err != nil {
		t.Fatalf("EncodeOwnerRootAuthorization: %v", err)
	}
	return b
}

// resignAuthorization signs a's current fields with the given synthetic key.
func resignAuthorization(t *testing.T, a OwnerRootAuthorization, priv ed25519.PrivateKey) OwnerRootAuthorization {
	t.Helper()
	msg, err := AuthorizationSigningBytes(a)
	if err != nil {
		t.Fatalf("AuthorizationSigningBytes: %v", err)
	}
	a.Signature = [AuthorizationSignatureSize]byte{}
	copy(a.Signature[:], ed25519.Sign(priv, msg))
	return a
}

func requireAuthorizationField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error naming %q, got nil", field)
	}
	var fe *AuthorizationFieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error is not an *AuthorizationFieldError: %v", err)
	}
	if fe.Field != field {
		t.Fatalf("AuthorizationFieldError.Field = %q, want %q (%v)", fe.Field, field, err)
	}
}

// TestAuthorizationFixedSyntheticVectors pins the exact digest bytes, the
// exact signature preimage and the exact encoded authorization, and checks the
// fixed signature under the deterministic synthetic key.
func TestAuthorizationFixedSyntheticVectors(t *testing.T) {
	src := authSourceVector(t)
	tgt := authTargetVector(t)

	ctxDigest, err := RemoteUnlockContextDigest(vectorContext())
	if err != nil {
		t.Fatalf("RemoteUnlockContextDigest: %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(ctxDigest[:]); got != authContextDigestVector {
		t.Fatalf("context digest = %s, want %s", got, authContextDigestVector)
	}
	// The domain prefix is part of the digest: hashing the bare context bytes
	// must give a different value.
	if digestOf(mustEncode(t, vectorContext())) == ctxDigest {
		t.Fatal("context digest does not include its domain prefix")
	}

	srcDigest, err := DeviceTransportBindingDigest(src)
	if err != nil {
		t.Fatalf("DeviceTransportBindingDigest(source): %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(srcDigest[:]); got != authSourceDigestVector {
		t.Fatalf("source binding digest = %s, want %s", got, authSourceDigestVector)
	}
	tgtDigest, err := DeviceTransportBindingDigest(tgt)
	if err != nil {
		t.Fatalf("DeviceTransportBindingDigest(target): %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(tgtDigest[:]); got != authTargetDigestVector {
		t.Fatalf("target binding digest = %s, want %s", got, authTargetDigestVector)
	}
	if srcDigest == tgtDigest {
		t.Fatal("distinct bindings share a digest")
	}

	// The digest covers the complete signed binding, signature included: a
	// still-canonical binding whose own signature changed gets a new digest.
	unsigned := src
	unsigned.Signature[0] ^= 0x01
	if _, err := EncodeDeviceTransportBinding(unsigned); err != nil {
		t.Fatalf("mutated binding is not encodable: %v", err)
	}
	if changed, _ := DeviceTransportBindingDigest(unsigned); changed == srcDigest {
		t.Fatal("binding digest ignores the binding signature")
	}

	if got := base64.RawURLEncoding.EncodeToString(seedPublic(0x20)); got != authorizationVectorPublicKey {
		t.Fatalf("deterministic owner-root public key = %s, want %s", got, authorizationVectorPublicKey)
	}
	if got := base64.RawURLEncoding.EncodeToString(authSourceKey.Public().(ed25519.PublicKey)); got != authSourceVectorPublicKey {
		t.Fatalf("source fixture public key = %s, want %s", got, authSourceVectorPublicKey)
	}
	if !ed25519.Verify(authSourceKey.Public().(ed25519.PublicKey), mustSigningBytes(t, src), src.Signature[:]) {
		t.Fatal("fixed source binding signature does not verify")
	}
	if !ed25519.Verify(authTargetKey.Public().(ed25519.PublicKey), mustSigningBytes(t, tgt), tgt.Signature[:]) {
		t.Fatal("fixed target binding signature does not verify")
	}

	a := authVector()
	if a.ContextSHA256 != ctxDigest || a.SourceBindingSHA256 != srcDigest || a.TargetBindingSHA256 != tgtDigest {
		t.Fatalf("vector authorization digests differ from the computed digests: %+v", a)
	}
	preimage, err := AuthorizationSigningBytes(a)
	if err != nil {
		t.Fatalf("AuthorizationSigningBytes: %v", err)
	}
	wantPreimage := OwnerRootAuthorizationSignatureDomain + authSignedJSONVector
	if string(preimage) != wantPreimage {
		t.Fatalf("signing preimage mismatch\n got: %q\nwant: %q", preimage, wantPreimage)
	}
	if !ed25519.Verify(seedPublic(0x20), preimage, a.Signature[:]) {
		t.Fatal("fixed owner-root signature does not verify over the preimage")
	}

	encoded := mustEncodeAuthorization(t, a)
	if string(encoded) != authVectorJSONPin {
		t.Fatalf("canonical encoding mismatch\n got: %s\nwant: %s", encoded, authVectorJSONPin)
	}
	// The composed vector (signed JSON + signature member) is the same value.
	if authVectorJSON != authVectorJSONPin {
		t.Fatalf("composed vector differs from the pinned literal\n got: %s\nwant: %s", authVectorJSON, authVectorJSONPin)
	}
	if len(encoded) > MaxAuthorizationSize {
		t.Fatalf("vector uses %d bytes, over budget %d", len(encoded), MaxAuthorizationSize)
	}
	parsed, err := ParseOwnerRootAuthorization([]byte(authVectorJSON))
	if err != nil {
		t.Fatalf("ParseOwnerRootAuthorization: %v", err)
	}
	if parsed != a {
		t.Fatalf("parsed authorization mismatch\n got: %+v\nwant: %+v", parsed, a)
	}
	if !bytes.Equal(mustEncodeAuthorization(t, parsed), encoded) {
		t.Fatal("re-encode of the parsed vector differs")
	}
	if parsed.ExpiresUnixMS != 1799999999000 {
		t.Fatalf("expires_unix_ms = %d, want 1799999999000", parsed.ExpiresUnixMS)
	}

	// The JSON and stream APIs must not diverge.
	marshaled, err := a.MarshalJSON()
	if err != nil || !bytes.Equal(marshaled, encoded) {
		t.Fatalf("MarshalJSON = %s, %v; want %s, nil", marshaled, err, encoded)
	}
	var decoded OwnerRootAuthorization
	if err := decoded.UnmarshalJSON(encoded); err != nil || decoded != a {
		t.Fatalf("UnmarshalJSON = %+v, %v; want %+v, nil", decoded, err, a)
	}
}

func digestOf(b []byte) [DigestSize]byte { return sha256.Sum256(b) }

func mustSigningBytes(t *testing.T, b DeviceTransportBinding) []byte {
	t.Helper()
	msg, err := SigningBytes(b)
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	return msg
}

// TestAuthorizationMaximumLegalBudget proves the documented maximum encoding
// fits the fixed cap. Six of the nine fields are fixed-width; only
// owner_root_key_id and expires_unix_ms vary.
func TestAuthorizationMaximumLegalBudget(t *testing.T) {
	a := authVector()
	a.OwnerRootKeyID = strings.Repeat("k", MaxIdentifierLen)
	a.ExpiresUnixMS = 1<<63 - 1
	a = resignAuthorization(t, a, seedKey(0x20))
	encoded := mustEncodeAuthorization(t, a)
	// Every field except owner_root_key_id and expires_unix_ms is fixed
	// width, so the maximum is the fixed skeleton plus the identifier and
	// int64 digits the schema allows.
	fixed := len(authVectorJSONPin) - len("owner-root-0001") - len("1799999999000") - len(authVectorSignature)
	const wantMax = 450 - len("owner-root-0001") - len("1799999999000") + MaxIdentifierLen + 19
	if len(encoded) != wantMax || len(authVectorJSONPin) != 450 || fixed < 0 {
		t.Fatalf("maximum legal authorization is %d bytes, want %d", len(encoded), wantMax)
	}
	if wantMax > MaxAuthorizationSize {
		t.Fatalf("maximum legal authorization %d exceeds the %d-byte cap", wantMax, MaxAuthorizationSize)
	}
	if _, err := ParseOwnerRootAuthorization(encoded); err != nil {
		t.Fatalf("maximum legal authorization does not parse: %v", err)
	}
	// The smallest legal authorization: one-byte identifier, expiry 1.
	a = authVector()
	a.OwnerRootKeyID = "k"
	a.ExpiresUnixMS = 1
	a = resignAuthorization(t, a, seedKey(0x20))
	if got, want := len(mustEncodeAuthorization(t, a)), wantMax-MaxIdentifierLen-19+1+1; got != want {
		t.Fatalf("minimum legal authorization is %d bytes, want %d", got, want)
	}
}

func TestEncodeAuthorizationRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*OwnerRootAuthorization)
		field  string
	}{
		{"owner root key id empty", func(a *OwnerRootAuthorization) { a.OwnerRootKeyID = "" }, "owner_root_key_id"},
		{"owner root key id too long", func(a *OwnerRootAuthorization) { a.OwnerRootKeyID = strings.Repeat("a", MaxIdentifierLen+1) }, "owner_root_key_id"},
		{"owner root key id uppercase", func(a *OwnerRootAuthorization) { a.OwnerRootKeyID = "OWNER-ROOT-0001" }, "owner_root_key_id"},
		{"owner root key id non ascii", func(a *OwnerRootAuthorization) { a.OwnerRootKeyID = "root-é" }, "owner_root_key_id"},
		{"owner root key id control", func(a *OwnerRootAuthorization) { a.OwnerRootKeyID = "root\x00id" }, "owner_root_key_id"},
		{"expires zero", func(a *OwnerRootAuthorization) { a.ExpiresUnixMS = 0 }, "expires_unix_ms"},
		{"expires negative", func(a *OwnerRootAuthorization) { a.ExpiresUnixMS = -1 }, "expires_unix_ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := authVector()
			tt.mutate(&a)
			if _, err := EncodeOwnerRootAuthorization(a); !errors.Is(err, ErrInvalidAuthorization) {
				t.Fatalf("EncodeOwnerRootAuthorization error does not wrap ErrInvalidAuthorization: %v", err)
			} else {
				requireAuthorizationField(t, err, tt.field)
			}
			if _, err := AuthorizationSigningBytes(a); !errors.Is(err, ErrInvalidAuthorization) {
				t.Fatalf("AuthorizationSigningBytes error does not wrap ErrInvalidAuthorization: %v", err)
			}
		})
	}
}

// TestAuthorizationParseRejectsNonCanonicalInput covers unknown, duplicate,
// missing and reordered members, whitespace and trailing data, bad integers,
// bad digest and signature forms, escapes and the size cap.
func TestAuthorizationParseRejectsNonCanonicalInput(t *testing.T) {
	canonical := []byte(authVectorJSON)
	sig := `"signature":"` + authVectorSignature + `"`

	tests := []struct {
		name   string
		mutate func(t *testing.T, b []byte) []byte
		field  string
	}{
		// Missing members. Removing a member makes the next member appear
		// where a separator was expected, so the error names that next
		// member; a missing signature is reported at the object close.
		{name: "missing format", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "format") }, field: "format"},
		{name: "missing version", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "version") }, field: "kind"},
		{name: "missing kind", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "kind") }, field: "owner_root_key_id"},
		{name: "missing owner_root_key_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "owner_root_key_id") }, field: "context_sha256"},
		{name: "missing context_sha256", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "context_sha256") }, field: "source_binding_sha256"},
		{name: "missing source_binding_sha256", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "source_binding_sha256") }, field: "target_binding_sha256"},
		{name: "missing target_binding_sha256", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "target_binding_sha256") }, field: "expires_unix_ms"},
		{name: "missing expires_unix_ms", mutate: func(t *testing.T, b []byte) []byte {
			return removeMember(t, b, "expires_unix_ms")
		}, field: "signature"},
		{name: "missing signature", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "signature") }, field: ""},
		{name: "empty object", mutate: func(t *testing.T, b []byte) []byte { return []byte(`{}`) }, field: ""},

		// Unknown, duplicate and reordered members.
		{name: "unknown member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `}`, `,"admin":true}`)
		}, field: ""},
		{name: "unknown renamed member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner_root_key_id":`, `"owner_key_id":`)
		}, field: ""},
		{name: "duplicate member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"context_sha256":"`+authContextDigestVector+`",`,
				`"context_sha256":"`+authContextDigestVector+`","context_sha256":"`+authContextDigestVector+`",`)
		}, field: "context_sha256"},
		{name: "duplicate last member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, sig+`,`+sig)
		}, field: ""},
		{name: "reordered members", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"source_binding_sha256":"`+authSourceDigestVector+`","target_binding_sha256":`,
				`"target_binding_sha256":"`+authTargetDigestVector+`","source_binding_sha256":`)
		}, field: ""},
		{name: "reordered constants", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"format":"locklark.remote-unlock","version":1,`,
				`"version":1,"format":"locklark.remote-unlock",`)
		}, field: ""},

		// Whitespace and trailing data.
		{name: "leading space", mutate: func(t *testing.T, b []byte) []byte { return append([]byte(" "), b...) }, field: ""},
		{name: "trailing newline", mutate: func(t *testing.T, b []byte) []byte { return append(b, '\n') }, field: ""},
		{name: "trailing space", mutate: func(t *testing.T, b []byte) []byte { return append(b, ' ') }, field: ""},
		{name: "trailing second value", mutate: func(t *testing.T, b []byte) []byte { return append(b, canonical...) }, field: ""},
		{name: "internal whitespace", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version": 1`)
		}, field: "version"},
		{name: "missing comma", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1,"kind"`, `"version":1"kind"`)
		}, field: ""},
		{name: "missing colon", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"kind":`, `"kind"`)
		}, field: ""},
		{name: "missing closing brace", mutate: func(t *testing.T, b []byte) []byte { return b[:len(b)-1] }, field: ""},
		{name: "extra closing brace", mutate: func(t *testing.T, b []byte) []byte { return append(b, '}') }, field: ""},
		{name: "empty input", mutate: func(t *testing.T, b []byte) []byte { return nil }, field: ""},
		{name: "not an object", mutate: func(t *testing.T, b []byte) []byte { return []byte(`[]`) }, field: ""},

		// Invalid UTF-8 and non-canonical strings.
		{name: "invalid utf8", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, "\"owner-\xffroot\"")
		}, field: ""},
		{name: "escaped identifier", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, `"owner\u002droot-0001"`)
		}, field: "owner_root_key_id"},
		{name: "escaped constant", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-authorization"`, `"owner\u002dauthorization"`)
		}, field: "kind"},
		{name: "escaped key", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"format"`, `"\u0066ormat"`)
		}, field: "format"},

		// Constants and member types.
		{name: "wrong format", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"locklark.remote-unlock"`, `"locklark.remote-unlock.v2"`)
		}, field: "format"},
		{name: "wrong kind", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-authorization"`, `"channel-binding-context"`)
		}, field: "kind"},
		{name: "wrong version value", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":2`)
		}, field: "version"},
		{name: "version as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":"1"`)
		}, field: "version"},
		{name: "version leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":01`)
		}, field: "version"},
		{name: "id as number", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, `7`)
		}, field: "owner_root_key_id"},

		// Identifier grammar.
		{name: "id empty", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, `""`)
		}, field: "owner_root_key_id"},
		{name: "id 129 bytes", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, `"`+strings.Repeat("a", MaxIdentifierLen+1)+`"`)
		}, field: "owner_root_key_id"},
		{name: "id uppercase", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, `"Owner-Root-0001"`)
		}, field: "owner_root_key_id"},
		{name: "id space", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"owner-root-0001"`, `"owner root 0001"`)
		}, field: "owner_root_key_id"},

		// expiris_unix_ms spelling and range.
		{name: "expires zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":0`)
		}, field: "expires_unix_ms"},
		{name: "expires negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":-1`)
		}, field: "expires_unix_ms"},
		{name: "expires plus sign", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":+1799999999000`)
		}, field: "expires_unix_ms"},
		{name: "expires leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":01799999999000`)
		}, field: "expires_unix_ms"},
		{name: "expires fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":1799999999000.0`)
		}, field: "expires_unix_ms"},
		{name: "expires exponent", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":1799999999e3`)
		}, field: "expires_unix_ms"},
		{name: "expires int64 overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":9223372036854775808`)
		}, field: "expires_unix_ms"},
		{name: "expires as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"expires_unix_ms":1799999999000`, `"expires_unix_ms":"1799999999000"`)
		}, field: "expires_unix_ms"},

		// Digest and signature forms.
		{name: "context digest short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"`+authContextDigestVector+`"`, `"`+authContextDigestVector[:42]+`"`)
		}, field: "context_sha256"},
		{name: "context digest padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"`+authContextDigestVector+`"`, `"`+authContextDigestVector+`="`)
		}, field: "context_sha256"},
		{name: "context digest noncanonical trailing bits", mutate: func(t *testing.T, b []byte) []byte {
			last := authContextDigestVector[len(authContextDigestVector)-1]
			alt := map[byte]byte{'U': 'V', 'V': 'U'}[last]
			return replaceOnce(t, b, `"`+authContextDigestVector+`"`, `"`+authContextDigestVector[:len(authContextDigestVector)-1]+string(alt)+`"`)
		}, field: "context_sha256"},
		{name: "context digest standard base64 alphabet", mutate: func(t *testing.T, b []byte) []byte {
			// 0xfb bytes encode to "-" in base64url; "+" is the standard
			// alphabet spelling of the same six bits.
			return replaceOnce(t, b, `"`+authContextDigestVector+`"`,
				`"`+strings.ReplaceAll(authContextDigestVector, "-", "+")+`A"`)
		}, field: "context_sha256"},
		{name: "source digest wrong size", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"`+authSourceDigestVector+`"`, `"`+authSourceDigestVector+`A"`)
		}, field: "source_binding_sha256"},
		{name: "target digest padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"`+authTargetDigestVector+`"`, `"`+authTargetDigestVector+`=="`)
		}, field: "target_binding_sha256"},
		{name: "signature short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, sig[:len(sig)-2]+`"`)
		}, field: "signature"},
		{name: "signature padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, sig[:len(sig)-1]+`="`)
		}, field: "signature"},

		// Size cap.
		{name: "input over budget", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxAuthorizationSize+1)...)
		}, field: ""},
		{name: "exactly the budget with trailing data", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxAuthorizationSize-len(b))...)
		}, field: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.mutate(t, append([]byte(nil), canonical...))
			_, err := ParseOwnerRootAuthorization(data)
			if err == nil {
				t.Fatal("ParseOwnerRootAuthorization accepted non-canonical input")
			}
			if !errors.Is(err, ErrInvalidAuthorizationEncoding) {
				t.Fatalf("error does not wrap ErrInvalidAuthorizationEncoding: %v", err)
			}
			if tt.field != "" {
				requireAuthorizationField(t, err, tt.field)
			}
		})
	}
}

func TestAuthorizationParseRejectsOversizedInput(t *testing.T) {
	for _, size := range []int{MaxAuthorizationSize + 1, MaxAuthorizationSize * 4} {
		_, err := ParseOwnerRootAuthorization(bytes.Repeat([]byte(" "), size))
		if !errors.Is(err, ErrInvalidAuthorizationEncoding) {
			t.Fatalf("%d bytes: error does not wrap ErrInvalidAuthorizationEncoding: %v", size, err)
		}
	}
}

func TestAuthorizationErrorsNeverContainValues(t *testing.T) {
	const secret = "UPPERSECRETOWNERROOT"
	a := authVector()
	a.OwnerRootKeyID = secret
	if _, err := EncodeOwnerRootAuthorization(a); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("encode error leaked or missed the identifier: %v", err)
	}
	// The unknown-key message never echoes the attacker-controlled key.
	data := replaceOnce(t, []byte(authVectorJSON), `}`, `,"`+strings.ToLower(secret)+`":1}`)
	if _, err := ParseOwnerRootAuthorization(data); err == nil || strings.Contains(err.Error(), strings.ToLower(secret)) {
		t.Fatalf("parse error leaked an unknown key: %v", err)
	}
	// A bad signature form never echoes its bytes.
	bad := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 63))
	bad = "+" + bad[1:]
	data = replaceOnce(t, []byte(authVectorJSON), `"signature":"`+authVectorSignature+`"`, `"signature":"`+bad+`"`)
	if _, err := ParseOwnerRootAuthorization(data); err == nil || strings.Contains(err.Error(), bad[1:20]) {
		t.Fatalf("parse error leaked signature bytes: %v", err)
	}
	// A verification failure names the member, never the digest or key.
	err := VerifyOwnerRootAuthorization(nil, nil, a, vectorContext(), authSourceVector(t), authTargetVector(t), 1)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("verification error leaked a value: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Synthetic vault-file fixture for the owner-root verification path.
// ---------------------------------------------------------------------------

// authorizationNowMS is the synthetic caller-supplied clock of every
// verification test. The verifier never reads a system clock.
const authorizationNowMS int64 = 1_800_000_000_000

// The synthetic age recipients of the fixed binding vectors, carried as the
// matching policy device age encryption keys.
const (
	authSourceVectorRecipient = "age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea"
	authTargetVectorRecipient = "age174eluezwt4dz6f3pj7mt520y6m9n85lgpnezw4j9e266m763vp6suajx3z"
	// authOtherRecipient is a different, valid synthetic age recipient.
	authOtherRecipient = "age13aqvttdk3ujkyjh9kg2w5an6dmy5mq5a84a4uxk3hfhnugfc9p0sy5p2wh"
)

const (
	authMemberID          = "member-0001"
	authSourceDeviceID    = "device-source"
	authTargetDeviceID    = "device-target"
	authVaultID           = "vault-0001"
	authPolicySeq         = 3
	authKeyEpoch          = 7
	authOwnerRootKeyID    = "owner-root-0001"
	authAuthorPrincipalID = "writer-0001"
)

// authPolicy builds the synthetic current policy. alice is an owner; the
// context member member-0001 holds the reader and writer roles with both
// devices, so it can read and author content; bob is a writer, carol an admin
// with the outsider device, and prior-reader reads only.
func authPolicy() *vaultfile.Policy {
	return &vaultfile.Policy{
		Format:           vaultfile.Format,
		Version:          vaultfile.Version,
		VaultID:          authVaultID,
		PolicySeq:        authPolicySeq,
		PrevPolicyDigest: bytes.Repeat([]byte{0x6a}, vaultfile.MaxIDLength/2),
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID:     authOwnerRootKeyID,
			Alg:       vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(seedPublic(0x20)),
			Owners:    []vaultfile.Principal{{PrincipalID: "alice", Label: "Alice"}},
		},
		Readers: []vaultfile.Member{{PrincipalID: authMemberID, Label: "Alice"}, {PrincipalID: "prior-reader", Label: "Prior reader"}},
		Writers: []vaultfile.Member{{PrincipalID: "bob", Label: "Bob"}, {PrincipalID: authMemberID, Label: "Alice"}},
		Admins:  []vaultfile.Member{{PrincipalID: "carol", Label: "Carol"}},
		Owners:  []vaultfile.Member{{PrincipalID: "alice", Label: "Alice"}},
		Devices: []vaultfile.Device{
			{
				DeviceID:          "device-outsider",
				PrincipalID:       "carol",
				Label:             "Synthetic outsider",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authOutsider.Public().(ed25519.PublicKey))},
				AgeEncryptionKey:  ageRecipientFor(authTestX25519Scalar("outsider")),
			},
			{
				DeviceID:          authSourceDeviceID,
				PrincipalID:       authMemberID,
				Label:             "Synthetic source",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authSourceKey.Public().(ed25519.PublicKey))},
				AgeEncryptionKey:  authSourceVectorRecipient,
			},
			{
				DeviceID:          authTargetDeviceID,
				PrincipalID:       authMemberID,
				Label:             "Synthetic target",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authTargetKey.Public().(ed25519.PublicKey))},
				AgeEncryptionKey:  authTargetVectorRecipient,
			},
		},
	}
}

// authTestX25519Scalar is a deterministic X25519 scalar for synthetic age
// recipients; no identity derived from it is ever used.
func authTestX25519Scalar(label string) []byte {
	k := sha256.Sum256([]byte("locklark-synthetic-age-scalar/" + label))
	s := k[:]
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}

// ageRecipientFor turns a scalar into the canonical age recipient through
// filippo.io/age's own encoder; the identity is synthetic and never used.
func ageRecipientFor(scalar []byte) string {
	id, err := age.ParseX25519Identity(ageIdentityFor(scalar))
	if err != nil {
		panic(err)
	}
	return id.Recipient().String()
}

// ageIdentityFor is the age secret-key text of scalar: the bech32 encoding
// age expects, upper-cased as age prints it (the HRP, including its trailing
// hyphen, is part of the upper-cased text).
func ageIdentityFor(scalar []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	hrp := "age-secret-key-"
	var data []byte
	acc, bits := uint32(0), byte(0)
	for _, v := range scalar {
		acc = acc<<8 | uint32(v)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data = append(data, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		data = append(data, byte(acc<<(5-bits))&31)
	}
	expansion := make([]byte, 0, len(hrp)*2+1)
	for _, c := range []byte(hrp) {
		expansion = append(expansion, c>>5)
	}
	expansion = append(expansion, 0)
	for _, c := range []byte(hrp) {
		expansion = append(expansion, c&31)
	}
	values := append(expansion, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if top>>i&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	mod := chk ^ 1
	// Build the lower-case text from a fresh buffer first: the upper-case
	// step below must never write into the shared data slice.
	out := []byte(hrp + "1")
	for _, p := range data {
		out = append(out, charset[p])
	}
	for i := 0; i < 6; i++ {
		out = append(out, charset[mod>>uint(5*(5-i))&31])
	}
	return strings.ToUpper(string(out))
}

// authDeviceByID returns the device of p with id, resolved by device ID (the
// policy array is sorted, so positions are not semantic).
func authDeviceByID(t *testing.T, p *vaultfile.Policy, id string) *vaultfile.Device {
	t.Helper()
	for i := range p.Devices {
		if p.Devices[i].DeviceID == id {
			return &p.Devices[i]
		}
	}
	t.Fatalf("device %q not in policy", id)
	return nil
}

// authPolicyVariant applies mutate to a copy of the synthetic policy.
func authPolicyVariant(mutate func(*vaultfile.Policy)) *vaultfile.Policy {
	p := authPolicy()
	p.OwnerRoot.PublicKey = bytes.Clone(p.OwnerRoot.PublicKey)
	p.Devices = append([]vaultfile.Device(nil), p.Devices...)
	for i := range p.Devices {
		p.Devices[i].ContentSigningKey.PublicKey = bytes.Clone(p.Devices[i].ContentSigningKey.PublicKey)
	}
	mutate(p)
	return p
}

// authDeviceKey is the synthetic content signing (and fixture author) key of
// each fixture device.
func authDeviceKey(deviceID string) ed25519.PrivateKey {
	switch deviceID {
	case authSourceDeviceID:
		return authSourceKey
	case authTargetDeviceID:
		return authTargetKey
	case "device-author":
		return authAuthorKey
	case "device-reader":
		return authReaderKey
	case "device-reader-target":
		return authReaderTargetKey
	}
	return authOutsider
}

// carryProof appends p to f as the next proof, chained to the digest of the
// current last proof, and leaves a shaped placeholder signature.
func carryProof(f *vaultfile.File, p *vaultfile.Policy) {
	p.Format, p.Version, p.VaultID = vaultfile.Format, vaultfile.Version, authVaultID
	if len(f.SignedPolicyProofs) == 0 {
		p.PolicySeq = 0
		p.PrevPolicyDigest = nil
	} else {
		last := &f.SignedPolicyProofs[len(f.SignedPolicyProofs)-1].Policy
		p.PolicySeq = last.PolicySeq + 1
		p.PrevPolicyDigest = vaultfile.PolicyDigest(last)
	}
	doc, err := vaultfile.EncodePolicyDocument(p)
	if err != nil {
		panic(err)
	}
	f.SignedPolicyProofs = append(f.SignedPolicyProofs, vaultfile.SignedPolicy{
		Policy: *p, Document: doc, SignerID: authOwnerRootKeyID, Alg: vaultfile.PolicySigAlgEd25519,
		Sig: make([]byte, ed25519.SignatureSize),
	})
}

// signProof signs proof i of f with priv over the frozen policy-document
// preimage.
func signProof(f *vaultfile.File, i int, priv ed25519.PrivateKey) {
	sp := &f.SignedPolicyProofs[i]
	sp.Sig = ed25519.Sign(priv, append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), sp.Document...))
}

// authFixture is one synthetic, sealed vault file, its caller-pinned
// PolicyCheckpoint (pinning the genesis policy proof) and the checkpoint
// sequence.
type authFixture struct {
	file       *vaultfile.File
	checkpoint *vaultfile.PolicyCheckpoint
	anchorSeq  uint64
}

// authChain is the number of carried policy proofs of the default fixture:
// the genesis anchor at policy_seq 0 and two root-signed continuations. The
// current policy is proof 2 at policy_seq 2.
const authChain = 3

// newAuthFixture builds and seals a synthetic vault file carrying policies
// as consecutive proofs signed by the synthetic owner root. The caller
// checkpoint pins the genesis proof exactly as carried, so an independently
// passed PolicyCheckpoint authenticates the whole chain before use.
func newAuthFixture(t *testing.T, policies ...*vaultfile.Policy) *authFixture {
	t.Helper()
	f := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version}
	for _, p := range policies {
		carryProof(f, p)
	}
	for i := range f.SignedPolicyProofs {
		signProof(f, i, seedKey(0x20))
	}
	return sealAuthFile(t, f)
}

// defaultAuthPolicies is the three-proof chain: a genesis policy whose
// readers are just the context member, and the current authPolicy at
// policy_seq 2. The anchor proof is the genesis policy.
func defaultAuthPolicies() []*vaultfile.Policy {
	genesis := authPolicyVariant(func(p *vaultfile.Policy) {
		p.PolicySeq = 0
		p.PrevPolicyDigest = nil
		// Only the context member and its two devices exist yet.
		p.Devices = p.Devices[:2]
		p.Readers = []vaultfile.Member{{PrincipalID: authMemberID, Label: "Alice"}}
		p.Writers = []vaultfile.Member{{PrincipalID: authMemberID, Label: "Alice"}}
	})
	return []*vaultfile.Policy{genesis, authPolicy(), authPolicy()}
}

// sealAuthFile computes the header of the current policy, signs the content
// as the source device (a synthetic writer through its reader principal) and
// seals with SealFile. The checkpoint pins proof 0.
func sealAuthFile(t *testing.T, f *vaultfile.File) *authFixture {
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
		AuthorDeviceID: authSourceDeviceID,
	}
	f.ContentEncoding = vaultfile.ContentEncoding
	// Structural placeholders only: no real KDBX, age wrapping or VUK exists.
	f.KDBXCiphertext = []byte("synthetic-kdbx-ciphertext-not-a-real-kdbx")
	// One slot per read-capable device, in strictly increasing device_id
	// order; every wrapped key is a placeholder. Slots are derived from the
	// current policy, so a scenario variant's registered devices stay covered.
	var slots []vaultfile.DeviceSlot
	for _, d := range cur.Devices {
		slots = append(slots, vaultfile.DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("synthetic-wrapped-vuk")})
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].DeviceID < slots[j].DeviceID })
	f.VUKDeviceSlots = slots
	f.CEKSlot = vaultfile.CEKSlot{KeyEpoch: authKeyEpoch, WrappedCEK: []byte("synthetic-wrapped-cek")}
	sealed := signAndSeal(t, f, authSourceDeviceID)
	fx := &authFixture{
		file:      sealed,
		anchorSeq: sealed.SignedPolicyProofs[0].Policy.PolicySeq,
	}
	fx.checkpoint = &vaultfile.PolicyCheckpoint{
		VaultID:            authVaultID,
		OwnerRootKeyID:     authOwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(seedPublic(0x20)),
		PolicySeq:          fx.anchorSeq,
		PolicyDigest:       vaultfile.PolicyDigest(&sealed.SignedPolicyProofs[0].Policy),
	}
	if err := vaultfile.VerifyPolicyCheckpoint(sealed, fx.checkpoint); err != nil {
		t.Fatalf("synthetic fixture is not checkpoint-authentic: %v", err)
	}
	return fx
}

// signAndSeal signs the draft f as author with its legitimate synthetic key
// and returns the re-parsed sealed file.
func signAndSeal(t *testing.T, f *vaultfile.File, author string) *vaultfile.File {
	t.Helper()
	draft := *f
	draft.Header.RevisionID = ""
	draft.Header.AuthorDeviceID = author
	draft.ContentSignature = vaultfile.Signature{SignerID: author, Alg: vaultfile.SigAlgEd25519, Sig: make([]byte, ed25519.SignatureSize)}
	canonical, err := vaultfile.ContentSigningBytes(&draft)
	if err != nil {
		t.Fatalf("synthetic draft is not structurally valid: %v", err)
	}
	msg := append([]byte(vaultfile.DomainContentSignature+"\x00"), canonical...)
	draft.ContentSignature.Sig = ed25519.Sign(authDeviceKey(author), msg)
	sealed, err := vaultfile.SealFile(&draft, &draft.ContentSignature)
	if err != nil {
		t.Fatalf("SealFile: %v", err)
	}
	parsed, err := vaultfile.ParseFile(sealed)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return parsed
}

func (fx *authFixture) cloneCheckpoint() *vaultfile.PolicyCheckpoint {
	c := *fx.checkpoint
	c.OwnerRootPublicKey = bytes.Clone(c.OwnerRootPublicKey)
	c.PolicyDigest = bytes.Clone(c.PolicyDigest)
	return &c
}

// currentPolicy returns the authenticated current policy of the fixture.
func (fx *authFixture) currentPolicy() *vaultfile.Policy {
	return &fx.file.SignedPolicyProofs[len(fx.file.SignedPolicyProofs)-1].Policy
}

// authorizationContextFor builds the context of the fixture's current policy
// with a request deadline 60 seconds after the synthetic clock.
func (fx *authFixture) authorizationContextFor() ChannelBindingContext {
	c := vectorContext()
	c.VaultID = authVaultID
	c.MemberID = authMemberID
	c.SourceDeviceID = authSourceDeviceID
	c.TargetDeviceID = authTargetDeviceID
	c.KeyEpoch = fx.file.Header.KeyEpoch
	c.PolicySeq = fx.file.Header.PolicySeq
	c.PolicyDigest = [DigestSize]byte(vaultfile.PolicyDigest(fx.currentPolicy()))
	c.DeadlineUnixMS = authorizationNowMS + 60_000
	return c
}

// authorizationFor signs a fresh synthetic owner authorization over c and the
// two bindings, expiring 30 seconds after the synthetic clock.
func (fx *authFixture) authorizationFor(t *testing.T, c ChannelBindingContext, src, tgt DeviceTransportBinding) OwnerRootAuthorization {
	t.Helper()
	ctxDigest, err := RemoteUnlockContextDigest(c)
	if err != nil {
		t.Fatalf("RemoteUnlockContextDigest: %v", err)
	}
	srcDigest, err := DeviceTransportBindingDigest(src)
	if err != nil {
		t.Fatalf("DeviceTransportBindingDigest(source): %v", err)
	}
	tgtDigest, err := DeviceTransportBindingDigest(tgt)
	if err != nil {
		t.Fatalf("DeviceTransportBindingDigest(target): %v", err)
	}
	a := OwnerRootAuthorization{
		OwnerRootKeyID:      authOwnerRootKeyID,
		ContextSHA256:       ctxDigest,
		SourceBindingSHA256: srcDigest,
		TargetBindingSHA256: tgtDigest,
		ExpiresUnixMS:       authorizationNowMS + 30_000,
	}
	return resignAuthorization(t, a, seedKey(0x20))
}

// verify runs the verifier for fx with a fresh copy of the pinned checkpoint
// and the fixture clock.
func (fx *authFixture) verify(a OwnerRootAuthorization, c ChannelBindingContext, src, tgt DeviceTransportBinding) error {
	return VerifyOwnerRootAuthorization(fx.file, fx.cloneCheckpoint(), a, c, src, tgt, authorizationNowMS)
}

// testVault returns a structurally valid, sealed synthetic file whose content
// signature does not verify under the current policy's key.
func testVault(t *testing.T) *vaultfile.File {
	t.Helper()
	f := *newAuthFixture(t, defaultAuthPolicies()...).file
	// Flip one bit of the sealed content signature: the shape stays valid
	// and only VerifyPolicyCheckpoint's cryptographic check can reject it.
	f.ContentSignature.Sig[0] ^= 0x01
	return &f
}

// TestOwnerRootAuthorizationSyntheticFullPath is the one full minimal valid
// owner-root path. Every identity, key, policy and content byte is synthetic;
// all crypto-valid values are real Ed25519 output so the path is
// demonstrably crypto-valid, but it demonstrates the verifier boundary only.
func TestOwnerRootAuthorizationSyntheticFullPath(t *testing.T) {
	fx := newAuthFixture(t, defaultAuthPolicies()...)
	if got := fx.currentPolicy().PolicySeq; got != 2 {
		t.Fatalf("current policy_seq = %d, want 2", got)
	}
	c := fx.authorizationContextFor()
	src, tgt := authSourceVector(t), authTargetVector(t)
	a := fx.authorizationFor(t, c, src, tgt)

	// The fixture bindings are exactly the fixed vectors and stay consistent
	// with the context and each device's synthetic key.
	if err := VerifyDeviceTransportBindingForContext(src, c, authSourceDeviceID, authSourceKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("source fixture binding: %v", err)
	}
	if err := VerifyDeviceTransportBindingForContext(tgt, c, authTargetDeviceID, authTargetKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("target fixture binding: %v", err)
	}
	if _, err := ParseOwnerRootAuthorization(mustEncodeAuthorization(t, a)); err != nil {
		t.Fatalf("fixture authorization is not canonical: %v", err)
	}
	if err := fx.verify(a, c, src, tgt); err != nil {
		t.Fatalf("valid synthetic owner-root path rejected: %v", err)
	}
	// Expiry is exclusive: one millisecond before it still verifies.
	if err := VerifyOwnerRootAuthorization(fx.file, fx.cloneCheckpoint(), a, c, src, tgt, a.ExpiresUnixMS-1); err != nil {
		t.Fatalf("authorization rejected one millisecond before expiry: %v", err)
	}
	// The verifier reads no file: the fixture still verifies afterwards.
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.checkpoint); err != nil {
		t.Fatalf("verification changed the fixture: %v", err)
	}

	// VerifyPolicyCheckpoint, not this verifier, owns the content author role:
	// the same authorization still verifies when the target device authored
	// the content, because both devices belong to the read-qualified member.
	fx.file = signAndSeal(t, fx.file, authTargetDeviceID)
	if err := fx.verify(a, c, src, tgt); err != nil {
		t.Fatalf("valid path with target-authored content rejected: %v", err)
	}
}

// authInputs is one complete set of verifier inputs, mutated per case.
type authInputs struct {
	file   *vaultfile.File
	cp     *vaultfile.PolicyCheckpoint
	auth   OwnerRootAuthorization
	ctx    ChannelBindingContext
	src    DeviceTransportBinding
	tgt    DeviceTransportBinding
	now    int64
	broken *vaultfile.File // when set, replaces file after sealing
}

// TestOwnerRootAuthorizationRejectsMutations mutates every input the verifier
// depends on and requires it to fail closed. Each case reports whether its
// failure is a stable *AuthorizationFieldError naming a member, or a wrapped
// vaultfile checkpoint error.
func TestOwnerRootAuthorizationRejectsMutations(t *testing.T) {
	// fixtureWith builds a fresh fixture whose default policy is replaced.
	fixtureWith := func(t *testing.T, mutate func(*vaultfile.Policy)) *authFixture {
		policies := defaultAuthPolicies()
		mutate(policies[2])
		return newAuthFixture(t, policies...)
	}
	tests := []struct {
		name  string
		field string
		wrap  error
		fx    func(t *testing.T) *authFixture
		check func(t *testing.T, err error)
		apply func(t *testing.T, in *authInputs)
	}{
		// Changed context claims. Without re-signing, the context digest
		// mismatch is reported first.
		{name: "context request change", apply: func(t *testing.T, in *authInputs) {
			in.ctx.RequestID = "req-0002"
		}, field: "context_sha256", wrap: ErrInvalidAuthorization},
		{name: "context request change without re-signing", apply: func(t *testing.T, in *authInputs) {
			// The original owner-root signature covers the old request, so
			// the changed request's context digest no longer matches.
			in.ctx.RequestID, in.ctx.RequestDigest = "req-0002", descendingDigest()
		}, field: "context_sha256", wrap: ErrInvalidAuthorization},
		{name: "signed context deadline change past authorization", apply: func(t *testing.T, in *authInputs) {
			in.auth = mustUnauthorizedFor(t, in) // signed first: expiry fits
			in.ctx.DeadlineUnixMS = authorizationNowMS + 20_000
		}, field: "expires_unix_ms", wrap: ErrInvalidAuthorization},
		{name: "signed context policy_seq change", apply: func(t *testing.T, in *authInputs) {
			in.ctx.PolicySeq++
			in.auth = mustUnauthorizedFor(t, in)
		}, wrap: ErrInvalidAuthorization},
		{name: "signed context policy_digest change", apply: func(t *testing.T, in *authInputs) {
			in.ctx.PolicyDigest[0] ^= 0x01
			in.auth = mustUnauthorizedFor(t, in)
		}, wrap: ErrInvalidAuthorization},
		{name: "signed context vault change", apply: func(t *testing.T, in *authInputs) {
			in.ctx.VaultID = "vault-0002"
			in.auth = mustUnauthorizedFor(t, in)
		}, wrap: ErrInvalidAuthorization},
		{name: "signed context key_epoch change", apply: func(t *testing.T, in *authInputs) {
			in.ctx.KeyEpoch++
			in.auth = mustUnauthorizedFor(t, in)
		}, wrap: ErrInvalidAuthorization},
		{name: "signed context member change", fx: func(t *testing.T) *authFixture {
			// bob exists in the policy only as a writer without devices.
			return newAuthFixture(t, defaultAuthPolicies()...)
		}, apply: func(t *testing.T, in *authInputs) {
			in.ctx.MemberID = "bob"
			in.auth = mustUnauthorizedFor(t, in)
		}, field: "context.source_device_id", wrap: ErrInvalidAuthorization},
		{name: "context key_epoch zero is not canonical", apply: func(t *testing.T, in *authInputs) {
			in.ctx.KeyEpoch = 0
		}, wrap: ErrInvalidAuthorization},
		{name: "context endpoints equal", apply: func(t *testing.T, in *authInputs) {
			in.ctx.TargetDeviceID = authSourceDeviceID
			in.auth = mustUnauthorizedFor(t, in)
		}, wrap: ErrInvalidAuthorization},
		{name: "context source device unknown", apply: func(t *testing.T, in *authInputs) {
			in.ctx.SourceDeviceID = "device-unknown"
			in.auth = mustUnauthorizedFor(t, in)
		}, field: "context.source_device_id", wrap: ErrInvalidAuthorization},
		{name: "context target device removed", apply: func(t *testing.T, in *authInputs) {
			in.ctx.TargetDeviceID = "device-removed"
			in.auth = mustUnauthorizedFor(t, in)
		}, field: "context.target_device_id", wrap: ErrInvalidAuthorization},
		{name: "source device belongs to another principal", fx: func(t *testing.T) *authFixture {
			return fixtureWith(t, func(p *vaultfile.Policy) {
				// The source device is resolved by device ID, then re-owned by
				// the writer bob: the source exchange still verifies for the
				// same device underneath bob.
				src := authDeviceByID(t, p, authSourceDeviceID)
				src.PrincipalID = "bob"
			})
		}, apply: func(t *testing.T, in *authInputs) {}, field: "context.source_device_id", wrap: ErrInvalidAuthorization},

		// Binding swaps, digests, SPKI, recipient and signatures.
		{name: "source and target bindings swapped", apply: func(t *testing.T, in *authInputs) {
			// The target binding arrives as the source: its recipient is not
			// the source device's policy encryption key.
			in.src, in.tgt = in.tgt, in.src
		}, field: "source_binding.recipient_public_key", wrap: ErrInvalidAuthorization},
		{name: "source binding claims the other device", apply: func(t *testing.T, in *authInputs) {
			// The source binding now claims the target device but keeps the
			// source device signature: it must not verify under the target
			// device's authenticated key.
			in.src.DeviceID = authTargetDeviceID
		}, wrap: ErrInvalidBinding},
		{name: "source binding renamed to the target device", apply: func(t *testing.T, in *authInputs) {
			in.src.DeviceID = authTargetDeviceID
		}, wrap: ErrInvalidBinding},
		{name: "source binding digest replaced by target digest", apply: func(t *testing.T, in *authInputs) {
			in.auth.SourceBindingSHA256 = in.auth.TargetBindingSHA256
		}, field: "source_binding_sha256", wrap: ErrInvalidAuthorization},
		{name: "target binding digest replaced by source digest", apply: func(t *testing.T, in *authInputs) {
			in.auth.TargetBindingSHA256 = in.auth.SourceBindingSHA256
		}, field: "target_binding_sha256", wrap: ErrInvalidAuthorization},
		{name: "swapped binding digests, root re-signed", apply: func(t *testing.T, in *authInputs) {
			in.auth.SourceBindingSHA256, in.auth.TargetBindingSHA256 = in.auth.TargetBindingSHA256, in.auth.SourceBindingSHA256
			in.auth = resignAuthorization(t, in.auth, seedKey(0x20))
		}, wrap: ErrInvalidAuthorization},
		{name: "binding spki mutated", apply: func(t *testing.T, in *authInputs) {
			in.src.SPKISHA256[0] ^= 0xff
		}, wrap: ErrInvalidBinding},
		{name: "binding recipient mutated", apply: func(t *testing.T, in *authInputs) {
			in.tgt.RecipientPublicKey = authOtherRecipient
		}, field: "target_binding.recipient_public_key", wrap: ErrInvalidAuthorization},
		{name: "binding install id mutated", apply: func(t *testing.T, in *authInputs) {
			in.src.InstallID = "install-0009"
		}, wrap: ErrInvalidBinding},
		{name: "binding signature mutated", apply: func(t *testing.T, in *authInputs) {
			in.src.Signature[0] ^= 0x01
		}, wrap: ErrInvalidBinding},
		{name: "binding re-signed by the other device key", apply: func(t *testing.T, in *authInputs) {
			msg, _ := SigningBytes(in.src)
			copy(in.src.Signature[:], ed25519.Sign(authTargetKey, msg))
		}, wrap: ErrInvalidBinding},
		{name: "binding pair generation mutated", apply: func(t *testing.T, in *authInputs) {
			in.src.PairGeneration = 1
		}, wrap: ErrInvalidBinding},
		{name: "binding pair generation differs from the context", apply: func(t *testing.T, in *authInputs) {
			in.ctx.PairGeneration = 4
			in.auth = mustUnauthorizedFor(t, in)
		}, wrap: ErrInvalidBinding},
		{name: "binding renamed to the context member only", apply: func(t *testing.T, in *authInputs) {
			in.tgt.MemberID = "member-0002"
		}, wrap: ErrInvalidBinding},
		{name: "authorization expires changed without re-signing", apply: func(t *testing.T, in *authInputs) {
			in.auth.ExpiresUnixMS++
		}, field: "signature", wrap: ErrInvalidAuthorization},
		{name: "authorization signed by a foreign root", apply: func(t *testing.T, in *authInputs) {
			in.auth = resignAuthorization(t, in.auth, seedKey(0xa0))
		}, field: "signature", wrap: ErrInvalidAuthorization},
		{name: "authorization context digest zeroed", apply: func(t *testing.T, in *authInputs) {
			in.auth.ContextSHA256 = [DigestSize]byte{}
		}, field: "context_sha256", wrap: ErrInvalidAuthorization},

		// Owner root pin, including a root replaced in the file.
		{name: "authorization owner root key id differs", apply: func(t *testing.T, in *authInputs) {
			in.auth.OwnerRootKeyID = "owner-root-0002"
			in.auth = resignAuthorization(t, in.auth, seedKey(0x20))
		}, field: "owner_root_key_id", wrap: ErrInvalidAuthorization},
		{name: "checkpoint pins a different root key id", apply: func(t *testing.T, in *authInputs) {
			in.cp.OwnerRootKeyID = "owner-root-0002"
		}, wrap: ErrInvalidAuthorization},
		{name: "checkpoint pins a foreign root public key", apply: func(t *testing.T, in *authInputs) {
			in.cp.OwnerRootPublicKey = bytes.Clone(seedPublic(0xa0))
		}, wrap: ErrInvalidAuthorization},
		{name: "checkpoint root key truncated", apply: func(t *testing.T, in *authInputs) {
			in.cp.OwnerRootPublicKey = bytes.Clone(seedPublic(0x20))[:31]
		}, wrap: ErrInvalidAuthorization},
		{name: "content author moved to a device with a reader principal only", fx: func(t *testing.T) *authFixture {
			return fixtureWith(t, func(p *vaultfile.Policy) {
				// bob is an existing writer, carol an admin: neither is a
				// reader role, so the vault file still accepts their devices as
				// authors only where their own role allows it.
				p.Devices[0].PrincipalID = "bob"
				p.Devices[1].PrincipalID = "carol"
			})
		}, apply: func(t *testing.T, in *authInputs) {
			in.file = signAndSeal(t, in.file, authTargetDeviceID)
		}, field: "context.source_device_id", wrap: ErrInvalidAuthorization},

		// Header, policy epoch/sequence/digest and checkpoint mismatch.
		{name: "header vault differs from context", apply: func(t *testing.T, in *authInputs) {
			in.ctx.VaultID = "vault-0002"
			in.auth = mustUnauthorizedFor(t, in)
		}, field: "header.vault_id", wrap: ErrInvalidAuthorization},
		{name: "header policy_seq differs from context", apply: func(t *testing.T, in *authInputs) {
			in.ctx.PolicySeq = authPolicySeq + 5
			in.auth = mustUnauthorizedFor(t, in)
		}, field: "header.policy_seq", wrap: ErrInvalidAuthorization},
		{name: "context policy digest differs from header", apply: func(t *testing.T, in *authInputs) {
			in.ctx.PolicyDigest[0] ^= 0x01
			in.auth = mustUnauthorizedFor(t, in)
		}, field: "context_sha256", wrap: ErrInvalidAuthorization},
		{name: "signed context adaptive: root signs the carried policy digest of a forged file", fx: func(t *testing.T) *authFixture {
			// A forged file whose current proof is not policy_seq+1 would be
			// rejected by the checkpoint; the verifier reports the checkpoint
			// error, never a forged policy claim.
			fx := newAuthFixture(t, defaultAuthPolicies()...)
			sealed := *fx.file
			sealed.SignedPolicyProofs = append([]vaultfile.SignedPolicy(nil), fx.file.SignedPolicyProofs...)
			sealed.SignedPolicyProofs[2].Policy.PolicySeq = 9
			fx.file = &sealed
			return fx
		}, apply: func(t *testing.T, in *authInputs) {}, wrap: ErrInvalidAuthorization},
		{name: "carried policy digest differs from the authenticated policy", apply: func(t *testing.T, in *authInputs) {
			// The header digest is changed without re-signing the policy: the
			// context is recomputed from it so only the policy recomputation
			// can reject the mismatch.
			in.file.Header.PolicyDigest = bytes.Repeat([]byte{0x33}, 32)
			copy(in.ctx.PolicyDigest[:], in.file.Header.PolicyDigest)
			in.auth = mustUnauthorizedFor(t, in)
		}, wrap: ErrInvalidAuthorization},
		{name: "checkpoint from an older sequence", apply: func(t *testing.T, in *authInputs) {
			in.cp.PolicySeq = 1
			in.cp.PolicyDigest = bytes.Repeat([]byte{0x01}, 32)
		}, wrap: ErrInvalidAuthorization},
		{name: "checkpoint points past the file", apply: func(t *testing.T, in *authInputs) {
			in.cp.PolicySeq = 9
			in.cp.PolicyDigest = bytes.Repeat([]byte{0x01}, 32)
		}, wrap: ErrInvalidAuthorization},

		// Expiry and caller clock.
		{name: "expired exactly at now", apply: func(t *testing.T, in *authInputs) {
			in.ctx.DeadlineUnixMS = authorizationNowMS + 120_000
			in.auth.ExpiresUnixMS = authorizationNowMS
			in.auth = resignAuthorization(t, in.auth, seedKey(0x20))
		}, field: "expires_unix_ms", wrap: ErrInvalidAuthorization},
		{name: "expired one millisecond before now", apply: func(t *testing.T, in *authInputs) {
			in.auth.ExpiresUnixMS = authorizationNowMS - 1
			in.auth = resignAuthorization(t, in.auth, seedKey(0x20))
		}, field: "expires_unix_ms", wrap: ErrInvalidAuthorization},
		{name: "expiry one millisecond after the request deadline", apply: func(t *testing.T, in *authInputs) {
			in.auth.ExpiresUnixMS = in.ctx.DeadlineUnixMS + 1
			in.auth = resignAuthorization(t, in.auth, seedKey(0x20))
		}, field: "expires_unix_ms", wrap: ErrInvalidAuthorization},
		{name: "expiry zero", apply: func(t *testing.T, in *authInputs) {
			in.auth.ExpiresUnixMS = 0
		}, field: "expires_unix_ms", wrap: ErrInvalidAuthorization},
		{name: "expiry negative", apply: func(t *testing.T, in *authInputs) {
			in.auth.ExpiresUnixMS = -5
		}, field: "expires_unix_ms", wrap: ErrInvalidAuthorization},
		{name: "caller clock zero", apply: func(t *testing.T, in *authInputs) {
			in.now = 0
		}, wrap: ErrInvalidAuthorization},
		{name: "caller clock negative", apply: func(t *testing.T, in *authInputs) {
			in.now = -1
		}, wrap: ErrInvalidAuthorization},

		// Checkpoint verification failure.
		{name: "content signature broken after sealing", apply: func(t *testing.T, in *authInputs) {
			in.file = testVault(t)
		}, wrap: ErrInvalidAuthorization},
		{name: "checkpoint digest points elsewhere", apply: func(t *testing.T, in *authInputs) {
			in.cp.PolicyDigest[0] ^= 0x01
		}, wrap: ErrInvalidAuthorization},
		{name: "nil file", apply: func(t *testing.T, in *authInputs) {
			in.file = nil
		}, wrap: ErrInvalidAuthorization},
		{name: "nil checkpoint", apply: func(t *testing.T, in *authInputs) {
			in.cp = nil
		}, wrap: ErrInvalidAuthorization},
		{name: "binding is not canonical-valid", apply: func(t *testing.T, in *authInputs) {
			in.tgt.RecipientPublicKey = "AGE1INVALID"
		}, field: "target_binding", wrap: ErrInvalidAuthorization},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newAuthFixture(t, defaultAuthPolicies()...)
			if tt.fx != nil {
				fx = tt.fx(t)
			}
			in := &authInputs{
				file: fx.file,
				cp:   fx.cloneCheckpoint(),
				ctx:  fx.authorizationContextFor(),
				src:  authSourceVector(t),
				tgt:  authTargetVector(t),
				now:  authorizationNowMS,
			}
			in.auth = fx.authorizationFor(t, in.ctx, in.src, in.tgt)
			tt.apply(t, in)
			err := VerifyOwnerRootAuthorization(in.file, in.cp, in.auth, in.ctx, in.src, in.tgt, in.now)
			if err == nil {
				t.Fatal("verifier accepted a mutated input")
			}
			if !errors.Is(err, ErrInvalidAuthorization) {
				t.Fatalf("error does not wrap ErrInvalidAuthorization: %v", err)
			}
			if !errors.Is(err, tt.wrap) {
				t.Fatalf("error does not wrap %v: %v", tt.wrap, err)
			}
			if tt.check != nil {
				tt.check(t, err)
			}
			if tt.field != "" {
				requireAuthorizationField(t, err, tt.field)
			}
		})
	}
}

// mustUnauthorizedFor returns an owner-root-signed authorization for in's
// current context and bindings. A case that mutates a claim together with its
// signature calls it before applying the on-wire mutation it is about to test.
func mustUnauthorizedFor(t *testing.T, in *authInputs) OwnerRootAuthorization {
	t.Helper()
	ctxDigest, err := RemoteUnlockContextDigest(in.ctx)
	if err != nil {
		t.Fatalf("RemoteUnlockContextDigest: %v", err)
	}
	srcDigest, err := DeviceTransportBindingDigest(in.src)
	if err != nil {
		t.Fatalf("DeviceTransportBindingDigest(source): %v", err)
	}
	tgtDigest, err := DeviceTransportBindingDigest(in.tgt)
	if err != nil {
		t.Fatalf("DeviceTransportBindingDigest(target): %v", err)
	}
	a := in.auth
	a.ContextSHA256 = ctxDigest
	a.SourceBindingSHA256 = srcDigest
	a.TargetBindingSHA256 = tgtDigest
	return resignAuthorization(t, a, seedKey(0x20))
}

// TestAuthorizationKeyMaterialIsDeclaredAndPinned proves that every fixed key,
// signature and digest is derived from the declared seed spans and that the
// fixed vectors agree with each other: the authVector() struct is
// byte-identical to the canonical authVectorJSON, the binding vectors verify
// under the declared device keys, and the authorization verifies under the
// declared root key.
func TestAuthorizationKeyMaterialIsDeclaredAndPinned(t *testing.T) {
	// Every fixed public key is the public half of the declared seed span,
	// compared as literals so the check does not depend on a helper.
	for _, tt := range []struct {
		name string
		seed byte
		want string
	}{
		{"owner root", authRootSeedSpan, authorizationVectorPublicKey},
		{"source device", authSourceSeedSpan, authSourceVectorPublicKey},
		{"target device", authTargetSeedSpan, authTargetVectorPublicKey},
	} {
		pub := seedKey(tt.seed).Public().(ed25519.PublicKey)
		if got := base64.RawURLEncoding.EncodeToString(pub); got != tt.want {
			t.Fatalf("%s: public key of seed span %#x = %s, want %s", tt.name, tt.seed, got, tt.want)
		}
	}

	// The struct form, the composed JSON and the pinned JSON are one vector.
	vec := authVector()
	if !ed25519.Verify(seedKey(authRootSeedSpan).Public().(ed25519.PublicKey), mustPreimage(t, vec), vec.Signature[:]) {
		t.Fatal("fixed owner-root signature does not verify under the declared root key")
	}
	encoded := mustEncodeAuthorization(t, vec)
	if string(encoded) != authVectorJSONPin || string(encoded) != authVectorJSON {
		t.Fatalf("authVector() does not encode to the pinned vector\n got: %s\nwant: %s", encoded, authVectorJSONPin)
	}

	// Each binding vector is signed by exactly the declared device key, and
	// its digest is the pinned value.
	for _, tt := range []struct {
		b    DeviceTransportBinding
		priv ed25519.PrivateKey
		want string
	}{
		{authSourceVector(t), authSourceKey, authSourceDigestVector},
		{authTargetVector(t), authTargetKey, authTargetDigestVector},
	} {
		pub := seedKey(map[string]byte{authSourceDeviceID: authSourceSeedSpan, authTargetDeviceID: authTargetSeedSpan}[tt.b.DeviceID]).Public().(ed25519.PublicKey)
		if !ed25519.Verify(pub, mustSigningBytes(t, tt.b), tt.b.Signature[:]) || !ed25519.Verify(tt.priv.Public().(ed25519.PublicKey), mustSigningBytes(t, tt.b), tt.b.Signature[:]) {
			t.Fatalf("binding %s does not verify under its declared key", tt.b.DeviceID)
		}
		digest, err := DeviceTransportBindingDigest(tt.b)
		if err != nil {
			t.Fatalf("DeviceTransportBindingDigest(%s): %v", tt.b.DeviceID, err)
		}
		if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != tt.want {
			t.Fatalf("binding %s digest = %s, want %s", tt.b.DeviceID, got, tt.want)
		}
	}
}

// mustPreimage is the owner-root signing preimage of a.
func mustPreimage(t *testing.T, a OwnerRootAuthorization) []byte {
	t.Helper()
	b, err := AuthorizationSigningBytes(a)
	if err != nil {
		t.Fatalf("AuthorizationSigningBytes: %v", err)
	}
	return b
}

// TestOwnerRootAuthorizationReaderReadRegression shows the read/author role
// boundary with real synthetic crypto. A reader-only principal (the reader
// role only; member-0001 principal) registers two devices, and the current
// file is authored and sealed by an independent writer device. The owner root
// authorizes that request for the reader's own two devices, and both the
// checkpoint and the owner-root verifier accept it: a reader's existing read
// qualification is enough for this authorization. The test also asserts the
// reader holds no author role and that the public vaultfile API refuses to
// seal a current file naming a reader-only device as its content author, so no
// reader-authored file is claimed to exist.
func TestOwnerRootAuthorizationReaderReadRegression(t *testing.T) {
	const (
		readerID        = "reader-0001"
		readerDevice    = "device-reader"
		readerTargetDev = "device-reader-target"
		authorDevice    = "device-author"
	)
	readerKey := authReaderKey

	// The current policy: the reader principal holds the reader role only and
	// registers both devices; the independent writer principal-0001 owns
	// device-author, which authors the file.
	policies := defaultAuthPolicies()
	pol := authPolicyVariant(func(*vaultfile.Policy) {})
	pol.PolicySeq = authPolicySeq
	pol.PrevPolicyDigest = bytes.Repeat([]byte{0x6a}, vaultfile.MaxIDLength/2)
	policies[2] = pol
	pol.Readers = []vaultfile.Member{
		{PrincipalID: authMemberID, Label: "Alice"},
		{PrincipalID: "prior-reader", Label: "Prior reader"},
		{PrincipalID: readerID, Label: "Reader"},
	}
	pol.Writers = []vaultfile.Member{
		{PrincipalID: "bob", Label: "Bob"},
		{PrincipalID: authMemberID, Label: "Alice"},
		{PrincipalID: authAuthorPrincipalID, Label: "Writer"},
	}
	// Devices are in the frozen vaultfile order: strictly ascending device_id.
	pol.Devices = []vaultfile.Device{
		{
			DeviceID:          authorDevice,
			PrincipalID:       authAuthorPrincipalID,
			Label:             "Synthetic author",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authAuthorKey.Public().(ed25519.PublicKey))},
			AgeEncryptionKey:  ageRecipientFor(authTestX25519Scalar("author")),
		},
		{
			DeviceID:          "device-outsider",
			PrincipalID:       "carol",
			Label:             "Synthetic outsider",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authOutsider.Public().(ed25519.PublicKey))},
			AgeEncryptionKey:  ageRecipientFor(authTestX25519Scalar("outsider")),
		},
		{
			DeviceID:          readerDevice,
			PrincipalID:       readerID,
			Label:             "Synthetic reader",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(readerKey.Public().(ed25519.PublicKey))},
			AgeEncryptionKey:  ageRecipientFor(authTestX25519Scalar("reader")),
		},
		{
			DeviceID:          readerTargetDev,
			PrincipalID:       readerID,
			Label:             "Synthetic reader target",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authReaderTargetKey.Public().(ed25519.PublicKey))},
			AgeEncryptionKey:  ageRecipientFor(authTestX25519Scalar("reader-target")),
		},
		{
			DeviceID:          authSourceDeviceID,
			PrincipalID:       authMemberID,
			Label:             "Synthetic source",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authSourceKey.Public().(ed25519.PublicKey))},
			AgeEncryptionKey:  authSourceVectorRecipient,
		},
		{
			DeviceID:          authTargetDeviceID,
			PrincipalID:       authMemberID,
			Label:             "Synthetic target",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authTargetKey.Public().(ed25519.PublicKey))},
			AgeEncryptionKey:  authTargetVectorRecipient,
		},
	}
	if err := vaultfile.ValidatePolicy(pol); err != nil {
		t.Fatalf("fixture current policy is not structurally valid: %v", err)
	}
	fx := newAuthFixture(t, policies...)
	// Re-seal the request file with the independent writer device as author.
	fx.file = signAndSeal(t, fx.file, authorDevice)
	if fx.currentPolicy().Devices[0].DeviceID >= fx.currentPolicy().Devices[1].DeviceID {
		t.Fatal("fixture devices are not in ascending device_id order")
	}
	if f := fx.file; f.Header.AuthorDeviceID != authorDevice || f.ContentSignature.SignerID != authorDevice {
		t.Fatalf("fixture file author is %q, want the independent writer %q", f.Header.AuthorDeviceID, authorDevice)
	}

	// The reader holds the read role only: it qualifies to read, but it has
	// no content author role.
	if !policyReadQualified(readerID, fx.currentPolicy()) {
		t.Fatal("reader principal is not read-qualified")
	}
	for _, roles := range [3][]vaultfile.Member{fx.currentPolicy().Writers, fx.currentPolicy().Admins, fx.currentPolicy().Owners} {
		for _, m := range roles {
			if m.PrincipalID == readerID {
				t.Fatalf("reader principal %q unexpectedly holds an author role", readerID)
			}
		}
	}

	// Context: the reader principal's two registered devices are the source
	// and target of the read request.
	c := fx.authorizationContextFor()
	c.MemberID = readerID
	c.SourceDeviceID = readerDevice
	c.TargetDeviceID = readerTargetDev

	// Both bindings are real Ed25519 signatures by each device's registered
	// key, in the stable binding format.
	mkBinding := func(device, install, recipient string, priv ed25519.PrivateKey) DeviceTransportBinding {
		b := DeviceTransportBinding{MemberID: c.MemberID, DeviceID: device, InstallID: install, VaultID: c.VaultID, PairGeneration: c.PairGeneration, RecipientPublicKey: recipient}
		msg, err := SigningBytes(b)
		if err != nil {
			t.Fatalf("SigningBytes(%s): %v", device, err)
		}
		copy(b.Signature[:], ed25519.Sign(priv, msg))
		return b
	}
	src := mkBinding(readerDevice, "install-reader", ageRecipientFor(authTestX25519Scalar("reader")), readerKey)
	tgt := mkBinding(readerTargetDev, "install-reader-target", ageRecipientFor(authTestX25519Scalar("reader-target")), authReaderTargetKey)
	a := fx.authorizationFor(t, c, src, tgt)

	// Positive path: the checkpoint authenticates the writer-authored file and
	// the owner-root authorization verifies for the reader's read request.
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.cloneCheckpoint()); err != nil {
		t.Fatalf("writer-authored file is not checkpoint-authentic: %v", err)
	}
	if err := fx.verify(a, c, src, tgt); err != nil {
		t.Fatalf("root-authorized reader read access rejected: %v", err)
	}
	before := vaultfile.PolicyDigest(fx.currentPolicy())

	// Negative path at the policy/API level: a reader-only device is not a
	// content author, so the public vaultfile API refuses to build a current
	// file naming it. No reader-authored file is constructed or claimed here.
	readerDraft := *fx.file
	readerDraft.Header.AuthorDeviceID = readerDevice
	readerDraft.Header.RevisionID = ""
	readerDraft.ContentSignature = vaultfile.Signature{}
	sig := vaultfile.Signature{SignerID: readerDevice, Alg: vaultfile.SigAlgEd25519, Sig: make([]byte, ed25519.SignatureSize)}
	if _, err := vaultfile.ContentSigningBytes(&readerDraft); err == nil {
		t.Fatal("ContentSigningBytes accepted a reader-only device as content author")
	}
	if _, err := vaultfile.SealFile(&readerDraft, &sig); err == nil {
		t.Fatal("SealFile accepted a reader-only device as content author")
	}
	if err := vaultfile.ValidateFile(&readerDraft); err == nil {
		t.Fatal("ValidateFile accepted a reader-only device as content author")
	}
	// Owner-root authorization fails closed on that invalid file and never
	// treats it as a proof of the reader's authoring role.
	if err := VerifyOwnerRootAuthorization(&readerDraft, fx.cloneCheckpoint(), a, c, src, tgt, authorizationNowMS); err == nil {
		t.Fatal("owner-root authorization accepted a file whose author is a reader-only device")
	}

	// No side effect: roles, devices and the policy digest are unchanged and
	// the original authorization still verifies.
	if !bytes.Equal(vaultfile.PolicyDigest(fx.currentPolicy()), before) {
		t.Fatal("verification mutated the authenticated policy")
	}
	if !policyReadQualified(readerID, fx.currentPolicy()) {
		t.Fatal("verification changed the reader's read qualification")
	}
	for _, roles := range [3][]vaultfile.Member{fx.currentPolicy().Writers, fx.currentPolicy().Admins, fx.currentPolicy().Owners} {
		for _, m := range roles {
			if m.PrincipalID == readerID {
				t.Fatal("verification promoted the reader")
			}
		}
	}
	if err := fx.verify(a, c, src, tgt); err != nil {
		t.Fatalf("valid authorization no longer verifies after rejection: %v", err)
	}
}
