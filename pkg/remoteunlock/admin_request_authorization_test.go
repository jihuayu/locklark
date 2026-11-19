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
// declared in authorization_test.go and admin_authorization_test.go, and every
// signature, policy proof and binding is real Ed25519 output over the
// documented preimages, but none belongs to a person, device, vault,
// enrollment, owner root or admin. The owner root signs only the reusable
// grant; the delegated admin device signs every per-request authorization.
// This proves nothing about production identity, enrollment, live TLS, VUK
// delivery or durable replay protection: the verifier is state-free and the
// caller's lifecycle must prevent replay and one-shot use.
//
// The fixture is the one in admin_authorization_test.go: a sealed,
// checkpoint-authentic file whose current policy (policy_seq 2) lists carol as
// an admin with device-outsider (policy signing key from seed 0xd0) and
// member-0001 as a reader and writer with device-source and device-target. An
// independent writer device-author signs the file content.

// ---------------------------------------------------------------------------
// Types under test, by name, so the two authorization objects stay distinct.
// ---------------------------------------------------------------------------

type (
	reusableGrant = OwnerRootAdminRemoteUnlockDelegation
	requestAuth   = AdminRemoteUnlockAuthorization
)

// ---------------------------------------------------------------------------
// Fixed synthetic vector.
// ---------------------------------------------------------------------------

const (
	// adminAuthorizationVectorDelegationDigest is AdminDelegationDigest of the
	// fixed reusable grant of admin_authorization_test.go.
	adminAuthorizationVectorDelegationDigest = "BqJKqhv9FaINZWmGD_eRraFGFosPn6ZfocLgr0mZZZU"

	// adminAuthorizationSignedJSON is the canonical JSON of members 1..8, the
	// delegated-device signed preimage without its domain.
	adminAuthorizationSignedJSON = `{"format":"locklark.remote-unlock","version":1,"kind":"admin-authorization","delegation_digest":"BqJKqhv9FaINZWmGD_eRraFGFosPn6ZfocLgr0mZZZU","context_sha256":"SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","expires_unix_ms":1799999999000}`

	// adminAuthorizationVectorSignature is the fixed synthetic signature over
	// the domain and adminAuthorizationSignedJSON, by the delegated admin
	// device's policy signing key of seed span 0xd0.
	adminAuthorizationVectorSignature = "TfY7H33nPo2v_xpNmd8kbIFtbsuc_e4sK-a6WWQS_Oaew-7Ew-uEtIxQn-_mc3Zq9PFbLJHkqATZl-xUoYxYDA"
)

// adminAuthorizationVectorJSON is the complete canonical 478-byte
// authorization: the signed members with the signature member appended.
var adminAuthorizationVectorJSON = adminAuthorizationSignedJSON[:len(adminAuthorizationSignedJSON)-1] +
	`,"signature":"` + adminAuthorizationVectorSignature + `"}`

// adminAuthorizationVector returns the fixed synthetic per-request
// authorization of the fixture's request context and bindings.
func adminAuthorizationVector() requestAuth {
	return requestAuth{
		DelegationDigest:    mustDigest(adminAuthorizationVectorDelegationDigest),
		ContextSHA256:       mustDigest(authContextDigestVector),
		SourceBindingSHA256: mustDigest(authSourceDigestVector),
		TargetBindingSHA256: mustDigest(authTargetDigestVector),
		ExpiresUnixMS:       1799999999000,
		Signature:           mustAdminAuthorizationSignature(adminAuthorizationVectorSignature),
	}
}

// delegationAdminKey is the synthetic private policy signing key of the
// delegated admin device device-outsider (seed span 0xd0). It is not the owner
// root, the requester, the content author or any content signing key.
var delegationAdminKey = seedKey(delegationDelegateSeed)

func mustAdminAuthorizationSignature(s string) [AdminAuthorizationSignatureSize]byte {
	var sig [AdminAuthorizationSignatureSize]byte
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != AdminAuthorizationSignatureSize {
		panic("bad admin authorization vector signature")
	}
	copy(sig[:], raw)
	return sig
}

func mustEncodeAdminAuthorization(t *testing.T, a requestAuth) []byte {
	t.Helper()
	b, err := EncodeAdminRemoteUnlockAuthorization(a)
	if err != nil {
		t.Fatalf("EncodeAdminRemoteUnlockAuthorization: %v", err)
	}
	return b
}

func mustAdminAuthorizationPreimage(t *testing.T, a requestAuth) []byte {
	t.Helper()
	b, err := AdminAuthorizationSigningBytes(a)
	if err != nil {
		t.Fatalf("AdminAuthorizationSigningBytes: %v", err)
	}
	return b
}

// signAdminAuthorization signs a's current members with priv and returns a.
// authorize reproduces in.auth from in's current grant, context and bindings
// with in.signer.
func authorize(t *testing.T, in *adminAuthorizationInputs) requestAuth {
	t.Helper()
	a := adminAuthorizationFor(t, in.grant, in.ctx, in.src, in.tgt, in.signer)
	a.ExpiresUnixMS = in.authExpires
	return signAdminAuthorization(t, a, in.signer)
}

func signAdminAuthorization(t *testing.T, a requestAuth, priv ed25519.PrivateKey) requestAuth {
	t.Helper()
	a.Signature = [AdminAuthorizationSignatureSize]byte{}
	copy(a.Signature[:], ed25519.Sign(priv, mustAdminAuthorizationPreimage(t, a)))
	return a
}

func requireAdminAuthorizationField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error naming %q, got nil", field)
	}
	var fe *AdminAuthorizationFieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error is not an *AdminAuthorizationFieldError: %v", err)
	}
	if fe.Field != field {
		t.Fatalf("AdminAuthorizationFieldError.Field = %q, want %q (%v)", fe.Field, field, err)
	}
}

// TestAdminAuthorizationFixedSyntheticVector pins the exact preimage,
// delegated-device signature, encoding and dispatch, and proves the signing
// domain is distinct from every other remote-unlock domain.
func TestAdminAuthorizationFixedSyntheticVector(t *testing.T) {
	fx := newDelegationFixture(t, nil)
	a := adminAuthorizationVector()
	grant := adminDelegationVector()

	// The vector binds exactly the pinned fixture values.
	digest, err := AdminDelegationDigest(grant)
	if err != nil {
		t.Fatalf("AdminDelegationDigest: %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != adminAuthorizationVectorDelegationDigest {
		t.Fatalf("grant digest = %s, want the pinned %s", got, adminAuthorizationVectorDelegationDigest)
	}
	if a.DelegationDigest != digest {
		t.Fatal("vector delegation digest differs from the grant digest")
	}
	ctxDigest, err := RemoteUnlockContextDigest(vectorContext())
	if err != nil {
		t.Fatalf("RemoteUnlockContextDigest: %v", err)
	}
	if a.ContextSHA256 != ctxDigest {
		t.Fatal("vector context digest differs from the fixture context digest")
	}
	if a.SourceBindingSHA256 != mustDigest(authSourceDigestVector) || a.TargetBindingSHA256 != mustDigest(authTargetDigestVector) {
		t.Fatal("vector binding digests differ from the fixture bindings")
	}
	dev := authDeviceByID(t, fx.currentDelegationPolicy(), grant.DelegateDeviceID)
	if dev.PolicySigningKey == nil || !bytes.Equal(dev.PolicySigningKey.PublicKey, delegationAdminKey.Public().(ed25519.PublicKey)) {
		t.Fatal("vector signer key differs from the fixture delegate policy signing key")
	}
	if bytes.Equal(delegationAdminKey.Public().(ed25519.PublicKey), seedPublic(authRootSeedSpan)) ||
		bytes.Equal(delegationAdminKey.Public().(ed25519.PublicKey), authOutsider.Public().(ed25519.PublicKey)) {
		t.Fatal("vector reuses the owner root or content key as its policy signing key")
	}

	if got, want := string(mustAdminAuthorizationPreimage(t, a)), AdminAuthorizationSignatureDomain+adminAuthorizationSignedJSON; got != want {
		t.Fatalf("signing preimage mismatch\n got: %q\nwant: %q", got, want)
	}
	if !ed25519.Verify(delegationAdminKey.Public().(ed25519.PublicKey), mustAdminAuthorizationPreimage(t, a), a.Signature[:]) {
		t.Fatal("fixed delegated-device signature does not verify")
	}
	// The owner root did not sign it, and it verifies under no other domain.
	if ed25519.Verify(seedPublic(authRootSeedSpan), mustAdminAuthorizationPreimage(t, a), a.Signature[:]) {
		t.Fatal("vector signature verifies under the owner root key")
	}
	for _, dom := range []string{OwnerRootAuthorizationSignatureDomain, AdminDelegationSignatureDomain, BindingSignatureDomain, AuthorizationContextDomain} {
		if ed25519.Verify(delegationAdminKey.Public().(ed25519.PublicKey),
			append([]byte(dom), adminAuthorizationSignedJSON...), a.Signature[:]) {
			t.Fatalf("authorization signature verifies under the foreign domain %q", dom)
		}
	}
	domains := map[string]bool{}
	for _, d := range []string{AdminAuthorizationSignatureDomain, OwnerRootAuthorizationSignatureDomain, AdminDelegationSignatureDomain, BindingSignatureDomain, AuthorizationContextDomain, BindingDigestDomain, AdminDelegationDigestDomain} {
		if domains[d] {
			t.Fatalf("domain %q is reused", d)
		}
		domains[d] = true
	}

	encoded := mustEncodeAdminAuthorization(t, a)
	if string(encoded) != adminAuthorizationVectorJSON || len(encoded) != 478 {
		t.Fatalf("canonical encoding is %d bytes, want the pinned 478-byte vector\n got: %s", len(encoded), encoded)
	}
	parsed, err := ParseAdminRemoteUnlockAuthorization(encoded)
	if err != nil || parsed != a {
		t.Fatalf("Parse = %+v, %v; want %+v, nil", parsed, err, a)
	}
	marshaled, err := a.MarshalJSON()
	if err != nil || !bytes.Equal(marshaled, encoded) {
		t.Fatalf("MarshalJSON = %s, %v; want %s, nil", marshaled, err, encoded)
	}
	var decoded requestAuth
	if err := decoded.UnmarshalJSON(encoded); err != nil || decoded != a {
		t.Fatalf("UnmarshalJSON = %+v, %v; want %+v, nil", decoded, err, a)
	}

	// The per-request object carries no requester, device, vault, epoch or
	// policy member; the reusable grant carries no per-request member.
	for _, banned := range []string{"request_id", "request_digest", "lock_generation", "deadline", "member_id", "device_id", "vault_id", "policy_seq", "owner_root_key_id"} {
		if bytes.Contains(encoded, []byte(`"`+banned+`"`)) {
			t.Fatalf("authorization carries a foreign member %q", banned)
		}
	}
	for _, banned := range []string{"request_id", "request_digest", "lock_generation", "deadline", "context_sha256"} {
		if bytes.Contains(mustEncodeDelegation(t, grant), []byte(`"`+banned+`"`)) {
			t.Fatalf("reusable grant carries a per-request member %q", banned)
		}
	}
}

// TestAdminAuthorizationMaximumLegalBudget pins the documented maximum size:
// every member except expires_unix_ms is fixed width.
func TestAdminAuthorizationMaximumLegalBudget(t *testing.T) {
	a := adminAuthorizationVector()
	a.ExpiresUnixMS = 1<<63 - 1
	a = signAdminAuthorization(t, a, delegationAdminKey)
	encoded := mustEncodeAdminAuthorization(t, a)
	const wantMax = 478 - len("1799999999000") + 19
	if len(encoded) != wantMax {
		t.Fatalf("maximum legal authorization is %d bytes, want %d", len(encoded), wantMax)
	}
	if wantMax > MaxAdminAuthorizationSize {
		t.Fatalf("maximum legal authorization %d exceeds the %d-byte cap", wantMax, MaxAdminAuthorizationSize)
	}
	if _, err := ParseAdminRemoteUnlockAuthorization(encoded); err != nil {
		t.Fatalf("maximum legal authorization does not parse: %v", err)
	}
	// The smallest legal authorization: expiry 1.
	a = adminAuthorizationVector()
	a.ExpiresUnixMS = 1
	a = signAdminAuthorization(t, a, delegationAdminKey)
	// Every other member is fixed-width, so only the one-digit expiry remains.
	if got, want := len(mustEncodeAdminAuthorization(t, a)), 478-len("1799999999000")+1; got != want {
		t.Fatalf("minimum legal authorization is %d bytes, want %d", got, want)
	}
}

func TestEncodeAdminAuthorizationRejectsInvalidFields(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value int64
	}{
		{"expires zero", 0},
		{"expires negative", -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := adminAuthorizationVector()
			a.ExpiresUnixMS = tt.value
			for _, f := range []func() error{
				func() error { _, err := EncodeAdminRemoteUnlockAuthorization(a); return err },
				func() error { _, err := AdminAuthorizationSigningBytes(a); return err },
				func() error { _, err := a.MarshalJSON(); return err },
			} {
				err := f()
				if !errors.Is(err, ErrInvalidAdminAuthorization) {
					t.Fatalf("error does not wrap ErrInvalidAdminAuthorization: %v", err)
				}
				requireAdminAuthorizationField(t, err, "expires_unix_ms")
			}
		})
	}
	var nilAuth *requestAuth
	if err := nilAuth.UnmarshalJSON([]byte(adminAuthorizationVectorJSON)); !errors.Is(err, ErrInvalidAdminAuthorizationEncoding) {
		t.Fatalf("nil UnmarshalJSON error does not wrap ErrInvalidAdminAuthorizationEncoding: %v", err)
	}
}

// TestAdminAuthorizationParseRejectsNonCanonicalInput covers missing, unknown,
// duplicate and reordered members, structural damage, bad constants, types,
// integers, digests and signature, escapes, trailing data and the size cap.
func TestAdminAuthorizationParseRejectsNonCanonicalInput(t *testing.T) {
	canonical := []byte(adminAuthorizationVectorJSON)
	sig := `"signature":"` + adminAuthorizationVectorSignature + `"`
	ctx := `"context_sha256":"` + authContextDigestVector + `"`
	dd := `"delegation_digest":"` + adminAuthorizationVectorDelegationDigest + `"`
	exp := `"expires_unix_ms":1799999999000`

	type tc struct {
		name   string
		mutate func(t *testing.T, b []byte) []byte
		field  string
	}
	var tests []tc
	for i, name := range adminAuthorizationMembers {
		next := ""
		if i+1 < len(adminAuthorizationMembers) {
			next = adminAuthorizationMembers[i+1]
		}
		if i == 0 {
			next = name
		}
		tests = append(tests, tc{name: "missing " + name, mutate: func(t *testing.T, b []byte) []byte {
			return removeMember(t, b, name)
		}, field: next})
	}
	tests = append(tests,
		tc{name: "empty object", mutate: func(t *testing.T, b []byte) []byte { return []byte(`{}`) }, field: ""},
		tc{name: "unknown member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `}`, `,"admin":true}`)
		}, field: ""},
		tc{name: "owner-root member smuggled in", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"context_sha256"`, `"owner_root_key_id":"owner-root-0001","context_sha256"`)
		}, field: ""},
		tc{name: "duplicate signature", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, sig, sig+`,`+sig)
		}, field: ""},
		tc{name: "duplicate delegation digest", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, dd+`,`, dd+`,`+dd+`,`)
		}, field: "delegation_digest"},
		tc{name: "members reordered", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, dd+`,`+ctx, ctx+`,`+dd)
		}, field: "delegation_digest"},
		tc{name: "digests swapped", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"source_binding_sha256":"`+authSourceDigestVector+`","target_binding_sha256":"`+authTargetDigestVector+`"`,
				`"target_binding_sha256":"`+authTargetDigestVector+`","source_binding_sha256":"`+authSourceDigestVector+`"`)
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
			return replaceOnce(t, b, `"admin-authorization"`, "\"admin-\xffauthorization\"")
		}, field: ""},
		tc{name: "escaped member name", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"format"`, `"\u0066ormat"`)
		}, field: "format"},
		tc{name: "escaped kind", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"admin-authorization"`, `"admin\u002dauthorization"`)
		}, field: "kind"},
		tc{name: "wrong format", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"locklark.remote-unlock"`, `"locklark.remote-unlock.v2"`)
		}, field: "format"},
		tc{name: "owner-root authorization kind", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"admin-authorization"`, `"owner-authorization"`)
		}, field: "kind"},
		tc{name: "delegation kind", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"admin-authorization"`, `"owner-admin-delegation"`)
		}, field: "kind"},
		tc{name: "wrong version", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":2`)
		}, field: "version"},
		tc{name: "version as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":"1"`)
		}, field: "version"},
		tc{name: "version leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":01`)
		}, field: "version"},
		tc{name: "context digest short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, ctx, `"context_sha256":"`+authContextDigestVector[:42]+`"`)
		}, field: "context_sha256"},
		tc{name: "context digest padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, ctx, `"context_sha256":"`+authContextDigestVector+`="`)
		}, field: "context_sha256"},
		tc{name: "context digest standard alphabet", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, ctx, `"context_sha256":"`+strings.ReplaceAll(authContextDigestVector, "_", "/")+`"`)
		}, field: "context_sha256"},
		tc{name: "context digest noncanonical trailing bits", mutate: func(t *testing.T, b []byte) []byte {
			last := authContextDigestVector[len(authContextDigestVector)-1]
			alt := map[byte]byte{'U': 'V', 'V': 'U'}[last]
			return replaceOnce(t, b, ctx, `"context_sha256":"`+authContextDigestVector[:len(authContextDigestVector)-1]+string(alt)+`"`)
		}, field: "context_sha256"},
		tc{name: "delegation digest empty", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, dd, `"delegation_digest":""`)
		}, field: "delegation_digest"},
		tc{name: "delegation digest as null", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, dd, `"delegation_digest":null`)
		}, field: "delegation_digest"},
		tc{name: "source digest long", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"`+authSourceDigestVector+`"`, `"`+authSourceDigestVector+`A"`)
		}, field: "source_binding_sha256"},
		tc{name: "target digest empty", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"`+authTargetDigestVector+`"`, `""`)
		}, field: "target_binding_sha256"},
		tc{name: "expires zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":0`)
		}, field: "expires_unix_ms"},
		tc{name: "expires negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":-1799999999000`)
		}, field: "expires_unix_ms"},
		tc{name: "expires plus sign", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":+1799999999000`)
		}, field: "expires_unix_ms"},
		tc{name: "expires leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":01799999999000`)
		}, field: "expires_unix_ms"},
		tc{name: "expires fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":1799999999000.0`)
		}, field: "expires_unix_ms"},
		tc{name: "expires exponent", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":1799999999e3`)
		}, field: "expires_unix_ms"},
		tc{name: "expires int64 overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":9223372036854775808`)
		}, field: "expires_unix_ms"},
		tc{name: "expires as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, exp, `"expires_unix_ms":"1799999999000"`)
		}, field: "expires_unix_ms"},
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
			return append(b, bytes.Repeat([]byte(" "), MaxAdminAuthorizationSize+1)...)
		}, field: ""},
		tc{name: "exactly the budget with trailing data", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxAdminAuthorizationSize-len(b))...)
		}, field: ""},
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.mutate(t, append([]byte(nil), canonical...))
			_, err := ParseAdminRemoteUnlockAuthorization(data)
			if err == nil {
				t.Fatal("Parse accepted non-canonical input")
			}
			if !errors.Is(err, ErrInvalidAdminAuthorizationEncoding) {
				t.Fatalf("error does not wrap ErrInvalidAdminAuthorizationEncoding: %v", err)
			}
			if tt.field != "" {
				requireAdminAuthorizationField(t, err, tt.field)
			}
		})
	}
	for _, size := range []int{MaxAdminAuthorizationSize + 1, MaxAdminAuthorizationSize * 4} {
		if _, err := ParseAdminRemoteUnlockAuthorization(bytes.Repeat([]byte(" "), size)); !errors.Is(err, ErrInvalidAdminAuthorizationEncoding) {
			t.Fatalf("%d bytes: error does not wrap ErrInvalidAdminAuthorizationEncoding: %v", size, err)
		}
	}
}

func TestAdminAuthorizationErrorsNeverContainValues(t *testing.T) {
	a := adminAuthorizationVector()
	a.ExpiresUnixMS = -1
	if _, err := EncodeAdminRemoteUnlockAuthorization(a); err == nil || strings.Contains(err.Error(), "-1") {
		t.Fatalf("encode error leaked or missed the value: %v", err)
	}
	const secret = "uppersecretmember"
	data := replaceOnce(t, []byte(adminAuthorizationVectorJSON), `}`, `,"`+secret+`":1}`)
	if _, err := ParseAdminRemoteUnlockAuthorization(data); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("parse error leaked an unknown key: %v", err)
	}
	bad := "+" + adminAuthorizationVectorSignature[1:]
	data = replaceOnce(t, []byte(adminAuthorizationVectorJSON), `"signature":"`+adminAuthorizationVectorSignature+`"`, `"signature":"`+bad+`"`)
	if _, err := ParseAdminRemoteUnlockAuthorization(data); err == nil || strings.Contains(err.Error(), bad[1:20]) {
		t.Fatalf("parse error leaked signature bytes: %v", err)
	}
	// A verification failure names the member, never the digest or signature.
	a = adminAuthorizationVector()
	a.ContextSHA256[0] ^= 0x01
	err := VerifyAdminRemoteUnlockAuthorization(nil, nil, adminDelegationVector(), a, vectorContext(), authSourceVector(t), authTargetVector(t), 1)
	if err == nil || strings.Contains(err.Error(), adminAuthorizationVectorDelegationDigest) ||
		strings.Contains(err.Error(), adminAuthorizationVectorSignature[:20]) {
		t.Fatalf("verification error leaked a value: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Per-request fixture and the real positive path.
// ---------------------------------------------------------------------------

// adminAuthorizationContext is a fresh request context in the grant's scope: a
// new request identifier and digest, a deadline one minute after
// delegationNowMS, and the fixture's pair, vault, epoch and policy anchor.
func adminAuthorizationContext(fx *authFixture, requestID string) ChannelBindingContext {
	c := vectorContext()
	c.RequestID = requestID
	c.RequestDigest = digestOf([]byte("synthetic-request/" + requestID))
	c.VaultID = authVaultID
	c.MemberID = authMemberID
	c.SourceDeviceID = authSourceDeviceID
	c.TargetDeviceID = authTargetDeviceID
	c.KeyEpoch = fx.file.Header.KeyEpoch
	c.PolicySeq = fx.file.Header.PolicySeq
	c.PolicyDigest = [DigestSize]byte(vaultfile.PolicyDigest(fx.currentDelegationPolicy()))
	c.DeadlineUnixMS = delegationNowMS + 60_000
	return c
}

// adminAuthorizationFor builds a fresh per-request authorization over c and
// the two bindings, signed by priv with an expiry 30 seconds after the
// synthetic clock.
func adminAuthorizationFor(t *testing.T, grant reusableGrant, c ChannelBindingContext, src, tgt DeviceTransportBinding, priv ed25519.PrivateKey) requestAuth {
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
	delegationDigest, err := AdminDelegationDigest(grant)
	if err != nil {
		t.Fatalf("AdminDelegationDigest: %v", err)
	}
	return signAdminAuthorization(t, requestAuth{
		DelegationDigest:    delegationDigest,
		ContextSHA256:       ctxDigest,
		SourceBindingSHA256: srcDigest,
		TargetBindingSHA256: tgtDigest,
		ExpiresUnixMS:       delegationNowMS + 30_000,
	}, priv)
}

// adminAuthorizationInputs is one complete set of verifier inputs.
type adminAuthorizationInputs struct {
	file   *vaultfile.File
	cp     *vaultfile.PolicyCheckpoint
	grant  reusableGrant
	auth   requestAuth
	ctx    ChannelBindingContext
	src    DeviceTransportBinding
	tgt    DeviceTransportBinding
	now    int64
	signer ed25519.PrivateKey
	// authExpires is the request authorization expiry used by authorize.
	authExpires int64
	// fx is the fixture the inputs were built from, for cases that need to
	// derive a companion grant.
	fx *authFixture
}

func (fx *authFixture) verifyAdminAuthorization(in *adminAuthorizationInputs) error {
	return VerifyAdminRemoteUnlockAuthorization(in.file, in.cp, in.grant, in.auth, in.ctx, in.src, in.tgt, in.now)
}

// newAdminAuthorizationInputs builds the default valid inputs. The reusable
// grant is widened to [now - 100 s, now + 60 s) and the request deadline to
// two minutes after the synthetic clock, so the default authorization expiry
// (thirty seconds after it) is inside both. The boundary checks build their
// cases from scratch and pin each bound exactly.
func newAdminAuthorizationInputs(t *testing.T, fx *authFixture) *adminAuthorizationInputs {
	t.Helper()
	ctx := adminAuthorizationContext(fx, "req-0001")
	ctx.DeadlineUnixMS = delegationNowMS + 120_000
	grant := windowedGrantAt(t, fx, delegationNowMS-100_000, delegationNowMS+60_000)
	in := &adminAuthorizationInputs{
		file:        fx.file,
		cp:          fx.cloneCheckpoint(),
		grant:       grant,
		ctx:         ctx,
		src:         authSourceVector(t),
		tgt:         authTargetVector(t),
		now:         delegationNowMS,
		signer:      delegationAdminKey,
		authExpires: delegationNowMS + 30_000,
		fx:          fx,
	}
	in.auth = authorize(t, in)
	return in
}

// windowedGrantAt returns fx's owner-root-signed grant re-signed with the
// declared validity window. The authorization must be reproduced afterwards
// (authorize) because its expiry is bounded by the grant's.
func windowedGrantAt(t *testing.T, fx *authFixture, notBefore, expires int64) reusableGrant {
	t.Helper()
	g := fx.delegationFor(t)
	g.NotBeforeUnixMS, g.ExpiresUnixMS = notBefore, expires
	return signDelegation(t, g, seedKey(authRootSeedSpan))
}

// TestVerifyAdminAuthorizationSyntheticFullPath is the real positive path: one
// owner-root-signed reusable grant, and the delegated admin device signs two
// different fresh request contexts within its scope without any new root
// contact. It also pins the per-request expiry boundaries.
func TestVerifyAdminAuthorizationSyntheticFullPath(t *testing.T) {
	fx := newDelegationFixture(t, nil)
	in := newAdminAuthorizationInputs(t, fx)

	// The owner root signed the grant once; it signs no request.
	grantBytes := mustEncodeDelegation(t, in.grant)
	if err := fx.verifyDelegation(in.grant, delegationNowMS); err != nil {
		t.Fatalf("reusable grant rejected: %v", err)
	}
	if !ed25519.Verify(seedPublic(authRootSeedSpan), mustDelegationPreimage(t, in.grant), in.grant.Signature[:]) {
		t.Fatal("grant is not owner-root signed")
	}
	if ed25519.Verify(seedPublic(authRootSeedSpan), mustAdminAuthorizationPreimage(t, in.auth), in.auth.Signature[:]) {
		t.Fatal("per-request authorization verifies under the owner root key")
	}

	a2 := newAdminAuthorizationInputs(t, fx)
	a2.ctx = adminAuthorizationContext(fx, "req-0002")
	a2.ctx.RequestDigest = descendingDigest()
	a2.ctx.LockGeneration = 9
	a2.ctx.DeadlineUnixMS = delegationNowMS + 120_000
	a2.auth = adminAuthorizationFor(t, a2.grant, a2.ctx, a2.src, a2.tgt, a2.signer)

	if in.ctx.RequestID == a2.ctx.RequestID || in.auth.ContextSHA256 == a2.auth.ContextSHA256 || in.auth.Signature == a2.auth.Signature {
		t.Fatal("the two requests are not distinct")
	}
	if !bytes.Equal(grantBytes, mustEncodeDelegation(t, a2.grant)) || in.auth.DelegationDigest != a2.auth.DelegationDigest {
		t.Fatal("the reused grant was not byte-identical")
	}
	policyBefore := vaultfile.PolicyDigest(fx.currentDelegationPolicy())
	for i, cur := range []*adminAuthorizationInputs{in, a2} {
		if _, err := ParseAdminRemoteUnlockAuthorization(mustEncodeAdminAuthorization(t, cur.auth)); err != nil {
			t.Fatalf("request %d authorization is not canonical: %v", i+1, err)
		}
		if err := fx.verifyAdminAuthorization(cur); err != nil {
			t.Fatalf("request %d rejected: %v", i+1, err)
		}
		// Expiry is exclusive: it verifies one millisecond before and fails
		// at exactly the expiry instant.
		cur.now = cur.auth.ExpiresUnixMS - 1
		if err := fx.verifyAdminAuthorization(cur); err != nil {
			t.Fatalf("request %d rejected one millisecond before its expiry: %v", i+1, err)
		}
		cur.now = cur.auth.ExpiresUnixMS
		if err := fx.verifyAdminAuthorization(cur); !errors.Is(err, ErrInvalidAdminAuthorization) {
			t.Fatalf("request %d accepted at the exact expiry: %v", i+1, err)
		}
		cur.now = delegationNowMS
	}
	// The grant stays byte-identical and free of per-request members.
	if !bytes.Equal(grantBytes, mustEncodeDelegation(t, in.grant)) {
		t.Fatal("verification changed the reusable grant")
	}
	if !bytes.Equal(vaultfile.PolicyDigest(fx.currentDelegationPolicy()), policyBefore) {
		t.Fatal("verification mutated the authenticated policy")
	}
	if in.grant.DelegatePolicySigningKey != adminDelegationVector().DelegatePolicySigningKey {
		t.Fatal("the grant signer key was not the granted admin key")
	}
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.cloneCheckpoint()); err != nil {
		t.Fatalf("verification changed the fixture: %v", err)
	}
}

// TestVerifyAdminAuthorizationBoundaries pins every time boundary to the
// exact millisecond: request expiry against the clock and the request
// deadline, and the request against the grant interval.
func TestVerifyAdminAuthorizationBoundaries(t *testing.T) {
	fx := newDelegationFixture(t, nil)

	// resignWith sets the request expiry and re-signs with the delegate key.
	resignWith := func(in *adminAuthorizationInputs, expires int64) {
		in.auth.ExpiresUnixMS = expires
		in.auth = signAdminAuthorization(t, in.auth, in.signer)
	}

	t.Run("expires exactly at now and one millisecond before", func(t *testing.T) {
		for _, at := range []int64{delegationNowMS, delegationNowMS - 1} {
			in := newAdminAuthorizationInputs(t, fx)
			resignWith(in, at)
			requireAdminAuthorizationField(t, fx.verifyAdminAuthorization(in), "expires_unix_ms")
		}
	})
	t.Run("one millisecond after now", func(t *testing.T) {
		in := newAdminAuthorizationInputs(t, fx)
		resignWith(in, delegationNowMS+1)
		if err := fx.verifyAdminAuthorization(in); err != nil {
			t.Fatalf("rejected one millisecond after now: %v", err)
		}
	})
	t.Run("expires exactly at the request deadline", func(t *testing.T) {
		in := newAdminAuthorizationInputs(t, fx)
		// Keep the deadline bound the tighter one inside the grant window.
		in.ctx.DeadlineUnixMS = delegationNowMS + 45_000
		in.auth = authorize(t, in)
		resignWith(in, in.ctx.DeadlineUnixMS)
		if err := fx.verifyAdminAuthorization(in); err != nil {
			t.Fatalf("rejected at the request deadline: %v", err)
		}
	})
	t.Run("expires one millisecond after the request deadline", func(t *testing.T) {
		in := newAdminAuthorizationInputs(t, fx)
		resignWith(in, in.ctx.DeadlineUnixMS+1)
		requireAdminAuthorizationField(t, fx.verifyAdminAuthorization(in), "expires_unix_ms")
	})

	// The grant ends at 60 s; the request deadline is widened to keep only the
	// grant-expiry bound in play.
	grantEndInputs := func(t *testing.T) *adminAuthorizationInputs {
		in := newAdminAuthorizationInputs(t, fx)
		in.ctx.DeadlineUnixMS = in.grant.ExpiresUnixMS + 60_000
		in.auth = adminAuthorizationFor(t, in.grant, in.ctx, in.src, in.tgt, in.signer)
		return in
	}
	t.Run("expires exactly at the grant expiry", func(t *testing.T) {
		in := grantEndInputs(t)
		resignWith(in, in.grant.ExpiresUnixMS)
		if err := fx.verifyAdminAuthorization(in); err != nil {
			t.Fatalf("rejected at the grant expiry instant: %v", err)
		}
	})
	t.Run("expires one millisecond after the grant expiry", func(t *testing.T) {
		in := grantEndInputs(t)
		resignWith(in, in.grant.ExpiresUnixMS+1)
		requireAdminAuthorizationField(t, fx.verifyAdminAuthorization(in), "expires_unix_ms")
	})
	t.Run("now exactly at the grant expiry", func(t *testing.T) {
		// The grant window is widened for this case so that only the clock
		// touches its end, not the request's own expiry.
		in := newAdminAuthorizationInputs(t, fx)
		in.grant = windowedGrantAt(t, fx, delegationNowMS-100_000, delegationNowMS)
		in.ctx.DeadlineUnixMS = delegationNowMS + 180_000
		in.auth = authorize(t, in)
		in.now = in.grant.ExpiresUnixMS
		err := fx.verifyAdminAuthorization(in)
		if !errors.Is(err, ErrInvalidAdminAuthorization) || !errors.Is(err, ErrInvalidAdminDelegation) {
			t.Fatalf("expected a wrapped grant expiry at the exact boundary, got %v", err)
		}
	})
	t.Run("now exactly at the grant not-before", func(t *testing.T) {
		in := grantEndInputs(t)
		in.now = in.grant.NotBeforeUnixMS
		resignWith(in, in.now+1)
		if err := fx.verifyAdminAuthorization(in); err != nil {
			t.Fatalf("rejected at the grant not-before instant: %v", err)
		}
	})
	t.Run("now one millisecond before the grant not-before", func(t *testing.T) {
		in := grantEndInputs(t)
		in.now = in.grant.NotBeforeUnixMS - 1
		err := fx.verifyAdminAuthorization(in)
		if !errors.Is(err, ErrInvalidAdminAuthorization) || !errors.Is(err, ErrInvalidAdminDelegation) {
			t.Fatalf("expected a wrapped not-yet-valid grant, got %v", err)
		}
	})
	t.Run("caller clock zero", func(t *testing.T) {
		in := newAdminAuthorizationInputs(t, fx)
		in.now = 0
		if err := fx.verifyAdminAuthorization(in); !errors.Is(err, ErrInvalidAdminAuthorization) {
			t.Fatalf("expected a clock rejection, got %v", err)
		}
	})
}

// altGrant signs a well-formed grant for ctx's fixture policy with ownerSeed,
// distinct from the fixture's grant. ctx must be the fixture whose file and
// checkpoint are used.
func altGrant(ctx *authFixture, mutate func(*reusableGrant), ownerSeed byte) reusableGrant {
	anchor := ctx.currentDelegationPolicy()
	var key [AdminDelegationPublicKeySize]byte
	copy(key[:], seedPublic(delegationDelegateSeed))
	d := reusableGrant{
		OwnerRootKeyID:           authOwnerRootKeyID,
		DelegateMemberID:         delegationDelegateMember,
		DelegateDeviceID:         delegationDelegateDevice,
		DelegatePolicySigningKey: key,
		VaultID:                  authVaultID,
		RequesterMemberID:        authMemberID,
		SourceDeviceID:           authSourceDeviceID,
		TargetDeviceID:           authTargetDeviceID,
		SourceBindingSHA256:      mustDigest(authSourceDigestVector),
		TargetBindingSHA256:      mustDigest(authTargetDigestVector),
		KeyEpoch:                 ctx.file.Header.KeyEpoch,
		PolicySeq:                anchor.PolicySeq,
		PolicyDigest:             [DigestSize]byte(vaultfile.PolicyDigest(anchor)),
		NotBeforeUnixMS:          delegationNowMS - 100_000,
		ExpiresUnixMS:            delegationNowMS + 60_000,
	}
	if mutate != nil {
		mutate(&d)
	}
	d.Signature = [AdminDelegationSignatureSize]byte{}
	pre, err := AdminDelegationSigningBytes(d)
	if err != nil {
		panic(err)
	}
	copy(d.Signature[:], ed25519.Sign(seedKey(ownerSeed), pre))
	return d
}

// appendRootPolicy adds one more root-signed current policy proof (a
// requester-label edit, valid for a root signer) and re-seals the file.
func appendRootPolicy(t *testing.T, fx *authFixture) *authFixture {
	t.Helper()
	out := *fx.file
	out.SignedPolicyProofs = append([]vaultfile.SignedPolicy(nil), fx.file.SignedPolicyProofs...)
	prev := &out.SignedPolicyProofs[len(out.SignedPolicyProofs)-1]
	next := prev.Policy
	next.PolicySeq = prev.Policy.PolicySeq + 1
	next.PrevPolicyDigest = bytes.Clone(vaultfile.PolicyDigest(&prev.Policy))
	// A deep copy: the label edit must never reach the previous proof, whose
	// document is carried separately. Readers are compared by principal ID and
	// label, so the edit is a valid root-signed change.
	next.Readers = append([]vaultfile.Member(nil), next.Readers...)
	for i := range next.Readers {
		if next.Readers[i].PrincipalID == authMemberID {
			next.Readers[i].Label = "Alice (renamed)"
		}
	}
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

// rebind signs b again with priv, keeping every other claim.
func rebind(t *testing.T, b DeviceTransportBinding, priv ed25519.PrivateKey) DeviceTransportBinding {
	t.Helper()
	b.Signature = [BindingSignatureSize]byte{}
	copy(b.Signature[:], ed25519.Sign(priv, mustSigningBytes(t, b)))
	return b
}

// TestVerifyAdminAuthorizationRejectsMutations mutates every input the
// verifier depends on and requires it to fail closed. A case either (a) leaves
// the authorization as is, so its delegated signature covers the mutation and
// fails against it, or (b) sets `fresh` to reproduce the authorization from the
// mutated inputs with the legitimate delegated key, so the failure comes from
// the intended check and not merely from a stale digest or signature.
func TestVerifyAdminAuthorizationRejectsMutations(t *testing.T) {
	variant := func(mutate func(*vaultfile.Policy)) func(t *testing.T) *authFixture {
		return func(t *testing.T) *authFixture { return newDelegationFixture(t, mutate) }
	}
	tests := []struct {
		name  string
		fx    func(t *testing.T) *authFixture
		apply func(t *testing.T, in *adminAuthorizationInputs)
		// fresh reproduces the authorization from the mutated inputs and
		// in.signer after apply.
		fresh bool
		// grantForAnchor, when non-zero, re-anchors the grant to the carried
		// policy proof at this slice offset (a negative offset counts from the
		// end) and re-signs it with the declared owner root. Zero leaves the
		// default grant anchored to the current policy.
		grantForAnchor int
		field          string
		wrap           []error
	}{
		// Reusable grant, delegation digest and root contact.
		{name: "grant re-signed by a foreign root", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.grant = signDelegation(t, in.grant, seedKey(authForeignSeedSpan))
			in.auth.DelegationDigest, _ = AdminDelegationDigest(in.grant)
		}), fresh: true, wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "grant delegate re-signed by the current root", apply: unaryIn(func(in *adminAuthorizationInputs) {
			// A well-formed grant naming a different, unknown delegate: only
			// the grant verifier can reject it.
			in.grant = altGrant(in.fx, func(g *reusableGrant) { g.DelegateMemberID = "dave" }, authRootSeedSpan)
		}), fresh: true, wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "delegation digest replaced", apply: unaryIn(func(in *adminAuthorizationInputs) {
			other := altGrant(in.fx, func(g *reusableGrant) { g.ExpiresUnixMS++ }, authRootSeedSpan)
			in.auth.DelegationDigest, _ = AdminDelegationDigest(other)
		}), field: "delegation_digest", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "delegation digest is the context digest", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.auth.DelegationDigest = in.ctx.PolicyDigest
		}), field: "delegation_digest", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "no owner-root signature on the grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.grant.Signature = [AdminDelegationSignatureSize]byte{}
		}), fresh: true, wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "authorization signed only with the owner root key", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.signer = seedKey(authRootSeedSpan)
		}), fresh: true, field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},

		// Context scope and freshness.
		{name: "request id changed after signing", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.RequestID = "req-0002"
		}), field: "context_sha256", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "request digest changed after signing", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.RequestDigest = descendingDigest()
		}), field: "context_sha256", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "lock generation changed after signing", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.LockGeneration = 3
		}), field: "context_sha256", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed vault out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.VaultID = "vault-0002"
		}), fresh: true, field: "context.vault_id", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed requester out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.MemberID = "writer-0001"
		}), fresh: true, field: "context.member_id", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed source device out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.SourceDeviceID = "device-other"
		}), fresh: true, field: "context.source_device_id", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed target device out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.TargetDeviceID = "device-other"
		}), fresh: true, field: "context.target_device_id", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed source and target swapped", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.SourceDeviceID, in.ctx.TargetDeviceID = in.ctx.TargetDeviceID, in.ctx.SourceDeviceID
		}), fresh: true, field: "context.source_device_id", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed pair generation out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.PairGeneration = 1
		}), fresh: true, field: "context.pair_generation", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed key epoch out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.KeyEpoch++
		}), fresh: true, field: "context.key_epoch", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed policy seq out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.PolicySeq++
		}), fresh: true, field: "context.policy_seq", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signed policy digest out of grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.PolicyDigest[0] ^= 0x01
		}), fresh: true, field: "context.policy_digest", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "request deadline moved before the authorization", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.DeadlineUnixMS = in.now + 1
		}), fresh: true, field: "expires_unix_ms", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "non-canonical context key epoch", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.KeyEpoch = 0
		}), wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "context endpoints equal", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.ctx.TargetDeviceID = in.ctx.SourceDeviceID
		}), fresh: true, wrap: []error{ErrInvalidAdminAuthorization}},

		// Bindings: recipients, signatures, digests.
		{name: "source and target bindings swapped", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.src, in.tgt = in.tgt, in.src
		}), fresh: true, field: "source_binding.recipient_public_key", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "source binding recipient changed", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.src.RecipientPublicKey = authOtherRecipient
		}), fresh: true, field: "source_binding.recipient_public_key", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "source binding signature mutated", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.src.Signature[0] ^= 0x01
		}), fresh: true, field: "source_binding", wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidBinding}},
		{name: "target binding signed by the source key", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.tgt = rebind(t, in.tgt, authSourceKey)
		}), fresh: true, field: "target_binding", wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidBinding}},
		{name: "binding spki changed and re-signed", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.src.SPKISHA256[0] ^= 0xff
			in.src = rebind(t, in.src, authSourceKey)
		}), fresh: true, field: "source_binding_sha256", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "source binding digest swapped for target", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.auth.SourceBindingSHA256 = in.auth.TargetBindingSHA256
		}), field: "source_binding_sha256", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "source binding not canonical", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.src.InstallID = ""
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidBinding}},
		{name: "target binding pair generation differs", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.tgt.PairGeneration = 1
		}), fresh: true, wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidBinding}},

		// Delegated-device signature.
		{name: "signature mutated", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.auth.Signature[0] ^= 0x01
		}), field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signature zeroed", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.auth.Signature = [AdminAuthorizationSignatureSize]byte{}
		}), field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signature by the delegate content key", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.signer = authOutsider
		}), fresh: true, field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signature by the requester source key", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.signer = authSourceKey
		}), fresh: true, field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signature by a foreign key", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.signer = seedKey(authForeignSeedSpan)
		}), fresh: true, field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signature by the delegate policy key of another grant", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.signer = seedKey(0x30)
		}), fresh: true, field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "signature over a reordered preimage", apply: unaryIn(func(in *adminAuthorizationInputs) {
			signed := signAdminAuthorization(t, in.auth, in.signer)
			in.auth.Signature = signed.Signature
			raw := mustAdminAuthorizationPreimage(t, in.auth)
			msg := bytes.Replace(raw, []byte(AdminAuthorizationSignatureDomain), []byte(OwnerRootAuthorizationSignatureDomain), 1)
			in.auth.Signature = [AdminAuthorizationSignatureSize]byte{}
			copy(in.auth.Signature[:], ed25519.Sign(in.signer, msg))
		}), field: "signature", wrap: []error{ErrInvalidAdminAuthorization}},

		// Current policy: delegate demoted, removed, re-keyed, or revoked by an
		// update; endpoint keys changed.
		{name: "delegate demoted to writer", fx: variant(func(p *vaultfile.Policy) {
			p.Admins = []vaultfile.Member{}
			p.Writers = sortedDelegationMembers(p.Writers, vaultfile.Member{PrincipalID: delegationDelegateMember, Label: "Carol"})
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "delegate removed from the policy", fx: variant(func(p *vaultfile.Policy) {
			p.Admins = []vaultfile.Member{}
			p.Devices = dropDelegationDevices(p, delegationDelegateDevice)
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "delegate device re-owned", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, delegationDelegateDevice).PrincipalID = "bob"
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "delegate policy key rotated", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, delegationDelegateDevice).PolicySigningKey.PublicKey = bytes.Clone(seedPublic(0x30))
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "delegate policy key removed", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, delegationDelegateDevice).PolicySigningKey = nil
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "grant revoked by a policy update", fx: func(t *testing.T) *authFixture {
			// The grant still anchors the previous policy, which is now an old
			// proof: it can never authorize a request again, even though its
			// interval would otherwise cover the request.
			return appendRootPolicy(t, newDelegationFixture(t, nil))
		}, grantForAnchor: -2, apply: unaryIn(func(in *adminAuthorizationInputs) {
			// The same delegated key signs a valid request; only the policy
			// anchor invalidates it.
			in.auth = authorize(t, in)
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},

		// Endpoint devices: with the old grant a policy change already breaks
		// the anchor; with a fresh grant for the new policy only the binding,
		// recipient or signature checks can reject the request.
		{name: "source content key rotated under a fresh grant", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, authSourceDeviceID).ContentSigningKey.PublicKey = bytes.Clone(seedPublic(0x31))
		}), apply: regrant, fresh: true, field: "source_binding", wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidBinding}},
		{name: "source age key rotated under a fresh grant", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, authSourceDeviceID).AgeEncryptionKey = authOtherRecipient
		}), apply: regrant, fresh: true, field: "source_binding.recipient_public_key", wrap: []error{ErrInvalidAdminAuthorization}},
		{name: "source device re-owned under a fresh grant", fx: variant(func(p *vaultfile.Policy) {
			authDeviceByID(t, p, authSourceDeviceID).PrincipalID = "bob"
		}), apply: regrant, wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "delegate demoted to writer under a fresh grant", fx: variant(func(p *vaultfile.Policy) {
			p.Admins = []vaultfile.Member{}
			p.Writers = sortedDelegationMembers(p.Writers, vaultfile.Member{PrincipalID: delegationDelegateMember, Label: "Carol"})
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},

		// Authenticated current policy and checkpoint.
		{name: "checkpoint pins a foreign root", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.cp.OwnerRootPublicKey = bytes.Clone(seedPublic(authForeignSeedSpan))
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "checkpoint digest points elsewhere", apply: unaryIn(func(in *adminAuthorizationInputs) {
			in.cp.PolicyDigest[0] ^= 0x01
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "content signature broken", apply: unaryIn(func(in *adminAuthorizationInputs) {
			c := *in.file
			c.ContentSignature.Sig = bytes.Clone(c.ContentSignature.Sig)
			c.ContentSignature.Sig[0] ^= 0x01
			in.file = &c
		}), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "nil checkpoint", apply: unaryIn(func(in *adminAuthorizationInputs) { in.cp = nil }), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
		{name: "nil file", apply: unaryIn(func(in *adminAuthorizationInputs) { in.file = nil }), wrap: []error{ErrInvalidAdminAuthorization, ErrInvalidAdminDelegation}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newDelegationFixture(t, nil)
			if tt.fx != nil {
				fx = tt.fx(t)
			}
			in := newAdminAuthorizationInputs(t, fx)
			if tt.grantForAnchor != 0 {
				idx := len(fx.file.SignedPolicyProofs) - 1
				if tt.grantForAnchor > 0 {
					idx = tt.grantForAnchor
				} else {
					idx += tt.grantForAnchor + 1
				}
				anchor := &fx.file.SignedPolicyProofs[idx].Policy
				in.grant.PolicySeq = anchor.PolicySeq
				in.grant.PolicyDigest = [DigestSize]byte(vaultfile.PolicyDigest(anchor))
				in.grant = signDelegation(t, in.grant, seedKey(authRootSeedSpan))
			}
			if tt.apply != nil {
				tt.apply(t, in)
			}
			if tt.fresh {
				in.auth = authorize(t, in)
			}
			if t.Failed() {
				return
			}
			err := fx.verifyAdminAuthorization(in)
			if err == nil {
				t.Fatal("verifier accepted a mutated input")
			}
			for _, want := range tt.wrap {
				if !errors.Is(err, want) {
					t.Fatalf("error does not wrap %v: %v", want, err)
				}
			}
			if tt.field != "" {
				requireAdminAuthorizationField(t, err, tt.field)
			}
			for _, v := range []string{
				base64.RawURLEncoding.EncodeToString(in.auth.DelegationDigest[:]),
				base64.RawURLEncoding.EncodeToString(in.auth.ContextSHA256[:]),
				base64.RawURLEncoding.EncodeToString(in.auth.Signature[:]),
				base64.RawURLEncoding.EncodeToString(in.grant.DelegatePolicySigningKey[:]),
			} {
				if strings.Contains(err.Error(), v) {
					t.Fatalf("error echoed an input value: %v", err)
				}
			}
		})
	}
}

// regrant replaces the grant with a fresh owner-root-signed one for the
// fixture's current policy, widened to the default window.
func regrant(t *testing.T, in *adminAuthorizationInputs) {
	t.Helper()
	in.grant = windowedGrantAt(t, in.fx, delegationNowMS-100_000, delegationNowMS+60_000)
}

// unaryIn adapts an input mutation to the table above.
func unaryIn(f func(in *adminAuthorizationInputs)) func(t *testing.T, in *adminAuthorizationInputs) {
	return func(t *testing.T, in *adminAuthorizationInputs) { f(in) }
}

// TestVerifyAdminAuthorizationDoesNotElevateRequester shows a non-admin
// requester is not elevated: the same requester that may request an unlock
// cannot sign the per-request authorization that authorizes it.
func TestVerifyAdminAuthorizationDoesNotElevateRequester(t *testing.T) {
	fx := newDelegationFixture(t, nil)
	cur := fx.currentDelegationPolicy()
	if policyAdminQualified(authMemberID, cur) {
		t.Fatal("fixture requester is already an admin or owner")
	}
	in := newAdminAuthorizationInputs(t, fx)
	if err := fx.verifyAdminAuthorization(in); err != nil {
		t.Fatalf("valid authorization rejected: %v", err)
	}
	// The requester's own devices sign the request bindings, never the
	// authorization: even a correct grant and context fail when signed by the
	// requester's source or target content key.
	for _, key := range []ed25519.PrivateKey{authSourceKey, authTargetKey, authAuthorKey, authReaderKey} {
		forged := newAdminAuthorizationInputs(t, fx)
		forged.auth = adminAuthorizationFor(t, forged.grant, forged.ctx, forged.src, forged.tgt, key)
		requireAdminAuthorizationField(t, fx.verifyAdminAuthorization(forged), "signature")
	}
	// The grant itself can never be re-scoped to make the requester the
	// delegate without the owner root re-signing it.
	moved := newAdminAuthorizationInputs(t, fx)
	moved.grant.DelegateMemberID = authMemberID
	moved.grant.DelegateDeviceID = authSourceDeviceID
	copy(moved.grant.DelegatePolicySigningKey[:], authSourceKey.Public().(ed25519.PublicKey))
	moved.auth.DelegationDigest, _ = AdminDelegationDigest(moved.grant)
	moved.auth = signAdminAuthorization(t, moved.auth, authSourceKey)
	if err := fx.verifyAdminAuthorization(moved); !errors.Is(err, ErrInvalidAdminDelegation) {
		t.Fatalf("an unsigned re-scoped grant was accepted: %v", err)
	}
	// No role or policy change happens.
	if !policyReadQualified(authMemberID, fx.currentDelegationPolicy()) || policyAdminQualified(authMemberID, fx.currentDelegationPolicy()) {
		t.Fatal("verification changed the requester's roles")
	}
	if got := len(fx.currentDelegationPolicy().Admins) + len(fx.currentDelegationPolicy().Owners); got != 2 {
		t.Fatalf("verification changed the policy roles: %d", got)
	}
}

// TestVerifyAdminAuthorizationDelegateRevocationIsAnchorBound pins what
// happens when the authenticated current policy no longer supports the grant:
// demoting, removing or re-keying the delegate, or any other policy update,
// changes the policy digest and invalidates the reusable grant's anchor before
// the per-request authorization is reached. No fresh grant for the new policy
// can be produced for a demoted or removed delegate, so the request fails
// closed with the wrapped grant error; the verifier's own current-policy role
// and exact-key re-check is defence in depth for the same rule. No role, key or
// policy byte is changed in any case.
func TestVerifyAdminAuthorizationDelegateRevocationIsAnchorBound(t *testing.T) {
	cases := map[string]struct {
		mutate func(*vaultfile.Policy)
		// revokesTheDelegate reports that the edit itself removes the
		// delegate's authority, so even a fresh grant for the new policy can
		// never verify.
		revokesTheDelegate bool
	}{
		"delegate demoted to writer": {revokesTheDelegate: true, mutate: func(p *vaultfile.Policy) {
			p.Admins = []vaultfile.Member{}
			p.Writers = sortedDelegationMembers(p.Writers, vaultfile.Member{PrincipalID: delegationDelegateMember, Label: "Carol"})
		}},
		"delegate device removed": {revokesTheDelegate: true, mutate: func(p *vaultfile.Policy) {
			p.Devices = dropDelegationDevices(p, delegationDelegateDevice)
		}},
		"delegate device re-owned": {revokesTheDelegate: true, mutate: func(p *vaultfile.Policy) {
			authDeviceByID(t, p, delegationDelegateDevice).PrincipalID = "bob"
		}},
		"delegate policy key rotated": {revokesTheDelegate: true, mutate: func(p *vaultfile.Policy) {
			authDeviceByID(t, p, delegationDelegateDevice).PolicySigningKey.PublicKey = bytes.Clone(seedPublic(0x30))
		}},
		"delegate policy key removed": {revokesTheDelegate: true, mutate: func(p *vaultfile.Policy) {
			authDeviceByID(t, p, delegationDelegateDevice).PolicySigningKey = nil
		}},
		"unrelated policy edit": {revokesTheDelegate: false, mutate: func(p *vaultfile.Policy) {
			p.Readers = sortedDelegationMembers(p.Readers, vaultfile.Member{PrincipalID: "zara", Label: "Zara"})
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newDelegationFixture(t, tc.mutate)
			before := vaultfile.PolicyDigest(fx.currentDelegationPolicy())
			// A grant built for the new policy verifies only when the edit
			// did not itself remove the delegate.
			fresh := fx.delegationFor(t)
			freshErr := fx.verifyDelegation(fresh, delegationNowMS)
			if tc.revokesTheDelegate && freshErr == nil {
				t.Fatal("a fresh grant verified against a policy that revoked the delegate")
			}
			if !tc.revokesTheDelegate && freshErr != nil {
				t.Fatalf("a fresh grant for the updated policy was rejected: %v", freshErr)
			}
			// The old grant no longer verifies and neither does any request
			// under it, even with the legitimate delegated key.
			in := newAdminAuthorizationInputs(t, fx)
			if !tc.revokesTheDelegate {
				// The request was built against the prior policy; the updated
				// file is what the verifier sees.
				prior := newAdminAuthorizationInputs(t, newDelegationFixture(t, nil))
				prior.file, prior.cp = fx.file, fx.cloneCheckpoint()
				in = prior
			}
			err := fx.verifyAdminAuthorization(in)
			if !errors.Is(err, ErrInvalidAdminAuthorization) || !errors.Is(err, ErrInvalidAdminDelegation) {
				t.Fatalf("expected a wrapped grant rejection, got %v", err)
			}
			if !bytes.Equal(vaultfile.PolicyDigest(fx.currentDelegationPolicy()), before) {
				t.Fatal("the verifier mutated the authenticated policy")
			}
			if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.cloneCheckpoint()); err != nil {
				t.Fatalf("the verifier changed the fixture: %v", err)
			}
		})
	}
}

// TestVerifyAdminAuthorizationNoDurableReplay pins the state-free boundary:
// the exact same valid authorization verifies repeatedly (no one-shot state),
// so the caller's lifecycle must prevent replay, and nothing here is TLS, a
// VUK delivery, a production identity or a durable one-shot proof.
func TestVerifyAdminAuthorizationNoDurableReplay(t *testing.T) {
	// The exact call shape is the boundary: there is no TLS connection, no
	// exporter value, no VUK, no key store, no durable nonce set and no system
	// clock parameter. Only the caller's time is accepted.
	var _ func(*vaultfile.File, *vaultfile.PolicyCheckpoint, reusableGrant, requestAuth, ChannelBindingContext, DeviceTransportBinding, DeviceTransportBinding, int64) error = VerifyAdminRemoteUnlockAuthorization

	fx := newDelegationFixture(t, nil)
	in := newAdminAuthorizationInputs(t, fx)
	encoded := mustEncodeAdminAuthorization(t, in.auth)
	reparsed, err := ParseAdminRemoteUnlockAuthorization(encoded)
	if err != nil {
		t.Fatalf("ParseAdminRemoteUnlockAuthorization: %v", err)
	}
	for i := 0; i < 3; i++ {
		again := *in
		again.auth = reparsed
		if err := newDelegationFixture(t, nil).verifyAdminAuthorization(&again); err != nil {
			t.Fatalf("replay %d rejected: %v", i+1, err)
		}
	}
	if _, err := ParseAdminRemoteUnlockAuthorization(encoded); err != nil {
		t.Fatalf("verification changed the authorization bytes: %v", err)
	}
	// None of these belong to this object: it is not TLS, a VUK delivery, a
	// production identity or a durable one-shot proof.
	for _, foreign := range []string{"request_id", "deadline_unix_ms", "spki_sha256", "exporter", "wrapped_vuk", "nonce", "tls"} {
		if bytes.Contains(encoded, []byte(`"`+foreign+`"`)) {
			t.Fatalf("authorization carries a foreign member %q", foreign)
		}
	}
	if len(adminAuthorizationMembers) != 9 {
		t.Fatalf("schema has %d members, want 8 signed plus the signature", len(adminAuthorizationMembers))
	}
}

// TestAdminAuthorizationFixtureDeviceOrder keeps the sorted fixture policy
// assumption explicit for the mutation helpers above.
func TestAdminAuthorizationFixtureDeviceOrder(t *testing.T) {
	p := delegateFixturePolicy(nil)
	if !sort.SliceIsSorted(p.Devices, func(i, j int) bool { return p.Devices[i].DeviceID < p.Devices[j].DeviceID }) {
		t.Fatal("fixture devices are not sorted")
	}
}
