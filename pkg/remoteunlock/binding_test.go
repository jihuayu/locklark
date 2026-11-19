package remoteunlock

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The fixed binding vector below is synthetic. Its Ed25519 key is derived from
// the deterministic seed 0x00..0x1f and its signature is real Ed25519 output
// over the documented preimage, but the key belongs to no device, member,
// vault, pairing, certificate or enrollment. It demonstrates the codec and the
// signature verification boundary only.
const bindingVectorJSON = `{"format":"locklark.remote-unlock","version":1,"kind":"device-transport-binding","member_id":"member-0001","device_id":"device-source","install_id":"install-0001","vault_id":"vault-0001","pair_generation":7,"spki_sha256":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","recipient_public_key":"age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea","signature":"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg"}`

// bindingVectorSignedJSON is bindingVectorJSON without the signature member.
const bindingVectorSignedJSON = `{"format":"locklark.remote-unlock","version":1,"kind":"device-transport-binding","member_id":"member-0001","device_id":"device-source","install_id":"install-0001","vault_id":"vault-0001","pair_generation":7,"spki_sha256":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","recipient_public_key":"age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea"}`

const (
	bindingVectorPublicKey = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
	// bindingOtherRecipient is another valid synthetic age X25519 recipient.
	bindingOtherRecipient = "age174eluezwt4dz6f3pj7mt520y6m9n85lgpnezw4j9e266m763vp6suajx3z"
)

func syntheticSigningSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func syntheticSigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(syntheticSigningSeed())
}

func syntheticSigningPublicKey() ed25519.PublicKey {
	return syntheticSigningKey().Public().(ed25519.PublicKey)
}

func bindingVector(t *testing.T) DeviceTransportBinding {
	t.Helper()
	signature, err := base64.RawURLEncoding.DecodeString(
		"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg")
	if err != nil {
		t.Fatalf("decode fixed signature: %v", err)
	}
	b := DeviceTransportBinding{
		MemberID:           "member-0001",
		DeviceID:           "device-source",
		InstallID:          "install-0001",
		VaultID:            "vault-0001",
		PairGeneration:     7,
		SPKISHA256:         ascendingDigest(),
		RecipientPublicKey: "age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea",
	}
	copy(b.Signature[:], signature)
	return b
}

// resignBinding signs the current fields with the synthetic test key. It is a
// test helper, not a production private-key path.
func resignBinding(t *testing.T, b DeviceTransportBinding) DeviceTransportBinding {
	t.Helper()
	msg, err := SigningBytes(b)
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	b.Signature = [BindingSignatureSize]byte{}
	copy(b.Signature[:], ed25519.Sign(syntheticSigningKey(), msg))
	return b
}

func mustEncodeBinding(t *testing.T, b DeviceTransportBinding) []byte {
	t.Helper()
	encoded, err := EncodeDeviceTransportBinding(b)
	if err != nil {
		t.Fatalf("EncodeDeviceTransportBinding: %v", err)
	}
	return encoded
}

func requireBindingField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error naming %q, got nil", field)
	}
	var fe *BindingFieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error is not a *BindingFieldError: %v", err)
	}
	if fe.Field != field {
		t.Fatalf("BindingFieldError.Field = %q, want %q (%v)", fe.Field, field, err)
	}
}

// TestBindingFixedSyntheticVector pins the exact canonical bytes, the exact
// signature preimage and the deterministic key, and checks that the fixed
// signature verifies.
func TestBindingFixedSyntheticVector(t *testing.T) {
	b := bindingVector(t)

	encoded := mustEncodeBinding(t, b)
	if string(encoded) != bindingVectorJSON {
		t.Fatalf("canonical encoding mismatch\n got: %s\nwant: %s", encoded, bindingVectorJSON)
	}
	if len(encoded) > MaxBindingSize {
		t.Fatalf("vector uses %d bytes, over budget %d", len(encoded), MaxBindingSize)
	}

	parsed, err := ParseDeviceTransportBinding([]byte(bindingVectorJSON))
	if err != nil {
		t.Fatalf("ParseDeviceTransportBinding: %v", err)
	}
	if parsed != b {
		t.Fatalf("parsed binding mismatch\n got: %+v\nwant: %+v", parsed, b)
	}
	// pair_generation is a non-zero value, so a parser that ignored or dropped
	// it cannot pass this assertion.
	if parsed.PairGeneration != 7 {
		t.Fatalf("pair_generation = %d, want 7", parsed.PairGeneration)
	}
	if reencoded := mustEncodeBinding(t, parsed); !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encode mismatch\n got: %s\nwant: %s", reencoded, encoded)
	}

	preimage, err := SigningBytes(b)
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	wantPreimage := BindingSignatureDomain + bindingVectorSignedJSON
	if string(preimage) != wantPreimage {
		t.Fatalf("signature preimage mismatch\n got: %q\nwant: %q", preimage, wantPreimage)
	}
	if got := base64.RawURLEncoding.EncodeToString(syntheticSigningPublicKey()); got != bindingVectorPublicKey {
		t.Fatalf("deterministic public key = %q, want %q", got, bindingVectorPublicKey)
	}
	if !ed25519.Verify(syntheticSigningPublicKey(), preimage, b.Signature[:]) {
		t.Fatal("fixed synthetic Ed25519 signature does not verify over the preimage")
	}
	if err := VerifyDeviceTransportBinding(b, "device-source", syntheticSigningPublicKey()); err != nil {
		t.Fatalf("VerifyDeviceTransportBinding: %v", err)
	}

	// The JSON and stream APIs must not diverge.
	marshaled, err := b.MarshalJSON()
	if err != nil || !bytes.Equal(marshaled, encoded) {
		t.Fatalf("MarshalJSON = %s, %v; want %s, nil", marshaled, err, encoded)
	}
	var decoded DeviceTransportBinding
	if err := decoded.UnmarshalJSON(encoded); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if decoded != b {
		t.Fatalf("UnmarshalJSON binding mismatch\n got: %+v\nwant: %+v", decoded, b)
	}
}

func TestEncodeBindingRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DeviceTransportBinding)
		field  string
	}{
		{"member id empty", func(b *DeviceTransportBinding) { b.MemberID = "" }, "member_id"},
		{"device id empty", func(b *DeviceTransportBinding) { b.DeviceID = "" }, "device_id"},
		{"install id empty", func(b *DeviceTransportBinding) { b.InstallID = "" }, "install_id"},
		{"vault id empty", func(b *DeviceTransportBinding) { b.VaultID = "" }, "vault_id"},
		{"member id too long", func(b *DeviceTransportBinding) { b.MemberID = strings.Repeat("a", MaxIdentifierLen+1) }, "member_id"},
		{"device id uppercase", func(b *DeviceTransportBinding) { b.DeviceID = "DEVICE-SOURCE" }, "device_id"},
		{"install id non ascii", func(b *DeviceTransportBinding) { b.InstallID = "install-é" }, "install_id"},
		{"vault id slash", func(b *DeviceTransportBinding) { b.VaultID = "vault/0001" }, "vault_id"},
		{"vault id control", func(b *DeviceTransportBinding) { b.VaultID = "vault\x00id" }, "vault_id"},
		{"recipient empty", func(b *DeviceTransportBinding) { b.RecipientPublicKey = "" }, "recipient_public_key"},
		{"recipient plain text", func(b *DeviceTransportBinding) { b.RecipientPublicKey = "not-an-age-recipient" }, "recipient_public_key"},
		{"recipient uppercase", func(b *DeviceTransportBinding) {
			b.RecipientPublicKey = strings.ToUpper(bindingVector(t).RecipientPublicKey)
		}, "recipient_public_key"},
		{"recipient padded", func(b *DeviceTransportBinding) { b.RecipientPublicKey += "=" }, "recipient_public_key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bindingVector(t)
			tt.mutate(&b)
			_, err := EncodeDeviceTransportBinding(b)
			if err == nil {
				t.Fatal("EncodeDeviceTransportBinding accepted an invalid binding")
			}
			if !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("error does not wrap ErrInvalidBinding: %v", err)
			}
			requireBindingField(t, err, tt.field)
		})
	}
}

// TestBindingParseRejectsNonCanonicalInput covers malformed canonical values
// and wire spellings, including the pair_generation value the parser must
// assign.
func TestBindingParseRejectsNonCanonicalInput(t *testing.T) {
	canonical := []byte(bindingVectorJSON)

	tests := []struct {
		name   string
		mutate func(t *testing.T, b []byte) []byte
	}{
		// Missing members, one case per schema field.
		{name: "missing format", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "format") }},
		{name: "missing version", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "version") }},
		{name: "missing kind", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "kind") }},
		{name: "missing member_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "member_id") }},
		{name: "missing device_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "device_id") }},
		{name: "missing install_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "install_id") }},
		{name: "missing vault_id", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "vault_id") }},
		{name: "missing pair_generation", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "pair_generation") }},
		{name: "missing spki_sha256", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "spki_sha256") }},
		{name: "missing recipient", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "recipient_public_key") }},
		{name: "missing signature", mutate: func(t *testing.T, b []byte) []byte { return removeMember(t, b, "signature") }},

		// Unknown, duplicate and reordered members.
		{name: "unknown member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `}`, `,"extra":0}`)
		}},
		{name: "unknown renamed member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"install_id":`, `"installation_id":`)
		}},
		{name: "duplicate member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"member_id":"member-0001",`, `"member_id":"member-0001","member_id":"member-0001",`)
		}},
		{name: "duplicate last member", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `,"signature":`, `,"signature":"`+strings.Repeat("A", 86)+`","signature":`)
		}},
		{name: "reordered members", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"install_id":"install-0001","vault_id"`, `"vault_id":"vault-0001","install_id"`)
		}},

		// Trailing data and surrounding whitespace.
		{name: "trailing newline", mutate: func(t *testing.T, b []byte) []byte { return append(b, '\n') }},
		{name: "trailing space", mutate: func(t *testing.T, b []byte) []byte { return append(b, ' ') }},
		{name: "trailing second value", mutate: func(t *testing.T, b []byte) []byte { return append(b, canonical...) }},
		{name: "leading space", mutate: func(t *testing.T, b []byte) []byte { return append([]byte(" "), b...) }},
		{name: "internal whitespace", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version": 1`)
		}},
		{name: "missing closing brace", mutate: func(t *testing.T, b []byte) []byte { return b[:len(b)-1] }},
		{name: "extra closing brace", mutate: func(t *testing.T, b []byte) []byte { return append(b, '}') }},
		{name: "missing comma", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"install-0001","vault_id"`, `"install-0001""vault_id"`)
		}},
		{name: "missing colon", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"vault_id":`, `"vault_id"`)
		}},

		// Shape and top-level type.
		{name: "empty input", mutate: func(t *testing.T, b []byte) []byte { return nil }},
		{name: "not an object", mutate: func(t *testing.T, b []byte) []byte { return []byte(`[]`) }},
		{name: "null", mutate: func(t *testing.T, b []byte) []byte { return []byte(`null`) }},
		{name: "string input", mutate: func(t *testing.T, b []byte) []byte { return []byte(`"binding"`) }},

		// Invalid UTF-8 and escaped strings.
		{name: "invalid utf8", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"install-0001"`, "\"install-\xff0001\"")
		}},
		{name: "escaped id", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"member-0001"`, `"member\u002d0001"`)
		}},
		{name: "control byte in id", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"install-0001"`, "\"install-\x010001\"")
		}},

		// Constants and member types.
		{name: "wrong format", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"locklark.remote-unlock"`, `"locklark.remote-unlock.v2"`)
		}},
		{name: "wrong kind", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"device-transport-binding"`, `"channel-binding-context"`)
		}},
		{name: "wrong version value", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":2`)
		}},
		{name: "version as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":"1"`)
		}},
		{name: "version leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":01`)
		}},
		{name: "version fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"version":1`, `"version":1.0`)
		}},
		{name: "id as number", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"install_id":"install-0001"`, `"install_id":123`)
		}},
		{name: "generation as string", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":7`, `"pair_generation":"7"`)
		}},

		// pair_generation spelling and range.
		{name: "generation negative", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":7`, `"pair_generation":-1`)
		}},
		{name: "generation plus sign", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":7`, `"pair_generation":+7`)
		}},
		{name: "generation leading zero", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":7`, `"pair_generation":07`)
		}},
		{name: "generation fraction", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":7`, `"pair_generation":7.0`)
		}},
		{name: "generation exponent", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":7`, `"pair_generation":7e0`)
		}},
		{name: "generation uint64 overflow", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"pair_generation":7`, `"pair_generation":18446744073709551616`)
		}},

		// Identifier grammar.
		{name: "id empty", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"member-0001"`, `""`)
		}},
		{name: "id 129 bytes", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"install-0001"`, `"`+strings.Repeat("a", MaxIdentifierLen+1)+`"`)
		}},
		{name: "id uppercase", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"vault-0001"`, `"VAULT-0001"`)
		}},
		{name: "id non ascii", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"member-0001"`, `"mémber-0001"`)
		}},
		{name: "id slash", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"device-source"`, `"device/source"`)
		}},
		{name: "id space", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"vault-0001"`, `"vault 0001"`)
		}},

		// spki_sha256 form.
		{name: "spki one byte short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh"`)
		}},
		{name: "spki padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`)
		}},
		{name: "spki noncanonical trailing bits", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9"`)
		}},
		{name: "spki standard base64 alphabet", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`,
				`"+AECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`)
		}},

		// Recipient form.
		{name: "recipient not age", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea"`, `"recipient-0001"`)
		}},
		{name: "recipient padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b, `"age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea"`, `"age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea="`)
		}},

		// Signature form.
		{name: "signature one byte short", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg"`,
				`"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFC"`)
		}},
		{name: "signature padded", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg"`,
				`"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg="`)
		}},
		{name: "signature standard base64 alphabet", mutate: func(t *testing.T, b []byte) []byte {
			return replaceOnce(t, b,
				`"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg"`,
				`"+hqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg"`)
		}},

		// Input budget.
		{name: "input over budget", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxBindingSize+1)...)
		}},
		{name: "input exactly budget with trailing data", mutate: func(t *testing.T, b []byte) []byte {
			return append(b, bytes.Repeat([]byte(" "), MaxBindingSize-len(b))...)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.mutate(t, append([]byte(nil), canonical...))
			if _, err := ParseDeviceTransportBinding(data); err == nil {
				t.Fatalf("ParseDeviceTransportBinding accepted non-canonical input: %s", data)
			} else if !errors.Is(err, ErrInvalidBindingEncoding) {
				t.Fatalf("error does not wrap ErrInvalidBindingEncoding: %v", err)
			}
		})
	}
}

// TestBindingPairGenerationRoundTrip proves the parser assigns the parsed
// uint64 to the struct, including explicit genesis and the maximum.
func TestBindingPairGenerationRoundTrip(t *testing.T) {
	for _, generation := range []uint64{0, 7, ^uint64(0)} {
		b := bindingVector(t)
		b.PairGeneration = generation
		b = resignBinding(t, b)
		encoded := mustEncodeBinding(t, b)
		parsed, err := ParseDeviceTransportBinding(encoded)
		if err != nil {
			t.Fatalf("pair_generation %d: %v", generation, err)
		}
		if parsed.PairGeneration != generation {
			t.Fatalf("pair_generation = %d, want %d", parsed.PairGeneration, generation)
		}
		if parsed != b {
			t.Fatalf("pair_generation %d did not round-trip", generation)
		}
	}
}

func TestBindingParseRejectsOversizedInput(t *testing.T) {
	for _, size := range []int{MaxBindingSize + 1, MaxBindingSize * 2} {
		if _, err := ParseDeviceTransportBinding(bytes.Repeat([]byte(" "), size)); err == nil {
			t.Fatalf("accepted %d bytes", size)
		} else if !errors.Is(err, ErrInvalidBindingEncoding) {
			t.Fatalf("error does not wrap ErrInvalidBindingEncoding: %v", err)
		}
	}
}

func TestVerifyBindingRejectsWrongKeyIDAndSignature(t *testing.T) {
	valid := bindingVector(t)

	t.Run("wrong expected device id", func(t *testing.T) {
		err := VerifyDeviceTransportBinding(valid, "device-target", syntheticSigningPublicKey())
		if !errors.Is(err, ErrInvalidBinding) {
			t.Fatalf("error does not wrap ErrInvalidBinding: %v", err)
		}
		requireBindingField(t, err, "device_id")
	})
	t.Run("empty expected device id", func(t *testing.T) {
		err := VerifyDeviceTransportBinding(valid, "", syntheticSigningPublicKey())
		requireBindingField(t, err, "device_id")
	})
	t.Run("expected device id is a prefix", func(t *testing.T) {
		err := VerifyDeviceTransportBinding(valid, "device-sourc", syntheticSigningPublicKey())
		requireBindingField(t, err, "device_id")
	})
	t.Run("wrong pinned key", func(t *testing.T) {
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
		err := VerifyDeviceTransportBinding(valid, "device-source", other.Public().(ed25519.PublicKey))
		if !errors.Is(err, ErrInvalidBinding) {
			t.Fatalf("error does not wrap ErrInvalidBinding: %v", err)
		}
		requireBindingField(t, err, "signature")
	})
	t.Run("short pinned key", func(t *testing.T) {
		err := VerifyDeviceTransportBinding(valid, "device-source", syntheticSigningPublicKey()[:16])
		if !errors.Is(err, ErrInvalidBinding) {
			t.Fatalf("error does not wrap ErrInvalidBinding: %v", err)
		}
	})
	t.Run("mutated signature", func(t *testing.T) {
		mutated := valid
		mutated.Signature[0] ^= 0x01
		err := VerifyDeviceTransportBinding(mutated, "device-source", syntheticSigningPublicKey())
		requireBindingField(t, err, "signature")
	})
	t.Run("zero signature", func(t *testing.T) {
		err := VerifyDeviceTransportBinding(DeviceTransportBinding{}, "device-source", syntheticSigningPublicKey())
		if err == nil {
			t.Fatal("zero binding verified")
		}
	})
}

// TestVerifyBindingRejectsEveryMutatedField mutates each signed field, keeps
// the original signature, and requires verification to fail. Each mutated
// binding is itself canonically encodable, so only the signature check rejects
// it.
func TestVerifyBindingRejectsEveryMutatedField(t *testing.T) {
	tests := []struct {
		name             string
		mutate           func(*DeviceTransportBinding)
		expectedDeviceID string
	}{
		{"member_id", func(b *DeviceTransportBinding) { b.MemberID = "member-0002" }, "device-source"},
		{"device_id", func(b *DeviceTransportBinding) { b.DeviceID = "device-other" }, "device-other"},
		{"install_id", func(b *DeviceTransportBinding) { b.InstallID = "install-0002" }, "device-source"},
		{"vault_id", func(b *DeviceTransportBinding) { b.VaultID = "vault-0002" }, "device-source"},
		{"pair_generation", func(b *DeviceTransportBinding) { b.PairGeneration = 8 }, "device-source"},
		{"spki_sha256", func(b *DeviceTransportBinding) { b.SPKISHA256[0] ^= 0xff }, "device-source"},
		{"recipient_public_key", func(b *DeviceTransportBinding) { b.RecipientPublicKey = bindingOtherRecipient }, "device-source"},
		{"signature", func(b *DeviceTransportBinding) { b.Signature[63] ^= 0xff }, "device-source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := bindingVector(t)
			tt.mutate(&mutated)
			if _, err := EncodeDeviceTransportBinding(mutated); err != nil {
				t.Fatalf("mutated binding is not encodable: %v", err)
			}
			err := VerifyDeviceTransportBinding(mutated, tt.expectedDeviceID, syntheticSigningPublicKey())
			if err == nil {
				t.Fatalf("verification accepted a mutated %s", tt.name)
			}
			if !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("error does not wrap ErrInvalidBinding: %v", err)
			}
			if tt.name == "signature" {
				requireBindingField(t, err, "signature")
			}
		})
	}
}

func bindingContext() ChannelBindingContext {
	return ChannelBindingContext{
		RequestID:      "req-0001",
		RequestDigest:  ascendingDigest(),
		PairID:         "pair-0001",
		PairGeneration: 7,
		LockGeneration: 1,
		MemberID:       "member-0001",
		SourceDeviceID: "device-source",
		TargetDeviceID: "device-target",
		VaultID:        "vault-0001",
		KeyEpoch:       7,
		PolicySeq:      0,
		PolicyDigest:   descendingDigest(),
		DeadlineUnixMS: 1800000000000,
	}
}

func TestVerifyBindingForContext(t *testing.T) {
	binding := bindingVector(t)
	context := bindingContext()

	if err := VerifyDeviceTransportBindingForContext(binding, context, "device-source", syntheticSigningPublicKey()); err != nil {
		t.Fatalf("valid source binding: %v", err)
	}

	// The binding may name either distinct context endpoint.
	target := resignBinding(t, func() DeviceTransportBinding {
		b := bindingVector(t)
		b.DeviceID = "device-target"
		return b
	}())
	if err := VerifyDeviceTransportBindingForContext(target, context, "device-target", syntheticSigningPublicKey()); err != nil {
		t.Fatalf("valid target binding: %v", err)
	}

	reversed := context
	reversed.SourceDeviceID = "device-target"
	reversed.TargetDeviceID = "device-source"
	if err := VerifyDeviceTransportBindingForContext(binding, reversed, "device-source", syntheticSigningPublicKey()); err != nil {
		t.Fatalf("valid reversed-endpoint binding: %v", err)
	}
}

// TestVerifyBindingForContextIsRequestIndependent shows that the stable
// binding cross-check ignores every per-request context field.
func TestVerifyBindingForContextIsRequestIndependent(t *testing.T) {
	context := bindingContext()
	context.RequestID = "req-9999"
	context.RequestDigest = [DigestSize]byte{}
	context.PairID = "pair-9999"
	context.LockGeneration = 99
	context.KeyEpoch = 1
	context.PolicySeq = 42
	context.PolicyDigest = [DigestSize]byte{}
	context.DeadlineUnixMS = 2000000000000

	if err := VerifyDeviceTransportBindingForContext(bindingVector(t), context, "device-source", syntheticSigningPublicKey()); err != nil {
		t.Fatalf("request-only context changes affected the stable binding: %v", err)
	}
}

func TestVerifyBindingForContextRejectsMismatches(t *testing.T) {
	binding := bindingVector(t)
	pinned := syntheticSigningPublicKey()

	tests := []struct {
		name             string
		mutate           func(*ChannelBindingContext)
		expectedDeviceID string
		field            string
	}{
		{
			name:             "member mismatch",
			mutate:           func(c *ChannelBindingContext) { c.MemberID = "member-0002" },
			expectedDeviceID: "device-source",
			field:            "member_id",
		},
		{
			name:             "vault mismatch",
			mutate:           func(c *ChannelBindingContext) { c.VaultID = "vault-0002" },
			expectedDeviceID: "device-source",
			field:            "vault_id",
		},
		{
			name:             "pair generation mismatch",
			mutate:           func(c *ChannelBindingContext) { c.PairGeneration = 8 },
			expectedDeviceID: "device-source",
			field:            "pair_generation",
		},
		{
			name: "equal context endpoints",
			mutate: func(c *ChannelBindingContext) {
				c.SourceDeviceID = "device-target"
				c.TargetDeviceID = "device-target"
			},
			expectedDeviceID: "device-source",
			field:            "",
		},
		{
			name:             "binding is not a context endpoint",
			mutate:           func(*ChannelBindingContext) {},
			expectedDeviceID: "device-other",
			field:            "device_id",
		},
		{
			name: "expected id matches binding but neither endpoint",
			mutate: func(c *ChannelBindingContext) {
				c.SourceDeviceID = "device-other-source"
				c.TargetDeviceID = "device-other-target"
			},
			expectedDeviceID: "device-source",
			field:            "device_id",
		},
		{
			name:             "context is not canonical-valid",
			mutate:           func(c *ChannelBindingContext) { c.KeyEpoch = 0 },
			expectedDeviceID: "device-source",
			field:            "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := bindingContext()
			tt.mutate(&context)
			err := VerifyDeviceTransportBindingForContext(binding, context, tt.expectedDeviceID, pinned)
			if err == nil {
				t.Fatal("VerifyDeviceTransportBindingForContext accepted an inconsistent binding")
			}
			if !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("error does not wrap ErrInvalidBinding: %v", err)
			}
			requireBindingField(t, err, tt.field)
		})
	}
}

func TestBindingErrorsNeverContainValues(t *testing.T) {
	secret := "UPPERSECRETIDENTIFIER"
	b := bindingVector(t)
	b.MemberID = secret
	if _, err := EncodeDeviceTransportBinding(b); err == nil {
		t.Fatal("expected encode error")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("encode error leaked an identifier value: %v", err)
	}

	// An unknown key is attacker-controlled input and must not be echoed.
	data := replaceOnce(t, []byte(bindingVectorJSON), `"install_id":`, `"`+secret+`":`)
	if _, err := ParseDeviceTransportBinding(data); err == nil {
		t.Fatal("expected parse error")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("parse error leaked an unknown key: %v", err)
	}
}
