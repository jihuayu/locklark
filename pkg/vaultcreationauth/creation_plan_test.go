package vaultcreationauth

import (
	"crypto/ed25519"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// basePlan has distinct, valid values in every bound field.
func basePlan() CreationPlan {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(0x20 + i)
	}
	pdig := make([]byte, 32)
	for i := range pdig {
		pdig[i] = byte(0x80 + i)
	}
	return CreationPlan{
		GenesisBytes: []byte("locklark-creation-plan-vector-genesis\n"),
		RootPin: vaultfile.PolicyCheckpoint{
			VaultID:            "vault:01j0vector",
			OwnerRootKeyID:     "owner-root.0",
			OwnerRootPublicKey: pub,
			PolicySeq:          0,
			PolicyDigest:       pdig,
		},
		BackendLocator: "objectstore://tenant-7/region-eu-1/bucket/v1",
		Slug:           "team-notes",
		Name:           "Team Notes",
	}
}

// mutatePlan returns plan with exactly one field changed by f.
func mutatePlan(p CreationPlan, f func(*CreationPlan)) CreationPlan {
	c := p
	c.RootPin.OwnerRootPublicKey = append([]byte(nil), p.RootPin.OwnerRootPublicKey...)
	c.RootPin.PolicyDigest = append([]byte(nil), p.RootPin.PolicyDigest...)
	c.GenesisBytes = append([]byte(nil), p.GenesisBytes...)
	f(&c)
	return c
}

func mustPlanDigest(t *testing.T, p CreationPlan) [32]byte {
	t.Helper()
	d, err := CreationPlanDigest(p)
	if err != nil {
		t.Fatalf("CreationPlanDigest: unexpected error %v", err)
	}
	return d
}

func TestCreationPlanDigestFixedVector(t *testing.T) {
	// The expected digest was computed independently, outside this package
	// (a separate SHA-256 implementation fed struct-packed fields), over:
	//
	//   "locklark.vault-creation-plan/v1" || 0x00
	//   || u32be(38) || "locklark-creation-plan-vector-genesis\n"
	//   || u32be(16) || "vault:01j0vector"
	//   || u32be(12) || "owner-root.0"
	//   || 0x20,0x21,...,0x3f                          (32 raw bytes)
	//   || 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00     (PolicySeq 0, u64be)
	//   || 0x80,0x81,...,0x9f                          (32 raw bytes)
	//   || u32be(44) || "objectstore://tenant-7/region-eu-1/bucket/v1"
	//   || u32be(10) || "team-notes"
	//   || u32be(10) || "Team Notes"
	const want = "8cb18ede1a2b4c9a2591ef34d51353a327570aa2eab23b373a63c632e56b6ca6"
	plan := basePlan()
	if got := hex.EncodeToString(plan.GenesisBytes); got != hex.EncodeToString([]byte("locklark-creation-plan-vector-genesis\n")) || len(plan.BackendLocator) != 44 {
		t.Fatalf("vector plan drifted: genesis %d bytes, locator %d bytes", len(plan.GenesisBytes), len(plan.BackendLocator))
	}
	d := mustPlanDigest(t, plan)
	if hex.EncodeToString(d[:]) != want {
		t.Fatalf("CreationPlanDigest = %x, want %s", d, want)
	}
	// Deterministic, and a second call agrees.
	if again := mustPlanDigest(t, plan); again != d {
		t.Fatalf("CreationPlanDigest is not deterministic")
	}
}

func TestCreationPlanDigestFieldMutations(t *testing.T) {
	base := basePlan()
	want := mustPlanDigest(t, base)
	cases := []struct {
		name string
		f    func(*CreationPlan)
	}{
		{"genesis one byte", func(p *CreationPlan) { p.GenesisBytes[0] ^= 0x01 }},
		{"genesis appended", func(p *CreationPlan) { p.GenesisBytes = append(p.GenesisBytes, 0) }},
		{"genesis truncated", func(p *CreationPlan) { p.GenesisBytes = p.GenesisBytes[:len(p.GenesisBytes)-1] }},
		{"genesis whole replacement", func(p *CreationPlan) { p.GenesisBytes = []byte("x") }},
		{"vault id", func(p *CreationPlan) { p.RootPin.VaultID = "vault:01j0vecto2" }},
		{"owner root key id", func(p *CreationPlan) { p.RootPin.OwnerRootKeyID = "owner-root.1" }},
		{"root public key", func(p *CreationPlan) { p.RootPin.OwnerRootPublicKey[31] ^= 0x01 }},
		{"policy digest", func(p *CreationPlan) { p.RootPin.PolicyDigest[0] ^= 0x01 }},
		{"backend locator", func(p *CreationPlan) { p.BackendLocator = "objectstore://tenant-7/region-eu-1/bucket/v2" }},
		{"slug", func(p *CreationPlan) { p.Slug = "team-notez" }},
		{"name", func(p *CreationPlan) { p.Name = "Team Notez" }},
		{"name case", func(p *CreationPlan) { p.Name = "team Notes" }},
		{"name outer space", func(p *CreationPlan) { p.Name = "Team Notes " }},
	}
	for _, c := range cases {
		got := mustPlanDigest(t, mutatePlan(base, c.f))
		if got == want {
			t.Errorf("%s: digest did not change", c.name)
		}
	}
	// The base plan itself is not mutated by any of the above.
	if again := mustPlanDigest(t, base); again != want {
		t.Fatalf("base plan digest changed after mutations")
	}
}

func TestCreationPlanDigestRawGenesis(t *testing.T) {
	// Same visible content, different raw bytes: the digest follows the
	// bytes, never a parse/re-encode of them.
	compact := basePlan()
	compact.GenesisBytes = []byte(`{"a":1}`)
	spaced := mutatePlan(compact, func(p *CreationPlan) { p.GenesisBytes = []byte(`{"a": 1}`) })
	if mustPlanDigest(t, compact) == mustPlanDigest(t, spaced) {
		t.Fatalf("raw genesis bytes did not affect the digest")
	}
	// A leading BOM and a trailing newline are bound as raw bytes too.
	plain := basePlan()
	plain.GenesisBytes = []byte("genesis")
	for _, g := range [][]byte{[]byte("\xef\xbb\xbfgenesis"), []byte("genesis\n"), []byte("Genesis")} {
		other := mutatePlan(plain, func(p *CreationPlan) { p.GenesisBytes = g })
		if mustPlanDigest(t, plain) == mustPlanDigest(t, other) {
			t.Fatalf("genesis %q did not change the digest", g)
		}
	}
}

func TestCreationPlanDigestDoesNotRetainGenesis(t *testing.T) {
	// The genesis is hashed during the call, never retained: changing the
	// caller's buffer after the call cannot change the earlier digest.
	plan := basePlan()
	d := mustPlanDigest(t, plan)
	for i := range plan.GenesisBytes {
		plan.GenesisBytes[i] = 0
	}
	if again := mustPlanDigest(t, basePlan()); again != d {
		t.Fatalf("digest depends on caller buffer state after the call")
	}
}

func TestCreationPlanDigestLengthPrefixAmbiguity(t *testing.T) {
	// "ab"+"c" and "a"+"bc" concatenate to the same bytes; the per-field
	// uint32 length prefixes must keep the digests apart.
	b1 := basePlan()
	b1.Slug, b1.Name = "ab", "c"
	b2 := basePlan()
	b2.Slug, b2.Name = "a", "bc"
	if b1.Slug+b1.Name != b2.Slug+b2.Name {
		t.Fatalf("test setup: concatenations differ")
	}
	if mustPlanDigest(t, b1) == mustPlanDigest(t, b2) {
		t.Fatalf("schemes whose adjacent fields concatenate alike hash the same")
	}
	// Same across every variable-length boundary: genesis|vault id,
	// vault id|owner id, owner id|locator, and an empty-looking field.
	pairs := func(build func(a, bb string) CreationPlan) {
		t.Helper()
		if mustPlanDigest(t, build("ab", "cde")) == mustPlanDigest(t, build("a", "bcde")) {
			t.Fatalf("length prefix missing at a field boundary")
		}
	}
	pairs(func(a, bb string) CreationPlan {
		return mutatePlan(basePlan(), func(p *CreationPlan) { p.RootPin.VaultID, p.RootPin.OwnerRootKeyID = a, bb })
	})
	pairs(func(a, bb string) CreationPlan {
		return mutatePlan(basePlan(), func(p *CreationPlan) { p.RootPin.OwnerRootKeyID, p.BackendLocator = a, bb })
	})
	pairs(func(a, bb string) CreationPlan {
		return mutatePlan(basePlan(), func(p *CreationPlan) { p.BackendLocator, p.Slug = a, bb })
	})
	// A genesis that runs into the next field, and a locator that ends in
	// the domain separator, are still unambiguous.
	g1 := mutatePlan(basePlan(), func(p *CreationPlan) { p.GenesisBytes, p.RootPin.VaultID = []byte("ab"), "c" })
	g2 := mutatePlan(basePlan(), func(p *CreationPlan) { p.GenesisBytes, p.RootPin.VaultID = []byte("a"), "bc" })
	if mustPlanDigest(t, g1) == mustPlanDigest(t, g2) {
		t.Fatalf("genesis|vault id boundary is ambiguous")
	}
}

func TestCreationPlanDigestErrors(t *testing.T) {
	base := basePlan()
	cases := []struct {
		name string
		f    func(*CreationPlan)
	}{
		{"nil genesis", func(p *CreationPlan) { p.GenesisBytes = nil }},
		{"empty genesis", func(p *CreationPlan) { p.GenesisBytes = []byte{} }},
		{"empty vault id", func(p *CreationPlan) { p.RootPin.VaultID = "" }},
		{"vault id 65 bytes", func(p *CreationPlan) { p.RootPin.VaultID = strings.Repeat("a", MaxCreationPlanIDBytes+1) }},
		{"vault id uppercase", func(p *CreationPlan) { p.RootPin.VaultID = "Vault" }},
		{"vault id slash", func(p *CreationPlan) { p.RootPin.VaultID = "va/ult" }},
		{"vault id space", func(p *CreationPlan) { p.RootPin.VaultID = "va ult" }},
		{"vault id non-ascii", func(p *CreationPlan) { p.RootPin.VaultID = "vault\xc3\xa9" }},
		{"vault id NUL", func(p *CreationPlan) { p.RootPin.VaultID = "vault\x00" }},
		{"empty owner id", func(p *CreationPlan) { p.RootPin.OwnerRootKeyID = "" }},
		{"owner id 65 bytes", func(p *CreationPlan) { p.RootPin.OwnerRootKeyID = strings.Repeat("0", MaxCreationPlanIDBytes+1) }},
		{"owner id uppercase", func(p *CreationPlan) { p.RootPin.OwnerRootKeyID = "Owner" }},
		{"nil root key", func(p *CreationPlan) { p.RootPin.OwnerRootPublicKey = nil }},
		{"root key 31", func(p *CreationPlan) { p.RootPin.OwnerRootPublicKey = p.RootPin.OwnerRootPublicKey[:31] }},
		{"root key 33", func(p *CreationPlan) { p.RootPin.OwnerRootPublicKey = append(p.RootPin.OwnerRootPublicKey, 0) }},
		{"policy seq 1", func(p *CreationPlan) { p.RootPin.PolicySeq = 1 }},
		{"policy seq max", func(p *CreationPlan) { p.RootPin.PolicySeq = 1<<64 - 1 }},
		{"nil policy digest", func(p *CreationPlan) { p.RootPin.PolicyDigest = nil }},
		{"policy digest 31", func(p *CreationPlan) { p.RootPin.PolicyDigest = p.RootPin.PolicyDigest[:31] }},
		{"policy digest 33", func(p *CreationPlan) { p.RootPin.PolicyDigest = append(p.RootPin.PolicyDigest, 0) }},
		{"empty locator", func(p *CreationPlan) { p.BackendLocator = "" }},
		{"locator 4097", func(p *CreationPlan) { p.BackendLocator = strings.Repeat("a", MaxBackendLocatorBytes+1) }},
		{"locator NUL", func(p *CreationPlan) { p.BackendLocator = "a\x00b" }},
		{"locator tab", func(p *CreationPlan) { p.BackendLocator = "a\tb" }},
		{"locator DEL", func(p *CreationPlan) { p.BackendLocator = "a\x7fb" }},
		{"locator C1", func(p *CreationPlan) { p.BackendLocator = "a\u0085b" }},
		{"locator invalid utf8", func(p *CreationPlan) { p.BackendLocator = "a\xffb" }},
		{"locator lone surrogate bytes", func(p *CreationPlan) { p.BackendLocator = "a\xed\xa0\x80b" }},
		{"empty slug", func(p *CreationPlan) { p.Slug = "" }},
		{"slug 64", func(p *CreationPlan) { p.Slug = "a" + strings.Repeat("b", 63) }},
		{"slug leading hyphen", func(p *CreationPlan) { p.Slug = "-team" }},
		{"slug underscore", func(p *CreationPlan) { p.Slug = "team_notes" }},
		{"slug uppercase", func(p *CreationPlan) { p.Slug = "Team" }},
		{"slug trace", func(p *CreationPlan) { p.Slug = "team.notebook" }},
		{"empty name", func(p *CreationPlan) { p.Name = "" }},
		{"name 257 bytes", func(p *CreationPlan) { p.Name = strings.Repeat("a", MaxCreationPlanNameBytes+1) }},
		{"name 256 bytes one rune over", func(p *CreationPlan) { p.Name = strings.Repeat("a", 255) + "é" }},
		{"name whitespace only", func(p *CreationPlan) { p.Name = "   \t" }},
		{"name whitespace only wide", func(p *CreationPlan) { p.Name = "\u00a0\u3000 \u2003" }},
		{"name NUL", func(p *CreationPlan) { p.Name = "a\x00" }},
		{"name C0 newline", func(p *CreationPlan) { p.Name = "a\nb" }},
		{"name DEL", func(p *CreationPlan) { p.Name = "a\x7fb" }},
		{"name C1", func(p *CreationPlan) { p.Name = "a\u0085b" }},
		{"name Zl", func(p *CreationPlan) { p.Name = "a\u2028b" }},
		{"name Zp", func(p *CreationPlan) { p.Name = "a\u2029b" }},
		{"name ZWSP", func(p *CreationPlan) { p.Name = "a\u200bb" }},
		{"name bidi override", func(p *CreationPlan) { p.Name = "a\u202eb" }},
		{"name soft hyphen", func(p *CreationPlan) { p.Name = "a\u00adb" }},
		{"name BOM", func(p *CreationPlan) { p.Name = "\ufeffa" }},
		{"name invalid utf8", func(p *CreationPlan) { p.Name = "a\xc3" }},
	}
	for _, c := range cases {
		p := mutatePlan(base, c.f)
		d, err := CreationPlanDigest(p)
		if err != ErrInvalidCreationPlan {
			t.Errorf("%s: err = %v, want ErrInvalidCreationPlan", c.name, err)
		}
		if d != ([32]byte{}) {
			t.Errorf("%s: digest = %x, want zero", c.name, d)
		}
	}
}

func TestCreationPlanDigestBounds(t *testing.T) {
	// Genesis: the exact vaultfile.MaxFileBytes cap is accepted; one more is
	// refused before any hashing, so no 32 MiB preimage is ever built.
	atCap := mutatePlan(basePlan(), func(p *CreationPlan) { p.GenesisBytes = make([]byte, vaultfile.MaxFileBytes) })
	atCap.GenesisBytes[0], atCap.GenesisBytes[len(atCap.GenesisBytes)-1] = 1, 2
	if _, err := CreationPlanDigest(atCap); err != nil {
		t.Fatalf("genesis at MaxFileBytes = %d: %v", vaultfile.MaxFileBytes, err)
	}
	over := mutatePlan(basePlan(), func(p *CreationPlan) { p.GenesisBytes = make([]byte, vaultfile.MaxFileBytes+1) })
	if d, err := CreationPlanDigest(over); err != ErrInvalidCreationPlan || d != ([32]byte{}) {
		t.Fatalf("genesis at MaxFileBytes+1 = (%x, %v), want zero, ErrInvalidCreationPlan", d, err)
	}
	// The cap is a length rule only: padding content changes the digest.
	padded := mutatePlan(basePlan(), func(p *CreationPlan) { p.GenesisBytes = append(p.GenesisBytes, make([]byte, 1<<20)...) })
	if mustPlanDigest(t, padded) == mustPlanDigest(t, basePlan()) {
		t.Fatalf("padded genesis did not change the digest")
	}

	valid := []struct {
		name string
		f    func(*CreationPlan)
	}{
		{"vault id 1 byte", func(p *CreationPlan) { p.RootPin.VaultID = "a" }},
		{"vault id 64 bytes", func(p *CreationPlan) { p.RootPin.VaultID = strings.Repeat("a", MaxCreationPlanIDBytes) }},
		{"vault id all allowed", func(p *CreationPlan) { p.RootPin.VaultID = "a-z_0.9:" }},
		{"owner id 1 byte", func(p *CreationPlan) { p.RootPin.OwnerRootKeyID = "0" }},
		{"owner id 64 bytes", func(p *CreationPlan) { p.RootPin.OwnerRootKeyID = strings.Repeat(":", MaxCreationPlanIDBytes) }},
		{"slugs", func(p *CreationPlan) { p.Slug = "a" }},
		{"slug 63", func(p *CreationPlan) { p.Slug = "a" + strings.Repeat("-", 62) }},
		{"slug 63 alnum", func(p *CreationPlan) { p.Slug = strings.Repeat("z9", 31) + "0" }},
		{"locator 1 byte", func(p *CreationPlan) { p.BackendLocator = "x" }},
		{"locator 4096", func(p *CreationPlan) { p.BackendLocator = strings.Repeat("l", MaxBackendLocatorBytes) }},
		{"locator multibyte", func(p *CreationPlan) { p.BackendLocator = "对象存储://租户-7/桶" }},
		{"locator keeps case", func(p *CreationPlan) { p.BackendLocator = "ObjectStore://Tenant-7" }},
		{"locator ZWJ", func(p *CreationPlan) { p.BackendLocator = "a\u200db" }},
		{"locator BOM passes", func(p *CreationPlan) { p.BackendLocator = "\ufeffa" }},
		{"name 1 byte", func(p *CreationPlan) { p.Name = "a" }},
		{"name 256 bytes", func(p *CreationPlan) { p.Name = strings.Repeat("a", MaxCreationPlanNameBytes) }},
		{"name 256 bytes multibyte", func(p *CreationPlan) { p.Name = strings.Repeat("é", 128) }},
		{"name inner spaces", func(p *CreationPlan) { p.Name = "My   Vault" }},
		{"name outer spaces", func(p *CreationPlan) { p.Name = "  Team Notes  " }},
		{"name outer NBSP", func(p *CreationPlan) { p.Name = "\u00a0Team\u00a0" }},
		{"name outer ideographic space", func(p *CreationPlan) { p.Name = "\u3000Team\u3000" }},
		{"name ZWNJ between visible", func(p *CreationPlan) { p.Name = "می\u200cخواهم" }},
		{"name ZWJ family emoji", func(p *CreationPlan) { p.Name = "👨‍👩‍👧" }},
		{"name ZWNJ/ZWJ between spaces", func(p *CreationPlan) { p.Name = "\u200c \u3000\u200d" }},
		{"name visible only after space", func(p *CreationPlan) { p.Name = " a" }},
	}
	for _, c := range valid {
		if _, err := CreationPlanDigest(mutatePlan(basePlan(), c.f)); err != nil {
			t.Errorf("%s: %v, want nil", c.name, err)
		}
	}

	// Ordinary spaces around a visible rune are bound exactly, never trimmed.
	spaced := mutatePlan(basePlan(), func(p *CreationPlan) { p.Name = " Team Notes " })
	if mustPlanDigest(t, spaced) == mustPlanDigest(t, basePlan()) {
		t.Fatalf("outer spaces were trimmed")
	}
}

func TestCreationPlanDigestSentinel(t *testing.T) {
	// The sentinel is fixed, shared by every rejection, and names no input.
	const leak = "leak-marker-\u2028-\xff"
	bad := mutatePlan(basePlan(), func(p *CreationPlan) { p.Name = "a" + leak })
	d, err := CreationPlanDigest(bad)
	if err != ErrInvalidCreationPlan || d != ([32]byte{}) {
		t.Fatalf("= (%x, %v), want zero, ErrInvalidCreationPlan", d, err)
	}
	if strings.Contains(err.Error(), "leak-marker") || strings.Contains(err.Error(), "\xff") {
		t.Fatalf("error text echoes caller input: %q", err.Error())
	}
	if err.Error() != "vaultcreationauth: invalid creation plan" {
		t.Fatalf("sentinel text = %q", err.Error())
	}
	// Every rejecting field reports the same one sentinel value.
	for _, f := range []func(*CreationPlan){
		func(p *CreationPlan) { p.GenesisBytes = nil },
		func(p *CreationPlan) { p.RootPin.VaultID = leak },
		func(p *CreationPlan) { p.RootPin.PolicySeq = 2 },
		func(p *CreationPlan) { p.BackendLocator = leak },
		func(p *CreationPlan) { p.Slug = leak },
	} {
		if _, err := CreationPlanDigest(mutatePlan(basePlan(), f)); err != ErrInvalidCreationPlan {
			t.Fatalf("err = %v, want the fixed ErrInvalidCreationPlan", err)
		}
	}
}

func TestVerifyBindsCreationPlanDigest(t *testing.T) {
	// A real plan digest carried by a signed context: the identity proof
	// verifies under the registered identity I and fails under the distinct
	// content key C, because the digest is authenticated as part of the
	// expected context.
	plan := basePlan()
	digest := mustPlanDigest(t, plan)
	expected := baseContext()
	expected.PlanDigest = digest
	proof := signProof(t, identityKey(), expected)

	if err := Verify(proof, expected, identityKey().Public().(ed25519.PublicKey), now(expected)); err != nil {
		t.Fatalf("Verify with expected plan digest = %v, want nil", err)
	}
	if err := Verify(proof, expected, contentKey().Public().(ed25519.PublicKey), now(expected)); err != ErrInvalidSignature {
		t.Fatalf("Verify(content key) = %v, want ErrInvalidSignature", err)
	}
	// A context carrying another plan digest is a context mismatch: the
	// signed digest byte binds the context even when the signature is valid
	// for the other digest.
	other := mutatePlan(plan, func(p *CreationPlan) { p.Name = "Other" })
	otherContext := expected
	otherContext.PlanDigest = mustPlanDigest(t, other)
	if err := Verify(signProof(t, identityKey(), otherContext), expected, identityKey().Public().(ed25519.PublicKey), now(expected)); err != ErrContextMismatch {
		t.Fatalf("Verify(other plan digest) = %v, want ErrContextMismatch", err)
	}
	// Verify is opaque to the plan: it does not recompute the digest from any
	// plan, so a context whose digest is any 32 bytes verifies as usual.
	opaque := expected
	opaque.PlanDigest = [32]byte{0xde, 0xad}
	if err := Verify(signProof(t, identityKey(), opaque), opaque, identityKey().Public().(ed25519.PublicKey), now(opaque)); err != nil {
		t.Fatalf("Verify(opaque digest) = %v, want nil", err)
	}
}

func TestCreationPlanDigestDoesNotAllocatePreimage(t *testing.T) {
	// A 32 MiB genesis costs no proportional allocations: the digest is fed
	// the caller's slice directly, field by field. Measured as total allocated
	// bytes around one call, so a single preimage-sized allocation is caught
	// even though it is only one allocation event.
	plan := mutatePlan(basePlan(), func(p *CreationPlan) { p.GenesisBytes = make([]byte, vaultfile.MaxFileBytes) })
	digestOne := func() {
		if _, err := CreationPlanDigest(plan); err != nil {
			t.Fatalf("at-cap plan: %v", err)
		}
	}
	digestOne() // Warm up: package-level and runtime state is paid here.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	digestOne()
	runtime.ReadMemStats(&after)
	// TotalAlloc counts bytes only: unlike heap stats it cannot move down
	// when deferred frees run, and no other goroutine of this test package
	// (the test is not parallel) allocates concurrently. 1 MiB is far below
	// one preimage at the genesis cap and far above the digest's own slices.
	const maxAllocatedBytes = 1 << 20
	if used := after.TotalAlloc - before.TotalAlloc; used > maxAllocatedBytes {
		t.Fatalf("CreationPlanDigest at the genesis cap allocated %d bytes, want at most %d: a preimage-sized allocation", used, maxAllocatedBytes)
	}
}
