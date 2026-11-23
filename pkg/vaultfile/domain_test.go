package vaultfile

import "testing"

// TestDomainConstantsExact pins the byte-exact v1 domain labels quoted in
// docs/vaultfile-wire-v1.md. They must not start with a slash.
func TestDomainConstantsExact(t *testing.T) {
	cases := map[string]string{
		"DomainRevision":         DomainRevision,
		"DomainContentSignature": DomainContentSignature,
		"DomainFileDigest":       DomainFileDigest,
	}
	want := map[string]string{
		"DomainRevision":         "passme.vault-file/v1/revision",
		"DomainContentSignature": "passme.vault-file/v1/content-signature",
		"DomainFileDigest":       "passme.vault-file/v1/file-digest",
	}
	for name, got := range cases {
		if got != want[name] {
			t.Errorf("%s = %q, want %q", name, got, want[name])
		}
	}
}
