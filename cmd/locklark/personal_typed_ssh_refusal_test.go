package main

// A refused key file must stop creation before the SAVE consent prompt and
// before any vault mutation, whatever the refusal class is.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestCreateTypedPersonalSSHKeyRefusesBeforeConsent(t *testing.T) {
	encrypted := writeTypedSSHKeyFile(t, ed25519.NewKeyFromSeed(typedSSHFixtureSeed()), []byte("passphrase"))
	malformed := filepath.Join(t.TempDir(), "malformed_key")
	writePrivateTypedFixture(t, malformed, []byte("not a private key"))
	cases := map[string]struct {
		document string
		want     error
	}{
		"encrypted":      {typedSSHCreateDocument(t, encrypted), errTypedSSHEncrypted},
		"malformed":      {typedSSHCreateDocument(t, malformed), errTypedSSHUnsupported},
		"missing":        {typedSSHCreateDocument(t, filepath.Join(t.TempDir(), "absent_key")), errTypedInputRefused},
		"wrong-category": {fmt.Sprintf(`{"category":"login","title":"k","ssh_private_key_file":%q}`, malformed), errTypedInputRefused},
		"bare-ssh":       {`{"category":"ssh_key","title":"k"}`, errTypedInputRefused},
		"attachments":    {fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"attachments":[{"file":%q,"file_name":"a.bin"}]}`, malformed, malformed), errTypedInputRefused},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			vaultPath, inputPath, pw, key := typedCreateFixture(t, tc.document)
			asked := 0
			response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(string) ([]byte, error) {
				asked++
				return []byte("SAVE"), nil
			}, &bytes.Buffer{})
			if response != nil || !errors.Is(err, tc.want) {
				t.Fatalf("expected fixed refusal before consent, got response=%+v err=%v", response, err)
			}
			if asked != 0 {
				t.Fatalf("refused key reached the consent prompt %d times", asked)
			}
			if count := typedCreateActiveCount(t, vaultPath, pw, key); count != 0 {
				t.Fatalf("refused key mutated the vault: %d items", count)
			}
		})
	}
}
