package main

// Targeted resolver tests: one explicit private key file becomes the native
// Ed25519 seed plus SSH wire public key. No raw key value or path is asserted
// through an error message, only through the fixed refusal classes.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jihuayu/locklark/internal/vault"
)

func typedSSHFixtureSeed() []byte {
	return bytes.Repeat([]byte{0x2a}, ed25519.SeedSize)
}

func writeTypedSSHKeyFile(t *testing.T, private crypto.PrivateKey, passphrase []byte) string {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == nil {
		block, err = ssh.MarshalPrivateKey(private, "typed")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(private, "typed", passphrase)
	}
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_typed")
	writePrivateTypedFixture(t, path, pem.EncodeToMemory(block))
	return path
}

func TestResolveTypedSSHKeyCopiesSeedAndPublicKey(t *testing.T) {
	private := ed25519.NewKeyFromSeed(typedSSHFixtureSeed())
	path := writeTypedSSHKeyFile(t, private, nil)
	item := vault.Item{Kind: string(vault.CategorySSHKey), Category: vault.CategorySSHKey, Title: "key"}
	if err := resolveTypedSSHKey(&item, path); err != nil {
		t.Fatalf("resolve ed25519 key: %v", err)
	}
	defer clearTypedItem(&item)
	want, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if len(item.SSHSeed) != ed25519.SeedSize || !bytes.Equal(item.SSHSeed, typedSSHFixtureSeed()) {
		t.Fatalf("seed was not copied: %d bytes", len(item.SSHSeed))
	}
	if !bytes.Equal(item.SSHPublicKey, want.Marshal()) {
		t.Fatalf("ssh wire public key mismatch: %d bytes", len(item.SSHPublicKey))
	}
}

func mustMarshalTypedSSHKey(t *testing.T) *pem.Block {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(ed25519.NewKeyFromSeed(typedSSHFixtureSeed()), "typed")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return block
}

func TestResolveTypedSSHKeyRefusesUnsupportedAndEncrypted(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	malformed := filepath.Join(t.TempDir(), "malformed_key")
	writePrivateTypedFixture(t, malformed, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
	leading := filepath.Join(t.TempDir(), "leading_garbage_key")
	writePrivateTypedFixture(t, leading, append([]byte("junk before pem\n"), pem.EncodeToMemory(mustMarshalTypedSSHKey(t))...))
	cases := map[string]struct {
		path string
		want error
	}{
		"encrypted": {writeTypedSSHKeyFile(t, ed25519.NewKeyFromSeed(typedSSHFixtureSeed()), []byte("passphrase")), errTypedSSHEncrypted},
		"ecdsa":     {writeTypedSSHKeyFile(t, ecdsaKey, nil), errTypedSSHUnsupported},
		"malformed": {malformed, errTypedSSHUnsupported},
		"leading":   {leading, errTypedSSHUnsupported},
		"relative":  {"id_typed", errTypedInputRefused},
		"missing":   {filepath.Join(t.TempDir(), "absent_key"), errTypedInputRefused},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			item := vault.Item{Kind: string(vault.CategorySSHKey), Category: vault.CategorySSHKey, Title: "key"}
			err := resolveTypedSSHKey(&item, tc.path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected fixed refusal, got %v", err)
			}
			if len(item.SSHSeed) != 0 || len(item.SSHPublicKey) != 0 {
				t.Fatal("refusal left SSH material on the item")
			}
			if text := err.Error(); bytes.Contains([]byte(text), []byte(tc.path)) || bytes.Contains([]byte(text), []byte("AAAA")) {
				t.Fatalf("refusal echoed a path or key byte: %q", text)
			}
		})
	}
}

func TestResolveTypedSSHKeyRefusesWrongCategoryAndSecondMaterial(t *testing.T) {
	path := writeTypedSSHKeyFile(t, ed25519.NewKeyFromSeed(typedSSHFixtureSeed()), nil)
	for _, item := range []vault.Item{
		{Kind: string(vault.CategoryLogin), Category: vault.CategoryLogin, Title: "login"},
		{Kind: string(vault.CategorySSHKey), Category: vault.CategorySSHKey, Title: "key", SSHSeed: typedSSHFixtureSeed()},
	} {
		if err := resolveTypedSSHKey(&item, path); !errors.Is(err, errTypedInputRefused) {
			t.Fatalf("expected fixed refusal for %+v, got %v", item.Category, err)
		}
	}
}
