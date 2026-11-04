package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"filippo.io/age"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"testing"
)

// The attacker is handed the actual new KDBX, the envelope, their old private
// identity and the recovered old file key. No registry or API is consulted.
func TestOfflineRevocation(t *testing.T) {
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	first, err := Seal([]byte("old fixture"), 1, []*age.X25519Recipient{a.Recipient(), b.Recipient()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*age.X25519Identity{a, b} {
		p, err := Open(first, id, pub, 1)
		if err != nil || string(p) != "old fixture" {
			t.Fatalf("first: %q %v", p, err)
		}
	}
	oldKey, err := unwrap(first.Envelope, a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal([]byte("new fixture"), 2, []*age.X25519Recipient{b.Recipient()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(second, a, pub, 2); err == nil {
		t.Fatal("revoked identity opened new snapshot")
	}
	if _, err := age.Decrypt(bytes.NewReader(second.Envelope), a); err == nil {
		t.Fatal("revoked key directly unwrapped new envelope")
	}
	// Independently try the old raw key with the upstream KDBX decoder.
	db := kdbx.NewDatabase()
	db.Credentials, err = kdbx.NewKeyDataCredentials(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = kdbx.NewDecoder(bytes.NewReader(second.Database)).Decode(db); err == nil {
		t.Fatal("old file key decrypted new KDBX")
	}
	if p, err := Open(second, b, pub, 2); err != nil || string(p) != "new fixture" {
		t.Fatalf("survivor: %q %v", p, err)
	}
	if _, err := Open(first, b, pub, 2); err == nil {
		t.Fatal("old epoch accepted")
	}
	second.Database[len(second.Database)-1] ^= 1
	if _, err := Open(second, b, pub, 2); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
}
