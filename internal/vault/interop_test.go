package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// The independent implementation receives only a fresh synthetic key via stdin.
// No product command or on-disk keyfile is introduced for this test.
func TestKDBXIndependentPeer(t *testing.T) {
	python := os.Getenv("LOCKLARK_TEST_PYKEEPASS")
	if python == "" {
		t.Skip("set LOCKLARK_TEST_PYKEEPASS to a Python interpreter with pykeepass==4.2.0")
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Seal([]byte("original fixture"), 1, []*age.X25519Recipient{id.Recipient()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := unwrap(s.Envelope, id)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	dir := t.TempDir()
	source, current, legacy := filepath.Join(dir, "source.kdbx"), filepath.Join(dir, "current.kdbx"), filepath.Join(dir, "legacy.kdbx")
	if err := os.WriteFile(source, s.Database, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-I", "testdata/kdbx_peer.py", source, current, legacy)
	cmd.Stdin = bytes.NewReader(key)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("peer: %v: %s", err, out)
	}
	for _, name := range []string{current, legacy} {
		edited := s
		edited.Database, err = os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Open(edited, id, pub, 1); err == nil {
			t.Fatal("unsigned external edit accepted")
		}
		// Only the fixture's authority can adopt and sign the changed bytes.
		edited.Signature = ed25519.Sign(signer, edited.signed())
		got, err := Open(edited, id, pub, 1)
		if err != nil || string(got) != "edited by independent peer" {
			t.Fatalf("%s: peer edit not recovered: %v", filepath.Base(name), err)
		}
	}
}
