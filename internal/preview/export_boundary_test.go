package preview

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// Even a validly signed, decryptable epoch must not turn the fixture command
// into an arbitrary plaintext export. The decision is about exact contents.
func TestExportRejectsUnknownSignedArchive(t *testing.T) {
	root := t.TempDir()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	client, bundle := filepath.Join(root, "client"), filepath.Join(root, "bundle")
	if err = saveDevice(client, device, pub, make([]byte, 16), make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	unknown, err := packFixture(append([]byte(" "), exportData...))
	if err != nil {
		t.Fatal(err)
	}
	if err = saveEpoch(bundle, payload{Archive: unknown}, 3, []*age.X25519Recipient{device.Recipient()}, key); err != nil {
		t.Fatal(err)
	}
	if _, err = Inspect(bundle, client, 3); err != nil {
		t.Fatal("control: signed synthetic ZIP should be readable", err)
	}
	out := filepath.Join(root, "refused.1pux")
	if err = ExportFixture(bundle, client, 3, out); err != errFixture {
		t.Fatal("expected archive allowlist rejection", err)
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("refused export left plaintext output")
	}
}
