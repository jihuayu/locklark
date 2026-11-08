//go:build !windows

package main

// Unix-only file-safety cases for the explicit ssh_private_key_file: a group or
// world readable file and a symlink are refused before the consent prompt. These
// run through the same owner-only descriptor reader as typed attachments.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateTypedPersonalSSHKeyRefusesUnsafeFileBeforeConsent(t *testing.T) {
	private := ed25519.NewKeyFromSeed(typedSSHFixtureSeed())
	readable := writeTypedSSHKeyFile(t, private, nil)
	if err := os.Chmod(readable, 0o644); err != nil {
		t.Fatalf("widen key file mode: %v", err)
	}
	target := writeTypedSSHKeyFile(t, private, nil)
	link := filepath.Join(t.TempDir(), "id_link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create key symlink: %v", err)
	}
	for name, keyPath := range map[string]string{"group-readable": readable, "symlink": link} {
		t.Run(name, func(t *testing.T) {
			vaultPath, inputPath, pw, key := typedCreateFixture(t, typedSSHCreateDocument(t, keyPath))
			asked := 0
			response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(string) ([]byte, error) {
				asked++
				return []byte("SAVE"), nil
			}, &bytes.Buffer{})
			if response != nil || !errors.Is(err, errTypedInputRefused) {
				t.Fatalf("unsafe key file was not refused: response=%+v err=%v", response, err)
			}
			if asked != 0 {
				t.Fatalf("unsafe key file reached the consent prompt %d times", asked)
			}
			if count := typedCreateActiveCount(t, vaultPath, pw, key); count != 0 {
				t.Fatalf("unsafe key file mutated the vault: %d items", count)
			}
		})
	}
}
