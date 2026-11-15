package personal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
)

func TestVaultFileDevicePublicFullFactorSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "personal.ll")
	password := []byte("owned-full-factor-password")
	secret := bytes.Repeat([]byte{0x5a}, 16)
	if err := Create(path, string(password), secret); err != nil {
		t.Fatal("CREATE_FAILED")
	}
	open := func() *Session {
		t.Helper()
		s, err := UnlockSession(path, password, secret, time.Minute)
		if err != nil {
			t.Fatal("FULL_UNLOCK_FAILED")
		}
		return s
	}
	s := open()
	public, err := s.VaultFileDevicePublic()
	if err != nil {
		t.Fatal("PUBLIC_ENROLLMENT_FAILED")
	}
	if _, err := age.ParseX25519Recipient(public.AgeRecipient); err != nil {
		t.Fatal("INVALID_AGE_RECIPIENT")
	}
	key, err := hex.DecodeString(public.ContentSigningPublicKey)
	if err != nil || len(key) != 32 || hex.EncodeToString(key) != public.ContentSigningPublicKey {
		t.Fatal("INVALID_CONTENT_SIGNING_PUBLIC_KEY")
	}
	s.Lock()
	if result, err := s.VaultFileDevicePublic(); !errors.Is(err, ErrSessionLocked) || result != (VaultFileDevicePublic{}) {
		t.Fatal("LOCKED_SESSION_DISCLOSED_PUBLIC_IDENTITY")
	}
	s = open()
	defer s.Lock()
	again, err := s.VaultFileDevicePublic()
	if err != nil || again != public {
		t.Fatal("FULL_UNLOCK_PUBLIC_IDENTITY_CHANGED")
	}
	s.mu.Lock()
	s.fullUnlock = time.Time{} // Model an OS quick-unlock session.
	s.mu.Unlock()
	if result, err := s.VaultFileDevicePublic(); !errors.Is(err, ErrVaultFileFullFactorRequired) || result != (VaultFileDevicePublic{}) {
		t.Fatal("QUICK_UNLOCK_DISCLOSED_PUBLIC_IDENTITY")
	}
	s.mu.Lock()
	s.fullUnlock = time.Now().Add(-passkeyTransferFullFactorWindow)
	s.mu.Unlock()
	if result, err := s.VaultFileDevicePublic(); !errors.Is(err, ErrVaultFileFullFactorRequired) || result != (VaultFileDevicePublic{}) {
		t.Fatal("EXPIRED_FULL_FACTOR_DISCLOSED_PUBLIC_IDENTITY")
	}
}
