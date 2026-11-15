package account

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTwoSecretVector(t *testing.T) {
	id, salt, secret := make([]byte, 16), make([]byte, 16), make([]byte, 16)
	for i := range id {
		id[i] = byte(i)
		salt[i] = byte(i + 16)
		secret[i] = byte(i + 32)
	}
	auk, err := derive(" Démo ", secret, id, salt)
	if err != nil || hex.EncodeToString(auk) != "96dc4f96708480e58fdce70e234f81e33ed92a3162c2296db509ce8a5a36d348" {
		t.Fatalf("independent vector mismatch (%v)", err)
	}
}

func TestSlotNeedsBothInputs(t *testing.T) {
	secret := bytes.Repeat([]byte{3}, 16)
	id := bytes.Repeat([]byte{4}, 16)
	slot, err := Wrap("sample password", secret, id, []byte("synthetic device private key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		password string
		secret   []byte
	}{{"sample password", make([]byte, 16)}, {"different", secret}, {"sample password", nil}} {
		if _, err := Unwrap(tc.password, tc.secret, slot); err == nil {
			t.Fatal("incomplete inputs unwrapped device key")
		}
	}
	raw, err := Unwrap("sample password", secret, slot)
	if err != nil || string(raw) != "synthetic device private key" {
		t.Fatal("valid inputs failed", err)
	}
	slot.Ciphertext[0] ^= 1
	if _, err := Unwrap("sample password", secret, slot); err == nil {
		t.Fatal("tampered slot accepted")
	}
}
