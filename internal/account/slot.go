// Package account is a synthetic-only Locklark 2SKD profile. The device slot
// is never part of a shared snapshot. It is not a 1Password wire format.
package account

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type Slot struct {
	Version    int    `json:"version"`
	Account    []byte `json:"account_id"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}

var errSlot = errors.New("invalid local device slot or unlock factors")

func derive(password string, secret, id, salt []byte) ([]byte, error) {
	if !utf8.ValidString(password) || len(password) > 1024 || len(secret) != 16 || len(id) != 16 || len(salt) != 16 {
		return nil, errSlot
	}
	password = strings.TrimSpace(norm.NFKD.String(password))
	if password == "" {
		return nil, errSlot
	}
	ps, err := hkdf.Key(sha256.New, salt, id, "locklark/m0/password-salt", 32)
	if err != nil {
		return nil, err
	}
	p, err := pbkdf2.Key(sha256.New, password, ps, 650000, 32)
	if err != nil {
		return nil, err
	}
	s, err := hkdf.Key(sha256.New, secret, id, "locklark/m0/secret-key", 32)
	if err != nil {
		clear(p)
		return nil, err
	}
	defer clear(s)
	for i := range p {
		p[i] ^= s[i]
	}
	return p, nil
}
func aead(password string, secret []byte, s Slot) (cipher.AEAD, error) {
	if s.Version != 1 {
		return nil, errSlot
	}
	key, err := derive(password, secret, s.Account, s.Salt)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

const domain = "locklark/m0/device-slot/v1"

func Wrap(password string, secret, id, data []byte) (Slot, error) {
	s := Slot{Version: 1, Account: append([]byte(nil), id...), Salt: make([]byte, 16)}
	if _, err := rand.Read(s.Salt); err != nil {
		return Slot{}, err
	}
	a, err := aead(password, secret, s)
	if err != nil {
		return Slot{}, err
	}
	s.Ciphertext = a.Seal(nil, nil, data, []byte(domain))
	return s, nil
}
func Unwrap(password string, secret []byte, s Slot) ([]byte, error) {
	a, err := aead(password, secret, s)
	if err != nil {
		return nil, errSlot
	}
	if len(s.Ciphertext) < a.Overhead() || len(s.Ciphertext) > 4096 {
		return nil, errSlot
	}
	p, err := a.Open(nil, nil, s.Ciphertext, []byte(domain))
	if err != nil {
		return nil, errSlot
	}
	return p, nil
}
