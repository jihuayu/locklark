package main

// Resolution of one explicit Ed25519 private-key file into the native ssh_key
// material. The decoder only records the explicit file path; this helper runs
// before the factors, the SAVE consent and the mutation, so a refusal happens
// before any prompt. It reads through the same bounded owner-private descriptor
// reader as typed attachments, accepts only an unencrypted Ed25519 private key
// whose 64 bytes are internally consistent, and copies the 32-byte seed plus
// the SSH wire public key into the item. Every refusal is a fixed error that
// never echoes the path, a key byte or a fingerprint.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"

	"github.com/jihuayu/locklark/internal/vault"
)

var (
	// errTypedSSHEncrypted refuses a passphrase-protected key; passphrase input
	// is not part of this command.
	errTypedSSHEncrypted = errors.New("typed SSH key is encrypted; passphrase input is not supported")
	// errTypedSSHUnsupported covers RSA/ECDSA, malformed files and an
	// inconsistent Ed25519 pair.
	errTypedSSHUnsupported = errors.New("typed SSH key must be an unencrypted Ed25519 private key")
)

// maxTypedSSHPrivateKeyBytes matches the small native SSH import bound.
const maxTypedSSHPrivateKeyBytes = 32 << 10

func resolveTypedSSHKey(item *vault.Item, file string) error {
	if item == nil {
		return errTypedInputRefused
	}
	if file == "" {
		if item.Category == vault.CategorySSHKey || item.SSHSeed != nil || item.SSHPublicKey != nil {
			return errTypedInputRefused
		}
		return nil
	}
	if item.Category != vault.CategorySSHKey || item.Kind != string(vault.CategorySSHKey) || item.SSHSeed != nil || item.SSHPublicKey != nil || !validTypedAttachmentPath(file) {
		return errTypedInputRefused
	}
	raw, err := readPrivateTypedFile(file, maxTypedSSHPrivateKeyBytes)
	if err != nil {
		return err
	}
	defer clear(raw)
	// Exactly one leading PEM block and no trailing content: ssh.ParseRawPrivateKey
	// itself ignores both leading garbage and trailing bytes.
	block, rest := pem.Decode(raw)
	trimmed := bytes.TrimSpace(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(trimmed, []byte("-----BEGIN "+block.Type+"-----")) {
		return errTypedSSHUnsupported
	}
	defer clear(block.Bytes)
	parsed, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return errTypedSSHEncrypted
		}
		return errTypedSSHUnsupported
	}
	var private ed25519.PrivateKey
	switch key := parsed.(type) {
	case *ed25519.PrivateKey:
		defer clear(*key)
		private = *key
	case ed25519.PrivateKey:
		defer clear(key)
		private = key
	default:
		return errTypedSSHUnsupported
	}
	if len(private) != ed25519.PrivateKeySize {
		return errTypedSSHUnsupported
	}
	canonical := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	defer clear(canonical)
	if !bytes.Equal(canonical, private) {
		return errTypedSSHUnsupported
	}
	public, err := ssh.NewPublicKey(canonical.Public())
	if err != nil {
		return errTypedSSHUnsupported
	}
	item.SSHSeed = bytes.Clone(private[:ed25519.SeedSize])
	item.SSHPublicKey = public.Marshal()
	return nil
}
