package vaultfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Per-snapshot content key (CEK) wrapping under the epoch vault key (VUK).
//
// Every content snapshot gets one fresh random 32-byte CEK, used as the KDBX
// key credential for the content ciphertext. The CEK is carried on the wire
// only wrapped by the 32-byte VUK of Header.KeyEpoch:
//
//	wrapped_cek = nonce_prefix(12) || ciphertext(32) || tag(16)   // 60 bytes
//	aead        = AES-256-GCM from cipher.NewGCMWithRandomNonce(VUK)
//	aead.Seal(nil, nil, CEK, aad) produces nonce-prefix || ciphertext || tag
//	aad         = DomainCEKWrapping || 0x00 || canonical_header_without_revision_id
//
// The AEAD comes from crypto/cipher.NewGCMWithRandomNonce, so Seal is called
// as aead.Seal(nil, nil, CEK, aad): the AEAD generates the nonce itself and
// prepends the 12-byte nonce prefix to the standard Seal output, which is
// already the 32-byte CEK ciphertext followed by the 16-byte tag. wrapped_cek
// is therefore exactly 60 bytes and carries no second tag. The canonical
// header without revision_id is the schema-order encoding
// writeHeaderWithoutRevision produces: the same member set and order as Header
// on the wire, with the derived member revision_id absent entirely.
//
// revision_id is excluded on purpose. RevisionID hashes the file including
// wrapped_cek, so binding the derived id here would make sealing circular.
// The final content signature still binds the final revision id and the
// complete file.
//
// This file implements the CEK envelope only. It does not generate, load or
// wrap the VUK for devices (age VUK device wrapping), does not serialize,
// encrypt or open KDBX content, and has no trusted full-file open path. See
// docs/vaultfile-wire-v1.md.

const (
	// CEKSize is the length in bytes of a content key, of the epoch VUK and of
	// the plaintext wrapped in one CEK slot.
	CEKSize = 32

	// AEAD parameters fixed by the specified API (AES-256-GCM with a random
	// nonce prefix). NewGCMWithRandomNonce reports Overhead as nonce+tag and
	// prepends the random 96-bit nonce to Seal's output.
	cekAEADNonceSize = 12
	cekAEADTagSize   = 16

	// WrappedCEKSize is the exact length of a valid CEKSlot.WrappedCEK:
	// nonce prefix, CEK ciphertext and tag (60 bytes).
	WrappedCEKSize = cekAEADNonceSize + CEKSize + cekAEADTagSize
)

// CodeCEKEnvelopeFailed is reported by OpenCEK for every cryptographic
// envelope failure: a slot whose KeyEpoch differs from the header, malformed
// wrapped bytes, a wrong VUK, or an authentication/tamper failure. It is one
// code for all of them so a caller cannot distinguish a wrong key from
// corrupted ciphertext.
const CodeCEKEnvelopeFailed = "cek_envelope_failed"

// SealCEK generates a fresh random 32-byte CEK, wraps it under the epoch VUK
// vuk and returns the CEK and the CEKSlot carrying the wrapped value.
//
// The returned cek is caller-owned: use it as the KDBX key credential, then
// clear it once the KDBX content has been encrypted. This function and
// OpenCEK do not retain any caller buffer (vuk, header, or a returned cek)
// after they return; the caller keeps its buffers stable while the call runs.
// The returned slot has KeyEpoch equal to header.KeyEpoch and a
// WrappedCEK of exactly WrappedCEKSize (60) bytes.
//
// header must be a valid Header (ValidateHeader) with a positive KeyEpoch;
// vuk must be exactly CEKSize bytes. The header may carry no revision id
// (a builder draft header) or a sealed one: revision_id is not bound by the
// wrapping, so the CEK can be sealed before the revision id is derived. The
// AAD binds every other Header field.
//
// Key usage limit: with NewGCMWithRandomNonce, a given VUK must not encrypt
// more than 2^32 (2**32) times; beyond that, nonce collisions and forgery
// risks are no longer negligible (see the crypto/cipher documentation). Each
// SealCEK call performs exactly one such encryption with vuk. This API is
// stateless and cannot track per-key usage, so the caller must count SealCEK
// calls per VUK and rotate to a new VUK and key epoch before any VUK reaches
// 2^32 encryptions.
//
// Errors:
//   - an invalid header is returned from ValidateHeader unchanged, and a zero
//     KeyEpoch is an invalid_value at key_epoch;
//   - a vuk that is not exactly CEKSize bytes is an invalid_value at "";
//   - a failure of crypto/rand is returned as the underlying operational
//     error, not as an *Error or a structural/validation code.
//
// On any error cek is nil and slot is the zero CEKSlot. If the call fails
// after the CEK buffer was generated (a crypto/rand failure), that buffer is
// cleared before returning.
func SealCEK(vuk []byte, header Header) (cek []byte, slot CEKSlot, err error) {
	if err := ValidateHeader(&header); err != nil {
		return nil, CEKSlot{}, err
	}
	if header.KeyEpoch == 0 {
		return nil, CEKSlot{}, Err("key_epoch", CodeInvalidValue)
	}
	if len(vuk) != CEKSize {
		return nil, CEKSlot{}, Err("", CodeInvalidValue)
	}
	aad, err := cekWrappingAAD(&header)
	if err != nil {
		return nil, CEKSlot{}, err
	}
	aead, err := newCEKAead(vuk)
	if err != nil {
		return nil, CEKSlot{}, Err("", CodeInvalidValue)
	}
	plain := make([]byte, CEKSize)
	if _, err := rand.Read(plain); err != nil {
		clear(plain)
		return nil, CEKSlot{}, err
	}
	wrapped := aead.Seal(nil, nil, plain, aad)
	return plain, CEKSlot{KeyEpoch: header.KeyEpoch, WrappedCEK: wrapped}, nil
}

// OpenCEK unwraps the CEK carried in slot with the epoch VUK vuk and returns
// it.
//
// The returned cek is caller-owned and must be cleared after KDBX use; this
// function retains no caller buffer after it returns. header may be a builder
// draft without a revision id or a sealed header; revision_id is not bound.
//
// Errors:
//   - an invalid header is returned from ValidateHeader unchanged, and a zero
//     KeyEpoch is an invalid_value at key_epoch;
//   - a vuk that is not exactly CEKSize bytes is an invalid_value at "";
//   - every envelope failure is an *Error with Code CodeCEKEnvelopeFailed at
//     "cek_slot": slot.KeyEpoch different from header.KeyEpoch, a WrappedCEK
//     that is nil, empty or not exactly WrappedCEKSize bytes (or above
//     MaxWrappedKeyLength), a wrong vuk, or any authentication/tamper failure.
//
// On any error cek is nil. Any plaintext produced before the failure is
// cleared before returning.
func OpenCEK(vuk []byte, header Header, slot CEKSlot) ([]byte, error) {
	if err := ValidateHeader(&header); err != nil {
		return nil, err
	}
	if header.KeyEpoch == 0 {
		return nil, Err("key_epoch", CodeInvalidValue)
	}
	if len(vuk) != CEKSize {
		return nil, Err("", CodeInvalidValue)
	}
	if slot.KeyEpoch != header.KeyEpoch ||
		len(slot.WrappedCEK) != WrappedCEKSize ||
		len(slot.WrappedCEK) > MaxWrappedKeyLength {
		return nil, Err("cek_slot", CodeCEKEnvelopeFailed)
	}
	aad, err := cekWrappingAAD(&header)
	if err != nil {
		return nil, err
	}
	aead, err := newCEKAead(vuk)
	if err != nil {
		return nil, Err("cek_slot", CodeCEKEnvelopeFailed)
	}
	cek, err := aead.Open(nil, nil, slot.WrappedCEK, aad)
	if err != nil || len(cek) != CEKSize {
		clear(cek)
		return nil, Err("cek_slot", CodeCEKEnvelopeFailed)
	}
	return cek, nil
}

// cekWrappingAAD returns the exact authenticated data of one CEK wrap:
// DomainCEKWrapping || 0x00 || canonical header without revision_id.
func cekWrappingAAD(header *Header) ([]byte, error) {
	var b bytes.Buffer
	writeHeaderWithoutRevision(&b, header)
	return append(append([]byte(DomainCEKWrapping), 0), b.Bytes()...), nil
}

// newCEKAead returns the AES-256-GCM AEAD over k. It never returns a nil
// error with a nil AEAD; every failure is a caller argument error.
func newCEKAead(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}
