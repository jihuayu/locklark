package vaultfile

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"filippo.io/age"
)

// Per-device VUK wrapping (vuk_device_slots).
//
// A per-library, per-epoch VUK is 32 random bytes (CEKSize) chosen by the
// caller. Each approved device carries one age X25519 envelope for it in one
// DeviceSlot.WrappedVUK:
//
//	wrapped_vuk = standard age file, one X25519 recipient only
//	plaintext   = DomainVUKDeviceWrapping || 0x00 || context || VUK
//	context     = u16be(len(vaultID))   || vaultID
//	            || u64be(keyEpoch)
//	            || u16be(len(deviceID))  || deviceID
//	VUK         = 32 bytes
//
// The purpose label and its single NUL separator are the first bytes of the
// plaintext, so they are authenticated by age: age has no associated-data
// parameter, and the domain prefix and context are checked after the envelope
// opens. The two length fields are big-endian uint16 and the IDs must pass
// validID with MaxIDLength (64) and MaxDeviceIDLength (128), so they fit. The
// epoch is a positive uint64 in the wire key_epoch domain.
//
// The context binds vault, epoch and device, and nothing else. It does not
// contain a content sequence or op id: one device slot is reused by every
// content snapshot in the same epoch, and a new epoch requires a new wrap.
// The wrapping contains exactly one X25519 recipient and one identity; no
// custom crypto, key derivation or recipient chaining is involved.
//
// Trust boundary: the expected vault id, epoch and device id, and the
// expected recipient, are independent caller inputs. The recipient must come
// from an already authenticated policy. DeviceSlot.DeviceID and
// DeviceSlot.Recipient are never the trust source: on open they must equal
// the caller's expectations, and the expected recipient must also equal the
// identity's own recipient.
//
// This file implements the VUK envelope only. It does not generate, load or
// rotate the VUK or key epoch, does not scope CEK epoch rotation, does not
// authenticate a policy itself and does not open KDBX content or a full file.
// OpenAuthenticatedFile is the caller-pinned full-file open path that
// authenticates the current policy before calling this primitive. See
// docs/vaultfile-wire-v1.md.

// CodeVUKEnvelopeFailed is reported by OpenVUKForDevice for every envelope
// or context failure: a slot that names another device or recipient, a wrong
// identity or caller expectation, a malformed, empty, oversized or tampered
// envelope, appended bytes, a decrypted context that does not match, or a
// plaintext of the wrong length. It is one code for all of them so a caller
// cannot distinguish a wrong recipient from a wrong context or tampering.
const CodeVUKEnvelopeFailed = "vuk_envelope_failed"

// vukDomainPrefix is the purpose label followed by exactly one NUL, as used
// by DomainSeparated. It is the first plaintext bytes before the context.
var vukDomainPrefix = append([]byte(DomainVUKDeviceWrapping), 0)

// errVUKNilWriter reports age.Encrypt returning a nil writer with a nil error.
// age v1.3.2 does not document when that can happen, and does not report a
// crypto/rand failure that way, so this guards an unexpected contract
// violation rather than a known failure mode.
var errVUKNilWriter = errors.New("vaultfile: age.Encrypt returned a nil writer with no error")

// SealVUKForDevice wraps the 32-byte VUK vuk to one device in an age X25519
// envelope and returns the DeviceSlot carrying it.
//
// vuk must be exactly CEKSize bytes; vaultID must pass validID with
// MaxIDLength; keyEpoch must be positive; deviceID must pass validID with
// MaxDeviceIDLength; recipient must be a canonical age X25519 recipient
// (age.ParseX25519Recipient plus the recipient's own canonical string form).
// The returned slot has DeviceID and Recipient exactly as given.
//
// The caller's VUK input buffer is not retained after the call, but the
// returned DeviceSlot contains DeviceID and Recipient exactly as given. The
// package-owned envelope plaintext (VUK included) is cleared on every
// path, success and failure. age.Encrypt keeps its own unexported copy of the
// plaintext until Close and exposes no way to clear it.
//
// Errors:
//   - a vuk that is not exactly CEKSize bytes is an invalid_value at "";
//   - an invalid vaultID, keyEpoch or deviceID is an invalid_value at
//     "vault_id", "key_epoch" or "device_id";
//   - an invalid recipient is an invalid_value at "recipient";
//   - any age error (for example a short write to the output) is returned as
//     is, not as an *Error or a validation code;
//   - an age.Encrypt nil writer with a nil error is an explicit operational
//     error, never a nil error with a zero slot. age v1.3.2 does not report a
//     crypto/rand failure that way, so this only guards an unexpected
//     contract violation.
//
// On any error slot is the zero DeviceSlot and the error is non-nil.
func SealVUKForDevice(vuk []byte, vaultID string, keyEpoch uint64, deviceID, recipient string) (DeviceSlot, error) {
	if len(vuk) != CEKSize {
		return DeviceSlot{}, Err("", CodeInvalidValue)
	}
	plain, err := vukPlaintext(vuk, vaultID, keyEpoch, deviceID)
	if err != nil {
		return DeviceSlot{}, err
	}
	defer clear(plain)
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil || r.String() != recipient {
		return DeviceSlot{}, Err("recipient", CodeInvalidValue)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return DeviceSlot{}, err
	}
	if w == nil {
		return DeviceSlot{}, errVUKNilWriter
	}
	if _, err := w.Write(plain); err != nil {
		return DeviceSlot{}, err
	}
	if err := w.Close(); err != nil {
		return DeviceSlot{}, err
	}
	if buf.Len() > MaxWrappedKeyLength {
		// Not reachable at valid ID limits: the largest plaintext is
		// 42 + 1 + (2 + 64 + 8 + 2 + 128) + 32 = 279 bytes, one age chunk,
		// but the wire limit is never exceeded.
		return DeviceSlot{}, Err("wrapped_vuk", CodeInvalidValue)
	}
	return DeviceSlot{DeviceID: deviceID, Recipient: recipient, WrappedVUK: buf.Bytes()}, nil
}

// OpenVUKForDevice unwraps the VUK carried in slot with identity and returns
// the 32-byte VUK.
//
// expectedVaultID, expectedKeyEpoch, expectedDeviceID and expectedRecipient
// are independent trusted caller inputs; expectedRecipient must come from an
// already authenticated policy and is never taken from slot.Recipient or
// derived from the slot. The call requires slot.DeviceID == expectedDeviceID,
// slot.Recipient == expectedRecipient and expectedRecipient ==
// identity.Recipient().String(), then opens the one-recipient age envelope and
// checks the decrypted domain prefix and full context against all expected
// values with a constant-time comparison.
//
// Ciphertext handling is bounded: slot.WrappedVUK must be non-empty and at
// most MaxWrappedKeyLength before any decryption; age.DecryptReaderAt gets
// exactly that length; the decrypted size must equal the exact expected
// context and VUK length and exactly that many bytes are read. Appended
// trailing ciphertext fails the age final-chunk authentication.
//
// The returned vuk is caller-owned and must be cleared after use by the
// caller. On any error the returned VUK is nil, and both package-owned
// buffers, the plaintext read here (VUK included) and the expected-context
// buffer, are cleared on every path.
//
// Limitation: age.DecryptReaderAt authenticates and decrypts the final chunk
// inside its cached reader and retains that plaintext in an unexported cache
// for the life of the reader, with no clear method. This package cannot clear
// that internal age copy; the guarantee above covers only the buffers this
// package owns.
//
// Errors:
//   - an invalid expected vault id, epoch, device id or recipient, or a nil
//     identity, is an invalid_value at "vault_id", "key_epoch", "device_id",
//     "recipient" or "identity", returned before any slot field or
//     ciphertext is considered;
//   - every envelope or context failure is an *Error with Code
//     CodeVUKEnvelopeFailed at "vuk_device_slot", and does not distinguish a
//     wrong recipient from a wrong context or tampering.
func OpenVUKForDevice(slot DeviceSlot, expectedVaultID string, expectedKeyEpoch uint64, expectedDeviceID, expectedRecipient string, identity *age.X25519Identity) ([]byte, error) {
	if err := validateVUKContext(expectedVaultID, expectedKeyEpoch, expectedDeviceID); err != nil {
		return nil, err
	}
	if !validAgeX25519Recipient(expectedRecipient) {
		return nil, Err("recipient", CodeInvalidValue)
	}
	if identity == nil {
		return nil, Err("identity", CodeInvalidValue)
	}
	if slot.DeviceID != expectedDeviceID || slot.Recipient != expectedRecipient ||
		identity.Recipient().String() != expectedRecipient {
		return nil, Err("vuk_device_slot", CodeVUKEnvelopeFailed)
	}
	if len(slot.WrappedVUK) == 0 || len(slot.WrappedVUK) > MaxWrappedKeyLength {
		return nil, Err("vuk_device_slot", CodeVUKEnvelopeFailed)
	}
	// want is the expected authenticated prefix, DomainVUKDeviceWrapping ||
	// 0x00 || context, followed by CEKSize placeholders; plainLen is the exact
	// expected plaintext size. The comparison below never reads the
	// placeholders.
	want := vukPlaintextFromPrefix(expectedVaultID, expectedKeyEpoch, expectedDeviceID)
	plainLen := len(want)
	prefixLen := plainLen - CEKSize
	plain := make([]byte, plainLen)
	r, n, err := age.DecryptReaderAt(bytes.NewReader(slot.WrappedVUK), int64(len(slot.WrappedVUK)), identity)
	if err != nil || n != int64(plainLen) {
		clear(plain)
		clear(want)
		return nil, Err("vuk_device_slot", CodeVUKEnvelopeFailed)
	}
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, n), plain); err != nil {
		clear(plain)
		clear(want)
		return nil, Err("vuk_device_slot", CodeVUKEnvelopeFailed)
	}
	match := subtle.ConstantTimeCompare(plain[:prefixLen], want[:prefixLen])
	// Copy the VUK out only on a full match, then clear the plaintext buffer,
	// VUK included, and the expected-context buffer. Both package-owned
	// buffers are cleared on every path. age's own final-chunk plaintext cache
	// lives inside r and cannot be cleared through its public API.
	var vuk []byte
	if match == 1 {
		vuk = make([]byte, CEKSize)
		copy(vuk, plain[prefixLen:])
	}
	clear(plain)
	clear(want)
	if match != 1 {
		return nil, Err("vuk_device_slot", CodeVUKEnvelopeFailed)
	}
	return vuk, nil
}

// vukPlaintext returns the age plaintext of one VUK wrap:
// DomainVUKDeviceWrapping || 0x00 || context || vuk. The caller clears it.
func vukPlaintext(vuk []byte, vaultID string, keyEpoch uint64, deviceID string) ([]byte, error) {
	if err := validateVUKContext(vaultID, keyEpoch, deviceID); err != nil {
		return nil, err
	}
	plain := vukPlaintextFromPrefix(vaultID, keyEpoch, deviceID)
	copy(plain[len(plain)-CEKSize:], vuk)
	return plain, nil
}

// vukPlaintextFromPrefix returns the expected age plaintext shape for the
// given context: DomainVUKDeviceWrapping || 0x00 || context, followed by
// CEKSize zero placeholders, so its length is the exact expected plaintext
// size. The caller must pass validated IDs and a positive epoch and clears
// the returned bytes.
func vukPlaintextFromPrefix(vaultID string, keyEpoch uint64, deviceID string) []byte {
	b := make([]byte, 0, len(vukDomainPrefix)+2+len(vaultID)+8+2+len(deviceID)+CEKSize)
	b = append(b, vukDomainPrefix...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(vaultID)))
	b = append(b, vaultID...)
	b = binary.BigEndian.AppendUint64(b, keyEpoch)
	b = binary.BigEndian.AppendUint16(b, uint16(len(deviceID)))
	b = append(b, deviceID...)
	return append(b, make([]byte, CEKSize)...)
}

// validateVUKContext checks the caller's expected vault id, epoch and device
// id without allocating.
func validateVUKContext(vaultID string, keyEpoch uint64, deviceID string) error {
	if !validID(vaultID, MaxIDLength) {
		return Err("vault_id", CodeInvalidValue)
	}
	if keyEpoch == 0 {
		return Err("key_epoch", CodeInvalidValue)
	}
	if !validID(deviceID, MaxDeviceIDLength) {
		return Err("device_id", CodeInvalidValue)
	}
	return nil
}

// vukContext returns the exact context payload without the purpose label:
//
//	u16be(len(vaultID)) || vaultID || u64be(keyEpoch)
//	|| u16be(len(deviceID)) || deviceID
//
// The caller clears the returned bytes.
func vukContext(vaultID string, keyEpoch uint64, deviceID string) ([]byte, error) {
	if err := validateVUKContext(vaultID, keyEpoch, deviceID); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 2+len(vaultID)+8+2+len(deviceID))
	b = binary.BigEndian.AppendUint16(b, uint16(len(vaultID)))
	b = append(b, vaultID...)
	b = binary.BigEndian.AppendUint64(b, keyEpoch)
	b = binary.BigEndian.AppendUint16(b, uint16(len(deviceID)))
	return append(b, deviceID...), nil
}
