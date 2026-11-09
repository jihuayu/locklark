// Package passkeytransfer implements the native-only, explicitly authorized
// Passkey migration codec for #52 (invitation, signed packet, encrypted
// selection payload).
//
// The codec uses only the existing filippo.io/age X25519 encryption and
// Ed25519 audit signing. It never reads user files, never opens a private key
// itself, never performs network I/O, and never generates new user
// identities. Callers supply an existing age recipient/identity and audit
// seed. Invitation self-signatures prove integrity only; both peers must pin
// the other side's public fingerprint out of band. Pins are mandatory and
// have no default.
//
// This package does not provide one-use/replay prevention, persistence,
// journal/audit writes, browser surfaces or CLI wiring. Those belong to the
// personal-session stage and the existing mutation gates.
//
// Serializable values are generated in a strict canonical JSON form. Decoders
// reject unknown fields, trailing data, duplicate keys, invalid UTF-8,
// non-canonical base64/hex and any byte-level re-encoding difference. Do not
// hand-edit this JSON.
//
// Decrypted records and plaintext buffers are zeroed on a best-effort basis
// (builtin clear) before being dropped. Go strings and runtime/internal copies
// are immutable and cannot be zeroed, so this is not a guarantee against a
// process memory disclosure; the encrypted payload remains the only durable
// representation.
package passkeytransfer
