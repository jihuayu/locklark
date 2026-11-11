package vaultfile

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// KDBX payload sealing and opening under the per-snapshot CEK.
//
// SealKDBXPayload encrypts one KDBX 4.1 database with the 32-byte CEK of a
// content snapshot; OpenKDBXPayload decrypts such a payload back into a
// kdbx.Database. Both use the vendored gokeepasslib encoder and bounded
// decoder, its header parser, header-hash/HMAC checks and KDF guard, and no
// custom cryptography. The package imports only that library, never an
// internal package.
//
// These are low-level payload APIs, not a trusted full-file open. They open
// KDBX ciphertext only: they do not inspect or accept a proposal's own roster
// as trust, do not verify policy proofs, do not check a caller-pinned owner
// root, revision or signature chain, and do not authenticate that the payload
// belongs to any particular file or revision. A trusted full-file open, which
// pins caller state and verifies the policy checkpoint before VUK/CEK
// decryption, is a later checkpoint. See docs/vaultfile-wire-v1.md.

// Error codes reported by SealKDBXPayload and OpenKDBXPayload. Like every
// *Error in this package, the message never embeds input data or key bytes.
const (
	// CodeKDBXPayloadInvalid is reported for every rejected input or KDBX
	// failure: a nil or malformed database, a header that is not KDBX 4.1, a
	// CEK of the wrong length, a wrong CEK, tampered or malformed KDBX bytes,
	// an unsupported KDF or a block authentication failure. It is one code
	// for all of them so a caller cannot distinguish a wrong key from
	// corrupted content.
	CodeKDBXPayloadInvalid = "kdbx_payload_invalid"
	// CodeKDBXPayloadTooLarge is reported when the input or the encoded
	// output exceeds MaxKDBXCiphertextBytes, a sealed plaintext body (the
	// KDBX4 InnerHeader plus XML, before compression) exceeds
	// MaxPlaintextBytes, or a decoded or gzip-expanded body or the aggregate
	// inner-header binaries exceed MaxPlaintextBytes.
	CodeKDBXPayloadTooLarge = "kdbx_payload_too_large"
)

// errKDBXPayloadInvalid and errKDBXPayloadTooLarge return fresh *Error
// values. Error.Code and Error.Path are exported and caller-mutable, so no
// *Error value is ever shared between calls.
func errKDBXPayloadInvalid() error  { return &Error{Code: CodeKDBXPayloadInvalid} }
func errKDBXPayloadTooLarge() error { return &Error{Code: CodeKDBXPayloadTooLarge} }

// Locklark snapshot KDBX 4.1 profile fixed by SealKDBXPayload: Argon2id,
// KDF version 0x13, 16 MiB memory, 3 iterations, parallelism 2, no secret key
// and no associated data.
const (
	kdbxProfileKDFVersion  = 0x13
	kdbxProfileMemory      = 16 << 20
	kdbxProfileIterations  = 3
	kdbxProfileParallelism = 2
)

// kdbxPayloadLimits is the bounded decode configuration of OpenKDBXPayload:
// MaxKDBXCiphertextBytes for the whole KDBX input and MaxPlaintextBytes for
// the expanded content and for the aggregate KDBX4 inner-header binaries.
func kdbxPayloadLimits() kdbx.DecodeLimits {
	return kdbx.DecodeLimits{
		MaxEncodedBytes:   MaxKDBXCiphertextBytes,
		MaxPlaintextBytes: MaxPlaintextBytes,
	}
}

// isKDBX41 reports whether data starts with the exact KDBX 4.1 signature.
func isKDBX41(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	sig := kdbx.Signature{
		BaseSignature:      [4]byte(data[0:4]),
		SecondarySignature: [4]byte(data[4:8]),
		MinorVersion:       binary.LittleEndian.Uint16(data[8:10]),
		MajorVersion:       binary.LittleEndian.Uint16(data[10:12]),
	}
	return sig == kdbx.DefaultKDBX41Sig
}

// kdbxCipherIVLength reports the exact content-encryption IV length of a
// cipher ID the vendored KDBX4 encoder supports, or false for any other ID.
// AES and Twofish run in CBC mode, whose setup panics on an IV that is not one
// block (16 bytes); ChaCha20 takes a 12-byte nonce.
func kdbxCipherIVLength(cipherID []byte) (int, bool) {
	switch {
	case bytes.Equal(cipherID, kdbx.CipherAES), bytes.Equal(cipherID, kdbx.CipherTwoFish):
		return 16, true
	case bytes.Equal(cipherID, kdbx.CipherChaCha20):
		return 12, true
	default:
		return 0, false
	}
}

// validKDBX41PackageShape reports whether db is shaped so that the encoder
// can write it without panicking: a KDBX 4.1 header with file headers and
// hashes (the KDBX4 encoder writes both), a supported cipher ID with an IV of
// exactly that cipher's length, and content with metadata, an inner header
// with its random stream key and exactly one root group, so that binary
// cleanup has a single group to walk. A missing KDF parameter dictionary is
// shaped here and receives the profile in configureKDBXProfile. Credentials
// are not part of the shape: Seal replaces them for the duration of the call.
func validKDBX41PackageShape(db *kdbx.Database) bool {
	if db == nil || db.Header == nil || db.Header.Signature == nil ||
		db.Header.FileHeaders == nil || db.Hashes == nil {
		return false
	}
	if *db.Header.Signature != kdbx.DefaultKDBX41Sig {
		return false
	}
	ivLen, ok := kdbxCipherIVLength(db.Header.FileHeaders.CipherID)
	if !ok || len(db.Header.FileHeaders.EncryptionIV) != ivLen {
		return false
	}
	content := db.Content
	if content == nil || content.Meta == nil || content.Root == nil ||
		content.InnerHeader == nil || content.InnerHeader.InnerRandomStreamKey == nil {
		return false
	}
	return len(content.Root.Groups) == 1
}

// installKDBXKey copies cek (which must be exactly CEKSize bytes) and installs
// an API-owned key credential built from that copy as db.Credentials.
// The caller's slice is never retained or modified. The returned key is the
// copy to clear; the credential references it rather than holding further
// key material.
//
// Every exactly CEKSize-byte CEK is raw key material, so the credential is
// constructed directly. kdbx.NewKeyDataCredentials is not used: it parses its
// input as a keyfile first, and would reject a CEK that happens to be a
// well-formed XML keyfile document instead of treating it as raw key bytes.
func installKDBXKey(db *kdbx.Database, cek []byte) (key []byte, err error) {
	key = bytes.Clone(cek)
	db.Credentials = &kdbx.DBCredentials{Key: key}
	return key, nil
}

// configureKDBXProfile sets the exact Locklark snapshot Argon2id profile on
// db's header, keeping the random 32-byte salt the header already carries. A
// header whose salt is unset receives a fresh random one, so no header ends up
// with the profile's fixed parameters and an all-zero salt.
func configureKDBXProfile(db *kdbx.Database) error {
	if db.Header.FileHeaders.KdfParameters == nil {
		db.Header.FileHeaders.KdfParameters = new(kdbx.KdfParameters)
	}
	p := db.Header.FileHeaders.KdfParameters
	p.UUID = bytes.Clone(kdbx.KdfArgon2id)
	p.Version = kdbxProfileKDFVersion
	p.Memory = kdbxProfileMemory
	p.Iterations = kdbxProfileIterations
	p.Parallelism = kdbxProfileParallelism
	p.Rounds = 0
	p.SecretKey = nil
	p.AssocData = nil
	var zero [32]byte
	if p.Salt == zero {
		if _, err := rand.Read(p.Salt[:]); err != nil {
			return err
		}
	}
	return nil
}

// SealKDBXPayload encodes db as a KDBX 4.1 payload keyed by the 32-byte
// per-snapshot CEK cek and returns the encoded bytes.
//
// Input state. db must be a well-formed KDBX 4.1 database (header with
// signature, file headers and hashes, metadata, inner header with its random
// stream key, and a root with exactly one group) in the natural state
// OpenKDBXPayload returns and the internal vault writer produces: protected
// values in plaintext, with Value.Protected set, not pre-locked. The header's
// cipher must be one the vendored KDBX4 encoder supports (AES, Twofish or
// ChaCha20) and its EncryptionIV must be exactly the length of that cipher's
// IV: 16 bytes for AES and Twofish in CBC mode, 12 bytes for ChaCha20. cek
// must be exactly CEKSize (32) bytes. A nil or malformed db (including a
// missing Hashes), an unknown cipher ID, a missing or wrong-length IV or a
// wrong-length cek is rejected with CodeKDBXPayloadInvalid before the database
// is modified. db.Credentials is irrelevant: Seal accepts nil
// credentials and any prior password, key or Windows value, because it
// installs its own for the duration of the call.
//
// Sealing. Seal sets the fixed Locklark snapshot profile on db's header:
// Argon2id, KDF version 0x13, 16 MiB memory, 3 iterations, parallelism 2, no
// secret key, no associated data. The existing random 32-byte salt is
// preserved; an unset salt receives a fresh random one. Any other prior KDF
// settings are replaced. Seal then calls db.LockProtectedEntries() once on the
// plaintext protected values and hands the database to gokeepasslib's
// Encoder, which unlocks and relocks protected entries under its own
// established contract. Protected values must therefore not be pre-locked:
// lock, encode and decode is exactly what existing callers do.
//
// Mutation. The supplied Database is modified even by a call that later
// reports CodeKDBXPayloadTooLarge, and is left with protected entries locked
// at the current inner-stream position: by this locking, by the encoder
// (binary cleanup and reindexing, KDBX metadata, header and hash
// normalization) and by the encoder's own unlock and relock. Unlocking it
// again is the caller's decision. The caller must have exclusive use of db
// for the duration and must not share it with concurrent readers or writers.
// On error the Database may be partially modified and locked.
//
// Credentials and key material. Seal copies cek into API-owned storage, builds
// a key-data credential from that copy and installs it as db.Credentials,
// replacing whatever *kdbx.DBCredentials the caller had. The caller's exact
// prior pointer and its bytes are restored on every return, success and error
// alike; the caller's cek is never modified. The API-owned copy is cleared on
// every return, but gokeepasslib allocates opaque temporaries (transformed
// keys, XML, compressed and encrypted content) that this API cannot reach or
// clear.
//
// Size. Seal enforces both size budgets Open enforces, so a payload it
// produces is one Open's budgets accept. First, the encoder's opt-in
// Encoder.EncodeWithLimits bounds the serialized KDBX4 plaintext body, the
// InnerHeader followed by the XML document, after the encoder's normalization
// and protected-entry ordering and before gzip compression or encryption: a
// body above MaxPlaintextBytes is reported as CodeKDBXPayloadTooLarge and is
// never compressed or encrypted. The budget is enforced on the body's writes,
// so nothing beyond it is retained. For a NoCompressionFlag ChaCha20 or
// Twofish payload the writer's 1..16 padding bytes are not PKCS#7 and are
// counted by Open, so that budget also reserves them and admits a body of at
// most floor(MaxPlaintextBytes/16)*16-1 bytes; for AES Open removes the PKCS#7
// suffix, and a gzip payload is budgeted by its expansion. A plaintext value
// that is large but compresses well is therefore rejected rather than sealed
// into a payload Open would reject for its expanded size. The encoder keeps
// its established write order, so by then the KDBX header and hashes have been
// written into the output collector; that collector is bounded by MaxKDBXCiphertextBytes
// and is released on every error, so an encoding rejected after that header
// is reported as CodeKDBXPayloadTooLarge and no output is returned. Second, a
// returned payload never exceeds MaxKDBXCiphertextBytes: a larger encoding is
// reported as CodeKDBXPayloadTooLarge and its collected bytes are released.
// No output is returned for any error.
//
// Errors are fresh *Error values: CodeKDBXPayloadInvalid when a shape field is
// nil or malformed, for a header that is not KDBX 4.1, a cek of the wrong
// length, a crypto/rand failure or any other encoder failure;
// CodeKDBXPayloadTooLarge when the plaintext body exceeds MaxPlaintextBytes or
// the encoded output exceeds MaxKDBXCiphertextBytes. A nil error always comes
// with non-nil bytes; on error the bytes are nil.
func SealKDBXPayload(db *kdbx.Database, cek []byte) (encoded []byte, err error) {
	if len(cek) != CEKSize || !validKDBX41PackageShape(db) {
		return nil, errKDBXPayloadInvalid()
	}

	priorCredentials := db.Credentials
	defer func() { db.Credentials = priorCredentials }()

	key, err := installKDBXKey(db, cek)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	if err := configureKDBXProfile(db); err != nil {
		return nil, errKDBXPayloadInvalid()
	}
	// Protected values arrive in plaintext (the state Open and the internal
	// writer produce); the encoder requires them locked before it unlocks.
	if err := db.LockProtectedEntries(); err != nil {
		return nil, errKDBXPayloadInvalid()
	}

	out := &boundedKDBXBuffer{max: MaxKDBXCiphertextBytes}
	defer out.release()
	limits := kdbx.EncodeLimits{MaxPlaintextBytes: MaxPlaintextBytes}
	writeErr := kdbx.NewEncoder(out).EncodeWithLimits(db, limits)
	if out.exceeded || errors.Is(writeErr, kdbx.ErrEncodeLimitExceeded) {
		return nil, errKDBXPayloadTooLarge()
	}
	if writeErr != nil {
		return nil, errKDBXPayloadInvalid()
	}
	// take marks the collector released, so the deferred release on return
	// leaves the bytes handed to the caller alone.
	return out.take(), nil
}

// OpenKDBXPayload decrypts the KDBX 4.1 payload ciphertext with the 32-byte
// per-snapshot CEK cek and returns the opened Database with protected entries
// in plaintext.
//
// Prechecks run before any decoding: ciphertext must be at most
// MaxKDBXCiphertextBytes (CodeKDBXPayloadTooLarge above the cap), non-empty
// and start with the exact KDBX 4.1 signature, and cek must be exactly
// CEKSize bytes (CodeKDBXPayloadInvalid otherwise). The decoder then runs
// gokeepasslib's bounded path (Decoder.DecodeWithLimits) with
// MaxKDBXCiphertextBytes as the encoded-input budget and MaxPlaintextBytes as
// the plaintext budget.
//
// Decode timing. The input budget is enforced while the input is read and
// before the KDBX header is parsed. The header hash is checked before the
// existing KDF guard, which rejects an unsupported KDF algorithm, version,
// iterations, parallelism, memory, secret key or associated data before any
// Argon2 allocation; a non-KDBX4 header is rejected before any legacy AES
// round. The header HMAC is checked before content decryption. The plaintext
// budget can only be evaluated after key derivation and content decryption:
// it is enforced on the decrypted content, on its gzip expansion and on the
// aggregate InnerHeader binary bytes, in each case before XML decoding or
// before an over-budget binary is copied. Those later checks bound memory and
// CPU after the fixed Argon2id cost, not before it.
//
// The returned Database is in the natural unlocked state that
// SealKDBXPayload accepts. Its Credentials are always set to an empty value:
// no CEK, passphrase, key file or Windows key is retained. Open copies cek and
// clears that API-owned copy on every return; the caller's cek is never
// modified. Only that copy is cleared: gokeepasslib's opaque crypto,
// decompression and XML temporaries cannot be reached through its interface.
//
// Untrusted, KDBX only. Open decrypts KDBX only. It does not authenticate a
// file: it does not pin caller trust, verify policy proofs or a policy chain,
// VUK slots, a file revision or digest or any signature. A trusted full-file
// open is a later checkpoint.
//
// Errors are fresh *Error values: CodeKDBXPayloadTooLarge for an input above
// MaxKDBXCiphertextBytes or a decoded or expanded body above
// MaxPlaintextBytes; CodeKDBXPayloadInvalid for every other rejection,
// including an empty input, a non-KDBX-4.1 signature, a CEK of the wrong
// length, a wrong CEK, a modified byte in authenticated content, a malformed
// KDBX file, an unsupported KDF and an authentication failure. A non-nil error
// always comes with a nil Database.
func OpenKDBXPayload(ciphertext, cek []byte) (db *kdbx.Database, err error) {
	if int64(len(ciphertext)) > MaxKDBXCiphertextBytes {
		return nil, errKDBXPayloadTooLarge()
	}
	if len(ciphertext) == 0 || !isKDBX41(ciphertext) || len(cek) != CEKSize {
		return nil, errKDBXPayloadInvalid()
	}

	opened := kdbx.NewDatabase()
	key, err := installKDBXKey(opened, cek)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	if err := kdbx.NewDecoder(&kdbxChunkReader{r: bytes.NewReader(ciphertext)}).DecodeWithLimits(opened, kdbxPayloadLimits()); err != nil {
		opened.Credentials = nil
		if errors.Is(err, kdbx.ErrDecodeLimitExceeded) {
			return nil, errKDBXPayloadTooLarge()
		}
		return nil, errKDBXPayloadInvalid()
	}
	if err := opened.UnlockProtectedEntries(); err != nil {
		opened.Credentials = nil
		return nil, errKDBXPayloadInvalid()
	}
	opened.Credentials = new(kdbx.DBCredentials)
	return opened, nil
}

// kdbxChunkBytes bounds one read of the encoded input or one write request of
// the encoder, so neither side is asked for a one-shot buffer copy.
const kdbxChunkBytes = 32 << 10

// kdbxChunkReader reads at most kdbxChunkBytes per Read, so the decoder's
// input reader never receives a larger request than one fixed chunk.
type kdbxChunkReader struct{ r io.Reader }

func (c *kdbxChunkReader) Read(p []byte) (int, error) {
	if len(p) > kdbxChunkBytes {
		p = p[:kdbxChunkBytes]
	}
	return c.r.Read(p)
}

// kdbxChunkWriter splits an encoder write into at most kdbxChunkBytes writes,
// so no single call asks the collector for a larger slice than one chunk.
type kdbxChunkWriter struct{ w io.Writer }

func (c kdbxChunkWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), kdbxChunkBytes)
		k, err := c.w.Write(p[:n])
		written += k
		if err != nil {
			return written, err
		}
		if k != n {
			return written, io.ErrShortWrite
		}
		p = p[n:]
	}
	return written, nil
}

// boundedKDBXBuffer collects encoded output up to max bytes. Once a write
// would cross max the cap is recorded, the collected bytes are cleared and
// released, and every later byte is counted and discarded, so an oversize
// encoding retains nothing beyond the cap. Writes are always accepted whole so
// the encoder never sees a short write.
type boundedKDBXBuffer struct {
	buf      bytes.Buffer
	max      int64
	kept     int64
	exceeded bool
	released bool
}

func (b *boundedKDBXBuffer) Write(p []byte) (int, error) {
	b.kept += int64(len(p))
	if b.exceeded {
		return len(p), nil
	}
	if b.kept > b.max {
		b.exceeded = true
		b.release()
		return len(p), nil
	}
	_, _ = kdbxChunkWriter{w: &b.buf}.Write(p)
	return len(p), nil
}

// take hands the collected bytes to the caller, dropping the buffer's
// reusable capacity behind them, and marks the collector released so that a
// later release leaves them alone. Every byte written within max is returned,
// exactly max included.
func (b *boundedKDBXBuffer) take() []byte {
	data := b.buf.Bytes()
	b.buf = bytes.Buffer{}
	b.kept = 0
	b.released = true
	return data
}

// release clears and empties the collected bytes. Bytes already taken by the
// caller are never cleared.
func (b *boundedKDBXBuffer) release() {
	if b.released {
		return
	}
	clear(b.buf.Bytes())
	b.buf.Reset()
}
