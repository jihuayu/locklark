package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math"

	"filippo.io/age"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// deriveFileDigestBytes returns the raw 32 bytes of FileDigest(f): the SHA-256
// digest the lowercase-hex FileDigest names. f must already be a validated
// sealed file; the derivation itself is FileDigest's, never a second one.
func deriveFileDigestBytes(f *File) ([]byte, error) {
	hexDigest, err := FileDigest(f)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(hexDigest)
}

// readCapableDevice returns the authenticated policy's entry for deviceID when
// its principal holds a read-capable role there, and nil otherwise.
func readCapableDevice(current *Policy, deviceID string) *Device {
	dev := findDevice(current, deviceID)
	if dev == nil || !current.hasRole(dev.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) {
		return nil
	}
	return dev
}

// innerHeaderBinaryContents returns the content buffer of every binary the
// database's InnerHeader carries, without copying the contents. It is the
// capture step of the rotation's ownership of an opened database: the
// gokeepasslib encoder removes an unreferenced binary from
// db.Content.InnerHeader.Binaries during SealAuthenticatedFile, and the bytes
// it removed stay reachable only through a reference captured before the seal.
// It tolerates a missing content or inner header.
func innerHeaderBinaryContents(db *kdbx.Database) [][]byte {
	if db == nil || db.Content == nil || db.Content.InnerHeader == nil {
		return nil
	}
	binaries := db.Content.InnerHeader.Binaries
	contents := make([][]byte, 0, len(binaries))
	for i := range binaries {
		contents = append(contents, binaries[i].Content)
	}
	return contents
}

// clearBinaryContents clears, in place, every content buffer in contents. It
// is the release half of innerHeaderBinaryContents and is safe to call more
// than once over overlapping captures.
func clearBinaryContents(contents [][]byte) {
	for _, content := range contents {
		clear(content)
	}
}

// ownInnerHeaderBinaries takes ownership of the InnerHeader binary content
// buffers of the opened database db and returns a release function that clears
// exactly those captured before the seal and any binary the InnerHeader still
// carries afterwards, so a binary the encoder removed is cleared as well. The
// caller defers the release. It is a minimum cleanup only: it makes no claim
// about the XML document, protected values, Go strings or any library
// temporary.
func ownInnerHeaderBinaries(db *kdbx.Database) func() {
	captured := innerHeaderBinaryContents(db)
	return func() {
		clearBinaryContents(captured)
		clearBinaryContents(innerHeaderBinaryContents(db))
	}
}

// RotateAuthenticatedFile is the package's caller-pinned complete-file epoch
// rotation primitive. It authenticates the caller's old file and an already
// authorized next draft against the same PolicyCheckpoint, opens the old
// full KDBX database through the authenticated open path, generates a fresh
// random 32-byte epoch VUK and seals a complete next-epoch baseline of that
// content under the next draft through SealAuthenticatedFile. The rotation
// returns the sealed successor bytes and the new VUK only to the caller whose
// source device remains read-capable in the authenticated next policy.
//
// oldEncoded is one complete sealed file. checkpoint is the caller's
// already-trusted pin and the only trust anchor: every accepted policy here
// continues it. nextDraft has exactly the builder contract of the File that
// SealAuthenticatedFile takes: protocol format and version, the header, and
// signed policy proofs whose chain already continues the checkpoint
// (root-signed, or an authorized delegated InviteReaders transition). Its
// carried VUKDeviceSlots, CEKSlot, KDBXCiphertext, revision id and content
// signature are allowed to be nil or stale and are ignored: this function
// never requires a structurally complete sealed file from the caller.
// sourceDeviceID and sourceIdentity identify the rotating device, and
// authorPrivateKey must be the content signing key the authenticated next
// policy records for nextDraft's author device.
//
// The order is fixed and is the security boundary. Steps 1 to 5 are pure
// checks: nothing is decrypted, generated, wrapped or encrypted until they
// pass.
//
//  1. Basic inputs. A nil draft, checkpoint, identity, author key or
//     sourceIdentity.Recipient(), or an empty sourceDeviceID, is an
//     invalid_value at "". A draft format or version other than the
//     protocol's is an invalid_value at ""; a non-empty ContentEncoding other
//     than the protocol's is an invalid_value at "content_encoding".
//  2. Old file. errOld, oldCurrent := verifyParsedAuthenticatedFile(oldEncoded,
//     checkpoint): ParseFile, then VerifyPolicyCheckpoint, with exactly
//     OpenAuthenticatedFile's order and errors. The old file is authenticated
//     before any of its fields are read as an input, and its carried roster is
//     never a trust source.
//  3. Next policy. verifyPolicyChain(nextDraft.Header, nextDraft.SignedPolicyProofs,
//     checkpoint) authenticates the next chain against the same caller pin;
//     the draft is not structurally validated as a sealed file, because it is
//     a builder value. It also rejects a next header whose VaultID differs
//     from the checkpoint: that is CodePolicyCheckpointFailed at "", and it is
//     returned here, before the explicit vault equality guard in step 4 ever
//     runs. Then, in the authenticated next policy:
//     the author device must be a writer, admin or owner whose Ed25519 content
//     signing key passes validatedAuthorKey with authorPrivateKey (otherwise
//     CodeAuthorSigningKeyMismatch at "content_signature"); the source device
//     must be present and read-capable (otherwise invalid_value at
//     "device_id"); and the source device's AgeEncryptionKey must equal
//     sourceIdentity.Recipient().String() (otherwise invalid_value at
//     "device_id"). The new VUK is returned only to a device that remains
//     authorized, so a device this rotation removes cannot receive it.
//  4. Continuation. The next header's VaultID must equal the old vault id
//     ("vault_id"); that guard is reached only after step 3, so a next draft
//     of another vault has already failed in step 3 as
//     CodePolicyCheckpointFailed at "". Its KeyEpoch must be exactly old + 1
//     and its ContentSeq exactly old + 1, with no 64-bit wrap ("key_epoch",
//     "content_seq"); its
//     PrevDigest must equal the raw 32 FileDigest bytes of the authenticated
//     old file ("prev_digest"); and its OpID must differ from the old op id
//     ("op_id"). Every failure is invalid_value at the naming path. This is an
//     exact immediate continuation in content_seq, not a freshness or
//     compare-and-swap check against any server.
//  5. Preconditions for the fresh baseline. nextDraft.Header.KeyEpoch must be
//     positive ("key_epoch"), so SealAuthenticatedFile can bind it into the
//     new envelopes and CEK slot.
//  6. Open. openVerifiedFile(*errOld, oldCurrent, checkpoint, sourceDeviceID,
//     sourceIdentity) runs steps 3 to 6 of OpenAuthenticatedFile: the source
//     device is resolved in the authenticated old policy, its VUK slot is
//     opened, the CEK slot is opened and the KDBX payload is decrypted.
//  7. Fresh VUK. 32 random bytes are drawn with crypto/rand. A crypto/rand
//     failure is returned as its operational error with nil outputs.
//  8. Seal. SealAuthenticatedFile(nextDraft, db, checkpoint, freshVUK,
//     authorPrivateKey) authenticates the next chain again, derives every
//     per-device VUK slot only from the authenticated next policy, generates
//     a fresh per-snapshot CEK and its fresh slot, encrypts db and signs the
//     content. Its error is returned unchanged.
//
// On success newEncoded is the sealed successor and newVUK is the
// caller-owned 32-byte epoch VUK the caller must clear after use. On every
// error both are nil and the package-owned new VUK buffer is cleared, and on
// success the package keeps no copy of the returned buffer.
// nextDraft, oldEncoded, checkpoint, sourceIdentity and authorPrivateKey are
// never modified and never retained.
//
// Ownership of the opened database. The function owns the db it opened and
// never returns it. Before sealing it captures, without copying, the content
// buffer of every InnerHeader binary the opened database carries; after
// sealing, on success and on every error including the SealAuthenticatedFile
// error path, it clears those captured buffers in place and also the content
// buffers of every binary the InnerHeader still carries. The capture is
// required because the gokeepasslib encoder removes an unreferenced binary
// from db.Content.InnerHeader.Binaries before that cleanup runs, and clearing
// only the remaining binaries would leave the removed one's plaintext behind.
// This is a minimum cleanup only: the decrypted XML, protected values and Go
// string fields of the database are not claimed to be securely zeroed, and
// gokeepasslib's opaque crypto, decompression and XML temporaries, including
// any content buffer the encoder itself allocated, remain beyond reach
// exactly as OpenKDBXPayload documents.
//
// Fresh keys. The new VUK is independent of the old one and no old VUK, CEK
// or CEK slot is reused: the successor carries a fresh CEK under the new VUK
// and a fresh envelope per authenticated next-policy device. A holder of the
// old VUK can still read the old plaintext wherever an old copy or old
// ciphertext exists, but it cannot open the successor's CEK slot, so a fresh
// epoch VUK keeps the old VUK from decrypting the new CEK. Prior plaintext is
// not erased from old copies.
//
// Trust limits:
//   - The checkpoint is the only trust anchor; it is scope only. Freshness,
//     provenance and CAS are not checked. Content-seq + 1 and prev_digest are
//     enforced against the specified old file only, so no server or replica is
//     known to hold the same baseline, and nothing prevents two callers from
//     rotating the same old file into two different successors.
//   - The next policy chain must already be authorized (root-signed, or an
//     authorized delegated InviteReaders transition) under the same
//     checkpoint. This function creates no policy, invitation, device key,
//     device-key generation, restore root or delegation.
//   - It recovers no old plaintext beyond the KDBX content the caller can
//     already open, and it cannot recall or revoke an old VUK a removed device
//     already learned. Rotation is performed by a device that stays
//     authorized; a device removed by this rotation is rejected by the next
//     policy and receives no new VUK.
//   - It does not bump generation counters, timestamps or backend revisions,
//     and it is not a sync protocol.
//
// Errors are the unchanged structural and verification errors of the old
// file, the unchanged error of verifyPolicyChain for the next draft,
// CodeAuthorSigningKeyMismatch for the author key, invalid_value at
// the naming path for continuation and source-device failures, the unchanged
// errors of the authenticated open, a crypto/rand operational error, and the
// unchanged error of SealAuthenticatedFile. Every error returns nil, nil.
func RotateAuthenticatedFile(oldEncoded []byte, checkpoint *PolicyCheckpoint, sourceDeviceID string, sourceIdentity *age.X25519Identity, nextDraft *File, authorPrivateKey ed25519.PrivateKey) (newEncoded []byte, newVUK []byte, err error) {
	// 1. Basic inputs.
	if nextDraft == nil || checkpoint == nil || sourceIdentity == nil || sourceIdentity.Recipient() == nil ||
		len(authorPrivateKey) == 0 || sourceDeviceID == "" {
		return nil, nil, Err("", CodeInvalidValue)
	}
	if nextDraft.Format != Format || nextDraft.Version != Version {
		return nil, nil, Err("", CodeInvalidValue)
	}
	if nextDraft.ContentEncoding != "" && nextDraft.ContentEncoding != ContentEncoding {
		return nil, nil, Err("content_encoding", CodeInvalidValue)
	}

	// 2. The old file, authenticated under the caller pin exactly as
	// OpenAuthenticatedFile authenticates it.
	oldFile, oldCurrent, err := verifyParsedAuthenticatedFile(oldEncoded, checkpoint)
	if err != nil {
		return nil, nil, err
	}

	// 3. The next policy chain under the same pin, and its author and source
	// device in the authenticated next policy.
	nextCurrent, err := verifyPolicyChain(nextDraft.Header, nextDraft.SignedPolicyProofs, checkpoint)
	if err != nil {
		return nil, nil, err
	}
	author := findDevice(nextCurrent, nextDraft.Header.AuthorDeviceID)
	if author == nil || !nextCurrent.hasRole(author.PrincipalID, RoleWriter, RoleAdmin, RoleOwner) ||
		author.ContentSigningKey.Alg != SigAlgEd25519 ||
		!validEd25519Key(author.ContentSigningKey.PublicKey) ||
		len(authorPrivateKey) != ed25519.PrivateKeySize {
		return nil, nil, Err("content_signature", CodeAuthorSigningKeyMismatch)
	}
	authorKey, ok := validatedAuthorKey(authorPrivateKey, author.ContentSigningKey.PublicKey)
	if !ok {
		return nil, nil, Err("content_signature", CodeAuthorSigningKeyMismatch)
	}
	defer clear(authorKey)
	source := readCapableDevice(nextCurrent, sourceDeviceID)
	if source == nil || source.AgeEncryptionKey != sourceIdentity.Recipient().String() {
		return nil, nil, Err("device_id", CodeInvalidValue)
	}

	// 4. The exact immediate continuation of the authenticated old file.
	h := &nextDraft.Header
	old := &oldFile.Header
	if h.VaultID != old.VaultID {
		return nil, nil, Err("vault_id", CodeInvalidValue)
	}
	if old.KeyEpoch == math.MaxUint64 || h.KeyEpoch != old.KeyEpoch+1 {
		return nil, nil, Err("key_epoch", CodeInvalidValue)
	}
	if old.ContentSeq == math.MaxUint64 || h.ContentSeq != old.ContentSeq+1 {
		return nil, nil, Err("content_seq", CodeInvalidValue)
	}
	prevDigest, err := deriveFileDigestBytes(oldFile)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(h.PrevDigest, prevDigest) {
		return nil, nil, Err("prev_digest", CodeInvalidValue)
	}
	if h.OpID == old.OpID {
		return nil, nil, Err("op_id", CodeInvalidValue)
	}

	// 5. The successor epoch must be sealable. ContentEncoding was already
	// constrained in step 1, so no successor with a foreign encoding reaches
	// step 8.
	if h.KeyEpoch == 0 {
		return nil, nil, Err("key_epoch", CodeInvalidValue)
	}

	// 6. Open the old full database through the authenticated open path.
	_, db, err := openVerifiedFile(oldFile, oldCurrent, checkpoint, sourceDeviceID, sourceIdentity)
	if err != nil {
		return nil, nil, err
	}
	// The opened database is owned by this function. Its InnerHeader binary
	// content buffers are captured here and cleared after sealing on every
	// path, including the binaries SealAuthenticatedFile's encoder removes
	// from the InnerHeader before the cleanup runs.
	defer ownInnerHeaderBinaries(db)()

	// 7. A fresh epoch VUK. freshVUK is the exact package-owned allocation
	// below; this local, not the named result, is what the defer clears, so
	// every return path after the allocation clears that buffer whoever wrote
	// newVUK. Only the successful return below hands it to the caller.
	freshVUK := make([]byte, CEKSize)
	defer func() {
		if err != nil || newEncoded == nil {
			clear(freshVUK)
		}
	}()
	if _, err := rand.Read(freshVUK); err != nil {
		return nil, nil, err
	}

	// 8. The complete next-epoch baseline: fresh CEK, fresh per-device
	// envelopes from the authenticated next policy, fresh signature.
	encoded, err := SealAuthenticatedFile(nextDraft, db, checkpoint, freshVUK, authorPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return encoded, freshVUK, nil
}
