package vaultfile

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"sync"

	"filippo.io/age"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// ScopedUnlock is an opaque, read-only, checkpoint-scoped unlock handle for
// repeated opens of one vault's authenticated files. It exists so a caller can
// authenticate the caller-pinned chain, resolve the device and unwrap the
// vault VUK once, and then read multiple exact canonical files without
// retaining or repeatedly supplying the caller's age identity.
//
// The handle owns exactly the following state and nothing else: a private copy
// of the vault VUK, the vault ID, the key epoch, the authenticated owner root
// (key id, algorithm and public key), the caller's checkpoint sequence and
// digest, the authenticated current policy sequence and digest, and the
// read-capable device binding (device id, principal id and expected age
// recipient). It does not retain the age identity, any account factor, a root
// private key, a caller's policy pointer or any caller slice. The VUK has no
// getter and is not an exported field; encoding the handle as JSON or
// formatting it with fmt never exposes it. The handle must not be copied after
// first use; copy the *ScopedUnlock pointer instead.
//
// Construction performs the same ordered check as OpenAuthenticatedFile and is
// the only place this type unwraps a VUK:
//
//  1. ParseFile validates the canonical sealed bytes without decrypting.
//  2. VerifyPolicyCheckpoint authenticates the caller's checkpoint pin, the
//     policy continuation and the content signature.
//  3. Only then is the caller's device resolved in the authenticated current
//     policy, its read-capable role checked, its VUK device slot located and
//     OpenVUKForDevice used with the authenticated recipient.
//
// Every later OpenDatabase re-runs ParseFile and VerifyPolicyCheckpoint on the
// exact canonical input and then checks that the authenticated file is still
// inside the pinned scope before it uses the cached VUK: same vault, same key
// epoch, same authenticated current policy sequence and digest, same owner
// root, and the same read-capable device with the same recipient and device
// slot. A file that authenticates under the checkpoint but is outside any of
// those bindings is rejected with CodeUnlockScopeMismatch. No account identity,
// no caller identity and no per-file VUK slot is used to re-unwrap a VUK: a
// valid file for the same vault and policy but a different VUK fails CEK
// opening rather than silently unlocking that file's own VUK.
//
// A policy sequence or key epoch change is fail-closed for this handle: it is
// rejected until the caller constructs a new handle by explicitly re-running
// NewScopedUnlock under the new policy or epoch. This type implements no
// rotation, rewrap, sharing, invitation, reseal or write path. It does not
// make a caller's already-returned database disappear or prove remote
// freshness.
type ScopedUnlock struct {
	state *scopedUnlockState
}

// CodeUnlockUnavailable is reported by OpenDatabase for a nil handle, a
// zero-value ScopedUnlock, or a handle whose Close has already completed. It
// is one code for all unavailable states so a caller cannot distinguish them
// through an error. Close itself is a no-op on a nil or zero handle.
const CodeUnlockUnavailable = "unlock_unavailable"

// CodeUnlockScopeMismatch is reported when an otherwise authenticated file is
// outside the handle's pinned scope: a different vault, key epoch, current
// policy sequence or digest, owner root, or read-capable device/recipient
// binding. The error is returned before the handle's cached VUK is used for
// CEK or KDBX decryption. It is one code for every binding so a caller cannot
// use the error to probe which field changed.
const CodeUnlockScopeMismatch = "unlock_scope_mismatch"

// scopedUnlockState is the private state behind ScopedUnlock. The exported
// handle is only a pointer to it, so formatting or JSON-encoding the handle
// cannot reach the VUK bytes or the retained bindings.
type scopedUnlockState struct {
	mu     sync.RWMutex
	closed bool

	// ownedVUK is the only secret this type retains. Close clears it and
	// drops it; every read uses it under mu.RLock and clears its own CEK.
	ownedVUK []byte

	vaultID  string
	keyEpoch uint64

	ownerRootKeyID     string
	ownerRootAlg       string
	ownerRootPublicKey []byte

	checkpointSeq    uint64
	checkpointDigest []byte

	policySeq    uint64
	policyDigest []byte

	deviceID    string
	principalID string
	recipient   string
}

// NewScopedUnlock authenticates encoded under checkpoint, resolves deviceID in
// the now-authenticated current policy, unwraps that device's VUK once and
// returns an opaque read-only handle. It performs no CEK or KDBX decryption.
//
// The order is fixed: ParseFile and VerifyPolicyCheckpoint run first (through
// verifyParsedAuthenticatedFile), so a malformed, stale, foreign-root or
// wrong-signature file is rejected before the device is resolved, before any
// VUK slot is opened and before the caller's identity is inspected. Device
// resolution, read-capable role checking, slot lookup and OpenVUKForDevice
// then follow exactly the order OpenAuthenticatedFile documents. Every error is
// returned unchanged. A nil checkpoint, a malformed checkpoint pin, a wrong
// device, a nil identity and any envelope failure therefore have their
// existing OpenAuthenticatedFile/OpenVUKForDevice codes and paths.
//
// The handle copies the checkpoint digest and owner-root key bytes it needs
// and stores only the authenticated current policy's sequence, digest, owner
// root and one device binding. Later mutation of the caller's checkpoint
// fields or slices cannot change the handle's binding. The encoded bytes,
// identity, policy and file are not retained. The caller's VUK is not an input
// and is never retained; the unwrapped VUK becomes package-owned state that
// Close clears.
//
// Trust limits: this is an unlock of one vault's current policy under one
// caller checkpoint. It does not prove checkpoint provenance, server
// freshness, complete content history, the trustworthiness of the opened KDBX
// content, or that a device remains authorized beyond the next authenticated
// policy the caller presents. It implements no rotation, invitation, rewrap,
// sharing or sealing API.
func NewScopedUnlock(encoded []byte, checkpoint *PolicyCheckpoint, deviceID string, identity *age.X25519Identity) (*ScopedUnlock, error) {
	// Parsing, checkpoint authentication and content-signature verification
	// all happen here, before any key unwrap or KDBX decryption.
	f, current, err := verifyParsedAuthenticatedFile(encoded, checkpoint)
	if err != nil {
		return nil, err
	}

	// Resolve the caller's device only in the authenticated current policy.
	// This mirrors openVerifiedFile's order and errors; the recipient comes
	// from the authenticated policy, never from the carried slot.
	dev := findDevice(current, deviceID)
	if dev == nil || !current.hasRole(dev.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) {
		return nil, Err("device_id", CodeInvalidValue)
	}
	recipient := dev.AgeEncryptionKey
	slot := findDeviceSlot(f, deviceID)
	if slot == nil {
		return nil, Err("", CodeInvalidValue)
	}

	vuk, err := OpenVUKForDevice(*slot, checkpoint.VaultID, f.Header.KeyEpoch, deviceID, recipient, identity)
	if err != nil {
		return nil, err
	}

	// The current policy is authenticated and structurally valid, so
	// PolicyDigest cannot fail here. Keep the check anyway rather than
	// binding a nil digest.
	policyDigest := PolicyDigest(current)
	if policyDigest == nil {
		clear(vuk)
		return nil, Err("", CodeInvalidValue)
	}

	s := &scopedUnlockState{
		ownedVUK: vuk,

		vaultID:  current.VaultID,
		keyEpoch: f.Header.KeyEpoch,

		ownerRootKeyID:     current.OwnerRoot.KeyID,
		ownerRootAlg:       current.OwnerRoot.Alg,
		ownerRootPublicKey: cloneBytes(current.OwnerRoot.PublicKey),

		checkpointSeq:    checkpoint.PolicySeq,
		checkpointDigest: cloneBytes(checkpoint.PolicyDigest),

		policySeq:    current.PolicySeq,
		policyDigest: policyDigest,

		deviceID:    dev.DeviceID,
		principalID: dev.PrincipalID,
		recipient:   recipient,
	}
	return &ScopedUnlock{state: s}, nil
}

// OpenDatabase authenticates encoded under the handle's checkpoint pin,
// verifies that it is still inside the handle's pinned scope, and only then
// opens the CEK with the cached VUK and decrypts the KDBX payload. It is the
// only read method of ScopedUnlock.
//
// The returned *File is the exact parsed authenticated file and the returned
// *kdbx.Database is caller-owned for this operation. The caller must release
// the database after the operation (clear its attachment binaries and
// credential byte slices and drop its decrypted Content and Credentials); it
// must not be retained by a desktop or other long-lived process. Close cannot
// clear a database that was already returned, nor any Go string or copy the
// caller made from it.
//
// Scope checks. After VerifyPolicyCheckpoint succeeds, the file is rejected
// with CodeUnlockScopeMismatch unless all of the following equal the handle's
// construction state:
//
//   - header vault ID and key epoch;
//   - header current-policy sequence and digest, the authenticated current
//     policy's sequence and PolicyDigest, and its owner root key id,
//     algorithm and public key;
//   - the handle device still exists in the current policy, with the same
//     principal, the same authenticated age recipient, a read-capable role,
//     and a matching VUK device slot recipient.
//
// The check runs before OpenCEK and OpenKDBXPayload, so a changed epoch,
// policy, owner root, device or recipient is rejected without using the
// cached VUK for content decryption. A different vault fails checkpoint
// authentication unless it shares the same pin; even when it authenticates,
// its vault id fails this scope check.
//
// Concurrency and Close. OpenDatabase holds a read lock for the entire
// verification and decryption, and Close takes the write lock. A successful
// open therefore cannot complete after Close returns: Close is linearized
// after every in-flight open and before every later one. Concurrent opens are
// allowed and use the same opaque VUK; the returned databases are independent
// caller-owned results.
//
// Errors are those of ParseFile, VerifyPolicyCheckpoint and
// verifyParsedAuthenticatedFile unchanged, CodeUnlockScopeMismatch for every
// out-of-scope but authenticated file, CodeUnlockUnavailable for a nil,
// zero-value or closed handle, the CEK envelope errors of OpenCEK, and the
// payload errors of OpenKDBXPayload. Every error returns nil, nil.
func (u *ScopedUnlock) OpenDatabase(encoded []byte) (*File, *kdbx.Database, error) {
	if u == nil || u.state == nil {
		return nil, nil, Err("", CodeUnlockUnavailable)
	}
	s := u.state
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || len(s.ownedVUK) != CEKSize {
		return nil, nil, Err("", CodeUnlockUnavailable)
	}

	// Re-authenticate against a checkpoint value rebuilt from the handle's
	// private copies. The verifier does not retain these slices.
	pin := &PolicyCheckpoint{
		VaultID:            s.vaultID,
		OwnerRootKeyID:     s.ownerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(s.ownerRootPublicKey),
		PolicySeq:          s.checkpointSeq,
		PolicyDigest:       s.checkpointDigest,
	}
	f, current, err := verifyParsedAuthenticatedFile(encoded, pin)
	if err != nil {
		return nil, nil, err
	}
	if !s.inScope(f, current) {
		return nil, nil, Err("", CodeUnlockScopeMismatch)
	}

	// The cached VUK is used exactly as unwrapped at construction. If this
	// file was sealed under another VUK for an otherwise in-scope policy,
	// OpenCEK fails instead of re-unwrapping the file's own slot.
	cek, err := OpenCEK(s.ownedVUK, f.Header, f.CEKSlot)
	if err != nil {
		return nil, nil, err
	}
	defer clear(cek)

	db, err := OpenKDBXPayload(f.KDBXCiphertext, cek)
	if err != nil {
		return nil, nil, err
	}
	return f, db, nil
}

// inScope reports whether the authenticated file and its authenticated current
// policy still match every binding captured by NewScopedUnlock. It is called
// while the handle's read lock is held and the caller has already verified the
// file against the handle's checkpoint. It never reads the VUK.
func (s *scopedUnlockState) inScope(f *File, current *Policy) bool {
	if f.Header.VaultID != s.vaultID ||
		f.Header.KeyEpoch != s.keyEpoch ||
		f.Header.PolicySeq != s.policySeq ||
		!bytes.Equal(f.Header.PolicyDigest, s.policyDigest) {
		return false
	}
	if current.PolicySeq != s.policySeq ||
		!bytes.Equal(PolicyDigest(current), s.policyDigest) {
		return false
	}
	if current.OwnerRoot.KeyID != s.ownerRootKeyID ||
		current.OwnerRoot.Alg != s.ownerRootAlg ||
		!bytes.Equal(current.OwnerRoot.PublicKey, s.ownerRootPublicKey) {
		return false
	}
	dev := findDevice(current, s.deviceID)
	if dev == nil || dev.PrincipalID != s.principalID || dev.AgeEncryptionKey != s.recipient ||
		!current.hasRole(dev.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) {
		return false
	}
	slot := findDeviceSlot(f, s.deviceID)
	if slot == nil || slot.DeviceID != s.deviceID || slot.Recipient != s.recipient {
		return false
	}
	return true
}

// Close clears the handle's owned VUK and revokes every later OpenDatabase.
// It is idempotent: the second and later calls, and calls on a nil or
// zero-value handle, do nothing and return nil.
//
// Close is linearized against OpenDatabase with the state's write lock. Once
// Close returns, every later OpenDatabase sees the closed state and returns
// CodeUnlockUnavailable; an OpenDatabase that already holds the read lock
// finishes first. Close cannot clear a database already returned by an
// earlier open, and it does not clear any Go string or caller copy made from
// that database.
func (u *ScopedUnlock) Close() error {
	if u == nil || u.state == nil {
		return nil
	}
	s := u.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	clear(s.ownedVUK)
	s.ownedVUK = nil
	return nil
}

// String, GoString and Format deliberately print only the type name. The
// handle's state is a pointer to unexported fields, but a formatter is part of
// the public surface and must not depend on that accident, so every fmt verb
// (including %v, %+v and %#v) is redacted here. The handle has no JSON
// marshaler and no exported fields, so encoding/json emits an empty object.
func (u *ScopedUnlock) String() string { return "vaultfile.ScopedUnlock" }

func (u *ScopedUnlock) GoString() string { return "vaultfile.ScopedUnlock" }

func (u *ScopedUnlock) Format(w fmt.State, verb rune) {
	_, _ = io.WriteString(w, "vaultfile.ScopedUnlock")
}
