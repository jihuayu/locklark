package vaultfile

import (
	"filippo.io/age"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// OpenAuthenticatedFile is the package's caller-pinned authenticated full-file
// open path. It parses a canonical sealed file, authenticates it against the
// caller's trusted PolicyCheckpoint, and only then resolves the caller's
// device and age recipient from the now-authenticated current policy, unwraps
// the caller device's VUK slot, opens the CEK slot and opens the KDBX payload.
// It returns both the parsed *File and the unlocked *kdbx.Database on success,
// and nil, nil, err on every error.
//
// The order is fixed and is the security boundary:
//
//  1. ParseFile performs the bounded canonical structural validation only; it
//     performs no decryption. Its error is returned unchanged. ValidateFile
//     requires vuk_device_slots to be exactly the current policy's
//     read-capable device set, so a missing required slot is already rejected
//     here as invalid_value at "" and never reaches steps 3 and 4. Likewise a
//     listed device whose principal holds no read-capable role makes the
//     policy structurally invalid, so ParseFile rejects it here as
//     invalid_value at "" and it never reaches step 3.
//  2. VerifyPolicyCheckpoint authenticates the caller-pinned root and policy
//     continuation and the content signature. The policy and slot roster
//     carried in the file are untrusted until this succeeds. Its error is
//     returned unchanged (for example CodePolicyCheckpointFailed or
//     CodeSignatureVerifyFailed).
//  3. Only after step 2, the caller's device is resolved in the authenticated
//     current policy, together with its expected age recipient
//     (Device.AgeEncryptionKey). The carried proposal roster and
//     DeviceSlot.Recipient are never the trust source. An unknown caller
//     device ID, absent from the authenticated current policy, is an
//     invalid_value at "device_id". A device in a valid parsed policy already
//     necessarily has reader-or-stronger access, because step 1 rejects any
//     policy device whose principal lacks a read-capable role.
//  4. OpenVUKForDevice opens the caller device's VUK slot with the pinned
//     checkpoint vault id, the authenticated header key epoch and the caller
//     device id and identity, and the expected recipient from the
//     authenticated current policy. Step 3 already proved the device has a
//     slot, so once a present, authenticated device slot reaches
//     OpenVUKForDevice only its envelope/context failures remain: those are
//     CodeVUKEnvelopeFailed at "vuk_device_slot". A nil identity or malformed
//     caller input is an invalid_value from OpenVUKForDevice.
//  5. OpenCEK opens the CEK with the authenticated header and the file's CEK
//     slot; any envelope failure is CodeCEKEnvelopeFailed at "cek_slot".
//  6. OpenKDBXPayload opens the KDBX payload with that CEK; its error is
//     returned unchanged.
//
// The VUK and CEK are package-owned during the call and are cleared on every
// path after use, success and failure alike. The returned *File is the parsed
// sealed wire file and the returned *kdbx.Database is in the unlocked state
// SealKDBXPayload accepts, with no retained credentials. The caller owns both.
//
// Trust limits: this is only a caller-pinned authenticated file-open path. It
// does not establish server freshness, proof of complete content history
// through prev_digest, the provenance of the checkpoint, or epoch/key
// generation. It performs no invitation, rewrap or rotation flow and does not
// claim that the opened KDBX content is otherwise trustworthy. It is not a
// sealing API: SealAuthenticatedFile is the caller-pinned seal that produces
// the bytes this path accepts.
func OpenAuthenticatedFile(encoded []byte, checkpoint *PolicyCheckpoint, deviceID string, identity *age.X25519Identity) (*File, *kdbx.Database, error) {
	f, err := ParseFile(encoded)
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyPolicyCheckpoint(f, checkpoint); err != nil {
		return nil, nil, err
	}
	// The chain and content signature are authenticated; the current policy
	// returned here is the one the verifier authenticated from the caller's
	// checkpoint.
	current, err := validateStructure(f)
	if err != nil {
		return nil, nil, err
	}
	dev := findDevice(current, deviceID)
	if dev == nil || !current.hasRole(dev.PrincipalID, RoleReader, RoleWriter, RoleAdmin, RoleOwner) {
		return nil, nil, Err("device_id", CodeInvalidValue)
	}
	// Defensive invariant only: ParseFile already rejected a slot roster that
	// is not exactly the current policy's read-capable device set, so the
	// fallback agrees with that structural rejection.
	slot := findDeviceSlot(f, deviceID)
	if slot == nil {
		return nil, nil, Err("", CodeInvalidValue)
	}

	vuk, err := OpenVUKForDevice(*slot, checkpoint.VaultID, f.Header.KeyEpoch, deviceID, dev.AgeEncryptionKey, identity)
	if err != nil {
		return nil, nil, err
	}
	defer clear(vuk)

	cek, err := OpenCEK(vuk, f.Header, f.CEKSlot)
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

// findDeviceSlot returns the VUK device slot for id, or nil. ValidateFile has
// already required the slot array to be the exact read-capable device set, so
// a nil result here is not a caller-selectable trust path.
func findDeviceSlot(f *File, id string) *DeviceSlot {
	for i := range f.VUKDeviceSlots {
		if f.VUKDeviceSlots[i].DeviceID == id {
			return &f.VUKDeviceSlots[i]
		}
	}
	return nil
}
