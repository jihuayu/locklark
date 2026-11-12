package vault

import (
	"crypto/ed25519"

	"filippo.io/age"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// This file is the narrow adapter between the internal vault item model (the
// Item slice and the opaque metadata bytes) and the public caller-pinned
// authenticated file format in pkg/vaultfile. It does not change Snapshot,
// SealItems or OpenItems, and it is not a sync protocol. It implements no
// item↔KDBX boundary of its own: every item representation decision belongs
// to the shared item-database adapter in item_database.go, and every file-layer
// decision belongs to public pkg/vaultfile.
//
// Exact scope. The adapter owns composition, not protocol state:
//
//   - SealAuthenticatedItems validates items and constructs the owned KDBX
//     database only through NewItemDatabase(metadata, items), the shared
//     item-database API, and then hands that database, unchanged, to public
//     vaultfile.SealAuthenticatedFile with the caller's draft, checkpoint, VUK
//     and author key. It never calls writeItems.
//   - The caller supplies the complete builder draft: its format, version,
//     header (vault id, key epoch, content_seq, prev_digest, op_id, policy_seq,
//     policy_digest, author device) and the signed policy proofs. The adapter
//     never edits the draft; SealAuthenticatedFile authenticates the policy
//     chain against the checkpoint, checks the author device and key, wraps
//     the VUK, encrypts the database and signs the content.
//   - OpenAuthenticatedItems calls public vaultfile.OpenAuthenticatedFile,
//     which parses the file, authenticates it against the caller's checkpoint
//     and only then decrypts the database, and only then reads the item group
//     back through ReadItemDatabase(db), the shared item-database API.
//
// What it deliberately does not do: it does not create content-sequence
// values, set or check prev_digest for continuity, compare revisions, perform
// compare-and-swap or conditional writes against any backend, fetch, order or
// de-duplicate concurrent updates, detect or resolve conflicts, check
// freshness, choose the current file, or implement synchronization of any
// kind. Two files sealed through this adapter can carry the same content_seq
// and both are individually valid; deciding which one is current, or whether
// one may replace another, is entirely the caller's responsibility and is not
// proven by either function here. It also performs no epoch or VUK rotation,
// no policy change or invitation, and no CRDT-style merge.
//
// Ownership. The caller owns the draft, metadata, items, checkpoint, VUK,
// authorPrivateKey and every Open input. Neither function mutates or retains
// them: NewItemDatabase neither aliases nor clears the caller's items,
// metadata or binary bytes, and its owned database is package-owned for the
// duration of the call and never returned. The returned file bytes, metadata
// bytes and items are owned by the caller.

// SealAuthenticatedItems validates items and metadata, builds the owned KDBX
// 4.1 item database with NewItemDatabase and seals that database into a
// caller-pinned authenticated file with vaultfile.SealAuthenticatedFile.
//
// Order:
//
//  1. ValidateItems(metadata, items) runs first, before any KDBX work. It
//     applies the same schema, bounds, digest and name checks SealItems uses
//     and rejects a nil item slice. An invalid input returns ErrSnapshot
//     exactly as SealItems does, with nil bytes.
//  2. A nil draft or a draft whose header key epoch is zero is rejected with
//     invalid_value before any database is built; SealAuthenticatedFile would
//     reject it anyway, but only after this adapter has done KDBX work. Every
//     other draft, checkpoint, VUK and author key check stays in
//     SealAuthenticatedFile. The code and empty path are the ones
//     SealAuthenticatedFile reports for the nil draft ("") and the zero epoch
//     ("key_epoch") cases, and both collapse to the same invalid_value.
//  3. NewItemDatabase(metadata, items) builds a fresh KDBX 4.1 database in the
//     shared personal snapshot layout: the item-group name, the metadata entry
//     and one entry per item in caller order, with a database-owned copy of
//     every item binary. It re-applies ValidateItems and also rejects nil
//     metadata by its own contract. Its errors are returned unchanged: an
//     item-representation failure is ErrSnapshot, before any file bytes exist.
//  4. vaultfile.SealAuthenticatedFile(draft, db, checkpoint, vuk,
//     authorPrivateKey) produces the bytes. Its errors are returned
//     unchanged, so a bad draft, checkpoint, VUK or author key is reported
//     with the exact vaultfile *Error code and path. Nothing is wrapped or
//     reinterpreted.
//
// metadata is carried verbatim (NewItemDatabase only validates it and stores
// it base64-encoded into the protected metadata entry). Item order is the
// order of the KDBX entries and is preserved exactly by
// OpenAuthenticatedItems. draft is used as a builder value exactly as
// SealAuthenticatedFile documents: it must carry the protocol format and
// version and a valid header, and SealAuthenticatedFile never mutates it. db
// is not a caller input and is never returned.
//
// Trust limits: this seals only content under a policy chain the caller's
// checkpoint already anchors, through SealAuthenticatedFile. It does not
// establish checkpoint provenance or freshness, create a content sequence
// (header.content_seq and header.prev_digest are the caller draft's values and
// are not computed or checked for continuity here), perform CAS or
// conditional writes, or synchronize with any other replica. A non-nil error
// always comes with nil bytes.
func SealAuthenticatedItems(draft *vaultfile.File, metadata []byte, items []Item, checkpoint *vaultfile.PolicyCheckpoint, vuk []byte, authorPrivateKey ed25519.PrivateKey) ([]byte, error) {
	if err := ValidateItems(metadata, items); err != nil {
		return nil, err
	}
	// Cheap precheck kept only to preserve the current error order: reject a
	// nil draft or a zero key epoch before the database is built. Every other
	// draft check stays in SealAuthenticatedFile.
	if draft == nil || draft.Header.KeyEpoch == 0 {
		return nil, vaultfile.Err("", vaultfile.CodeInvalidValue)
	}
	db, err := NewItemDatabase(metadata, items)
	if err != nil {
		return nil, err
	}
	return vaultfile.SealAuthenticatedFile(draft, db, checkpoint, vuk, authorPrivateKey)
}

// OpenAuthenticatedItems opens a file sealed by SealAuthenticatedItems and
// returns the parsed authenticated file, its metadata and its items.
//
// Order:
//
//  1. vaultfile.OpenAuthenticatedFile(encoded, checkpoint, deviceID,
//     identity) authenticates the canonical file, the caller's pinned policy
//     checkpoint and the content signature before it resolves the device,
//     unwraps the VUK, opens the CEK and decrypts the KDBX payload. Its errors
//     are returned unchanged; a wrong checkpoint pin in particular is the
//     exact vaultfile.CodePolicyCheckpointFailed with an empty path.
//  2. Only after that succeeds is the decrypted database read with
//     ReadItemDatabase(db), the shared item-database API that enforces the
//     supported database shape (exactly one item group), the group name, the
//     single metadata entry, one entry per item in wire order, the field
//     shapes, the binaries and the item schema. A database it rejects returns
//     ErrSnapshot.
//
// On success the returned *vaultfile.File, metadata bytes and []Item are
// caller-owned; the returned file is the parsed authenticated wire file and
// the items and metadata are fresh decodes, in the sealed order. On any error
// the file, metadata and items are all nil.
//
// Trust limits: this is only a caller-pinned authenticated open plus the
// shared item-database reader. It performs no sync, CAS or freshness check: it
// does not compare the header's content sequence or previous digest against
// any local state, does not prove that the file is the newest one the caller
// has seen, and does not order or reconcile it with any other file.
func OpenAuthenticatedItems(encoded []byte, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity) (*vaultfile.File, []byte, []Item, error) {
	f, db, err := vaultfile.OpenAuthenticatedFile(encoded, checkpoint, deviceID, identity)
	if err != nil {
		return nil, nil, nil, err
	}
	metadata, items, err := ReadItemDatabase(db)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, metadata, items, nil
}
