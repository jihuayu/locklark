package vault

import (
	"crypto/ed25519"

	"filippo.io/age"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// This file is the narrow adapter between the internal vault item model (the
// Item slice and the opaque metadata bytes) and the public caller-pinned
// authenticated file format in pkg/vaultfile. It does not change Snapshot,
// SealItems or OpenItems, and it is not a sync protocol. Its implementation
// uses only the standard library, age, public pkg/vaultfile and KDBX APIs.
//
// Exact scope. The adapter owns representation, not protocol state:
//
//   - SealAuthenticatedItems validates the items, builds a fresh, empty KDBX
//     4.1 database and writes the existing internal v1/v2 item-group layout
//     into it with writeItems. It creates no content sequence, predecessor
//     digest, operation id, revision or content signature, and no policy,
//     policy proof, epoch or key.
//   - The caller supplies the complete builder draft: its format, version,
//     header (vault id, key epoch, content_seq, prev_digest, op_id, policy_seq,
//     policy_digest, author device) and the signed policy proofs. The adapter
//     never edits the draft; it passes it unchanged, with the database and
//     the caller's checkpoint, VUK and author key, to
//     vaultfile.SealAuthenticatedFile, which authenticates the policy chain
//     against the checkpoint, checks the author device and key, wraps the VUK,
//     encrypts the database and signs the content.
//   - OpenAuthenticatedItems calls vaultfile.OpenAuthenticatedFile, which
//     parses the file, authenticates it against the caller's checkpoint and
//     only then decrypts the database, and only then reads the item group back
//     with readItems.
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
// them. SealAuthenticatedItems hands writeItems package-owned deep clones of
// the item byte slices (the bytes that become KDBX binaries) and clears
// exactly those clones on every return path, success and error alike. Within a
// call the clones outlive the KDBX encoding, because the database still
// references them until SealAuthenticatedFile has encrypted it. The returned
// file bytes, metadata bytes and items are owned by the caller.

// SealAuthenticatedItems validates items and metadata, writes them into a new
// KDBX 4.1 database in the internal item-group layout, and seals that
// database into a caller-pinned authenticated file.
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
//     SealAuthenticatedFile.
//  3. A fresh database from kdbx.NewDatabase(WithDatabaseKDBXVersion41()) is
//     populated by writeItems, unchanged, with the item-group name, the
//     metadata entry and one entry per item in caller order. writeItems
//     stores document attachment bytes and v2 attachment contents as KDBX
//     binaries, so it is given package-owned deep clones of every item byte
//     slice (Attachment, ImportSource, SSH seed and public key, legacy and
//     collection passkey records, and every attachment content). Each clone
//     lives only as long as the KDBX work that reads it and is cleared before
//     the call returns, on success and on every error. The caller's items are
//     never modified or cleared. A writeItems failure, which cannot follow a
//     successful ValidateItems through caller input, is ErrSnapshot with nil
//     bytes and nothing handed on to SealAuthenticatedFile.
//  4. vaultfile.SealAuthenticatedFile(draft, db, checkpoint, vuk,
//     authorPrivateKey) produces the bytes. Its errors are returned
//     unchanged, so a bad draft, checkpoint, VUK or author key is reported
//     with the exact vaultfile *Error code and path. Nothing is wrapped or
//     reinterpreted.
//
// metadata is carried verbatim (it is only validated and base64-encoded into
// the protected metadata entry). Item order is the order of the KDBX entries
// and is preserved exactly by OpenAuthenticatedItems. draft is used as a
// builder value exactly as SealAuthenticatedFile documents: it must carry the
// protocol format and version and a valid header, and SealAuthenticatedFile
// never mutates it. db is not a caller input and is never returned.
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
	// SealAuthenticatedFile requires a positive key epoch before any
	// cryptographic work. A nil draft or a draft without one is rejected here
	// before any database is built; every other draft check stays in
	// SealAuthenticatedFile. The code and empty path are the ones
	// SealAuthenticatedFile reports for the nil draft ("") and the zero epoch
	// ("key_epoch") cases, and both collapse to the same invalid_value.
	if draft == nil || draft.Header.KeyEpoch == 0 {
		return nil, vaultfile.Err("", vaultfile.CodeInvalidValue)
	}
	db, owned, err := newAuthenticatedItemsDB(metadata, items)
	// The clones are cleared after SealAuthenticatedFile returns, never
	// earlier: the KDBX encoding reads them while it encrypts db. They are
	// already cleared when writeItems failed, so this is a no-op then.
	defer clearAuthenticatedItemBytes(owned)
	if err != nil {
		return nil, err
	}
	return vaultfile.SealAuthenticatedFile(draft, db, checkpoint, vuk, authorPrivateKey)
}

// newAuthenticatedItemsDB builds the fresh KDBX 4.1 database SealKDBXPayload
// accepts and writes metadata and items into it. The item byte slices handed
// to writeItems are deep clones owned by this package, returned in owned so
// the caller can clear them on every exit.
//
// The only writeItems failures after a successful ValidateItems are internal
// (JSON encoding of an envelope, passkey collection encoding); they are
// reported as ErrSnapshot like every other item-representation error, and the
// clones are cleared before returning so a failed database retains no item
// bytes.
func newAuthenticatedItemsDB(metadata []byte, items []Item) (*kdbx.Database, [][]byte, error) {
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	var owned [][]byte
	cloned := make([]Item, len(items))
	for i, it := range items {
		cloned[i] = authenticatedItemsClone(it, &owned)
	}
	if err := writeItems(db, metadata, cloned); err != nil {
		clearAuthenticatedItemBytes(owned)
		return nil, nil, ErrSnapshot
	}
	return db, owned, nil
}

// authenticatedItemsClone returns a copy of it whose every byte slice is a
// fresh package-owned clone, appended to owned. Strings and the remaining value
// fields are copied by value and share no mutable storage with it.
func authenticatedItemsClone(it Item, owned *[][]byte) Item {
	c := it
	own := func(b []byte) []byte {
		cloned := cloneBytes(b)
		*owned = append(*owned, cloned)
		return cloned
	}
	c.Attachment = own(it.Attachment)
	c.ImportSource = own(it.ImportSource)
	c.SSHSeed = own(it.SSHSeed)
	c.SSHPublicKey = own(it.SSHPublicKey)
	c.Passkey = own(it.Passkey)
	if it.Passkeys != nil {
		c.Passkeys = make([][]byte, len(it.Passkeys))
		for i := range it.Passkeys {
			c.Passkeys[i] = own(it.Passkeys[i])
		}
	}
	if it.Attachments != nil {
		c.Attachments = make([]AttachmentMeta, len(it.Attachments))
		for i := range it.Attachments {
			c.Attachments[i] = it.Attachments[i]
			c.Attachments[i].Content = own(it.Attachments[i].Content)
		}
	}
	return c
}

// clearAuthenticatedItemBytes clears every package-owned clone.
func clearAuthenticatedItemBytes(owned [][]byte) {
	for _, b := range owned {
		clear(b)
	}
}

// authenticatedItemsDB is the database shape readItems requires: content, a
// root and an inner header that carries the binaries, with the single group
// readItems will be handed. OpenAuthenticatedFile already guarantees content
// and root; this guard keeps the reader from dereferencing a shape it does not
// require, and it checks nothing about the item layout itself.
func authenticatedItemsDB(db *kdbx.Database) bool {
	return db != nil && db.Content != nil && db.Content.Root != nil && db.Content.InnerHeader != nil && len(db.Content.Root.Groups) == 1
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
//  2. Only after that succeeds is the decrypted database's item-group layout
//     validated with readItems, the same strict reader OpenItems uses for
//     item snapshots: the group name, the single metadata entry, one entry
//     per item in wire order, the field shapes, the binaries and the full
//     item schema. A layout that readItems rejects returns ErrSnapshot.
//
// On success the returned *vaultfile.File, metadata bytes and []Item are
// caller-owned; the returned file is the parsed authenticated wire file and
// the items and metadata are fresh decodes, in the sealed order. On any error
// all three results are nil.
//
// Trust limits: this is only a caller-pinned authenticated open plus the item
// layout reader. It performs no sync, CAS or freshness check: it does not
// compare the header's content sequence or previous digest against any
// local state, does not prove that the file is the newest one the caller has
// seen, and does not order or reconcile it with any other file.
func OpenAuthenticatedItems(encoded []byte, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity) (*vaultfile.File, []byte, []Item, error) {
	f, db, err := vaultfile.OpenAuthenticatedFile(encoded, checkpoint, deviceID, identity)
	if err != nil {
		return nil, nil, nil, err
	}
	// OpenAuthenticatedFile returns a database whose content and root are
	// present; this is a shape guard, not a trust decision.
	if !authenticatedItemsDB(db) {
		return nil, nil, nil, ErrSnapshot
	}
	metadata, items, err := readItems(db, db.Content.Root.Groups[0])
	if err != nil {
		return nil, nil, nil, err
	}
	return f, metadata, items, nil
}
