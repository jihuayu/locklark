package vault

import (
	"bytes"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// This file is the item-database adapter: it turns the internal vault items
// into, and back out of, a KDBX 4.1 database that the caller seals, encrypts,
// opens and unlocks itself.
//
// The adapter implements no file-layer security. NewItemDatabase neither sets
// credentials nor encrypts, locks or authenticates anything;
// ReadItemDatabase performs no file signature, credential, epoch, encryption
// or authorization check. All of that belongs to the caller.

// NewItemDatabase returns an unlocked KDBX 4.1 database holding exactly the
// established personal snapshot layout: the single "Locklark items v1" root
// group, the protected metadata entry and one entry per item as written by the
// snapshot write path. Its KDF profile is the shared personal snapshot profile
// (Argon2id, 16 MiB, 3 iterations, default parallelism).
//
// The database has no credentials and nothing is encrypted, locked or
// authenticated, so a caller that encodes it must first lock it the way
// SealItems and ExportKDBX do: LockProtectedEntries (the encoder does not
// transform protected values itself), then set caller-owned credentials and
// encode. Other KDBX tools also expect maybe-compressed binaries
// (SetKDBXv4Binary), which this adapter deliberately does not apply. It does
// not alias the caller's items, metadata or binary bytes.
//
// Input is validated exactly like SealItems: a nil metadata or item slice,
// metadata above MaxPayload, more than MaxItems items, a value that only the
// legacy read path accepts, or anything else ValidateItems rejects returns
// ErrSnapshot. Metadata must be non-nil (empty metadata is non-nil empty). A
// non-nil empty item slice is valid and round-trips as a non-nil empty result.
// Values are never normalized or repaired.
func NewItemDatabase(metadata []byte, items []Item) (*kdbx.Database, error) {
	if metadata == nil || items == nil || len(metadata) > MaxPayload || ValidateItems(metadata, items) != nil {
		return nil, ErrSnapshot
	}
	db := newSnapshotDatabase()
	if err := writeItems(db, metadata, items); err != nil {
		return nil, ErrSnapshot
	}
	// writeItems borrows the caller's attachment bytes for the KDBX inner-header
	// binaries. Give every binary its own copy so the database owns every
	// buffer it exposes, before any caller observes or encodes it. Binaries are
	// never shared, even when their content is equal: a protected and a clear
	// binary with the same bytes must stay independent.
	for n := range db.Content.InnerHeader.Binaries {
		db.Content.InnerHeader.Binaries[n].Content = bytes.Clone(db.Content.InnerHeader.Binaries[n].Content)
	}
	return db, nil
}

// ReadItemDatabase returns the metadata and items of an already-opened and
// unlocked KDBX 4.1 item database.
//
// The caller is responsible for authenticating, opening, decrypting and
// unlocking the file (Decode, then UnlockProtectedEntries). This function
// verifies no file signature, credentials, epoch, encryption or
// authorization; it does not mutate db. It enforces only
// the supported in-memory shape: a non-nil header, signature, file header, KDF
// parameters, content, meta, root and inner header, exactly one root group
// named "Locklark items v1", and exactly the entry, value and binary layout
// that readItems enforces. A nil, rootless, multi-group, wrong-group,
// malformed or legacy "Locklark" preview database, nil metadata, or an item
// carrying a legacy-read-only value returns ErrSnapshot with nil outputs.
//
// Returned metadata, attachment, provenance and passkey buffers are fresh
// copies that alias neither db nor each other, so the caller owns them.
func ReadItemDatabase(db *kdbx.Database) ([]byte, []Item, error) {
	if !openedItemDatabase(db) {
		return nil, nil, ErrSnapshot
	}
	metadata, items, err := readItems(db, db.Content.Root.Groups[0])
	if err != nil {
		return nil, nil, ErrSnapshot
	}
	// readItems applies the legacy read rules; the result must also survive the
	// strict write path, otherwise a caller could only fail on the next write.
	if ValidateItems(metadata, items) != nil {
		clearReadItemDatabase(metadata, items)
		return nil, nil, ErrSnapshot
	}
	return metadata, items, nil
}

// openedItemDatabase reports whether db is a non-nil, opened KDBX 4.1 database
// with a single root group named like the item layout. It only reads db.
func openedItemDatabase(db *kdbx.Database) bool {
	if db == nil || db.Header == nil || db.Header.Signature == nil ||
		!db.Header.IsKdbx4() || !db.Header.IsKdbx41() ||
		db.Header.FileHeaders == nil || db.Header.FileHeaders.KdfParameters == nil ||
		db.Content == nil || db.Content.Meta == nil || db.Content.Root == nil ||
		db.Content.InnerHeader == nil || db.Content.InnerHeader.InnerRandomStreamKey == nil {
		return false
	}
	return len(db.Content.Root.Groups) == 1 && db.Content.Root.Groups[0].Name == itemGroup
}

// clearReadItemDatabase zeroes a refused read. These buffers are fresh copies
// owned by the read, never buffers referenced by db or its entries.
func clearReadItemDatabase(metadata []byte, items []Item) {
	for n := range items {
		clearSensitiveItemBuffers(&items[n])
		items[n].ClearPasskeys()
	}
	clear(metadata)
}
