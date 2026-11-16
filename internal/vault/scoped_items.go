package vault

import (
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// ItemSummary is the bounded, read-only projection returned by
// ReadScopedItemSummaries. It carries only the item ID (when explicitly
// requested), the title and the canonical category. It never carries a
// database, a key, a credential, a password, an OTP, a URL, notes, an
// attachment, a passkey, SSH material or any other decrypted item field.
type ItemSummary struct {
	ID       string       `json:"id,omitempty"`
	Title    string       `json:"title"`
	Category ItemCategory `json:"category"`
}

// ItemSummaryOptions selects the only optional field of ItemSummary. The ID is
// an opaque item identifier, not secret-equivalent key material, but a caller
// that does not need it can omit it from the projection.
type ItemSummaryOptions struct {
	IncludeID bool
}

// ReadScopedItemSummaries is the bounded internal-vault bridge over one
// pkg/vaultfile.ScopedUnlock handle. It opens exactly the canonical encoded
// file the caller supplies through the handle, reads the real item database
// with ReadItemDatabase and returns only the item ID (if opts.IncludeID), title
// and canonical category.
//
// The ordering and cleanup are deliberate:
//
//  1. handle.OpenDatabase(encoded) re-authenticates the canonical file under
//     the handle's caller checkpoint, checks its pinned scope, and only then
//     opens the CEK and KDBX payload with the cached VUK. Its errors are
//     returned unchanged; a closed, nil or zero handle is
//     vaultfile.CodeUnlockUnavailable.
//  2. The opened database is package-owned by this call and never returned.
//     releaseOpenedItemDatabase is deferred immediately: it clears the
//     database's InnerHeader binary content and credential byte slices and
//     drops its decrypted Content and Credentials references on success and
//     error alike.
//  3. ReadItemDatabase(db) is the existing real item-database reader; this
//     bridge does not fake a constant projection or parse the KDBX itself. Its
//     ErrSnapshot and all other errors are returned unchanged.
//  4. After the summaries are copied, the decoded metadata and item buffers
//     that can be cleared are cleared: attachment content, import provenance,
//     SSH key bytes, the legacy passkey record and the passkey collection.
//     Entry, title, category and other item values are Go strings, which
//     cannot be securely overwritten; they are only dropped for the garbage
//     collector. The returned summary strings are necessarily copies of the
//     title (and ID when requested) and carry the same limitation.
//
// The returned slice and its strings are caller-owned. The function retains
// no database, VUK, CEK, item, attachment or metadata buffer. It performs no
// sync, CAS, freshness, conflict-resolution, rotation or write operation; a
// successful call means only that the file verified under the handle's pinned
// checkpoint and scope and that its real item database produced these bounded
// summaries.
func ReadScopedItemSummaries(handle *vaultfile.ScopedUnlock, encoded []byte, opts ItemSummaryOptions) ([]ItemSummary, error) {
	// The handle rejects nil, zero-value and closed states itself.
	_, db, err := handle.OpenDatabase(encoded)
	if err != nil {
		return nil, err
	}
	defer releaseOpenedItemDatabase(db)

	metadata, items, err := ReadItemDatabase(db)
	if err != nil {
		return nil, err
	}
	defer func() {
		clear(metadata)
		for i := range items {
			clearScopedItemBuffers(&items[i])
		}
	}()

	summaries := make([]ItemSummary, len(items))
	for i := range items {
		summaries[i].Title = items[i].Title
		summaries[i].Category = items[i].EffectiveCategory()
		if opts.IncludeID {
			summaries[i].ID = items[i].ID
		}
	}
	return summaries, nil
}

// clearScopedItemBuffers clears every clearable decrypted byte buffer of one
// decoded item. Go strings are not clearable and are left for the garbage
// collector with the item.
func clearScopedItemBuffers(it *Item) {
	clearSensitiveItemBuffers(it)
	clear(it.SSHSeed)
	clear(it.SSHPublicKey)
	it.ClearPasskeys()
}
