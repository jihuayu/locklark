// Package vaultfilesync implements the authenticated bootstrap of a local
// vault-file sync journal from a remote file.
//
// Scope: this package is one checkpoint of #110. It reads the remote file
// once, verifies it completely against a caller-supplied, already-trusted
// vaultfile.PolicyCheckpoint, checks that the opened payload is exactly the
// unlocked item database layout internal/vault defines, establishes the local
// journal's initial state when the journal is empty, and returns a sealed
// receipt. It performs no merge, no remote write, no cryptography of its own
// and no product integration; it does not implement #110 as a whole.
//
// It is a bootstrap, not an open: it does not return the plaintext file, the
// KDBX database or the items to the caller. Every mutable plaintext byte slice
// it creates is cleared on the way out; Go strings, including the KDBX value
// strings, are immutable and are only dropped, not cleared. The returned receipt
// carries only opaque metadata. It never derives or trusts a policy checkpoint
// of its own: the caller's pin is the only trust input, and nothing read from
// the remote bytes can replace it.
package vaultfilesync

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

// Sentinel errors classify the failure of Bootstrap; callers test them with
// errors.Is. Every returned error wraps exactly one of them with %w, except a
// context error (context.Canceled or context.DeadlineExceeded observed at one
// of the checks), which is returned unchanged and is still matched with
// errors.Is. Neither the message text nor any wrapped cause includes a remote
// value, revision or plaintext produced by this package.
var (
	// ErrInvalidInput reports a malformed or nil argument or a rejected
	// caller pin: a nil backend, journal, checkpoint or identity, an invalid
	// backend name, an empty device ID, or a checkpoint whose shape is not a
	// usable pin. Nothing was written.
	ErrInvalidInput = errors.New("vault file sync: invalid input")
	// ErrRead reports that Backend.Read failed or returned a result this
	// package cannot accept: a zero revision, a revision longer than
	// vaultfilebackend.MaxRevisionSize, or bytes that are empty or larger than
	// vaultfilebackend.MaxValueSize. Nothing was written.
	ErrRead = errors.New("vault file sync: remote read failed")
	// ErrVerify reports that the caller-pinned open (OpenAuthenticatedFile)
	// or the item-database structure check (ReadItemDatabase) rejected the
	// remote bytes. The cause is available through errors.Unwrap and
	// errors.Is; remote content is untrusted input and is never part of the
	// message. Nothing was written.
	ErrVerify = errors.New("vault file sync: remote file rejected")
	// ErrJournal reports that the journal refused the initial state, or that
	// the initializer rejected its argument, so nothing was written. Journal
	// sentinels (vaultfilejournal.ErrJournalNotEmpty, ErrStateExists,
	// ErrCorrupt, ErrInvalid, ErrClosed) stay discoverable through errors.Is.
	ErrJournal = errors.New("vault file sync: journal bootstrap rejected")
	// ErrCommitted reports that the journal write may have committed or did
	// commit, and no receipt is returned: an unclassifiable journal error, or
	// a cancelled context observed after the commit. The journal holds either
	// nothing or the complete bootstrap state, never a partial one. Do not
	// assume the journal is still empty; reload it and compare LoadState
	// exactly with the expected bootstrap state.
	ErrCommitted = errors.New("vault file sync: journal bootstrap outcome not confirmed")
)

// Receipt is the sealed result of a successful Bootstrap. It is deliberately
// plain metadata: it carries no File, database, items, plaintext or private
// key, and it is not a claim that the local vault is complete or synced.
type Receipt struct {
	// RemoteRevision is the opaque backend revision the remote bytes were
	// read at, stored verbatim. It is the expected revision of a later
	// compare-and-swap write to the same name.
	RemoteRevision vaultfilebackend.Revision
	// FileDigest is vaultfile.FileDigest of the verified remote file,
	// recomputed locally from the opened file: the lowercase hex SHA-256 of
	// the domain separator DomainFileDigest, a NUL byte, and EncodeFile(f)
	// (the canonical sealed encoding, with header.revision_id and
	// content_signature kept unchanged). It is not a value named by the file
	// header (header.revision_id is a different, derived identifier); it
	// identifies the content, not a backend version.
	FileDigest string
	// Generation is the local journal generation this bootstrap established.
	// It is always 0; it is a local CAS counter and says nothing about the
	// remote.
	Generation uint64
}

// Bootstrap establishes the initial local journal state from one authenticated
// read of the remote vault file.
//
// Inputs. ctx is the caller's context, checked at every stage. backend is read
// exactly once with Read, yielding the remote bytes R and the opaque revision
// of the same committed version. journal is the local journal. name is the
// backend name of the remote file. checkpoint is the caller's already-trusted
// vaultfile.PolicyCheckpoint; it is the only trust input. deviceID and identity
// select the caller's device and its age X25519 key.
//
// Steps, in order:
//
//  1. Check ctx, then the inputs.
//  2. backend.Read(ctx, name). A zero revision, an over-long revision, empty
//     or oversize bytes, or any Read error is ErrRead. A zero revision is
//     never accepted: the journal stores it as "no remote base".
//  3. Check ctx.
//  4. vaultfile.OpenAuthenticatedFile(R, checkpoint, deviceID, identity). This
//     is the complete caller-pinned open: canonical parse, policy-checkpoint
//     and content-signature verification, device and age VUK slot resolution
//     from the authenticated policy, CEK open, KDBX decrypt and unlock. Any
//     error is ErrVerify wrapping it.
//  5. Check ctx.
//  6. vault.ReadItemDatabase on the unlocked database. Any error, including a
//     payload that is a valid KDBX but not exactly the item-database layout,
//     is ErrVerify.
//  7. Check ctx.
//  8. Compute the receipt from the verified File and the read pair.
//  9. Check ctx, then journal.InitializeEmptyState with BaseBytes and
//     WorkingBytes equal to the exact bytes R and RemoteRevision equal to the
//     revision returned with them, Generation 0. It succeeds only when the
//     journal holds no record; any existing state (even one byte-for-byte
//     equal), proposal, prepared proposal, unknown record or bucket is refused
//     and preserved byte for byte, and a known record key holding a nested
//     bucket is ErrCorrupt. Its definite rejections are ErrJournal wrapping it
//     (so errors.Is(err, vaultfilejournal.ErrJournalNotEmpty), ErrStateExists
//     and ErrCorrupt still hold); any other journal error is ErrCommitted.
//  10. Check ctx and return the receipt.
//
// No step writes to the backend. The journal state is the only durable effect.
//
// Context and commit. Cancellation anywhere before step 9 writes nothing and
// returns a zero Receipt. Once the journal transaction may have committed,
// cancellation can no longer undo it: if ctx is cancelled after commit, or the
// journal returns an error this package cannot classify, Bootstrap returns
// ErrCommitted with a zero Receipt. In that case the journal holds either the
// complete bootstrap state or none, never a partial one; it is only the receipt
// that is missing. This is deliberately not reported as "journal unchanged":
// the caller must reload the journal and compare LoadState exactly with the
// expected state (BaseBytes and WorkingBytes equal to R, RemoteRevision equal
// to the revision, Generation 0) to learn the outcome. Repeating Bootstrap on a
// journal that already holds that state therefore does not succeed: it is
// refused as a non-empty journal (ErrJournal wrapping
// vaultfilejournal.ErrJournalNotEmpty), and the caller confirms the committed
// state with LoadState itself.
//
// Errors. Every error return has a zero Receipt. Errors wrap one of the
// sentinels above with %w, so errors.Is matches them and the underlying cause
// is reachable with errors.Unwrap. The one exception is a context error from a
// ctx check, which is returned unchanged (not wrapped in a sentinel); it is
// still matched with errors.Is(err, context.Canceled) or
// errors.Is(err, context.DeadlineExceeded). Neither the error text nor the
// Receipt contains remote bytes, plaintext, item values or backend values.
//
// Cleanup. The opened File, its ciphertext and envelopes, the KDBX database,
// its binary buffers, credentials and every []byte of the items
// ReadItemDatabase returns are released and those byte slices are cleared in
// place before the call returns, on success and on every failure after they
// exist. Go does not guarantee physical erasure: strings are immutable and
// cannot be overwritten, so the KDBX value strings (item values, protected
// values, history values) and item string fields are only dropped with the
// database and the items, not cleared; copies made by libraries, the runtime
// or the garbage collector cannot be reached either and are not claimed to be
// cleared. clear([]byte(s)) would clear only a copy of s's bytes, so no such
// step is performed or counted. This package claims cleared []byte buffers, not
// zeroization of strings and not forensic erasure.
//
// Trust limits. Bootstrap verifies only that the remote file authenticates
// under the caller's pin and has the exact item-database structure. It does not
// prove where the pin came from, that it is fresh, that the remote's content
// history through prev_digest and content_seq is complete, that the backend
// revision cannot be rolled back by the provider, or that the remote stored
// bytes of any later write. It never promotes anything read from R into trust:
// no carried policy, roster, key or revision replaces the caller's pin.
func Bootstrap(
	ctx context.Context,
	backend vaultfilebackend.Backend,
	journal *vaultfilejournal.Journal,
	name string,
	checkpoint *vaultfile.PolicyCheckpoint,
	deviceID string,
	identity *age.X25519Identity,
) (Receipt, error) {
	if err := checkContext(ctx); err != nil {
		return Receipt{}, err
	}
	if err := checkInputs(backend, journal, name, checkpoint, deviceID, identity); err != nil {
		return Receipt{}, err
	}

	read, err := backend.Read(ctx, name)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrRead, err)
	}
	remote := read.Bytes
	// Our own copy of R, cleared on every path it leaves by, so the bytes do
	// not stay live past this call.
	defer clearSlice(remote)
	if len(remote) == 0 || len(remote) > vaultfilebackend.MaxValueSize {
		return Receipt{}, fmt.Errorf("%w: remote bytes have an unacceptable length", ErrRead)
	}
	if read.Revision.Zero() || len(read.Revision) > vaultfilebackend.MaxRevisionSize {
		return Receipt{}, fmt.Errorf("%w: remote revision is malformed", ErrRead)
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}

	file, db, err := vaultfile.OpenAuthenticatedFile(remote, checkpoint, deviceID, identity)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrVerify, err)
	}
	// From here on plaintext exists; the deferred release drops the sealed
	// file and the database whatever happens next.
	defer releaseFile(file)
	defer releaseDatabase(db)
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}

	metadata, items, err := vault.ReadItemDatabase(db)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrVerify, err)
	}
	// ReadItemDatabase transfers ownership of the metadata and item buffers.
	releasePlaintext(metadata, items)
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}

	receipt, err := receiptFor(file, read)
	if err != nil {
		return Receipt{}, err
	}

	// The last context check before the only durable write.
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	// The journal copies both slices before its transaction, so remote may
	// be cleared as soon as this returns.
	journalErr := journal.InitializeEmptyState(vaultfilejournal.State{
		BaseBytes:      remote,
		RemoteRevision: read.Revision,
		WorkingBytes:   remote,
		Generation:     0,
	})
	if journalErr != nil {
		if isDefiniteJournalRejection(journalErr) {
			return Receipt{}, fmt.Errorf("%w: %w", ErrJournal, journalErr)
		}
		return Receipt{}, fmt.Errorf("%w: %w", ErrCommitted, journalErr)
	}
	// The transaction is committed. A cancellation observed now cannot roll
	// it back: report the committed state without a receipt, never a
	// guarantee that nothing was written.
	if err := ctx.Err(); err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrCommitted, err)
	}
	return receipt, nil
}

// receiptFor builds the receipt of a verified file and the read pair it came
// from.
func receiptFor(file *vaultfile.File, read vaultfilebackend.ReadResult) (Receipt, error) {
	digest, err := vaultfile.FileDigest(file)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrVerify, err)
	}
	return Receipt{
		RemoteRevision: read.Revision,
		FileDigest:     digest,
		Generation:     0,
	}, nil
}

// checkInputs validates the non-context arguments without reading anything.
func checkInputs(backend vaultfilebackend.Backend, journal *vaultfilejournal.Journal, name string, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity) error {
	if backend == nil || journal == nil {
		return fmt.Errorf("%w: nil backend or journal", ErrInvalidInput)
	}
	if !vaultfilebackend.ValidName(name) {
		return fmt.Errorf("%w: backend name is not a valid name", ErrInvalidInput)
	}
	if checkpoint == nil {
		return fmt.Errorf("%w: nil policy checkpoint", ErrInvalidInput)
	}
	if checkpoint.VaultID == "" || checkpoint.OwnerRootKeyID == "" ||
		len(checkpoint.OwnerRootPublicKey) != 32 || len(checkpoint.PolicyDigest) != sha256.Size {
		return fmt.Errorf("%w: malformed policy checkpoint", ErrInvalidInput)
	}
	if deviceID == "" {
		return fmt.Errorf("%w: empty device ID", ErrInvalidInput)
	}
	if identity == nil {
		return fmt.Errorf("%w: nil age identity", ErrInvalidInput)
	}
	return nil
}

// isDefiniteJournalRejection reports whether err proves the journal did not
// commit with the new state: the initializer refused the journal's existing
// content, the journal is closed, or the state was rejected as malformed.
// Every other journal error (a commit or I/O failure) may have committed.
func isDefiniteJournalRejection(err error) bool {
	return errors.Is(err, vaultfilejournal.ErrJournalNotEmpty) ||
		errors.Is(err, vaultfilejournal.ErrStateExists) ||
		errors.Is(err, vaultfilejournal.ErrCorrupt) ||
		errors.Is(err, vaultfilejournal.ErrInvalid) ||
		errors.Is(err, vaultfilejournal.ErrClosed)
}

// releaseFile drops the parsed file and its own byte buffers. The receipt's
// digest has already been computed, so the content is no longer needed.
func releaseFile(f *vaultfile.File) {
	if f == nil {
		return
	}
	clearSlice(f.KDBXCiphertext)
	for i := range f.VUKDeviceSlots {
		clearSlice(f.VUKDeviceSlots[i].WrappedVUK)
	}
	clearSlice(f.CEKSlot.WrappedCEK)
	f.KDBXCiphertext = nil
	f.VUKDeviceSlots = nil
	f.CEKSlot.WrappedCEK = nil
}

// releaseDatabase clears the opened database's plaintext and releases it.
// ReadItemDatabase did not mutate db, so every decrypted value is still in its
// unlocked form and can be cleared in place, together with the inner-header
// binaries that backed the item attachments. gokeepasslib's decrypted XML
// document and its crypto temporaries are internal to it and are not reachable
// here.
func releaseDatabase(db *kdbx.Database) {
	if db == nil {
		return
	}
	if db.Content != nil {
		if db.Content.Meta != nil {
			for i := range db.Content.Meta.Binaries {
				clearSlice(db.Content.Meta.Binaries[i].Content)
			}
		}
		if db.Content.InnerHeader != nil {
			for i := range db.Content.InnerHeader.Binaries {
				clearSlice(db.Content.InnerHeader.Binaries[i].Content)
			}
			db.Content.InnerHeader.Binaries = nil
		}
		if db.Content.Root != nil {
			clearGroups(db.Content.Root.Groups)
		}
	}
	if db.Credentials != nil {
		clearSlice(db.Credentials.Passphrase)
		clearSlice(db.Credentials.Key)
		clearSlice(db.Credentials.Windows)
	}
	db.Credentials = nil
	db.Content = nil
}

// clearGroups clears every value buffer of every entry in groups and their
// subgroups.
func clearGroups(groups []kdbx.Group) {
	for i := range groups {
		for j := range groups[i].Entries {
			clearEntry(&groups[i].Entries[j])
		}
		clearGroups(groups[i].Groups)
	}
}

// clearEntry drops the value strings and history entries of one entry. The
// values are Go strings: they are immutable, []byte(s) would only clear a copy,
// and the backing bytes cannot be overwritten here, so they are only released
// with the entry, not cleared.
func clearEntry(e *kdbx.Entry) {
	clear(e.Values)
	for h := range e.Histories {
		for k := range e.Histories[h].Entries {
			clearEntry(&e.Histories[h].Entries[k])
		}
	}
}

// releasePlaintext clears the metadata and the byte buffers of the items
// vault.ReadItemDatabase returned: the legacy and multi passkey records, the
// legacy document attachment, every v2 attachment body, the import-source
// provenance and the SSH key material. The item records are unreachable once
// this returns; their immutable string fields, and the section and history
// values, are Go strings and are not cleared, only dropped.
func releasePlaintext(metadata []byte, items []vault.Item) {
	clearSlice(metadata)
	for i := range items {
		it := &items[i]
		it.ClearPasskeys()
		clearSlice(it.Attachment)
		clearSlice(it.ImportSource)
		clearSlice(it.SSHSeed)
		clearSlice(it.SSHPublicKey)
		for a := range it.Attachments {
			clearSlice(it.Attachments[a].Content)
		}
	}
}

// clearSlice zeroes b, including any spare capacity, in place.
func clearSlice(b []byte) {
	if cap(b) > 0 {
		clear(b[:cap(b)])
	}
}

// checkContext reports a nil or already cancelled context.
func checkContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidInput)
	}
	return ctx.Err()
}
