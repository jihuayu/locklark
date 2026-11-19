package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// Sentinel errors classify the failure of UpdateWorkingItems; callers test them
// with errors.Is. A definite rejection wraps ErrWorkingUpdateRejected together
// with its cause, so journal sentinels such as
// vaultfilejournal.ErrStateGenerationMismatch stay discoverable, as do
// context.Canceled and context.DeadlineExceeded. The context sentinels are
// preserved on both sides of the journal compare-and-swap; only the sentinel
// that classifies whether anything may have been written differs.
var (
	// ErrWorkingUpdateRejected reports that nothing was written: invalid
	// input, a failure to authenticate the old working file or read its item
	// database, a policy/VUK failure, a sealing or final-verification
	// failure, a cancellation observed before the journal CAS, or a definite
	// journal rejection (a stale generation, a missing state, corruption, an
	// invalid state or a closed journal). The previous working, base,
	// revision, legacy proposal and prepared proposal records are unchanged.
	ErrWorkingUpdateRejected = errors.New("vault file sync: working update rejected")
	// ErrWorkingUpdateCommitted reports that the journal CAS committed the
	// complete new working state, but the caller could not be given the
	// success result because a cancellation was observed after the CAS. A
	// non-zero WorkingReceipt is returned for reconciliation, but it is not
	// proof of persistence: reload the journal with LoadState and compare the
	// working bytes, generation, base, revision and pending records.
	ErrWorkingUpdateCommitted = errors.New("vault file sync: working update committed")
	// ErrWorkingUpdateOutcomeUnknown reports an unclassifiable journal error
	// from UpdateWorking, which may have committed. A non-zero
	// WorkingReceipt is returned for reconciliation, but it is not proof that
	// the update persisted: reload the journal with LoadState and compare it
	// exactly before deciding what happened. The journal holds either the old
	// state or the complete new one, never a partial state.
	ErrWorkingUpdateOutcomeUnknown = errors.New("vault file sync: working update outcome unknown")
)

// errWorkingVerificationMismatch reports that the independently reopened
// sealed working file did not carry the exact header linkage, metadata or
// items requested. It is internal: callers see ErrWorkingUpdateRejected. The
// message never includes plaintext, keys or file bytes.
var errWorkingVerificationMismatch = errors.New("vault file sync: sealed working file verification mismatch")

// WorkingReceipt is the result of a successful UpdateWorkingItems, and the
// reconciliation hint returned when the journal CAS may have committed but the
// outcome cannot be confirmed. It carries only metadata: no item plaintext,
// metadata bytes, VUK, private key or sealed file bytes.
type WorkingReceipt struct {
	// OperationID is the fresh operation ID carried by the sealed working
	// file. It differs from the previous file's operation ID.
	OperationID string
	// ContentSeq is the sealed working file's content sequence: exactly the
	// previous working file's sequence plus one.
	ContentSeq uint64
	// Generation is the local journal generation after the update,
	// expectedGeneration+1. It is a local CAS counter and says nothing about
	// a remote publication.
	Generation uint64
	// FileDigest is vaultfile.FileDigest of the sealed working file,
	// lowercase hex. It identifies the content, not a backend version.
	FileDigest string
}

// UpdateWorkingItems replaces the journal's local working file with a complete,
// caller-pinned authenticated item update.
//
// Inputs. ctx is the caller's context, checked at entry, after the old working
// file is authenticated and its items are read, after the new file is sealed,
// after the new file is independently reopened and verified, and before the
// journal CAS. journal is the local journal; only Journal.LoadState is used to
// read the old working bytes, and the journal is the only place this function
// writes. expectedGeneration is the local CAS generation the caller observed.
// items is the caller's complete new item list; it is snapshot-copied and is
// never mutated. A non-nil empty slice is a valid request that clears all
// items; a nil slice is rejected. checkpoint is the caller's already-trusted
// vaultfile.PolicyCheckpoint and the only trust input. deviceID and identity
// select the caller's device and age X25519 key. authorPrivateKey is the
// caller's Ed25519 content signing key for that device.
//
// Metadata is not a caller input. It is read from the item database carried by
// the current journal State.WorkingBytes through ReadItemDatabase and is
// preserved byte for byte in the new file.
//
// Steps, in order:
//
//  1. Check ctx and the inputs.
//  2. journal.LoadState and require its Generation to equal
//     expectedGeneration. No backend is read or written.
//  3. vaultfile.OpenAuthenticatedFile(oldWorking, checkpoint, deviceID,
//     identity): the complete caller-pinned open of the old working bytes.
//  4. vault.ReadItemDatabase on the unlocked database. The old items are
//     fully validated and then discarded; only the metadata is retained.
//  5. Check ctx.
//  6. Take the last (current) signed policy proof of the just-authenticated
//     File and parse its canonical Document with
//     vaultfile.ParsePolicyDocument, producing an independent deep snapshot.
//     Confirm explicitly that its VaultID, PolicySeq and PolicyDigest are the
//     Header's, resolve deviceID and its age recipient only in that snapshot,
//     find the matching DeviceSlot, and recover the per-epoch VUK with
//     vaultfile.OpenVUKForDevice. The slot's Recipient is never a trust
//     source. The recovered VUK is reused for the same key epoch; this
//     function never generates or rotates a VUK.
//  7. Build the sealed draft from the old authenticated file: preserve
//     Format, Version, ContentEncoding, VaultID, KeyEpoch, PolicySeq,
//     PolicyDigest and every signed policy proof; set AuthorDeviceID to
//     deviceID; set ContentSeq to exactly old+1 and reject an old sequence of
//     MaxUint64; set PrevDigest to the raw 32 bytes decoded from
//     vaultfile.FileDigest(oldFile) (never a fresh SHA-256 of raw bytes); and
//     set OpID to a fresh crypto/rand lowercase-hex identifier that differs
//     from the old OpID. BaseBytes and RemoteRevision are not inputs or
//     outputs of this step and are never changed by this function.
//  8. vault.SealAuthenticatedItems with the preserved metadata, the snapshot
//     copy of the caller's items, the same VUK, checkpoint and author key.
//  9. Check ctx.
//  10. Reopen the sealed bytes with vaultfile.OpenAuthenticatedFile under the
//     same checkpoint, deviceID and identity, read them back with
//     vault.ReadItemDatabase, and require the same vault, key epoch, policy
//     sequence and digest, exactly old+1 content sequence, the decoded old
//     file digest as PrevDigest, the requested fresh OpID (different from the
//     old one), AuthorDeviceID == deviceID, and metadata and items exactly
//     equal to the request. The expected item representation is itself taken
//     from the same NewItemDatabase/ReadItemDatabase round trip, so the check
//     compares canonical content rather than incidental in-memory nilness
//     (for example a non-nil empty Sections, History or Passkeys collection,
//     which the KDBX wire normalizes to nil). This proves the produced file is
//     a valid caller-pinned file carrying the requested content. It does not
//     prove backend freshness, remote history, or synchronization of any
//     kind.
//  11. Check ctx and call journal.UpdateWorking(expectedGeneration, sealed).
//     That atomic generation CAS is the final authority. A concurrent or
//     stale caller cannot overwrite a higher generation.
//
// Journal effects. UpdateWorking changes only WorkingBytes and Generation
// (to expectedGeneration+1). BaseBytes, RemoteRevision, the legacy proposal
// record and the prepared proposal record are preserved exactly. This
// function does not delete, rewrite or fold either pending record.
//
// Context and commit. Cancellation before the CAS writes nothing and returns a
// zero WorkingReceipt wrapping ErrWorkingUpdateRejected; errors.Is still
// matches context.Canceled or context.DeadlineExceeded. The CAS itself accepts
// no context. If the CAS commits and a cancellation is then observed, the
// complete new state is durable and cannot be rolled back: the function
// returns ErrWorkingUpdateCommitted wrapping the context error, with a non-zero
// WorkingReceipt. If the CAS returns an error this function cannot classify, it
// may have committed: it returns ErrWorkingUpdateOutcomeUnknown wrapping that
// error, with a non-zero WorkingReceipt. In either non-zero-receipt case the
// receipt is a reconciliation hint only, not proof of persistence; compare
// LoadState exactly. Every definite rejection returns a zero WorkingReceipt.
//
// Errors and cleanup. Every non-context cause is reachable with errors.Unwrap
// and errors.Is; journal sentinels remain matched. Error strings contain no
// item plaintext, metadata, key material or sealed file bytes. The function
// owns and clears, in place, the state bytes it copied from the journal, the
// old metadata and item buffers, its deep copy of the caller's items and its
// canonical item representation, the recovered VUK, the raw previous digest,
// the sealed bytes and every File and KDBX database it opened, on success and
// failure, using releaseFile, releaseDatabase, releasePlaintext and
// clearSlice. Go strings, including item string fields and policy identifiers,
// are immutable and are only dropped, never claimed to be erased; caller-owned
// items and keys are never cleared.
func UpdateWorkingItems(
	ctx context.Context,
	journal *vaultfilejournal.Journal,
	expectedGeneration uint64,
	items []vault.Item,
	checkpoint *vaultfile.PolicyCheckpoint,
	deviceID string,
	identity *age.X25519Identity,
	authorPrivateKey ed25519.PrivateKey,
) (WorkingReceipt, error) {
	if err := workingContextError(ctx); err != nil {
		return WorkingReceipt{}, err
	}
	if err := checkWorkingInputs(journal, items, checkpoint, deviceID, identity, authorPrivateKey); err != nil {
		return WorkingReceipt{}, err
	}

	state, err := journal.LoadState()
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	// Both slices are copies returned by LoadState and are owned here. They
	// are sealed bytes, not plaintext, but they are still cleared on the way
	// out so no unnecessary copy stays live.
	oldWorking := state.WorkingBytes
	defer clearSlice(oldWorking)
	defer clearSlice(state.BaseBytes)

	if state.Generation != expectedGeneration {
		return WorkingReceipt{}, fmt.Errorf("%w: %w", ErrWorkingUpdateRejected, &vaultfilejournal.StateCASMismatchError{
			Expected: expectedGeneration,
			Stored:   state.Generation,
		})
	}
	if state.Generation == math.MaxUint64 {
		return WorkingReceipt{}, fmt.Errorf("%w: %w", ErrWorkingUpdateRejected, &vaultfilejournal.StateGenerationOverflowError{
			Generation: state.Generation,
		})
	}
	if err := workingContextError(ctx); err != nil {
		return WorkingReceipt{}, err
	}

	oldFile, oldDB, err := vaultfile.OpenAuthenticatedFile(oldWorking, checkpoint, deviceID, identity)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	defer releaseFile(oldFile)
	defer releaseDatabase(oldDB)
	if err := workingContextError(ctx); err != nil {
		return WorkingReceipt{}, err
	}

	metadata, oldItems, err := vault.ReadItemDatabase(oldDB)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	// ReadItemDatabase transfers ownership of the metadata and item buffers.
	defer releasePlaintext(metadata, oldItems)
	if err := workingContextError(ctx); err != nil {
		return WorkingReceipt{}, err
	}

	current, err := workingCurrentPolicy(oldFile)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	vuk, err := workingEpochVUK(oldFile, current, deviceID, identity)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	defer clear(vuk)

	requested := cloneWorkingItems(items)
	defer releasePlaintext(nil, requested)
	// The sealed and reopened form is the wire form, not the caller's exact
	// in-memory slice shape. NewItemDatabase/ReadItemDatabase canonicalize
	// representational differences the wire does not preserve (notably a
	// non-nil empty Sections, History or Passkeys collection versus nil), so
	// final verification compares content rather than incidental nilness.
	canonicalItems, err := canonicalWorkingItems(metadata, requested)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	defer releasePlaintext(nil, canonicalItems)

	prevDigest, err := workingPrevDigest(oldFile)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	defer clearSlice(prevDigest)
	if oldFile.Header.ContentSeq == math.MaxUint64 {
		return WorkingReceipt{}, fmt.Errorf("%w: content sequence cannot be incremented", ErrWorkingUpdateRejected)
	}
	opID, err := newWorkingOpID(oldFile.Header.OpID)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	draft := workingDraft(oldFile, deviceID, opID, prevDigest)
	defer clear(draft.Header.PolicyDigest)

	sealed, err := vault.SealAuthenticatedItems(draft, metadata, requested, checkpoint, vuk, authorPrivateKey)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	defer clearSlice(sealed)
	if err := workingContextError(ctx); err != nil {
		return WorkingReceipt{}, err
	}

	newFile, newDB, err := vaultfile.OpenAuthenticatedFile(sealed, checkpoint, deviceID, identity)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	defer releaseFile(newFile)
	defer releaseDatabase(newDB)
	newMetadata, newItems, err := vault.ReadItemDatabase(newDB)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	defer releasePlaintext(newMetadata, newItems)
	if err := verifySealedWorking(oldFile, newFile, deviceID, prevDigest, opID, metadata, newMetadata, canonicalItems, newItems); err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	if err := workingContextError(ctx); err != nil {
		return WorkingReceipt{}, err
	}

	digest, err := vaultfile.FileDigest(newFile)
	if err != nil {
		return WorkingReceipt{}, workingReject(err)
	}
	receipt := WorkingReceipt{
		OperationID: opID,
		ContentSeq:  newFile.Header.ContentSeq,
		Generation:  expectedGeneration + 1,
		FileDigest:  digest,
	}

	// The last context check before the only durable write. The CAS itself
	// does not accept a context.
	if err := workingContextError(ctx); err != nil {
		return WorkingReceipt{}, err
	}
	journalErr := journal.UpdateWorking(expectedGeneration, sealed)
	if journalErr != nil {
		if isWorkingJournalRejection(journalErr) {
			return WorkingReceipt{}, fmt.Errorf("%w: %w", ErrWorkingUpdateRejected, journalErr)
		}
		return receipt, fmt.Errorf("%w: %w", ErrWorkingUpdateOutcomeUnknown, journalErr)
	}
	// The transaction is committed. A cancellation observed now cannot roll
	// it back: report the committed state with a reconciliation receipt,
	// never a guarantee that nothing was written.
	if err := ctx.Err(); err != nil {
		return receipt, fmt.Errorf("%w: %w", ErrWorkingUpdateCommitted, err)
	}
	return receipt, nil
}

// workingContextError checks ctx, classifying a nil or cancelled context as a
// definite rejection. A context sentinel remains reachable with errors.Is.
func workingContextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrWorkingUpdateRejected)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrWorkingUpdateRejected, err)
	}
	return nil
}

// checkWorkingInputs validates the non-context arguments before any journal
// read. The checkpoint's shape and every cryptographic binding are checked by
// the vaultfile paths this function calls.
func checkWorkingInputs(journal *vaultfilejournal.Journal, items []vault.Item, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity, authorPrivateKey ed25519.PrivateKey) error {
	if journal == nil || checkpoint == nil || identity == nil {
		return fmt.Errorf("%w: nil journal, checkpoint or identity", ErrWorkingUpdateRejected)
	}
	if deviceID == "" {
		return fmt.Errorf("%w: empty device ID", ErrWorkingUpdateRejected)
	}
	if len(authorPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: malformed author private key", ErrWorkingUpdateRejected)
	}
	if items == nil {
		// A non-nil empty slice is meaningful (clear all items); nil is not.
		return fmt.Errorf("%w: nil item slice", ErrWorkingUpdateRejected)
	}
	return nil
}

// workingReject wraps a definite failure in ErrWorkingUpdateRejected without
// hiding the underlying cause from errors.Is and errors.Unwrap.
func workingReject(err error) error {
	if err == nil {
		return ErrWorkingUpdateRejected
	}
	return fmt.Errorf("%w: %w", ErrWorkingUpdateRejected, err)
}

// workingCurrentPolicy parses the last (current) signed policy proof's
// canonical Document into an independent deep snapshot and binds it explicitly
// to the authenticated Header. It never returns the proof's own Policy value,
// whose slices alias the File.
func workingCurrentPolicy(file *vaultfile.File) (*vaultfile.Policy, error) {
	if file == nil || len(file.SignedPolicyProofs) == 0 {
		return nil, errWorkingVerificationMismatch
	}
	proof := &file.SignedPolicyProofs[len(file.SignedPolicyProofs)-1]
	current, err := vaultfile.ParsePolicyDocument(proof.Document)
	if err != nil {
		return nil, err
	}
	if current.VaultID != file.Header.VaultID ||
		current.PolicySeq != file.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(current), file.Header.PolicyDigest) {
		return nil, vaultfile.Err("", vaultfile.CodeHeaderMismatch)
	}
	return current, nil
}

// workingEpochVUK recovers the current epoch VUK for deviceID. The recipient
// and device are resolved only in the authenticated policy snapshot, never in
// the carried DeviceSlot.Recipient. OpenVUKForDevice independently requires
// the slot device, slot recipient and identity recipient to agree and checks
// the authenticated VUK context.
func workingEpochVUK(file *vaultfile.File, current *vaultfile.Policy, deviceID string, identity *age.X25519Identity) ([]byte, error) {
	if file == nil || current == nil {
		return nil, errWorkingVerificationMismatch
	}
	var dev *vaultfile.Device
	for i := range current.Devices {
		if current.Devices[i].DeviceID == deviceID {
			dev = &current.Devices[i]
			break
		}
	}
	if dev == nil {
		return nil, fmt.Errorf("%w: device is absent from the authenticated current policy", errWorkingVerificationMismatch)
	}
	var slot *vaultfile.DeviceSlot
	for i := range file.VUKDeviceSlots {
		if file.VUKDeviceSlots[i].DeviceID == deviceID {
			slot = &file.VUKDeviceSlots[i]
			break
		}
	}
	if slot == nil {
		return nil, errWorkingVerificationMismatch
	}
	return vaultfile.OpenVUKForDevice(*slot, current.VaultID, file.Header.KeyEpoch, deviceID, dev.AgeEncryptionKey, identity)
}

// workingPrevDigest computes vaultfile.FileDigest of the old authenticated file
// and decodes its lowercase hex into the raw 32-byte value the Header's
// PrevDigest carries. The digest function already applies the DomainFileDigest
// preimage; no raw SHA-256 is performed here.
func workingPrevDigest(file *vaultfile.File) ([]byte, error) {
	digest, err := vaultfile.FileDigest(file)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != 32 {
		return nil, errWorkingVerificationMismatch
	}
	return raw, nil
}

// newWorkingOpID returns a fresh, valid, lowercase-hex operation ID that is
// different from the old one.
func newWorkingOpID(old string) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			clear(random)
			return "", err
		}
		id := "op-" + hex.EncodeToString(random)
		clear(random)
		if id != old {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: could not generate a fresh operation ID", errWorkingVerificationMismatch)
}

// workingDraft builds the new sealed draft without touching the old File. The
// caller's items are not part of the draft; they are supplied to
// SealAuthenticatedItems separately.
func workingDraft(old *vaultfile.File, deviceID, opID string, prevDigest []byte) *vaultfile.File {
	return &vaultfile.File{
		Format:  old.Format,
		Version: old.Version,
		Header: vaultfile.Header{
			VaultID:        old.Header.VaultID,
			KeyEpoch:       old.Header.KeyEpoch,
			ContentSeq:     old.Header.ContentSeq + 1,
			PrevDigest:     prevDigest,
			OpID:           opID,
			PolicySeq:      old.Header.PolicySeq,
			PolicyDigest:   bytes.Clone(old.Header.PolicyDigest),
			AuthorDeviceID: deviceID,
		},
		SignedPolicyProofs: append([]vaultfile.SignedPolicy(nil), old.SignedPolicyProofs...),
		ContentEncoding:    old.ContentEncoding,
	}
}

// verifySealedWorking checks the independently reopened sealed working file
// against the old file and the exact requested content.
func verifySealedWorking(oldFile, newFile *vaultfile.File, deviceID string, prevDigest []byte, opID string, metadata, newMetadata []byte, items, newItems []vault.Item) error {
	if oldFile == nil || newFile == nil {
		return errWorkingVerificationMismatch
	}
	if newFile.Header.VaultID != oldFile.Header.VaultID ||
		newFile.Header.KeyEpoch != oldFile.Header.KeyEpoch ||
		newFile.Header.PolicySeq != oldFile.Header.PolicySeq ||
		!bytes.Equal(newFile.Header.PolicyDigest, oldFile.Header.PolicyDigest) {
		return fmt.Errorf("%w: vault, epoch or policy continuity", errWorkingVerificationMismatch)
	}
	if newFile.Header.ContentSeq != oldFile.Header.ContentSeq+1 {
		return fmt.Errorf("%w: content sequence is not old+1", errWorkingVerificationMismatch)
	}
	if !bytes.Equal(newFile.Header.PrevDigest, prevDigest) {
		return fmt.Errorf("%w: previous digest is not the old file digest", errWorkingVerificationMismatch)
	}
	if newFile.Header.OpID != opID || newFile.Header.OpID == oldFile.Header.OpID {
		return fmt.Errorf("%w: operation ID is not the fresh requested one", errWorkingVerificationMismatch)
	}
	if newFile.Header.AuthorDeviceID != deviceID {
		return fmt.Errorf("%w: author device is not the caller device", errWorkingVerificationMismatch)
	}
	if !sameSignedProofs(oldFile.SignedPolicyProofs, newFile.SignedPolicyProofs) {
		return fmt.Errorf("%w: signed policy proofs were not preserved", errWorkingVerificationMismatch)
	}
	if !bytes.Equal(metadata, newMetadata) {
		return fmt.Errorf("%w: metadata differs from the preserved old metadata", errWorkingVerificationMismatch)
	}
	if !sameWorkingItems(items, newItems) {
		return fmt.Errorf("%w: reopened items differ from the requested items", errWorkingVerificationMismatch)
	}
	return nil
}

// cloneWorkingItems deep-copies the caller's complete item list. A non-nil
// empty slice stays non-nil; a nil slice is rejected earlier.
func cloneWorkingItems(items []vault.Item) []vault.Item {
	out := make([]vault.Item, len(items))
	for i := range items {
		out[i] = vault.CloneItem(items[i])
	}
	return out
}

// canonicalWorkingItems returns the exact item representation
// NewItemDatabase followed by ReadItemDatabase produces for the request. It
// normalizes representational differences the KDBX wire does not preserve,
// such as a non-nil empty collection versus nil, so final verification does
// not reject a valid update over incidental Go slice shape. The temporary
// database is released here; the returned items are fresh caller-owned copies.
func canonicalWorkingItems(metadata []byte, items []vault.Item) ([]vault.Item, error) {
	db, err := vault.NewItemDatabase(metadata, items)
	if err != nil {
		return nil, err
	}
	defer releaseDatabase(db)
	canonicalMetadata, canonicalItems, err := vault.ReadItemDatabase(db)
	if err != nil {
		return nil, err
	}
	clearSlice(canonicalMetadata)
	return canonicalItems, nil
}

// isWorkingJournalRejection reports whether err proves UpdateWorking did not
// commit. Every other journal error may have committed.
func isWorkingJournalRejection(err error) bool {
	return errors.Is(err, vaultfilejournal.ErrStateGenerationMismatch) ||
		errors.Is(err, vaultfilejournal.ErrStateGenerationOverflow) ||
		errors.Is(err, vaultfilejournal.ErrEmpty) ||
		errors.Is(err, vaultfilejournal.ErrCorrupt) ||
		errors.Is(err, vaultfilejournal.ErrInvalid) ||
		errors.Is(err, vaultfilejournal.ErrClosed)
}

// sameSignedProofs reports whether the reopened file carries the same signed
// policy proofs, documents and signatures in the same order. The proof Policy
// value is bound to Document by the parser and chain verifier, so comparing the
// canonical document bytes, sequence and signature is sufficient.
func sameSignedProofs(a, b []vaultfile.SignedPolicy) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Policy.PolicySeq != b[i].Policy.PolicySeq ||
			a[i].SignerID != b[i].SignerID ||
			a[i].Alg != b[i].Alg ||
			!bytes.Equal(a[i].Document, b[i].Document) ||
			!bytes.Equal(a[i].Sig, b[i].Sig) {
			return false
		}
	}
	return true
}

// sameWorkingItems compares two item slices with their full in-memory shape,
// including nil versus non-nil optional slices and byte buffers.
func sameWorkingItems(a, b []vault.Item) bool {
	return reflect.DeepEqual(a, b)
}
