package vaultfilesync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// workingItems is the complete new item list used by the positive paths. It
// carries a v1 login and a protected document attachment, so the reopened file
// exercises both strings and owned binary buffers.
func workingItems() []vault.Item {
	return []vault.Item{
		{
			ID: "working-login-1", Kind: "login", Title: "Working login",
			Username: "working-user", Password: "working-password",
			URL: "https://working.example/login", Notes: "working notes",
			CreatedAt: 100, UpdatedAt: 200,
		},
		{
			ID: "working-document-1", Kind: "document", Title: "Working document",
			Filename: "working.bin", Attachment: []byte("new attachment body"), AttachmentProtected: true,
		},
	}
}

// snapshotWorkingItems returns a deep copy of items through the real cloning
// adapter, so a later mutation of any exported item buffer or nested slice is
// visible to the comparison.
func snapshotWorkingItems(items []vault.Item) []vault.Item {
	out := make([]vault.Item, len(items))
	for i := range items {
		out[i] = vault.CloneItem(items[i])
	}
	return out
}

// openWorkingState opens encoded with the caller pin and device, reads the item
// database, and registers release of everything it owns with t.Cleanup.
func openWorkingState(t *testing.T, encoded []byte, pin *vaultfile.PolicyCheckpoint, id *age.X25519Identity) (*vaultfile.File, []byte, []vault.Item) {
	t.Helper()
	file, db, err := vaultfile.OpenAuthenticatedFile(encoded, pin, fixtureDeviceID, id)
	if err != nil {
		t.Fatalf("OpenAuthenticatedFile: %v", err)
	}
	defer releaseDatabase(db)
	metadata, items, err := vault.ReadItemDatabase(db)
	if err != nil {
		t.Fatalf("ReadItemDatabase: %v", err)
	}
	t.Cleanup(func() {
		releaseFile(file)
		releasePlaintext(metadata, items)
	})
	return file, metadata, items
}

// workingVUKForTest independently recovers the per-epoch VUK for device-1 from
// the authenticated policy document and the file's matching slot. It is used
// to prove that the update reused the same epoch key instead of rotating it.
func workingVUKForTest(t *testing.T, file *vaultfile.File, id *age.X25519Identity) []byte {
	t.Helper()
	if len(file.SignedPolicyProofs) == 0 {
		t.Fatal("file carries no policy proof")
	}
	current, err := vaultfile.ParsePolicyDocument(file.SignedPolicyProofs[len(file.SignedPolicyProofs)-1].Document)
	if err != nil {
		t.Fatalf("ParsePolicyDocument: %v", err)
	}
	var recipient string
	for i := range current.Devices {
		if current.Devices[i].DeviceID == fixtureDeviceID {
			recipient = current.Devices[i].AgeEncryptionKey
			break
		}
	}
	if recipient == "" {
		t.Fatal("authenticated policy has no fixture device recipient")
	}
	for i := range file.VUKDeviceSlots {
		if file.VUKDeviceSlots[i].DeviceID != fixtureDeviceID {
			continue
		}
		vuk, err := vaultfile.OpenVUKForDevice(file.VUKDeviceSlots[i], file.Header.VaultID, file.Header.KeyEpoch, fixtureDeviceID, recipient, id)
		if err != nil {
			t.Fatalf("OpenVUKForDevice: %v", err)
		}
		t.Cleanup(func() { clear(vuk) })
		return vuk
	}
	t.Fatal("file has no fixture device VUK slot")
	return nil
}

// wantWorkingReceiptZero asserts the definite-rejection receipt contract.
func wantWorkingReceiptZero(t *testing.T, r WorkingReceipt) {
	t.Helper()
	if r != (WorkingReceipt{}) {
		t.Fatalf("error path returned a non-zero WorkingReceipt: %+v", r)
	}
}

// wantWorkingStateUnchanged asserts every field of the stored state.
func wantWorkingStateUnchanged(t *testing.T, j *vaultfilejournal.Journal, want vaultfilejournal.State) {
	t.Helper()
	got, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after rejected update: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rejected update changed the stored state: got %+v want %+v", got, want)
	}
}

// TestUpdateWorkingItemsSuccess covers one complete local update: a real
// reopen under the caller pin and device, full header continuity, preserved
// metadata, the same current policy and epoch VUK, exact journal state, no
// backend read and caller ownership of the input items.
func TestUpdateWorkingItemsSuccess(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)

	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	oldFile, oldMetadata, oldItems := openWorkingState(t, before.WorkingBytes, f.pin, f.id)
	if len(oldItems) == 0 {
		t.Fatal("fixture old working file carries no items")
	}
	readsBefore := f.remote.readCount()

	items := workingItems()
	wantItems := snapshotWorkingItems(items)
	r, err := UpdateWorkingItems(context.Background(), j, before.Generation, items, f.pin, fixtureDeviceID, f.id, signingKey)
	if err != nil {
		t.Fatalf("UpdateWorkingItems: %v", err)
	}
	if hits := f.remote.readCount(); hits != readsBefore {
		t.Fatalf("backend reads increased from %d to %d during a local update", readsBefore, hits)
	}
	if !reflect.DeepEqual(items, wantItems) {
		t.Fatal("UpdateWorkingItems mutated the caller's items")
	}

	after, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after update: %v", err)
	}
	if !bytes.Equal(after.BaseBytes, before.BaseBytes) {
		t.Fatal("update changed BaseBytes")
	}
	if after.RemoteRevision != before.RemoteRevision {
		t.Fatal("update changed RemoteRevision")
	}
	if after.Generation != before.Generation+1 {
		t.Fatalf("generation = %d, want %d", after.Generation, before.Generation+1)
	}
	if bytes.Equal(after.WorkingBytes, before.WorkingBytes) {
		t.Fatal("update did not change WorkingBytes")
	}

	newFile, newMetadata, newItems := openWorkingState(t, after.WorkingBytes, f.pin, f.id)

	// Full header continuity: everything except the derived revision, the
	// fresh op id, the incremented sequence and the linkage digest.
	oldDigestHex, err := vaultfile.FileDigest(oldFile)
	if err != nil {
		t.Fatalf("FileDigest(old): %v", err)
	}
	oldDigest, err := hex.DecodeString(oldDigestHex)
	if err != nil || len(oldDigest) != 32 {
		t.Fatalf("old file digest is not 32 raw bytes: %v", err)
	}
	if newFile.Header.VaultID != oldFile.Header.VaultID ||
		newFile.Header.KeyEpoch != oldFile.Header.KeyEpoch ||
		newFile.Header.PolicySeq != oldFile.Header.PolicySeq ||
		!bytes.Equal(newFile.Header.PolicyDigest, oldFile.Header.PolicyDigest) ||
		newFile.Header.AuthorDeviceID != fixtureDeviceID {
		t.Fatalf("header continuity lost: old %+v new %+v", oldFile.Header, newFile.Header)
	}
	if newFile.Header.ContentSeq != oldFile.Header.ContentSeq+1 {
		t.Fatalf("content sequence = %d, want %d", newFile.Header.ContentSeq, oldFile.Header.ContentSeq+1)
	}
	if !bytes.Equal(newFile.Header.PrevDigest, oldDigest) {
		t.Fatalf("prev digest = %x, want the decoded old FileDigest %x", newFile.Header.PrevDigest, oldDigest)
	}
	if newFile.Header.OpID == oldFile.Header.OpID || newFile.Header.OpID == "" {
		t.Fatal("new operation ID is not fresh")
	}
	if newFile.Header.RevisionID == "" {
		t.Fatal("reopened sealed file has no revision ID")
	}
	if !reflect.DeepEqual(newFile.SignedPolicyProofs, oldFile.SignedPolicyProofs) {
		t.Fatal("the update did not preserve every signed policy proof")
	}

	if !bytes.Equal(newMetadata, oldMetadata) {
		t.Fatalf("metadata changed: got %x want %x", newMetadata, oldMetadata)
	}
	if !reflect.DeepEqual(newItems, wantItems) {
		t.Fatalf("items were not preserved exactly:\n got %+v\nwant %+v", newItems, wantItems)
	}
	oldVUK := workingVUKForTest(t, oldFile, f.id)
	newVUK := workingVUKForTest(t, newFile, f.id)
	if !bytes.Equal(oldVUK, newVUK) {
		t.Fatal("the update changed the per-epoch VUK instead of reusing it")
	}

	// The receipt identifies the committed content and local generation.
	newDigest, err := vaultfile.FileDigest(newFile)
	if err != nil {
		t.Fatalf("FileDigest(new): %v", err)
	}
	if r.OperationID != newFile.Header.OpID || r.ContentSeq != newFile.Header.ContentSeq ||
		r.Generation != after.Generation || r.FileDigest != newDigest {
		t.Fatalf("receipt = %+v, want op %q seq %d gen %d digest %q", r, newFile.Header.OpID, newFile.Header.ContentSeq, after.Generation, newDigest)
	}

	// Close and reopen the real database: the base and revision must be
	// byte-identical and the working state must be the committed result.
	path := journalPath(t, j)
	closeNow(t, j)
	reopened := openJournalAt(t, path)
	reloaded, err := reopened.LoadState()
	if err != nil {
		t.Fatalf("reloaded LoadState: %v", err)
	}
	if !bytes.Equal(reloaded.BaseBytes, before.BaseBytes) {
		t.Fatal("reopened journal BaseBytes changed")
	}
	if reloaded.RemoteRevision != before.RemoteRevision {
		t.Fatal("reopened journal RemoteRevision changed")
	}
	if !bytes.Equal(reloaded.WorkingBytes, after.WorkingBytes) || reloaded.Generation != after.Generation {
		t.Fatal("reopened journal does not hold the committed working state")
	}

	// The caller pin and the caller device still open the committed bytes.
	_, _, again := openWorkingState(t, reloaded.WorkingBytes, f.pin, f.id)
	if !reflect.DeepEqual(again, wantItems) {
		t.Fatal("committed working bytes do not reopen with the requested items")
	}
}

// TestUpdateWorkingItemsClearsAllItems proves the documented non-nil empty
// request: it is accepted, clears every item, and preserves metadata and the
// rest of the header.
func TestUpdateWorkingItemsClearsAllItems(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	oldFile, oldMetadata, _ := openWorkingState(t, before.WorkingBytes, f.pin, f.id)

	r, err := UpdateWorkingItems(context.Background(), j, before.Generation, []vault.Item{}, f.pin, fixtureDeviceID, f.id, signingKey)
	if err != nil {
		t.Fatalf("UpdateWorkingItems with a non-nil empty slice: %v", err)
	}
	if r.Generation != 1 {
		t.Fatalf("receipt generation = %d, want 1", r.Generation)
	}
	after, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	newFile, newMetadata, newItems := openWorkingState(t, after.WorkingBytes, f.pin, f.id)
	if newItems == nil || len(newItems) != 0 {
		t.Fatalf("cleared items = %#v, want a non-nil empty slice", newItems)
	}
	if !bytes.Equal(newMetadata, oldMetadata) {
		t.Fatal("clearing all items changed the preserved metadata")
	}
	if newFile.Header.ContentSeq != oldFile.Header.ContentSeq+1 {
		t.Fatalf("content sequence = %d, want %d", newFile.Header.ContentSeq, oldFile.Header.ContentSeq+1)
	}
}

// TestUpdateWorkingItemsAcceptsEmptyOptionalCollections proves that valid
// non-nil empty Passkeys, Sections and History collections are not rejected
// merely because the KDBX wire normalizes them to nil.
func TestUpdateWorkingItemsAcceptsEmptyOptionalCollections(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	items := []vault.Item{{
		ID: "empty-collections", Kind: "login", Title: "Empty collections",
		Passkeys: [][]byte{}, Sections: []vault.ItemSection{}, History: []vault.ItemHistoryEntry{},
	}}
	wantItems := snapshotWorkingItems(items)
	if _, err := UpdateWorkingItems(context.Background(), j, before.Generation, items, f.pin, fixtureDeviceID, f.id, signingKey); err != nil {
		t.Fatalf("UpdateWorkingItems with non-nil empty collections: %v", err)
	}
	if !reflect.DeepEqual(items, wantItems) {
		t.Fatal("the update mutated the caller's empty collections")
	}
	after, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	_, _, got := openWorkingState(t, after.WorkingBytes, f.pin, f.id)
	if len(got) != 1 {
		t.Fatalf("item count = %d, want 1", len(got))
	}
	if got[0].ID != "empty-collections" || len(got[0].Passkeys) != 0 || len(got[0].Sections) != 0 || len(got[0].History) != 0 {
		t.Fatalf("reopened empty collections are not the canonical content: %+v", got[0])
	}
}

// TestUpdateWorkingItemsPreCommitCancellation proves a cancellation before the
// journal CAS writes nothing and returns a zero receipt while preserving both
// the context and rejection sentinels.
func TestUpdateWorkingItemsPreCommitCancellation(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := UpdateWorkingItems(ctx, j, before.Generation, workingItems(), f.pin, fixtureDeviceID, f.id, signingKey)
	if !errors.Is(err, ErrWorkingUpdateRejected) {
		t.Fatalf("pre-commit cancellation = %v, want ErrWorkingUpdateRejected", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-commit cancellation = %v, want context.Canceled", err)
	}
	wantWorkingReceiptZero(t, r)
	wantWorkingStateUnchanged(t, j, before)
}

// multiProofRemote builds a real sealed remote file carrying two older
// structurally valid policy proofs before the caller-pinned current proof.
// The older proofs are before the anchor, so the chain verifier ignores their
// signatures; they still exercise preservation of every carried proof.
func multiProofRemote(t *testing.T) []byte {
	t.Helper()
	p, _, signingKey := fixtureInputs(t)
	draft := fixtureDraft(t, p)
	olderIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	older := make([]vaultfile.SignedPolicy, 0, 2)
	for _, seq := range []uint64{3, 4} {
		old := *p
		old.PolicySeq = seq
		old.PrevPolicyDigest = bytes.Repeat([]byte{byte(seq)}, 32)
		// The older policy carries a different age recipient, so an
		// implementation that resolved the device from an older proof instead
		// of the authenticated current one would fail to unwrap the current
		// VUK slot.
		old.Devices = append([]vaultfile.Device(nil), p.Devices...)
		old.Devices[0].AgeEncryptionKey = olderIdentity.Recipient().String()
		doc, err := vaultfile.EncodePolicyDocument(&old)
		if err != nil {
			t.Fatalf("encode older policy %d: %v", seq, err)
		}
		older = append(older, vaultfile.SignedPolicy{
			Policy:   old,
			Document: doc,
			SignerID: p.OwnerRoot.KeyID,
			Alg:      vaultfile.PolicySigAlgEd25519,
			Sig:      make([]byte, ed25519.SignatureSize),
		})
	}
	draft.SignedPolicyProofs = append(older, draft.SignedPolicyProofs...)
	encoded, err := vaultfile.SealAuthenticatedFile(draft, itemDatabase(t), fixturePin(t, p), makeVUK(t), signingKey)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile with older proofs: %v", err)
	}
	return encoded
}

// TestUpdateWorkingItemsPreservesOlderPolicyProofs verifies that a working
// update carries every older signed policy proof through sealing and reopen,
// not only the current one.
func TestUpdateWorkingItemsPreservesOlderPolicyProofs(t *testing.T) {
	f := newFixture(t)
	multi := multiProofRemote(t)
	current, err := f.remote.Dir.Read(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("read current fixture revision: %v", err)
	}
	if err := f.remote.ReplaceIfVersion(context.Background(), remoteName, current.Revision, multi); err != nil {
		t.Fatalf("replace with multi-proof remote: %v", err)
	}
	f.bytes = multi

	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	oldFile, _, _ := openWorkingState(t, before.WorkingBytes, f.pin, f.id)
	if len(oldFile.SignedPolicyProofs) != 3 {
		t.Fatalf("fixture proof count = %d, want 3", len(oldFile.SignedPolicyProofs))
	}

	if _, err := UpdateWorkingItems(context.Background(), j, before.Generation, workingItems(), f.pin, fixtureDeviceID, f.id, signingKey); err != nil {
		t.Fatalf("UpdateWorkingItems: %v", err)
	}
	after, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after update: %v", err)
	}
	newFile, _, _ := openWorkingState(t, after.WorkingBytes, f.pin, f.id)
	if !reflect.DeepEqual(newFile.SignedPolicyProofs, oldFile.SignedPolicyProofs) {
		t.Fatal("the update did not preserve every older signed policy proof")
	}
	for i, wantSeq := range []uint64{3, 4, 5} {
		if newFile.SignedPolicyProofs[i].Policy.PolicySeq != wantSeq {
			t.Fatalf("proof %d sequence = %d, want %d", i, newFile.SignedPolicyProofs[i].Policy.PolicySeq, wantSeq)
		}
	}
}

// TestUpdateWorkingItemsStaleGeneration proves the generation CAS is final: a
// stale expected generation is rejected and the stored state is untouched.
func TestUpdateWorkingItemsStaleGeneration(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)

	// Advance the journal independently before the stale caller runs.
	if err := j.UpdateWorking(0, f.bytes); err != nil {
		t.Fatalf("UpdateWorking: %v", err)
	}
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if before.Generation != 1 {
		t.Fatalf("generation = %d, want 1", before.Generation)
	}

	r, err := UpdateWorkingItems(context.Background(), j, 0, workingItems(), f.pin, fixtureDeviceID, f.id, signingKey)
	if !errors.Is(err, ErrWorkingUpdateRejected) {
		t.Fatalf("stale update = %v, want ErrWorkingUpdateRejected", err)
	}
	if !errors.Is(err, vaultfilejournal.ErrStateGenerationMismatch) {
		t.Fatalf("stale update = %v, want the journal generation-mismatch sentinel", err)
	}
	wantWorkingReceiptZero(t, r)
	wantWorkingStateUnchanged(t, j, before)
}

// TestUpdateWorkingItemsAuthenticationFailures proves a wrong author key or a
// foreign age identity is rejected before any journal write.
func TestUpdateWorkingItemsAuthenticationFailures(t *testing.T) {
	t.Run("wrong author key", func(t *testing.T) {
		f := newFixture(t)
		j := f.openJournal(t)
		if _, err := f.bootstrap(t, context.Background(), j); err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		before, err := j.LoadState()
		if err != nil {
			t.Fatalf("LoadState: %v", err)
		}
		_, foreign, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r, err := UpdateWorkingItems(context.Background(), j, before.Generation, workingItems(), f.pin, fixtureDeviceID, f.id, foreign)
		if !errors.Is(err, ErrWorkingUpdateRejected) {
			t.Fatalf("wrong author key = %v, want ErrWorkingUpdateRejected", err)
		}
		if code := vaultfileCode(err); code != vaultfile.CodeAuthorSigningKeyMismatch {
			t.Fatalf("wrong author key failed with %q, want %q", code, vaultfile.CodeAuthorSigningKeyMismatch)
		}
		wantWorkingReceiptZero(t, r)
		wantWorkingStateUnchanged(t, j, before)
	})

	t.Run("wrong identity", func(t *testing.T) {
		f := newFixture(t)
		j := f.openJournal(t)
		if _, err := f.bootstrap(t, context.Background(), j); err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		_, _, signingKey := fixtureInputs(t)
		before, err := j.LoadState()
		if err != nil {
			t.Fatalf("LoadState: %v", err)
		}
		foreign, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		r, err := UpdateWorkingItems(context.Background(), j, before.Generation, workingItems(), f.pin, fixtureDeviceID, foreign, signingKey)
		if !errors.Is(err, ErrWorkingUpdateRejected) {
			t.Fatalf("wrong identity = %v, want ErrWorkingUpdateRejected", err)
		}
		wantWorkingReceiptZero(t, r)
		wantWorkingStateUnchanged(t, j, before)
	})
}

// TestUpdateWorkingItemsPreservesPendingRecords proves that a successful
// working update does not consume or rewrite an existing legacy proposal or
// prepared proposal, even when the prepared record's working generation is now
// older than the state.
func TestUpdateWorkingItemsPreservesPendingRecords(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)
	state0, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	legacy := vaultfilejournal.Proposal{
		Generation:       9,
		OperationID:      "op-legacy-pending",
		ExpectedRevision: state0.RemoteRevision,
		Bytes:            []byte("synthetic legacy sealed proposal"),
	}
	if err := j.Save(legacy); err != nil {
		t.Fatalf("Save legacy proposal: %v", err)
	}
	prepared := vaultfilejournal.Proposal{
		Generation:       3,
		OperationID:      "op-prepared-pending",
		ExpectedRevision: state0.RemoteRevision,
		Bytes:            state0.WorkingBytes,
	}
	if err := j.Prepare(0, prepared); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	wantLegacy, err := j.Load()
	if err != nil {
		t.Fatalf("Load legacy: %v", err)
	}
	wantPrepared, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared: %v", err)
	}

	r, err := UpdateWorkingItems(context.Background(), j, 0, workingItems(), f.pin, fixtureDeviceID, f.id, signingKey)
	if err != nil {
		t.Fatalf("UpdateWorkingItems: %v", err)
	}
	if r.Generation != 1 {
		t.Fatalf("receipt generation = %d, want 1", r.Generation)
	}

	gotLegacy, err := j.Load()
	if err != nil {
		t.Fatalf("Load legacy after update: %v", err)
	}
	if !reflect.DeepEqual(gotLegacy, wantLegacy) {
		t.Fatalf("legacy proposal changed:\n got %+v\nwant %+v", gotLegacy, wantLegacy)
	}
	gotPrepared, err := j.LoadPrepared()
	if err != nil {
		t.Fatalf("LoadPrepared after update: %v", err)
	}
	if !reflect.DeepEqual(gotPrepared, wantPrepared) {
		t.Fatalf("prepared proposal changed:\n got %+v\nwant %+v", gotPrepared, wantPrepared)
	}
	if gotPrepared.WorkingGeneration != 0 || gotPrepared.Proposal.OperationID != "op-prepared-pending" {
		t.Fatalf("prepared record was not preserved field for field: %+v", gotPrepared)
	}
	state, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.Generation != 1 || !bytes.Equal(state.BaseBytes, state0.BaseBytes) || state.RemoteRevision != state0.RemoteRevision {
		t.Fatalf("state after update = %+v, want generation 1 and preserved base/revision", state)
	}
}

// postCommitContext reports cancellation only once the journal generation has
// moved away from the value observed before the call. It therefore proves the
// cancellation was observed after the CAS committed, without sleeps or timing.
type postCommitContext struct {
	context.Context
	journal *vaultfilejournal.Journal
	before  uint64
}

func (c *postCommitContext) Err() error {
	state, err := c.journal.LoadState()
	if err == nil && state.Generation != c.before {
		return context.Canceled
	}
	return nil
}

// TestUpdateWorkingItemsPostCommitCancellation proves cancellation observed
// after the CAS returns ErrWorkingUpdateCommitted with a reconciliation
// receipt, while the journal holds the complete new state.
func TestUpdateWorkingItemsPostCommitCancellation(t *testing.T) {
	f := newFixture(t)
	j := f.openJournal(t)
	if _, err := f.bootstrap(t, context.Background(), j); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	_, _, signingKey := fixtureInputs(t)
	before, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	ctx := &postCommitContext{Context: context.Background(), journal: j, before: before.Generation}

	items := workingItems()
	wantItems := snapshotWorkingItems(items)
	r, err := UpdateWorkingItems(ctx, j, before.Generation, items, f.pin, fixtureDeviceID, f.id, signingKey)
	if !errors.Is(err, ErrWorkingUpdateCommitted) {
		t.Fatalf("post-commit cancellation = %v, want ErrWorkingUpdateCommitted", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-commit cancellation = %v, want context.Canceled", err)
	}
	if r == (WorkingReceipt{}) {
		t.Fatal("post-commit cancellation returned a zero receipt")
	}
	if r.Generation != before.Generation+1 || r.OperationID == "" || r.FileDigest == "" {
		t.Fatalf("reconciliation receipt is incomplete: %+v", r)
	}

	after, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState after committed cancellation: %v", err)
	}
	if after.Generation != before.Generation+1 {
		t.Fatalf("generation = %d, want %d", after.Generation, before.Generation+1)
	}
	if !bytes.Equal(after.BaseBytes, before.BaseBytes) || after.RemoteRevision != before.RemoteRevision {
		t.Fatal("post-commit cancellation changed the base or revision")
	}
	newFile, metadata, newItems := openWorkingState(t, after.WorkingBytes, f.pin, f.id)
	if !reflect.DeepEqual(newItems, wantItems) {
		t.Fatalf("committed items are not the requested items:\n got %+v\nwant %+v", newItems, wantItems)
	}
	if len(metadata) == 0 {
		t.Fatal("committed working file has no preserved metadata")
	}
	digest, err := vaultfile.FileDigest(newFile)
	if err != nil {
		t.Fatalf("FileDigest: %v", err)
	}
	if r.FileDigest != digest || r.ContentSeq != newFile.Header.ContentSeq || r.OperationID != newFile.Header.OpID {
		t.Fatalf("receipt %+v does not identify the committed file", r)
	}
}
