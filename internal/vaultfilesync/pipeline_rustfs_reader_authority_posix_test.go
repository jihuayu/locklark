//go:build darwin || linux

package vaultfilesync

// Issue #122 reader-authority acceptance against the real local RustFS
// provider.
//
// This is the negative companion to TestPipelinePublishThirdWriterOnRustFS and
// the two-device RustFS tests. It does not exercise transport credential
// scoping and it does not add a second writer path. One synthetic policy
// contains a genuine writer (the package fixture device) and a distinct,
// genuinely read-capable vault reader with its own real age identity and real
// Ed25519 content-signing key. The reader opens the exact ciphertext and
// revision stored remotely, then calls the real production local working-edit
// and sealed-snapshot entrypoint with its own signing identity and a complete
// edited item list. The vault authorization gate must reject the reader with
// the typed content-author code before any journal write, prepared record or
// backend write. The exact remote bytes and opaque revision and the reader's
// durable journal state must remain unchanged.
//
// The same test then runs the explicit control on the same policy, bucket,
// prefix, object and provider: the genuine writer edits locally, seals its own
// successor and publishes it through the production coordinator and a real
// conditional write. That proves the backend transport accepts an authorized
// writer operation, so the reader refusal is vault authority and not transport
// inability.
//
// The test is opt-in and local-only. It uses the same pinned RustFS environment,
// credentials, TLS guard, unique bucket ownership and cleanup as
// TestPipelinePublishThirdWriterOnRustFS; see pipeline_rustfs_posix_test.go.
// It never contacts a cloud or external endpoint and is skipped unless
// RUSTFS_SMOKE_ENABLE=1 plus the documented endpoint, CA and private credential
// file are supplied. It asserts only typed outcomes and never prints provider
// errors, object bytes, revisions or fixture contents.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"github.com/jihuayu/locklark/pkg/vaultfilepublish"
)

const (
	readerAuthorityDeviceID    = "device-3"
	readerAuthorityPrincipalID = "reader"
	readerAuthorityPrefix      = "reader-authority-pipeline"

	readerAuthorityReaderTitle = "Reader attempted local edit"
	readerAuthorityWriterTitle = "Writer control edit"
)

// readerAuthorityMaterial is one authenticated synthetic policy and its real
// key material. The writer keys are the package fixture's existing device-1
// keys. Only the reader's distinct device, age identity and content-signing key
// are generated here.
type readerAuthorityMaterial struct {
	policy   *vaultfile.Policy
	document []byte
	pin      *vaultfile.PolicyCheckpoint

	writerID       string
	writerIdentity *age.X25519Identity
	writerSigning  ed25519.PrivateKey

	readerID       string
	readerIdentity *age.X25519Identity
	readerSigning  ed25519.PrivateKey
}

// newReaderAuthorityMaterial reuses the package's static fixture policy,
// writer keys and checkpoint helper. It adds exactly one reader principal and
// one reader device, with real generated key material, then validates the
// resulting policy. The reader's signing key is recorded in the authenticated
// policy even though its principal has only the reader role, so the later
// refusal cannot be attributed to a wrong key or an unreadable device slot.
func newReaderAuthorityMaterial(t *testing.T) *readerAuthorityMaterial {
	t.Helper()
	p, writerIdentity, writerSigning := fixtureInputs(t)
	writerID := fixtureDeviceID
	readerIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic reader age identity failed: %s", rustfsPipelineSafeError(err))
	}
	readerPublic, readerSigning, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic reader signing key failed: %s", rustfsPipelineSafeError(err))
	}
	p.Readers = append(p.Readers, vaultfile.Member{
		PrincipalID: readerAuthorityPrincipalID,
		Label:       "Synthetic vault reader",
	})
	p.Devices = append(p.Devices, vaultfile.Device{
		DeviceID:          readerAuthorityDeviceID,
		PrincipalID:       readerAuthorityPrincipalID,
		Label:             "Synthetic reader device",
		ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: readerPublic},
		AgeEncryptionKey:  readerIdentity.Recipient().String(),
	})
	if err := vaultfile.ValidatePolicy(p); err != nil {
		t.Fatalf("synthetic reader-authority policy is invalid: %s", rustfsPipelineSafeError(err))
	}
	document, err := vaultfile.EncodePolicyDocument(p)
	if err != nil {
		t.Fatalf("encode synthetic reader-authority policy failed: %s", rustfsPipelineSafeError(err))
	}
	material := &readerAuthorityMaterial{
		policy:         p,
		document:       document,
		pin:            fixturePin(t, p),
		writerID:       writerID,
		writerIdentity: writerIdentity,
		writerSigning:  writerSigning,
		readerID:       readerAuthorityDeviceID,
		readerIdentity: readerIdentity,
		readerSigning:  readerSigning,
	}
	if material.writerID == material.readerID {
		t.Fatal("synthetic writer and reader device IDs are not distinct")
	}
	if !contentProposalCanAuthor(material.policy, material.writerID) {
		t.Fatal("synthetic writer is not authorized to author content")
	}
	if !readerAuthorityDeviceMatches(material.policy, material.writerID,
		material.writerIdentity.Recipient().String(), material.writerSigning.Public().(ed25519.PublicKey)) {
		t.Fatal("synthetic writer device does not carry the fixture writer key material")
	}
	if contentProposalCanAuthor(material.policy, material.readerID) {
		t.Fatal("synthetic reader unexpectedly holds writer authority")
	}
	if !readerAuthorityPrincipalIsReaderOnly(material.policy, readerAuthorityPrincipalID) {
		t.Fatal("synthetic reader principal unexpectedly holds a writer-or-stronger role")
	}
	if !readerAuthorityDeviceMatches(material.policy, material.readerID,
		material.readerIdentity.Recipient().String(), material.readerSigning.Public().(ed25519.PublicKey)) {
		t.Fatal("synthetic reader device does not carry the generated reader key material")
	}
	if bytes.Equal(material.readerSigning.Public().(ed25519.PublicKey), material.writerSigning.Public().(ed25519.PublicKey)) {
		t.Fatal("synthetic writer and reader do not have distinct signing keys")
	}
	if material.writerIdentity.Recipient().String() == material.readerIdentity.Recipient().String() {
		t.Fatal("synthetic writer and reader do not have distinct age identities")
	}
	return material
}

// readerAuthorityPrincipalIsReaderOnly reports whether principal is a reader
// and is absent from every writer-or-stronger role and the owner root.
func readerAuthorityPrincipalIsReaderOnly(policy *vaultfile.Policy, principal string) bool {
	if policy == nil {
		return false
	}
	found := false
	for _, reader := range policy.Readers {
		if reader.PrincipalID == principal {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, role := range [][]vaultfile.Member{policy.Writers, policy.Admins, policy.Owners} {
		for _, member := range role {
			if member.PrincipalID == principal {
				return false
			}
		}
	}
	for _, owner := range policy.OwnerRoot.Owners {
		if owner.PrincipalID == principal {
			return false
		}
	}
	return true
}

// readerAuthorityDeviceMatches requires deviceID to name exactly one policy
// device carrying the supplied age recipient and content-signing public key.
func readerAuthorityDeviceMatches(policy *vaultfile.Policy, deviceID, recipient string, signingKey ed25519.PublicKey) bool {
	if policy == nil || deviceID == "" || recipient == "" || len(signingKey) != ed25519.PublicKeySize {
		return false
	}
	matched := 0
	for i := range policy.Devices {
		device := &policy.Devices[i]
		if device.DeviceID != deviceID {
			continue
		}
		if device.AgeEncryptionKey == recipient && device.ContentSigningKey.Alg == vaultfile.SigAlgEd25519 &&
			bytes.Equal(device.ContentSigningKey.PublicKey, signingKey) {
			matched++
		}
	}
	return matched == 1
}

// readerAuthoritySealed produces the synthetic baseline sealed under the one
// authenticated policy. It then independently opens the result as both the
// writer and the reader, so the reader is known to be genuinely read-capable
// before any provider interaction.
func readerAuthoritySealed(t *testing.T, material *readerAuthorityMaterial) []byte {
	t.Helper()
	draft := fixtureDraft(t, material.policy)
	draft.SignedPolicyProofs[0].Document = bytes.Clone(material.document)
	sealed, err := vaultfile.SealAuthenticatedFile(draft, itemDatabase(t), material.pin, makeVUK(t), material.writerSigning)
	if err != nil {
		t.Fatalf("seal synthetic reader-authority baseline failed: %s", rustfsPipelineSafeError(err))
	}
	if bytes.Contains(sealed, []byte("synthetic-password")) {
		t.Fatal("synthetic reader-authority baseline ciphertext contains a plaintext marker")
	}
	for _, key := range []struct {
		deviceID string
		identity *age.X25519Identity
	}{
		{material.writerID, material.writerIdentity},
		{material.readerID, material.readerIdentity},
	} {
		file, db, err := vaultfile.OpenAuthenticatedFile(sealed, material.pin, key.deviceID, key.identity)
		if err != nil {
			t.Fatalf("synthetic baseline does not open for an expected device: %s", rustfsPipelineSafeError(err))
		}
		metadata, items, err := vault.ReadItemDatabase(db)
		releaseDatabase(db)
		releaseFile(file)
		if err != nil {
			t.Fatalf("synthetic baseline item database is unreadable: %s", rustfsPipelineSafeError(err))
		}
		releasePlaintext(metadata, items)
	}
	return sealed
}

// readerAuthorityRemote creates the unique provider object through the real
// backend once and returns the tracking read handle and the exact sealed
// baseline bytes.
func readerAuthorityRemote(t *testing.T, backend vaultfilebackend.Backend, sealed []byte) *trackingBackend {
	t.Helper()
	remote := &trackingBackend{Backend: backend}
	if err := remote.CreateIfAbsent(context.Background(), remoteName, sealed); err != nil {
		t.Fatalf("seed synthetic reader-authority remote failed: %s", rustfsPipelineSafeError(err))
	}
	return remote
}

// readerAuthorityOpen performs the complete caller-pinned authenticated open
// and item-database read for one device, exactly as production does. The
// returned plaintext is released at test cleanup.
func readerAuthorityOpen(t *testing.T, encoded []byte, material *readerAuthorityMaterial, deviceID string, identity *age.X25519Identity) (*vaultfile.File, []vault.Item) {
	t.Helper()
	file, db, err := vaultfile.OpenAuthenticatedFile(encoded, material.pin, deviceID, identity)
	if err != nil {
		t.Fatalf("authenticated read failed: %s", rustfsPipelineSafeError(err))
	}
	defer releaseDatabase(db)
	metadata, items, err := vault.ReadItemDatabase(db)
	if err != nil {
		releaseFile(file)
		t.Fatalf("authenticated item database read failed: %s", rustfsPipelineSafeError(err))
	}
	t.Cleanup(func() {
		releaseFile(file)
		releasePlaintext(metadata, items)
	})
	return file, items
}

// readerAuthorityReplace changes one fixture item's title after requiring a
// unique match and an actual change. Failure text contains no item values.
func readerAuthorityReplace(t *testing.T, items []vault.Item, id, title string) []vault.Item {
	t.Helper()
	found := -1
	for i := range items {
		if items[i].ID != id {
			continue
		}
		if found >= 0 {
			t.Fatal("synthetic fixture item ID is duplicated")
		}
		found = i
	}
	if found < 0 || items[found].Title == title {
		t.Fatal("synthetic fixture item is absent or the edit would be a no-op")
	}
	out := append([]vault.Item(nil), items...)
	out[found].Title = title
	return out
}

// readerAuthorityLoadState loads the complete durable local state.
func readerAuthorityLoadState(t *testing.T, journal *vaultfilejournal.Journal) vaultfilejournal.State {
	t.Helper()
	state, err := journal.LoadState()
	if err != nil {
		t.Fatalf("load local journal state failed: %s", readerAuthoritySafeError(err))
	}
	return state
}

// readerAuthorityRequireState proves the complete journal state is unchanged.
func readerAuthorityRequireState(t *testing.T, got, want vaultfilejournal.State) {
	t.Helper()
	if got.Generation != want.Generation ||
		got.RemoteRevision != want.RemoteRevision ||
		!bytes.Equal(got.BaseBytes, want.BaseBytes) ||
		!bytes.Equal(got.WorkingBytes, want.WorkingBytes) {
		t.Fatal("durable local journal state changed")
	}
}

// readerAuthorityRequireNoPending proves the journal has neither a legacy
// proposal nor a prepared proposal.
func readerAuthorityRequireNoPending(t *testing.T, journal *vaultfilejournal.Journal) {
	t.Helper()
	if _, err := journal.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("journal has an unexpected prepared record: %s", readerAuthoritySafeError(err))
	}
	if _, err := journal.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("journal has an unexpected legacy record: %s", readerAuthoritySafeError(err))
	}
}

// readerAuthorityPullVerifier authenticates a pulled value and its item
// database under one device. It is the only trust decision handed to the
// production publish coordinator.
func readerAuthorityPullVerifier(material *readerAuthorityMaterial, deviceID string, identity *age.X25519Identity) vaultfilepublish.PullVerifier {
	return func(_ context.Context, data []byte, _ vaultfilebackend.Revision) error {
		file, db, err := vaultfile.OpenAuthenticatedFile(data, material.pin, deviceID, identity)
		if err != nil {
			return err
		}
		defer releaseFile(file)
		defer releaseDatabase(db)
		metadata, items, err := vault.ReadItemDatabase(db)
		releasePlaintext(metadata, items)
		return err
	}
}

// readerAuthoritySafeError classifies an error without printing any wrapped
// provider message or value. Vault-file structural codes are constants.
func readerAuthoritySafeError(err error) string {
	if err == nil {
		return "nil"
	}
	var vaultErr *vaultfile.Error
	if errors.As(err, &vaultErr) {
		if vaultErr.Path == "" {
			return "vaultfile " + vaultErr.Code
		}
		return "vaultfile " + vaultErr.Code + " at " + vaultErr.Path
	}
	switch {
	case errors.Is(err, ErrWorkingUpdateRejected):
		return "working update rejected"
	case errors.Is(err, ErrWorkingUpdateCommitted):
		return "working update committed"
	case errors.Is(err, ErrWorkingUpdateOutcomeUnknown):
		return "working update outcome unknown"
	case errors.Is(err, ErrVerify):
		return "authenticated remote rejection"
	case errors.Is(err, ErrJournal):
		return "local journal rejection"
	case errors.Is(err, ErrRead):
		return "provider read rejection"
	case errors.Is(err, vaultfilepublish.ErrVerification):
		return "publish verification rejection"
	case errors.Is(err, vaultfilepublish.ErrStaleBase):
		return "publish stale base"
	case errors.Is(err, vaultfilepublish.ErrConflict):
		return "publish conflict"
	case errors.Is(err, vaultfilepublish.ErrUnknownReview):
		return "publish outcome needs review"
	case errors.Is(err, vaultfilepublish.ErrUnknownWrite):
		return "publish outcome unknown"
	case errors.Is(err, vaultfilejournal.ErrEmpty):
		return "journal empty"
	case errors.Is(err, vaultfilejournal.ErrStateMismatch):
		return "journal state mismatch"
	case errors.Is(err, vaultfilejournal.ErrPendingRecords):
		return "journal pending records"
	}
	return rustfsPipelineSafeError(err)
}

// readerAuthorityRemoteRead reads the exact current provider pair through the
// embedded production backend, not through any tracking observation.
func readerAuthorityRemoteRead(t *testing.T, remote *trackingBackend) vaultfilebackend.ReadResult {
	t.Helper()
	read, err := remote.readPortable(context.Background(), remoteName)
	if err != nil {
		t.Fatalf("read current provider object failed: %s", rustfsPipelineSafeError(err))
	}
	if !read.Revision.Zero() {
		return read
	}
	t.Fatal("provider read returned a zero revision")
	return vaultfilebackend.ReadResult{}
}

// TestPipelineReaderCannotPublishOnRustFS is the opt-in real-provider
// reader-authority checkpoint. See the file comment for its exact scope.
func TestPipelineReaderCannotPublishOnRustFS(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	material := newReaderAuthorityMaterial(t)

	// Separate production S3 handles address the same unique bucket and
	// prefix, exactly as the existing RustFS pipeline tests do.
	readerBackend := env.newBackendAt(t, bucket, readerAuthorityPrefix)
	writerBackend := env.newBackendAt(t, bucket, readerAuthorityPrefix)
	sealed := readerAuthoritySealed(t, material)
	readerRemote := readerAuthorityRemote(t, readerBackend, sealed)

	// The reader opens the exact remotely stored ciphertext and current
	// revision through the complete authenticated read path. The author of the
	// baseline is the genuine writer, while the reader device is the distinct
	// reader principal.
	base := readerAuthorityRemoteRead(t, readerRemote)
	if !bytes.Equal(base.Bytes, sealed) {
		t.Fatal("seeded provider bytes are not the exact synthetic baseline")
	}
	baseFile, baseItems := readerAuthorityOpen(t, base.Bytes, material, material.readerID, material.readerIdentity)
	if baseFile.Header.AuthorDeviceID != material.writerID {
		t.Fatal("remote baseline author is not the synthetic writer")
	}
	if len(baseItems) != 2 {
		t.Fatalf("remote baseline item count = %d, want 2", len(baseItems))
	}

	// Bootstrap is the production authenticated pull into the reader's durable
	// local journal. It records exactly the provider pair just read.
	readerJournal := openNewJournal(t)
	receipt, err := Bootstrap(context.Background(), readerRemote, readerJournal, remoteName,
		material.pin, material.readerID, material.readerIdentity)
	if err != nil {
		t.Fatalf("reader bootstrap failed: %s", readerAuthoritySafeError(err))
	}
	if receipt.Generation != 0 || receipt.RemoteRevision != base.Revision {
		t.Fatal("reader bootstrap receipt is not the exact current provider revision at generation zero")
	}
	readerState := readerAuthorityLoadState(t, readerJournal)
	readerAuthorityRequireState(t, readerState,
		vaultfilejournal.State{BaseBytes: base.Bytes, RemoteRevision: base.Revision, WorkingBytes: base.Bytes})
	readerAuthorityRequireNoPending(t, readerJournal)

	// The exact production local edit and sealed-snapshot entrypoint. It
	// authenticates the current working file, resolves the reader's own VUK
	// slot and policy device, and asks the vault-file author gate to seal a
	// complete successor signed by the reader. That gate must reject the
	// read-only principal before the journal CAS. The product title-edit path
	// enforces the same writer-only role before its preparation step; this is
	// the owning provider-backed local edit API, not a test-only gate.
	readerEdit := readerAuthorityReplace(t, baseItems, "login-1", readerAuthorityReaderTitle)
	workingReceipt, err := UpdateWorkingItems(context.Background(), readerJournal, readerState.Generation,
		readerEdit, material.pin, material.readerID, material.readerIdentity, material.readerSigning)
	if !errors.Is(err, ErrWorkingUpdateRejected) {
		t.Fatalf("reader local edit returned the wrong error class: %s", readerAuthoritySafeError(err))
	}
	if errors.Is(err, ErrWorkingUpdateCommitted) || errors.Is(err, ErrWorkingUpdateOutcomeUnknown) {
		t.Fatalf("reader local edit has an ambiguous outcome: %s", readerAuthoritySafeError(err))
	}
	var vaultErr *vaultfile.Error
	if !errors.As(err, &vaultErr) || vaultErr.Code != vaultfile.CodeAuthorSigningKeyMismatch ||
		vaultErr.Path != "content_signature" {
		t.Fatalf("reader local edit did not fail at the typed content-author gate: %s", readerAuthoritySafeError(err))
	}
	if workingReceipt != (WorkingReceipt{}) {
		t.Fatal("reader local edit returned a non-zero working receipt")
	}

	// The reader's own durable journal is unchanged and holds no prepared or
	// legacy proposal, so no valid conditional publish could start from it.
	afterReader := readerAuthorityLoadState(t, readerJournal)
	readerAuthorityRequireState(t, afterReader, readerState)
	readerAuthorityRequireNoPending(t, readerJournal)

	// The provider still holds the exact current bytes and revision.
	unchanged := readerAuthorityRemoteRead(t, readerRemote)
	if unchanged.Revision != base.Revision || !bytes.Equal(unchanged.Bytes, base.Bytes) {
		t.Fatal("reader local edit changed the provider bytes or revision")
	}

	// Close and reopen the reader journal before the writer control, proving
	// the unchanged state and absence of pending records are durable.
	readerJournalPath := journalPath(t, readerJournal)
	closeNow(t, readerJournal)
	reopenedReader := openJournalAt(t, readerJournalPath)
	readerAuthorityRequireState(t, readerAuthorityLoadState(t, reopenedReader), readerState)
	readerAuthorityRequireNoPending(t, reopenedReader)

	// Explicit writer control on the same policy, bucket, prefix and object.
	// The genuine writer runs the same local edit/coordination path and its
	// real conditional write must succeed, proving the provider transport
	// accepts an authorized writer operation on this exact profile.
	writerJournal := openNewJournal(t)
	readerAuthorityWriterControl(t, writerBackend, writerJournal, material, base)
}

// readerAuthorityWriterControl proves the same underlying provider profile
// accepts a complete authorized-writer edit, prepare, conditional publish and
// durable acknowledgement. It is a control only; the reader path above is the
// acceptance under test.
func readerAuthorityWriterControl(t *testing.T, backend vaultfilebackend.Backend, journal *vaultfilejournal.Journal, material *readerAuthorityMaterial, base vaultfilebackend.ReadResult) {
	t.Helper()
	ctx := context.Background()
	receipt, err := Bootstrap(ctx, backend, journal, remoteName, material.pin, material.writerID, material.writerIdentity)
	if err != nil {
		t.Fatalf("writer control bootstrap failed: %s", readerAuthoritySafeError(err))
	}
	if receipt.Generation != 0 || receipt.RemoteRevision != base.Revision {
		t.Fatal("writer control bootstrap is not the exact current provider revision")
	}
	start := readerAuthorityLoadState(t, journal)
	if !bytes.Equal(start.BaseBytes, base.Bytes) || !bytes.Equal(start.WorkingBytes, base.Bytes) {
		t.Fatal("writer control did not start from the exact provider baseline")
	}

	_, items := readerAuthorityOpen(t, start.WorkingBytes, material, material.writerID, material.writerIdentity)
	writerEdit := readerAuthorityReplace(t, items, "login-1", readerAuthorityWriterTitle)
	workingReceipt, err := UpdateWorkingItems(ctx, journal, start.Generation, writerEdit,
		material.pin, material.writerID, material.writerIdentity, material.writerSigning)
	if err != nil {
		t.Fatalf("authorized writer local edit failed: %s", readerAuthoritySafeError(err))
	}
	if workingReceipt.Generation != start.Generation+1 {
		t.Fatal("authorized writer local edit did not advance exactly one local generation")
	}
	edited := readerAuthorityLoadState(t, journal)
	if edited.Generation != workingReceipt.Generation ||
		edited.RemoteRevision != base.Revision ||
		!bytes.Equal(edited.BaseBytes, base.Bytes) ||
		bytes.Equal(edited.WorkingBytes, edited.BaseBytes) {
		t.Fatal("authorized writer local edit did not preserve the base and produce a new working snapshot")
	}
	sealed, err := vaultfile.ParseFile(edited.WorkingBytes)
	if err != nil {
		t.Fatalf("authorized writer sealed snapshot does not parse: %s", rustfsPipelineSafeError(err))
	}
	if sealed.Header.AuthorDeviceID != material.writerID {
		t.Fatal("authorized writer sealed snapshot is not authored by the writer device")
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       edited.Generation,
		OperationID:      sealed.Header.OpID,
		ExpectedRevision: edited.RemoteRevision,
		Bytes:            edited.WorkingBytes,
	}
	proposalVerifier, err := NewContentProposalVerifier(material.pin)
	if err != nil {
		t.Fatalf("writer control proposal verifier failed: %s", readerAuthoritySafeError(err))
	}
	coordinator, err := vaultfilepublish.NewCoordinator(backend, journal, remoteName, proposalVerifier)
	if err != nil {
		t.Fatalf("writer control coordinator construction failed: %s", readerAuthoritySafeError(err))
	}
	pullVerifier := readerAuthorityPullVerifier(material, material.writerID, material.writerIdentity)
	pulledBase, err := vaultfilepublish.ReadPulled(ctx, backend, remoteName, pullVerifier)
	if err != nil {
		t.Fatalf("writer control pull of the current base failed: %s", readerAuthoritySafeError(err))
	}
	if pulledBase.Revision() != base.Revision || !bytes.Equal(pulledBase.Bytes(), base.Bytes) {
		t.Fatal("writer control pull is not the exact provider baseline")
	}
	if err := coordinator.PrepareAndPublish(ctx, pulledBase, proposal, pullVerifier); err != nil {
		t.Fatalf("authorized writer conditional publish failed: %s", readerAuthoritySafeError(err))
	}
	published, err := vaultfilepublish.ReadPulled(ctx, backend, remoteName, pullVerifier)
	if err != nil {
		t.Fatalf("writer control published readback failed: %s", readerAuthoritySafeError(err))
	}
	if published.Revision() == base.Revision || !bytes.Equal(published.Bytes(), proposal.Bytes) {
		t.Fatal("authorized writer publish is not the exact proposal at a changed provider revision")
	}
	if _, err := journal.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("writer control journal still has a prepared record: %s", readerAuthoritySafeError(err))
	}
	final := readerAuthorityLoadState(t, journal)
	if final.Generation != edited.Generation ||
		final.RemoteRevision != published.Revision() ||
		!bytes.Equal(final.BaseBytes, proposal.Bytes) ||
		!bytes.Equal(final.WorkingBytes, proposal.Bytes) {
		t.Fatal("writer control durable state is not the exact acknowledged proposal")
	}
}
