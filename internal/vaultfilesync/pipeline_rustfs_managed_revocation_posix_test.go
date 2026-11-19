//go:build darwin || linux

package vaultfilesync

// Issue #122 real-provider managed vault revocation acceptance.
//
// This is the managed policy/epoch companion to the same-policy RustFS reader,
// two-device and third-writer evidence. One synthetic authenticated owner/admin
// device rotates a real sealed baseline to a root-signed successor policy that
// removes one prior writer and its device. The rotation is produced by the
// existing vaultfile.RotateAuthenticatedFile and authenticated by the existing
// vaultfile.VerifyManagedTransition. Only a new managed-transition proposal
// admission is added; the coordinator, journal, conditional write, readback and
// acknowledgement are the production implementations.
//
// The ordinary content verifier must reject the genuine policy change even
// though the same provider credentials could write it, proving transport
// authorization is not vault authorization. The managed verifier then admits
// the exact transition and the real conditional write publishes it. After a
// fresh journal reopen and a fresh provider handle, the owner opens the exact
// observed next bytes, the removed writer can still read those bytes through
// the transport but cannot authenticate or decrypt them, and its stale
// conditional write against the old revision is refused by the now-changed
// object.
//
// The test is opt-in and local-only. It uses the same pinned RustFS
// environment, credentials, TLS guard, unique bucket ownership and cleanup as
// TestPipelinePublishThirdWriterOnRustFS; see pipeline_rustfs_posix_test.go.
// It never contacts a cloud or external endpoint and is skipped unless
// RUSTFS_SMOKE_ENABLE=1 plus the documented endpoint, CA and private credential
// file are supplied. Diagnostics name only constant categories, typed vault
// error codes at field paths, or provider error classes; they never print
// object bytes, revisions, policy or device identifiers, keys, plaintext or the
// endpoint.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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
	managedRevocationOwnerPrincipal   = "alice"
	managedRevocationFormerPrincipal  = "bob"
	managedRevocationOwnerDeviceID    = fixtureDeviceID
	managedRevocationFormerDeviceID   = "device-2"
	managedRevocationOwnerLabel       = "Synthetic owner device"
	managedRevocationFormerLabel      = "Synthetic former writer device"
	managedRevocationVaultID          = "vault-managed-revocation"
	managedRevocationPolicySeq        = uint64(7)
	managedRevocationOwnerRootKeyID   = "owner-root-managed"
	managedRevocationOldOpID          = "op-managed-revocation-old"
	managedRevocationNewOpID          = "op-managed-revocation-next"
	managedRevocationPipelinePrefix   = "managed-revocation-pipeline"
	managedRevocationBaseRevisionName = "opaque-managed-revocation-base"
)

// managedRevocationMaterial is one synthetic authenticated current policy, the
// root-signed successor that revokes one writer and its device, and the real
// key material of both devices. The owner root key is generated here because
// the static fixture's root public key has no test private key; every other
// fixture helper is reused.
type managedRevocationMaterial struct {
	policy     *vaultfile.Policy
	nextPolicy *vaultfile.Policy
	pin        *vaultfile.PolicyCheckpoint
	oldProof   vaultfile.SignedPolicy
	nextProof  vaultfile.SignedPolicy

	ownerID       string
	ownerIdentity *age.X25519Identity
	ownerSigning  ed25519.PrivateKey

	formerID       string
	formerIdentity *age.X25519Identity
}

// managedRevocationProof returns a structurally valid root-signed proof of p.
func managedRevocationProof(t *testing.T, p *vaultfile.Policy, root ed25519.PrivateKey) vaultfile.SignedPolicy {
	t.Helper()
	document, err := vaultfile.EncodePolicyDocument(p)
	if err != nil {
		t.Fatalf("encode synthetic managed policy failed: %s", rustfsPipelineSafeError(err))
	}
	proof := vaultfile.SignedPolicy{
		Document: document,
		Policy:   *p,
		SignerID: p.OwnerRoot.KeyID,
		Alg:      vaultfile.PolicySigAlgEd25519,
	}
	message := append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...)
	proof.Sig = ed25519.Sign(root, message)
	return proof
}

// managedRevocationHasDevice reports whether p records deviceID.
func managedRevocationHasDevice(p *vaultfile.Policy, deviceID string) bool {
	if p == nil {
		return false
	}
	for i := range p.Devices {
		if p.Devices[i].DeviceID == deviceID {
			return true
		}
	}
	return false
}

// newManagedRevocationMaterial builds the exact current policy (owner writer,
// admin and owner plus one prior writer) and its immediate root-signed
// successor that removes the prior writer and device. Every device has a real
// generated age identity and content-signing key, and the owner root is a real
// generated Ed25519 key used only by the test.
func newManagedRevocationMaterial(t *testing.T) *managedRevocationMaterial {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic owner root failed: %s", rustfsPipelineSafeError(err))
	}
	ownerIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic owner age identity failed: %s", rustfsPipelineSafeError(err))
	}
	ownerPublic, ownerSigning, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic owner signing key failed: %s", rustfsPipelineSafeError(err))
	}
	formerIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic former-writer age identity failed: %s", rustfsPipelineSafeError(err))
	}
	formerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic former-writer signing key failed: %s", rustfsPipelineSafeError(err))
	}

	p := &vaultfile.Policy{
		Format:           vaultfile.Format,
		Version:          vaultfile.Version,
		VaultID:          managedRevocationVaultID,
		PolicySeq:        managedRevocationPolicySeq,
		PrevPolicyDigest: bytes.Repeat([]byte{0x5a}, 32),
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID:     managedRevocationOwnerRootKeyID,
			Alg:       vaultfile.PolicySigAlgEd25519,
			PublicKey: rootPublic,
			Owners:    []vaultfile.Principal{{PrincipalID: managedRevocationOwnerPrincipal, Label: "Owner"}},
		},
		Writers: []vaultfile.Member{
			{PrincipalID: managedRevocationOwnerPrincipal, Label: "Owner"},
			{PrincipalID: managedRevocationFormerPrincipal, Label: "Former writer"},
		},
		Admins: []vaultfile.Member{{PrincipalID: managedRevocationOwnerPrincipal, Label: "Owner"}},
		Owners: []vaultfile.Member{{PrincipalID: managedRevocationOwnerPrincipal, Label: "Owner"}},
		Devices: []vaultfile.Device{
			{
				DeviceID:          managedRevocationOwnerDeviceID,
				PrincipalID:       managedRevocationOwnerPrincipal,
				Label:             managedRevocationOwnerLabel,
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: ownerPublic},
				AgeEncryptionKey:  ownerIdentity.Recipient().String(),
			},
			{
				DeviceID:          managedRevocationFormerDeviceID,
				PrincipalID:       managedRevocationFormerPrincipal,
				Label:             managedRevocationFormerLabel,
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: formerPublic},
				AgeEncryptionKey:  formerIdentity.Recipient().String(),
			},
		},
	}
	if err := vaultfile.ValidatePolicy(p); err != nil {
		t.Fatalf("synthetic managed current policy is invalid: %s", rustfsPipelineSafeError(err))
	}

	next := *p
	next.PolicySeq = p.PolicySeq + 1
	next.PrevPolicyDigest = vaultfile.PolicyDigest(p)
	next.Writers = []vaultfile.Member{{PrincipalID: managedRevocationOwnerPrincipal, Label: "Owner"}}
	next.Devices = append([]vaultfile.Device(nil), p.Devices[:1]...)
	if err := vaultfile.ValidatePolicy(&next); err != nil {
		t.Fatalf("synthetic managed successor policy is invalid: %s", rustfsPipelineSafeError(err))
	}

	material := &managedRevocationMaterial{
		policy:     p,
		nextPolicy: &next,
		pin: &vaultfile.PolicyCheckpoint{
			VaultID:            p.VaultID,
			OwnerRootKeyID:     p.OwnerRoot.KeyID,
			OwnerRootPublicKey: append(ed25519.PublicKey(nil), rootPublic...),
			PolicySeq:          p.PolicySeq,
			PolicyDigest:       vaultfile.PolicyDigest(p),
		},
		oldProof:       managedRevocationProof(t, p, rootPrivate),
		nextProof:      managedRevocationProof(t, &next, rootPrivate),
		ownerID:        managedRevocationOwnerDeviceID,
		ownerIdentity:  ownerIdentity,
		ownerSigning:   ownerSigning,
		formerID:       managedRevocationFormerDeviceID,
		formerIdentity: formerIdentity,
	}
	if !managedRevocationHasDevice(p, material.formerID) {
		t.Fatal("synthetic current policy does not contain the former writer device")
	}
	if managedRevocationHasDevice(&next, material.formerID) {
		t.Fatal("synthetic successor policy still contains the former writer device")
	}
	if material.ownerID == material.formerID {
		t.Fatal("synthetic managed device IDs are not distinct")
	}
	if bytes.Equal(ownerPublic, formerPublic) ||
		ownerIdentity.Recipient().String() == formerIdentity.Recipient().String() {
		t.Fatal("synthetic managed devices do not carry distinct keys")
	}
	return material
}

// managedRevocationRequireOpen performs the complete caller-pinned
// authenticated open and reads the item database, then releases the plaintext
// immediately. The parsed file remains owned by test cleanup.
func managedRevocationRequireOpen(t *testing.T, encoded []byte, material *managedRevocationMaterial, deviceID string, identity *age.X25519Identity) *vaultfile.File {
	t.Helper()
	file, db, err := vaultfile.OpenAuthenticatedFile(encoded, material.pin, deviceID, identity)
	if err != nil {
		t.Fatalf("synthetic managed authenticated open failed: %s", readerAuthoritySafeError(err))
	}
	metadata, items, err := vault.ReadItemDatabase(db)
	releaseDatabase(db)
	if err != nil {
		releaseFile(file)
		t.Fatalf("synthetic managed item database read failed: %s", rustfsPipelineSafeError(err))
	}
	releasePlaintext(metadata, items)
	t.Cleanup(func() { releaseFile(file) })
	return file
}

// managedRevocationSealed seals the baseline under the current policy and
// independently opens it as both the owner and the prior writer, so the former
// is known to be genuinely authorized before the revocation.
func managedRevocationSealed(t *testing.T, material *managedRevocationMaterial) []byte {
	t.Helper()
	draft := fixtureDraft(t, material.policy)
	draft.Header.OpID = managedRevocationOldOpID
	draft.SignedPolicyProofs = []vaultfile.SignedPolicy{material.oldProof}
	sealed, err := vaultfile.SealAuthenticatedFile(draft, itemDatabase(t), material.pin,
		makeVUK(t), material.ownerSigning)
	if err != nil {
		t.Fatalf("seal synthetic managed baseline failed: %s", readerAuthoritySafeError(err))
	}
	if bytes.Contains(sealed, []byte("synthetic-password")) {
		t.Fatal("synthetic managed baseline ciphertext contains a plaintext marker")
	}
	ownerFile := managedRevocationRequireOpen(t, sealed, material, material.ownerID, material.ownerIdentity)
	if ownerFile.Header.AuthorDeviceID != material.ownerID {
		t.Fatal("synthetic managed baseline is not authored by the owner device")
	}
	managedRevocationRequireOpen(t, sealed, material, material.formerID, material.formerIdentity)
	return sealed
}

// managedRevocationRotate runs the existing managed epoch rotation on the exact
// old bytes and authenticates the result with the existing managed transition
// verifier. It returns the sealed successor and its parsed form.
func managedRevocationRotate(t *testing.T, material *managedRevocationMaterial, oldEncoded []byte) ([]byte, *vaultfile.File) {
	t.Helper()
	oldFile, err := vaultfile.ParseFile(oldEncoded)
	if err != nil {
		t.Fatalf("synthetic managed old file does not parse: %s", rustfsPipelineSafeError(err))
	}
	oldDigestHex, err := vaultfile.FileDigest(oldFile)
	if err != nil {
		t.Fatalf("synthetic managed old file digest failed: %s", rustfsPipelineSafeError(err))
	}
	oldDigest, err := hex.DecodeString(oldDigestHex)
	if err != nil || len(oldDigest) != 32 {
		t.Fatal("synthetic managed old file digest is not a 32-byte value")
	}
	draft := &vaultfile.File{
		Format:  vaultfile.Format,
		Version: vaultfile.Version,
		Header: vaultfile.Header{
			VaultID:        oldFile.Header.VaultID,
			KeyEpoch:       oldFile.Header.KeyEpoch + 1,
			ContentSeq:     oldFile.Header.ContentSeq + 1,
			PrevDigest:     oldDigest,
			OpID:           managedRevocationNewOpID,
			PolicySeq:      material.nextPolicy.PolicySeq,
			PolicyDigest:   vaultfile.PolicyDigest(material.nextPolicy),
			AuthorDeviceID: material.ownerID,
		},
		SignedPolicyProofs: []vaultfile.SignedPolicy{material.oldProof, material.nextProof},
		ContentEncoding:    vaultfile.ContentEncoding,
	}
	nextEncoded, newVUK, err := vaultfile.RotateAuthenticatedFile(oldEncoded, material.pin,
		material.ownerID, material.ownerIdentity, draft, material.ownerSigning)
	defer clear(newVUK)
	if err != nil {
		t.Fatalf("synthetic managed epoch rotation failed: %s", rustfsPipelineSafeError(err))
	}
	if len(newVUK) != vaultfile.CEKSize {
		t.Fatal("synthetic managed epoch rotation returned a malformed VUK")
	}
	if err := vaultfile.VerifyManagedTransition(oldEncoded, nextEncoded, material.pin); err != nil {
		t.Fatalf("synthetic managed successor is not the exact authenticated transition: %s", readerAuthoritySafeError(err))
	}
	nextFile, err := vaultfile.ParseFile(nextEncoded)
	if err != nil {
		t.Fatalf("synthetic managed successor does not parse: %s", rustfsPipelineSafeError(err))
	}
	if nextFile.Header.KeyEpoch != oldFile.Header.KeyEpoch+1 ||
		nextFile.Header.ContentSeq != oldFile.Header.ContentSeq+1 ||
		nextFile.Header.PolicySeq != oldFile.Header.PolicySeq+1 ||
		nextFile.Header.AuthorDeviceID != material.ownerID {
		t.Fatal("synthetic managed successor does not advance exactly one epoch, content and policy step")
	}
	return nextEncoded, nextFile
}

// managedRevocationPullVerifier accepts only bytes that authenticate under the
// pinned policy for deviceID and carry the item-database layout.
func managedRevocationPullVerifier(material *managedRevocationMaterial, deviceID string, identity *age.X25519Identity) vaultfilepublish.PullVerifier {
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

// managedRevocationRequireState proves the complete durable journal state.
func managedRevocationRequireState(t *testing.T, got, want vaultfilejournal.State) {
	t.Helper()
	if got.Generation != want.Generation ||
		got.RemoteRevision != want.RemoteRevision ||
		!bytes.Equal(got.BaseBytes, want.BaseBytes) ||
		!bytes.Equal(got.WorkingBytes, want.WorkingBytes) {
		t.Fatal("managed revocation durable journal state changed")
	}
}

// managedRevocationRequireNoPending proves the journal has neither a legacy
// proposal nor a prepared proposal.
func managedRevocationRequireNoPending(t *testing.T, journal *vaultfilejournal.Journal) {
	t.Helper()
	if _, err := journal.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("journal has an unexpected prepared record: %s", rustfsPipelineSafeError(err))
	}
	if _, err := journal.Load(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatalf("journal has an unexpected legacy record: %s", rustfsPipelineSafeError(err))
	}
}

// TestPipelineManagedRevocationOnRustFS is the opt-in real-provider managed
// revocation checkpoint. See the file comment for its exact scope.
func TestPipelineManagedRevocationOnRustFS(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	material := newManagedRevocationMaterial(t)
	runManagedRevocationScenario(t, material,
		env.newBackendAt(t, bucket, managedRevocationPipelinePrefix),
		func(t *testing.T) vaultfilebackend.Backend {
			return env.newBackendAt(t, bucket, managedRevocationPipelinePrefix)
		})
}

// runManagedRevocationScenario owns the end-to-end managed transition over one
// exact remote object. seeded must be a real backend handle; newHandle must
// construct genuinely independent handles over the same bucket and prefix.
func runManagedRevocationScenario(t *testing.T, material *managedRevocationMaterial, seeded vaultfilebackend.Backend, newHandle func(*testing.T) vaultfilebackend.Backend) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), lateAckTimeout)
	defer cancel()

	oldSealed := managedRevocationSealed(t, material)
	if err := seeded.CreateIfAbsent(ctx, remoteName, oldSealed); err != nil {
		t.Fatalf("seed synthetic managed remote failed: %s", rustfsPipelineSafeError(err))
	}
	oldRead, err := seeded.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read exact managed source failed: %s", rustfsPipelineSafeError(err))
	}
	if oldRead.Revision.Zero() || !bytes.Equal(oldRead.Bytes, oldSealed) {
		t.Fatal("managed source read is not the exact seeded bytes at a real revision")
	}
	// The former writer is a genuine prior participant before the revocation.
	managedRevocationRequireOpen(t, oldRead.Bytes, material, material.ownerID, material.ownerIdentity)
	managedRevocationRequireOpen(t, oldRead.Bytes, material, material.formerID, material.formerIdentity)

	journal := openNewJournal(t)
	receipt, err := Bootstrap(ctx, seeded, journal, remoteName, material.pin,
		material.ownerID, material.ownerIdentity)
	if err != nil {
		t.Fatalf("managed owner bootstrap failed: %s", readerAuthoritySafeError(err))
	}
	if receipt.Generation != 0 || receipt.RemoteRevision != oldRead.Revision {
		t.Fatal("managed owner bootstrap is not the exact current provider revision at generation zero")
	}
	start, err := journal.LoadState()
	if err != nil {
		t.Fatalf("load managed owner journal failed: %s", rustfsPipelineSafeError(err))
	}
	managedRevocationRequireState(t, start, vaultfilejournal.State{
		BaseBytes: oldRead.Bytes, RemoteRevision: oldRead.Revision, WorkingBytes: oldRead.Bytes,
	})
	managedRevocationRequireNoPending(t, journal)

	// The actual managed policy revocation and epoch rotation. The source is
	// the exact observed provider pair, not a locally reconstructed file.
	rotated, nextFile := managedRevocationRotate(t, material, oldRead.Bytes)
	if err := journal.UpdateWorking(start.Generation, rotated); err != nil {
		t.Fatalf("stage managed successor in the owner journal failed: %s", rustfsPipelineSafeError(err))
	}
	working, err := journal.LoadState()
	if err != nil {
		t.Fatalf("load managed owner working state failed: %s", rustfsPipelineSafeError(err))
	}
	if working.Generation != start.Generation+1 ||
		working.RemoteRevision != start.RemoteRevision ||
		!bytes.Equal(working.BaseBytes, start.BaseBytes) ||
		!bytes.Equal(working.WorkingBytes, rotated) {
		t.Fatal("staged managed successor did not preserve the source base and revision")
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       working.Generation,
		OperationID:      nextFile.Header.OpID,
		ExpectedRevision: working.RemoteRevision,
		Bytes:            rotated,
	}
	pullVerifier := managedRevocationPullVerifier(material, material.ownerID, material.ownerIdentity)
	pulled, err := vaultfilepublish.ReadPulled(ctx, seeded, remoteName, pullVerifier)
	if err != nil {
		t.Fatalf("pull managed source failed: %s", rustfsPipelineSafeError(err))
	}
	if pulled.Revision() != oldRead.Revision || !bytes.Equal(pulled.Bytes(), oldRead.Bytes) {
		t.Fatal("pulled managed base is not the exact source provider pair")
	}

	// A genuine production content verifier must refuse the genuine policy
	// change even though the same provider credentials could write it. This is
	// the admission gap the managed verifier fills; no CAS may happen here.
	contentVerifier, err := NewContentProposalVerifier(material.pin)
	if err != nil {
		t.Fatalf("ordinary content verifier construction failed: %s", rustfsPipelineSafeError(err))
	}
	contentCoordinator, err := vaultfilepublish.NewCoordinator(seeded, journal, remoteName, contentVerifier)
	if err != nil {
		t.Fatalf("ordinary content coordinator construction failed: %s", rustfsPipelineSafeError(err))
	}
	err = contentCoordinator.PrepareAndPublish(ctx, pulled, proposal, pullVerifier)
	if !errors.Is(err, vaultfilepublish.ErrVerification) || !errors.Is(err, ErrContentProposalRejected) {
		t.Fatalf("ordinary content admission returned the wrong class for a managed transition: %s", readerAuthoritySafeError(err))
	}
	managedRevocationRequireNoPending(t, journal)
	unchanged, err := seeded.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read managed source after content rejection failed: %s", rustfsPipelineSafeError(err))
	}
	if unchanged.Revision != oldRead.Revision || !bytes.Equal(unchanged.Bytes, oldRead.Bytes) {
		t.Fatal("ordinary content admission changed the exact provider pair")
	}

	// The focused managed admission accepts the exact authenticated transition;
	// the real coordinator then prepares, conditionally writes, reads back,
	// verifies and acknowledges it.
	managedVerifier, err := NewManagedTransitionProposalVerifier(material.pin)
	if err != nil {
		t.Fatalf("managed transition verifier construction failed: %s", rustfsPipelineSafeError(err))
	}
	coordinator, err := vaultfilepublish.NewCoordinator(seeded, journal, remoteName, managedVerifier)
	if err != nil {
		t.Fatalf("managed transition coordinator construction failed: %s", rustfsPipelineSafeError(err))
	}
	if err := coordinator.PrepareAndPublish(ctx, pulled, proposal, pullVerifier); err != nil {
		t.Fatalf("managed transition conditional publish failed: %s", readerAuthoritySafeError(err))
	}
	published, err := seeded.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read observed managed successor failed: %s", rustfsPipelineSafeError(err))
	}
	if published.Revision == oldRead.Revision || !bytes.Equal(published.Bytes, rotated) {
		t.Fatal("managed publish is not the exact successor at a changed opaque revision")
	}
	if err := vaultfile.VerifyManagedTransition(oldRead.Bytes, published.Bytes, material.pin); err != nil {
		t.Fatalf("observed managed successor is not the authenticated transition: %s", readerAuthoritySafeError(err))
	}
	final := vaultfilejournal.State{
		BaseBytes: published.Bytes, RemoteRevision: published.Revision, WorkingBytes: published.Bytes,
		Generation: working.Generation,
	}
	managedRevocationRequireState(t, mustLoadManagedState(t, journal), final)
	managedRevocationRequireNoPending(t, journal)

	// Fresh provider handle and fresh journal reopen: the owner must open the
	// exact observed successor under the same pin.
	path := journalPath(t, journal)
	closeNow(t, journal)
	fresh := newHandle(t)
	reopened := openJournalAt(t, path)
	managedRevocationRequireState(t, mustLoadManagedState(t, reopened), final)
	managedRevocationRequireNoPending(t, reopened)
	freshPulled, err := vaultfilepublish.ReadPulled(ctx, fresh, remoteName, pullVerifier)
	if err != nil {
		t.Fatalf("fresh managed readback failed: %s", rustfsPipelineSafeError(err))
	}
	if freshPulled.Revision() != published.Revision || !bytes.Equal(freshPulled.Bytes(), published.Bytes) {
		t.Fatal("fresh handle did not observe the exact published managed successor")
	}
	ownerFile := managedRevocationRequireOpen(t, freshPulled.Bytes(), material, material.ownerID, material.ownerIdentity)
	if ownerFile.Header.KeyEpoch != nextFile.Header.KeyEpoch ||
		ownerFile.Header.ContentSeq != nextFile.Header.ContentSeq ||
		ownerFile.Header.PolicySeq != nextFile.Header.PolicySeq ||
		!bytes.Equal(ownerFile.Header.PolicyDigest, nextFile.Header.PolicyDigest) {
		t.Fatal("owner fresh reopen is not the exact rotated successor")
	}

	// The removed prior writer still has transport-level read access to the
	// object, but its device is absent from the authenticated current policy,
	// so the caller-pinned open must refuse it. There is no stale-policy
	// fallback to the old proof that still names it.
	formerBackend := newHandle(t)
	formerRead, err := formerBackend.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("former writer transport read failed: %s", rustfsPipelineSafeError(err))
	}
	if formerRead.Revision != published.Revision || !bytes.Equal(formerRead.Bytes, published.Bytes) {
		t.Fatal("former writer transport read is not the exact published object")
	}
	_, _, err = vaultfile.OpenAuthenticatedFile(formerRead.Bytes, material.pin,
		material.formerID, material.formerIdentity)
	if err == nil {
		t.Fatal("revoked former writer opened the new managed successor")
	}
	var vaultErr *vaultfile.Error
	if !errors.As(err, &vaultErr) || vaultErr.Code != vaultfile.CodeInvalidValue || vaultErr.Path != "device_id" {
		t.Fatalf("revoked former writer did not fail at the authenticated current-policy device gate: %s", readerAuthoritySafeError(err))
	}

	// The former writer's transport credentials still permit a conditional
	// write call, but the old revision is no longer current. The real provider
	// must refuse the stale replacement and preserve the exact new object.
	err = formerBackend.ReplaceIfVersion(ctx, remoteName, oldRead.Revision, oldRead.Bytes)
	if !errors.Is(err, vaultfilebackend.ErrConflict) {
		t.Fatalf("stale former-writer replacement returned the wrong provider class: %s", rustfsPipelineSafeError(err))
	}
	finalRead, err := fresh.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read managed successor after stale replacement failed: %s", rustfsPipelineSafeError(err))
	}
	if finalRead.Revision != published.Revision || !bytes.Equal(finalRead.Bytes, published.Bytes) {
		t.Fatal("stale former-writer replacement changed the exact published object")
	}
}

// mustLoadManagedState loads the complete durable state or fails without
// printing it.
func mustLoadManagedState(t *testing.T, journal *vaultfilejournal.Journal) vaultfilejournal.State {
	t.Helper()
	state, err := journal.LoadState()
	if err != nil {
		t.Fatalf("load managed durable state failed: %s", rustfsPipelineSafeError(err))
	}
	return state
}

// TestManagedTransitionProposalVerifierOnSyntheticRotation exercises the new
// admission offline with the same real synthetic rotation. The ordinary content
// verifier must refuse the policy change; the managed verifier must accept only
// the exact authenticated successor with its exact operation and revision.
func TestManagedTransitionProposalVerifierOnSyntheticRotation(t *testing.T) {
	material := newManagedRevocationMaterial(t)
	oldSealed := managedRevocationSealed(t, material)
	rotated, nextFile := managedRevocationRotate(t, material, oldSealed)

	managed, err := NewManagedTransitionProposalVerifier(material.pin)
	if err != nil {
		t.Fatalf("managed transition verifier construction failed: %s", rustfsPipelineSafeError(err))
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       1,
		OperationID:      nextFile.Header.OpID,
		ExpectedRevision: managedRevocationBaseRevisionName,
		Bytes:            rotated,
	}
	ctx := context.Background()
	if err := managed(ctx, oldSealed, proposal.ExpectedRevision, proposal); err != nil {
		t.Fatalf("managed transition verifier rejected the exact rotation: %s", readerAuthoritySafeError(err))
	}

	content, err := NewContentProposalVerifier(material.pin)
	if err != nil {
		t.Fatalf("ordinary content verifier construction failed: %s", rustfsPipelineSafeError(err))
	}
	if err := content(ctx, oldSealed, proposal.ExpectedRevision, proposal); !errors.Is(err, ErrContentProposalRejected) {
		t.Fatalf("ordinary content verifier returned the wrong class for a managed transition: %s", readerAuthoritySafeError(err))
	}

	if _, err := NewManagedTransitionProposalVerifier(nil); err == nil {
		t.Fatal("managed transition verifier accepted a nil checkpoint")
	}
	if err := managed(nil, oldSealed, proposal.ExpectedRevision, proposal); !errors.Is(err, ErrManagedTransitionProposalRejected) {
		t.Fatalf("managed transition verifier returned the wrong class for a nil context: %s", readerAuthoritySafeError(err))
	}
	if err := managed(ctx, oldSealed, "other-revision", proposal); !errors.Is(err, ErrManagedTransitionProposalRejected) {
		t.Fatalf("managed transition verifier accepted a mismatched revision: %s", readerAuthoritySafeError(err))
	}
	wrongOperation := proposal
	wrongOperation.OperationID = "op-managed-revocation-wrong"
	if err := managed(ctx, oldSealed, proposal.ExpectedRevision, wrongOperation); !errors.Is(err, ErrManagedTransitionProposalRejected) {
		t.Fatalf("managed transition verifier accepted a mismatched operation: %s", readerAuthoritySafeError(err))
	}
	oldFile, err := vaultfile.ParseFile(oldSealed)
	if err != nil {
		t.Fatalf("synthetic managed old file does not parse: %s", rustfsPipelineSafeError(err))
	}
	notASuccessor := proposal
	notASuccessor.OperationID = oldFile.Header.OpID
	notASuccessor.Bytes = oldSealed
	if err := managed(ctx, oldSealed, proposal.ExpectedRevision, notASuccessor); !errors.Is(err, ErrManagedTransitionProposalRejected) {
		t.Fatalf("managed transition verifier accepted a non-successor: %s", readerAuthoritySafeError(err))
	}
}
