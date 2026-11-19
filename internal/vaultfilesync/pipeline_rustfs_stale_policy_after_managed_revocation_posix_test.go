//go:build darwin || linux

package vaultfilesync

// Issue #122 stale-policy adoption checkpoint after a real managed revocation.
//
// The existing managed-revocation test proves the authentic rotated R1 is
// installed, a former device cannot open it under the caller pin and its stale
// conditional write against the old revision conflicts. It does not cover the
// retained-transport case: the revoked former writer reads the current opaque
// revision and conditionally publishes a genuinely signed old-policy file over
// R1. The provider accepts that CAS because transport permission was only
// synthetically retained; the honest recipient's separately advanced trusted
// checkpoint must still refuse the stale policy as a trust decision.
//
// This scenario reuses the synthetic managed material, sealing, rotation,
// authenticated open, journal-state and cleanup helpers from
// pipeline_rustfs_managed_revocation_posix_test.go. It adds no production hook,
// trust model, credential claim or pin reset. It is opt-in and local-only, uses
// the same pinned RustFS environment, credentials, TLS guard, unique bucket
// ownership and cleanup as TestPipelinePublishThirdWriterOnRustFS, and is
// skipped unless RUSTFS_SMOKE_ENABLE=1 plus the documented endpoint, CA and
// private credential file are supplied. Diagnostics name only constant
// categories, typed vault error codes at field paths, or provider error
// classes; they never print object bytes, revisions, policy or device
// identifiers, keys, plaintext or the endpoint.

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	stalePolicyPipelinePrefix = "stale-policy-managed-revocation-pipeline"
	stalePolicyOpID           = "op-managed-revocation-stale-writeback"
)

// TestPipelineRejectStalePolicyAfterManagedRevocationOnRustFS is the opt-in
// real-provider stale-policy checkpoint. See the file comment for its scope.
func TestPipelineRejectStalePolicyAfterManagedRevocationOnRustFS(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	material := newManagedRevocationMaterial(t)
	runStalePolicyAfterManagedRevocationScenario(t, material,
		env.newBackendAt(t, bucket, stalePolicyPipelinePrefix),
		func(t *testing.T) vaultfilebackend.Backend {
			return env.newBackendAt(t, bucket, stalePolicyPipelinePrefix)
		})
}

// runStalePolicyAfterManagedRevocationScenario runs the complete retained
// transport stale-policy scenario. seeded is a real backend handle and
// newHandle constructs genuinely independent handles over the same store.
func runStalePolicyAfterManagedRevocationScenario(t *testing.T, material *managedRevocationMaterial, seeded vaultfilebackend.Backend, newHandle func(*testing.T) vaultfilebackend.Backend) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), lateAckTimeout)
	defer cancel()

	// Honest rotation: seed the authentic old baseline, bootstrap the owner,
	// run the real managed rotation and publish it through the production
	// managed coordinator.
	oldRead, published := managedRevocationPublishHonestRotation(t, ctx, material, seeded)

	// A fresh real handle independently observes the authentic successor, and
	// the existing managed verifier authenticates the exact transition under
	// the old pin. Only after that external verification does the honest
	// recipient advance its own trusted checkpoint from R1's authenticated
	// current policy and the root it already trusted, never from stale bytes.
	external := newHandle(t)
	externalRead, err := external.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("independent read of authentic managed successor failed: %s", rustfsPipelineSafeError(err))
	}
	if externalRead.Revision != published.Revision || !bytes.Equal(externalRead.Bytes, published.Bytes) {
		t.Fatal("independent handle did not observe the exact published managed successor")
	}
	if err := vaultfile.VerifyManagedTransition(oldRead.Bytes, externalRead.Bytes, material.pin); err != nil {
		t.Fatalf("external managed transition verification failed: %s", readerAuthoritySafeError(err))
	}
	successor, err := vaultfile.ParseFile(externalRead.Bytes)
	if err != nil {
		t.Fatalf("authentic managed successor does not parse: %s", rustfsPipelineSafeError(err))
	}
	advanced := managedRevocationAdvancedCheckpoint(t, successor, material.pin)
	managedRevocationRequireOpenAt(t, externalRead.Bytes, advanced, material.ownerID, material.ownerIdentity)

	// The honest recipient adopts exactly the externally verified R1 through
	// the production authenticated bootstrap under its advanced checkpoint.
	recipient := openNewJournal(t)
	if _, err := Bootstrap(ctx, external, recipient, remoteName, advanced,
		material.ownerID, material.ownerIdentity); err != nil {
		t.Fatalf("honest recipient adoption of verified successor failed: %s", readerAuthoritySafeError(err))
	}
	adopted := mustLoadManagedState(t, recipient)
	managedRevocationRequireState(t, adopted, vaultfilejournal.State{
		BaseBytes: externalRead.Bytes, RemoteRevision: externalRead.Revision, WorkingBytes: externalRead.Bytes,
	})
	managedRevocationRequireNoPending(t, recipient)
	advancedBefore := managedRevocationSnapshotCheckpoint(advanced)

	// Positive control before contamination: a fresh real handle's verified
	// pull and authenticated open both pass with the same current trust pin.
	currentPull := managedRevocationPullVerifierAt(material, advanced,
		material.ownerID, material.ownerIdentity)
	preContamination := newHandle(t)
	prePulled, err := vaultfilepublish.ReadPulled(ctx, preContamination, remoteName, currentPull)
	if err != nil {
		t.Fatalf("fresh honest readback before contamination failed: %s", readerAuthoritySafeError(err))
	}
	if prePulled.Revision() != externalRead.Revision || !bytes.Equal(prePulled.Bytes(), externalRead.Bytes) {
		t.Fatal("fresh honest readback is not the exact authentic managed successor")
	}
	managedRevocationRequireOpenAt(t, prePulled.Bytes(), advanced, material.ownerID, material.ownerIdentity)

	// The synthetic retained transport writer publishes a real old-policy file
	// it signed with the former device's real key, at the actual current
	// conditional provider revision. This is an offline former-writer branch
	// from the old baseline: old key epoch and policy, one content step above
	// the old baseline, and an author the old policy still authorized.
	staleBytes := managedRevocationStaleOldPolicyFile(t, material, oldRead.Bytes)
	staleFile, err := vaultfile.ParseFile(staleBytes)
	if err != nil {
		t.Fatalf("stale old-policy publication does not parse: %s", rustfsPipelineSafeError(err))
	}
	if staleFile.Header.AuthorDeviceID != material.formerID ||
		staleFile.Header.PolicySeq != material.policy.PolicySeq ||
		staleFile.Header.KeyEpoch >= successor.Header.KeyEpoch ||
		staleFile.Header.ContentSeq < successor.Header.ContentSeq ||
		bytes.Equal(staleFile.Header.PolicyDigest, advanced.PolicyDigest) {
		t.Fatal("stale publication is not an old-policy old-writer branch")
	}
	// The former writer can still authenticate and read its own stale
	// publication under the old, now obsolete policy.
	managedRevocationRequireOpen(t, staleBytes, material, material.formerID, material.formerIdentity)

	staleWriter := newHandle(t)
	if err := staleWriter.ReplaceIfVersion(ctx, remoteName, externalRead.Revision, staleBytes); err != nil {
		t.Fatalf("synthetic retained transport write-back failed: %s", rustfsPipelineSafeError(err))
	}

	// Two independent fresh handles observe the same later provider pair. The
	// revision is real provider evidence; it is not authenticated adoption.
	freshA := newHandle(t)
	freshB := newHandle(t)
	contaminatedA, err := freshA.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("fresh handle A read of stale publication failed: %s", rustfsPipelineSafeError(err))
	}
	contaminatedB, err := freshB.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("fresh handle B read of stale publication failed: %s", rustfsPipelineSafeError(err))
	}
	if contaminatedA.Revision.Zero() ||
		contaminatedA.Revision == externalRead.Revision ||
		contaminatedA.Revision != contaminatedB.Revision ||
		!bytes.Equal(contaminatedA.Bytes, staleBytes) ||
		!bytes.Equal(contaminatedB.Bytes, staleBytes) {
		t.Fatal("fresh handles did not observe one exact later stale provider pair")
	}

	// At the actual verified pull boundary, the current checkpoint refuses the
	// stale policy. No Pulled exists, and the refusal is a trust decision, not
	// a provider conflict or an unknown write/durability outcome.
	pulled, err := vaultfilepublish.ReadPulled(ctx, freshA, remoteName, currentPull)
	if !errors.Is(err, vaultfilepublish.ErrVerification) {
		t.Fatalf("stale-policy pull returned the wrong class: %s", readerAuthoritySafeError(err))
	}
	if vaultfileCode(err) != vaultfile.CodePolicyCheckpointFailed {
		t.Fatalf("stale-policy pull did not fail at the current policy checkpoint: %s", readerAuthoritySafeError(err))
	}
	if errors.Is(err, vaultfilebackend.ErrConflict) || errors.Is(err, vaultfilebackend.ErrUnknown) ||
		errors.Is(err, vaultfilepublish.ErrConflict) || errors.Is(err, vaultfilepublish.ErrUnknownWrite) ||
		errors.Is(err, vaultfilepublish.ErrUnknownReview) {
		t.Fatalf("stale-policy trust refusal was misclassified: %s", readerAuthoritySafeError(err))
	}
	if pulled.Revision() != "" || pulled.Bytes() != nil {
		t.Fatal("stale-policy pull returned a verified value")
	}

	// The normal adopting consumer expresses the same advanced checkpoint and
	// must refuse the stale remote before any candidate, adoption or journal
	// transaction. This is a definite trust rejection, not a provider read or
	// durability-unknown failure.
	candidate, err := BuildMergeCandidate(ctx, freshB, remoteName, recipient, advanced,
		material.ownerID, material.ownerIdentity, material.ownerSigning)
	if !errors.Is(err, ErrMergeCandidateVerify) {
		t.Fatalf("stale-policy merge candidate returned the wrong class: %s", readerAuthoritySafeError(err))
	}
	if errors.Is(err, ErrMergeCandidateRead) || vaultfileCode(err) != vaultfile.CodePolicyCheckpointFailed {
		t.Fatalf("stale-policy merge candidate did not fail at current-policy verification: %s", readerAuthoritySafeError(err))
	}
	candidate.Clear()

	// Neither the former device nor the honest owner obtains an obsolete grant
	// to the later bytes under the current checkpoint.
	if _, _, err := vaultfile.OpenAuthenticatedFile(contaminatedA.Bytes, advanced,
		material.formerID, material.formerIdentity); err == nil {
		t.Fatal("former device opened the stale publication under the current pin")
	} else if vaultfileCode(err) != vaultfile.CodePolicyCheckpointFailed {
		t.Fatalf("former device stale-policy refusal returned the wrong code: %s", readerAuthoritySafeError(err))
	}

	// The failed pull and candidate read no durable state. The journal still
	// holds exactly the adopted R1 base, working bytes and revision, with no
	// prepared or legacy proposal, and the trusted checkpoint is unchanged.
	managedRevocationRequireState(t, mustLoadManagedState(t, recipient), adopted)
	managedRevocationRequireNoPending(t, recipient)
	managedRevocationRequireCheckpoint(t, advanced, &advancedBefore)

	// The same state and absence of pending records survive a close/reopen, so
	// the trust refusal did not leave a durability-unknown commit behind.
	path := journalPath(t, recipient)
	closeNow(t, recipient)
	reopened := openJournalAt(t, path)
	managedRevocationRequireState(t, mustLoadManagedState(t, reopened), adopted)
	managedRevocationRequireNoPending(t, reopened)
	managedRevocationRequireCheckpoint(t, advanced, &advancedBefore)

	// Provider conflict is a separate, definite class: a conditional write at
	// the superseded R1 revision cannot commit over the later stale pair.
	err = freshB.ReplaceIfVersion(ctx, remoteName, externalRead.Revision, externalRead.Bytes)
	if !errors.Is(err, vaultfilebackend.ErrConflict) {
		t.Fatalf("superseded revision write returned the wrong provider class: %s", rustfsPipelineSafeError(err))
	}
	if errors.Is(err, vaultfilepublish.ErrVerification) {
		t.Fatalf("provider conflict was misclassified as a trust refusal: %s", rustfsPipelineSafeError(err))
	}
	if errors.Is(err, vaultfilebackend.ErrUnknown) ||
		errors.Is(err, vaultfilepublish.ErrUnknownWrite) ||
		errors.Is(err, vaultfilepublish.ErrUnknownReview) {
		t.Fatalf("provider conflict was misclassified as unknown: %s", rustfsPipelineSafeError(err))
	}

	// The provider still holds exactly the later stale pair observed above.
	final, err := freshA.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("final provider read failed: %s", rustfsPipelineSafeError(err))
	}
	if final.Revision != contaminatedA.Revision || !bytes.Equal(final.Bytes, staleBytes) {
		t.Fatal("provider conflict check changed the later stale pair")
	}
}

// managedRevocationPublishHonestRotation seeds the synthetic old baseline,
// bootstraps its owner, performs the real managed rotation and publishes R1
// through the production managed proposal coordinator. It returns the exact
// source read pair and the published successor pair.
func managedRevocationPublishHonestRotation(t *testing.T, ctx context.Context, material *managedRevocationMaterial, backend vaultfilebackend.Backend) (vaultfilebackend.ReadResult, vaultfilebackend.ReadResult) {
	t.Helper()
	oldSealed := managedRevocationSealed(t, material)
	if err := backend.CreateIfAbsent(ctx, remoteName, oldSealed); err != nil {
		t.Fatalf("seed synthetic managed remote failed: %s", rustfsPipelineSafeError(err))
	}
	oldRead, err := backend.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read exact managed source failed: %s", rustfsPipelineSafeError(err))
	}
	if oldRead.Revision.Zero() || !bytes.Equal(oldRead.Bytes, oldSealed) {
		t.Fatal("managed source read is not the exact seeded bytes at a real revision")
	}
	journal := openNewJournal(t)
	if _, err := Bootstrap(ctx, backend, journal, remoteName, material.pin,
		material.ownerID, material.ownerIdentity); err != nil {
		t.Fatalf("managed owner bootstrap failed: %s", readerAuthoritySafeError(err))
	}
	start, err := journal.LoadState()
	if err != nil {
		t.Fatalf("load managed owner journal failed: %s", rustfsPipelineSafeError(err))
	}
	managedRevocationRequireState(t, start, vaultfilejournal.State{
		BaseBytes: oldRead.Bytes, RemoteRevision: oldRead.Revision, WorkingBytes: oldRead.Bytes,
	})
	managedRevocationRequireNoPending(t, journal)

	rotated, nextFile := managedRevocationRotate(t, material, oldRead.Bytes)
	if err := journal.UpdateWorking(start.Generation, rotated); err != nil {
		t.Fatalf("stage managed successor in the owner journal failed: %s", rustfsPipelineSafeError(err))
	}
	working, err := journal.LoadState()
	if err != nil {
		t.Fatalf("load managed owner working state failed: %s", rustfsPipelineSafeError(err))
	}
	proposal := vaultfilejournal.Proposal{
		Generation:       working.Generation,
		OperationID:      nextFile.Header.OpID,
		ExpectedRevision: working.RemoteRevision,
		Bytes:            rotated,
	}
	pullVerifier := managedRevocationPullVerifier(material, material.ownerID, material.ownerIdentity)
	pulled, err := vaultfilepublish.ReadPulled(ctx, backend, remoteName, pullVerifier)
	if err != nil {
		t.Fatalf("pull managed source failed: %s", rustfsPipelineSafeError(err))
	}
	managedVerifier, err := NewManagedTransitionProposalVerifier(material.pin)
	if err != nil {
		t.Fatalf("managed transition verifier construction failed: %s", rustfsPipelineSafeError(err))
	}
	coordinator, err := vaultfilepublish.NewCoordinator(backend, journal, remoteName, managedVerifier)
	if err != nil {
		t.Fatalf("managed transition coordinator construction failed: %s", rustfsPipelineSafeError(err))
	}
	if err := coordinator.PrepareAndPublish(ctx, pulled, proposal, pullVerifier); err != nil {
		t.Fatalf("managed transition conditional publish failed: %s", readerAuthoritySafeError(err))
	}
	published, err := backend.Read(ctx, remoteName)
	if err != nil {
		t.Fatalf("read observed managed successor failed: %s", rustfsPipelineSafeError(err))
	}
	if published.Revision == oldRead.Revision || !bytes.Equal(published.Bytes, rotated) {
		t.Fatal("managed publish is not the exact successor at a changed opaque revision")
	}
	if err := vaultfile.VerifyManagedTransition(oldRead.Bytes, published.Bytes, material.pin); err != nil {
		t.Fatalf("observed managed successor is not the authenticated transition: %s", readerAuthoritySafeError(err))
	}
	return oldRead, published
}

// managedRevocationAdvancedCheckpoint advances the caller's checkpoint from an
// externally authenticated R1. The sequence and digest come only from the
// authenticated current proof and header; the vault and owner root are copied
// from the old trusted checkpoint. The stale candidate is never read.
func managedRevocationAdvancedCheckpoint(t *testing.T, verified *vaultfile.File, old *vaultfile.PolicyCheckpoint) *vaultfile.PolicyCheckpoint {
	t.Helper()
	if verified == nil || old == nil || len(verified.SignedPolicyProofs) == 0 {
		t.Fatal("cannot advance a checkpoint from an incomplete authenticated file")
	}
	current := &verified.SignedPolicyProofs[len(verified.SignedPolicyProofs)-1]
	if current.Policy.PolicySeq != verified.Header.PolicySeq ||
		!bytes.Equal(vaultfile.PolicyDigest(&current.Policy), verified.Header.PolicyDigest) {
		t.Fatal("authenticated successor current proof is not bound to its header")
	}
	advanced := &vaultfile.PolicyCheckpoint{
		VaultID:            old.VaultID,
		OwnerRootKeyID:     old.OwnerRootKeyID,
		OwnerRootPublicKey: append(ed25519.PublicKey(nil), old.OwnerRootPublicKey...),
		PolicySeq:          verified.Header.PolicySeq,
		PolicyDigest:       append([]byte(nil), verified.Header.PolicyDigest...),
	}
	if advanced.PolicySeq <= old.PolicySeq ||
		bytes.Equal(advanced.PolicyDigest, old.PolicyDigest) {
		t.Fatal("checkpoint advancement did not move to a distinct later policy")
	}
	if err := vaultfile.VerifyPolicyCheckpoint(verified, advanced); err != nil {
		t.Fatalf("advanced checkpoint does not authenticate the verified successor: %s", readerAuthoritySafeError(err))
	}
	return advanced
}

// managedRevocationSnapshotCheckpoint owns an independent copy for later exact
// comparison.
func managedRevocationSnapshotCheckpoint(checkpoint *vaultfile.PolicyCheckpoint) vaultfile.PolicyCheckpoint {
	return vaultfile.PolicyCheckpoint{
		VaultID:            checkpoint.VaultID,
		OwnerRootKeyID:     checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: append(ed25519.PublicKey(nil), checkpoint.OwnerRootPublicKey...),
		PolicySeq:          checkpoint.PolicySeq,
		PolicyDigest:       append([]byte(nil), checkpoint.PolicyDigest...),
	}
}

// managedRevocationRequireCheckpoint proves the trusted checkpoint is exactly
// unchanged.
func managedRevocationRequireCheckpoint(t *testing.T, got, want *vaultfile.PolicyCheckpoint) {
	t.Helper()
	if got == nil || want == nil ||
		got.VaultID != want.VaultID ||
		got.OwnerRootKeyID != want.OwnerRootKeyID ||
		!bytes.Equal(got.OwnerRootPublicKey, want.OwnerRootPublicKey) ||
		got.PolicySeq != want.PolicySeq ||
		!bytes.Equal(got.PolicyDigest, want.PolicyDigest) {
		t.Fatal("trusted policy checkpoint changed")
	}
}

// managedRevocationRequireOpenAt performs a complete caller-pinned
// authenticated open and item-database read under an explicit checkpoint.
func managedRevocationRequireOpenAt(t *testing.T, encoded []byte, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity) {
	t.Helper()
	file, db, err := vaultfile.OpenAuthenticatedFile(encoded, checkpoint, deviceID, identity)
	if err != nil {
		t.Fatalf("explicit-checkpoint authenticated open failed: %s", readerAuthoritySafeError(err))
	}
	metadata, items, err := vault.ReadItemDatabase(db)
	releaseDatabase(db)
	if err != nil {
		releaseFile(file)
		t.Fatalf("explicit-checkpoint item database read failed: %s", rustfsPipelineSafeError(err))
	}
	releasePlaintext(metadata, items)
	t.Cleanup(func() { releaseFile(file) })
}

// managedRevocationPullVerifierAt authenticates bytes and their item database
// under one explicit checkpoint and device.
func managedRevocationPullVerifierAt(material *managedRevocationMaterial, checkpoint *vaultfile.PolicyCheckpoint, deviceID string, identity *age.X25519Identity) vaultfilepublish.PullVerifier {
	return func(_ context.Context, data []byte, _ vaultfilebackend.Revision) error {
		file, db, err := vaultfile.OpenAuthenticatedFile(data, checkpoint, deviceID, identity)
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

// managedRevocationStaleOldPolicyFile builds a genuinely sealed old-policy
// branch authored with the former device's real private key. It stays at the
// old key epoch and old policy sequence, advancing exactly one content step
// from the old baseline, so it is the former writer's real offline branch and
// not a fabricated byte string.
func managedRevocationStaleOldPolicyFile(t *testing.T, material *managedRevocationMaterial, oldSealed []byte) []byte {
	t.Helper()
	oldFile, err := vaultfile.ParseFile(oldSealed)
	if err != nil {
		t.Fatalf("old managed baseline does not parse: %s", rustfsPipelineSafeError(err))
	}
	vuk := managedRevocationOldEpochVUK(t, material, oldFile, material.formerID, material.formerIdentity)
	defer clear(vuk)
	prevDigest := pipelineRawDigest(t, oldFile)
	draft := &vaultfile.File{
		Format:  vaultfile.Format,
		Version: vaultfile.Version,
		Header: vaultfile.Header{
			VaultID:        oldFile.Header.VaultID,
			KeyEpoch:       oldFile.Header.KeyEpoch,
			ContentSeq:     oldFile.Header.ContentSeq + 1,
			PrevDigest:     prevDigest,
			OpID:           stalePolicyOpID,
			PolicySeq:      material.policy.PolicySeq,
			PolicyDigest:   vaultfile.PolicyDigest(material.policy),
			AuthorDeviceID: material.formerID,
		},
		SignedPolicyProofs: []vaultfile.SignedPolicy{material.oldProof},
		ContentEncoding:    vaultfile.ContentEncoding,
	}
	stale, err := vaultfile.SealAuthenticatedFile(draft, itemDatabase(t), material.pin,
		vuk, material.formerSigning)
	clear(vuk)
	if err != nil {
		t.Fatalf("seal stale old-policy publication failed: %s", readerAuthoritySafeError(err))
	}
	return stale
}

// managedRevocationOldEpochVUK recovers the old per-epoch VUK from the
// authenticated old file's slot for one device, using that device's real age
// identity and recipient from the old policy.
func managedRevocationOldEpochVUK(t *testing.T, material *managedRevocationMaterial, oldFile *vaultfile.File, deviceID string, identity *age.X25519Identity) []byte {
	t.Helper()
	var device *vaultfile.Device
	for i := range material.policy.Devices {
		if material.policy.Devices[i].DeviceID == deviceID {
			device = &material.policy.Devices[i]
			break
		}
	}
	if device == nil {
		t.Fatal("old-policy device is absent from the synthetic policy")
	}
	var slot *vaultfile.DeviceSlot
	for i := range oldFile.VUKDeviceSlots {
		if oldFile.VUKDeviceSlots[i].DeviceID == deviceID {
			slot = &oldFile.VUKDeviceSlots[i]
			break
		}
	}
	if slot == nil {
		t.Fatal("old managed baseline has no slot for the former device")
	}
	vuk, err := vaultfile.OpenVUKForDevice(*slot, oldFile.Header.VaultID, oldFile.Header.KeyEpoch,
		deviceID, device.AgeEncryptionKey, identity)
	if err != nil {
		t.Fatalf("recover old epoch VUK failed: %s", readerAuthoritySafeError(err))
	}
	return vuk
}
