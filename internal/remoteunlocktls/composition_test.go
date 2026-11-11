package remoteunlocktls

// This file is one isolated positive-composition smoke test for the remote
// unlock admin-delegation path. Every certificate, Ed25519 key, age X25519
// identity, policy, vault-file byte, recipient, request identifier and
// timestamp is synthetic test data generated or declared here; none belongs to
// a person, device, enrollment, owner root, vault or pairing.
//
// TEST-ONLY FRAMING. The tiny 4-byte big-endian length-prefixed frames and the
// request/approval section layout below exist only to carry the canonical
// public codec bytes over an established remoteunlocktls.Channel in this test.
// They are deliberately private to the test, bounded, and define no product
// wire protocol: they are not the remote-unlock v1 wire format, not a relay or
// session protocol, and not a production frame, relay or VUK service. The v1
// production framing contract in docs/remote-unlock-wire-v1.md is unchanged.
//
// This test proves one positive flow only. It has no failure matrix: it does
// not exercise a wrong SPKI, key, device, member, context, expiry,
// cancellation, restart, stale policy or replay packet. It makes no claim that
// #127, #129 or #130 is complete.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/jihuayu/locklark/pkg/remoteunlock"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// Deterministic synthetic naming, values and caller-supplied timestamps of the
// positive composition flow. No system clock is read for any protocol value.
const (
	compositionNowUnixMS int64 = 1_800_000_000_000

	compositionVaultID           = "vault-remote-unlock-smoke"
	compositionOwnerRootKeyID    = "owner-root-remote-unlock-smoke"
	compositionRequesterMemberID = "member-requester-smoke"
	compositionAuthorMemberID    = "member-writer-smoke"
	compositionDelegateMemberID  = "member-delegate-smoke"

	compositionSourceDeviceID   = "device-source-smoke"
	compositionTargetDeviceID   = "device-target-smoke"
	compositionDelegateDeviceID = "device-delegate-smoke"
	compositionAuthorDeviceID   = "device-author-smoke"

	compositionPairID               = "pair-remote-unlock-smoke"
	compositionPairGeneration       = uint64(3)
	compositionKeyEpoch             = uint64(7)
	compositionFirstLockGeneration  = uint64(11)
	compositionSecondLockGeneration = uint64(12)
	compositionFirstRequestID       = "request-remote-unlock-smoke-0001"
	compositionSecondRequestID      = "request-remote-unlock-smoke-0002"

	compositionRequestDeadlineDeltaMS int64 = 120_000
	compositionAuthorizationDeltaMS   int64 = 30_000
	compositionGrantNotBeforeDeltaMS  int64 = -60_000
	compositionGrantExpiryDeltaMS     int64 = 600_000
	compositionOwnerRootLabel               = "Synthetic owner"
	compositionRequesterLabel               = "Synthetic requester"
	compositionWriterLabel                  = "Synthetic writer"
	compositionDelegateLabel                = "Synthetic delegate admin"
)

// Test-only frame and section bounds.
const (
	compositionFrameHeaderSize  = 4
	compositionRequestFrameMax  = 16 << 10
	compositionApprovalFrameMax = 2
	compositionApprovalMagic    = byte(0xa5)
)

// ---------------------------------------------------------------------------
// TEST-ONLY length-bounded framing helpers.
// ---------------------------------------------------------------------------

// writeTestOnlyFrame writes one bounded length-prefixed payload. A frame's
// length prefix is exactly compositionFrameHeaderSize big-endian bytes. This
// is a test helper, not a product wire format.
func writeTestOnlyFrame(w io.Writer, payload []byte, max int) error {
	if max <= 0 {
		return errors.New("remoteunlocktls test-only frame: invalid bound")
	}
	if len(payload) == 0 || len(payload) > max {
		return fmt.Errorf("remoteunlocktls test-only frame: payload length %d outside (0, %d]", len(payload), max)
	}
	var header [compositionFrameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeTestOnlyAll(w, header[:]); err != nil {
		return err
	}
	return writeTestOnlyAll(w, payload)
}

func writeTestOnlyAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// readTestOnlyFrame reads exactly one bounded length-prefixed payload.
func readTestOnlyFrame(r io.Reader, max int) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("remoteunlocktls test-only frame: invalid bound")
	}
	var header [compositionFrameHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(header[:]))
	if n <= 0 || n > max {
		return nil, fmt.Errorf("remoteunlocktls test-only frame: payload length %d outside (0, %d]", n, max)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ---------------------------------------------------------------------------
// TEST-ONLY request packet.
//
// The packet is a fixed sequence of sections, each length-prefixed with the
// same 4-byte big-endian helper: canonical context bytes, canonical source
// binding bytes, canonical target binding bytes, canonical admin authorization
// bytes and the client's actual exporter binding. Nothing here is a production
// message.
// ---------------------------------------------------------------------------

type compositionRequest struct {
	context       remoteunlock.ChannelBindingContext
	source        remoteunlock.DeviceTransportBinding
	target        remoteunlock.DeviceTransportBinding
	authorization remoteunlock.AdminRemoteUnlockAuthorization
	exporter      []byte
}

type compositionRequestSections struct {
	context       []byte
	source        []byte
	target        []byte
	authorization []byte
	exporter      []byte
}

func encodeCompositionRequest(s compositionRequestSections) ([]byte, error) {
	if len(s.exporter) != ChannelBindingSize {
		return nil, fmt.Errorf("remoteunlocktls test-only request: exporter binding length %d, want %d", len(s.exporter), ChannelBindingSize)
	}
	type section struct {
		name  string
		value []byte
		max   int
	}
	sections := []section{
		{"context", s.context, remoteunlock.MaxContextSize},
		{"source binding", s.source, remoteunlock.MaxBindingSize},
		{"target binding", s.target, remoteunlock.MaxBindingSize},
		{"admin authorization", s.authorization, remoteunlock.MaxAdminAuthorizationSize},
		{"exporter binding", s.exporter, ChannelBindingSize},
	}
	var out []byte
	for _, sec := range sections {
		if len(sec.value) == 0 || len(sec.value) > sec.max {
			return nil, fmt.Errorf("remoteunlocktls test-only request: %s length %d outside (0, %d]", sec.name, len(sec.value), sec.max)
		}
		var header [compositionFrameHeaderSize]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(sec.value)))
		out = append(out, header[:]...)
		out = append(out, sec.value...)
	}
	return out, nil
}

func nextCompositionSection(buf []byte, offset *int, max int) ([]byte, error) {
	if len(buf)-*offset < compositionFrameHeaderSize {
		return nil, errors.New("remoteunlocktls test-only request: truncated section header")
	}
	n := int(binary.BigEndian.Uint32(buf[*offset:]))
	*offset += compositionFrameHeaderSize
	if n <= 0 || n > max {
		return nil, fmt.Errorf("remoteunlocktls test-only request: section length %d outside (0, %d]", n, max)
	}
	if len(buf)-*offset < n {
		return nil, errors.New("remoteunlocktls test-only request: truncated section")
	}
	section := buf[*offset : *offset+n]
	*offset += n
	return section, nil
}

// parseCompositionRequest splits the test-only packet and parses every public
// canonical codec. It never invents a second encoding.
func parseCompositionRequest(buf []byte) (compositionRequest, error) {
	var out compositionRequest
	offset := 0
	contextBytes, err := nextCompositionSection(buf, &offset, remoteunlock.MaxContextSize)
	if err != nil {
		return out, err
	}
	sourceBytes, err := nextCompositionSection(buf, &offset, remoteunlock.MaxBindingSize)
	if err != nil {
		return out, err
	}
	targetBytes, err := nextCompositionSection(buf, &offset, remoteunlock.MaxBindingSize)
	if err != nil {
		return out, err
	}
	authorizationBytes, err := nextCompositionSection(buf, &offset, remoteunlock.MaxAdminAuthorizationSize)
	if err != nil {
		return out, err
	}
	exporter, err := nextCompositionSection(buf, &offset, ChannelBindingSize)
	if err != nil {
		return out, err
	}
	if offset != len(buf) {
		return out, errors.New("remoteunlocktls test-only request: trailing section bytes")
	}
	if len(exporter) != ChannelBindingSize {
		return out, fmt.Errorf("remoteunlocktls test-only request: exporter binding length %d, want %d", len(exporter), ChannelBindingSize)
	}
	out.context, err = remoteunlock.ParseChannelBindingContext(contextBytes)
	if err != nil {
		return out, err
	}
	out.source, err = remoteunlock.ParseDeviceTransportBinding(sourceBytes)
	if err != nil {
		return out, err
	}
	out.target, err = remoteunlock.ParseDeviceTransportBinding(targetBytes)
	if err != nil {
		return out, err
	}
	out.authorization, err = remoteunlock.ParseAdminRemoteUnlockAuthorization(authorizationBytes)
	if err != nil {
		return out, err
	}
	out.exporter = append([]byte(nil), exporter...)
	return out, nil
}

// ---------------------------------------------------------------------------
// TEST-ONLY approval packet.
//
// The server's approval response is two bytes: a fixed magic and a flag that
// states whether one VUK frame follows. It is a test harness acknowledgement,
// not a product approval message.
// ---------------------------------------------------------------------------

func encodeCompositionApproval(vukFollows bool) []byte {
	flag := byte(0)
	if vukFollows {
		flag = 1
	}
	return []byte{compositionApprovalMagic, flag}
}

func parseCompositionApproval(payload []byte) (bool, error) {
	if len(payload) != compositionApprovalFrameMax {
		return false, fmt.Errorf("remoteunlocktls test-only approval: length %d, want %d", len(payload), compositionApprovalFrameMax)
	}
	if payload[0] != compositionApprovalMagic {
		return false, errors.New("remoteunlocktls test-only approval: wrong magic")
	}
	switch payload[1] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("remoteunlocktls test-only approval: wrong VUK flag")
	}
}

// ---------------------------------------------------------------------------
// Synthetic positive fixture.
// ---------------------------------------------------------------------------

// compositionFixture holds one synthetic checkpoint-authentic vault file, the
// caller-pinned current policy checkpoint, one owner-root-signed reusable
// delegation and the device keys needed by the two endpoints and the delegate.
// It deliberately does NOT retain the owner-root private key: the owner root
// signs the carried policy proof and the reusable grant inside the builder
// exactly once, and then its private key is cleared before the fixture is
// returned. No per-request authorization is ever signed by the root.
type compositionFixture struct {
	file           *vaultfile.File
	checkpoint     *vaultfile.PolicyCheckpoint
	policySeq      uint64
	policyDigest   [remoteunlock.DigestSize]byte
	grant          remoteunlock.OwnerRootAdminRemoteUnlockDelegation
	grantCanonical []byte

	ownerRootPublicKey ed25519.PublicKey
	sourceKey          ed25519.PublicKey
	sourcePriv         ed25519.PrivateKey
	targetKey          ed25519.PublicKey
	targetPriv         ed25519.PrivateKey
	delegateContentKey ed25519.PublicKey
	delegatePolicyKey  ed25519.PublicKey
	delegatePolicyPriv ed25519.PrivateKey
	sourceIdentity     *age.X25519Identity
	sourceRecipient    string
	sourceBinding      remoteunlock.DeviceTransportBinding
	targetBinding      remoteunlock.DeviceTransportBinding
}

// newCompositionFixture builds the synthetic policy, sealed file, current
// policy checkpoint, endpoint bindings and the single root-signed reusable
// grant. sourceSPKI is the certificate the server channel actually verified
// for the source PC; targetSPKI is the certificate the client channel actually
// verified for the target device.
func newCompositionFixture(t *testing.T, sourceSPKI, targetSPKI PeerSPKIPin) *compositionFixture {
	t.Helper()

	ownerPub, ownerPriv := syntheticSigningKey(t, "composition owner root")
	defer clear(ownerPriv)
	authorPub, authorPriv := syntheticSigningKey(t, "composition author")
	defer clear(authorPriv)
	sourcePub, sourcePriv := syntheticSigningKey(t, "composition source")
	targetPub, targetPriv := syntheticSigningKey(t, "composition target")
	delegateContentPub, delegateContentPriv := syntheticSigningKey(t, "composition delegate content")
	defer clear(delegateContentPriv)
	delegatePolicyPub, delegatePolicyPriv := syntheticSigningKey(t, "composition delegate policy")

	sourceIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic source age identity: %v", err)
	}
	targetIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic target age identity: %v", err)
	}
	delegateIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic delegate age identity: %v", err)
	}
	authorIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate synthetic author age identity: %v", err)
	}

	// The owner root, both requester endpoint content keys, the delegate's
	// content key and the delegate's policy key are independently generated,
	// and no one of them may be reused for another role. In particular the
	// delegate's policy signing key (the per-request signer) is neither its
	// content signing key nor the owner root.
	namedEdKeys := []struct {
		name string
		key  ed25519.PublicKey
	}{
		{"owner root", ownerPub},
		{"author content", authorPub},
		{"source content", sourcePub},
		{"target content", targetPub},
		{"delegate content", delegateContentPub},
		{"delegate policy", delegatePolicyPub},
	}
	for i := range namedEdKeys {
		if len(namedEdKeys[i].key) != ed25519.PublicKeySize {
			t.Fatalf("synthetic %s key length = %d, want %d", namedEdKeys[i].name, len(namedEdKeys[i].key), ed25519.PublicKeySize)
		}
		for j := i + 1; j < len(namedEdKeys); j++ {
			if bytes.Equal(namedEdKeys[i].key, namedEdKeys[j].key) {
				t.Fatalf("synthetic %s key equals the %s key", namedEdKeys[i].name, namedEdKeys[j].name)
			}
		}
	}

	// Each device carries a real, independently generated age X25519
	// recipient. They must differ so one device's envelope cannot name another.
	namedRecipients := []struct {
		name      string
		recipient string
	}{
		{"source", sourceIdentity.Recipient().String()},
		{"target", targetIdentity.Recipient().String()},
		{"delegate", delegateIdentity.Recipient().String()},
		{"author", authorIdentity.Recipient().String()},
	}
	for i := range namedRecipients {
		for j := i + 1; j < len(namedRecipients); j++ {
			if namedRecipients[i].recipient == namedRecipients[j].recipient {
				t.Fatalf("synthetic %s age recipient equals the %s recipient", namedRecipients[i].name, namedRecipients[j].name)
			}
		}
	}

	// The requester holds only its existing reader role. It is not promoted.
	policy := &vaultfile.Policy{
		Format:    vaultfile.Format,
		Version:   vaultfile.Version,
		VaultID:   compositionVaultID,
		PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID:     compositionOwnerRootKeyID,
			Alg:       vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(ownerPub),
			Owners:    []vaultfile.Principal{{PrincipalID: "alice", Label: compositionOwnerRootLabel}},
		},
		Readers: []vaultfile.Member{{PrincipalID: compositionRequesterMemberID, Label: compositionRequesterLabel}},
		Writers: []vaultfile.Member{{PrincipalID: compositionAuthorMemberID, Label: compositionWriterLabel}},
		Admins:  []vaultfile.Member{{PrincipalID: compositionDelegateMemberID, Label: compositionDelegateLabel}},
		Owners:  []vaultfile.Member{{PrincipalID: "alice", Label: compositionOwnerRootLabel}},
		Devices: []vaultfile.Device{
			{
				DeviceID:          compositionAuthorDeviceID,
				PrincipalID:       compositionAuthorMemberID,
				Label:             "Synthetic author device",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(authorPub)},
				AgeEncryptionKey:  authorIdentity.Recipient().String(),
			},
			{
				DeviceID:          compositionDelegateDeviceID,
				PrincipalID:       compositionDelegateMemberID,
				Label:             "Synthetic delegate admin device",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(delegateContentPub)},
				PolicySigningKey:  &vaultfile.PublicKey{Alg: vaultfile.PolicySigAlgEd25519, PublicKey: bytes.Clone(delegatePolicyPub)},
				AgeEncryptionKey:  delegateIdentity.Recipient().String(),
			},
			{
				DeviceID:          compositionSourceDeviceID,
				PrincipalID:       compositionRequesterMemberID,
				Label:             "Synthetic source PC",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(sourcePub)},
				AgeEncryptionKey:  sourceIdentity.Recipient().String(),
			},
			{
				DeviceID:          compositionTargetDeviceID,
				PrincipalID:       compositionRequesterMemberID,
				Label:             "Synthetic target device",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: bytes.Clone(targetPub)},
				AgeEncryptionKey:  targetIdentity.Recipient().String(),
			},
		},
	}
	if err := vaultfile.ValidatePolicy(policy); err != nil {
		t.Fatalf("synthetic composition policy is not structurally valid: %v", err)
	}

	sourceBinding := signCompositionBinding(t, compositionRequesterMemberID, compositionSourceDeviceID,
		compositionVaultID, compositionPairGeneration, sourceSPKI, "install-source-smoke",
		sourceIdentity.Recipient().String(), sourcePriv)
	targetBinding := signCompositionBinding(t, compositionRequesterMemberID, compositionTargetDeviceID,
		compositionVaultID, compositionPairGeneration, targetSPKI, "install-target-smoke",
		targetIdentity.Recipient().String(), targetPriv)

	document, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatalf("encode synthetic policy document: %v", err)
	}
	policySignature := ed25519.Sign(ownerPriv,
		append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...))

	// Structural placeholders only: no real KDBX, CEK or per-device VUK
	// envelope is carried by the file. Step 5 exercises the genuine VUK API
	// separately over the channel, and every slot below is still structurally
	// shaped and covers exactly the read-capable devices of the current policy.
	const placeholder = "synthetic-placeholder-not-an-encrypted-vault-key"
	slots := make([]vaultfile.DeviceSlot, 0, len(policy.Devices))
	for i := range policy.Devices {
		device := &policy.Devices[i]
		slots = append(slots, vaultfile.DeviceSlot{
			DeviceID:   device.DeviceID,
			Recipient:  device.AgeEncryptionKey,
			WrappedVUK: []byte(placeholder),
		})
	}

	policyDigest := vaultfile.PolicyDigest(policy)
	file := &vaultfile.File{
		Format:  vaultfile.Format,
		Version: vaultfile.Version,
		Header: vaultfile.Header{
			VaultID:        compositionVaultID,
			KeyEpoch:       compositionKeyEpoch,
			ContentSeq:     0,
			PrevDigest:     nil,
			OpID:           "op-remote-unlock-smoke-0001",
			PolicySeq:      policy.PolicySeq,
			PolicyDigest:   policyDigest,
			AuthorDeviceID: compositionAuthorDeviceID,
		},
		SignedPolicyProofs: []vaultfile.SignedPolicy{{
			Policy:   *policy,
			Document: document,
			SignerID: compositionOwnerRootKeyID,
			Alg:      vaultfile.PolicySigAlgEd25519,
			Sig:      policySignature,
		}},
		ContentEncoding: vaultfile.ContentEncoding,
		KDBXCiphertext:  []byte("synthetic-kdbx-ciphertext-remote-unlock-smoke-not-a-real-kdbx"),
		VUKDeviceSlots:  slots,
		CEKSlot: vaultfile.CEKSlot{
			KeyEpoch:   compositionKeyEpoch,
			WrappedCEK: []byte(placeholder),
		},
	}

	draft := *file
	draft.Header.RevisionID = ""
	draft.ContentSignature = vaultfile.Signature{
		SignerID: compositionAuthorDeviceID,
		Alg:      vaultfile.SigAlgEd25519,
		Sig:      make([]byte, ed25519.SignatureSize),
	}
	contentInput, err := vaultfile.ContentSigningBytes(&draft)
	if err != nil {
		t.Fatalf("synthetic composition content preimage: %v", err)
	}
	draft.ContentSignature.Sig = ed25519.Sign(authorPriv,
		append([]byte(vaultfile.DomainContentSignature+"\x00"), contentInput...))
	wire, err := vaultfile.SealFile(&draft, &draft.ContentSignature)
	if err != nil {
		t.Fatalf("seal synthetic composition file: %v", err)
	}
	sealed, err := vaultfile.ParseFile(wire)
	if err != nil {
		t.Fatalf("parse sealed synthetic composition file: %v", err)
	}

	// The caller pins the current policy exactly as carried. This is the
	// already-trusted state; VerifyPolicyCheckpoint must authenticate it before
	// any policy claim is used.
	checkpoint := &vaultfile.PolicyCheckpoint{
		VaultID:            compositionVaultID,
		OwnerRootKeyID:     compositionOwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(ownerPub),
		PolicySeq:          policy.PolicySeq,
		PolicyDigest:       vaultfile.PolicyDigest(policy),
	}
	if err := vaultfile.VerifyPolicyCheckpoint(sealed, checkpoint); err != nil {
		t.Fatalf("synthetic composition file is not checkpoint-authentic: %v", err)
	}

	sourceDigest, err := remoteunlock.DeviceTransportBindingDigest(sourceBinding)
	if err != nil {
		t.Fatalf("synthetic source binding digest: %v", err)
	}
	targetDigest, err := remoteunlock.DeviceTransportBindingDigest(targetBinding)
	if err != nil {
		t.Fatalf("synthetic target binding digest: %v", err)
	}

	var grantedDigest [remoteunlock.DigestSize]byte
	copy(grantedDigest[:], vaultfile.PolicyDigest(policy))
	var delegatePolicyKey [remoteunlock.AdminDelegationPublicKeySize]byte
	copy(delegatePolicyKey[:], delegatePolicyPub)

	grant := remoteunlock.OwnerRootAdminRemoteUnlockDelegation{
		OwnerRootKeyID:           compositionOwnerRootKeyID,
		DelegateMemberID:         compositionDelegateMemberID,
		DelegateDeviceID:         compositionDelegateDeviceID,
		DelegatePolicySigningKey: delegatePolicyKey,
		VaultID:                  compositionVaultID,
		RequesterMemberID:        compositionRequesterMemberID,
		SourceDeviceID:           compositionSourceDeviceID,
		TargetDeviceID:           compositionTargetDeviceID,
		SourceBindingSHA256:      sourceDigest,
		TargetBindingSHA256:      targetDigest,
		PairGeneration:           compositionPairGeneration,
		KeyEpoch:                 compositionKeyEpoch,
		PolicySeq:                policy.PolicySeq,
		PolicyDigest:             grantedDigest,
		NotBeforeUnixMS:          compositionNowUnixMS + compositionGrantNotBeforeDeltaMS,
		ExpiresUnixMS:            compositionNowUnixMS + compositionGrantExpiryDeltaMS,
	}
	// The owner root signs the reusable grant exactly once, here. The private
	// key is cleared when this builder returns and is never stored in the
	// fixture, so no per-request authorization can use it.
	grantMessage, err := remoteunlock.AdminDelegationSigningBytes(grant)
	if err != nil {
		t.Fatalf("synthetic reusable grant preimage: %v", err)
	}
	copy(grant.Signature[:], ed25519.Sign(ownerPriv, grantMessage))
	if !ed25519.Verify(ownerPub, grantMessage, grant.Signature[:]) {
		t.Fatal("synthetic reusable grant signature does not verify under the synthetic owner root")
	}
	grantCanonical, err := remoteunlock.EncodeOwnerRootAdminRemoteUnlockDelegation(grant)
	if err != nil {
		t.Fatalf("encode synthetic reusable grant: %v", err)
	}
	if err := remoteunlock.VerifyOwnerRootAdminRemoteUnlockDelegation(sealed, checkpoint, grant, compositionNowUnixMS); err != nil {
		t.Fatalf("synthetic reusable grant does not verify against the pinned current policy: %v", err)
	}

	return &compositionFixture{
		file:               sealed,
		checkpoint:         checkpoint,
		policySeq:          policy.PolicySeq,
		policyDigest:       grantedDigest,
		grant:              grant,
		grantCanonical:     grantCanonical,
		ownerRootPublicKey: bytes.Clone(ownerPub),
		sourceKey:          bytes.Clone(sourcePub),
		sourcePriv:         sourcePriv,
		targetKey:          bytes.Clone(targetPub),
		targetPriv:         targetPriv,
		delegateContentKey: bytes.Clone(delegateContentPub),
		delegatePolicyKey:  bytes.Clone(delegatePolicyPub),
		delegatePolicyPriv: delegatePolicyPriv,
		sourceIdentity:     sourceIdentity,
		sourceRecipient:    sourceIdentity.Recipient().String(),
		sourceBinding:      sourceBinding,
		targetBinding:      targetBinding,
	}
}

// signCompositionBinding builds one stable binding and signs it with the
// device's real content signing key over the canonical public preimage.
func signCompositionBinding(t *testing.T, memberID, deviceID, vaultID string, pairGeneration uint64, spki PeerSPKIPin, installID, recipient string, priv ed25519.PrivateKey) remoteunlock.DeviceTransportBinding {
	t.Helper()
	binding := remoteunlock.DeviceTransportBinding{
		MemberID:           memberID,
		DeviceID:           deviceID,
		InstallID:          installID,
		VaultID:            vaultID,
		PairGeneration:     pairGeneration,
		SPKISHA256:         [remoteunlock.BindingSPKIDigestSize]byte(spki),
		RecipientPublicKey: recipient,
	}
	message, err := remoteunlock.SigningBytes(binding)
	if err != nil {
		t.Fatalf("synthetic binding preimage for %s: %v", deviceID, err)
	}
	copy(binding.Signature[:], ed25519.Sign(priv, message))
	return binding
}

// compositionContext builds one fresh request context wholly inside the grant
// scope. Only request_id, request_digest and lock_generation vary per request.
func compositionContext(fx *compositionFixture, requestID string, requestDigest [remoteunlock.DigestSize]byte, lockGeneration uint64) remoteunlock.ChannelBindingContext {
	return remoteunlock.ChannelBindingContext{
		RequestID:      requestID,
		RequestDigest:  requestDigest,
		PairID:         compositionPairID,
		PairGeneration: compositionPairGeneration,
		LockGeneration: lockGeneration,
		MemberID:       compositionRequesterMemberID,
		SourceDeviceID: compositionSourceDeviceID,
		TargetDeviceID: compositionTargetDeviceID,
		VaultID:        compositionVaultID,
		KeyEpoch:       compositionKeyEpoch,
		PolicySeq:      fx.policySeq,
		PolicyDigest:   fx.policyDigest,
		DeadlineUnixMS: compositionNowUnixMS + compositionRequestDeadlineDeltaMS,
	}
}

func compositionRequestDigest(label string) [remoteunlock.DigestSize]byte {
	return sha256.Sum256([]byte("locklark.synthetic.remote-unlock.request\x00" + label))
}

// signCompositionAuthorization has the delegated admin device sign one fresh
// per-request authorization with its policy signing key. The owner root is
// never involved.
func signCompositionAuthorization(t *testing.T, fx *compositionFixture, c remoteunlock.ChannelBindingContext) (remoteunlock.AdminRemoteUnlockAuthorization, []byte) {
	t.Helper()
	delegationDigest, err := remoteunlock.AdminDelegationDigest(fx.grant)
	if err != nil {
		t.Fatalf("synthetic reusable grant digest: %v", err)
	}
	contextDigest, err := remoteunlock.RemoteUnlockContextDigest(c)
	if err != nil {
		t.Fatalf("synthetic request context digest: %v", err)
	}
	sourceDigest, err := remoteunlock.DeviceTransportBindingDigest(fx.sourceBinding)
	if err != nil {
		t.Fatalf("synthetic source binding digest: %v", err)
	}
	targetDigest, err := remoteunlock.DeviceTransportBindingDigest(fx.targetBinding)
	if err != nil {
		t.Fatalf("synthetic target binding digest: %v", err)
	}
	authorization := remoteunlock.AdminRemoteUnlockAuthorization{
		DelegationDigest:    delegationDigest,
		ContextSHA256:       contextDigest,
		SourceBindingSHA256: sourceDigest,
		TargetBindingSHA256: targetDigest,
		ExpiresUnixMS:       compositionNowUnixMS + compositionAuthorizationDeltaMS,
	}
	message, err := remoteunlock.AdminAuthorizationSigningBytes(authorization)
	if err != nil {
		t.Fatalf("synthetic admin authorization preimage: %v", err)
	}
	copy(authorization.Signature[:], ed25519.Sign(fx.delegatePolicyPriv, message))
	encoded, err := remoteunlock.EncodeAdminRemoteUnlockAuthorization(authorization)
	if err != nil {
		t.Fatalf("encode synthetic admin authorization: %v", err)
	}
	return authorization, encoded
}

func syntheticCompositionVUK() []byte {
	sum := sha256.Sum256([]byte("locklark.synthetic.remote-unlock.vuk.0001"))
	return append([]byte(nil), sum[:]...)
}

func compositionPolicyAgeRecipient(f *vaultfile.File, deviceID string) (string, error) {
	if f == nil || len(f.SignedPolicyProofs) == 0 {
		return "", errors.New("remoteunlocktls test-only server: no authenticated current policy")
	}
	policy := &f.SignedPolicyProofs[len(f.SignedPolicyProofs)-1].Policy
	for i := range policy.Devices {
		if policy.Devices[i].DeviceID == deviceID {
			return policy.Devices[i].AgeEncryptionKey, nil
		}
	}
	return "", errors.New("remoteunlocktls test-only server: scoped source device is absent from the current policy")
}

func assertCompositionCleared(t *testing.T, name string, b []byte) {
	t.Helper()
	for _, v := range b {
		if v != 0 {
			t.Fatalf("%s buffer was not cleared", name)
		}
	}
}

// compositionServerResult is one test server's outcome.
type compositionServerResult struct {
	vukFrames int
	err       error
}

// runCompositionServer is the test-only server side. It parses the canonical
// public codecs, verifies the request exporter on the actual server channel,
// verifies the source peer binding against the channel's verified peer SPKI
// with the current-policy content key, and then composes the pinned file,
// checkpoint, grant and per-request authorization. Only the first verified
// request produces one genuine VUK envelope frame.
func runCompositionServer(ch *Channel, fx *compositionFixture) (int, error) {
	vukFrames := 0
	vuk := syntheticCompositionVUK()
	defer clear(vuk)

	for requestIndex := 0; requestIndex < 2; requestIndex++ {
		payload, err := readTestOnlyFrame(ch, compositionRequestFrameMax)
		if err != nil {
			return vukFrames, fmt.Errorf("read test-only request frame %d: %w", requestIndex+1, err)
		}
		request, err := parseCompositionRequest(payload)
		if err != nil {
			return vukFrames, fmt.Errorf("parse test-only request %d: %w", requestIndex+1, err)
		}

		// 1. The exporter value the client actually derived on this channel.
		if err := ch.VerifyBindingContext(request.context, request.exporter); err != nil {
			return vukFrames, fmt.Errorf("request %d exporter binding: %w", requestIndex+1, err)
		}
		// 2. The source peer binding names the client certificate the server
		// channel actually verified, and verifies under the current policy's
		// source content signing key.
		if err := ch.VerifyPeerDeviceTransportBinding(request.source, request.context,
			request.context.SourceDeviceID, fx.sourceKey); err != nil {
			return vukFrames, fmt.Errorf("request %d source peer binding: %w", requestIndex+1, err)
		}
		// 3. The composed owner-root grant and delegated-device per-request
		// authorization against the pinned current file and checkpoint.
		if err := remoteunlock.VerifyAdminRemoteUnlockAuthorization(fx.file, fx.checkpoint,
			fx.grant, request.authorization, request.context, request.source,
			request.target, compositionNowUnixMS); err != nil {
			return vukFrames, fmt.Errorf("request %d composed authorization: %w", requestIndex+1, err)
		}

		vukFollows := requestIndex == 0
		if err := writeTestOnlyFrame(ch, encodeCompositionApproval(vukFollows), compositionApprovalFrameMax); err != nil {
			return vukFrames, fmt.Errorf("write test-only approval frame %d: %w", requestIndex+1, err)
		}
		if !vukFollows {
			continue
		}

		// The composed verifier above returned nil, so it authenticated this
		// current policy and this scoped source device. The recipient is taken
		// from that authenticated policy, never from the request.
		recipient, err := compositionPolicyAgeRecipient(fx.file, compositionSourceDeviceID)
		if err != nil {
			return vukFrames, err
		}
		slot, err := vaultfile.SealVUKForDevice(vuk, fx.file.Header.VaultID,
			fx.file.Header.KeyEpoch, compositionSourceDeviceID, recipient)
		if err != nil {
			return vukFrames, fmt.Errorf("seal VUK for the source device: %w", err)
		}
		if err := writeTestOnlyFrame(ch, slot.WrappedVUK, vaultfile.MaxWrappedKeyLength); err != nil {
			return vukFrames, fmt.Errorf("write test-only VUK frame: %w", err)
		}
		vukFrames++
	}
	return vukFrames, nil
}

// TestLoopbackPositiveCompositionSmoke is the single positive-composition
// checkpoint for this branch. It uses the existing real 127.0.0.1:0 loopback
// mTLS harness, one concurrent client/server handshake, one byte-identical
// owner-root-signed reusable grant, two fresh delegated-admin request
// authorizations, and one genuine per-device age VUK envelope delivery.
func TestLoopbackPositiveCompositionSmoke(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverPin := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, clientPin := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	clientGot, serverGot := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   serverPin,
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   clientPin,
		},
	)
	client := mustChannel(t, "ClientHandshake", clientGot)
	server := mustChannel(t, "ServerHandshake", serverGot)

	for name, ch := range map[string]*Channel{"client": client, "server": server} {
		if err := ch.Check(); err != nil {
			t.Fatalf("%s Check: %v", name, err)
		}
		state := ch.conn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			t.Fatalf("%s negotiated TLS version %#x, want TLS 1.3", name, state.Version)
		}
		if state.DidResume {
			t.Fatalf("%s resumed a TLS session", name)
		}
	}

	// Bound every test-only exchange so a composed rejection cannot hang the
	// loopback harness.
	deadline := time.Now().Add(testHandshakeLimit)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("client SetDeadline: %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatalf("server SetDeadline: %v", err)
	}

	// The server channel verified the client leaf (the source PC); the client
	// channel verified the server leaf (the target device). The stable
	// bindings carry exactly those actual verified SPKIs.
	fx := newCompositionFixture(t, peerLeafPin(t, "server", server), peerLeafPin(t, "client", client))

	// The synthetic file must be checkpoint-authentic before anything else.
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.checkpoint); err != nil {
		t.Fatalf("pinned current PolicyCheckpoint does not authenticate the synthetic file: %v", err)
	}
	// The requester keeps only its existing reader role and was not promoted.
	policy := &fx.file.SignedPolicyProofs[len(fx.file.SignedPolicyProofs)-1].Policy
	requesterIsReader := false
	for _, member := range policy.Readers {
		if member.PrincipalID == compositionRequesterMemberID {
			requesterIsReader = true
		}
	}
	if !requesterIsReader {
		t.Fatal("synthetic requester is not listed with its existing reader role")
	}
	for _, role := range [][]vaultfile.Member{policy.Writers, policy.Admins, policy.Owners} {
		for _, member := range role {
			if member.PrincipalID == compositionRequesterMemberID {
				t.Fatal("synthetic requester was promoted out of its existing reader-only role")
			}
		}
	}
	if fx.sourceKey != nil && fx.delegatePolicyKey != nil && bytes.Equal(fx.sourceKey, fx.delegatePolicyKey) {
		t.Fatal("source content key equals the delegate policy signing key")
	}
	if bytes.Equal(fx.delegateContentKey, fx.delegatePolicyKey) {
		t.Fatal("delegate content key equals the delegate policy signing key")
	}
	if bytes.Equal(fx.ownerRootPublicKey, fx.delegatePolicyKey) {
		t.Fatal("owner root key equals the delegate policy signing key")
	}

	// The same canonical root grant, byte for byte, covers both fresh requests.
	freshGrantBytes, err := remoteunlock.EncodeOwnerRootAdminRemoteUnlockDelegation(fx.grant)
	if err != nil {
		t.Fatalf("re-encode synthetic reusable grant: %v", err)
	}
	if !bytes.Equal(freshGrantBytes, fx.grantCanonical) {
		t.Fatal("reusable grant canonical bytes changed between requests")
	}

	ctx1 := compositionContext(fx, compositionFirstRequestID,
		compositionRequestDigest("0001"), compositionFirstLockGeneration)
	ctx2 := compositionContext(fx, compositionSecondRequestID,
		compositionRequestDigest("0002"), compositionSecondLockGeneration)
	if ctx1 == ctx2 {
		t.Fatal("the two synthetic request contexts are not distinct")
	}
	if ctx1.RequestID == ctx2.RequestID || ctx1.RequestDigest == ctx2.RequestDigest ||
		ctx1.LockGeneration == ctx2.LockGeneration {
		t.Fatal("request_id, request_digest and lock_generation must all differ per request")
	}
	// Everything else stays within the same grant scope and policy.
	if ctx1.PairID != ctx2.PairID || ctx1.PairGeneration != ctx2.PairGeneration ||
		ctx1.MemberID != ctx2.MemberID || ctx1.SourceDeviceID != ctx2.SourceDeviceID ||
		ctx1.TargetDeviceID != ctx2.TargetDeviceID || ctx1.VaultID != ctx2.VaultID ||
		ctx1.KeyEpoch != ctx2.KeyEpoch || ctx1.PolicySeq != ctx2.PolicySeq ||
		ctx1.PolicyDigest != ctx2.PolicyDigest || ctx1.DeadlineUnixMS != ctx2.DeadlineUnixMS {
		t.Fatal("the two request contexts do not share the same grant scope and policy")
	}

	auth1, authBytes1 := signCompositionAuthorization(t, fx, ctx1)
	auth2, authBytes2 := signCompositionAuthorization(t, fx, ctx2)
	if auth1.Signature == auth2.Signature {
		t.Fatal("two distinct contexts produced the same delegated-admin signature")
	}
	if auth1.ContextSHA256 == auth2.ContextSHA256 {
		t.Fatal("two distinct contexts produced the same context digest")
	}
	if auth1.DelegationDigest != auth2.DelegationDigest {
		t.Fatal("the two request authorizations do not bind the same reusable grant")
	}

	// Each authorization is genuinely signed by the delegate's policy signing
	// key, and not by the owner root or the delegate's content signing key.
	for index, authorization := range []remoteunlock.AdminRemoteUnlockAuthorization{auth1, auth2} {
		message, err := remoteunlock.AdminAuthorizationSigningBytes(authorization)
		if err != nil {
			t.Fatalf("request %d authorization preimage: %v", index+1, err)
		}
		if !ed25519.Verify(fx.delegatePolicyKey, message, authorization.Signature[:]) {
			t.Fatalf("request %d authorization does not verify under the delegate policy key", index+1)
		}
		if ed25519.Verify(fx.ownerRootPublicKey, message, authorization.Signature[:]) {
			t.Fatalf("request %d authorization verifies under the owner root key", index+1)
		}
		if ed25519.Verify(fx.delegateContentKey, message, authorization.Signature[:]) {
			t.Fatalf("request %d authorization verifies under the delegate content key", index+1)
		}
	}

	// Model the requester's process-local lifecycle for request 1 only. This
	// is an in-memory state machine: it is not restorable and provides no
	// durable restart or anti-rollback guarantee.
	lifecycle, err := remoteunlock.NewRequestLifecycle(ctx1, compositionNowUnixMS)
	if err != nil {
		t.Fatalf("NewRequestLifecycle: %v", err)
	}
	if status, err := lifecycle.StatusAt(compositionNowUnixMS); err != nil {
		t.Fatalf("StatusAt(requested): %v", err)
	} else if status != remoteunlock.StatusRequested {
		t.Fatalf("initial lifecycle status = %q, want %q", status, remoteunlock.StatusRequested)
	}

	serverResultCh := make(chan compositionServerResult, 1)
	go func() {
		vukFrames, err := runCompositionServer(server, fx)
		serverResultCh <- compositionServerResult{vukFrames: vukFrames, err: err}
	}()

	exchanges := []struct {
		context   remoteunlock.ChannelBindingContext
		authBytes []byte
	}{
		{context: ctx1, authBytes: authBytes1},
		{context: ctx2, authBytes: authBytes2},
	}

	var receivedVUK []byte
	for index, exchange := range exchanges {
		// Client side: the target peer binding always names the server leaf
		// this channel actually verified, under the current-policy target
		// content signing key.
		if err := client.VerifyPeerDeviceTransportBinding(fx.targetBinding, exchange.context,
			exchange.context.TargetDeviceID, fx.targetKey); err != nil {
			t.Fatalf("request %d target peer binding: %v", index+1, err)
		}

		exporter, err := client.ExportBindingContext(exchange.context)
		if err != nil {
			t.Fatalf("request %d client ExportBindingContext: %v", index+1, err)
		}
		contextBytes, err := remoteunlock.EncodeChannelBindingContext(exchange.context)
		if err != nil {
			t.Fatalf("request %d encode context: %v", index+1, err)
		}
		sourceBytes, err := remoteunlock.EncodeDeviceTransportBinding(fx.sourceBinding)
		if err != nil {
			t.Fatalf("request %d encode source binding: %v", index+1, err)
		}
		targetBytes, err := remoteunlock.EncodeDeviceTransportBinding(fx.targetBinding)
		if err != nil {
			t.Fatalf("request %d encode target binding: %v", index+1, err)
		}
		packet, err := encodeCompositionRequest(compositionRequestSections{
			context:       contextBytes,
			source:        sourceBytes,
			target:        targetBytes,
			authorization: exchange.authBytes,
			exporter:      exporter,
		})
		if err != nil {
			t.Fatalf("request %d encode test-only packet: %v", index+1, err)
		}
		if err := writeTestOnlyFrame(client, packet, compositionRequestFrameMax); err != nil {
			t.Fatalf("request %d write test-only packet: %v", index+1, err)
		}

		approvalPayload, err := readTestOnlyFrame(client, compositionApprovalFrameMax)
		if err != nil {
			t.Fatalf("request %d read test-only approval: %v", index+1, err)
		}
		vukFollows, err := parseCompositionApproval(approvalPayload)
		if err != nil {
			t.Fatalf("request %d parse test-only approval: %v", index+1, err)
		}
		if vukFollows != (index == 0) {
			t.Fatalf("request %d VUK-follows flag = %v, want %v", index+1, vukFollows, index == 0)
		}
		if index != 0 {
			// Request 2 is authorized and approved but receives no VUK frame.
			continue
		}

		// The peer approved request 1: requested -> confirmed.
		if err := lifecycle.Confirm(compositionNowUnixMS + 1_000); err != nil {
			t.Fatalf("lifecycle Confirm after approval: %v", err)
		}
		if status, err := lifecycle.StatusAt(compositionNowUnixMS + 1_000); err != nil {
			t.Fatalf("StatusAt(confirmed): %v", err)
		} else if status != remoteunlock.StatusConfirmed {
			t.Fatalf("confirmed lifecycle status = %q, want %q", status, remoteunlock.StatusConfirmed)
		}

		// Request 1 receives exactly one bounded genuine age envelope.
		wrappedVUK, err := readTestOnlyFrame(client, vaultfile.MaxWrappedKeyLength)
		if err != nil {
			t.Fatalf("read bounded VUK frame: %v", err)
		}
		slot := vaultfile.DeviceSlot{
			DeviceID:   compositionSourceDeviceID,
			Recipient:  fx.sourceRecipient,
			WrappedVUK: wrappedVUK,
		}
		// The expected vault, epoch, source device and recipient are taken
		// independently from the authenticated fixture/policy, never from the
		// received slot.
		receivedVUK, err = vaultfile.OpenVUKForDevice(slot,
			fx.file.Header.VaultID, fx.file.Header.KeyEpoch,
			compositionSourceDeviceID, fx.sourceRecipient, fx.sourceIdentity)
		if err != nil {
			t.Fatalf("OpenVUKForDevice over the TLS-delivered envelope: %v", err)
		}
		expectedVUK := syntheticCompositionVUK()
		if len(receivedVUK) != vaultfile.CEKSize {
			t.Fatalf("received VUK length = %d, want %d", len(receivedVUK), vaultfile.CEKSize)
		}
		if subtle.ConstantTimeCompare(receivedVUK, expectedVUK) != 1 {
			t.Fatal("received VUK bytes differ from the independent expected VUK")
		}
		// Clear every caller-owned plaintext/VUK buffer and prove it.
		clear(receivedVUK)
		clear(expectedVUK)
		clear(wrappedVUK)
		assertCompositionCleared(t, "received VUK", receivedVUK)
		assertCompositionCleared(t, "expected VUK", expectedVUK)

		// One successful authenticated receive: confirmed -> received.
		if err := lifecycle.Receive(compositionNowUnixMS + 2_000); err != nil {
			t.Fatalf("lifecycle Receive after authenticated VUK: %v", err)
		}
		if status, err := lifecycle.StatusAt(compositionNowUnixMS + 2_000); err != nil {
			t.Fatalf("StatusAt(received): %v", err)
		} else if status != remoteunlock.StatusReceived {
			t.Fatalf("received lifecycle status = %q, want %q", status, remoteunlock.StatusReceived)
		}

		// A second local consume is rejected. Receive returns no key material,
		// and the only local VUK buffer was already cleared above, so this
		// rejected transition exposes no VUK bytes.
		receivedVUK = nil
		if err := lifecycle.Receive(compositionNowUnixMS + 3_000); !errors.Is(err, remoteunlock.ErrLifecycleTransition) {
			t.Fatalf("second lifecycle Receive = %v, want ErrLifecycleTransition", err)
		}
		if receivedVUK != nil {
			t.Fatal("a rejected second local consume produced VUK bytes")
		}
		if status, err := lifecycle.StatusAt(compositionNowUnixMS + 3_000); err != nil {
			t.Fatalf("StatusAt(after rejected second receive): %v", err)
		} else if status != remoteunlock.StatusReceived {
			t.Fatalf("lifecycle status after rejected second receive = %q, want %q", status, remoteunlock.StatusReceived)
		}
	}

	var serverResult compositionServerResult
	select {
	case serverResult = <-serverResultCh:
	case <-time.After(testHandshakeLimit):
		t.Fatal("timed out waiting for the test-only composition server")
	}
	if serverResult.err != nil {
		t.Fatalf("test-only composition server: %v", serverResult.err)
	}
	if serverResult.vukFrames != 1 {
		t.Fatalf("server produced %d VUK frames, want exactly 1", serverResult.vukFrames)
	}

	// Both requests passed against the one byte-identical reusable grant, and
	// no second owner-root signing step was performed or exposed.
	afterBytes, err := remoteunlock.EncodeOwnerRootAdminRemoteUnlockDelegation(fx.grant)
	if err != nil {
		t.Fatalf("re-encode reusable grant after both requests: %v", err)
	}
	if !bytes.Equal(afterBytes, fx.grantCanonical) {
		t.Fatal("the reusable grant changed after the two requests")
	}
	if err := remoteunlock.VerifyOwnerRootAdminRemoteUnlockDelegation(
		fx.file, fx.checkpoint, fx.grant, compositionNowUnixMS); err != nil {
		t.Fatalf("reusable grant no longer verifies after both requests: %v", err)
	}
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.checkpoint); err != nil {
		t.Fatalf("synthetic file/checkpoint no longer verify after both requests: %v", err)
	}
}
