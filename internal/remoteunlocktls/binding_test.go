package remoteunlocktls

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jihuayu/locklark/pkg/remoteunlock"
)

// All keys, certificates and recipients in this file are SYNTHETIC test data
// generated in memory. The Ed25519 signing keys sign only manufactured binding
// structs; the TLS certificates are anonymous test leaves from newTestCA; and
// the age recipient belongs to no real device. Nothing here is an enrolled
// device, member, vault or pairing, and a passing test proves no authorization.

// syntheticRecipient is a throwaway, canonical age X25519 recipient reused only
// for test bindings. It is not an identity of any device.
const syntheticRecipient = "age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea"

// peerLeafPin returns the SPKI pin of the verified peer leaf on ch, failing if
// the channel has no verified peer chain.
func peerLeafPin(t *testing.T, name string, ch *Channel) PeerSPKIPin {
	t.Helper()
	cs := ch.conn.ConnectionState()
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		t.Fatalf("%s: no verified peer chain", name)
	}
	return PeerSPKIPinOf(cs.VerifiedChains[0][0])
}

// syntheticSigningKey generates a real Ed25519 key pair for test fixtures.
func syntheticSigningKey(t *testing.T, name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic %s signing key: %v", name, err)
	}
	return pub, priv
}

// signedBinding builds a binding for endpoint with spki and signs it with a
// real crypto/ed25519 signature over remoteunlock.SigningBytes.
func signedBinding(t *testing.T, endpoint *remoteunlock.DeviceTransportBinding, spki PeerSPKIPin, installID string, priv ed25519.PrivateKey) remoteunlock.DeviceTransportBinding {
	t.Helper()
	b := remoteunlock.DeviceTransportBinding{
		MemberID:           endpoint.MemberID,
		DeviceID:           endpoint.DeviceID,
		InstallID:          installID,
		VaultID:            endpoint.VaultID,
		PairGeneration:     endpoint.PairGeneration,
		SPKISHA256:         [remoteunlock.BindingSPKIDigestSize]byte(spki),
		RecipientPublicKey: syntheticRecipient,
	}
	msg, err := remoteunlock.SigningBytes(b)
	if err != nil {
		t.Fatalf("SigningBytes(%s): %v", b.DeviceID, err)
	}
	copy(b.Signature[:], ed25519.Sign(priv, msg))
	return b
}

// bindingTestFixture is one loopback mTLS handshake plus synthetic signing
// material for both endpoints of a synthetic context.
type bindingTestFixture struct {
	client, server *Channel
	ctx            remoteunlock.ChannelBindingContext
	sourceKey      ed25519.PublicKey
	targetKey      ed25519.PublicKey
	sourceBinding  remoteunlock.DeviceTransportBinding
	targetBinding  remoteunlock.DeviceTransportBinding
}

// newBindingTestFixture handshakes on the existing typedTestChannels harness and
// signs one binding per endpoint. Each binding's SPKISHA256 is the actual
// certificate this channel verified for its peer, read from the channel's own
// ConnectionState: the server channel sees the client leaf, so it verifies the
// source (client) binding; the client channel sees the server leaf, so it
// verifies the target (server) binding. Per crypto/tls, ConnectionState is the
// perspective of the local side.
func newBindingTestFixture(t *testing.T) *bindingTestFixture {
	t.Helper()
	client, server := typedTestChannels(t)
	ctx := typedTestContext()

	clientLeaf := peerLeafPin(t, "client", client) // the server's leaf
	serverLeaf := peerLeafPin(t, "server", server) // the client's leaf

	sourcePub, sourcePriv := syntheticSigningKey(t, "source")
	targetPub, targetPriv := syntheticSigningKey(t, "target")

	return &bindingTestFixture{
		client:    client,
		server:    server,
		ctx:       ctx,
		sourceKey: sourcePub,
		targetKey: targetPub,
		sourceBinding: signedBinding(t, &remoteunlock.DeviceTransportBinding{
			MemberID:       ctx.MemberID,
			DeviceID:       ctx.SourceDeviceID,
			VaultID:        ctx.VaultID,
			PairGeneration: ctx.PairGeneration,
		}, serverLeaf, "install-source-test", sourcePriv),
		targetBinding: signedBinding(t, &remoteunlock.DeviceTransportBinding{
			MemberID:       ctx.MemberID,
			DeviceID:       ctx.TargetDeviceID,
			VaultID:        ctx.VaultID,
			PairGeneration: ctx.PairGeneration,
		}, clientLeaf, "install-target-test", targetPriv),
	}
}

// TestVerifyPeerDeviceTransportBindingAcceptsBothEndpoints asserts that a
// binding naming the channel's verified peer leaf verifies on that channel,
// once per endpoint direction, each with its caller-pinned key.
func TestVerifyPeerDeviceTransportBindingAcceptsBothEndpoints(t *testing.T) {
	f := newBindingTestFixture(t)

	// The server channel verified the client leaf: check the source binding.
	if err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, f.ctx, f.ctx.SourceDeviceID, f.sourceKey); err != nil {
		t.Fatalf("server VerifyPeerDeviceTransportBinding(source binding) = %v, want nil", err)
	}
	// The client channel verified the server leaf: check the target binding.
	if err := f.client.VerifyPeerDeviceTransportBinding(f.targetBinding, f.ctx, f.ctx.TargetDeviceID, f.targetKey); err != nil {
		t.Fatalf("client VerifyPeerDeviceTransportBinding(target binding) = %v, want nil", err)
	}
}

// TestVerifyPeerDeviceTransportBindingWrongSPKI asserts a binding whose SPKI
// digest is not the verified peer leaf is rejected with the SPKI sentinel, and
// that this happens before the signature and context checks even on an open
// channel: a wrong signature and a mismatched context still lose to it.
func TestVerifyPeerDeviceTransportBindingWrongSPKI(t *testing.T) {
	f := newBindingTestFixture(t)

	// The server channel verified the client leaf, which is the source
	// binding's SPKI. Perturb it so it no longer matches.
	wrongSPKI := f.sourceBinding
	wrongSPKI.SPKISHA256 = [remoteunlock.BindingSPKIDigestSize]byte(wrongPin(PeerSPKIPin(f.sourceBinding.SPKISHA256)))

	if err := f.server.VerifyPeerDeviceTransportBinding(wrongSPKI, f.ctx, f.ctx.SourceDeviceID, f.sourceKey); !errors.Is(err, ErrDeviceTransportBindingSPKIMismatch) {
		t.Fatalf("wrong SPKI = %v, want ErrDeviceTransportBindingSPKIMismatch", err)
	}

	// Same channel, correct SPKI, but a tampered signature: the public
	// verifier reports ErrInvalidBinding. With the SPKI also wrong the
	// channel reports the SPKI sentinel first.
	badSignature := f.sourceBinding
	badSignature.Signature[0] ^= 0xff
	if err := f.server.VerifyPeerDeviceTransportBinding(badSignature, f.ctx, f.ctx.SourceDeviceID, f.sourceKey); !errors.Is(err, remoteunlock.ErrInvalidBinding) {
		t.Fatalf("correct SPKI, bad signature = %v, want remoteunlock.ErrInvalidBinding", err)
	}
	badSignature.SPKISHA256 = wrongSPKI.SPKISHA256
	if err := f.server.VerifyPeerDeviceTransportBinding(badSignature, f.ctx, f.ctx.SourceDeviceID, f.sourceKey); !errors.Is(err, ErrDeviceTransportBindingSPKIMismatch) {
		t.Fatalf("wrong SPKI, bad signature = %v, want ErrDeviceTransportBindingSPKIMismatch", err)
	}

	// A mismatched context likewise loses to the SPKI check.
	otherCtx := withMember(f.ctx, f.ctx.MemberID+"-other")
	if err := f.server.VerifyPeerDeviceTransportBinding(wrongSPKI, otherCtx, f.ctx.SourceDeviceID, f.sourceKey); !errors.Is(err, ErrDeviceTransportBindingSPKIMismatch) {
		t.Fatalf("wrong SPKI, mismatched context = %v, want ErrDeviceTransportBindingSPKIMismatch", err)
	}

	// A target binding names the server leaf, not the client leaf the server
	// verified, so the same channel rejects it on its unchanged SPKI too.
	if err := f.server.VerifyPeerDeviceTransportBinding(f.targetBinding, f.ctx, f.ctx.TargetDeviceID, f.targetKey); !errors.Is(err, ErrDeviceTransportBindingSPKIMismatch) {
		t.Fatalf("target binding on server channel = %v, want ErrDeviceTransportBindingSPKIMismatch", err)
	}
}

// TestVerifyPeerDeviceTransportBindingWrongKey asserts a wrong caller-pinned
// signing key is rejected by the public verifier with
// remoteunlock.ErrInvalidBinding once the SPKI matches.
func TestVerifyPeerDeviceTransportBindingWrongKey(t *testing.T) {
	f := newBindingTestFixture(t)
	_, otherPriv := syntheticSigningKey(t, "unrelated")
	otherPub := otherPriv.Public().(ed25519.PublicKey)

	if err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, f.ctx, f.ctx.SourceDeviceID, otherPub); !errors.Is(err, remoteunlock.ErrInvalidBinding) {
		t.Fatalf("wrong pinned key = %v, want remoteunlock.ErrInvalidBinding", err)
	}
	if err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, f.ctx, f.ctx.SourceDeviceID, f.targetKey); !errors.Is(err, remoteunlock.ErrInvalidBinding) {
		t.Fatalf("other endpoint's key = %v, want remoteunlock.ErrInvalidBinding", err)
	}
	if err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, f.ctx, f.ctx.SourceDeviceID, ed25519.PublicKey(f.sourceKey[:16])); !errors.Is(err, remoteunlock.ErrInvalidBinding) {
		t.Fatalf("short pinned key = %v, want remoteunlock.ErrInvalidBinding", err)
	}
}

// TestVerifyPeerDeviceTransportBindingContextMismatch asserts device ID and
// context overlap failures are reported with remoteunlock.ErrInvalidBinding and
// are delegated to the public verifier unchanged.
func TestVerifyPeerDeviceTransportBindingContextMismatch(t *testing.T) {
	f := newBindingTestFixture(t)

	mutations := []struct {
		name     string
		ctx      remoteunlock.ChannelBindingContext
		expected string
	}{
		{"wrong_expected_device_id", f.ctx, f.ctx.TargetDeviceID},
		{"empty_expected_device_id", f.ctx, ""},
		{"non_endpoint_device_id", f.ctx, "device-other-test"},
		{"member_mismatch", withMember(f.ctx, f.ctx.MemberID+"-other"), f.ctx.SourceDeviceID},
		{"vault_mismatch", withVault(f.ctx, f.ctx.VaultID+"-other"), f.ctx.SourceDeviceID},
		{"generation_mismatch", withPairGeneration(f.ctx, f.ctx.PairGeneration+1), f.ctx.SourceDeviceID},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, tc.ctx, tc.expected, f.sourceKey)
			if !errors.Is(err, remoteunlock.ErrInvalidBinding) {
				t.Fatalf("= %v, want remoteunlock.ErrInvalidBinding", err)
			}
			// The channel method must not alter or wrap away the public error.
			want := remoteunlock.VerifyDeviceTransportBindingForContext(f.sourceBinding, tc.ctx, tc.expected, f.sourceKey)
			if want == nil || err.Error() != want.Error() {
				t.Fatalf("channel error %q differs from public verifier error %q", err, want)
			}
		})
	}

	// Equal endpoints are rejected by the public verifier too.
	reused := f.ctx
	reused.TargetDeviceID = reused.SourceDeviceID
	if err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, reused, f.ctx.SourceDeviceID, f.sourceKey); !errors.Is(err, remoteunlock.ErrInvalidBinding) {
		t.Fatalf("equal endpoints = %v, want remoteunlock.ErrInvalidBinding", err)
	}

	// An invalid typed context is likewise refused with ErrInvalidBinding.
	invalid := f.ctx
	invalid.RequestID = ""
	if err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, invalid, f.ctx.SourceDeviceID, f.sourceKey); !errors.Is(err, remoteunlock.ErrInvalidBinding) {
		t.Fatalf("invalid context = %v, want remoteunlock.ErrInvalidBinding", err)
	}
}

func withMember(c remoteunlock.ChannelBindingContext, member string) remoteunlock.ChannelBindingContext {
	c.MemberID = member
	return c
}

func withVault(c remoteunlock.ChannelBindingContext, vault string) remoteunlock.ChannelBindingContext {
	c.VaultID = vault
	return c
}

func withPairGeneration(c remoteunlock.ChannelBindingContext, gen uint64) remoteunlock.ChannelBindingContext {
	c.PairGeneration = gen
	return c
}

// TestVerifyPeerDeviceTransportBindingClosed asserts that a closed channel
// returns ErrChannelClosed before a malformed signature or context could win.
func TestVerifyPeerDeviceTransportBindingClosed(t *testing.T) {
	f := newBindingTestFixture(t)

	badSignature := f.targetBinding
	badSignature.Signature = [remoteunlock.BindingSignatureSize]byte{}
	badContext := f.ctx
	badContext.RequestID = ""

	if err := f.client.Close(); err != nil {
		t.Fatalf("client Close: %v", err)
	}

	for _, tc := range []struct {
		name    string
		ch      *Channel
		binding remoteunlock.DeviceTransportBinding
		ctx     remoteunlock.ChannelBindingContext
		want    error
	}{
		{"valid", f.client, f.targetBinding, f.ctx, ErrChannelClosed},
		{"bad_signature", f.client, badSignature, f.ctx, ErrChannelClosed},
		{"bad_context", f.client, f.targetBinding, badContext, ErrChannelClosed},
		{"wrong_spki", f.client, f.sourceBinding, f.ctx, ErrChannelClosed},
		{"nil", nil, f.targetBinding, f.ctx, ErrUninitializedChannel},
		{"zero", &Channel{}, f.targetBinding, f.ctx, ErrUninitializedChannel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.ch.VerifyPeerDeviceTransportBinding(tc.binding, tc.ctx, f.ctx.TargetDeviceID, f.targetKey); !errors.Is(err, tc.want) {
				t.Fatalf("= %v, want %v", err, tc.want)
			}
		})
	}

	// The open server channel is unaffected.
	if err := f.server.VerifyPeerDeviceTransportBinding(f.sourceBinding, f.ctx, f.ctx.SourceDeviceID, f.sourceKey); err != nil {
		t.Fatalf("server VerifyPeerDeviceTransportBinding after client Close: %v", err)
	}
}
