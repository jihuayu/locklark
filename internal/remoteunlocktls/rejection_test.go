package remoteunlocktls

// This file is the narrow negative checkpoint for the remote unlock
// admin-delegation path. It reuses the synthetic fixture, the test-only framing
// helpers, the real 127.0.0.1:0 mTLS loopback harness (runHandshakes), the
// canonical public codecs and the public verification APIs of
// composition_test.go. Every certificate, Ed25519 key, age X25519 identity,
// policy, vault-file byte, recipient, request identifier and timestamp is
// synthetic test data generated or declared here; none belongs to a person,
// device, enrollment, owner root, vault or pairing.
//
// TEST-ONLY FRAMING. The 4-byte big-endian length-prefixed frames and the
// request/approval section layout are the private, bounded helpers of
// composition_test.go. This file defines no product frame. It reuses those
// helpers and only adds two 1-byte control sections appended to the end of the
// same request packet (send_vuk and pause_before_response), so the packet stays
// one bounded frame. The verification pause is signalled to the test goroutine
// only through buffered Go channels, never through the TLS channel or any
// protocol frame. All of this is private to these tests and bounded. It
// defines no product wire protocol and is not the remote-unlock v1 wire format.
//
// This file covers exactly two rejections:
//
//  1. One request already accepted on channel 1 (context, bindings and
//     delegated-admin authorization) is replayed on a second fresh TLS 1.3
//     channel with channel-1's exporter. The server's channel-2
//     VerifyBindingContext rejects the stale exporter with ErrBindingMismatch
//     before any further check, approval, VUK sealing or VUK frame.
//  2. A fresh request whose local lifecycle is cancelled while the server is
//     verified and paused before any response frame. The server then still
//     sends one test-only approval and one genuine age-wrapped VUK. The local
//     lifecycle stays cancelled and never consumes the late response: the
//     client reads the late ciphertext but never opens it, so it derives no
//     client-side plaintext VUK from that response. The server itself holds
//     the synthetic plaintext VUK to seal the response and clears its source
//     buffer.
//
// It is not a failure matrix: it does not exercise a wrong SPKI, key, device,
// member, expiry, policy, signature or restart, and it makes no claim that
// #127, #129 or #130 is complete. Cancellation here is process-local and
// in-memory only: it does not revoke authorization, notify the server, stop the
// server's delivery, survive a restart or provide durable anti-replay
// protection.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/remoteunlock"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

// testNoBytesWindow bounds the read that proves a rejected request produced
// no reply bytes.
const testNoBytesWindow = 250 * time.Millisecond

// Rejection request frames carry the canonical positive packet plus two
// 1-byte test-only control sections (send_vuk, pause_before_response), so the
// maximum grows by two bounded sections only.
const rejectionRequestFrameMax = compositionRequestFrameMax + 2*(compositionFrameHeaderSize+1)

// ---------------------------------------------------------------------------
// TEST-ONLY request packet extension.
//
// The positive request packet is unchanged. rejectionRequest appends exactly
// two more 1-byte-bounded sections, each using the shared helper:
//   - send_vuk: 1 => the server, after a successful verification, seals and
//     writes one genuine age VUK frame; 0 => no VUK frame.
//   - pause_before_response: the server verifies the exporter, source peer
//     binding and authorization, signals that verified-and-paused point over a
//     buffered Go channel without sending any response frame, and waits for
//     the test to release it. Only after release does it write the approval
//     (whose VUK flag is 1) and, when send_vuk is 1, exactly one VUK frame.
type rejectionRequest struct {
	compositionRequest
	sendVUK          bool
	pauseBeforeFrame bool
}

// encodeCompositionRejectionRequest appends the two control sections to an
// already encoded positive request packet and checks the total bound.
func encodeCompositionRejectionRequest(packet []byte, sendVUK, pauseBeforeFrame bool) ([]byte, error) {
	flags := []struct {
		name  string
		value bool
	}{
		{"send_vuk", sendVUK},
		{"pause_before_response", pauseBeforeFrame},
	}
	out := append([]byte(nil), packet...)
	for _, flag := range flags {
		var header [compositionFrameHeaderSize]byte
		binary.BigEndian.PutUint32(header[:], 1)
		out = append(out, header[:]...)
		v := byte(0)
		if flag.value {
			v = 1
		}
		out = append(out, v)
	}
	if len(out) > rejectionRequestFrameMax {
		return nil, fmt.Errorf("remoteunlocktls test-only rejection request: packet length %d over %d", len(out), rejectionRequestFrameMax)
	}
	return out, nil
}

// parseCompositionRejectionRequest walks the shared section layout once from
// the front, with the same bounds the encoder applied, parses the canonical
// sections exactly as parseCompositionRequest does and reads the two 1-byte
// control sections behind them.
func parseCompositionRejectionRequest(buf []byte) (rejectionRequest, error) {
	var out rejectionRequest
	offset := 0
	parse := func(max int) ([]byte, error) {
		return nextCompositionSection(buf, &offset, max)
	}
	contextBytes, err := parse(remoteunlock.MaxContextSize)
	if err != nil {
		return out, err
	}
	sourceBytes, err := parse(remoteunlock.MaxBindingSize)
	if err != nil {
		return out, err
	}
	targetBytes, err := parse(remoteunlock.MaxBindingSize)
	if err != nil {
		return out, err
	}
	authorizationBytes, err := parse(remoteunlock.MaxAdminAuthorizationSize)
	if err != nil {
		return out, err
	}
	exporter, err := parse(ChannelBindingSize)
	if err != nil {
		return out, err
	}
	if len(exporter) != ChannelBindingSize {
		return out, fmt.Errorf("remoteunlocktls test-only rejection request: exporter binding length %d, want %d", len(exporter), ChannelBindingSize)
	}
	var control [2]bool
	for i := range control {
		value, err := parse(1)
		if err != nil {
			return out, err
		}
		switch value[0] {
		case 0:
			control[i] = false
		case 1:
			control[i] = true
		default:
			return out, errors.New("remoteunlocktls test-only rejection request: invalid control flag")
		}
	}
	if offset != len(buf) {
		return out, errors.New("remoteunlocktls test-only rejection request: trailing bytes")
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
	out.sendVUK = control[0]
	out.pauseBeforeFrame = control[1]
	return out, nil
}

func encodeCompositionRequestFor(fx *compositionFixture, c remoteunlock.ChannelBindingContext, authorization []byte, exporter []byte) ([]byte, error) {
	contextBytes, err := remoteunlock.EncodeChannelBindingContext(c)
	if err != nil {
		return nil, err
	}
	sourceBytes, err := remoteunlock.EncodeDeviceTransportBinding(fx.sourceBinding)
	if err != nil {
		return nil, err
	}
	targetBytes, err := remoteunlock.EncodeDeviceTransportBinding(fx.targetBinding)
	if err != nil {
		return nil, err
	}
	return encodeCompositionRequest(compositionRequestSections{
		context:       contextBytes,
		source:        sourceBytes,
		target:        targetBytes,
		authorization: authorization,
		exporter:      exporter,
	})
}

// rejectionExchangeResult is one test server's outcome.
type rejectionExchangeResult struct {
	vukSealed int
	vukFrames int
	// verified records that the server passed the exporter, source peer
	// binding and authorization checks.
	verified bool
	// paused records that the server reached its verified-and-paused point and
	// sent no response frame before the test released it.
	paused bool
	// exporterRejected records that the channel exporter check itself failed.
	exporterRejected bool
	// verifyErr is the first failed TLS-identity, peer-binding or
	// authorization check. A rejected step produces no approval and no VUK.
	verifyErr error
	// err is a harness failure: malformed packets or a broken channel.
	err error
}

// rejectionHooks are the test-only Go synchronization points of one server run.
// Neither is a protocol frame. verified is optional: when non-nil the server
// sends one signal after it has verified the request and is about to pause, and
// release must then be non-nil.
type rejectionHooks struct {
	verified chan<- struct{}
	release  <-chan struct{}
}

// runRejectionServer is the test-only server side for the two cases below. It
// reuses the positive server's verification order and composition: the channel
// exporter first, then the source peer binding against the channel's verified
// peer SPKI, then the composed grant/authorization, then (for a successfully
// verified request only) the VUK delivery with the current-policy source
// recipient.
//
// Response-frame order. After any verification failure: no frame at all.
// With pause_before_response=0: the approval (whose VUK flag is send_vuk).
// With pause_before_response=1: no frame until the test releases the server;
// then the approval (whose VUK flag is 1) and, when send_vuk is 1, exactly one
// VUK frame.
func runRejectionServer(ch *Channel, fx *compositionFixture, hooks rejectionHooks) rejectionExchangeResult {
	var a rejectionExchangeResult
	fail := func(format string, err error) rejectionExchangeResult {
		a.err = fmt.Errorf(format+": %w", err)
		return a
	}
	writeFrame := func(payload []byte, max int, what string) bool {
		if err := writeTestOnlyFrame(ch, payload, max); err != nil {
			a.err = fmt.Errorf("write test-only %s: %w", what, err)
			return false
		}
		return true
	}

	payload, err := readTestOnlyFrame(ch, rejectionRequestFrameMax)
	if err != nil {
		return fail("read test-only request frame", err)
	}
	request, err := parseCompositionRejectionRequest(payload)
	if err != nil {
		return fail("parse test-only request", err)
	}

	// The first TLS-identity failure of this request is the case under test:
	// it is recorded, and nothing is approved, sealed or written.
	if err := ch.VerifyBindingContext(request.context, request.exporter); err != nil {
		a.exporterRejected = true
		a.verifyErr = err
		return a
	}
	if err := ch.VerifyPeerDeviceTransportBinding(request.source, request.context,
		request.context.SourceDeviceID, fx.sourceKey); err != nil {
		a.verifyErr = err
		return a
	}
	if err := remoteunlock.VerifyAdminRemoteUnlockAuthorization(fx.file, fx.checkpoint,
		fx.grant, request.authorization, request.context, request.source,
		request.target, compositionNowUnixMS); err != nil {
		a.verifyErr = err
		return a
	}
	a.verified = true

	if !request.pauseBeforeFrame {
		if !writeFrame(encodeCompositionApproval(request.sendVUK), compositionApprovalFrameMax, "approval") {
			return a
		}
		if request.sendVUK {
			if err := a.sealAndWriteVUK(ch, fx); err != nil {
				return fail("deliver VUK", err)
			}
		}
		return a
	}

	// Verified and paused: no response frame has been written. The signal is a
	// buffered Go channel, not a frame.
	if hooks.release == nil {
		return fail("pause requested without a release channel", errors.New("invalid hooks"))
	}
	if hooks.verified != nil {
		select {
		case hooks.verified <- struct{}{}:
		case <-time.After(testHandshakeLimit):
			return fail("signal verified-and-paused point", errors.New("timed out"))
		}
	}
	a.paused = true
	select {
	case <-hooks.release:
	case <-time.After(testHandshakeLimit):
		return fail("wait for release", errors.New("timed out waiting for the synchronization point release"))
	}

	// Released: send the late approval, then the genuine age VUK if requested.
	if !writeFrame(encodeCompositionApproval(true), compositionApprovalFrameMax, "approval") {
		return a
	}
	if request.sendVUK {
		if err := a.sealAndWriteVUK(ch, fx); err != nil {
			return fail("deliver late VUK", err)
		}
	}
	return a
}

// sealAndWriteVUK seals one genuine age envelope for the current-policy source
// device, records it as sealed, and writes it as one bounded frame. It must
// hold the synthetic plaintext VUK to seal the response; it clears that
// caller-owned source buffer before returning.
func (a *rejectionExchangeResult) sealAndWriteVUK(ch *Channel, fx *compositionFixture) error {
	vuk := syntheticCompositionVUK()
	defer clear(vuk)
	recipient, err := compositionPolicyAgeRecipient(fx.file, compositionSourceDeviceID)
	if err != nil {
		return fmt.Errorf("resolve source recipient: %w", err)
	}
	slot, err := vaultfile.SealVUKForDevice(vuk, fx.file.Header.VaultID,
		fx.file.Header.KeyEpoch, compositionSourceDeviceID, recipient)
	if err != nil {
		return fmt.Errorf("seal VUK for the source device: %w", err)
	}
	a.vukSealed++
	if err := writeTestOnlyFrame(ch, slot.WrappedVUK, vaultfile.MaxWrappedKeyLength); err != nil {
		return fmt.Errorf("write test-only VUK frame: %w", err)
	}
	a.vukFrames++
	return nil
}

// startRejectionServer runs runRejectionServer in its own goroutine. Harness
// failures are returned to the test goroutine instead of failing inside it.
func startRejectionServer(ch *Channel, fx *compositionFixture, hooks rejectionHooks) <-chan rejectionExchangeResult {
	done := make(chan rejectionExchangeResult, 1)
	go func() {
		done <- runRejectionServer(ch, fx, hooks)
	}()
	return done
}

// awaitRejectionServer waits for the server outcome without asserting it, so
// the assertion order (and the bytes the client reads) is under test control.
func awaitRejectionServer(t *testing.T, done <-chan rejectionExchangeResult, which string) rejectionExchangeResult {
	t.Helper()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("%s test-only server: %v", which, res.err)
		}
		return res
	case <-time.After(testHandshakeLimit):
		t.Fatalf("timed out waiting for the %s test-only server", which)
		return rejectionExchangeResult{}
	}
}

// newSyntheticChannel opens one fresh real loopback TLS 1.3 mTLS handshake with
// the same synthetic CA and certificates, bounds its I/O, and asserts TLS 1.3
// without resumption on both ends. It returns the two Channels and the actual
// verified peer SPKIs each side observed.
func newSyntheticChannel(t *testing.T, ca *testCA, serverCert tls.Certificate, clientCert tls.Certificate) (client, server *Channel, serverSees, clientSees PeerSPKIPin) {
	t.Helper()
	clientGot, serverGot := runHandshakes(t,
		ClientOptions{
			ServerName:  testServerName,
			Roots:       ca.pool,
			Certificate: clientCert,
			ServerPin:   PeerSPKIPinOf(serverCert.Leaf),
		},
		ServerOptions{
			Roots:       ca.pool,
			Certificate: serverCert,
			ClientPin:   PeerSPKIPinOf(clientCert.Leaf),
		},
	)
	client = mustChannel(t, "ClientHandshake", clientGot)
	server = mustChannel(t, "ServerHandshake", serverGot)
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
	deadline := time.Now().Add(testHandshakeLimit)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("client SetDeadline: %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatalf("server SetDeadline: %v", err)
	}
	return client, server, peerLeafPin(t, "server", server), peerLeafPin(t, "client", client)
}

// newRejectionFixture runs one short-lived runHandshakes pair only to obtain
// the SPKIs this test's channels will verify, builds the synthetic fixture with
// those pins, and then drops the probe's verified peer certificates. The CA
// and leaf certificates are unchanged, so the probe pins equal the pins of
// every channel opened later with the same leaf certificates.
func newRejectionFixture(t *testing.T, ca *testCA, serverCert, clientCert tls.Certificate) *compositionFixture {
	t.Helper()
	probeClient, probeServer, _, _ := newSyntheticChannel(t, ca, serverCert, clientCert)
	// The server Channel verified the client leaf (the source PC); the client
	// Channel verified the server leaf (the target device).
	fx := newCompositionFixture(t, peerLeafPin(t, "server", probeServer), peerLeafPin(t, "client", probeClient))
	for _, ch := range []*Channel{probeClient, probeServer} {
		state := ch.conn.ConnectionState()
		state.PeerCertificates = nil
	}
	if err := vaultfile.VerifyPolicyCheckpoint(fx.file, fx.checkpoint); err != nil {
		t.Fatalf("pinned current PolicyCheckpoint does not authenticate the synthetic file: %v", err)
	}
	return fx
}

// assertFixtureScope re-checks that the fixture's bindings carry the exact
// synthetic leaves (the source PC presents the client leaf the server verifies;
// the target device presents the server leaf the client verifies), that the
// requester keeps only its reader role, and that the distinct signing roles did
// not collapse onto one key. serverCert and clientCert are the certificate
// pairs issued for this test.
func assertFixtureScope(t *testing.T, fx *compositionFixture, serverCert, clientCert tls.Certificate) {
	t.Helper()
	if PeerSPKIPinOf(clientCert.Leaf) != PeerSPKIPin(fx.sourceBinding.SPKISHA256) {
		t.Fatal("the source binding does not carry the synthetic client leaf SPKI")
	}
	if PeerSPKIPinOf(serverCert.Leaf) != PeerSPKIPin(fx.targetBinding.SPKISHA256) {
		t.Fatal("the target binding does not carry the synthetic server leaf SPKI")
	}
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
	if bytes.Equal(fx.sourceKey, fx.delegatePolicyKey) ||
		bytes.Equal(fx.delegateContentKey, fx.delegatePolicyKey) ||
		bytes.Equal(fx.ownerRootPublicKey, fx.delegatePolicyKey) {
		t.Fatal("delegate policy signing key is shared with another synthetic role")
	}
}

// ---------------------------------------------------------------------------
// Case 1: the same request replayed on another TLS exporter/channel.
// ---------------------------------------------------------------------------

func TestLoopbackStaleExporterOnSecondChannelRejected(t *testing.T) {
	ca := newTestCA(t)
	serverCert, _ := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, _ := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	fx := newRejectionFixture(t, ca, serverCert, clientCert)
	t.Cleanup(func() {
		if fx.sourcePriv != nil {
			clear(fx.sourcePriv)
		}
		if fx.targetPriv != nil {
			clear(fx.targetPriv)
		}
		if fx.delegatePolicyPriv != nil {
			clear(fx.delegatePolicyPriv)
		}
	})
	assertFixtureScope(t, fx, serverCert, clientCert)

	// Channel 1: one valid context, one delegated-admin authorization. Both
	// ends verified the same pinned synthetic leaf SPKIs and the bindings.
	client1, server1, _, _ := newSyntheticChannel(t, ca, serverCert, clientCert)
	if client1.RemoteAddr() == nil || client1.RemoteAddr().String() == client1.LocalAddr().String() {
		t.Fatal("channel 1 is not a distinct loopback peer")
	}

	ctx := compositionContext(fx, compositionFirstRequestID,
		compositionRequestDigest("replay-0001"), compositionFirstLockGeneration)
	_, authBytes := signCompositionAuthorization(t, fx, ctx)
	if err := client1.VerifyPeerDeviceTransportBinding(fx.targetBinding, ctx,
		ctx.TargetDeviceID, fx.targetKey); err != nil {
		t.Fatalf("channel 1 target peer binding: %v", err)
	}
	exporter1, err := client1.ExportBindingContext(ctx)
	if err != nil {
		t.Fatalf("channel 1 ExportBindingContext: %v", err)
	}
	if len(exporter1) != ChannelBindingSize {
		t.Fatalf("channel 1 exporter length = %d, want %d", len(exporter1), ChannelBindingSize)
	}

	replayPacket, err := encodeCompositionRequestFor(fx, ctx, authBytes, exporter1)
	if err != nil {
		t.Fatalf("encode test-only replay packet: %v", err)
	}
	// Channel 1 delivers the request synchronously (no pause, no VUK) so this
	// request is already verified and approved on its own channel.
	server1Done := startRejectionServer(server1, fx, rejectionHooks{})
	channel1Packet, err := encodeCompositionRejectionRequest(replayPacket, false, false)
	if err != nil {
		t.Fatalf("extend channel-1 packet: %v", err)
	}
	if err := writeTestOnlyFrame(client1, channel1Packet, rejectionRequestFrameMax); err != nil {
		t.Fatalf("channel 1 write valid request: %v", err)
	}
	server1Result := awaitRejectionServer(t, server1Done, "channel 1")
	if server1Result.verifyErr != nil {
		t.Fatalf("channel 1 rejected the valid request: %v", server1Result.verifyErr)
	}
	if !server1Result.verified || server1Result.paused {
		t.Fatalf("channel 1 verified=%v paused=%v, want verified without a pause", server1Result.verified, server1Result.paused)
	}
	if server1Result.vukSealed != 0 || server1Result.vukFrames != 0 {
		t.Fatalf("channel 1 sealed %d / wrote %d VUKs, want none (send_vuk=false)",
			server1Result.vukSealed, server1Result.vukFrames)
	}
	approvalPayload, err := readTestOnlyFrame(client1, compositionApprovalFrameMax)
	if err != nil {
		t.Fatalf("channel 1 read approval: %v", err)
	}
	if vukFollows, err := parseCompositionApproval(approvalPayload); err != nil {
		t.Fatalf("channel 1 parse approval: %v", err)
	} else if vukFollows {
		// The channel-1 request carries send_vuk=0, so a promised VUK would be
		// a harness bug rather than a product behavior.
		t.Fatal("channel 1 approval reports a VUK despite send_vuk=0")
	}
	if err := client1.Close(); err != nil {
		t.Fatalf("channel 1 Close: %v", err)
	}

	// Channel 2: a fresh handshake with the same synthetic CA and certificates.
	client2, server2, _, _ := newSyntheticChannel(t, ca, serverCert, clientCert)

	// Everything except the exporter still holds on channel 2.
	if err := client2.VerifyPeerDeviceTransportBinding(fx.targetBinding, ctx,
		ctx.TargetDeviceID, fx.targetKey); err != nil {
		t.Fatalf("channel 2 target peer binding: %v", err)
	}
	if err := server2.VerifyPeerDeviceTransportBinding(fx.sourceBinding, ctx,
		ctx.SourceDeviceID, fx.sourceKey); err != nil {
		t.Fatalf("channel 2 source peer binding: %v", err)
	}
	// The same delegated-admin authorization re-parses and verifies against the
	// pinned file/checkpoint and the unchanged bindings.
	authorization := mustParseAuthorization(t, authBytes)
	if err := remoteunlock.VerifyAdminRemoteUnlockAuthorization(fx.file, fx.checkpoint,
		fx.grant, authorization, ctx, fx.sourceBinding,
		fx.targetBinding, compositionNowUnixMS); err != nil {
		t.Fatalf("channel 2 independent composed authorization: %v", err)
	}
	// The authorization binds the complete-binding digests; include both so
	// the per-request grant is re-proved on channel 2 as well.
	sourceDigest, err := remoteunlock.DeviceTransportBindingDigest(fx.sourceBinding)
	if err != nil {
		t.Fatalf("channel 2 source binding digest: %v", err)
	}
	targetDigest, err := remoteunlock.DeviceTransportBindingDigest(fx.targetBinding)
	if err != nil {
		t.Fatalf("channel 2 target binding digest: %v", err)
	}
	if sourceDigest != authorization.SourceBindingSHA256 || targetDigest != authorization.TargetBindingSHA256 {
		t.Fatal("the channel-2 bindings do not match the authorization's complete-binding digests")
	}
	// Both handshakes pinned the same two leaf certificates, so the verified
	// peer SPKIs on channel 2 are unchanged from channel 1.
	assertFixtureScope(t, fx, serverCert, clientCert)

	exporter2, err := client2.ExportBindingContext(ctx)
	if err != nil {
		t.Fatalf("channel 2 ExportBindingContext: %v", err)
	}
	if len(exporter2) != ChannelBindingSize {
		t.Fatalf("channel 2 exporter length = %d, want %d", len(exporter2), ChannelBindingSize)
	}
	if bytes.Equal(exporter1, exporter2) {
		t.Fatal("two fresh TLS 1.3 channels derived the same exporter")
	}
	// Channel 2's own exporter verifies on channel 2, so the rejection below
	// is caused by the stale exporter alone.
	if err := server2.VerifyBindingContext(ctx, exporter2); err != nil {
		t.Fatalf("channel 2 own exporter on channel 2: %v", err)
	}
	if err := client2.VerifyBindingContext(ctx, exporter2); err != nil {
		t.Fatalf("channel 2 own exporter on channel 2 (client): %v", err)
	}

	server2Done := startRejectionServer(server2, fx, rejectionHooks{})
	// Replay the exact channel-1 packet bytes, plus the two test-only control
	// sections (send_vuk=0, no pause).
	replayed, err := encodeCompositionRejectionRequest(replayPacket, false, false)
	if err != nil {
		t.Fatalf("extend replayed packet: %v", err)
	}
	if err := writeTestOnlyFrame(client2, replayed, rejectionRequestFrameMax); err != nil {
		t.Fatalf("channel 2 write replayed packet: %v", err)
	}
	server2Result := awaitRejectionServer(t, server2Done, "channel 2")
	if !server2Result.exporterRejected || !errors.Is(server2Result.verifyErr, ErrBindingMismatch) {
		t.Fatalf("channel 2 VerifyBindingContext = %v, want ErrBindingMismatch", server2Result.verifyErr)
	}
	if server2Result.vukSealed != 0 {
		t.Fatalf("channel 2 sealed %d VUKs before rejecting, want 0", server2Result.vukSealed)
	}
	if server2Result.vukFrames != 0 {
		t.Fatalf("channel 2 wrote %d VUK frames, want 0", server2Result.vukFrames)
	}
	if server2Result.verified || server2Result.paused {
		t.Fatal("channel 2 reached a later stage despite the stale exporter")
	}
	// Nothing was approved or delivered to channel 2's client: after the
	// exporter rejection the server writes no frame at all and then blocks on
	// its next (absent) request. A short bounded read must observe no bytes.
	if err := client2.SetReadDeadline(time.Now().Add(testNoBytesWindow)); err != nil {
		t.Fatalf("channel 2 SetReadDeadline: %v", err)
	}
	var one [1]byte
	n, readErr := client2.Read(one[:])
	if n != 0 || readErr != nil && !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("channel 2 read %d bytes (err %v) after the stale exporter was rejected, want a silent timeout", n, readErr)
	}
}

// ---------------------------------------------------------------------------
// Case 2: cancelled fresh request receives a late response but consumes none.
// ---------------------------------------------------------------------------

func TestLoopbackCancelledRequestDoesNotConsumeLateVUK(t *testing.T) {
	ca := newTestCA(t)
	serverCert, _ := ca.issue(t, 2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testServerName})
	clientCert, _ := ca.issue(t, 3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	fx := newRejectionFixture(t, ca, serverCert, clientCert)
	t.Cleanup(func() {
		if fx.sourcePriv != nil {
			clear(fx.sourcePriv)
		}
		if fx.targetPriv != nil {
			clear(fx.targetPriv)
		}
		if fx.delegatePolicyPriv != nil {
			clear(fx.delegatePolicyPriv)
		}
	})
	assertFixtureScope(t, fx, serverCert, clientCert)

	client, server, _, _ := newSyntheticChannel(t, ca, serverCert, clientCert)

	// A distinct fresh request: new request ID, digest and lock generation.
	ctx := compositionContext(fx, compositionSecondRequestID,
		compositionRequestDigest("late-0002"), compositionSecondLockGeneration)
	if ctx.RequestID == compositionFirstRequestID ||
		ctx.RequestDigest == compositionRequestDigest("0002") ||
		ctx.LockGeneration == compositionFirstLockGeneration {
		t.Fatal("the late-request context is not distinct from the positive checkpoint's first request")
	}
	_, authBytes := signCompositionAuthorization(t, fx, ctx)

	if err := client.VerifyPeerDeviceTransportBinding(fx.targetBinding, ctx,
		ctx.TargetDeviceID, fx.targetKey); err != nil {
		t.Fatalf("target peer binding: %v", err)
	}
	exporter, err := client.ExportBindingContext(ctx)
	if err != nil {
		t.Fatalf("client ExportBindingContext: %v", err)
	}
	if err := server.VerifyBindingContext(ctx, exporter); err != nil {
		t.Fatalf("server VerifyBindingContext: %v", err)
	}
	packet, err := encodeCompositionRequestFor(fx, ctx, authBytes, exporter)
	if err != nil {
		t.Fatalf("encode test-only request: %v", err)
	}
	packet, err = encodeCompositionRejectionRequest(packet, true, true)
	if err != nil {
		t.Fatalf("extend test-only request: %v", err)
	}

	// The requester's process-local lifecycle exists before the request is
	// sent. This is an in-memory state machine: it is local to this process.
	lifecycle, err := remoteunlock.NewRequestLifecycle(ctx, compositionNowUnixMS)
	if err != nil {
		t.Fatalf("NewRequestLifecycle: %v", err)
	}
	assertLifecycleStatus(t, lifecycle, compositionNowUnixMS, remoteunlock.StatusRequested)

	verified := make(chan struct{}, 1)
	release := make(chan struct{})
	// Signal-before-write proof: while the server is verified-and-paused it has
	// written no response frame, so reading now must time out.
	if err := client.SetReadDeadline(time.Now().Add(testNoBytesWindow)); err != nil {
		t.Fatalf("client SetReadDeadline: %v", err)
	}
	serverDone := startRejectionServer(server, fx, rejectionHooks{verified: verified, release: release})
	if err := writeTestOnlyFrame(client, packet, rejectionRequestFrameMax); err != nil {
		t.Fatalf("write test-only request: %v", err)
	}

	// Wait for the bounded Go signal that the server verified the exporter,
	// source peer binding and authorization and is paused before any response.
	select {
	case <-verified:
	case <-time.After(testHandshakeLimit):
		t.Fatal("timed out waiting for the server's verified-and-paused signal")
	}
	var one [1]byte
	if n, readErr := client.Read(one[:]); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("server wrote %d bytes (err %v) before the verified pause was released", n, readErr)
	}

	// The requester cancels its local lifecycle, then releases the server.
	cancelAt := compositionNowUnixMS + 1_500
	lateAt := compositionNowUnixMS + 2_500
	if err := lifecycle.Cancel(cancelAt); err != nil {
		t.Fatalf("lifecycle Cancel: %v", err)
	}
	assertLifecycleStatus(t, lifecycle, cancelAt, remoteunlock.StatusCancelled)
	if err := client.SetDeadline(time.Now().Add(testHandshakeLimit)); err != nil {
		t.Fatalf("client SetDeadline: %v", err)
	}
	close(release)

	serverResult := awaitRejectionServer(t, serverDone, "late VUK")
	if serverResult.verifyErr != nil {
		t.Fatalf("server rejected the authorized request: %v", serverResult.verifyErr)
	}
	if !serverResult.verified || !serverResult.paused {
		t.Fatalf("server verified=%v paused=%v, want both", serverResult.verified, serverResult.paused)
	}
	if serverResult.vukSealed != 1 || serverResult.vukFrames != 1 {
		t.Fatalf("server sealed %d / wrote %d VUK frames, want 1 / 1", serverResult.vukSealed, serverResult.vukFrames)
	}

	// The client reads the late approval and VUK after cancellation. It never
	// opens the envelope.
	approvalPayload, err := readTestOnlyFrame(client, compositionApprovalFrameMax)
	if err != nil {
		t.Fatalf("read late approval: %v", err)
	}
	if vukFollows, err := parseCompositionApproval(approvalPayload); err != nil {
		t.Fatalf("parse late approval: %v", err)
	} else if !vukFollows {
		t.Fatal("late approval does not promise the VUK")
	}
	lateEnvelope, err := readTestOnlyFrame(client, vaultfile.MaxWrappedKeyLength)
	if err != nil {
		t.Fatalf("read late bounded VUK frame: %v", err)
	}
	defer func() {
		clear(lateEnvelope)
		assertCompositionCleared(t, "late VUK envelope", lateEnvelope)
	}()
	if len(lateEnvelope) == 0 || len(lateEnvelope) > vaultfile.MaxWrappedKeyLength {
		t.Fatalf("late envelope length = %d outside (0, %d]", len(lateEnvelope), vaultfile.MaxWrappedKeyLength)
	}

	// Confirm and Receive stay rejected; the status stays cancelled.
	if err := lifecycle.Confirm(lateAt); !errors.Is(err, remoteunlock.ErrLifecycleTransition) {
		t.Fatalf("late Confirm = %v, want ErrLifecycleTransition", err)
	}
	if err := lifecycle.Receive(lateAt + 1); !errors.Is(err, remoteunlock.ErrLifecycleTransition) {
		t.Fatalf("late Receive = %v, want ErrLifecycleTransition", err)
	}
	assertLifecycleStatus(t, lifecycle, lateAt+2, remoteunlock.StatusCancelled)
	if lifecycle.Context() != ctx {
		t.Fatal("lifecycle context changed after the late response")
	}

	// Client-side plaintext boundary: the late envelope is never passed to
	// vaultfile.OpenVUKForDevice, so the client never unpacks it and derives no
	// client-side plaintext VUK from this response. The only plaintext VUK in
	// this flow is the server's synthetic source value: the server must hold it
	// to seal the response with vaultfile.SealVUKForDevice and clears that
	// source buffer before it returns (see sealAndWriteVUK). This test does not
	// claim the server never held plaintext, and because it makes no bytewise
	// comparison against the VUK it does not claim the VUK is absent from the
	// envelope bytes. The envelope is cleared above. The bounded recipient
	// check below is a separate property: the device age recipient is not
	// carried in plaintext.
	if bytes.Contains(lateEnvelope, []byte(fx.sourceRecipient)) {
		t.Fatal("late envelope leaks the source recipient in plaintext")
	}
}

func mustParseAuthorization(t *testing.T, encoded []byte) remoteunlock.AdminRemoteUnlockAuthorization {
	t.Helper()
	a, err := remoteunlock.ParseAdminRemoteUnlockAuthorization(encoded)
	if err != nil {
		t.Fatalf("parse delegated-admin authorization: %v", err)
	}
	return a
}

func assertLifecycleStatus(t *testing.T, lifecycle *remoteunlock.RequestLifecycle, nowUnixMS int64, want string) {
	t.Helper()
	status, err := lifecycle.StatusAt(nowUnixMS)
	if err != nil {
		t.Fatalf("StatusAt(%d): %v", nowUnixMS, err)
	}
	if status != want {
		t.Fatalf("lifecycle status at %d = %q, want %q", nowUnixMS, status, want)
	}
}
