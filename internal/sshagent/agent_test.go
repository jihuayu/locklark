package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	clientagent "golang.org/x/crypto/ssh/agent"
)

type testHandler struct {
	signer    ssh.Signer
	calls     atomic.Int32
	lists     atomic.Int32
	wait      bool
	entered   chan struct{}
	cancelled chan struct{}
}

func newTestHandler(t *testing.T) *testHandler {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture generation failed")
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal("fixture signer failed")
	}
	return &testHandler{signer: signer, entered: make(chan struct{}, 1), cancelled: make(chan struct{}, 1)}
}
func (h *testHandler) Identities(context.Context, Peer) ([]Identity, error) {
	h.lists.Add(1)
	return []Identity{{h.signer.PublicKey().Marshal(), "Locklark fixture"}}, nil
}
func (h *testHandler) Sign(ctx context.Context, r SignRequest) ([]byte, error) {
	h.calls.Add(1)
	select {
	case h.entered <- struct{}{}:
	default:
	}
	if h.wait {
		<-ctx.Done()
		h.cancelled <- struct{}{}
		return nil, ErrRefused
	}
	sig, e := h.signer.Sign(rand.Reader, r.Data)
	if e != nil {
		return nil, ErrRefused
	}
	return ssh.Marshal(sig), nil
}
func TestIdentitiesAndSignUseActualSSHWireClient(t *testing.T) {
	h := newTestHandler(t)
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer client.Close()
	go serve(ctx, server, Peer{"UID test", 1, "fixture"}, h, make(chan struct{}, MaxWriters))
	api := clientagent.NewClient(client)
	keys, e := api.List()
	if e != nil || len(keys) != 1 {
		t.Fatal("identities wire response failed")
	}
	data := []byte("public SSH protocol fixture")
	sig, e := api.Sign(h.signer.PublicKey(), data)
	if e != nil || h.signer.PublicKey().Verify(data, sig) != nil || h.calls.Load() != 1 {
		t.Fatal("sign-only wire response failed")
	}
	if e = api.RemoveAll(); e == nil {
		t.Fatal("mutation request accepted")
	}
}
func TestUnsupportedFlagsAndDataBudgetRefuseBeforeBackend(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint32
		data  []byte
	}{{"nonzero-flags", 2, []byte("fixture")}, {"oversized-data", 0, make([]byte, MaxSignData+1)}, {"empty-data", 0, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t)
			frame := append([]byte{13}, ssh.Marshal(struct {
				Key, Data []byte
				Flags     uint32
			}{h.signer.PublicKey().Marshal(), tc.data, tc.flags})...)
			response := dispatch(context.Background(), Peer{"UID test", 1, "fixture"}, "connection", frame, h)
			if len(response) != 1 || response[0] != 5 || h.calls.Load() != 0 {
				t.Fatal("unsupported sign reached backend or returned a signature")
			}
		})
	}
}
func TestDisconnectCancelsPendingApproval(t *testing.T) {
	h := newTestHandler(t)
	h.wait = true
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		serve(context.Background(), server, Peer{"UID test", 1, "fixture"}, h, make(chan struct{}, MaxWriters))
		close(done)
	}()
	go func() { _, _ = clientagent.NewClient(client).Sign(h.signer.PublicKey(), []byte("fixture")) }()
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("request did not reach approval")
	}
	_ = client.Close()
	select {
	case <-h.cancelled:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel approval")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection worker leaked")
	}
}
func TestUnknownMessagesCannotMutateOrExposeKeys(t *testing.T) {
	h := newTestHandler(t)
	for _, kind := range []byte{1, 2, 7, 8, 9, 17, 18, 19, 20, 22, 23, 27, 255} {
		r := dispatch(context.Background(), Peer{}, "connection", []byte{kind}, h)
		if len(r) != 1 || r[0] != 5 {
			t.Fatal("unsupported agent message accepted")
		}
	}
	if h.calls.Load() != 0 {
		t.Fatal("unsupported message touched signer")
	}
}

// sshAgentFailure is the SSH_AGENT_FAILURE message number, the one-byte
// failure body no client library exports.
const sshAgentFailure = byte(5)

// canonicalFailureFrame is the full SSH_AGENT_FAILURE frame: its four-byte
// big-endian length followed by the one-byte failure body. The forced ordering
// below can only ever deliver its header.
var canonicalFailureFrame = []byte{0, 0, 0, 1, sshAgentFailure}

// refusingHandler announces its one Sign entry and immediately refuses.
type refusingHandler struct {
	entered chan struct{}
	calls   atomic.Int32
}

func (h *refusingHandler) Identities(context.Context, Peer) ([]Identity, error) {
	return nil, ErrRefused
}

func (h *refusingHandler) Sign(context.Context, SignRequest) ([]byte, error) {
	h.calls.Add(1)
	h.entered <- struct{}{}
	return nil, ErrRefused
}

// headerFirstGate wraps only the server side of a net.Pipe. The first Write
// (the four-byte response header) delegates normally. The second Write (the
// response body) signals payloadStarted and waits for release before it
// delegates, and its result is recorded privately before bodyDrained closes.
// release fires the gate exactly once, whether from the cancellation path or
// from cleanup. Close closes the underlying connection first and signals
// underlyingClosed once, however often it is invoked.
type headerFirstGate struct {
	net.Conn
	writes           atomic.Int32
	payloadStarted   chan struct{}
	released         chan struct{}
	underlyingClosed chan struct{}
	payloadStartOnce sync.Once
	releaseOnce      sync.Once
	underlyingOnce   sync.Once
	bodyMu           sync.Mutex
	bodyN            int
	bodyErr          error
	bodyDrained      chan struct{}
}

func newHeaderFirstGate(c net.Conn) *headerFirstGate {
	return &headerFirstGate{
		Conn:             c,
		payloadStarted:   make(chan struct{}),
		released:         make(chan struct{}),
		underlyingClosed: make(chan struct{}),
		bodyDrained:      make(chan struct{}),
	}
}

func (g *headerFirstGate) Write(p []byte) (int, error) {
	if g.writes.Add(1) == 1 {
		return g.Conn.Write(p)
	}
	g.payloadStartOnce.Do(func() { close(g.payloadStarted) })
	<-g.released
	n, e := g.Conn.Write(p)
	g.bodyMu.Lock()
	g.bodyN, g.bodyErr = n, e
	close(g.bodyDrained)
	g.bodyMu.Unlock()
	return n, e
}

func (g *headerFirstGate) release() {
	g.releaseOnce.Do(func() { close(g.released) })
}

func (g *headerFirstGate) Close() error {
	e := g.Conn.Close()
	g.underlyingOnce.Do(func() { close(g.underlyingClosed) })
	return e
}

// TestForcedCancellationBetweenFailureHeaderAndPayload is an explicitly
// injected cancellation ordering test. It forces a reachable ordering, cancel
// after the response header and before the response body, and shows the peer
// receives only the strict canonical SSH_AGENT_FAILURE header prefix. It is
// neither a naturally observed ordering nor evidence of bytes produced by CI.
func TestForcedCancellationBetweenFailureHeaderAndPayload(t *testing.T) {
	const deadline = 5 * time.Second
	_, signingKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture generation failed")
	}
	pub, e := ssh.NewPublicKey(signingKey.Public())
	if e != nil {
		t.Fatal("fixture public key failed")
	}
	payload := append([]byte{13}, ssh.Marshal(struct {
		Key, Data []byte
		Flags     uint32
	}{pub.Marshal(), []byte("forced cancellation ordering fixture"), 0})...)
	// serve reads a four-byte big-endian outer frame length before the payload.
	request := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(request, uint32(len(payload)))
	request = append(request, payload...)

	h := &refusingHandler{entered: make(chan struct{}, 1)}
	plainServer, peer := net.Pipe()
	server := newHeaderFirstGate(plainServer)
	parentCtx, cancelParent := context.WithCancel(context.Background())
	cancelParent = sync.OnceFunc(cancelParent)
	served := make(chan struct{})
	requestDone := make(chan error, 1)
	// The peer write cannot finish while serve is busy with Sign on a plain
	// net.Pipe, so it is reported once Sign was entered and the header read.
	var requestErr error

	// Cleanup runs after the test body, including when an assertion failed:
	// it cancels, fires the release gate, closes both sockets, and reaps serve.
	t.Cleanup(func() {
		cancelParent()
		server.release()
		_ = server.Close()
		_ = peer.Close()
		select {
		case <-served:
		case <-time.After(deadline):
			t.Error("serve did not exit during cleanup")
		}
	})

	go func() {
		defer close(served)
		serve(parentCtx, server, Peer{"UID test", 1, "fixture"}, h, make(chan struct{}, MaxWriters))
	}()

	go func() {
		_ = peer.SetWriteDeadline(time.Now().Add(deadline))
		n, e := peer.Write(request)
		if e == nil && n != len(request) {
			e = io.ErrShortWrite
		}
		requestDone <- e
	}()
	select {
	case <-h.entered:
	case <-time.After(deadline):
		t.Fatal("request did not reach the refusing handler")
	}

	header := make([]byte, 4)
	_ = peer.SetReadDeadline(time.Now().Add(deadline))
	if n, e := peer.Read(header); e != nil || n != len(header) {
		t.Fatal("failure header was not received")
	}
	select {
	case requestErr = <-requestDone:
	case <-time.After(deadline):
		t.Fatal("sign request write did not finish")
	}
	select {
	case <-server.payloadStarted:
	case <-time.After(deadline):
		t.Fatal("response body write did not start")
	}

	// Cancel strictly between the header and the body, wait for serve's own
	// close of the server connection, and only then release the body write.
	cancelParent()
	select {
	case <-server.underlyingClosed:
	case <-time.After(deadline):
		t.Fatal("cancellation did not close the server connection")
	}
	server.release()
	select {
	case <-server.bodyDrained:
	case <-time.After(deadline):
		t.Fatal("response body write did not return")
	}
	server.bodyMu.Lock()
	bodyN, bodyErr := server.bodyN, server.bodyErr
	server.bodyMu.Unlock()
	if bodyN != 0 || bodyErr == nil {
		t.Fatal("response body write did not fail with zero bytes after close")
	}

	buffer := make([]byte, 1)
	_ = peer.SetReadDeadline(time.Now().Add(deadline))
	n, e := peer.Read(buffer)
	if n != 0 {
		t.Fatal("response body was observable after cancellation")
	}
	if e != io.EOF && !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("read after the header did not observe end of stream")
	}

	select {
	case <-served:
	case <-time.After(deadline):
		t.Fatal("serve did not exit")
	}
	if requestErr != nil {
		t.Fatal("sign request write did not succeed")
	}
	if h.calls.Load() != 1 {
		t.Fatal("refusing handler Sign call count is not one")
	}
	if len(header) >= len(canonicalFailureFrame) || !bytes.Equal(header, canonicalFailureFrame[:len(header)]) {
		t.Fatal("received bytes are not the strict canonical SSH_AGENT_FAILURE header prefix")
	}
}
