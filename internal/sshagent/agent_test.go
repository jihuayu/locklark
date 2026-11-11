package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
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

// SSH_AGENT_FAILURE is the one-byte failure body; no client library exports it.
const sshAgentFailure = 5

// failureHeader is the canonical length header of a one-byte SSH_AGENT_FAILURE
// payload. The strict canonical frame is failureHeader followed by
// sshAgentFailure.
var failureHeader = []byte{0, 0, 0, 1}

// refusingHandler announces that Sign was entered and immediately refuses.
type refusingHandler struct {
	key     ssh.PublicKey
	entered chan struct{}
	calls   atomic.Int32
}

func newRefusingHandler(t *testing.T) *refusingHandler {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture generation failed")
	}
	pub, e := ssh.NewPublicKey(key.Public())
	if e != nil {
		t.Fatal("fixture public key failed")
	}
	return &refusingHandler{key: pub, entered: make(chan struct{}, 1)}
}

func (h *refusingHandler) Identities(context.Context, Peer) ([]Identity, error) {
	return []Identity{{h.key.Marshal(), "Locklark fixture"}}, nil
}

func (h *refusingHandler) Sign(context.Context, SignRequest) ([]byte, error) {
	h.calls.Add(1)
	h.entered <- struct{}{}
	return nil, ErrRefused
}

// headerFirstGate wraps only the server side of a net.Pipe. The first Write (the
// four-byte response header) delegates normally. The second Write (the
// one-byte failure body) closes payloadStarted, waits for releasePayload, and
// then delegates. Close closes the underlying connection first and signals
// underlyingClosed exactly once, however often it is invoked.
//
// The wrapper never reads, so serve reads the request through net.Pipe
// directly. Every read completes before any write can fail the peer's step
// request write, so that write reports only success or its step deadline.
type headerFirstGate struct {
	net.Conn
	writes           atomic.Int32
	payloadStarted   chan struct{}
	releasePayload   chan struct{}
	underlyingClosed chan struct{}
	payloadStartOnce sync.Once
	underlyingOnce   sync.Once
}

func newHeaderFirstGate(c net.Conn) *headerFirstGate {
	return &headerFirstGate{
		Conn:             c,
		payloadStarted:   make(chan struct{}),
		releasePayload:   make(chan struct{}),
		underlyingClosed: make(chan struct{}),
	}
}

func (g *headerFirstGate) Write(p []byte) (int, error) {
	if g.writes.Add(1) == 1 {
		return g.Conn.Write(p)
	}
	g.payloadStartOnce.Do(func() { close(g.payloadStarted) })
	<-g.releasePayload
	return g.Conn.Write(p)
}

func (g *headerFirstGate) Close() error {
	e := g.Conn.Close()
	g.underlyingOnce.Do(func() { close(g.underlyingClosed) })
	return e
}

// TestForcedCancellationBetweenFailureHeaderAndPayload is an explicitly
// injected cancellation ordering test. It demonstrates a forced reachable
// ordering, cancel after the response header and before the payload, under
// which the peer observes only the strict canonical SSH_AGENT_FAILURE header
// prefix. It is neither a naturally observed ordering nor evidence of bytes
// produced by CI.
func TestForcedCancellationBetweenFailureHeaderAndPayload(t *testing.T) {
	const deadline = 5 * time.Second
	h := newRefusingHandler(t)
	plainServer, peer := net.Pipe()
	server := newHeaderFirstGate(plainServer)
	parentCtx, cancelParent := context.WithCancel(context.Background())
	cancelParent = sync.OnceFunc(cancelParent)
	served := make(chan struct{})
	requestDone := make(chan error, 1)

	// Cleanup runs before any deferred assertion reports, so a failed
	// assertion still releases the gates, closes both sockets, and reaps the
	// serve goroutine even when the request write was already lost.
	t.Cleanup(func() {
		cancelParent()
		close(server.releasePayload)
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

	request := append([]byte{13}, ssh.Marshal(struct {
		Key, Data []byte
		Flags     uint32
	}{h.key.Marshal(), []byte("forced cancellation ordering fixture"), 0})...)
	go func() {
		_ = peer.SetWriteDeadline(time.Now().Add(deadline))
		n, e := peer.Write(request)
		if e == nil && n != len(request) {
			e = io.ErrShortWrite
		}
		requestDone <- e
	}()
	entered := false
	for !entered {
		select {
		case e := <-requestDone:
			// The step request transfer is committed once serve consumes it,
			// and that read precedes every write, so a completed write reports
			// only nil or its step deadline: only those mean the write ended.
			if e != nil && !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal("sign request write failed")
			}
		case <-h.entered:
			entered = true
		case <-time.After(deadline):
			t.Fatal("request did not reach the refusing handler")
		}
	}
	select {
	case <-requestDone:
	case <-time.After(deadline):
		t.Fatal("sign request write did not finish")
	}

	header := make([]byte, len(failureHeader))
	_ = peer.SetReadDeadline(time.Now().Add(deadline))
	if n, e := peer.Read(header); e != nil || n != len(header) {
		t.Fatal("failure header was not received")
	}
	if !bytes.Equal(header, failureHeader) {
		t.Fatal("received header is not the one-byte payload length")
	}
	select {
	case <-server.payloadStarted:
	case <-time.After(deadline):
		t.Fatal("failure payload write did not start")
	}

	// Cancel strictly between the header and the payload; the header's
	// transfer is already committed, so only the body could still be lost.
	cancelParent()
	select {
	case <-server.underlyingClosed:
	case <-time.After(deadline):
		t.Fatal("cancellation did not close the server connection")
	}
	close(server.releasePayload)

	payload := make([]byte, 1)
	_ = peer.SetReadDeadline(time.Now().Add(deadline))
	n, e := peer.Read(payload)
	if n != 0 {
		t.Fatal("failure payload was observable after cancellation")
	}
	if completed := e == io.EOF || errors.Is(e, io.ErrClosedPipe); !completed {
		t.Fatal("failure payload read did not observe end of stream")
	}
	select {
	case <-served:
	case <-time.After(deadline):
		t.Fatal("serve did not exit after cancellation")
	}

	observed := append(append([]byte(nil), header...), payload...)
	if !bytes.Equal(observed, append(append([]byte(nil), failureHeader...), 0)) {
		t.Fatal("observed bytes are not only the strict canonical SSH_AGENT_FAILURE header prefix")
	}
	if h.calls.Load() != 1 {
		t.Fatal("refusing handler Sign call count is not one")
	}
}
