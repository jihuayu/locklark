package sshagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
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
