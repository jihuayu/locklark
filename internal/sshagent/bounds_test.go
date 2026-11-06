package sshagent

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	clientagent "golang.org/x/crypto/ssh/agent"
)

func TestFrameBudgetRefusesWithoutAllocatingOrCallingHandler(t *testing.T) {
	for _, size := range []uint32{0, MaxFrame + 1, 0xffffffff} {
		h := newTestHandler(t)
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() { serve(context.Background(), server, Peer{}, h, make(chan struct{}, MaxWriters)); close(done) }()
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if _, e := client.Write(header[:]); e != nil {
			t.Fatal("frame header fixture failed")
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("oversized frame kept a connection worker")
		}
		_ = client.Close()
		if h.calls.Load() != 0 {
			t.Fatal("invalid frame reached signing backend")
		}
	}
}
func TestPerConnectionRequestBudgetClosesAfterBound(t *testing.T) {
	h := newTestHandler(t)
	server, client := net.Pipe()
	defer client.Close()
	go serve(context.Background(), server, Peer{}, h, make(chan struct{}, MaxWriters))
	api := clientagent.NewClient(client)
	for i := 0; i < MaxRequests; i++ {
		if _, e := api.List(); e != nil {
			t.Fatal("within-budget enumeration failed")
		}
	}
	if _, e := api.List(); e == nil {
		t.Fatal("unbounded requests were accepted")
	}
}
func TestCancellationClosesSlowConsumerWithinDeadline(t *testing.T) {
	h := newTestHandler(t)
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { serve(ctx, server, Peer{}, h, make(chan struct{}, MaxWriters)); close(done) }()
	if e := writeFrame(client, []byte{11}); e != nil {
		t.Fatal("slow consumer fixture failed")
	}
	// The server is now trying to write a response to a client that never reads.
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel waited for a slow socket consumer")
	}
	_ = client.Close()
}
