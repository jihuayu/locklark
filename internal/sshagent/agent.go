// Package sshagent implements a bounded, local identities/sign-only SSH agent.
// It stores no private keys, does not unlock a vault, and never logs wire data.
package sshagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

const (
	MaxFrame           = 64 << 10
	MaxSignData        = 60 << 10
	MaxConnections     = 8
	MaxWriters         = 4
	MaxIdentities      = 32
	MaxRequests        = 64
	ReadIdle           = 35 * time.Second
	WriteTimeout       = 2 * time.Second
	ApprovalTimeout    = 30 * time.Second
	ConnectionLifetime = 120 * time.Second
)

var ErrUnavailable = errors.New("local SSH agent unavailable")
var ErrRefused = errors.New("local SSH agent request refused")

// Fixed internal refusal categories contain no OS error text or peer values.
// They are retained as bounded scalar test evidence, never sent over the wire.
type peerRefusal string

const (
	peerFrame       peerRefusal = "FRAME"
	peerDescriptor  peerRefusal = "DESCRIPTOR"
	peerPID         peerRefusal = "PID"
	peerOwner       peerRefusal = "OWNER"
	peerImpersonate peerRefusal = "IMPERSONATE"
	peerToken       peerRefusal = "TOKEN"
	peerTokenUser   peerRefusal = "TOKEN_USER"
	peerSID         peerRefusal = "SID"
	peerRevert      peerRefusal = "REVERT"
)

func (peerRefusal) Error() string { return "local SSH agent peer authentication refused" }
func (peerRefusal) Unwrap() error { return ErrRefused }

func peerRefusalCategory(err error) string {
	var refusal peerRefusal
	if errors.As(err, &refusal) {
		switch refusal {
		case peerFrame, peerDescriptor, peerPID, peerOwner, peerImpersonate, peerToken, peerTokenUser, peerSID, peerRevert:
			return string(refusal)
		}
	}
	return "OTHER"
}

type Peer struct {
	User    string
	PID     uint32
	Process string
}

func (p Peer) Label() string {
	return fmt.Sprintf("%s · 连接建立时 PID %d · %s", SafeText(p.User, 256), p.PID, SafeText(p.Process, 512))
}
func SafeText(value string, limit int) string {
	var b strings.Builder
	for _, r := range value {
		piece := string(r)
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			piece = fmt.Sprintf("\\u{%X}", r)
		}
		if b.Len()+len(piece) > limit {
			break
		}
		b.WriteString(piece)
	}
	return b.String()
}

type Identity struct {
	Blob    []byte
	Comment string
}
type SignRequest struct {
	RequestID, ConnectionID string
	Peer                    Peer
	PublicKey, Data         []byte
	Until                   time.Time
}

func (SignRequest) String() string               { return "[local SSH request]" }
func (SignRequest) GoString() string             { return "[local SSH request]" }
func (SignRequest) MarshalJSON() ([]byte, error) { return nil, ErrRefused }

// Handler must obtain explicit native consent for every Sign. Sign is called
// with an already reserved bounded writer slot; its final delivery grant may
// return a public SSH signature blob, never a signer or a private key.
type Handler interface {
	Identities(context.Context, Peer) ([]Identity, error)
	Sign(context.Context, SignRequest) ([]byte, error)
}

type Service struct {
	listener    net.Listener
	endpoint    string
	handler     Handler
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	connections map[net.Conn]bool
	slots       chan struct{}
	writers     chan struct{}
	wg          sync.WaitGroup
	done        chan struct{}
	ioStopped   chan struct{}
	stop        sync.Once
	stopError   error
	accepted    uint64 // guarded by mu; fixed-size runtime-test evidence only
	peerRefusal string // fixed category, never the underlying error body
}

// Start never replaces an existing endpoint or changes SSH_AUTH_SOCK itself.
func Start(endpoint string, handler Handler) (*Service, error) {
	if handler == nil {
		return nil, ErrUnavailable
	}
	l, e := listenLocal(endpoint)
	if e != nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{listener: l, endpoint: l.Addr().String(), handler: handler, ctx: ctx, cancel: cancel, connections: map[net.Conn]bool{}, slots: make(chan struct{}, MaxConnections), writers: make(chan struct{}, MaxWriters), done: make(chan struct{}), ioStopped: make(chan struct{})}
	s.wg.Add(1)
	go s.accept()
	go func() { s.wg.Wait(); close(s.done) }()
	return s, nil
}
func (s *Service) Endpoint() string { return s.endpoint }

// RequestStop revokes pending authority immediately, then closes OS endpoints
// off-thread. Native lifecycle callbacks do not wait for filesystem or pipe I/O.
func (s *Service) RequestStop() {
	s.stop.Do(func() {
		s.cancel()
		go func() {
			defer close(s.ioStopped)
			e := s.listener.Close()
			s.mu.Lock()
			if e != nil && !errors.Is(e, net.ErrClosed) {
				s.stopError = ErrUnavailable
			}
			for c := range s.connections {
				_ = c.Close()
			}
			s.mu.Unlock()
		}()
	})
}
func (s *Service) Close() error {
	s.RequestStop()
	<-s.done
	<-s.ioStopped
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopError
}
func (s *Service) accept() {
	defer s.wg.Done()
	defer s.RequestStop()
	for {
		c, e := s.listener.Accept()
		if e != nil {
			s.cancel()
			return
		}
		select {
		case <-s.ctx.Done():
			_ = c.Close()
			return
		default:
		}
		select {
		case s.slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		s.mu.Lock()
		s.connections[c] = true
		s.accepted++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { _ = c.Close(); <-s.slots; s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
			ctx, cancel := context.WithTimeout(s.ctx, ConnectionLifetime)
			defer cancel()
			stopClose := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stopClose()
			peer, first, e := prepareConnection(c)
			if e != nil {
				s.mu.Lock()
				s.peerRefusal = peerRefusalCategory(e)
				s.mu.Unlock()
				return
			}
			serveInitial(ctx, c, peer, s.handler, s.writers, first)
		}()
	}
}

func randomID() (string, error) {
	var value [16]byte
	if _, e := rand.Read(value[:]); e != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(value[:]), nil
}
func readFrame(c net.Conn) ([]byte, error) {
	if e := c.SetReadDeadline(time.Now().Add(ReadIdle)); e != nil {
		return nil, ErrRefused
	}
	var header [4]byte
	if _, e := io.ReadFull(c, header[:]); e != nil {
		return nil, ErrRefused
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrame {
		return nil, ErrRefused
	}
	frame := make([]byte, int(n))
	if _, e := io.ReadFull(c, frame); e != nil {
		clear(frame)
		return nil, ErrRefused
	}
	return frame, nil
}
func writeFrame(c net.Conn, frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxFrame {
		return ErrRefused
	}
	if e := c.SetWriteDeadline(time.Now().Add(WriteTimeout)); e != nil {
		return ErrRefused
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(frame)))
	if e := writeAll(c, header[:]); e != nil {
		return e
	}
	return writeAll(c, frame)
}
func writeAll(w io.Writer, value []byte) error {
	for len(value) > 0 {
		n, e := w.Write(value)
		if e != nil || n <= 0 {
			return ErrRefused
		}
		value = value[n:]
	}
	return nil
}

func serve(parent context.Context, c net.Conn, peer Peer, handler Handler, writers chan struct{}) {
	serveInitial(parent, c, peer, handler, writers, nil)
}
func serveInitial(parent context.Context, c net.Conn, peer Peer, handler Handler, writers chan struct{}, first []byte) {
	ctx, cancel := context.WithTimeout(parent, ConnectionLifetime)
	defer cancel()
	connection, e := randomID()
	if e != nil {
		return
	}
	frames := make(chan []byte, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(frames)
		defer cancel()
		for {
			frame := first
			first = nil
			var e error
			if frame == nil {
				frame, e = readFrame(c)
			}
			if e != nil {
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				clear(frame)
				return
			default:
				clear(frame)
				return
			}
		}
	}()
	go func() { <-ctx.Done(); _ = c.Close() }()
	defer func() {
		cancel()
		_ = c.Close()
		<-readerDone
		for frame := range frames {
			clear(frame)
		}
	}()
	for count := 0; count < MaxRequests; count++ {
		var frame []byte
		select {
		case <-ctx.Done():
			return
		case value, ok := <-frames:
			if !ok {
				return
			}
			frame = value
		}
		select {
		case writers <- struct{}{}:
		case <-ctx.Done():
			clear(frame)
			return
		default:
			clear(frame)
			return
		}
		response := dispatch(ctx, peer, connection, frame, handler)
		clear(frame)
		if ctx.Err() != nil {
			clear(response)
			<-writers
			return
		}
		e = writeFrame(c, response)
		clear(response)
		<-writers
		if e != nil {
			return
		}
	}
}

func dispatch(ctx context.Context, peer Peer, connection string, frame []byte, handler Handler) []byte {
	failure := func() []byte { return []byte{5} }
	if len(frame) == 0 {
		return failure()
	}
	switch frame[0] {
	case 11:
		if len(frame) != 1 {
			return failure()
		}
		keys, e := handler.Identities(ctx, peer)
		if e != nil || len(keys) > MaxIdentities {
			return failure()
		}
		response := []byte{12, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(response[1:5], uint32(len(keys)))
		for _, key := range keys {
			pub, e := ssh.ParsePublicKey(key.Blob)
			if e != nil || pub.Type() != ssh.KeyAlgoED25519 || !bytes.Equal(pub.Marshal(), key.Blob) || len(key.Comment) > 256 {
				return failure()
			}
			response = append(response, ssh.Marshal(struct {
				Blob    []byte
				Comment string
			}{key.Blob, SafeText(key.Comment, 256)})...)
			if len(response) > MaxFrame {
				return failure()
			}
		}
		return response
	case 13:
		var request struct {
			Key, Data []byte
			Flags     uint32
		}
		if ssh.Unmarshal(frame[1:], &request) != nil {
			return failure()
		}
		if request.Flags != 0 || len(request.Data) == 0 || len(request.Data) > MaxSignData || len(request.Key) > 1024 {
			return failure()
		}
		pub, e := ssh.ParsePublicKey(request.Key)
		if e != nil || pub.Type() != ssh.KeyAlgoED25519 || !bytes.Equal(pub.Marshal(), request.Key) {
			return failure()
		}
		id, e := randomID()
		if e != nil {
			return failure()
		}
		deadline := time.Now().Add(ApprovalTimeout)
		signCtx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		bound := SignRequest{id, connection, peer, append([]byte(nil), request.Key...), append([]byte(nil), request.Data...), deadline}
		defer clear(bound.PublicKey)
		defer clear(bound.Data)
		blob, e := handler.Sign(signCtx, bound)
		defer clear(blob)
		if e != nil || signCtx.Err() != nil {
			return failure()
		}
		var sig ssh.Signature
		if len(blob) > 128 || ssh.Unmarshal(blob, &sig) != nil || sig.Format != ssh.KeyAlgoED25519 || len(sig.Blob) != 64 || len(sig.Rest) != 0 || pub.Verify(request.Data, &sig) != nil {
			return failure()
		}
		return append([]byte{14}, ssh.Marshal(struct{ Signature []byte }{blob})...)
	default:
		return failure()
	}
}
