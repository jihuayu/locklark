package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
)

// ManagedHandler owns the sequencer key retained by an HTTPS handler.
// Close invalidates future grants without waiting for storage or network I/O.
// A commit or write granted before Close can still finish.
type ManagedHandler interface {
	http.Handler
	Close()
}

// Per-instance barriers make grant ordering testable without changing public
// requests, exposing keys or installing a process-wide callback.
type serverLifecycleHooks struct {
	beforeRead, beforeCommitGrant, afterCommitGrant func()
	beforeSign, afterSign                           func()
	beforeWriteGrant                                func()
}

func (s *server) live(ctx context.Context) bool {
	return s != nil && !s.closed.Load() && ctx != nil && ctx.Err() == nil
}

func (s *server) Close() {
	if s == nil {
		return
	}
	// This signal prevents a grant even while another worker owns the DB mutex.
	s.closed.Store(true)
	if s.cancel != nil {
		s.cancel()
	}
	s.keyMu.Lock()
	clear(s.key)
	s.key = nil
	s.keyMu.Unlock()
}

func (s *server) commitKey(ctx context.Context) (ed25519.PrivateKey, bool) {
	if s.hooks != nil && s.hooks.beforeCommitGrant != nil {
		s.hooks.beforeCommitGrant()
	}
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if !s.live(ctx) {
		return nil, false
	}
	return bytes.Clone(s.key), true
}

func (s *server) signResponse(ctx context.Context, out *response) bool {
	if s.hooks != nil && s.hooks.beforeSign != nil {
		s.hooks.beforeSign()
	}
	payload := out.signingBytes()
	s.keyMu.Lock()
	if !s.live(ctx) {
		s.keyMu.Unlock()
		return false
	}
	// The checked critical section is the signature grant. Close may signal
	// during this short operation, but cannot race the base-key buffer.
	out.Signature = ed25519.Sign(s.key, payload)
	s.keyMu.Unlock()
	if s.hooks != nil && s.hooks.afterSign != nil {
		s.hooks.afterSign()
	}
	return true
}

func (s *server) grantWrite(ctx context.Context) bool {
	if s.hooks != nil && s.hooks.beforeWriteGrant != nil {
		s.hooks.beforeWriteGrant()
	}
	s.keyMu.Lock()
	granted := s.live(ctx)
	s.keyMu.Unlock()
	return granted
}

func (s *server) refuse(ctx context.Context, w http.ResponseWriter, code int) {
	if s.grantWrite(ctx) {
		refuseHTTP(w, code)
	}
}
