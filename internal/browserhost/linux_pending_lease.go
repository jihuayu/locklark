//go:build linux

package browserhost

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

const (
	linuxPendingLeaseCapacity = 16
	linuxPendingLeaseTTL      = 2 * time.Minute
)

type linuxPendingLeaseKey struct {
	vault    string
	session  *personal.Session
	epoch    uint64
	uid      uint32
	exePath  string
	exeDev   uint64
	exeIno   uint64
	scopeSum [sha256.Size]byte
}

type linuxPendingLeaseRecord struct {
	key    linuxPendingLeaseKey
	anchor *linuxLeaseAnchor
	expiry time.Time
}

// linuxPendingLeaseStore is a fixed-capacity, non-authorizing qualification
// cache. No production caller uses it and it never approves or discloses
// values. It exists only to bind a pending lease to a sealed proof and an
// independently held terminal anchor for review.
type linuxPendingLeaseStore struct {
	mu       sync.Mutex
	capacity int
	now      func() time.Time
	records  []linuxPendingLeaseRecord
	closed   bool
}

func newLinuxPendingLeaseStore(capacity int) *linuxPendingLeaseStore {
	if capacity <= 0 || capacity > linuxPendingLeaseCapacity {
		capacity = linuxPendingLeaseCapacity
	}
	return &linuxPendingLeaseStore{capacity: capacity, now: time.Now}
}

func (s *linuxPendingLeaseStore) Add(req CLIRunBrokerRequest, peer Peer, vault string, session *personal.Session, epoch uint64, deadline time.Time) bool {
	if s == nil || session == nil || !session.Unlocked() || !req.VerifyCLIRunCTTY(peer) {
		return false
	}
	assoc, ok := req.cttyProof.owner.(*linuxPeerCTTYAssociation)
	if !ok || assoc == nil {
		return false
	}
	digest, ok := linuxPendingScopeDigest(req.Scope, req.Targets)
	if !ok {
		return false
	}
	now := s.now()
	expiry := now.Add(linuxPendingLeaseTTL)
	if !deadline.IsZero() && deadline.Before(expiry) {
		expiry = deadline
	}
	if !expiry.After(now) {
		return false
	}
	anchor, ok := newLinuxLeaseAnchor(assoc)
	if !ok {
		return false
	}
	key := linuxPendingLeaseKey{
		vault: vault, session: session, epoch: epoch,
		uid: assoc.proof.uid, exePath: assoc.proof.exe.path,
		exeDev: assoc.proof.exe.dev, exeIno: assoc.proof.exe.ino,
		scopeSum: digest,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = anchor.Close()
		return false
	}
	s.expireLocked(now)
	for _, record := range s.records {
		if record.key == key {
			_ = anchor.Close() // duplicate/no renewal
			return false
		}
	}
	if len(s.records) >= s.capacity {
		_ = anchor.Close()
		return false
	}
	s.records = append(s.records, linuxPendingLeaseRecord{key: key, anchor: anchor, expiry: expiry})
	return true
}

func (s *linuxPendingLeaseStore) Match(req CLIRunBrokerRequest, peer Peer, vault string, session *personal.Session, epoch uint64) bool {
	if s == nil || session == nil || !session.Unlocked() || !req.VerifyCLIRunCTTY(peer) {
		return false
	}
	assoc, ok := req.cttyProof.owner.(*linuxPeerCTTYAssociation)
	if !ok || assoc == nil {
		return false
	}
	digest, ok := linuxPendingScopeDigest(req.Scope, req.Targets)
	if !ok {
		return false
	}
	binding, ok := req.CLIRunCTTYBinding(peer)
	if !ok {
		return false
	}
	key := linuxPendingLeaseKey{
		vault: vault, session: session, epoch: epoch,
		uid: assoc.proof.uid, exePath: assoc.proof.exe.path,
		exeDev: assoc.proof.exe.dev, exeIno: assoc.proof.exe.ino,
		scopeSum: digest,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	now := s.now()
	s.expireLocked(now)
	s.removeForeignEpochLocked(session, vault, epoch)
	s.removeDeadAnchorsLocked()
	for i, record := range s.records {
		if record.key != key {
			continue
		}
		if !now.Before(record.expiry) || !record.anchor.matches(binding) {
			s.removeLocked(i)
			return false
		}
		return true
	}
	return false
}

func (s *linuxPendingLeaseStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
}

func (s *linuxPendingLeaseStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.clearLocked()
}

func (s *linuxPendingLeaseStore) clearLocked() {
	for _, record := range s.records {
		_ = record.anchor.Close()
	}
	s.records = nil
}

func (s *linuxPendingLeaseStore) expireLocked(now time.Time) {
	kept := s.records[:0]
	for _, record := range s.records {
		if now.Before(record.expiry) {
			kept = append(kept, record)
			continue
		}
		_ = record.anchor.Close()
	}
	s.records = kept
}

func (s *linuxPendingLeaseStore) removeForeignEpochLocked(session *personal.Session, vault string, epoch uint64) {
	kept := s.records[:0]
	for _, record := range s.records {
		if record.key.session == session && record.key.vault == vault && record.key.epoch != epoch {
			_ = record.anchor.Close()
			continue
		}
		kept = append(kept, record)
	}
	s.records = kept
}

func (s *linuxPendingLeaseStore) removeDeadAnchorsLocked() {
	kept := s.records[:0]
	for _, record := range s.records {
		if !record.anchor.live() {
			_ = record.anchor.Close()
			continue
		}
		kept = append(kept, record)
	}
	s.records = kept
}

func (s *linuxPendingLeaseStore) removeLocked(index int) {
	record := s.records[index]
	_ = record.anchor.Close()
	copy(s.records[index:], s.records[index+1:])
	s.records = s.records[:len(s.records)-1]
}

func linuxPendingScopeDigest(scope CLIRunScope, targets []personal.CLIBrokerTarget) ([sha256.Size]byte, bool) {
	scope.Nonce = ""
	scope.TempRoot = ""
	raw, err := json.Marshal(struct {
		Scope   CLIRunScope
		Targets []personal.CLIBrokerTarget
	}{Scope: scope, Targets: targets})
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	defer clear(raw)
	payload := append([]byte("locklark/linux/pending-lease-scope/v1\x00"), raw...)
	defer clear(payload)
	return sha256.Sum256(payload), true
}
