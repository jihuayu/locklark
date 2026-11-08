package nativeclipboard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Outcome describes only local delivery. Unknown must never trigger a retry.
type Outcome uint8

const (
	Refused Outcome = iota
	Confirmed
	Unknown
)

type copyOffer struct {
	ticket            string
	value             []byte
	until, clearUntil time.Time
	valid             func() bool
	timer             *time.Timer
}

type copyJob struct {
	offer     *copyOffer
	ctx       context.Context
	valueMu   sync.Mutex
	cancelled atomic.Bool
	state     atomic.Uint32 // 0: queued; 1: native write won; 2: cancellation won
	done      chan Outcome
	finished  chan struct{}
	once      sync.Once
	timer     *time.Timer
}

func (j *copyJob) finish(result Outcome) {
	j.once.Do(func() {
		j.done <- result
		close(j.finished)
	})
}

// cancel never waits for a native write that is borrowing the buffer. The
// writer observes cancellation after returning and then owns cleanup.
func (j *copyJob) cancel() {
	j.state.CompareAndSwap(0, 2)
	j.cancelled.Store(true)
	if j.valueMu.TryLock() {
		clear(j.offer.value)
		j.offer.value = nil
		if j.state.Load() == 2 {
			j.finish(Refused)
		}
		j.valueMu.Unlock()
	}
}

// Manager bounds each connection to one prepared secret, one queued/in-flight
// write, and one current lease. Native callbacks run only through dispatch.
// dispatch must return false only when it has not executed/enqueued its work.
type Manager struct {
	mu         sync.Mutex
	dispatch   func(func()) bool
	write      func([]byte) (*Lease, error)
	clearOwned func(*Lease) Result
	closed     bool
	offer      *copyOffer
	job        *copyJob
	lease      *Lease
	leaseTimer *time.Timer
	sequence   uint64
	pending    *Lease
	retryTimer *time.Timer
	cleanupSeq uint64
}

func (*Manager) String() string               { return "[clipboard manager]" }
func (*Manager) GoString() string             { return "[clipboard manager]" }
func (*Manager) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func NewManager(dispatch func(func()) bool, write func([]byte) (*Lease, error), clearOwned func(*Lease) Result) *Manager {
	if write == nil {
		write = Write
	}
	if clearOwned == nil {
		clearOwned = ClearOwned
	}
	return &Manager{dispatch: dispatch, write: write, clearOwned: clearOwned}
}

// Prepare copies a value without acquiring the OS clipboard. valid must be a
// non-blocking authority check and must not reenter this Manager.
func (m *Manager) Prepare(value []byte, until, clearUntil time.Time, valid func() bool) (string, error) {
	now := time.Now()
	if len(value) > 4<<20 || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 ||
		!now.Before(until) || until.After(now.Add(30*time.Second)) ||
		!clearUntil.IsZero() && !now.Before(clearUntil) || valid == nil || !valid() {
		return "", ErrUnavailable
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", ErrUnavailable
	}
	ticket := hex.EncodeToString(token[:])
	clear(token[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.dispatch == nil || m.job != nil {
		return "", ErrUnavailable
	}
	m.dropOfferLocked()
	m.offer = &copyOffer{ticket: ticket, value: bytes.Clone(value), until: until, clearUntil: clearUntil, valid: valid}
	m.offer.timer = time.AfterFunc(time.Until(until), func() { m.CancelOffer(ticket) })
	return ticket, nil
}

func ticketMatches(a, b string) bool {
	return len(a) == 64 && len(b) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (m *Manager) dropOfferLocked() {
	if m.offer == nil {
		return
	}
	if m.offer.timer != nil {
		m.offer.timer.Stop()
	}
	clear(m.offer.value)
	m.offer.value = nil
	m.offer = nil
}

// CancelOffer cannot cancel a newer offer with a different ticket.
func (m *Manager) CancelOffer(ticket string) {
	m.mu.Lock()
	if m.offer != nil && ticketMatches(m.offer.ticket, ticket) {
		m.dropOfferLocked()
	}
	j := m.job
	if j != nil && !ticketMatches(j.offer.ticket, ticket) {
		j = nil
	}
	m.mu.Unlock()
	if j != nil {
		j.cancel()
	}
}

// Commit consumes its offer once. The caller may abandon the result on
// cancellation; it must never retry a write whose outcome is Unknown.
func (m *Manager) Commit(ctx context.Context, ticket string) <-chan Outcome {
	done := make(chan Outcome, 1)
	m.mu.Lock()
	o := m.offer
	if ctx == nil || ctx.Err() != nil || m.closed || m.job != nil || o == nil ||
		!ticketMatches(o.ticket, ticket) || !time.Now().Before(o.until) {
		if o != nil && !time.Now().Before(o.until) {
			m.dropOfferLocked()
		}
		m.mu.Unlock()
		done <- Refused
		return done
	}
	m.offer = nil
	o.timer.Stop()
	j := &copyJob{offer: o, ctx: ctx, done: done, finished: make(chan struct{})}
	m.job = j
	j.timer = time.AfterFunc(time.Until(o.until), j.cancel)
	m.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			j.cancel()
		case <-j.finished:
		}
	}()
	if !m.dispatch(func() { m.run(j) }) {
		j.cancel()
		m.releaseJob(j)
	}
	return done
}

func (m *Manager) currentJob(j *copyJob) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.job == j
}

func (m *Manager) live(j *copyJob) bool {
	return !j.cancelled.Load() && j.ctx.Err() == nil && time.Now().Before(j.offer.until) &&
		(j.offer.clearUntil.IsZero() || time.Now().Before(j.offer.clearUntil)) &&
		m.currentJob(j) && j.offer.valid()
}

func (m *Manager) releaseJob(j *copyJob) {
	j.timer.Stop()
	m.mu.Lock()
	if m.job == j {
		m.job = nil
	}
	m.mu.Unlock()
}

func (m *Manager) run(j *copyJob) {
	j.valueMu.Lock()
	defer j.valueMu.Unlock()
	defer m.releaseJob(j)
	defer func() { clear(j.offer.value); j.offer.value = nil }()
	if !m.live(j) {
		j.finish(Refused)
		return
	}
	// This one-shot decision is the cancellation/write linearization point.
	// Cancellation that wins first cannot be followed by a native acquisition.
	if !j.state.CompareAndSwap(0, 1) {
		j.finish(Refused)
		return
	}
	lease, err := m.write(j.offer.value)
	clear(j.offer.value)
	j.offer.value = nil
	if err != nil || lease == nil || !m.live(j) {
		if lease != nil {
			m.detachSuperseded(j)
		}
		m.cleanup(lease)
		j.finish(Unknown)
		return
	}
	m.mu.Lock()
	if m.closed || m.job != j {
		m.mu.Unlock()
		m.cleanup(lease)
		j.finish(Unknown)
		return
	}
	old := m.lease
	m.lease = lease
	m.sequence++
	// A confirmed new acquisition supersedes cleanup for the previous owner,
	// including a previous acquisition of identical bytes.
	m.pending = nil
	m.cleanupSeq++
	if m.retryTimer != nil {
		m.retryTimer.Stop()
		m.retryTimer = nil
	}
	sequence := m.sequence
	if m.leaseTimer != nil {
		m.leaseTimer.Stop()
	}
	if !j.offer.clearUntil.IsZero() {
		m.leaseTimer = time.AfterFunc(time.Until(j.offer.clearUntil), func() { m.expire(lease, sequence) })
	}
	m.mu.Unlock()
	m.cleanup(old)
	if !m.live(j) {
		m.expire(lease, sequence)
		j.finish(Unknown)
		return
	}
	j.finish(Confirmed)
}

// detachSuperseded releases the previous logical lease after a new native
// acquisition, even one whose write reported an error or went stale. A non-nil
// lease proves native ownership moved, so clearing the old lease would blank
// the new copy and its deadline must not fire; only the new lease keeps cleanup
// authority (see cleanup). It does nothing once this job no longer owns state.
func (m *Manager) detachSuperseded(j *copyJob) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job != j || m.closed {
		return
	}
	if m.leaseTimer != nil {
		m.leaseTimer.Stop()
		m.leaseTimer = nil
	}
	m.lease = nil
	m.sequence++
	m.pending = nil
	m.cleanupSeq++
	if m.retryTimer != nil {
		m.retryTimer.Stop()
		m.retryTimer = nil
	}
}

func (m *Manager) expire(lease *Lease, sequence uint64) {
	m.mu.Lock()
	if m.lease != lease || m.sequence != sequence {
		m.mu.Unlock()
		return
	}
	m.lease = nil
	m.mu.Unlock()
	m.cleanup(lease)
}

// cleanup retains only opaque cleanup authority. A newer acquisition or
// cleanup supersedes its retries; no value is retained or written again.
func (m *Manager) cleanup(lease *Lease) {
	if lease == nil {
		return
	}
	m.mu.Lock()
	if m.lease != nil && m.lease != lease {
		m.mu.Unlock()
		return
	}
	m.pending = lease
	m.cleanupSeq++
	sequence := m.cleanupSeq
	if m.retryTimer != nil {
		m.retryTimer.Stop()
	}
	m.mu.Unlock()
	m.tryCleanup(lease, sequence, 0)
}

func (m *Manager) tryCleanup(lease *Lease, sequence uint64, attempt int) {
	if m.dispatch == nil {
		return
	}
	m.dispatch(func() {
		m.mu.Lock()
		if m.pending != lease || m.cleanupSeq != sequence || m.lease != nil && m.lease != lease {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		result := m.clearOwned(lease)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.pending != lease || m.cleanupSeq != sequence {
			return
		}
		if result != Unavailable {
			m.pending = nil
			return
		}
		if attempt < 3 {
			m.retryTimer = time.AfterFunc(time.Second, func() { m.tryCleanup(lease, sequence, attempt+1) })
		}
	})
}

// CleanupPending reports an unconfirmed cleanup without exposing a payload.
func (m *Manager) CleanupPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending != nil
}

func (m *Manager) Clear() {
	m.mu.Lock()
	m.dropOfferLocked()
	j := m.job
	lease := m.lease
	m.lease = nil
	m.sequence++
	if m.leaseTimer != nil {
		m.leaseTimer.Stop()
	}
	m.mu.Unlock()
	if j != nil {
		j.cancel()
	}
	m.cleanup(lease)
}

func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.Clear()
}
