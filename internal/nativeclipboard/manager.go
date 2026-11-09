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

// deadline is the single hard boundary for an offer: the earlier of until and
// a nonzero clearUntil. Every timer and admission check uses it so plaintext is
// never retained past the earliest deadline while a job is still queued.
func (o *copyOffer) deadline() time.Time {
	if o.clearUntil.IsZero() || !o.clearUntil.Before(o.until) {
		return o.until
	}
	return o.clearUntil
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
	timer     atomic.Pointer[time.Timer]
	// onQueuedCancel releases the manager slot when cancellation wins before
	// the dispatched run acquires the buffer. It is set before the deadline
	// timer is armed so the timer can never observe a nil callback.
	onQueuedCancel func(*copyJob)
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
	wiped := false
	if j.valueMu.TryLock() {
		clear(j.offer.value)
		j.offer.value = nil
		wiped = true
		j.valueMu.Unlock()
	}
	// The release runs after valueMu is unlocked so it never nests the buffer
	// lock under m.mu. A failed TryLock means a dispatched run owns the buffer
	// (or its write is in flight); that run keeps the slot occupied and its
	// deferred release finishes the job, so state 1 never releases early.
	if wiped && j.state.Load() == 2 {
		if j.onQueuedCancel != nil {
			j.onQueuedCancel(j)
		}
		j.finish(Refused)
	}
}

// Manager bounds each connection to one prepared secret, one queued/in-flight
// write, and one current lease. Native callbacks run only through dispatch.
// dispatch must return false only when it has not executed/enqueued its work.
type Manager struct {
	mu           sync.Mutex
	dispatch     func(func()) bool
	write        func([]byte) (*Lease, error)
	writeContext func([]byte, time.Time, func() bool) (*Lease, error)
	clearOwned   func(*Lease) Result
	closed       bool
	offer        *copyOffer
	job          *copyJob
	runner       bool // one queued/running UI callback, reused after queued cancellation
	lease        *Lease
	leaseTimer   *time.Timer
	sequence     uint64
	pending      *Lease
	retryTimer   *time.Timer
	cleanupSeq   uint64
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

// NewManagerWithWriter builds a manager whose native acquisition receives the
// offer's clear deadline and a non-blocking authority check. The writer must
// call valid synchronously; valid must not reenter the Manager while it is
// otherwise holding Manager.mu. run calls it without holding that lock.
func NewManagerWithWriter(dispatch func(func()) bool, write func([]byte, time.Time, func() bool) (*Lease, error), clearOwned func(*Lease) Result) *Manager {
	if write == nil {
		write = func(value []byte, _ time.Time, _ func() bool) (*Lease, error) { return Write(value) }
	}
	if clearOwned == nil {
		clearOwned = ClearOwned
	}
	return &Manager{dispatch: dispatch, writeContext: write, clearOwned: clearOwned}
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
	m.offer.timer = time.AfterFunc(time.Until(m.offer.deadline()), func() { m.CancelOffer(ticket) })
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
		!ticketMatches(o.ticket, ticket) || !time.Now().Before(o.deadline()) {
		if o != nil && !time.Now().Before(o.deadline()) {
			m.dropOfferLocked()
		}
		m.mu.Unlock()
		done <- Refused
		return done
	}
	m.offer = nil
	o.timer.Stop()
	j := &copyJob{offer: o, ctx: ctx, done: done, finished: make(chan struct{}), onQueuedCancel: m.releaseJob}
	m.job = j
	queueRunner := !m.runner
	if queueRunner {
		m.runner = true
	}
	j.timer.Store(time.AfterFunc(time.Until(o.deadline()), j.cancel))
	m.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			j.cancel()
		case <-j.finished:
		}
	}()
	if queueRunner && !m.dispatch(m.drain) {
		// No callback was queued. A cancellation may already have replaced the
		// original job; refuse whichever job was relying on this runner.
		m.mu.Lock()
		m.runner = false
		waiting := m.job
		m.mu.Unlock()
		if waiting != nil {
			waiting.cancel()
		}
	}
	return done
}

// drain captures no job or secret in the UI queue. A cancelled queued job can
// release its slot while the one existing callback stays queued; a later,
// explicitly committed job reuses that callback instead of growing the queue.
func (m *Manager) drain() {
	for {
		m.mu.Lock()
		j := m.job
		if j == nil {
			m.runner = false
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		m.run(j)
	}
}

func (m *Manager) currentJob(j *copyJob) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.job == j
}

func (m *Manager) live(j *copyJob) bool {
	now := time.Now()
	return !j.cancelled.Load() && j.ctx.Err() == nil && now.Before(j.offer.deadline()) &&
		m.currentJob(j) && j.offer.valid()
}

func (m *Manager) releaseJob(j *copyJob) {
	if timer := j.timer.Load(); timer != nil {
		timer.Stop()
	}
	m.mu.Lock()
	if m.job == j {
		m.job = nil
	}
	m.mu.Unlock()
}

func (m *Manager) run(j *copyJob) {
	outcome := Refused
	// Publish only after the buffer and manager slot have been released, so a
	// consumer of the receipt can immediately prepare its next explicit copy.
	defer func() { j.finish(outcome) }()
	j.valueMu.Lock()
	defer j.valueMu.Unlock()
	defer m.releaseJob(j)
	defer func() { clear(j.offer.value); j.offer.value = nil }()
	if !m.live(j) {
		return
	}
	// This one-shot decision is the cancellation/write linearization point.
	// Cancellation that wins first cannot be followed by a native acquisition.
	if !j.state.CompareAndSwap(0, 1) {
		return
	}
	outcome = Unknown
	var lease *Lease
	var err error
	if m.writeContext != nil {
		lease, err = m.writeContext(j.offer.value, j.offer.clearUntil, func() bool { return m.live(j) })
	} else {
		lease, err = m.write(j.offer.value)
	}
	clear(j.offer.value)
	j.offer.value = nil
	if err != nil || lease == nil || !m.live(j) {
		if lease != nil {
			m.detachSuperseded(j)
		}
		m.cleanup(lease)
		return
	}
	m.mu.Lock()
	if m.closed || m.job != j {
		m.mu.Unlock()
		m.cleanup(lease)
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
		return
	}
	outcome = Confirmed
}

// detachSuperseded releases the previous logical lease after a new native
// acquisition attempt, even one whose write reported an error or went stale. A
// non-nil lease is only cleanup authority for that acquisition attempt; it does
// not prove the write currently owns the clipboard (ClearOwned refuses to blank
// a newer owner). Retiring the old lease here keeps its deadline from firing and
// leaves this attempt's lease as the sole cleanup authority (see cleanup). It
// does nothing once this job no longer owns state.
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
		if result == ManualCleanup {
			// The platform cannot revoke only our owner. This is terminal: drop
			// the lease and retry queue without claiming a confirmed cleanup.
			m.pending = nil
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
