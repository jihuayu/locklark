package vaultfilebackend

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
)

// memoryInstanceSeq hands out process-unique Memory instance IDs so revisions
// minted by different instances never collide.
var memoryInstanceSeq atomic.Uint64

// Memory is an in-process Backend for tests and ephemeral use. It is not
// durable, is not shared between processes, and returns ErrUnsupported from
// List.
//
// Memory issues its own opaque revisions: a process-unique instance prefix plus
// a counter scoped to this instance, so every committed version gets a distinct
// revision. They are not content digests, are not equal across instances, and
// carry no history: a revision only identifies the version it was returned
// with. All waits on the internal lock are cancellable through ctx.
type Memory struct {
	id     string
	mu     memoryLock
	values map[string]memoryVersion
	seq    uint64
	closed bool
}

type memoryVersion struct {
	bytes    []byte
	revision Revision
}

// NewMemory returns an empty Memory backend.
func NewMemory() *Memory {
	m := &Memory{
		id:     strconv.FormatUint(memoryInstanceSeq.Add(1), 10),
		values: make(map[string]memoryVersion),
	}
	m.mu.sem = make(chan struct{}, 1)
	return m
}

func (m *Memory) Read(ctx context.Context, name string) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, denied(err)
	}
	if !ValidName(name) {
		return ReadResult{}, denied(nil)
	}
	if err := m.mu.lock(ctx); err != nil {
		return ReadResult{}, denied(err)
	}
	defer m.mu.unlock()
	// The fast path in lock can win the lock after ctx was already cancelled:
	// re-check so a cancelled caller never observes stored state, including the
	// ErrNotFound path for a missing name.
	if err := ctx.Err(); err != nil {
		return ReadResult{}, denied(err)
	}
	if m.closed {
		return ReadResult{}, denied(nil)
	}
	v, ok := m.values[name]
	if !ok {
		return ReadResult{}, ErrNotFound
	}
	b := append([]byte(nil), v.bytes...)
	if err := ctx.Err(); err != nil {
		return ReadResult{}, denied(err)
	}
	return ReadResult{Bytes: b, Revision: v.revision}, nil
}

func (m *Memory) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if !ValidName(name) || !validValue(value) {
		return denied(nil)
	}
	if err := m.mu.lock(ctx); err != nil {
		return denied(err)
	}
	defer m.mu.unlock()
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if m.closed {
		return denied(nil)
	}
	if _, ok := m.values[name]; ok {
		return ErrConflict
	}
	return m.commit(ctx, name, value)
}

func (m *Memory) ReplaceIfVersion(ctx context.Context, name string, expected Revision, value []byte) error {
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if !ValidName(name) || !validValue(value) || !validExpectedRevision(expected) {
		return denied(nil)
	}
	if err := m.mu.lock(ctx); err != nil {
		return denied(err)
	}
	defer m.mu.unlock()
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if m.closed {
		return denied(nil)
	}
	cur, ok := m.values[name]
	if !ok || cur.revision != expected {
		return ErrConflict
	}
	return m.commit(ctx, name, value)
}

func (m *Memory) List(ctx context.Context) ([]string, error) {
	if err := m.mu.lock(ctx); err != nil {
		return nil, denied(err)
	}
	defer m.mu.unlock()
	// The fast path in lock can win the lock after ctx was already cancelled:
	// re-check so a cancelled caller sees the cancellation rather than
	// ErrUnsupported.
	if err := ctx.Err(); err != nil {
		return nil, denied(err)
	}
	if m.closed {
		return nil, denied(nil)
	}
	return nil, ErrUnsupported
}

// Close discards in-memory state; it is idempotent.
func (m *Memory) Close() error {
	m.mu.lock(context.Background())
	defer m.mu.unlock()
	m.closed = true
	m.values = make(map[string]memoryVersion)
	return nil
}

// commit must be called with m.mu held and ctx already checked. It copies
// value into a private buffer and checks ctx once more right before installing
// the version: if the caller was cancelled in between, the copy is discarded
// and nothing is committed.
func (m *Memory) commit(ctx context.Context, name string, value []byte) error {
	b := append([]byte(nil), value...)
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	m.seq++
	rev := Revision(m.id + "-" + strconv.FormatUint(m.seq, 10))
	m.values[name] = memoryVersion{bytes: b, revision: rev}
	return nil
}

// memoryLock is a mutex whose acquisition can be abandoned when ctx is done:
// the waiter returns the context error without ever holding the lock, so a
// cancelled caller never writes later and leaves no goroutine behind. The
// holder is not interrupted; it observes cancellation under the lock as usual.
type memoryLock struct {
	sem chan struct{}
}

// lock acquires the lock or returns ctx.Err() while it is still held by
// another holder.
func (l *memoryLock) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case l.sem <- struct{}{}:
		return nil
	default:
	}
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *memoryLock) unlock() { <-l.sem }

func denied(cause error) error {
	if cause == nil {
		return ErrDenied
	}
	return fmt.Errorf("%w: %w", ErrDenied, cause)
}
