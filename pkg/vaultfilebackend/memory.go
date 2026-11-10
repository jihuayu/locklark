package vaultfilebackend

import (
	"context"
	"fmt"
	"strconv"
	"sync"
)

// Memory is an in-process Backend for tests and ephemeral use. It is not
// durable, is not shared between processes, and returns ErrUnsupported from
// List.
//
// Memory issues its own opaque revisions: a counter scoped to this instance,
// so every committed version gets a distinct revision. They are not content
// digests, are not equal across instances, and carry no history: a revision
// only identifies the version it was returned with. All waits on the internal
// lock are cancellable through ctx.
type Memory struct {
	mu     sync.Mutex
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
	return &Memory{values: make(map[string]memoryVersion)}
}

func (m *Memory) Read(ctx context.Context, name string) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, denied(err)
	}
	if !ValidName(name) {
		return ReadResult{}, denied(nil)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ReadResult{}, denied(nil)
	}
	if err := ctx.Err(); err != nil {
		return ReadResult{}, denied(err)
	}
	v, ok := m.values[name]
	if !ok {
		return ReadResult{}, ErrNotFound
	}
	out := append([]byte(nil), v.bytes...)
	if err := ctx.Err(); err != nil {
		return ReadResult{}, denied(err)
	}
	return ReadResult{Bytes: out, Revision: v.revision}, nil
}

func (m *Memory) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if !ValidName(name) || !validValue(value) {
		return denied(nil)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return denied(nil)
	}
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if _, ok := m.values[name]; ok {
		return ErrConflict
	}
	m.commit(name, value)
	return nil
}

func (m *Memory) ReplaceIfVersion(ctx context.Context, name string, expected Revision, value []byte) error {
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if !ValidName(name) || !validValue(value) || !validExpectedRevision(expected) {
		return denied(nil)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return denied(nil)
	}
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	cur, ok := m.values[name]
	if !ok || cur.revision != expected {
		return ErrConflict
	}
	m.commit(name, value)
	return nil
}

func (m *Memory) List(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, denied(nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, denied(err)
	}
	return nil, ErrUnsupported
}

// Close discards in-memory state; it is idempotent.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.values = make(map[string]memoryVersion)
	return nil
}

// commit must be called with m.mu held and a fresh ctx check done.
func (m *Memory) commit(name string, value []byte) {
	m.seq++
	b := append([]byte(nil), value...)
	m.values[name] = memoryVersion{bytes: b, revision: Revision(strconv.FormatUint(m.seq, 10))}
}

func denied(cause error) error {
	if cause == nil {
		return ErrDenied
	}
	return fmt.Errorf("%w: %w", ErrDenied, cause)
}
