package vaultfilebackend

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
)

// Memory is an in-process Backend for tests and ephemeral use. It is not
// durable, is not shared between processes, and returns ErrUnsupported from
// List. Each committed version gets a token derived from its bytes, with the
// same meaning as on-disk tokens: equal bytes give an equal token.
type Memory struct {
	mu     sync.Mutex
	values map[string]memoryVersion
	closed bool
}

type memoryVersion struct {
	bytes []byte
	token Token
}

// NewMemory returns an empty Memory backend.
func NewMemory() *Memory {
	return &Memory{values: make(map[string]memoryVersion)}
}

func memoryToken(value []byte) Token {
	return sha256.Sum256(value)
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
	v, ok := m.values[name]
	if !ok {
		return ReadResult{}, ErrNotFound
	}
	return ReadResult{Bytes: append([]byte(nil), v.bytes...), Token: v.token}, nil
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
	if _, ok := m.values[name]; ok {
		return ErrConflict
	}
	m.commit(name, value)
	return nil
}

func (m *Memory) ReplaceIfVersion(ctx context.Context, name string, expected Token, value []byte) error {
	if err := ctx.Err(); err != nil {
		return denied(err)
	}
	if !ValidName(name) || !validValue(value) || expected.Zero() {
		return denied(nil)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return denied(nil)
	}
	cur, ok := m.values[name]
	if !ok || cur.token != expected {
		return ErrConflict
	}
	m.commit(name, value)
	return nil
}

func (m *Memory) List(context.Context) ([]string, error) { return nil, ErrUnsupported }

// Close discards in-memory state; it is idempotent.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.values = make(map[string]memoryVersion)
	return nil
}

func (m *Memory) commit(name string, value []byte) {
	b := append([]byte(nil), value...)
	m.values[name] = memoryVersion{bytes: b, token: memoryToken(b)}
}

func denied(cause error) error {
	if cause == nil {
		return ErrDenied
	}
	return fmt.Errorf("%w: %w", ErrDenied, cause)
}
