// Package vaultfilebackend defines the versioned file backend contract used by
// the vault-file protocol (#104/#106) and provides an in-memory implementation.
//
// The contract is deliberately small. A backend stores opaque encrypted bytes
// under caller-chosen names and guards every write with an opaque version
// token:
//
//   - Read returns the bytes and the token of the exact same committed version.
//   - CreateIfAbsent commits bytes only when the name has no committed version.
//     Callers pass the zero Token. An empty value is still a committed version.
//   - ReplaceIfVersion commits bytes only when the name's current token equals
//     expected. Replacing with a token that still matches current (a
//     "same-token replace") is how callers retry a write whose outcome was
//     unknown: at most one write per token can commit.
//
// Every mutating call is linearizable: of any set of concurrent writes to one
// name (equal or different tokens, same or different processes for on-disk
// drivers), at most one is committed, and exactly one wins whenever the caller
// preconditions are true at some serialization point.
//
// List and history are not part of the contract; drivers return ErrUnsupported.
package vaultfilebackend

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors classify every failure. Callers test them with errors.Is;
// drivers may wrap them only to add context.
var (
	// ErrNotFound reports that no committed version exists for the name.
	// CreateIfAbsent never returns it as a final result: it commits instead.
	ErrNotFound = errors.New("vault file backend: not found")
	// ErrConflict reports that the caller's expected token does not match the
	// current committed version. The stored version is unchanged. It is also
	// returned by timeouts discovered before publication; see ErrUnknown.
	ErrConflict = errors.New("vault file backend: version conflict")
	// ErrDenied reports that the operation is refused by policy: a malformed
	// argument, a name or path that would escape the configured root, a
	// symlinked or non-regular lock or data file, a non-private permission, or
	// a caller-visible cancellation. Nothing was written.
	ErrDenied = errors.New("vault file backend: denied")
	// ErrUnsupported reports that this backend or this operation cannot run on
	// the current platform, configuration or filesystem (for example List, or
	// a platform without a local directory driver). Nothing was written.
	ErrUnsupported = errors.New("vault file backend: unsupported")
	// ErrUnknown reports that a mutating call may or may not have committed:
	// the durable publication step started but its outcome could not be
	// confirmed (I/O error, or cancellation/timeout during publication). The
	// stored version is intact either way; callers resolve it with Read and
	// retry with the observed token. CreateIfAbsent never returns ErrUnknown
	// after a successful link-based publication step.
	ErrUnknown = errors.New("vault file backend: outcome unknown")
	// ErrCorrupt reports that stored state exists but cannot be trusted: a
	// malformed token, a truncated or tampered record, or a body whose bytes do
	// not match the recorded digest. Callers must not overwrite it by guess.
	ErrCorrupt = errors.New("vault file backend: corrupt state")
)

// Limits shared by all drivers and the Memory backend.
const (
	// MaxValueSize is the largest value a backend accepts.
	MaxValueSize = 16 << 20
	// MaxNameSize bounds a name in bytes; names are opaque to the backend
	// except for the validation rules documented on Backend.
	MaxNameSize = 255
	// DefaultLockTimeout is the default upper bound for waiting on a writer.
	DefaultLockTimeout = 10 * time.Second
)

// Token denotes the committed version of bytes returned by Read and expected
// by ReplaceIfVersion. The zero Token means "no version": it is the expected
// token for CreateIfAbsent and can never identify a committed version, so Read
// never returns it and ReplaceIfVersion with the zero token always fails
// ErrConflict.
//
// Drivers derive a Token from the stored bytes and not from the name, path,
// timestamp or lock state, so reading the same version after a restart, on
// another store rooted at the same directory, or via a copy of the data yields
// the same Token. Tokens are not secrets: they are not authenticated by the
// backend, the caller's encryption layer must authenticate its own content.
type Token [32]byte

// Zero reports whether t is the zero Token.
func (t Token) Zero() bool {
	return t == Token{}
}

// ReadResult is the atomically consistent output of Read: Bytes and Token
// describe the same committed version.
type ReadResult struct {
	Bytes []byte
	Token Token
}

// Backend is the vault-file backend contract. All methods are safe for
// concurrent use by multiple goroutines inside one process. On-disk drivers
// are also safe across processes sharing the same local directory on one
// machine; see the driver documentation for the limits.
//
// ctx cancellation: drivers honour it before doing any work, while waiting on
// writers, and while reading data. A cancelled call returns ErrDenied (when
// nothing was published; the original context error stays discoverable via
// context.Cause) or ErrUnknown (when cancellation raced publication and the
// outcome cannot be determined). ErrConflict and ErrUnknown are distinct:
// ErrConflict means the write definitely did not commit because the caller's
// precondition was false at publication time.
type Backend interface {
	// Read returns the committed bytes and the token of the same version.
	// Missing name: ErrNotFound. Malformed stored state: ErrCorrupt.
	Read(ctx context.Context, name string) (ReadResult, error)

	// CreateIfAbsent commits value when name has no committed version.
	// Existing name, valid or corrupt: ErrConflict.
	CreateIfAbsent(ctx context.Context, name string, value []byte) error

	// ReplaceIfVersion commits value when the current token is expected. A
	// missing name or a different token is ErrConflict.
	ReplaceIfVersion(ctx context.Context, name string, expected Token, value []byte) error

	// List returns the names of committed versions. Optional: ErrUnsupported.
	List(ctx context.Context) ([]string, error)

	// Close releases resources. Calls after Close return ErrDenied. Close is
	// idempotent and does not remove stored data.
	Close() error
}
