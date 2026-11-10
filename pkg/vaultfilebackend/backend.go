// Package vaultfilebackend defines the versioned file backend contract used by
// the vault-file protocol (#104/#106) and provides an in-memory implementation.
//
// The contract is deliberately small. A backend stores opaque encrypted bytes
// under caller-chosen names and guards every write with an opaque Revision:
//
//   - Read returns the bytes and the revision of the exact same committed
//     version.
//   - CreateIfAbsent commits bytes only when the name has no committed version.
//     An empty value is rejected with ErrDenied.
//   - ReplaceIfVersion commits bytes only when the name's current revision
//     equals expected. The zero Revision is malformed and rejected with
//     ErrDenied; any other non-matching revision is ErrConflict.
//
// Every mutating call is linearizable: of any set of concurrent writes to one
// name (equal or different revisions, same or different processes for on-disk
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
	// ErrConflict reports that no committed version exists for the name or that
	// the caller's expected revision (non-zero) does not match the current
	// committed version. The stored version is unchanged. It is also returned
	// by timeouts discovered before publication; see ErrUnknown.
	ErrConflict = errors.New("vault file backend: version conflict")
	// ErrDenied reports that the operation is refused by policy: a malformed
	// argument (bad name, empty or oversize value, zero or oversize expected
	// revision), a closed backend, a name or path that would escape the configured root, a
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
	// retry with the observed revision. CreateIfAbsent never returns ErrUnknown
	// after a successful link-based publication step.
	ErrUnknown = errors.New("vault file backend: outcome unknown")
	// ErrCorrupt reports that stored state exists but cannot be trusted: a
	// malformed or zero stored revision, a truncated or tampered record, or a body whose bytes do
	// not match the recorded digest. Callers must not overwrite it by guess.
	ErrCorrupt = errors.New("vault file backend: corrupt state")
)

// Limits shared by all drivers and the Memory backend.
const (
	// MaxValueSize is the largest value a backend accepts: the complete file,
	// including any caller-side framing or envelope headers around the
	// ciphertext. Callers that keep separate budgets (for example 16 MiB of
	// decrypted content) must enforce them on their side.
	MaxValueSize = 32 << 20
	// MaxNameSize bounds a name in bytes; names are opaque to the backend
	// except for the validation rules documented on Backend.
	MaxNameSize = 255
	// MaxRevisionSize bounds a Revision in bytes so that every driver can
	// carry it (for example as a quoted ETag header or a store item field).
	MaxRevisionSize = 1024
	// DefaultLockTimeout is the default upper bound for waiting on a writer.
	DefaultLockTimeout = 10 * time.Second
)

// Revision denotes the committed version of bytes returned by Read and
// expected by ReplaceIfVersion. It is an opaque, bounded string: the backend
// never interprets it and hands it back byte-for-byte, so it can carry a
// provider version such as an S3, Graph or HTTP ETag verbatim (including any
// quotes) or a store-specific version identifier.
//
// Revisions are not derived from the bytes: they are not content digests,
// they are not required to match across backends or across stores, and equal
// bytes written twice may get different revisions. Callers that need a
// content digest compute it themselves from the returned bytes.
//
// The zero Revision means "no version": it is the expected revision for
// CreateIfAbsent and can never identify a committed version. A driver must
// reject it as malformed (ErrDenied) wherever a committed revision is
// expected and never return it from Read. Revisions longer than
// MaxRevisionSize are malformed too. Revisions are not secrets: the backend
// does not authenticate them, the caller's encryption layer must
// authenticate its own content.
type Revision string

// Zero reports whether r is the zero Revision.
func (r Revision) Zero() bool { return r == "" }

// ReadResult is the atomically consistent output of Read: Bytes and Revision
// describe the same committed version.
type ReadResult struct {
	Bytes    []byte
	Revision Revision
}

// Backend is the vault-file backend contract. All methods are safe for
// concurrent use by multiple goroutines inside one process. On-disk drivers
// are also safe across processes sharing the same local directory on one
// machine; see the driver documentation for the limits.
//
// ctx cancellation: drivers honour it before doing any work, and again after
// acquiring any internal lock and after copying the stored bytes for the
// result, so a call that loses a cancellation race returns ErrDenied and
// writes nothing. Waiting for a lock is cancellable. A cancelled call returns
// ErrDenied when nothing was published (the original context error stays
// discoverable via context.Cause) or ErrUnknown when cancellation raced
// publication and the outcome cannot be determined. ErrConflict and
// ErrUnknown are distinct: ErrConflict means the write definitely did not
// commit because the caller's precondition was false at publication time.
//
// Values: an empty value is rejected with ErrDenied by every mutating call.
// A value larger than MaxValueSize is rejected with ErrDenied.
// After Close every method returns ErrDenied.
type Backend interface {
	// Read returns the committed bytes and the revision of the same version.
	// Missing name: ErrNotFound. Malformed stored state: ErrCorrupt.
	Read(ctx context.Context, name string) (ReadResult, error)

	// CreateIfAbsent commits value when name has no committed version.
	// Existing name, valid or corrupt: ErrConflict.
	CreateIfAbsent(ctx context.Context, name string, value []byte) error

	// ReplaceIfVersion commits value when the current revision is expected. A
	// missing name or a different revision is ErrConflict. A zero or
	// oversize expected revision is malformed: ErrDenied.
	ReplaceIfVersion(ctx context.Context, name string, expected Revision, value []byte) error

	// List returns the names of committed versions. Optional: ErrUnsupported.
	List(ctx context.Context) ([]string, error)

	// Close releases resources. Calls after Close, including List, return
	// ErrDenied. Close is idempotent and does not remove stored data.
	Close() error
}
