// Package vaultfilepublish coordinates publishing and pulling encrypted
// vault files through a vaultfilebackend-compatible backend.
//
// This package provides the validated pull capability and, on top of it and
// the vaultfilejournal, the I/O-only prepare/CAS/reconcile/Ack coordinator for
// one file (see coordinator.go). It does no wire parsing, cryptography, policy
// authorization (for example KDBX or unlock-policy checks), KDBX validation,
// parent-digest or content-signature checks, or merge logic. It never parses
// or accepts an uploaded proposal roster. Those steps stay with the caller, and
// the coordinator claims no cryptographic closure of its own: the required
// ProposalVerifier bound by NewCoordinator and the per-call PullVerifier are
// the only trust decisions it relies on.
//
// No success is ever inferred from a write response. Every backend write is
// followed by one verified readback, and only a readback that is exactly the
// prepared proposal (and that the caller's ProposalVerifier, called with the
// operation's original base R, still accepts) is acknowledged in the journal.
//
// # Caller-validated pull
//
// ReadPulled reads one name from a ReadBackend and requires a PullVerifier.
// The verifier receives an independent copy of the exact bytes together with
// the exact opaque revision and must decide whether they are acceptable. It is
// the caller's hook for checking the result against the trust the caller has
// already pinned out of band: a cached checkpoint, a stored revision, a file
// digest, or any other external anchor. The package never decides trust on its
// own and never interprets the revision; it only hands both back verbatim.
//
// A Pulled value can only be produced by ReadPulled. Its byte and revision
// fields are private, there is no constructor or literal that bypasses
// verification, and its accessors return copies so neither the caller nor the
// verifier can mutate the state that was verified.
package vaultfilepublish

import (
	"context"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	// MaxPulledBytes is the largest byte sequence ReadPulled accepts. It matches
	// the backend value limit; a larger result is rejected as malformed.
	MaxPulledBytes = vaultfilebackend.MaxValueSize
	// MaxPulledRevisionSize is the largest opaque revision ReadPulled accepts,
	// in bytes. It matches the backend revision limit.
	MaxPulledRevisionSize = vaultfilebackend.MaxRevisionSize
)

var (
	// ErrInvalidArgument reports that ReadPulled was called with a nil context,
	// a nil backend or verifier, or an empty name. No read was performed.
	ErrInvalidArgument = errors.New("vault file publish: invalid argument")
	// ErrBackendResult reports that the backend returned a result outside the
	// contract: empty or oversize bytes, or an empty or oversize revision. The
	// verifier is not called and no Pulled value is returned.
	ErrBackendResult = errors.New("vault file publish: invalid backend result")
	// ErrVerification reports that a caller-supplied verifier rejected: the
	// PullVerifier rejected a pull, or the ProposalVerifier rejected a
	// prepared proposal. Its error remains discoverable through errors.Is and
	// errors.As.
	ErrVerification = errors.New("vault file publish: verification failed")
)

// ReadBackend is the narrow read surface ReadPulled needs. It matches one
// method of vaultfilebackend.Backend so any backend can be adapted with a
// thin wrapper or embedding, but implementers need to provide nothing else.
//
// Read must return the bytes and revision of the exact same committed version,
// as documented by vaultfilebackend.Backend. ReadPulled treats both as
// untrusted and validates them.
type ReadBackend interface {
	Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error)
}

// PullVerifier decides whether a pulled version is acceptable. It is required:
// ReadPulled refuses to run without one.
//
// The verifier receives the exact bytes returned by the backend and the exact
// opaque revision, the same pair that would be retained by a successful
// Pulled. The byte slice is a private copy: the verifier may keep or modify it
// and it cannot affect the bytes retained by Pulled. The verifier must return
// nil to accept; any error rejects the pull and is returned wrapped in
// ErrVerification.
//
// Faithful callers verify the bytes against their external pinned trust, such
// as a checkpoint or revision recorded on a previous trusted run, rather than
// merely echoing the revision they were given.
type PullVerifier func(ctx context.Context, data []byte, revision vaultfilebackend.Revision) error

// Pulled is a backend result that passed both contract validation and the
// caller's PullVerifier. The zero value is invalid and no Pulled exists unless
// it was returned by ReadPulled; there is no other constructor.
type Pulled struct {
	data     []byte
	revision vaultfilebackend.Revision
}

// Bytes returns a deep copy of the verified bytes. Mutating the result does not
// affect the Pulled value.
func (p Pulled) Bytes() []byte {
	return append([]byte(nil), p.data...)
}

// Revision returns the exact opaque revision token that was verified,
// byte-for-byte (for example a quoted ETag). It must be passed back verbatim
// when the caller later replace-writes this name.
func (p Pulled) Revision() vaultfilebackend.Revision {
	return p.revision
}

// ReadPulled reads name from backend, validates the result against the
// contract and requires verifier to accept the exact bytes and revision before
// returning a Pulled value.
//
// ReadPulled returns:
//   - ErrInvalidArgument, without reading, when ctx, backend or verifier is
//     nil or name is empty;
//   - a backend read error unchanged (errors.Is still matches it);
//   - ErrBackendResult when the result has empty or oversize bytes, or an
//     empty or oversize revision, without calling the verifier;
//   - ErrVerification wrapping the verifier error when verification fails.
//
// ReadPulled does not parse the bytes, check cryptography, authorize policy or
// validate KDBX content: verification is entirely the verifier's job.
func ReadPulled(ctx context.Context, backend ReadBackend, name string, verifier PullVerifier) (Pulled, error) {
	if ctx == nil {
		return Pulled{}, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if backend == nil {
		return Pulled{}, fmt.Errorf("%w: nil backend", ErrInvalidArgument)
	}
	if verifier == nil {
		return Pulled{}, fmt.Errorf("%w: nil verifier", ErrInvalidArgument)
	}
	if name == "" {
		return Pulled{}, fmt.Errorf("%w: empty name", ErrInvalidArgument)
	}

	result, err := backend.Read(ctx, name)
	if err != nil {
		return Pulled{}, fmt.Errorf("vault file publish: read %q: %w", name, err)
	}
	if len(result.Bytes) == 0 || len(result.Bytes) > MaxPulledBytes {
		return Pulled{}, fmt.Errorf("%w: %q: byte length %d outside (0, %d]", ErrBackendResult, name, len(result.Bytes), MaxPulledBytes)
	}
	if result.Revision == "" || len(result.Revision) > MaxPulledRevisionSize {
		return Pulled{}, fmt.Errorf("%w: %q: revision length %d outside (0, %d]", ErrBackendResult, name, len(result.Revision), MaxPulledRevisionSize)
	}

	// The verifier and the retained value each get their own copy, so neither
	// can mutate the other or the backend's returned slice.
	verified := append([]byte(nil), result.Bytes...)
	if err := verifier(ctx, append([]byte(nil), result.Bytes...), result.Revision); err != nil {
		return Pulled{}, fmt.Errorf("%w: %q: %w", ErrVerification, name, err)
	}
	return Pulled{data: verified, revision: result.Revision}, nil
}
