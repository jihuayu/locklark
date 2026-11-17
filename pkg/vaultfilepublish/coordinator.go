package vaultfilepublish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

// This file adds the second checkpoint: a one-file, I/O-only prepare, CAS and
// reconcile coordinator on top of the validated pull capability and the
// durable journal (state, prepared proposal and Ack).
//
// It is deliberately not a state machine with crypto. It never parses an
// uploaded proposal, checks a signature, evaluates unlock policy, compares
// content or parent digests, opens a KDBX database or merges files. It only
// moves opaque bytes between three places: the backend, the caller's pulled
// value and the journal. The proposal verifier bound by NewCoordinator and the
// per-call pull verifier are the only trust decisions, and both belong to the
// caller.
//
// # Sequence
//
// PrepareAndPublish verifies the inputs against the stored local state, calls
// the ProposalVerifier, durably records the exact proposal with Journal.Prepare
// and then performs exactly one ReplaceIfVersion against the base revision.
// ResumePrepared picks up that durable record after a restart: it either acks a
// current version that is exactly the prepared proposal, retries the same
// operation against the unchanged original base, or reports ErrUnknownReview.
// Neither call retries on its own, re-signs, or infers success from the write
// response: every write result is followed by one verified readback, and only
// that readback can lead to Journal.Ack.

var (
	// ErrStaleBase reports that an input does not match the stored local state:
	// a prepared value or started base that is not the journal's exact base
	// bytes and revision, a proposal built for another revision or for other
	// bytes, or a resume whose current version is neither the prepared proposal
	// nor the original base. Nothing was written. In PrepareAndPublish no
	// Prepare and no CAS happened; in ResumePrepared no CAS and no Ack happened
	// and the prepared record is preserved.
	ErrStaleBase = errors.New("vault file publish: stale base")
	// ErrUnknownReview reports a remote outcome that the readback could not
	// resolve to either the exact prepared proposal or the unchanged original
	// base: a different successor, an unverifiable readback, an exact repeat of
	// the original base after a definite conflict, or an exact repeat of the
	// original base after a nilled write whose outcome cannot be known. Nothing
	// was acknowledged and the prepared record is preserved. The caller must
	// review the outcome out of band; the coordinator never overwrites it.
	ErrUnknownReview = errors.New("vault file publish: remote outcome needs review")
	// ErrUnknownWrite reports a ReplaceIfVersion whose outcome is indeed unknown
	// and whose verified readback reports the original base revision again with
	// exactly the original base bytes: the stored version is still R. Nothing
	// was acknowledged and the prepared record is preserved, so a later
	// ResumePrepared may retry the same operation. It matches
	// vaultfilebackend.ErrUnknown.
	ErrUnknownWrite = errors.New("vault file publish: remote write outcome unknown")
	// ErrConflict reports a ReplaceIfVersion that definitely did not commit
	// (ErrConflict) and a readback that is not the prepared proposal. The
	// conflict is definite, the prepared record is preserved, and the caller
	// must decide whether to reconcile it. It matches
	// vaultfilebackend.ErrConflict.
	ErrConflict = errors.New("vault file publish: remote version conflict")
)

// ConditionalBackend is the narrow backend surface the coordinator needs: one
// read and one preconditioned replace. It matches ReadBackend plus one method
// of vaultfilebackend.Backend. Create, list and close are not needed and the
// coordinator never creates a name.
type ConditionalBackend interface {
	ReadBackend
	// ReplaceIfVersion must have vaultfilebackend.Backend.ReplaceIfVersion
	// semantics: it commits value only when the current revision equals
	// expected, returns ErrConflict when it definitely did not commit, and
	// ErrUnknown when it may or may not have committed.
	ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error
}

// ProposalVerifier decides whether a prepared proposal is trustworthy. It is
// required: NewCoordinator refuses to build a coordinator without one, and it
// is the only proposal verifier the coordinator ever calls.
//
// It is called with independent copies of the base bytes, the opaque revision
// those bytes were read at, and the exact journal.Proposal (the operation ID,
// the expected revision and the sealed proposal bytes). Its contract is to
// authenticate both the base and the candidate against the caller's external
// pin and to verify that the candidate is authorized and directly based on
// exactly the expected revision R. The revision is only the opaque one the
// base bytes were read at, not an authenticated reading of the proposal, so
// "directly based on R" is a claim the verifier itself must establish. The
// coordinator cannot check any of that itself; it checks only that opaque
// slices and revisions agree internally.
//
// The base is always R, the operation's original state base: the snapshot of
// State.BaseBytes and State.RemoteRevision loaded when the operation began
// (for PrepareAndPublish) or stored when the proposal was prepared (for
// ResumePrepared). It is never the proposal itself and never changes while the
// proposal is in flight, even if the local working file is edited. The
// proposal passed with it always has ExpectedRevision == R.
//
// It is called before Journal.Prepare, before every CAS write (the first one
// and any retry), and before every Journal.Ack, whether that Ack follows a
// readback in reconcile or a resume of an already applied proposal. The
// verifier must return nil to accept; any error rejects and is returned wrapped
// in ErrVerification.
type ProposalVerifier func(ctx context.Context, base []byte, baseRevision vaultfilebackend.Revision, proposal vaultfilejournal.Proposal) error

// Coordinator performs the prepare, CAS and reconcile sequence for one file
// name. It is not safe for concurrent use: a caller must serialize calls to
// PrepareAndPublish and ResumePrepared so that at most one operation is in
// flight for the name.
type Coordinator struct {
	backend  ConditionalBackend
	journal  *vaultfilejournal.Journal
	name     string
	verifier ProposalVerifier
}

// NewCoordinator returns a coordinator for name. backend must implement
// ConditionalBackend and journal must already be open. name must be a valid
// backend name (the validation rule implemented by vaultfilebackend.ValidName).
// verifier is required and may not be nil; it is the only proposal verifier
// PrepareAndPublish and ResumePrepared use. A nil backend or journal, an
// invalid name or a nil verifier is ErrInvalidArgument; nothing is read or
// mutated.
//
// NewCoordinator performs no I/O and claims no crypto: it holds the caller's
// verifier but never implements one.
func NewCoordinator(backend ConditionalBackend, journal *vaultfilejournal.Journal, name string, verifier ProposalVerifier) (*Coordinator, error) {
	if isNilInterface(backend) {
		return nil, fmt.Errorf("%w: nil backend", ErrInvalidArgument)
	}
	if isNilInterface(journal) {
		return nil, fmt.Errorf("%w: nil journal", ErrInvalidArgument)
	}
	if !vaultfilebackend.ValidName(name) {
		return nil, fmt.Errorf("%w: invalid backend name", ErrInvalidArgument)
	}
	if verifier == nil {
		return nil, fmt.Errorf("%w: nil proposal verifier", ErrInvalidArgument)
	}
	return &Coordinator{backend: backend, journal: journal, name: name, verifier: verifier}, nil
}

// isNilInterface reports whether v is nil or holds a nil pointer, so a typed
// nil cannot sneak past the constructor.
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

// equalBytes compares two byte slices by content.
func equalBytes(a, b []byte) bool {
	return bytes.Equal(a, b)
}

// loadState loads the current local state.
func (c *Coordinator) loadState() (vaultfilejournal.State, error) {
	s, err := c.journal.LoadState()
	if err != nil {
		return vaultfilejournal.State{}, fmt.Errorf("vault file publish: load local state: %w", err)
	}
	return s, nil
}

// loadBaseState loads the local state and requires pulledBase to be exactly its
// base bytes and revision. The returned state is the caller's private
// snapshot of the operation's base R: the journal returns deep copies, so
// later local writes cannot change it.
func (c *Coordinator) loadBaseState(pulledBase Pulled) (vaultfilejournal.State, error) {
	if len(pulledBase.data) == 0 || pulledBase.revision == "" {
		return vaultfilejournal.State{}, fmt.Errorf("%w: no pulled base", ErrInvalidArgument)
	}
	s, err := c.loadState()
	if err != nil {
		return vaultfilejournal.State{}, err
	}
	if len(s.BaseBytes) == 0 ||
		s.RemoteRevision != pulledBase.revision ||
		!equalBytes(s.BaseBytes, pulledBase.data) {
		return vaultfilejournal.State{}, fmt.Errorf("%w: pulled base is not the stored base", ErrStaleBase)
	}
	return s, nil
}

// verifyProposal runs the coordinator's bound proposal verifier on R, the
// original base snapshot, and the exact proposal, so neither the coordinator
// nor the caller can observe the verifier's mutations.
func (c *Coordinator) verifyProposal(ctx context.Context, base vaultfilejournal.State, p vaultfilejournal.Proposal) error {
	check := cloneProposal(p)
	if err := c.verifier(ctx, bytes.Clone(base.BaseBytes), base.RemoteRevision, check); err != nil {
		return fmt.Errorf("%w: %q: %w", ErrVerification, c.name, err)
	}
	return nil
}

// cloneProposal returns a Proposal that shares no memory with p.
func cloneProposal(p vaultfilejournal.Proposal) vaultfilejournal.Proposal {
	return vaultfilejournal.Proposal{
		Generation:       p.Generation,
		OperationID:      string(bytes.Clone([]byte(p.OperationID))),
		ExpectedRevision: vaultfilebackend.Revision(bytes.Clone([]byte(p.ExpectedRevision))),
		Bytes:            bytes.Clone(p.Bytes),
	}
}

// PrepareAndPublish verifies pulledBase and proposal against the journal,
// durably prepares the exact proposal and performs exactly one CAS write,
// followed by one readback.
//
// It accepts only a Pulled produced by ReadPulled. It requires:
//
//   - pulledBase.Bytes() and pulledBase.Revision() to equal the journal's
//     State.BaseBytes and State.RemoteRevision exactly;
//   - proposal.ExpectedRevision to equal that base revision exactly;
//   - proposal.Bytes to equal the journal's State.WorkingBytes exactly;
//   - the NewCoordinator proposal verifier to accept the base R and the
//     proposal (see ProposalVerifier);
//   - pullVerifier to be non-nil: it is mandatory for the readback.
//
// It then calls Journal.Prepare with the loaded local generation, so the
// durable prepared record exists before any backend write, and calls
// ReplaceIfVersion exactly once with the opaque base revision and a copy of the
// exact proposal bytes. The journal's legacy proposal record is never read or
// written. The write response alone is never treated as success: the result is
// always resolved by one readback through ReadPulled and pullVerifier (see
// reconcile).
//
// Validation failures happen before the write and perform no CAS:
// ErrInvalidArgument, ErrStaleBase (the inputs disagree with the stored state),
// ErrVerification (the proposal verifier rejected), or a journal error from
// Prepare, which leaves any prepared record exactly as it was.
//
// The return value follows the rules documented on reconcile. This call does
// no parsing, crypto, policy, KDBX or merge work.
func (c *Coordinator) PrepareAndPublish(ctx context.Context, pulledBase Pulled, proposal vaultfilejournal.Proposal, pullVerifier PullVerifier) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if pullVerifier == nil {
		return fmt.Errorf("%w: nil pull verifier", ErrInvalidArgument)
	}

	base, err := c.loadBaseState(pulledBase)
	if err != nil {
		return err
	}
	if proposal.ExpectedRevision != base.RemoteRevision {
		return fmt.Errorf("%w: proposal expected revision is not the base revision", ErrStaleBase)
	}
	if len(proposal.Bytes) == 0 || !equalBytes(proposal.Bytes, base.WorkingBytes) {
		return fmt.Errorf("%w: proposal bytes are not the local working bytes", ErrStaleBase)
	}
	if err := c.verifyProposal(ctx, base, proposal); err != nil {
		return err
	}
	// Prepare re-checks the generation, revision and bytes against the stored
	// state in its own transaction.
	if err := c.journal.Prepare(base.Generation, proposal); err != nil {
		return fmt.Errorf("vault file publish: prepare: %w", err)
	}

	pp := vaultfilejournal.PreparedProposal{WorkingGeneration: base.Generation, Proposal: cloneProposal(proposal)}
	writeErr := c.backend.ReplaceIfVersion(ctx, c.name, pp.Proposal.ExpectedRevision, bytes.Clone(pp.Proposal.Bytes))
	return c.reconcile(ctx, base, pp, writeErr, pullVerifier)
}

// ResumePrepared continues the durably prepared proposal after a restart.
// It loads the prepared proposal and the original base state and requires the
// prepared proposal's ExpectedRevision to be that stored base revision,
// WorkingGeneration not to be greater than the state Generation, and, when the
// generations are equal, the state WorkingBytes to equal the proposal bytes; an
// inconsistent record is ErrStaleBase before anything is written or
// acknowledged. currentPulled (obtained from ReadPulled) must then be either:
//
//   - byte-for-byte the prepared proposal: it is revalidated with the
//     ProposalVerifier against the original base R and acknowledged with its
//     pulled revision; no write happens, and a nil return means the prepared
//     state is resolved;
//   - byte-for-byte the original State.BaseBytes with exactly the original
//     State.RemoteRevision: the same operation is retried with at most one
//     ReplaceIfVersion using the same operation ID, proposal bytes and
//     expected revision, followed by one readback.
//
// Any other successor is ErrUnknownReview: nothing is written and the prepared
// record is preserved.
//
// Missing prepared or state records, or local records that fail validation,
// are returned as the journal error and nothing is written. A ProposalVerifier
// rejection before a retry or an Ack is ErrVerification. A retry and the
// following readback follow the same reconcile rules as PrepareAndPublish and
// use the same original base R, whatever edits landed locally since it was
// prepared.
func (c *Coordinator) ResumePrepared(ctx context.Context, currentPulled Pulled, pullVerifier PullVerifier) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if pullVerifier == nil {
		return fmt.Errorf("%w: nil pull verifier", ErrInvalidArgument)
	}
	if len(currentPulled.data) == 0 || currentPulled.revision == "" {
		return fmt.Errorf("%w: no current pulled value", ErrInvalidArgument)
	}

	pp, err := c.journal.LoadPrepared()
	if err != nil {
		return fmt.Errorf("vault file publish: load prepared: %w", err)
	}
	base, err := c.loadState()
	if err != nil {
		return err
	}
	if len(base.BaseBytes) == 0 || pp.Proposal.ExpectedRevision != base.RemoteRevision {
		return fmt.Errorf("%w: prepared proposal expected revision is not the stored base revision", ErrStaleBase)
	}
	// These are the cross-record conditions Journal.Ack re-checks in its own
	// transaction. Reject them before any verifier, CAS or Ack so a resume
	// cannot write a proposal that Ack would then refuse to acknowledge.
	if pp.WorkingGeneration > base.Generation {
		return fmt.Errorf("%w: prepared generation %d is newer than state generation %d", ErrStaleBase, pp.WorkingGeneration, base.Generation)
	}
	if pp.WorkingGeneration == base.Generation && !equalBytes(base.WorkingBytes, pp.Proposal.Bytes) {
		return fmt.Errorf("%w: state working bytes do not match the prepared proposal", ErrStaleBase)
	}

	switch {
	case equalBytes(currentPulled.data, pp.Proposal.Bytes):
		// The remote already holds the prepared proposal. Revalidate it
		// against R, then record the exact revision it was read at.
		if err := c.verifyProposal(ctx, base, pp.Proposal); err != nil {
			return err
		}
		return c.ack(pp, currentPulled.revision)
	case equalBytes(currentPulled.data, base.BaseBytes) && currentPulled.revision == base.RemoteRevision:
		// The remote is still exactly the original R. Retry the very same
		// operation, never a newly built one.
		if err := c.verifyProposal(ctx, base, pp.Proposal); err != nil {
			return err
		}
		writeErr := c.backend.ReplaceIfVersion(ctx, c.name, pp.Proposal.ExpectedRevision, bytes.Clone(pp.Proposal.Bytes))
		return c.reconcile(ctx, base, pp, writeErr, pullVerifier)
	}
	return fmt.Errorf("%w: %q: current version is neither the prepared proposal nor the original base", ErrUnknownReview, c.name)
}

// reconcile resolves a CAS result with exactly one verified readback.
//
// base is R, the original base snapshot the operation began from; every
// proposal verifier call and every original-base comparison uses it, never the
// journal's current state, so local working edits cannot change it. pp is the
// exact prepared (and written) proposal.
//
// A nil result is never trusted on its own and a definite error other than
// ErrConflict or ErrUnknown propagates unchanged (the backend error stays
// discoverable); the readback happens either way, because a backend may commit
// and then report a failure, and nothing is ever acknowledged from the write
// result alone. The prepared record is preserved unless the Ack succeeds.
//
// For a nil, ErrUnknown or ErrConflict result the readback goes through
// ReadPulled with pullVerifier. A read failure is returned together with the
// write result (nothing is acknowledged). Otherwise:
//
//   - readback bytes equal to the prepared proposal and a valid revision are
//     revalidated with the proposal verifier against R and then acknowledged
//     with the readback revision (Ack keeps a newer working generation, so a
//     local edit made during the write survives). Nothing is acknowledged if
//     the verifier rejects the readback or the Ack fails;
//   - an exact original base after ErrUnknown returns ErrUnknownWrite, which
//     matches vaultfilebackend.ErrUnknown, so a later ResumePrepared can retry
//     the same operation;
//   - an exact original base after ErrConflict returns ErrConflict, the
//     definite conflict;
//   - an exact original base after a nil write returns ErrUnknownReview: the
//     stored version did not advance, so success must not be inferred from the
//     write response;
//   - any other readback returns ErrUnknownReview.
//
// Whenever reconciliation does not verify and Ack the exact proposal, an
// ErrUnknown write result is never lost: the specific outcome error (the
// readback error, ErrVerification, the Ack error or ErrUnknownReview) is
// returned wrapped around writeErr, so errors.Is finds both that specific
// error and vaultfilebackend.ErrUnknown. Only a successful Ack returns nil.
//
// In every case the prepared record is preserved unless the Ack succeeded.
func (c *Coordinator) reconcile(ctx context.Context, base vaultfilejournal.State, pp vaultfilejournal.PreparedProposal, writeErr error, pullVerifier PullVerifier) error {
	if writeErr != nil &&
		!errors.Is(writeErr, vaultfilebackend.ErrUnknown) &&
		!errors.Is(writeErr, vaultfilebackend.ErrConflict) {
		// Definite failure. Still look once, because a backend may commit and
		// then fail its response; only an exact readback of the proposal
		// acknowledges, and anything else reports the definite error.
		current, readErr := ReadPulled(ctx, c.backend, c.name, pullVerifier)
		if readErr == nil && equalBytes(current.data, pp.Proposal.Bytes) {
			if err := c.verifyProposal(ctx, base, pp.Proposal); err != nil {
				return err
			}
			return c.ack(pp, current.revision)
		}
		return writeErr
	}

	current, readErr := ReadPulled(ctx, c.backend, c.name, pullVerifier)
	if readErr != nil {
		// Nothing was acknowledged. An ErrUnknown write is otherwise
		// unobservable, so keep it discoverable next to the readback error.
		return c.unknownWrite(writeErr, readErr)
	}
	if equalBytes(current.data, pp.Proposal.Bytes) {
		if err := c.verifyProposal(ctx, base, pp.Proposal); err != nil {
			return c.unknownWrite(writeErr, err)
		}
		return c.unknownWrite(writeErr, c.ack(pp, current.revision))
	}

	conflict := errors.Is(writeErr, vaultfilebackend.ErrConflict)
	unknown := errors.Is(writeErr, vaultfilebackend.ErrUnknown)

	// The readback is the original base only if it is exactly R. A nil
	// writeErr is never enough on its own.
	if current.revision == base.RemoteRevision && equalBytes(current.data, base.BaseBytes) {
		if unknown {
			return c.unknownWrite(writeErr, fmt.Errorf("%w: %q: remote still shows the original base", ErrUnknownWrite, c.name))
		}
		if conflict {
			return c.conflict(writeErr)
		}
		return fmt.Errorf("%w: %q: write reported success but the remote shows the original base", ErrUnknownReview, c.name)
	}
	if !writeErrIsNil(writeErr) && conflict {
		return c.conflict(writeErr)
	}
	if writeErrIsNil(writeErr) {
		// A nil write leading to a different successor proves nothing; only an
		// exact readback of the proposal is a success.
		return fmt.Errorf("%w: %q: write reported success but the remote shows a different version", ErrUnknownReview, c.name)
	}
	return c.unknownWrite(writeErr, fmt.Errorf("%w: %q: remote version is neither the prepared proposal nor the original base", ErrUnknownReview, c.name))
}

// unknownWrite returns outcome, wrapping an ErrUnknown write result so that
// errors.Is still reaches vaultfilebackend.ErrUnknown. A nil outcome is
// returned as is: the proposal was verified and acknowledged. Outcome is the
// specific reconciliation error, never a conflict, so the wrapped write result
// stays just a discoverable cause next to it and is not reclassified.
func (c *Coordinator) unknownWrite(writeErr, outcome error) error {
	if outcome == nil || !errors.Is(writeErr, vaultfilebackend.ErrUnknown) {
		return outcome
	}
	return fmt.Errorf("%q: %w: write outcome unknown: %w", c.name, outcome, writeErr)
}

// writeErrIsNil reports whether the CAS reported no error at all.
func writeErrIsNil(err error) bool { return err == nil }

// conflict returns a definite conflict that still matches
// vaultfilebackend.ErrConflict.
func (c *Coordinator) conflict(writeErr error) error {
	return fmt.Errorf("%w: %w", ErrConflict, writeErr)
}

// ack acknowledges the prepared proposal at the observed readback revision.
func (c *Coordinator) ack(pp vaultfilejournal.PreparedProposal, revision vaultfilebackend.Revision) error {
	if err := c.journal.Ack(pp.Proposal.OperationID, bytes.Clone(pp.Proposal.Bytes), revision); err != nil {
		return fmt.Errorf("vault file publish: ack: %w", err)
	}
	return nil
}
