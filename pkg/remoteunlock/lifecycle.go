package remoteunlock

import (
	"errors"
	"fmt"
	"sync"
)

// Lifecycle statuses of one process-local remote unlock request.
const (
	// StatusRequested is the initial status: the target has been asked to
	// confirm the unlock request.
	StatusRequested = "requested"
	// StatusConfirmed means the target confirmed the request and the
	// requester may proceed to receive.
	StatusConfirmed = "confirmed"
	// StatusReceived means the request outcome was received. It is terminal.
	StatusReceived = "received"
	// StatusUnknown means the outcome could not be determined locally. It is
	// terminal and is never treated as success.
	StatusUnknown = "unknown"
	// StatusCancelled means the request was cancelled before receipt. It is
	// terminal.
	StatusCancelled = "cancelled"
	// StatusExpired means a phase or absolute deadline elapsed before receipt.
	// It is terminal.
	StatusExpired = "expired"
)

// Timing bounds of a lifecycle. All values are milliseconds and all timing is
// evaluated against caller-supplied Unix-millisecond values; the lifecycle
// never reads the system clock.
const (
	// DefaultRequestTTLMS is the default overall request lifetime: two minutes.
	DefaultRequestTTLMS int64 = 120_000
	// MaxActivePhaseMS is the maximum lifetime of each active phase: 30
	// seconds, counted from construction for StatusRequested and from the
	// requested-to-confirmed transition for StatusConfirmed.
	MaxActivePhaseMS int64 = 30_000
)

// Lifecycle errors. They wrap ErrLifecycle and carry static messages that never
// include an identifier, digest, timestamp, or the context.
var (
	// ErrLifecycle is the base of every lifecycle error.
	ErrLifecycle = errors.New("remoteunlock: request lifecycle")
	// ErrLifecycleInvalidTime reports a zero or negative caller-supplied time
	// or a deadline computation that overflows.
	ErrLifecycleInvalidTime = fmt.Errorf("%w: invalid or out-of-range time", ErrLifecycle)
	// ErrLifecycleInvalidContext reports a context that is not a valid
	// canonical binding context or whose deadline has already elapsed.
	ErrLifecycleInvalidContext = fmt.Errorf("%w: invalid binding context", ErrLifecycle)
	// ErrLifecycleTransition reports a transition that the current status does
	// not allow, including any transition out of a terminal status.
	ErrLifecycleTransition = fmt.Errorf("%w: transition not allowed in current status", ErrLifecycle)
)

// DefaultRequestDeadlineUnixMS returns nowUnixMS plus DefaultRequestTTLMS. It
// rejects a non-positive nowUnixMS and any sum that overflows int64.
func DefaultRequestDeadlineUnixMS(nowUnixMS int64) (int64, error) {
	return deadlineAfter(nowUnixMS, DefaultRequestTTLMS)
}

// deadlineAfter returns now+delta, rejecting a non-positive now or overflow.
func deadlineAfter(now, delta int64) (int64, error) {
	if now <= 0 {
		return 0, ErrLifecycleInvalidTime
	}
	at := now + delta
	if at < now {
		return 0, ErrLifecycleInvalidTime
	}
	return at, nil
}

// RequestLifecycle is the in-memory status machine of one remote unlock
// request. It is safe for concurrent use.
//
// It is a state-only primitive. It never verifies identity, signatures or
// policy, never binds a TLS channel or checks a request digest preimage, never
// contacts a relay or cancels anything remotely, and never holds, delivers or
// stores vault unlock key (VUK) bytes. It is not restorable and gives no
// cross-process replay protection: a fresh instance starts in StatusRequested
// and does not recognize any prior request. A caller must issue fresh request
// state and rely on the existing real TLS exporter channel binding to reject
// old channel-bound packets.
type RequestLifecycle struct {
	mu     sync.Mutex
	ctx    ChannelBindingContext
	status string
	// phaseDeadline is the current active phase's deadline; it is only
	// meaningful while status is StatusRequested or StatusConfirmed.
	phaseDeadline int64
}

// NewRequestLifecycle validates ctx through the canonical codec and starts a
// lifecycle in StatusRequested at the explicit nowUnixMS.
//
// The context must be a valid canonical binding context whose deadline is
// strictly after nowUnixMS. It is preserved unchanged: its deadline is never
// clamped, rewritten or extended. nowUnixMS must be positive. The returned
// lifecycle's partial deadlines are min(nowUnixMS+MaxActivePhaseMS,
// ctx.DeadlineUnixMS); they are recomputed after the requested-to-confirmed
// transition.
func NewRequestLifecycle(ctx ChannelBindingContext, nowUnixMS int64) (*RequestLifecycle, error) {
	if nowUnixMS <= 0 {
		return nil, ErrLifecycleInvalidTime
	}
	if err := ctx.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLifecycleInvalidContext, err)
	}
	canonical, err := EncodeChannelBindingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLifecycleInvalidContext, err)
	}
	if _, err := ParseChannelBindingContext(canonical); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLifecycleInvalidContext, err)
	}
	if ctx.DeadlineUnixMS <= nowUnixMS {
		return nil, ErrLifecycleInvalidContext
	}
	phase, err := deadlineAfter(nowUnixMS, MaxActivePhaseMS)
	if err != nil {
		return nil, err
	}
	if ctx.DeadlineUnixMS < phase {
		phase = ctx.DeadlineUnixMS
	}
	return &RequestLifecycle{ctx: ctx, status: StatusRequested, phaseDeadline: phase}, nil
}

// Context returns the binding context exactly as supplied to
// NewRequestLifecycle.
func (l *RequestLifecycle) Context() ChannelBindingContext { return l.ctx }

// StatusAt returns the status at nowUnixMS without changing it. An active
// status whose phase deadline or absolute deadline has elapsed at nowUnixMS
// (nowUnixMS >= deadline) is reported as StatusExpired. A non-positive
// nowUnixMS is rejected and reported as returned status StatusUnknown.
func (l *RequestLifecycle) StatusAt(nowUnixMS int64) (string, error) {
	if nowUnixMS <= 0 {
		return StatusUnknown, ErrLifecycleInvalidTime
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.statusAtLocked(nowUnixMS), nil
}

// Confirm moves a requested lifecycle to confirmed once. It fails when the
// current phase is no longer active, when the status is not requested, or for
// a non-positive nowUnixMS.
func (l *RequestLifecycle) Confirm(nowUnixMS int64) error {
	if nowUnixMS <= 0 {
		return ErrLifecycleInvalidTime
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.statusAtLocked(nowUnixMS) != StatusRequested {
		return ErrLifecycleTransition
	}
	phase, err := deadlineAfter(nowUnixMS, MaxActivePhaseMS)
	if err != nil {
		return err
	}
	if l.ctx.DeadlineUnixMS < phase {
		phase = l.ctx.DeadlineUnixMS
	}
	l.status = StatusConfirmed
	l.phaseDeadline = phase
	return nil
}

// Receive moves a confirmed lifecycle to received, consuming it. It succeeds at
// most once; a second call, or a call when the confirmed phase is no longer
// active, fails. Receipt only records the local state transition; no key
// material is accepted or returned.
func (l *RequestLifecycle) Receive(nowUnixMS int64) error {
	if nowUnixMS <= 0 {
		return ErrLifecycleInvalidTime
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.statusAtLocked(nowUnixMS) != StatusConfirmed {
		return ErrLifecycleTransition
	}
	l.status = StatusReceived
	l.phaseDeadline = 0
	return nil
}

// MarkUnknown moves an active requested or confirmed lifecycle to terminal
// unknown. It fails once the request is terminal or the current phase is no
// longer active.
func (l *RequestLifecycle) MarkUnknown(nowUnixMS int64) error {
	if nowUnixMS <= 0 {
		return ErrLifecycleInvalidTime
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.statusAtLocked(nowUnixMS) {
	case StatusRequested, StatusConfirmed:
		l.status = StatusUnknown
		l.phaseDeadline = 0
		return nil
	}
	return ErrLifecycleTransition
}

// Cancel moves an active requested or confirmed lifecycle to terminal
// cancelled. It is local only: it contacts no relay and cancels nothing
// remotely. It fails once the request is terminal, so a received request cannot
// be retroactively cancelled, and once the current phase is no longer active.
func (l *RequestLifecycle) Cancel(nowUnixMS int64) error {
	if nowUnixMS <= 0 {
		return ErrLifecycleInvalidTime
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.statusAtLocked(nowUnixMS) {
	case StatusRequested, StatusConfirmed:
		l.status = StatusCancelled
		l.phaseDeadline = 0
		return nil
	}
	return ErrLifecycleTransition
}

// statusAtLocked returns the status at now and latches StatusExpired when an
// active phase or the absolute deadline has elapsed. The caller holds l.mu.
func (l *RequestLifecycle) statusAtLocked(nowUnixMS int64) string {
	switch l.status {
	case StatusRequested, StatusConfirmed:
		if nowUnixMS >= l.phaseDeadline || nowUnixMS >= l.ctx.DeadlineUnixMS {
			l.status = StatusExpired
			l.phaseDeadline = 0
		}
	}
	return l.status
}
