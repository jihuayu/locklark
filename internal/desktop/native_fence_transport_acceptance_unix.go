//go:build locklark_native_acceptance && (darwin || linux)

package desktop

import (
	"bytes"
	"context"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	nativeFenceReleasePayload = "RELEASE"
	nativeFenceCancelledFrame = "CANCELLED\n"
)

type nativeFenceTestWriteResult uint8

const (
	nativeFenceTestWriteReal nativeFenceTestWriteResult = iota
	nativeFenceTestWriteEINTR
)

// nativeFenceTestSeam carries only finite phase signals and a finite syscall
// result enum for deterministic tagged tests. It is nil/zero in production and
// is never exposed as an observer or control API.
type nativeFenceTestSeam struct {
	readPhase    chan<- struct{}
	readResume   <-chan struct{}
	readPaused   bool
	acceptPhase  chan<- struct{}
	acceptResume <-chan struct{}
	acceptPaused bool
	writeResult  nativeFenceTestWriteResult
}

// nativeFenceTransport is a one-shot finite protocol controller. It carries
// only numeric pipe descriptors, finite state, an internal attempt identity and
// a bounded child count. It holds no application, session, wrapper, token,
// account, factor, row, path or cleanup capability. Its DRAINED and ADOPTED
// frames are notification transitions only; no physical cleanup or adoption is
// performed or proved here.
type nativeFenceTransport struct {
	mu sync.Mutex

	controlInFD int
	eventOutFD  int
	config      nativeFenceConfig

	wait             time.Duration
	writeTimeout     time.Duration
	terminalLifetime time.Duration

	claimed    bool
	phase      nativeFencePhase
	attemptID  uint64
	childCount int
	deadline   time.Time

	terminalTimer *time.Timer
	terminal      bool
	disposed      bool
	inputClosed   bool
	eventClosed   bool

	test nativeFenceTestSeam
}

func newNativeFenceTransport(controlInFD, eventOutFD int) *nativeFenceTransport {
	return newNativeFenceTransportWithLimits(controlInFD, eventOutFD,
		nativeFenceProductionWait, nativeFenceProductionWrite, nativeFenceProductionTerm)
}

func newNativeFenceTransportForTest(controlInFD, eventOutFD int, wait, writeTimeout, terminalLifetime time.Duration) *nativeFenceTransport {
	return newNativeFenceTransportWithLimits(controlInFD, eventOutFD,
		nativeFenceLimitDuration(wait, nativeFenceProductionWait),
		nativeFenceLimitDuration(writeTimeout, nativeFenceProductionWrite),
		nativeFenceLimitDuration(terminalLifetime, nativeFenceProductionTerm))
}

func nativeFenceLimitDuration(value, production time.Duration) time.Duration {
	if value <= 0 || value > production {
		return production
	}
	return value
}

func newNativeFenceTransportWithLimits(controlInFD, eventOutFD int, wait, writeTimeout, terminalLifetime time.Duration) *nativeFenceTransport {
	return &nativeFenceTransport{
		controlInFD:      controlInFD,
		eventOutFD:       eventOutFD,
		config:           nativeFenceClassifyFDs(controlInFD, eventOutFD),
		wait:             wait,
		writeTimeout:     writeTimeout,
		terminalLifetime: terminalLifetime,
		phase:            nativeFencePhaseUnclaimed,
	}
}

func nativeFenceClassifyFDs(controlInFD, eventOutFD int) nativeFenceConfig {
	if controlInFD < 0 && eventOutFD < 0 {
		return nativeFenceConfigDisabled
	}
	if controlInFD < 0 || eventOutFD < 0 {
		return nativeFenceConfigInvalid
	}
	if controlInFD <= 2 || eventOutFD <= 2 || controlInFD == eventOutFD {
		return nativeFenceConfigInvalid
	}
	if !nativeFenceIsPipe(controlInFD) || !nativeFenceIsPipe(eventOutFD) {
		return nativeFenceConfigInvalid
	}
	if !nativeFenceFDReadable(controlInFD) || !nativeFenceFDWritable(eventOutFD) {
		return nativeFenceConfigInvalid
	}
	if err := syscall.SetNonblock(controlInFD, true); err != nil {
		return nativeFenceConfigInvalid
	}
	if err := syscall.SetNonblock(eventOutFD, true); err != nil {
		return nativeFenceConfigInvalid
	}
	return nativeFenceConfigValid
}

func nativeFenceIsPipe(fd int) bool {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return false
	}
	return stat.Mode&syscall.S_IFMT == syscall.S_IFIFO
}

func nativeFenceFDReadable(fd int) bool {
	flags, ok := nativeFenceFDFlags(fd)
	if !ok {
		return false
	}
	access := flags & syscall.O_ACCMODE
	return access == syscall.O_RDONLY || access == syscall.O_RDWR
}

func nativeFenceFDWritable(fd int) bool {
	flags, ok := nativeFenceFDFlags(fd)
	if !ok {
		return false
	}
	access := flags & syscall.O_ACCMODE
	return access == syscall.O_WRONLY || access == syscall.O_RDWR
}

func nativeFenceFDFlags(fd int) (int, bool) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFL), 0)
	if errno != 0 {
		return 0, false
	}
	return int(flags), true
}

func (t *nativeFenceTransport) claim(attemptID uint64, childCount int) nativeFenceClaimResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.claimed {
		return nativeFenceClaimResult{
			state:  nativeFenceClaimAlreadyBound,
			reason: nativeFenceReasonState,
		}
	}
	t.claimed = true
	switch t.config {
	case nativeFenceConfigDisabled:
		return nativeFenceClaimResult{
			state:  nativeFenceClaimDisabled,
			reason: nativeFenceReasonDisabled,
		}
	case nativeFenceConfigInvalid:
		return nativeFenceClaimResult{
			state:  nativeFenceClaimInvalid,
			reason: nativeFenceReasonConfig,
		}
	}
	if childCount < 0 || childCount > nativeFenceMaxChildren {
		t.disposeLocked()
		return nativeFenceClaimResult{
			state:  nativeFenceClaimInvalid,
			reason: nativeFenceReasonCount,
		}
	}
	t.attemptID = attemptID
	t.childCount = childCount
	t.phase = nativeFencePhaseClaimed
	return nativeFenceClaimResult{
		state:  nativeFenceClaimBound,
		reason: nativeFenceReasonNone,
	}
}

func (t *nativeFenceTransport) hold(ctx context.Context) nativeFenceHoldResult {
	if ctx == nil {
		ctx = context.Background()
	}
	t.mu.Lock()
	if t.disposed || t.phase != nativeFencePhaseClaimed {
		t.mu.Unlock()
		return nativeFenceHoldResult{
			verdict: nativeFenceVerdictInvalid,
			reason:  nativeFenceReasonState,
		}
	}
	t.phase = nativeFencePhaseWaiting
	t.deadline = time.Now().Add(t.wait)
	childCount := t.childCount
	deadline := t.deadline
	t.mu.Unlock()

	select {
	case <-ctx.Done():
		return t.finishAbort(nativeFenceReasonCancelled, false)
	default:
	}

	if !t.writeFrame(nativeFenceReadyFrame(childCount)) {
		return t.finishAbort(nativeFenceReasonWrite, true)
	}

	reason := t.readRelease(ctx, deadline)
	if reason == nativeFenceReasonNone {
		return t.finishReleased(ctx, deadline)
	}
	return t.finishAbort(reason, false)
}

func nativeFenceAcceptRelease(ctx context.Context, deadline time.Time) nativeFenceReason {
	select {
	case <-ctx.Done():
		return nativeFenceReasonCancelled
	default:
	}
	if !time.Now().Before(deadline) {
		return nativeFenceReasonTimeout
	}
	return nativeFenceReasonNone
}

func (t *nativeFenceTransport) readRelease(ctx context.Context, deadline time.Time) nativeFenceReason {
	frame := make([]byte, 0, nativeFenceInputFrameLimit)
	buffer := make([]byte, nativeFenceInputFrameLimit+1)
	for {
		if reason := nativeFenceAcceptRelease(ctx, deadline); reason != nativeFenceReasonNone {
			return reason
		}
		t.nativeFenceTestPauseRead()
		if reason := nativeFenceAcceptRelease(ctx, deadline); reason != nativeFenceReasonNone {
			return reason
		}
		count, err, owned := t.readControlNonblocking(buffer)
		if !owned {
			return nativeFenceReasonState
		}
		if count > 0 {
			frame = append(frame, buffer[:count]...)
			if newline := bytes.IndexByte(frame, '\n'); newline >= 0 {
				if newline > nativeFenceInputFrameLimit || string(frame[:newline]) != nativeFenceReleasePayload {
					return nativeFenceReasonFrame
				}
				if reason := nativeFenceAcceptRelease(ctx, deadline); reason != nativeFenceReasonNone {
					return reason
				}
				return nativeFenceReasonNone
			}
			if len(frame) > nativeFenceInputFrameLimit {
				return nativeFenceReasonFrame
			}
		}
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(nativeFenceReadWritePoll)
				continue
			}
			return nativeFenceReasonRead
		}
		if count == 0 {
			if len(frame) > 0 {
				return nativeFenceReasonFrame
			}
			return nativeFenceReasonEOF
		}
	}
}

// readControlNonblocking serializes the owned-FD check and one nonblocking
// read with close/dispose, so a closed reader can never touch a reused FD.
func (t *nativeFenceTransport) readControlNonblocking(buffer []byte) (int, error, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disposed || t.inputClosed || t.controlInFD < 0 {
		return 0, nil, false
	}
	count, err := syscall.Read(t.controlInFD, buffer)
	return count, err, true
}

// finishReleased rechecks the same context and original absolute deadline at
// the release linearization point. A cancellation or expiry that already
// happened aborts rather than releasing.
func (t *nativeFenceTransport) finishReleased(ctx context.Context, deadline time.Time) nativeFenceHoldResult {
	t.nativeFenceTestPauseAccept()
	t.mu.Lock()
	if t.disposed {
		t.mu.Unlock()
		return nativeFenceHoldResult{
			verdict:         nativeFenceVerdictInvalid,
			reason:          nativeFenceReasonState,
			transportFailed: true,
		}
	}
	if reason := nativeFenceAcceptRelease(ctx, deadline); reason != nativeFenceReasonNone {
		t.mu.Unlock()
		return t.finishAbort(reason, false)
	}
	t.phase = nativeFencePhaseReleased
	t.closeInputLocked()
	t.armTerminalLocked()
	t.mu.Unlock()
	return nativeFenceHoldResult{
		verdict: nativeFenceVerdictReleased,
		reason:  nativeFenceReasonNone,
	}
}

func (t *nativeFenceTransport) finishAbort(reason nativeFenceReason, transportFailed bool) nativeFenceHoldResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disposed {
		return nativeFenceHoldResult{
			verdict:         nativeFenceVerdictInvalid,
			reason:          nativeFenceReasonState,
			transportFailed: true,
		}
	}
	t.phase = nativeFencePhaseAborted
	t.closeInputLocked()
	if t.eventClosed {
		transportFailed = true
	} else if !t.writeFrameLocked(nativeFenceCancelledFrame) {
		transportFailed = true
		t.closeEventLocked()
	}
	t.armTerminalLocked()
	return nativeFenceHoldResult{
		verdict:         nativeFenceVerdictAborted,
		reason:          reason,
		transportFailed: transportFailed,
	}
}

func (t *nativeFenceTransport) publishDrained(attemptID uint64, closedCount int, parentLocked bool) nativeFenceNotifyResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disposed || t.terminal {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyIgnored,
			reason: nativeFenceReasonTerminal,
		}
	}
	if t.phase != nativeFencePhaseAborted && t.phase != nativeFencePhaseReleased {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyRejected,
			reason: nativeFenceReasonState,
		}
	}
	if attemptID != t.attemptID {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyIgnored,
			reason: nativeFenceReasonAttempt,
		}
	}
	if closedCount < 0 || closedCount > t.childCount {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyRejected,
			reason: nativeFenceReasonCount,
		}
	}
	// A released operation may still be dropped by the original App adoption
	// gate. The private owner then reports the observed drain. This frame is a
	// finite caller observation only, never cleanup proof or an ADOPTED grant.
	written := t.writeFrameLocked(nativeFenceDrainedFrame(closedCount, parentLocked))
	t.terminal = true
	t.stopTerminalLocked()
	t.closeEventLocked()
	if !written {
		return nativeFenceNotifyResult{
			status:          nativeFenceNotifyTransportFailed,
			reason:          nativeFenceReasonWrite,
			transportFailed: true,
		}
	}
	return nativeFenceNotifyResult{status: nativeFenceNotifyDone}
}

func (t *nativeFenceTransport) publishAdopted(attemptID uint64, childCount int) nativeFenceNotifyResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disposed || t.terminal {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyIgnored,
			reason: nativeFenceReasonTerminal,
		}
	}
	if t.phase != nativeFencePhaseReleased {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyRejected,
			reason: nativeFenceReasonState,
		}
	}
	if attemptID != t.attemptID {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyIgnored,
			reason: nativeFenceReasonAttempt,
		}
	}
	if childCount < 0 || childCount > nativeFenceMaxChildren || childCount > t.childCount {
		return nativeFenceNotifyResult{
			status: nativeFenceNotifyRejected,
			reason: nativeFenceReasonCount,
		}
	}
	written := t.writeFrameLocked(nativeFenceAdoptedFrame(childCount))
	t.terminal = true
	t.stopTerminalLocked()
	t.closeEventLocked()
	if !written {
		return nativeFenceNotifyResult{
			status:          nativeFenceNotifyTransportFailed,
			reason:          nativeFenceReasonWrite,
			transportFailed: true,
		}
	}
	return nativeFenceNotifyResult{status: nativeFenceNotifyDone}
}

func (t *nativeFenceTransport) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.disposeLocked()
}

func (t *nativeFenceTransport) disposeLocked() {
	if t.disposed {
		return
	}
	t.disposed = true
	t.stopTerminalLocked()
	if t.config == nativeFenceConfigValid {
		t.closeInputLocked()
		t.closeEventLocked()
	}
}

func (t *nativeFenceTransport) writeFrame(frame string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writeFrameLocked(frame)
}

func (t *nativeFenceTransport) closeInputLocked() {
	if t.inputClosed || t.controlInFD < 0 {
		return
	}
	t.inputClosed = true
	_ = syscall.Close(t.controlInFD)
	t.controlInFD = -1
}

func (t *nativeFenceTransport) closeEventLocked() {
	if t.eventClosed || t.eventOutFD < 0 {
		return
	}
	t.eventClosed = true
	_ = syscall.Close(t.eventOutFD)
	t.eventOutFD = -1
}

func (t *nativeFenceTransport) stopTerminalLocked() {
	if t.terminalTimer == nil {
		return
	}
	t.terminalTimer.Stop()
	t.terminalTimer = nil
}

func (t *nativeFenceTransport) armTerminalLocked() {
	if t.terminal || t.disposed || t.eventClosed || t.terminalTimer != nil {
		return
	}
	t.terminalTimer = time.AfterFunc(t.terminalLifetime, t.expireTerminal)
}

func (t *nativeFenceTransport) expireTerminal() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.terminal || t.disposed {
		return
	}
	t.disposed = true
	t.terminalTimer = nil
	if t.config == nativeFenceConfigValid {
		t.closeInputLocked()
		t.closeEventLocked()
	}
}

func (t *nativeFenceTransport) writeFrameLocked(frame string) bool {
	if t.eventClosed || t.disposed {
		return false
	}
	// The deadline is absolute across every retry, including EINTR and partial
	// writes; no retry renews it.
	deadline := time.Now().Add(t.writeTimeout)
	pending := []byte(frame)
	for len(pending) > 0 {
		if !time.Now().Before(deadline) {
			return false
		}
		var count int
		var err error
		if t.test.writeResult == nativeFenceTestWriteEINTR {
			err = syscall.EINTR
		} else {
			count, err = syscall.Write(t.eventOutFD, pending)
		}
		if count > 0 {
			pending = pending[count:]
		}
		if err == nil {
			if count == 0 {
				return false
			}
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			if !time.Now().Before(deadline) {
				return false
			}
			time.Sleep(nativeFenceReadWritePoll)
			continue
		}
		return false
	}
	return true
}

func (t *nativeFenceTransport) nativeFenceTestPauseRead() {
	if t.test.readPhase == nil || t.test.readPaused {
		return
	}
	t.test.readPaused = true
	nativeFenceTestSignalAndWait(t.test.readPhase, t.test.readResume)
}

func (t *nativeFenceTransport) nativeFenceTestPauseAccept() {
	if t.test.acceptPhase == nil || t.test.acceptPaused {
		return
	}
	t.test.acceptPaused = true
	nativeFenceTestSignalAndWait(t.test.acceptPhase, t.test.acceptResume)
}

func nativeFenceTestSignalAndWait(phase chan<- struct{}, resume <-chan struct{}) {
	select {
	case phase <- struct{}{}:
	case <-time.After(5 * time.Second):
		return
	}
	select {
	case <-resume:
	case <-time.After(5 * time.Second):
	}
}

func nativeFenceReadyFrame(childCount int) string {
	return "READY_HELD " + strconv.Itoa(childCount) + "\n"
}

func nativeFenceDrainedFrame(closedCount int, parentLocked bool) string {
	locked := "0"
	if parentLocked {
		locked = "1"
	}
	return "DRAINED " + strconv.Itoa(closedCount) + " " + locked + "\n"
}

func nativeFenceAdoptedFrame(childCount int) string {
	return "ADOPTED " + strconv.Itoa(childCount) + "\n"
}
