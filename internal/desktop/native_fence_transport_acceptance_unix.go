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
		return t.finishReleased()
	}
	return t.finishAbort(reason, false)
}

func (t *nativeFenceTransport) readRelease(ctx context.Context, deadline time.Time) nativeFenceReason {
	frame := make([]byte, 0, nativeFenceInputFrameLimit)
	buffer := make([]byte, nativeFenceInputFrameLimit+1)
	for {
		select {
		case <-ctx.Done():
			return nativeFenceReasonCancelled
		default:
		}
		if !time.Now().Before(deadline) {
			return nativeFenceReasonTimeout
		}
		count, err := syscall.Read(t.controlInFD, buffer)
		if count > 0 {
			frame = append(frame, buffer[:count]...)
			if newline := bytes.IndexByte(frame, '\n'); newline >= 0 {
				if newline > nativeFenceInputFrameLimit || string(frame[:newline]) != nativeFenceReleasePayload {
					return nativeFenceReasonFrame
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

func (t *nativeFenceTransport) finishReleased() nativeFenceHoldResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.disposed {
		return nativeFenceHoldResult{
			verdict:         nativeFenceVerdictInvalid,
			reason:          nativeFenceReasonState,
			transportFailed: true,
		}
	}
	t.phase = nativeFencePhaseReleased
	t.closeInputLocked()
	t.armTerminalLocked()
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
	if t.phase != nativeFencePhaseAborted {
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
	deadline := time.Now().Add(t.writeTimeout)
	pending := []byte(frame)
	for len(pending) > 0 {
		count, err := syscall.Write(t.eventOutFD, pending)
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
