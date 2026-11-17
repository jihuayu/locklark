//go:build locklark_native_acceptance && (darwin || linux)

package desktop

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type nativeFenceTestHarness struct {
	transport  *nativeFenceTransport
	controlIn  int
	controlOut int
	eventIn    int
	eventOut   int
}

func newNativeFenceTestHarness(t *testing.T, wait, writeTimeout, terminalLifetime time.Duration) *nativeFenceTestHarness {
	t.Helper()
	controlIn, controlOut := nativeFenceTestPipe(t)
	eventIn, eventOut := nativeFenceTestPipe(t)
	transport := newNativeFenceTransportForTest(controlIn, eventOut, wait, writeTimeout, terminalLifetime)
	t.Cleanup(transport.close)
	return &nativeFenceTestHarness{
		transport:  transport,
		controlIn:  controlIn,
		controlOut: controlOut,
		eventIn:    eventIn,
		eventOut:   eventOut,
	}
}

func nativeFenceTestPipe(t *testing.T) (int, int) {
	t.Helper()
	fds := []int{0, 0}
	if err := syscall.Pipe(fds); err != nil {
		t.Fatal("NATIVE_FENCE_TEST_PIPE_CREATE_FAILED")
	}
	t.Cleanup(func() {
		nativeFenceTestClose(fds[0])
		nativeFenceTestClose(fds[1])
	})
	return fds[0], fds[1]
}

func nativeFenceTestClose(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

func nativeFenceTestClaim(t *testing.T, transport *nativeFenceTransport, attemptID uint64, childCount int) {
	t.Helper()
	result := transport.claim(attemptID, childCount)
	if result.state != nativeFenceClaimBound || result.reason != nativeFenceReasonNone {
		t.Fatal("NATIVE_FENCE_TEST_CLAIM_FAILED")
	}
}

func nativeFenceTestWrite(t *testing.T, fd int, frame string) {
	t.Helper()
	pending := []byte(frame)
	for len(pending) > 0 {
		count, err := syscall.Write(fd, pending)
		if count > 0 {
			pending = pending[count:]
		}
		if err == nil {
			if count == 0 {
				t.Fatal("NATIVE_FENCE_TEST_CONTROL_WRITE_STALLED")
			}
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		t.Fatal("NATIVE_FENCE_TEST_CONTROL_WRITE_FAILED")
	}
}

func nativeFenceTestReadFrame(t *testing.T, fd int, timeout time.Duration) string {
	t.Helper()
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal("NATIVE_FENCE_TEST_EVENT_NONBLOCK_FAILED")
	}
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 1)
	var pending []byte
	for {
		count, err := syscall.Read(fd, buffer)
		if count > 0 {
			pending = append(pending, buffer[:count]...)
			if newline := bytes.IndexByte(pending, '\n'); newline >= 0 {
				if len(pending) != newline+1 {
					t.Fatal("NATIVE_FENCE_TEST_EVENT_TRAILING_DATA")
				}
				return string(pending[:newline])
			}
			if len(pending) > 256 {
				t.Fatal("NATIVE_FENCE_TEST_EVENT_FRAME_OVERSIZE")
			}
		}
		if count == 0 && err == nil {
			t.Fatal("NATIVE_FENCE_TEST_EVENT_EOF")
		}
		if err != nil && err != syscall.EAGAIN && err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			t.Fatal("NATIVE_FENCE_TEST_EVENT_READ_FAILED")
		}
		if time.Now().After(deadline) {
			t.Fatal("NATIVE_FENCE_TEST_EVENT_FRAME_TIMEOUT")
		}
		time.Sleep(time.Millisecond)
	}
}

func nativeFenceTestExpectEOF(t *testing.T, fd int, timeout time.Duration) {
	t.Helper()
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal("NATIVE_FENCE_TEST_EVENT_NONBLOCK_FAILED")
	}
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 128)
	for {
		count, err := syscall.Read(fd, buffer)
		if count > 0 {
			t.Fatal("NATIVE_FENCE_TEST_EVENT_UNEXPECTED_FRAME")
		}
		if count == 0 && err == nil {
			return
		}
		if err != nil && err != syscall.EAGAIN && err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			t.Fatal("NATIVE_FENCE_TEST_EVENT_READ_FAILED")
		}
		if time.Now().After(deadline) {
			t.Fatal("NATIVE_FENCE_TEST_EVENT_NOT_CLOSED")
		}
		time.Sleep(time.Millisecond)
	}
}

func nativeFenceTestHold(t *testing.T, transport *nativeFenceTransport, ctx context.Context) <-chan nativeFenceHoldResult {
	t.Helper()
	result := make(chan nativeFenceHoldResult, 1)
	go func() {
		result <- transport.hold(ctx)
	}()
	return result
}

func nativeFenceTestResult(t *testing.T, result <-chan nativeFenceHoldResult) nativeFenceHoldResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("NATIVE_FENCE_TEST_HOLD_TIMEOUT")
		return nativeFenceHoldResult{}
	}
}

func nativeFenceTestFDClosed(fd int) bool {
	var stat syscall.Stat_t
	return syscall.Fstat(fd, &stat) == syscall.EBADF
}

func nativeFenceTestWaitClosed(t *testing.T, fd int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if nativeFenceTestFDClosed(fd) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("NATIVE_FENCE_TEST_FD_NOT_CLOSED")
		}
		time.Sleep(time.Millisecond)
	}
}

func nativeFenceTestFillPipe(t *testing.T, fd int) {
	t.Helper()
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal("NATIVE_FENCE_TEST_PIPE_NONBLOCK_FAILED")
	}
	buffer := make([]byte, 4096)
	for {
		count, err := syscall.Write(fd, buffer)
		if count > 0 {
			continue
		}
		if err == nil {
			t.Fatal("NATIVE_FENCE_TEST_PIPE_FILL_STALLED")
		}
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return
		}
		t.Fatal("NATIVE_FENCE_TEST_PIPE_FILL_FAILED")
	}
}

func nativeFenceTestWaitSignal(t *testing.T, signal <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(timeout):
		t.Fatal("NATIVE_FENCE_TEST_PHASE_TIMEOUT")
	}
}

func nativeFenceTestReadSentinel(t *testing.T, fd int, timeout time.Duration) byte {
	t.Helper()
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal("NATIVE_FENCE_TEST_SENTINEL_NONBLOCK_FAILED")
	}
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 1)
	for {
		count, err := syscall.Read(fd, buffer)
		if count == 1 {
			return buffer[0]
		}
		if count == 0 && err == nil {
			t.Fatal("NATIVE_FENCE_TEST_SENTINEL_MISSING")
		}
		if err != nil && err != syscall.EAGAIN && err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			t.Fatal("NATIVE_FENCE_TEST_SENTINEL_READ_FAILED")
		}
		if time.Now().After(deadline) {
			t.Fatal("NATIVE_FENCE_TEST_SENTINEL_TIMEOUT")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNativeFenceTransportDescriptors(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		transport := newNativeFenceTransport(-1, -1)
		t.Cleanup(transport.close)
		result := transport.claim(1, 1)
		if result.state != nativeFenceClaimDisabled || result.reason != nativeFenceReasonDisabled {
			t.Fatal("NATIVE_FENCE_TEST_DISABLED_NOT_REPORTED")
		}
		if again := transport.claim(2, 1); again.state != nativeFenceClaimAlreadyBound {
			t.Fatal("NATIVE_FENCE_TEST_DISABLED_REARMED")
		}
	})

	t.Run("partial", func(t *testing.T) {
		controlIn, _ := nativeFenceTestPipe(t)
		transport := newNativeFenceTransport(controlIn, -1)
		t.Cleanup(transport.close)
		result := transport.claim(1, 1)
		if result.state != nativeFenceClaimInvalid || result.reason != nativeFenceReasonConfig {
			t.Fatal("NATIVE_FENCE_TEST_PARTIAL_NOT_INVALID")
		}
		if nativeFenceTestFDClosed(controlIn) {
			t.Fatal("NATIVE_FENCE_TEST_PARTIAL_OWNERSHIP_LEAK")
		}
	})

	t.Run("stdio", func(t *testing.T) {
		_, eventOut := nativeFenceTestPipe(t)
		transport := newNativeFenceTransport(0, eventOut)
		t.Cleanup(transport.close)
		result := transport.claim(1, 1)
		if result.state != nativeFenceClaimInvalid || result.reason != nativeFenceReasonConfig {
			t.Fatal("NATIVE_FENCE_TEST_STDIO_NOT_INVALID")
		}
		var before syscall.Stat_t
		if syscall.Fstat(0, &before) == nil && nativeFenceTestFDClosed(0) {
			t.Fatal("NATIVE_FENCE_TEST_STDIO_CLOSED")
		}
	})

	t.Run("same", func(t *testing.T) {
		controlIn, _ := nativeFenceTestPipe(t)
		transport := newNativeFenceTransport(controlIn, controlIn)
		t.Cleanup(transport.close)
		result := transport.claim(1, 1)
		if result.state != nativeFenceClaimInvalid || result.reason != nativeFenceReasonConfig {
			t.Fatal("NATIVE_FENCE_TEST_SAME_FD_NOT_INVALID")
		}
		if nativeFenceTestFDClosed(controlIn) {
			t.Fatal("NATIVE_FENCE_TEST_SAME_FD_CLOSED")
		}
	})

	t.Run("regular", func(t *testing.T) {
		_, eventOut := nativeFenceTestPipe(t)
		file, err := os.CreateTemp(t.TempDir(), "native-fence-*")
		if err != nil {
			t.Fatal("NATIVE_FENCE_TEST_REGULAR_FILE_CREATE_FAILED")
		}
		t.Cleanup(func() { _ = file.Close() })
		transport := newNativeFenceTransport(int(file.Fd()), eventOut)
		t.Cleanup(transport.close)
		result := transport.claim(1, 1)
		if result.state != nativeFenceClaimInvalid || result.reason != nativeFenceReasonConfig {
			t.Fatal("NATIVE_FENCE_TEST_REGULAR_FILE_NOT_INVALID")
		}
		if nativeFenceTestFDClosed(int(file.Fd())) {
			t.Fatal("NATIVE_FENCE_TEST_REGULAR_FILE_CLOSED")
		}
	})

	t.Run("wrong-direction", func(t *testing.T) {
		controlIn, controlOut := nativeFenceTestPipe(t)
		eventIn, eventOut := nativeFenceTestPipe(t)
		transport := newNativeFenceTransport(controlOut, eventIn)
		t.Cleanup(transport.close)
		result := transport.claim(1, 1)
		if result.state != nativeFenceClaimInvalid || result.reason != nativeFenceReasonConfig {
			t.Fatal("NATIVE_FENCE_TEST_WRONG_DIRECTION_NOT_INVALID")
		}
		if nativeFenceTestFDClosed(controlIn) || nativeFenceTestFDClosed(controlOut) || nativeFenceTestFDClosed(eventIn) || nativeFenceTestFDClosed(eventOut) {
			t.Fatal("NATIVE_FENCE_TEST_WRONG_DIRECTION_OWNERSHIP_LEAK")
		}
	})
}

func TestNativeFenceTransportReleaseAdopt(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, harness.transport, 101, 2)

	result := nativeFenceTestHold(t, harness.transport, context.Background())
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
	held := nativeFenceTestResult(t, result)
	if held.verdict != nativeFenceVerdictReleased || held.reason != nativeFenceReasonNone || held.transportFailed {
		t.Fatal("NATIVE_FENCE_TEST_RELEASE_VERDICT_MISMATCH")
	}
	if drained := harness.transport.publishDrained(101, 2, true); drained.status != nativeFenceNotifyRejected || drained.reason != nativeFenceReasonState {
		t.Fatal("NATIVE_FENCE_TEST_DRAINED_BEFORE_ABORT_ACCEPTED")
	}
	if adopted := harness.transport.publishAdopted(101, 2); adopted.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_ADOPT_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "ADOPTED 2" {
		t.Fatal("NATIVE_FENCE_TEST_ADOPTED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
	if !nativeFenceTestFDClosed(harness.controlIn) {
		t.Fatal("NATIVE_FENCE_TEST_RELEASE_READER_OPEN")
	}
	if duplicate := harness.transport.publishAdopted(101, 2); duplicate.status != nativeFenceNotifyIgnored {
		t.Fatal("NATIVE_FENCE_TEST_DUPLICATE_ADOPT_NOT_IGNORED")
	}
}

func TestNativeFenceTransportContextCancellation(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, harness.transport, 111, 2)
	ctx, cancel := context.WithCancel(context.Background())
	result := nativeFenceTestHold(t, harness.transport, ctx)
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	cancel()
	held := nativeFenceTestResult(t, result)
	if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonCancelled || held.transportFailed {
		t.Fatal("NATIVE_FENCE_TEST_CANCEL_VERDICT_MISMATCH")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
		t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
	}
	if !nativeFenceTestFDClosed(harness.controlIn) {
		t.Fatal("NATIVE_FENCE_TEST_CANCEL_READER_OPEN")
	}
	if drained := harness.transport.publishDrained(111, 2, true); drained.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_DRAIN_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "DRAINED 2 1" {
		t.Fatal("NATIVE_FENCE_TEST_DRAINED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
	if duplicate := harness.transport.publishDrained(111, 2, true); duplicate.status != nativeFenceNotifyIgnored {
		t.Fatal("NATIVE_FENCE_TEST_DUPLICATE_DRAIN_NOT_IGNORED")
	}
}

func TestNativeFenceTransportEOF(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, harness.transport, 121, 1)
	result := nativeFenceTestHold(t, harness.transport, context.Background())
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	nativeFenceTestClose(harness.controlOut)
	held := nativeFenceTestResult(t, result)
	if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonEOF || held.transportFailed {
		t.Fatal("NATIVE_FENCE_TEST_EOF_VERDICT_MISMATCH")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
		t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
	}
	if !nativeFenceTestFDClosed(harness.controlIn) {
		t.Fatal("NATIVE_FENCE_TEST_EOF_READER_OPEN")
	}
	if drained := harness.transport.publishDrained(121, 1, false); drained.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_DRAIN_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "DRAINED 1 0" {
		t.Fatal("NATIVE_FENCE_TEST_DRAINED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
}

func TestNativeFenceTransportTimeout(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 30*time.Millisecond, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, harness.transport, 131, 1)
	start := time.Now()
	result := nativeFenceTestHold(t, harness.transport, context.Background())
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	held := nativeFenceTestResult(t, result)
	elapsed := time.Since(start)
	if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonTimeout || held.transportFailed {
		t.Fatal("NATIVE_FENCE_TEST_TIMEOUT_VERDICT_MISMATCH")
	}
	if elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatal("NATIVE_FENCE_TEST_TIMEOUT_DURATION_UNBOUNDED")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
		t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
	}
	if drained := harness.transport.publishDrained(131, 1, true); drained.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_DRAIN_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "DRAINED 1 1" {
		t.Fatal("NATIVE_FENCE_TEST_DRAINED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
}

func TestNativeFenceTransportFrames(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		nativeFenceTestClaim(t, harness.transport, 141, 1)
		nativeFenceTestWrite(t, harness.controlOut, "PING\n")
		result := nativeFenceTestHold(t, harness.transport, context.Background())
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		held := nativeFenceTestResult(t, result)
		if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonFrame {
			t.Fatal("NATIVE_FENCE_TEST_UNKNOWN_FRAME_ACCEPTED")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
			t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		nativeFenceTestClaim(t, harness.transport, 142, 1)
		nativeFenceTestWrite(t, harness.controlOut, strings.Repeat("X", 32)+"\n")
		result := nativeFenceTestHold(t, harness.transport, context.Background())
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		held := nativeFenceTestResult(t, result)
		if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonFrame {
			t.Fatal("NATIVE_FENCE_TEST_OVERSIZE_FRAME_ACCEPTED")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
			t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
		}
	})

	t.Run("duplicate-release", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		nativeFenceTestClaim(t, harness.transport, 143, 1)
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\nRELEASE\n")
		result := nativeFenceTestHold(t, harness.transport, context.Background())
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		held := nativeFenceTestResult(t, result)
		if held.verdict != nativeFenceVerdictReleased || held.reason != nativeFenceReasonNone {
			t.Fatal("NATIVE_FENCE_TEST_DUPLICATE_RELEASE_REJECTED")
		}
		if adopted := harness.transport.publishAdopted(143, 1); adopted.status != nativeFenceNotifyDone {
			t.Fatal("NATIVE_FENCE_TEST_ADOPT_NOT_DONE")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "ADOPTED 1" {
			t.Fatal("NATIVE_FENCE_TEST_ADOPTED_FRAME_MISMATCH")
		}
		nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
	})
}

func TestNativeFenceTransportOneShot(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, harness.transport, 151, 1)
	if again := harness.transport.claim(152, 1); again.state != nativeFenceClaimAlreadyBound {
		t.Fatal("NATIVE_FENCE_TEST_SECOND_CLAIM_ACCEPTED")
	}
	result := nativeFenceTestHold(t, harness.transport, context.Background())
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
	held := nativeFenceTestResult(t, result)
	if held.verdict != nativeFenceVerdictReleased {
		t.Fatal("NATIVE_FENCE_TEST_RELEASE_VERDICT_MISMATCH")
	}
	if again := harness.transport.claim(153, 1); again.state != nativeFenceClaimAlreadyBound {
		t.Fatal("NATIVE_FENCE_TEST_POST_RELEASE_CLAIM_ACCEPTED")
	}
	if second := harness.transport.hold(context.Background()); second.verdict != nativeFenceVerdictInvalid || second.reason != nativeFenceReasonState {
		t.Fatal("NATIVE_FENCE_TEST_SECOND_HOLD_ACCEPTED")
	}
	_, _ = syscall.Write(harness.controlOut, []byte("RELEASE\n"))
	if second := harness.transport.hold(context.Background()); second.verdict != nativeFenceVerdictInvalid {
		t.Fatal("NATIVE_FENCE_TEST_LATE_CONTROL_REARMED")
	}
	if adopted := harness.transport.publishAdopted(151, 1); adopted.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_ADOPT_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "ADOPTED 1" {
		t.Fatal("NATIVE_FENCE_TEST_ADOPTED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
}

func TestNativeFenceTransportAttemptIsolation(t *testing.T) {
	first := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, first.transport, 161, 2)
	ctx, cancel := context.WithCancel(context.Background())
	result := nativeFenceTestHold(t, first.transport, ctx)
	if frame := nativeFenceTestReadFrame(t, first.eventIn, time.Second); frame != "READY_HELD 2" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	cancel()
	if held := nativeFenceTestResult(t, result); held.verdict != nativeFenceVerdictAborted {
		t.Fatal("NATIVE_FENCE_TEST_CANCEL_VERDICT_MISMATCH")
	}
	if frame := nativeFenceTestReadFrame(t, first.eventIn, time.Second); frame != "CANCELLED" {
		t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
	}
	if stale := first.transport.publishDrained(262, 2, true); stale.status != nativeFenceNotifyIgnored || stale.reason != nativeFenceReasonAttempt {
		t.Fatal("NATIVE_FENCE_TEST_STALE_DRAIN_ACCEPTED")
	}
	if drained := first.transport.publishDrained(161, 2, true); drained.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_DRAIN_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, first.eventIn, time.Second); frame != "DRAINED 2 1" {
		t.Fatal("NATIVE_FENCE_TEST_DRAINED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, first.eventIn, time.Second)
	_, _ = syscall.Write(first.controlOut, []byte("RELEASE\n"))
	if stale := first.transport.publishAdopted(262, 1); stale.status != nativeFenceNotifyIgnored {
		t.Fatal("NATIVE_FENCE_TEST_STALE_ADOPT_ACCEPTED")
	}

	second := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, second.transport, 262, 1)
	result = nativeFenceTestHold(t, second.transport, context.Background())
	if frame := nativeFenceTestReadFrame(t, second.eventIn, time.Second); frame != "READY_HELD 1" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	if stale := second.transport.publishDrained(161, 1, true); stale.status != nativeFenceNotifyRejected {
		t.Fatal("NATIVE_FENCE_TEST_OLD_DRAIN_AFFECTED_B")
	}
	if stale := second.transport.publishAdopted(161, 1); stale.status != nativeFenceNotifyRejected {
		t.Fatal("NATIVE_FENCE_TEST_EARLY_ADOPT_AFFECTED_B")
	}
	nativeFenceTestWrite(t, second.controlOut, "RELEASE\n")
	if held := nativeFenceTestResult(t, result); held.verdict != nativeFenceVerdictReleased {
		t.Fatal("NATIVE_FENCE_TEST_RELEASE_VERDICT_MISMATCH")
	}
	if stale := second.transport.publishAdopted(161, 1); stale.status != nativeFenceNotifyIgnored || stale.reason != nativeFenceReasonAttempt {
		t.Fatal("NATIVE_FENCE_TEST_OLD_ADOPT_AFFECTED_B")
	}
	if stale := second.transport.publishDrained(161, 1, true); stale.status != nativeFenceNotifyRejected {
		t.Fatal("NATIVE_FENCE_TEST_OLD_DRAIN_TERMINALIZED_B")
	}
	if adopted := second.transport.publishAdopted(262, 1); adopted.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_ADOPT_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, second.eventIn, time.Second); frame != "ADOPTED 1" {
		t.Fatal("NATIVE_FENCE_TEST_ADOPTED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, second.eventIn, time.Second)
}

func TestNativeFenceTransportAdoptBeforeRelease(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, harness.transport, 171, 2)
	if early := harness.transport.publishAdopted(171, 2); early.status != nativeFenceNotifyRejected || early.reason != nativeFenceReasonState {
		t.Fatal("NATIVE_FENCE_TEST_EARLY_ADOPT_ACCEPTED")
	}
	result := nativeFenceTestHold(t, harness.transport, context.Background())
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
	if held := nativeFenceTestResult(t, result); held.verdict != nativeFenceVerdictReleased {
		t.Fatal("NATIVE_FENCE_TEST_RELEASE_VERDICT_MISMATCH")
	}
	if adopted := harness.transport.publishAdopted(171, 2); adopted.status != nativeFenceNotifyDone {
		t.Fatal("NATIVE_FENCE_TEST_ADOPT_NOT_DONE")
	}
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "ADOPTED 2" {
		t.Fatal("NATIVE_FENCE_TEST_ADOPTED_FRAME_MISMATCH")
	}
	nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
}

func TestNativeFenceTransportCountBound(t *testing.T) {
	t.Run("negative-claim", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		result := harness.transport.claim(181, -1)
		if result.state != nativeFenceClaimInvalid || result.reason != nativeFenceReasonCount {
			t.Fatal("NATIVE_FENCE_TEST_NEGATIVE_COUNT_ACCEPTED")
		}
		if !nativeFenceTestFDClosed(harness.controlIn) || !nativeFenceTestFDClosed(harness.eventOut) {
			t.Fatal("NATIVE_FENCE_TEST_INVALID_COUNT_NOT_DISPOSED")
		}
		if again := harness.transport.claim(182, 1); again.state != nativeFenceClaimAlreadyBound {
			t.Fatal("NATIVE_FENCE_TEST_INVALID_COUNT_REARMED")
		}
	})

	t.Run("oversize-claim", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		result := harness.transport.claim(183, nativeFenceMaxChildren+1)
		if result.state != nativeFenceClaimInvalid || result.reason != nativeFenceReasonCount {
			t.Fatal("NATIVE_FENCE_TEST_OVERSIZE_COUNT_ACCEPTED")
		}
	})

	t.Run("max-claim", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		nativeFenceTestClaim(t, harness.transport, 184, nativeFenceMaxChildren)
		result := nativeFenceTestHold(t, harness.transport, context.Background())
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 64" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
		if held := nativeFenceTestResult(t, result); held.verdict != nativeFenceVerdictReleased {
			t.Fatal("NATIVE_FENCE_TEST_RELEASE_VERDICT_MISMATCH")
		}
		if adopted := harness.transport.publishAdopted(184, nativeFenceMaxChildren); adopted.status != nativeFenceNotifyDone {
			t.Fatal("NATIVE_FENCE_TEST_ADOPT_NOT_DONE")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "ADOPTED 64" {
			t.Fatal("NATIVE_FENCE_TEST_ADOPTED_FRAME_MISMATCH")
		}
		nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
	})

	t.Run("drain-bound", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		nativeFenceTestClaim(t, harness.transport, 185, 2)
		ctx, cancel := context.WithCancel(context.Background())
		result := nativeFenceTestHold(t, harness.transport, ctx)
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		cancel()
		if held := nativeFenceTestResult(t, result); held.verdict != nativeFenceVerdictAborted {
			t.Fatal("NATIVE_FENCE_TEST_CANCEL_VERDICT_MISMATCH")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
			t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
		}
		if oversized := harness.transport.publishDrained(185, nativeFenceMaxChildren+1, true); oversized.status != nativeFenceNotifyRejected || oversized.reason != nativeFenceReasonCount {
			t.Fatal("NATIVE_FENCE_TEST_OVERSIZE_DRAIN_ACCEPTED")
		}
		if overbound := harness.transport.publishDrained(185, 3, true); overbound.status != nativeFenceNotifyRejected || overbound.reason != nativeFenceReasonCount {
			t.Fatal("NATIVE_FENCE_TEST_DRAIN_EXCEEDED_ATTEMPT_BOUND")
		}
		if drained := harness.transport.publishDrained(185, 2, true); drained.status != nativeFenceNotifyDone {
			t.Fatal("NATIVE_FENCE_TEST_DRAIN_NOT_DONE")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "DRAINED 2 1" {
			t.Fatal("NATIVE_FENCE_TEST_DRAINED_FRAME_MISMATCH")
		}
		nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
	})

	t.Run("adopt-bound", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		nativeFenceTestClaim(t, harness.transport, 186, 2)
		result := nativeFenceTestHold(t, harness.transport, context.Background())
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 2" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
		if held := nativeFenceTestResult(t, result); held.verdict != nativeFenceVerdictReleased {
			t.Fatal("NATIVE_FENCE_TEST_RELEASE_VERDICT_MISMATCH")
		}
		if overbound := harness.transport.publishAdopted(186, 3); overbound.status != nativeFenceNotifyRejected || overbound.reason != nativeFenceReasonCount {
			t.Fatal("NATIVE_FENCE_TEST_ADOPT_EXCEEDED_ATTEMPT_BOUND")
		}
		if oversized := harness.transport.publishAdopted(186, nativeFenceMaxChildren+1); oversized.status != nativeFenceNotifyRejected || oversized.reason != nativeFenceReasonCount {
			t.Fatal("NATIVE_FENCE_TEST_OVERSIZE_ADOPT_ACCEPTED")
		}
		if adopted := harness.transport.publishAdopted(186, 2); adopted.status != nativeFenceNotifyDone {
			t.Fatal("NATIVE_FENCE_TEST_ADOPT_NOT_DONE")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "ADOPTED 2" {
			t.Fatal("NATIVE_FENCE_TEST_ADOPTED_FRAME_MISMATCH")
		}
		nativeFenceTestExpectEOF(t, harness.eventIn, time.Second)
	})
}

func TestNativeFenceTransportEventChannelBounded(t *testing.T) {
	t.Run("blocked", func(t *testing.T) {
		controlIn, _ := nativeFenceTestPipe(t)
		eventIn, eventOut := nativeFenceTestPipe(t)
		_ = eventIn
		transport := newNativeFenceTransportForTest(controlIn, eventOut, time.Second, 20*time.Millisecond, 100*time.Millisecond)
		t.Cleanup(transport.close)
		nativeFenceTestClaim(t, transport, 191, 1)
		nativeFenceTestFillPipe(t, eventOut)
		start := time.Now()
		held := transport.hold(context.Background())
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatal("NATIVE_FENCE_TEST_BLOCKED_EVENT_UNBOUNDED")
		}
		if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonWrite || !held.transportFailed {
			t.Fatal("NATIVE_FENCE_TEST_BLOCKED_EVENT_VERDICT_MISMATCH")
		}
	})

	t.Run("broken", func(t *testing.T) {
		controlIn, _ := nativeFenceTestPipe(t)
		eventIn, eventOut := nativeFenceTestPipe(t)
		nativeFenceTestClose(eventIn)
		transport := newNativeFenceTransportForTest(controlIn, eventOut, time.Second, 100*time.Millisecond, 100*time.Millisecond)
		t.Cleanup(transport.close)
		nativeFenceTestClaim(t, transport, 192, 1)
		start := time.Now()
		held := transport.hold(context.Background())
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatal("NATIVE_FENCE_TEST_BROKEN_EVENT_UNBOUNDED")
		}
		if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonWrite || !held.transportFailed {
			t.Fatal("NATIVE_FENCE_TEST_BROKEN_EVENT_VERDICT_MISMATCH")
		}
	})
}

func TestNativeFenceTransportTerminalLifetime(t *testing.T) {
	t.Run("released", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 25*time.Millisecond)
		nativeFenceTestClaim(t, harness.transport, 201, 1)
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
		if held := harness.transport.hold(context.Background()); held.verdict != nativeFenceVerdictReleased {
			t.Fatal("NATIVE_FENCE_TEST_RELEASE_VERDICT_MISMATCH")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		nativeFenceTestWaitClosed(t, harness.eventOut, time.Second)
		if !nativeFenceTestFDClosed(harness.controlIn) {
			t.Fatal("NATIVE_FENCE_TEST_RELEASE_READER_OPEN")
		}
		if late := harness.transport.publishAdopted(201, 1); late.status != nativeFenceNotifyIgnored {
			t.Fatal("NATIVE_FENCE_TEST_TERMINAL_NOT_DISPOSED")
		}
	})

	t.Run("aborted", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 25*time.Millisecond)
		nativeFenceTestClaim(t, harness.transport, 202, 1)
		ctx, cancel := context.WithCancel(context.Background())
		result := nativeFenceTestHold(t, harness.transport, ctx)
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		cancel()
		if held := nativeFenceTestResult(t, result); held.verdict != nativeFenceVerdictAborted {
			t.Fatal("NATIVE_FENCE_TEST_CANCEL_VERDICT_MISMATCH")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
			t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
		}
		nativeFenceTestWaitClosed(t, harness.eventOut, time.Second)
		if late := harness.transport.publishDrained(202, 1, true); late.status != nativeFenceNotifyIgnored {
			t.Fatal("NATIVE_FENCE_TEST_TERMINAL_NOT_DISPOSED")
		}
	})
}

func TestNativeFenceTransportReleaseAcceptanceRecheck(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		reached := make(chan struct{}, 1)
		resume := make(chan struct{})
		harness.transport.test.acceptPhase = reached
		harness.transport.test.acceptResume = resume
		nativeFenceTestClaim(t, harness.transport, 301, 1)
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
		ctx, cancel := context.WithCancel(context.Background())
		result := nativeFenceTestHold(t, harness.transport, ctx)
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		nativeFenceTestWaitSignal(t, reached, time.Second)
		cancel()
		close(resume)
		held := nativeFenceTestResult(t, result)
		if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonCancelled {
			t.Fatal("NATIVE_FENCE_TEST_CANCEL_AFTER_FRAME_RELEASED")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
			t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
		}
	})

	t.Run("deadline", func(t *testing.T) {
		harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
		reached := make(chan struct{}, 1)
		resume := make(chan struct{})
		harness.transport.test.acceptPhase = reached
		harness.transport.test.acceptResume = resume
		nativeFenceTestClaim(t, harness.transport, 302, 1)
		nativeFenceTestWrite(t, harness.controlOut, "RELEASE\n")
		result := nativeFenceTestHold(t, harness.transport, context.Background())
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
			t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
		}
		nativeFenceTestWaitSignal(t, reached, time.Second)
		time.Sleep(2200 * time.Millisecond)
		close(resume)
		held := nativeFenceTestResult(t, result)
		if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonTimeout {
			t.Fatal("NATIVE_FENCE_TEST_TIMEOUT_AFTER_FRAME_RELEASED")
		}
		if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "CANCELLED" {
			t.Fatal("NATIVE_FENCE_TEST_CANCELLED_FRAME_MISMATCH")
		}
	})
}

func TestNativeFenceTransportReadCloseReuse(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	reached := make(chan struct{}, 1)
	resume := make(chan struct{})
	harness.transport.test.readPhase = reached
	harness.transport.test.readResume = resume
	nativeFenceTestClaim(t, harness.transport, 303, 1)
	result := nativeFenceTestHold(t, harness.transport, context.Background())
	if frame := nativeFenceTestReadFrame(t, harness.eventIn, time.Second); frame != "READY_HELD 1" {
		t.Fatal("NATIVE_FENCE_TEST_READY_FRAME_MISMATCH")
	}
	nativeFenceTestWaitSignal(t, reached, time.Second)
	freedFD := harness.controlIn
	harness.transport.close()
	sentinelRead, sentinelWrite := nativeFenceTestPipe(t)
	if sentinelRead != freedFD {
		t.Fatal("NATIVE_FENCE_TEST_SENTINEL_FD_NOT_REUSED")
	}
	if _, err := syscall.Write(sentinelWrite, []byte{'Z'}); err != nil {
		t.Fatal("NATIVE_FENCE_TEST_SENTINEL_WRITE_FAILED")
	}
	nativeFenceTestClose(sentinelWrite)
	close(resume)
	held := nativeFenceTestResult(t, result)
	if held.verdict != nativeFenceVerdictInvalid || held.reason != nativeFenceReasonState {
		t.Fatal("NATIVE_FENCE_TEST_CLOSE_REUSE_VERDICT_MISMATCH")
	}
	if got := nativeFenceTestReadSentinel(t, freedFD, time.Second); got != 'Z' {
		t.Fatal("NATIVE_FENCE_TEST_SENTINEL_TOUCHED")
	}
}

func TestNativeFenceTransportEINTRWriteBounded(t *testing.T) {
	harness := newNativeFenceTestHarness(t, 2*time.Second, 20*time.Millisecond, 2*time.Second)
	nativeFenceTestClaim(t, harness.transport, 304, 1)
	harness.transport.test.writeResult = nativeFenceTestWriteEINTR
	start := time.Now()
	result := nativeFenceTestHold(t, harness.transport, context.Background())
	held := nativeFenceTestResult(t, result)
	elapsed := time.Since(start)
	if held.verdict != nativeFenceVerdictAborted || held.reason != nativeFenceReasonWrite || !held.transportFailed {
		t.Fatal("NATIVE_FENCE_TEST_EINTR_WRITE_VERDICT_MISMATCH")
	}
	if elapsed < 10*time.Millisecond {
		t.Fatal("NATIVE_FENCE_TEST_EINTR_WRITE_NOT_EXERCISED")
	}
	if elapsed > time.Second {
		t.Fatal("NATIVE_FENCE_TEST_EINTR_WRITE_UNBOUNDED")
	}
	if !harness.transport.mu.TryLock() {
		t.Fatal("NATIVE_FENCE_TEST_EINTR_WRITE_LOCK_HELD")
	}
	harness.transport.mu.Unlock()
}
