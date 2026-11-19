//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openTestPTY returns the master and slave of a new pseudo-terminal, the
// terminal the prompt would use. It is not made the controlling terminal here.
func openTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err = os.OpenFile("/dev/pts/"+itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

// fionread is FIONREAD, which x/sys/unix does not export for Linux.
const fionread = 0x541b

// itoa formats a small non-negative int without strconv.
func itoa(n int) string {
	var b [8]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	return string(b[i:])
}

func ttyMode(t *testing.T, f *os.File) unix.Termios {
	t.Helper()
	state, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	return *state
}

// writeTTY types s into the terminal's input queue. In cooked mode the line
// discipline echoes it immediately; in raw mode the prompt keeps every echo off.
func writeTTY(t *testing.T, master *os.File, s string) {
	t.Helper()
	if _, err := master.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// readTTYEcho reads what the test's own end of the terminal echoes, so it only
// returns echo even though echo is off for the prompt. It returns within a fixed
// deadline, empty when nothing echoed. The deadline is enforced with poll on a
// raw nonblocking descriptor: (*os.File).SetReadDeadline does not apply once the
// descriptor came through Fd, as it does for the PTY master here.
func readTTYEcho(t *testing.T, master *os.File) string {
	t.Helper()
	fd := int(master.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags) }()
	var out bytes.Buffer
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return out.String()
		}
		n, err := unix.Poll(pfd, int(left/time.Millisecond)+1)
		if err != nil && !errors.Is(err, syscall.EINTR) {
			t.Fatal(err)
		}
		if n <= 0 {
			continue
		}
		if pfd[0].Revents&unix.POLLIN == 0 {
			t.Fatalf("master poll revents = %#x without POLLIN", pfd[0].Revents)
		}
	readLoop:
		for {
			var buf [256]byte
			read, err := unix.Read(fd, buf[:])
			switch {
			case read > 0:
				out.Write(buf[:read])
			case err != nil && (errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)):
				// Nothing more to echo now; poll for it.
				break readLoop
			case err != nil && errors.Is(err, syscall.EINTR):
				// Retry the read.
			case err != nil:
				t.Fatalf("master read: %v", err)
			default:
				t.Fatalf("master read returned 0 bytes without an error")
			}
		}
	}
}

func openFileFlags(t *testing.T, f *os.File) int {
	t.Helper()
	flags, err := unix.FcntlInt(uintptr(f.Fd()), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return flags
}

func waitForPromptError(t *testing.T, control, stderr *os.File) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := promptControl(labelPrompt{ctx: context.Background(), control: control, stderr: stderr, text: "label"})
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("prompt did not return")
		return nil
	}
}

// TestPromptOverlongLabelDrainedBeforeReturn types a label one byte too long and
// then more bytes and the CR. The prompt must still be reading when only the
// overflow has arrived, and every byte queued by the time it returns must be
// consumed, so nothing of them can echo once the terminal is restored.
func TestPromptOverlongLabelDrainedBeforeReturn(t *testing.T) {
	master, slave := openTestPTY(t)
	before := ttyMode(t, slave)
	slaveFlags := openFileFlags(t, slave)
	stderr, err := os.CreateTemp(t.TempDir(), "prompt")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()

	done := make(chan error, 1)
	go func() {
		_, err := promptControl(labelPrompt{ctx: context.Background(), control: slave, stderr: stderr, text: "label"})
		done <- err
	}()
	writeTTY(t, master, strings.Repeat("o", maxProfileLabelByte+1))
	select {
	case err := <-done:
		t.Fatalf("prompt returned after the overflow alone: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	writeTTY(t, master, "TRAILING\r")
	select {
	case err := <-done:
		if !errors.Is(err, errOnedriveLabel) {
			t.Fatalf("overlong label = %v, want errOnedriveLabel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("prompt did not return")
	}

	queued, err := unix.IoctlGetInt(int(slave.Fd()), fionread)
	if err != nil {
		t.Fatal(err)
	}
	if queued != 0 {
		t.Fatalf("%d unread bytes left queued", queued)
	}
	after := ttyMode(t, slave)
	if before.Iflag != after.Iflag || before.Lflag != after.Lflag || before.Cflag != after.Cflag {
		t.Fatalf("terminal mode changed: before %+v after %+v", before, after)
	}
	if flags, err := unix.FcntlInt(uintptr(slave.Fd()), unix.F_GETFL, 0); err != nil || flags != slaveFlags {
		t.Fatalf("open-file flags after the prompt = %#x, %v; want %#x", flags, err, slaveFlags)
	}
}

// TestPromptCancelReturnsWithoutFurtherInput cancels the prompt while it waits
// and types nothing more: it must still return promptly and restore the
// terminal, where a blocking raw read would hang, and leave no input queued.
func TestPromptCancelReturnsWithoutFurtherInput(t *testing.T) {
	_, slave := openTestPTY(t)
	stderr, err := os.CreateTemp(t.TempDir(), "prompt")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	done := make(chan error, 1)
	go func() {
		_, err := promptControl(labelPrompt{ctx: ctx, control: slave, stderr: stderr, text: "label"})
		done <- err
	}()
	<-ctx.Done()
	select {
	case err := <-done:
		if !errors.Is(err, errOnedriveTerminal) {
			t.Fatalf("cancelled prompt = %v, want errOnedriveTerminal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled prompt did not return promptly")
	}
	// Checked before anything is typed after the return: the prompt leaves no
	// unread input queued. Input typed now would echo, as a restored terminal
	// should echo it, so nothing here asserts on later echoes.
	if queued, err := unix.IoctlGetInt(int(slave.Fd()), fionread); err != nil || queued != 0 {
		t.Fatalf("unread bytes queued = %d, %v", queued, err)
	}
	if after := ttyMode(t, slave); after.Lflag&unix.ECHO == 0 || after.Lflag&unix.ICANON == 0 {
		t.Fatalf("terminal not restored: %+v", after)
	}
}

// TestPromptReturnsValidHiddenLabel checks the success path under raw mode: the
// typed label is returned as typed and nothing of it echoes.
func TestPromptReturnsValidHiddenLabel(t *testing.T) {
	master, slave := openTestPTY(t)
	stderr, err := os.CreateTemp(t.TempDir(), "prompt")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	done := make(chan []byte, 1)
	go func() {
		label, _ := promptControl(labelPrompt{ctx: context.Background(), control: slave, stderr: stderr, text: "label"})
		done <- label
	}()
	time.Sleep(150 * time.Millisecond)
	writeTTY(t, master, "hidden-label\r")
	select {
	case label := <-done:
		if string(label) != "hidden-label" {
			t.Fatalf("label = %q", label)
		}
		clear(label)
	case <-time.After(10 * time.Second):
		t.Fatal("prompt did not return")
	}
	if echo := readTTYEcho(t, master); echo != "" {
		t.Fatalf("hidden label echoed: %q", echo)
	}
}

// TestPromptRestoresOnWriteError replaces stderr with a closed pipe, so the
// prompt write fails after MakeRaw; the terminal must still be restored.
func TestPromptRestoresOnWriteError(t *testing.T) {
	_, slave := openTestPTY(t)
	before := ttyMode(t, slave)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	w.Close()
	defer w.Close()
	_ = waitForPromptError(t, slave, w)
	if after := ttyMode(t, slave); before.Iflag != after.Iflag || before.Oflag != after.Oflag || before.Lflag != after.Lflag || before.Cflag != after.Cflag {
		t.Fatalf("terminal mode not restored after a prompt write error: before %+v after %+v", before, after)
	}
}

// TestPromptNonASCIIByteCancels types a leading non-ASCII byte, then bytes that
// would echo once the terminal is restored. The prompt must cancel, restore the
// mode and flags, and leave nothing queued.
func TestPromptNonASCIIByteCancels(t *testing.T) {
	master, slave := openTestPTY(t)
	before := ttyMode(t, slave)
	beforeFlags := openFileFlags(t, slave)
	stderr, err := os.CreateTemp(t.TempDir(), "prompt")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()

	done := make(chan error, 1)
	go func() {
		_, err := promptControl(labelPrompt{ctx: context.Background(), control: slave, stderr: stderr, text: "label"})
		done <- err
	}()
	time.Sleep(150 * time.Millisecond)
	// 0xc3 is the first byte of a UTF-8 sequence, so it is enough on its
	// own; the rest is queued behind it and must not survive the return.
	writeTTY(t, master, "\xc3TRAILING\r")
	select {
	case err := <-done:
		if !errors.Is(err, errOnedriveTerminal) {
			t.Fatalf("non-ASCII byte = %v, want errOnedriveTerminal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("prompt did not cancel on a non-ASCII byte")
	}
	if queued, err := unix.IoctlGetInt(int(slave.Fd()), fionread); err != nil || queued != 0 {
		t.Fatalf("unread bytes queued = %d, %v", queued, err)
	}
	after := ttyMode(t, slave)
	if before.Iflag != after.Iflag || before.Lflag != after.Lflag || before.Cflag != after.Cflag {
		t.Fatalf("terminal mode changed: before %+v after %+v", before, after)
	}
	if flags := openFileFlags(t, slave); flags != beforeFlags {
		t.Fatalf("open-file flags after the prompt = %#x; want %#x", flags, beforeFlags)
	}
}

// TestPromptSurvivesBlockingOriginal verifies that an external caller making the
// original control descriptor blocking, as (*os.File).Fd does, cannot undo the
// prompt's nonblocking cached descriptor: a typed label is still read.
func TestPromptSurvivesBlockingOriginal(t *testing.T) {
	master, slave := openTestPTY(t)
	// Force a blocking original descriptor, as os.File.Fd would.
	if err := unix.SetNonblock(int(slave.Fd()), false); err != nil {
		t.Fatal(err)
	}
	stderr, err := os.CreateTemp(t.TempDir(), "prompt")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	done := make(chan []byte, 1)
	go func() {
		label, _ := promptControl(labelPrompt{ctx: context.Background(), control: slave, stderr: stderr, text: "label"})
		done <- label
	}()
	time.Sleep(150 * time.Millisecond)
	writeTTY(t, master, "blocking-label\r")
	select {
	case label := <-done:
		if string(label) != "blocking-label" {
			t.Fatalf("label = %q", label)
		}
		clear(label)
	case <-time.After(10 * time.Second):
		t.Fatal("prompt did not return")
	}
}
