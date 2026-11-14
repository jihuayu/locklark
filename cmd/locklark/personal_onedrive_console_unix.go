//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// controlPollInterval bounds how long one pending-input wait may last before
// the prompt checks its context again.
const controlPollInterval = 50 * time.Millisecond

// controlDrainWait bounds how long dismissing queued input may take before the
// terminal is restored anyway.
const controlDrainWait = time.Second

// controlDiscardBuffer bounds how many queued bytes dismissing input drops.
const controlDiscardBuffer = 64 << 10

// openControlConsole opens this process's controlling terminal. /dev/tty is not
// an inherited standard stream, so hidden input never reads a redirected stdin.
func openControlConsole() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// promptControlTerminal is the !windows implementation of promptHidden: the label
// is read from /dev/tty in raw mode, so it never comes from flags, arguments or
// the environment and is never echoed. Only the control terminal is changed;
// stdin and stdout are only checked, and the prompt goes to stderr.
func promptControlTerminal(ctx context.Context, stdin, stdout *os.File, prompt string) ([]byte, error) {
	if !term.IsTerminal(int(stdin.Fd())) || !term.IsTerminal(int(stdout.Fd())) {
		return nil, errOnedriveTerminal
	}
	control, err := openControlConsole()
	if err != nil {
		return nil, errOnedriveTerminal
	}
	defer control.Close()
	return promptControl(labelPrompt{ctx: ctx, control: control, stderr: os.Stderr, text: prompt})
}

// promptControlSave puts one control terminal in raw mode and returns the
// function that restores it and the cached descriptor all prompt I/O uses.
//
// The descriptor is obtained once through control.SyscallConn().Control, which,
// unlike (*os.File).Fd, does not hand it to the os package's SetBlocking and so
// never undoes the nonblocking mode set here. It is then duplicated atomically
// close-on-exec with F_DUPFD_CLOEXEC: the duplicate shares the terminal, so
// termios set through it applies to the control terminal, while all flags
// changed here are set through F_SETFL on the duplicate. The prompt therefore never calls Fd again, and it
// stays correct even if a caller already made the original descriptor blocking.
// MakeRaw does not set O_NONBLOCK, so it is added here with the previous flags
// recorded: it keeps every read and drain from blocking, and the waits stay
// bounded polls. Restore puts back the terminal mode and the flags, then closes
// the duplicate, on every path.
//
// Cancellation reaches the prompt in two ways, neither of which needs O_ASYNC:
// in raw mode ISIG is off, so the terminal delivers Ctrl-C as byte 0x03 and the
// line reader cancels on it; a SIGINT delivered to the process cancels the
// signal.NotifyContext of runPersonalOnedrive, whose ctx is checked at every
// poll.
func promptControlSave(control *os.File) (restore func(), controlFD int, err error) {
	conn, err := control.SyscallConn()
	if err != nil {
		return nil, 0, errOnedriveTerminal
	}
	fd := -1
	var dupErr error
	if rawErr := conn.Control(func(orig uintptr) {
		fd, dupErr = unix.FcntlInt(orig, unix.F_DUPFD_CLOEXEC, 0)
	}); rawErr != nil || dupErr != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return nil, 0, errOnedriveTerminal
	}
	closeDup := func() { _ = unix.Close(fd) }
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		closeDup()
		return nil, 0, errOnedriveTerminal
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		closeDup()
		return nil, 0, errOnedriveTerminal
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
		closeDup()
		return nil, 0, errOnedriveTerminal
	}
	return func() {
		_ = term.Restore(fd, state)
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
		closeDup()
	}, fd, nil
}

// promptControlWait wakes the line reader to attempt one nonblocking read. It
// only queries pending input; it never reads, writes or changes the terminal.
//
// The poll result is classified explicitly:
//   - POLLIN means a byte is pending, so the read runs at once.
//   - POLLHUP, POLLERR or POLLNVAL without POLLIN is a status poll may report
//     for a control tty regardless of input availability: the Darwin polltty
//     probe saw POLLNVAL (0x20) even with an empty terminal. The nonblocking
//     read is authoritative, and the read attempt is immediate: a queued byte
//     is consumed at once, while a read that finds no byte (EAGAIN) is paced
//     afterward, in promptControlNoData. A closed or broken fd surfaces as a
//     real read error, which the caller treats as fatal.
//   - An EINTR poll goes straight to the read attempt. Any other poll syscall
//     error fails closed.
//   - A poll timeout (n == 0) wakes the reader for one read attempt.
//
// An active context with a usable read path returns (true, nil). Readiness for
// an unrecognized non-readable mode, a cancelled context and an impossible
// negative poll count fail closed. Every path checks p.ctx.
func promptControlWait(p labelPrompt) (bool, error) {
	if p.ctx.Err() != nil {
		return false, errOnedriveTerminal
	}
	pfd := []unix.PollFd{{Fd: int32(p.controlFD), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, int(controlPollInterval/time.Millisecond))
	if err != nil && !errors.Is(err, syscall.EINTR) {
		return false, errOnedriveTerminal
	}
	if err != nil {
		// EINTR: a signal arrived. The read reports the terminal's
		// state and promptControlNoData checks the context.
		return true, nil
	}
	if n < 0 {
		// Poll never reports a negative count with a nil error.
		return false, errOnedriveTerminal
	}
	if n == 0 {
		return true, nil
	}
	switch revents := pfd[0].Revents; {
	case revents&unix.POLLIN != 0:
		return true, nil
	case revents&(unix.POLLNVAL|unix.POLLHUP|unix.POLLERR) != 0:
		return true, nil
	}
	// Readiness for a nonblocking non-readable mode: no usable read path.
	return false, errOnedriveTerminal
}

// promptControlNoData paces a wakeup that found no byte. It waits no longer
// than controlPollInterval with context cancellation, so an empty terminal is
// polled in bounded, cancellable steps while queued input, which reads without
// a miss between bytes, never pauses.
func promptControlNoData(p labelPrompt) error {
	if !sleepContext(p.ctx, controlPollInterval) {
		return errOnedriveTerminal
	}
	return nil
}

// sleepContext pauses until d has passed or ctx is done, and reports whether
// the pause completed with ctx still active.
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err() == nil
	case <-timer.C:
		return ctx.Err() == nil
	}
}

// promptControlRead reads at most one pending byte from the raw control terminal
// with a nonblocking syscall, so it can never block a restore. n is 1 for a
// character, -1 when no byte is ready, -2 for a byte above ASCII (which cancels),
// and 0 on a read error.
func promptControlRead(p labelPrompt) (byte, int) {
	var buf [1]byte
	n, err := unix.Read(p.controlFD, buf[:])
	if n == 1 {
		if buf[0] > 0x7f {
			return 0, -2
		}
		return buf[0], 1
	}
	if err != nil && (errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR)) {
		// No byte is ready yet, even if the poll said so: the caller
		// goes back to a bounded wait while its context is active.
		return 0, -1
	}
	return 0, 0
}

// dismissControlInput drops input still queued on the control terminal and ends
// the hidden line, so a stray CR cannot echo once echo returns. It runs only
// while echo is still off.
func dismissControlInput(p labelPrompt) {
	discardControlInput(p.controlFD)
	_, _ = io.WriteString(p.stderr, "\r\n")
}

// discardControlInput drops input already queued on the control terminal. The
// descriptor is nonblocking, so queued bytes are read and dropped until the
// queue is empty; this never waits for new input and never blocks on a signal,
// because every read is nonblocking and an interrupted one simply retries.
func discardControlInput(fd int) {
	var buf [256]byte
	dropped := 0
	for dropped < controlDiscardBuffer {
		n, err := unix.Read(fd, buf[:])
		if n > 0 {
			dropped += n
			continue
		}
		if err != nil && errors.Is(err, syscall.EINTR) {
			continue
		}
		return
	}
}
