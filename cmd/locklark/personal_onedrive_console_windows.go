//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

// controlPollInterval bounds one console-input wait, so a cancellation is
// noticed within it. A console handle is not a pollable waitable object.
const controlPollInterval = 50 * time.Millisecond

// controlDrainWait bounds the flush of queued console input before the mode is
// restored.
const controlDrainWait = 50 * time.Millisecond

// openControlConsole opens this process's console input, not an inherited
// standard stream, so hidden input never reads a redirected stdin.
func openControlConsole() (*os.File, error) {
	wide, err := windows.UTF16PtrFromString("CONIN$")
	if err != nil {
		return nil, errOnedriveTerminal
	}
	// Nil SECURITY_ATTRIBUTES creates a non-inheritable handle.
	handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, errOnedriveTerminal
	}
	return os.NewFile(uintptr(handle), "CONIN$"), nil
}

// promptControlTerminal is the Windows implementation of promptHidden. The
// profile label is typed on the console; only visible ASCII is kept, and echo
// is off for the whole prompt. Only the control console is changed; stdin and
// stdout are only checked, and the prompt goes to stderr.
func promptControlTerminal(ctx context.Context, stdin, stdout *os.File, prompt string) ([]byte, error) {
	if !term.IsTerminal(int(stdin.Fd())) || !term.IsTerminal(int(stdout.Fd())) {
		return nil, errOnedriveTerminal
	}
	control, err := openControlConsole()
	if err != nil {
		return nil, errOnedriveTerminal
	}
	defer control.Close()
	// The one character taken from the queue between wait and read, and
	// whether it is valid; both live per prompt, so prompts never share or
	// race on state.
	var pending byte
	var hasPending bool
	return promptControl(labelPrompt{ctx: ctx, control: control, stderr: os.Stderr, text: prompt, pending: &pending, hasPending: &hasPending})
}

// promptControlSave puts the console input in raw mode, with echo, line input
// and processed input off, and returns the function that restores its previous
// mode plus the console handle every prompt I/O uses. The handle is taken from
// Fd once, here, and cached for the prompt's lifetime.
func promptControlSave(control *os.File) (restore func(), controlFD int, err error) {
	fd := int(control.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, 0, errOnedriveTerminal
	}
	return func() { _ = term.Restore(fd, state) }, fd, nil
}

// waitTimeout is WAIT_TIMEOUT as WaitForSingleObject returns it in its uint32
// wait result; x/sys types the constant as a syscall.Errno.
const waitTimeout = uint32(windows.WAIT_TIMEOUT)

// promptControlWait waits in bounded steps for the next character. A console
// handle is not a pollable object, so WaitForSingleObject only waits out a short
// step and reports whether the console is signaled. An event is dequeued only
// after WAIT_OBJECT_0; a timeout checks the prompt's context and loops, so a
// cancelled prompt is noticed within controlPollInterval and a wait is never
// turned into a blocking read. Exactly one event is read per dequeue, which
// consumes key-up and other non-key events as well, so nothing can stay at the
// head of the queue and spin.
func promptControlWait(p labelPrompt) (bool, error) {
	for {
		if p.ctx.Err() != nil {
			return false, errOnedriveTerminal
		}
		wait := controlPollInterval
		if deadline, ok := p.ctx.Deadline(); ok {
			left := time.Until(deadline)
			if left <= 0 {
				return false, errOnedriveTerminal
			}
			if left < wait {
				wait = left
			}
		}
		// A positive wait below one millisecond rounds up: a zero
		// timeout would mean INFINITE and block forever.
		ms := uint32(wait / time.Millisecond)
		if ms == 0 {
			ms = 1
		}
		event, err := windows.WaitForSingleObject(windows.Handle(p.controlFD), ms)
		if err != nil {
			return false, errOnedriveTerminal
		}
		if event == waitTimeout {
			continue
		}
		if event != windows.WAIT_OBJECT_0 {
			// WAIT_ABANDONED or WAIT_FAILED: no console event is
			// guaranteed, so a read could block.
			return false, errOnedriveTerminal
		}
		rec, ok := readConsoleInput(windows.Handle(p.controlFD))
		if !ok {
			return false, errOnedriveTerminal
		}
		if c := consoleChar(rec); c != consoleNoChar {
			*p.pending = byte(c)
			*p.hasPending = true
			return true, nil
		}
	}
}

// promptControlNoData paces a read attempt that found no byte while the context
// is still active. Windows console events already pace the wait steps, so it is
// immediate here.
func promptControlNoData(p labelPrompt) error {
	if p.ctx.Err() != nil {
		return errOnedriveTerminal
	}
	return nil
}

// promptControlRead returns the character promptControlWait found: n is 1 for a
// character, -2 for one above ASCII (which cancels), and 0 when there is none.
func promptControlRead(p labelPrompt) (byte, int) {
	if !*p.hasPending {
		return 0, 0
	}
	*p.hasPending = false
	c := *p.pending
	*p.pending = 0
	if c > 0x7f {
		return 0, -2
	}
	return c, 1
}

// consoleNoChar is the consoleChar result for an event that carries no character.
const consoleNoChar = -1

// dismissControlInput drops key-down events still queued on the console and ends
// the hidden line, so a stray CR cannot echo once echo returns. It runs only
// while echo is still off and consumes events one at a time, so it never blocks
// on later input and leaves key-up and other events in order.
func dismissControlInput(p labelPrompt) {
	deadline := time.Now().Add(controlDrainWait)
	for time.Now().Before(deadline) {
		var n uint32
		if err := getNumberOfConsoleInputEvents(windows.Handle(p.controlFD), &n); err != nil || n == 0 {
			break
		}
		if _, ok := readConsoleInput(windows.Handle(p.controlFD)); !ok {
			break
		}
	}
	_, _ = fmt.Fprint(p.stderr, "\r\n")
}

// readConsoleInput removes and returns one queued console event.
func readConsoleInput(handle windows.Handle) (consoleRecord, bool) {
	var rec consoleRecord
	var n uint32
	if err := readConsoleInputRaw(handle, &rec, &n); err != nil || n != 1 {
		return consoleRecord{}, false
	}
	return rec, true
}

// consoleChar returns the character of a key-down event, 0xff for a key-down
// character above ASCII (which cancels), and consoleNoChar for every other event.
func consoleChar(rec consoleRecord) int {
	if rec.EventType != windows.KEY_EVENT {
		return consoleNoChar
	}
	key := (*consoleKeyEvent)(unsafe.Pointer(&rec.event[0]))
	if key.KeyDown == 0 {
		return consoleNoChar
	}
	if key.UnicodeChar > 0x7f {
		return 0xff
	}
	return int(key.UnicodeChar)
}

var procReadConsoleInputW = syscall.NewLazyDLL("kernel32.dll").NewProc("ReadConsoleInputW")

// readConsoleInputRaw is ReadConsoleInputW: it removes up to one queued event,
// in order and including key-up events, into rec.
func readConsoleInputRaw(console windows.Handle, rec *consoleRecord, n *uint32) error {
	r1, _, e1 := procReadConsoleInputW.Call(uintptr(console), uintptr(unsafe.Pointer(rec)), 1, uintptr(unsafe.Pointer(n)))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

// consoleRecord is INPUT_RECORD: one WORD event type followed by a union whose
// largest member is a KEY_EVENT_RECORD. The input mode has
// ENABLE_EXTENDED_FLAGS without ENABLE_INSERT_MODE and without
// ENABLE_QUICK_EDIT_MODE, so no key event is ever merged.
type consoleRecord struct {
	EventType uint16
	_         uint16
	event     [16]byte
}

// consoleKeyEvent is KEY_EVENT_RECORD, at the start of a consoleRecord's union.
type consoleKeyEvent struct {
	KeyDown         int32
	RepeatCount     uint16
	VirtualKeyCode  uint16
	VirtualScanCode uint16
	UnicodeChar     uint16
	ControlKeyState uint32
}

var procGetNumberOfConsoleInputEvents = syscall.NewLazyDLL("kernel32.dll").NewProc("GetNumberOfConsoleInputEvents")

// getNumberOfConsoleInputEvents is GetNumberOfConsoleInputEvents: how many events
// are queued, including key-up and non-key events.
func getNumberOfConsoleInputEvents(console windows.Handle, n *uint32) error {
	r1, _, e1 := procGetNumberOfConsoleInputEvents.Call(uintptr(console), uintptr(unsafe.Pointer(n)))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}
