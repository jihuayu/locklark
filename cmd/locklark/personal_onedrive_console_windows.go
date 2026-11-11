//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

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

// nudgeControlConsole ends a pending hidden read by writing a CR, which the
// line reader treats as an empty line, for the cancelled path to discard. It
// runs only after a cancellation.
func nudgeControlConsole(control *os.File) {
	_, _ = control.Write([]byte{'\r'})
}

// promptControlTerminal is the Windows implementation of promptHidden. The
// profile label is typed on the console; only visible ASCII is kept, and echo
// is off for the whole prompt.
func promptControlTerminal(ctx context.Context, stdin, stdout *os.File, prompt string) ([]byte, error) {
	if !term.IsTerminal(int(stdin.Fd())) || !term.IsTerminal(int(stdout.Fd())) {
		return nil, errOnedriveTerminal
	}
	control, err := openControlConsole()
	if err != nil {
		return nil, errOnedriveTerminal
	}
	defer control.Close()
	fd := int(control.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, errOnedriveTerminal
	}
	if _, err := fmt.Fprint(os.Stderr, prompt+": "); err != nil {
		_ = term.Restore(fd, state)
		return nil, errOnedriveTerminal
	}
	interrupt := context.AfterFunc(ctx, func() {
		_ = control.SetReadDeadline(time.Now())
	})
	defer interrupt()
	label, readErr := readLabelLine(control)
	if interrupt() {
		if err := term.Restore(fd, state); err != nil && readErr == nil {
			clear(label)
			return nil, errOnedriveTerminal
		}
	}
	if readErr != nil || ctx.Err() != nil {
		clear(label)
		_, _ = io.WriteString(os.Stderr, "\r\n")
		return nil, errOnedriveTerminal
	}
	return label, nil
}

// readLabelLine reads one profile label from the raw console. CR or LF ends the
// line, backspace (or DEL) deletes a byte, and Ctrl-C, Ctrl-D, ESC or any other
// non-printable byte cancels.
func readLabelLine(control *os.File) ([]byte, error) {
	label := make([]byte, 0, 64)
	var b [1]byte
	for {
		if _, err := control.Read(b[:]); err != nil {
			clear(label)
			return nil, errOnedriveTerminal
		}
		switch c := b[0]; {
		case c == '\r' || c == '\n':
			return label, nil
		case c == 8 || c == 127:
			if len(label) > 0 {
				clear(label[len(label)-1:])
				label = label[:len(label)-1]
			}
		case c >= 0x20 && c <= 0x7e:
			if len(label) >= maxProfileLabelByte {
				clear(label)
				return nil, errOnedriveLabel
			}
			label = append(label, c)
		default:
			clear(label)
			return nil, errOnedriveTerminal
		}
	}
}
