//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"
)

// openControlConsole opens this process's controlling terminal. /dev/tty is not
// an inherited standard stream, so hidden input never reads a redirected stdin.
func openControlConsole() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// nudgeControlConsole ends a pending hidden read by writing a CR, which the
// line reader treats as an empty line, for the cancelled path to discard. It
// runs only after a cancellation.
func nudgeControlConsole(control *os.File) {
	_ = control.SetWriteDeadline(time.Now())
	_, _ = control.Write([]byte{'\r'})
	_ = control.SetWriteDeadline(time.Time{})
}

// promptControlTerminal is the Unix implementation of promptHidden: the label is
// read from /dev/tty in raw mode, so it never comes from flags, arguments or the
// environment and is never echoed.
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
	// A cancellation while raw mode is on ends the pending read, so echo is
	// restored below without leaving input pending in the terminal.
	interrupt := context.AfterFunc(ctx, func() { nudgeControlConsole(control) })
	defer interrupt()
	label, readErr := readLabelLine(control)
	// Restoring echo before anything else can print keeps the terminal from
	// echoing the rest of the line or the end of the prompt.
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

// readLabelLine reads one profile label from the raw control terminal. CR or LF
// ends the line, backspace (or DEL) deletes a byte, and Ctrl-C, Ctrl-D, ESC or
// any other non-printable byte cancels. Reads are unbuffered, so nothing past
// the line is consumed.
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
