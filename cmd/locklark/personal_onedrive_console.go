package main

import (
	"context"
	"fmt"
	"os"
)

// labelPrompt is one hidden profile-label prompt. The platform files provide
// promptControlTerminal and the save/restore, wait, read and dismiss hooks for
// the control terminal this prompt was opened on; this file holds the one prompt
// body every platform runs. promptControlRead reports one character with n == 1,
// no byte ready yet with n == -1, a non-ASCII byte that cancels now with n == -2,
// and a failed read with n == 0 (also fatal).
type labelPrompt struct {
	ctx        context.Context
	control    *os.File // controlling terminal, never a redirected std stream
	stderr     *os.File // where the prompt and the terminating line break go
	text       string
	pending    *byte // Windows only: key-down character taken from the queue
	hasPending *bool // Windows only: whether pending holds a character
}

// promptControl runs labelPrompt: it writes the prompt, reads one line and
// restores the terminal mode on every return path.
//
// Raw mode is followed immediately by a deferred restore, which runs after the
// prompt write error, a read error, a cancellation, an invalid label and on
// success. A cancelled or invalid line ends here: input still queued is dropped,
// and the line is ended, while echo is still off, so nothing typed after the
// prompt can echo once the shell has it back. Reads are nonblocking, every idle
// wait and pacing interval is bounded and context-aware, and p.ctx is checked
// before the next read, so a cancellation ends the prompt without any concurrent
// terminal write or mode change; no read ever runs concurrently with the
// restore.
func promptControl(p labelPrompt) ([]byte, error) {
	restore, err := promptControlSave(p.control)
	if err != nil {
		return nil, err
	}
	defer restore()
	if _, err := fmt.Fprint(p.stderr, p.text+": "); err != nil {
		return nil, errOnedriveTerminal
	}
	label, err := readLabelLine(p)
	if err != nil {
		clear(label)
		dismissControlInput(p)
		return nil, err
	}
	return label, nil
}

// readLabelLine reads one profile label from the raw control terminal. CR or LF
// ends the line, backspace (or DEL) deletes a byte, and Ctrl-C (byte 0x03),
// Ctrl-D, ESC or any other non-printable byte cancels. Reads are nonblocking,
// every idle wait and pacing interval is bounded and context-aware, and p.ctx is
// checked before each read, so cancellation stops reading without any concurrent
// terminal write or mode change.
//
// A label longer than maxProfileLabelByte is reported only once the rest of its
// line up to CR or LF has been read and dropped, so the overflow cannot echo into
// the shell after the prompt returns.
func readLabelLine(p labelPrompt) ([]byte, error) {
	label := make([]byte, 0, maxProfileLabelByte)
	overflow := false
	for {
		if p.ctx.Err() != nil {
			clear(label)
			return nil, errOnedriveTerminal
		}
		ready, err := promptControlWait(p)
		if err != nil || !ready || p.ctx.Err() != nil {
			clear(label)
			return nil, errOnedriveTerminal
		}
		// promptControlRead: 1 is a character; -1 is no byte yet, which
		// is paced by a bounded, cancellable pause so an empty terminal
		// never spins and queued input never waits; -2 is a non-ASCII
		// byte, which cancels at once and drops queued input before
		// restore; 0 is a read error.
		c, n := promptControlRead(p)
		if p.ctx.Err() != nil || n == 0 || n == -2 {
			clear(label)
			return nil, errOnedriveTerminal
		}
		if n < 0 {
			if err := promptControlNoData(p); err != nil {
				clear(label)
				return nil, err
			}
			continue
		}
		switch {
		case c == '\r' || c == '\n':
			if overflow {
				return nil, errOnedriveLabel
			}
			return label, nil
		case c == 8 || c == 127:
			if !overflow && len(label) > 0 {
				clear(label[len(label)-1:])
				label = label[:len(label)-1]
			}
		case c >= 0x20 && c <= 0x7e:
			if overflow || len(label) >= maxProfileLabelByte {
				clear(label)
				overflow = true
				continue
			}
			label = append(label, c)
		default:
			clear(label)
			return nil, errOnedriveTerminal
		}
	}
}
