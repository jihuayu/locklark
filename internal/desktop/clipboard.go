package desktop

import (
	"errors"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

var errClipboardSuperseded = errors.New("clipboard action was superseded")

func (a *App) detachClipboard() *nativeclipboard.Lease {
	lease := a.clipboardLease
	a.clipboardLease = nil
	a.clipboardUntil = time.Time{}
	a.otpClipboard = nil
	if a.clipboardTimer != nil {
		a.clipboardTimer.Stop()
		a.clipboardTimer = nil
	}
	if a.otpClipboardTimer != nil {
		a.otpClipboardTimer.Stop()
		a.otpClipboardTimer = nil
	}
	return lease
}

func (a *App) clearClipboard() uint64 {
	sequence := a.clipboardSequence
	lease := a.detachClipboard()
	if lease == nil {
		lease = a.clipboardPending
	}
	if lease != nil {
		a.cleanupClipboard(lease)
	}
	return sequence
}

func (a *App) cleanupClipboard(lease *nativeclipboard.Lease) {
	result := nativeclipboard.Unavailable
	if a.clipboardClear != nil {
		result = a.clipboardClear(lease)
	}
	if result == nativeclipboard.Unavailable {
		// A confirmed newer acquisition supersedes older cleanup, even if its
		// bytes happen to be identical. Never retain a queue of payloads.
		if a.clipboardLease != nil && a.clipboardLease != lease {
			return
		}
		a.clipboardPending = lease
		a.clipboardWarning = true
		if a.clipboardRetry != nil {
			a.clipboardRetry.Stop()
		}
		a.clipboardRetry = time.AfterFunc(time.Second, func() {
			a.dispatch(func() {
				if a.clipboardPending == lease {
					a.cleanupClipboard(lease)
				}
			})
		})
		return
	}
	if a.clipboardPending == lease {
		a.clipboardPending = nil
	}
	if a.clipboardPending == nil {
		a.clipboardWarning = false
		if a.clipboardRetry != nil {
			a.clipboardRetry.Stop()
			a.clipboardRetry = nil
		}
	}
}

func (a *App) recordClipboardOwner(lease *nativeclipboard.Lease, until time.Time) uint64 {
	a.clipboardSequence++
	sequence := a.clipboardSequence
	a.clipboardLease, a.clipboardUntil = lease, until
	a.clipboardPending = nil
	a.clipboardWarning = false
	if a.clipboardRetry != nil {
		a.clipboardRetry.Stop()
		a.clipboardRetry = nil
	}
	if a.clipboardTimer != nil {
		a.clipboardTimer.Stop()
		a.clipboardTimer = nil
	}
	if d := time.Until(until); !until.IsZero() && d > 0 {
		a.clipboardTimer = time.AfterFunc(d, func() {
			a.dispatch(func() {
				if a.clipboardSequence == sequence && a.clipboardLease == lease {
					a.clearClipboard()
				}
			})
		})
	}
	return sequence
}

func (a *App) writeClipboard(value []byte, until time.Time, valid func() bool) error {
	if a.clipboardWrite == nil || !valid() || !time.Now().Before(until) {
		return personal.ErrDesktopDelivery
	}
	sequence := a.clipboardSequence
	old := a.clipboardLease
	// Replacing an existing GTK provider directly avoids generating an extra
	// SelectionClear before the next acquisition. Keep the old OTP deadline
	// armed until the native result: failure must not extend that older lease.
	lease, err := a.clipboardWrite(value)
	if sequence != a.clipboardSequence || !valid() || !time.Now().Before(until) {
		if sequence == a.clipboardSequence {
			a.detachClipboard()
		}
		if lease != nil {
			a.cleanupClipboard(lease)
		} else if old != nil {
			a.cleanupClipboard(old)
		}
		if sequence != a.clipboardSequence || !valid() {
			return errClipboardSuperseded
		}
		return personal.ErrDesktopDelivery
	}
	if lease == nil {
		a.detachClipboard()
		if old != nil {
			a.cleanupClipboard(old)
		}
		if err != nil {
			return err
		}
		return nativeclipboard.ErrWrite
	}
	a.detachClipboard()
	a.recordClipboardOwner(lease, until)
	if err != nil {
		// A partial native write retains only cleanup authority. Never keep the
		// input or retry its write, and never report this as a confirmed copy.
		a.clearClipboard()
		return nativeclipboard.ErrWrite
	}
	return nil
}
