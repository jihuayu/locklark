package desktop

import (
	"errors"
	"fmt"
	"runtime"
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
	if result == nativeclipboard.ManualCleanup {
		// The platform cannot revoke only this owner. Drop every retry/lease
		// reference and expose a truthful manual-cleanup notice instead of
		// claiming Cleared, Superseded or an unconfirmed retry loop. A newer
		// current owner still wins over stale cleanup.
		if a.clipboardLease != nil && a.clipboardLease != lease {
			return
		}
		if a.clipboardPending == lease {
			a.clipboardPending = nil
		}
		a.clipboardWarning = false
		a.clipboardManual = true
		if a.clipboardRetry != nil {
			a.clipboardRetry.Stop()
			a.clipboardRetry = nil
		}
		return
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
	a.clipboardManual = false
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
	_, err := a.writeClipboardOwned(value, until, valid)
	return err
}

// writeClipboardOwned has the same control flow and cleanup as writeClipboard
// but returns the exact new native lease, including on a partial failure. That
// lease carries only owned cleanup authority; callers must never retry a write
// whose error says the outcome is unknown.
func (a *App) writeClipboardOwned(value []byte, until time.Time, valid func() bool) (*nativeclipboard.Lease, error) {
	if a.clipboardWrite == nil || !valid() || !time.Now().Before(until) {
		return nil, personal.ErrDesktopDelivery
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
			return lease, errClipboardSuperseded
		}
		return lease, personal.ErrDesktopDelivery
	}
	if lease == nil {
		a.detachClipboard()
		if old != nil {
			a.cleanupClipboard(old)
		}
		if err != nil {
			return nil, err
		}
		return nil, nativeclipboard.ErrWrite
	}
	a.detachClipboard()
	a.recordClipboardOwner(lease, until)
	if err != nil {
		// A partial native write retains only cleanup authority. Never keep the
		// input or retry its write, and never report this as a confirmed copy.
		a.clearClipboard()
		return lease, nativeclipboard.ErrWrite
	}
	return lease, nil
}

// newBrowserClipboardManager builds one two-phase manager for a browser
// connection. Native work is dispatched through the existing App dispatch
// surface; accepted work is executed or enqueued, so true is truthful for the
// Manager's dispatch contract. The shared App lease remains the single owner of
// actual OS clipboard state.
func (a *App) newBrowserClipboardManager() *nativeclipboard.Manager {
	if !nativeclipboard.NativeLeaseSupported() {
		// Do not advertise a native lease where cleanup cannot be owner-safe.
		// Ordinary desktop copy still uses the explicit-copy path and reports
		// the platform's manual-cleanup status.
		return nil
	}
	return nativeclipboard.NewManagerWithWriter(a.dispatchClipboard, a.writeClipboardContext, a.clearBrowserClipboardLease)
}

// dispatchClipboard reports false only when the App has no dispatch surface.
// The existing dispatch contract executes or enqueues every accepted callback.
func (a *App) dispatchClipboard(fn func()) bool {
	if a.dispatch == nil || fn == nil {
		return false
	}
	a.dispatch(fn)
	return true
}

// writeClipboardContext translates the Manager's zero clear deadline into the
// existing no-auto-clear representation. A non-zero deadline bounds the App
// lease exactly as the Manager's offer does.
func (a *App) writeClipboardContext(value []byte, clearUntil time.Time, valid func() bool) (*nativeclipboard.Lease, error) {
	until := clearUntil
	if until.IsZero() {
		until = clipboardDeadline(0)
	}
	return a.writeClipboardOwned(value, until, valid)
}

// clearBrowserClipboardLease clears only the matching native owner and updates
// App lease state only when this lease is still the current App owner. It never
// clears a newer App copy or a foreign OS owner.
func (a *App) clearBrowserClipboardLease(lease *nativeclipboard.Lease) nativeclipboard.Result {
	if lease == nil {
		return nativeclipboard.Superseded
	}
	result := nativeclipboard.Unavailable
	if a.clipboardClear != nil {
		result = a.clipboardClear(lease)
	} else {
		result = nativeclipboard.ClearOwned(lease)
	}
	if result == nativeclipboard.Unavailable {
		return result
	}
	if result == nativeclipboard.ManualCleanup {
		if a.clipboardLease == lease {
			a.detachClipboard()
		}
		if a.clipboardPending == lease {
			a.clipboardPending = nil
		}
		a.clipboardWarning = false
		a.clipboardManual = true
		if a.clipboardRetry != nil {
			a.clipboardRetry.Stop()
			a.clipboardRetry = nil
		}
		return result
	}
	if a.clipboardLease == lease {
		a.detachClipboard()
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
	return result
}

// clipboardStatusForOS is a pure status policy so platform truthfulness can be
// tested without a GUI or a real macOS pasteboard. Native cleanup reports an
// attempted expiry; a platform without owner-safe cleanup must tell the user
// explicitly to clear the clipboard by hand.
func clipboardStatusForOS(goos string, nativeCleanup bool, timeout time.Duration) string {
	if !nativeCleanup {
		if goos == "darwin" {
			return "已复制到系统剪贴板；macOS 无法保证自动清除，请手动清理系统剪贴板"
		}
		return "已复制到系统剪贴板；当前系统无法保证自动清除，请手动清理系统剪贴板"
	}
	if timeout <= 0 {
		return "已复制到系统剪贴板（未配置自动清理）"
	}
	return fmt.Sprintf("已复制到系统剪贴板 · %d 秒后尝试清理", int(timeout/time.Second))
}

// otpClipboardDeadline bounds a copied one-time code by both its own validity
// (boundsDeadline, already capped by the OTP window in personal) and the
// configured security.clipboard.clearAfterSeconds, whichever comes first. A
// zero clear-after preference still keeps the OTP validity cap: an expired
// code is never retained on the clipboard just because auto-clear is off.
func otpClipboardDeadline(boundsDeadline time.Time, clearAfter time.Duration, now time.Time) time.Time {
	deadline := boundsDeadline
	if clearAfter > 0 {
		if configured := now.Add(clearAfter); configured.Before(deadline) {
			deadline = configured
		}
	}
	return deadline
}

func clipboardStatus(timeout time.Duration) string {
	return clipboardStatusForOS(runtime.GOOS, nativeclipboard.NativeLeaseSupported(), timeout)
}

func clipboardOTPCopiedStatusForOS(goos string, nativeCleanup bool) string {
	if nativeCleanup {
		return "已复制验证码；到期尝试清理，系统剪贴板历史可能保留"
	}
	if goos == "darwin" {
		return "已复制验证码；macOS 无法保证到期或锁定自动清除，请手动清理系统剪贴板"
	}
	return "已复制验证码；无法保证到期或锁定自动清除，请手动清理系统剪贴板"
}

func clipboardOTPCopiedStatus() string {
	return clipboardOTPCopiedStatusForOS(runtime.GOOS, nativeclipboard.NativeLeaseSupported())
}

func clipboardManualCleanupNotice() string {
	if runtime.GOOS == "darwin" {
		return "macOS 无法保证自动清除系统剪贴板；请手动清理"
	}
	return "当前系统无法保证自动清除系统剪贴板；请手动清理"
}
