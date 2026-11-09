// Package nativeclipboard offers text through a per-acquisition native lease.
// It never requests clipboard contents. Calls belong on the native UI thread.
package nativeclipboard

import (
	"bytes"
	"errors"
	"unicode/utf8"
)

var (
	ErrUnsupported = errors.New("safe clipboard ownership is unsupported")
	ErrUnavailable = errors.New("clipboard ownership is unavailable")
	ErrWrite       = errors.New("clipboard write was not confirmed")
)

// Result describes a conditional cleanup, never the contents of the clipboard.
type Result uint8

const (
	Cleared Result = iota
	Superseded
	Unavailable
	// ManualCleanup means this platform cannot revoke only our native owner:
	// the lease must be dropped, no retry may be scheduled, and the user must
	// be told to clear the system clipboard manually. It never means Cleared
	// or Superseded and must not be reported as a confirmed cleanup.
	ManualCleanup
)

// Lease identifies one native acquisition. It contains no publicly accessible
// text. A new acquisition, including an identical value, has a different lease.
type Lease struct{ native any }

func (Lease) String() string               { return "[clipboard lease]" }
func (Lease) GoString() string             { return "[clipboard lease]" }
func (Lease) MarshalJSON() ([]byte, error) { return []byte(`"[clipboard lease]"`), nil }

// Write borrows value for this call. The caller still owns and clears its input;
// any provider copy is cleared when revoked or released. Success means a native
// acquisition was confirmed, not that a paste has occurred. A non-nil lease
// with an error means a partial write: retain only its cleanup authority and
// report an unconfirmed outcome. Never retry a failed disclosure automatically.
func Write(value []byte) (*Lease, error) {
	if len(value) > 4<<20 || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
		return nil, ErrWrite
	}
	return write(value)
}

// ClearOwned revokes this provider and clears only the matching native owner.
// Unavailable retains an opaque retryable lease; Superseded preserves the new
// owner, even when it contains the same text; ManualCleanup is terminal and
// asks the user to clear the clipboard by hand. There is no foreign Read API.
func ClearOwned(lease *Lease) Result {
	if lease == nil {
		return Superseded
	}
	return clearOwned(lease)
}

// NativeLeaseSupported reports whether ClearOwned can revoke only this
// process's native owner without risking a foreign value. Platforms such as
// Darwin without a public compare-and-clear operation return false; callers
// must then use their ordinary manual-cleanup path instead of advertising an
// automatic native lease.
func NativeLeaseSupported() bool { return leaseSupported }
