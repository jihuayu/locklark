//go:build locklark_native_acceptance && (darwin || linux)

package desktop

import (
	"os"
	"strconv"
	"sync"
)

const (
	nativeFenceFactoryControlEnv = "LOCKLARK_NATIVE_FENCE_CONTROL_FD"
	nativeFenceFactoryEventEnv   = "LOCKLARK_NATIVE_FENCE_EVENT_FD"

	// The frozen launcher contract carries two small canonical decimal
	// descriptor numbers. Ten characters covers every 32-bit descriptor value
	// and keeps the accepted input finite.
	nativeFenceFactoryFDInputLimit = 10
	nativeFenceFactoryFDMax        = int64(1<<31 - 1)
)

var (
	nativeFenceFactoryOnce     sync.Once
	nativeFenceFactorySelected *nativeFenceTransport
)

// nativeInitialUnlockFenceForBuild lazily selects the process-wide native
// initial-unlock fence transport after a real initial-account work success.
// Selection is intentionally process-once: later environment changes, attempts
// or App instances re-read nothing and cannot rearm, rebind or replace it.
//
// It returns nil when both contract variables are absent. A malformed or
// partial contract returns a private invalid transport that owns no
// descriptor. Only a complete canonical pair reaches the existing transport
// constructor, which remains the sole authority on pipe, direction and
// nonblocking validity and takes ownership only of a valid accepted pair.
// A partial pair is rejected before either value is treated as an owned
// descriptor; any launcher-owned failed-process descriptor stays with the
// launcher and this factory never closes it.
func nativeInitialUnlockFenceForBuild() *nativeFenceTransport {
	nativeFenceFactoryOnce.Do(func() {
		controlValue, controlPresent := os.LookupEnv(nativeFenceFactoryControlEnv)
		eventValue, eventPresent := os.LookupEnv(nativeFenceFactoryEventEnv)
		nativeFenceFactorySelected = nativeFenceFactoryFromValues(
			controlValue, controlPresent, eventValue, eventPresent)
	})
	return nativeFenceFactorySelected
}

// nativeFenceFactoryFromValues is the pure selection helper used by the
// process-once wrapper and component tests. It receives only the two frozen
// contract values and their presence; it never consults the environment.
func nativeFenceFactoryFromValues(controlValue string, controlPresent bool, eventValue string, eventPresent bool) *nativeFenceTransport {
	if !controlPresent && !eventPresent {
		return nil
	}
	if !controlPresent || !eventPresent {
		return nativeFenceFactoryInvalidTransport()
	}
	controlInFD, controlOK := nativeFenceFactoryParseFD(controlValue)
	eventOutFD, eventOK := nativeFenceFactoryParseFD(eventValue)
	if !controlOK || !eventOK || controlInFD == eventOutFD {
		return nativeFenceFactoryInvalidTransport()
	}
	return newNativeFenceTransport(controlInFD, eventOutFD)
}

// nativeFenceFactoryParseFD accepts only canonical positive decimal descriptor
// numbers outside stdio. It rejects empty, signed, spaced, zero-padded,
// overlong and overflowing input. Descriptor ownership and physical validity
// are not decided here.
func nativeFenceFactoryParseFD(value string) (int, bool) {
	if value == "" || len(value) > nativeFenceFactoryFDInputLimit {
		return 0, false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, strconv.IntSize)
	if err != nil || parsed > nativeFenceFactoryFDMax {
		return 0, false
	}
	fd := int(parsed)
	if fd <= 2 {
		return 0, false
	}
	return fd, true
}

// nativeFenceFactoryInvalidTransport represents a parser-level rejection. The
// constructor receives no caller descriptor, so a parser error cannot inspect,
// steal or close anything. It is marked invalid in-package only after the
// no-descriptor construction path has completed.
func nativeFenceFactoryInvalidTransport() *nativeFenceTransport {
	transport := newNativeFenceTransport(-1, -1)
	transport.config = nativeFenceConfigInvalid
	return transport
}
