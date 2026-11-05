//go:build windows && (amd64 || arm64)

package nativeclipboard

import (
	"crypto/rand"
	"crypto/subtle"
	"os"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/windows"
)

var globalLockOnce sync.Once
var globalLockPointer func(uintptr) unsafe.Pointer

func nativeLock(handle uintptr) unsafe.Pointer {
	// GlobalLock returns OS-owned native storage, never a Go heap address.
	// Preserve its pointer type across FFI instead of round-tripping uintptr.
	globalLockOnce.Do(func() { purego.RegisterFunc(&globalLockPointer, clipLock.Addr()) })
	return globalLockPointer(handle)
}

var (
	clipUser             = windows.NewLazySystemDLL("user32.dll")
	clipKernel           = windows.NewLazySystemDLL("kernel32.dll")
	clipOpen             = clipUser.NewProc("OpenClipboard")
	clipClose            = clipUser.NewProc("CloseClipboard")
	clipEmpty            = clipUser.NewProc("EmptyClipboard")
	clipOwner            = clipUser.NewProc("GetClipboardOwner")
	clipSequence         = clipUser.NewProc("GetClipboardSequenceNumber")
	clipSet              = clipUser.NewProc("SetClipboardData")
	clipGet              = clipUser.NewProc("GetClipboardData")
	clipRegister         = clipUser.NewProc("RegisterClipboardFormatW")
	clipCreate           = clipUser.NewProc("CreateWindowExW")
	clipWindowPID        = clipUser.NewProc("GetWindowThreadProcessId")
	clipAlloc            = clipKernel.NewProc("GlobalAlloc")
	clipFree             = clipKernel.NewProc("GlobalFree")
	clipLock             = clipKernel.NewProc("GlobalLock")
	clipUnlock           = clipKernel.NewProc("GlobalUnlock")
	clipSize             = clipKernel.NewProc("GlobalSize")
	clipHWND, clipFormat uintptr
)

// A narrow call boundary also permits a native test to fail only the second
// SetClipboardData call after the first eager value has genuinely reached OS.
var setWinClipboard = func(format, data uintptr) uintptr {
	result, _, _ := clipSet.Call(format, data)
	return result
}

type winLease struct {
	window    uintptr
	sequence  uint32
	nonce     [16]byte
	withNonce bool
}

func initWinClipboard() bool {
	if clipHWND != 0 && clipFormat != 0 {
		return true
	}
	class, _ := windows.UTF16PtrFromString("STATIC")
	name, _ := windows.UTF16PtrFromString("Locklark clipboard owner")
	format, _ := windows.UTF16PtrFromString("org.locklark.clipboard.lease.v1")
	clipFormat, _, _ = clipRegister.Call(uintptr(unsafe.Pointer(format)))
	if clipFormat == 0 {
		return false
	}
	// A process-owned message-only builtin window; no delayed rendering or
	// application callbacks. It lives for this process, independent of MyGo's
	// visible windows and their ordinary text-control copy operations.
	clipHWND, _, _ = clipCreate.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, 0, ^uintptr(2), 0, 0, 0)
	return clipHWND != 0
}

func nativeBytes(value []byte) uintptr {
	h, _, _ := clipAlloc.Call(0x42, uintptr(len(value))) // GMEM_MOVEABLE|ZEROINIT
	if h == 0 {
		return 0
	}
	p := nativeLock(h)
	if p == nil {
		clipFree.Call(h)
		return 0
	}
	copy(unsafe.Slice((*byte)(p), len(value)), value)
	clipUnlock.Call(h)
	return h
}

func freeNative(h uintptr) {
	if h == 0 {
		return
	}
	n, _, _ := clipSize.Call(h)
	p := nativeLock(h)
	if p != nil {
		clear(unsafe.Slice((*byte)(p), int(n)))
		clipUnlock.Call(h)
	}
	clipFree.Call(h)
}

func write(value []byte) (lease *Lease, err error) {
	if !initWinClipboard() {
		return nil, ErrUnavailable
	}
	p := &winLease{window: clipHWND}
	if _, err := rand.Read(p.nonce[:]); err != nil {
		return nil, ErrWrite
	}
	var units []uint16
	for len(value) != 0 {
		r, n := utf8.DecodeRune(value)
		if r == 0 {
			return nil, ErrWrite
		}
		value = value[n:]
		if r <= 0xffff {
			units = append(units, uint16(r))
		} else {
			hi, lo := utf16.EncodeRune(r)
			units = append(units, uint16(hi), uint16(lo))
		}
	}
	units = append(units, 0)
	defer clear(units)
	text := nativeBytes(unsafe.Slice((*byte)(unsafe.Pointer(&units[0])), len(units)*2))
	meta := nativeBytes(p.nonce[:])
	defer func() { freeNative(text); freeNative(meta) }()
	if text == 0 || meta == 0 {
		return nil, ErrWrite
	}
	opened, _, _ := clipOpen.Call(p.window)
	if opened == 0 {
		return nil, ErrUnavailable
	}
	defer func() {
		if closed, _, _ := clipClose.Call(); closed == 0 {
			err = ErrWrite
		}
	}()
	if emptied, _, _ := clipEmpty.Call(); emptied == 0 {
		return nil, ErrWrite
	}
	if setWinClipboard(13, text) == 0 {
		return nil, ErrWrite
	} // CF_UNICODETEXT
	text = 0 // OS owns eager native memory after successful SetClipboardData.
	lease = &Lease{native: p}
	if setWinClipboard(clipFormat, meta) == 0 {
		seq, _, _ := clipSequence.Call()
		p.sequence = uint32(seq)
		return lease, ErrWrite
	}
	meta = 0
	p.withNonce = true
	seq, _, _ := clipSequence.Call()
	p.sequence = uint32(seq)
	if !windowIsOurs(p.window) {
		return lease, ErrWrite
	}
	owner, _, _ := clipOwner.Call()
	if owner != p.window {
		return lease, ErrWrite
	}
	return lease, nil
}

func windowIsOurs(window uintptr) bool {
	var pid uint32
	thread, _, _ := clipWindowPID.Call(window, uintptr(unsafe.Pointer(&pid)))
	return thread != 0 && pid == uint32(os.Getpid())
}

func clearOwned(lease *Lease) (result Result) {
	p, ok := lease.native.(*winLease)
	if !ok || p == nil {
		return Superseded
	}
	opened, _, _ := clipOpen.Call(p.window)
	if opened == 0 {
		return Unavailable
	}
	result = Superseded
	defer func() {
		if closed, _, _ := clipClose.Call(); closed == 0 {
			result = Unavailable
		}
	}()
	owner, _, _ := clipOwner.Call()
	if owner != p.window || !windowIsOurs(p.window) {
		return result
	}
	seq, _, _ := clipSequence.Call()
	if !p.withNonce && p.sequence == 0 {
		return Unavailable
	}
	if !p.withNonce && uint32(seq) != p.sequence {
		// Same-owner format publication can advance the sequence while the
		// partially written value remains. Without our nonce this is unknown,
		// not proof of replacement, and cannot justify discarding cleanup.
		return Unavailable
	}
	if p.withNonce {
		// Read only our eager fixed metadata, under the same OpenClipboard
		// lock and after owner HWND/PID/sequence proof. Never read foreign text.
		h, _, _ := clipGet.Call(clipFormat)
		if h == 0 {
			return Unavailable
		}
		n, _, _ := clipSize.Call(h)
		if n < 16 || n > 4096 {
			return Unavailable
		}
		data := nativeLock(h)
		if data == nil {
			return Unavailable
		}
		match := subtle.ConstantTimeCompare(unsafe.Slice((*byte)(data), 16), p.nonce[:]) == 1
		clipUnlock.Call(h)
		if !match {
			return Superseded
		}
	}
	if emptied, _, _ := clipEmpty.Call(); emptied == 0 {
		return Unavailable
	}
	return Cleared
}
