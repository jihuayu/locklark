//go:build linux && (amd64 || arm64)

package nativeclipboard

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestX11CleanupArbitratesOnlyServerOwnership(t *testing.T) {
	grab, ungrab, flush, owner, set := gtk.grab, gtk.ungrab, gtk.flush, gtk.xowner, gtk.xsetOwner
	defer func() { gtk.grab, gtk.ungrab, gtk.flush, gtk.xowner, gtk.xsetOwner = grab, ungrab, flush, owner, set }()
	for _, same := range []bool{false, true} {
		inside, writes, unlocked, flushed := false, 0, false, false
		gtk.grab = func(uintptr) int32 { inside = true; return 1 }
		gtk.ungrab = func(uintptr) int32 { inside = false; unlocked = true; return 1 }
		gtk.flush = func(uintptr) int32 { flushed = true; return 1 }
		gtk.xowner = func(uintptr, uintptr) uintptr {
			if !inside {
				t.Fatal("owner query outside arbitration")
			}
			if writes != 0 {
				return 0
			}
			if same {
				return 7
			}
			return 8
		}
		gtk.xsetOwner = func(_, _, window, timestamp uintptr) int32 {
			if !inside || window != 0 || timestamp != 0 {
				t.Fatal("invalid conditional clear")
			}
			writes++
			return 1
		}
		p := &gtkLease{window: 7}
		result := clearX11(p, 1, 2)
		if same && (result != Cleared || writes != 1) {
			t.Fatal("matching owner was not cleared")
		}
		if !same && (result != Superseded || writes != 0) {
			t.Fatal("foreign owner was changed")
		}
		if !unlocked || !flushed || inside {
			t.Fatal("server grab retained")
		}
	}
	gtk.grab = func(uintptr) int32 { return 1 }
	unlocked, flushed := false, false
	gtk.ungrab = func(uintptr) int32 { unlocked = true; return 1 }
	gtk.flush = func(uintptr) int32 { flushed = true; return 1 }
	gtk.xowner = func(uintptr, uintptr) uintptr { panic("synthetic metadata failure") }
	func() { defer func() { _ = recover() }(); clearX11(&gtkLease{window: 7}, 1, 2) }()
	if !unlocked || !flushed {
		t.Fatal("panic retained global server grab")
	}
}

func fakeGTK(t *testing.T) {
	t.Helper()
	loadGTK()
	saved := gtk
	t.Cleanup(func() { gtk = saved })
	current, next := uintptr(0), uintptr(10)
	gtk = gtkAPI{
		ok:             true,
		getDisplay:     func() uintptr { return 1 },
		x11Type:        func() uintptr { return 2 },
		isA:            func(uintptr, uintptr) bool { return true },
		atom:           func(string, bool) uintptr { return 3 },
		getClipboard:   func(uintptr) uintptr { return 4 },
		getOwner:       func(uintptr) uintptr { return current },
		selectionOwner: func(uintptr, uintptr) uintptr { return 5 },
		xid:            func(uintptr) uintptr { return 7 },
		xdisplay:       func(uintptr) uintptr { return 6 },
		newObject:      func(uintptr, uintptr) uintptr { next++; return next },
		unref:          func(uintptr) {},
		targetList:     func(uintptr, uint32) uintptr { return 8 },
		addTextTargets: func(uintptr, uint32) {},
		targetTable:    func(_ uintptr, n *int32) uintptr { *n = 1; return 9 },
		freeTargets:    func(uintptr, int32) {},
		unrefTargets:   func(uintptr) {},
		setOwner: func(_, _ uintptr, _ uint32, _, _, owner uintptr) bool {
			if current != 0 {
				releaseGTK(current)
			}
			current = owner
			return true
		},
		setText: func(uintptr, unsafe.Pointer, int32) bool { return true },
		grab:    func(uintptr) int32 { return 1 },
		ungrab:  func(uintptr) int32 { return 1 },
		flush:   func(uintptr) int32 { return 1 },
		xatom:   func(uintptr, string, bool) uintptr { return 3 },
		xowner:  func(uintptr, uintptr) uintptr { return 7 },
		xsetOwner: func(uintptr, uintptr, uintptr, uintptr) int32 {
			gtk.xowner = func(uintptr, uintptr) uintptr { return 0 }
			return 1
		},
		sources: map[uintptr]*gtkLease{},
	}
}

func TestGTKPartialAcquisitionNeverAdoptsForeignOwner(t *testing.T) {
	fakeGTK(t)
	gtk.selectionOwner = func(uintptr, uintptr) uintptr { return 0 }
	lease, err := Write([]byte("private-value"))
	if lease == nil || err != ErrWrite {
		t.Fatal("partial mapping failure lost cleanup authority")
	}
	if ClearOwned(lease) != Superseded {
		t.Fatal("foreign ownership was adopted")
	}
	for _, p := range gtk.sources {
		if p.active || p.data != nil {
			t.Fatal("failed binding retained an active provider")
		}
	}
}

func TestGTKPartialMetadataKeepsCleanupLease(t *testing.T) {
	fakeGTK(t)
	gtk.xid = func(uintptr) uintptr { return 0 }
	lease, err := Write([]byte("private-value"))
	if lease == nil || err != ErrWrite {
		t.Fatal("partial acquisition lost cleanup authority")
	}
	if ClearOwned(lease) != Unavailable {
		t.Fatal("missing XID was considered cleared")
	}
	gtk.xid = func(uintptr) uintptr { return 7 }
	if ClearOwned(lease) != Cleared {
		t.Fatal("partial acquisition cleanup could not recover")
	}
}

func TestGTKProviderRevocationAndReplacement(t *testing.T) {
	fakeGTK(t)
	input := []byte("雪🙂\nlarge-provider")
	lease, err := Write(input)
	if err != nil {
		t.Fatal(err)
	}
	p := lease.native.(*gtkLease)
	input[0] = 'x'
	if p.data[0] == 'x' {
		t.Fatal("provider borrowed caller buffer")
	}
	calls := 0
	gtk.setText = func(uintptr, unsafe.Pointer, int32) bool { calls++; return true }
	provideGTK(1, p.owner)
	if calls != 1 {
		t.Fatal("active provider did not serve prepared text")
	}
	if ClearOwned(lease) != Cleared {
		t.Fatal("own cleanup failed")
	}
	provideGTK(1, p.owner)
	if calls != 1 || p.data != nil {
		t.Fatal("revoked queued request received text")
	}
	// Reacquisition is permitted immediately: GDK's native serial filter drops
	// the old SelectionClear. A subsequent replacement releases this provider.
	newLease, err := Write([]byte("same-value"))
	if err != nil {
		t.Fatal("quick rewrite failed")
	}
	if ClearOwned(lease) != Superseded {
		t.Fatal("old provider cleared new acquisition")
	}
	if newLease.native.(*gtkLease).data == nil {
		t.Fatal("new provider was cleared")
	}
}

func TestGTKUnsupportedBackendAndTargetAllocationFailure(t *testing.T) {
	fakeGTK(t)
	gtk.isA = func(uintptr, uintptr) bool { return false }
	if lease, err := Write([]byte("value")); lease != nil || err != ErrUnsupported {
		t.Fatal("non-X11 backend did not fail closed")
	}
	gtk.isA = func(uintptr, uintptr) bool { return true }
	gtk.targetList = func(uintptr, uint32) uintptr { return 0 }
	if lease, err := Write([]byte("value")); lease != nil || err != ErrUnavailable || len(gtk.sources) != 0 {
		t.Fatal("target allocation failure leaked provider")
	}
}

func TestGTKReleaseZeroesProvider(t *testing.T) {
	oldSources, oldUnref := gtk.sources, gtk.unref
	defer func() { gtk.sources, gtk.unref = oldSources, oldUnref }()
	value := []byte("private-provider-value")
	p := &gtkLease{owner: 7, data: value, active: true}
	gtk.sources = map[uintptr]*gtkLease{7: p}
	calls := 0
	gtk.unref = func(uintptr) { calls++ }
	releaseGTK(7)
	releaseGTK(7)
	if p.active || p.data != nil || !bytes.Equal(value, make([]byte, len(value))) || calls != 1 || len(gtk.sources) != 0 {
		t.Fatal("provider lifetime cleanup failed")
	}
}

func TestGTKReleasedLeaseCannotClearReusedGObjectAddress(t *testing.T) {
	sources := gtk.sources
	defer func() { gtk.sources = sources }()
	old := &gtkLease{owner: 7, window: 9}
	current := &gtkLease{owner: 7, window: 9, active: true, data: []byte("new-private-value")}
	gtk.sources = map[uintptr]*gtkLease{7: current}
	if ClearOwned(&Lease{native: old}) != Superseded {
		t.Fatal("released lease accepted a recycled native address")
	}
	if !current.active || string(current.data) != "new-private-value" {
		t.Fatal("old cleanup changed current provider")
	}
}
