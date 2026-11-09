//go:build linux && (amd64 || arm64)

package nativeclipboard

import (
	"bytes"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const leaseSupported = true

type gtkLease struct {
	owner, window uintptr
	data          []byte
	active        bool
	awaitingClear bool
}

type gtkAPI struct {
	ok                         bool
	getDisplay                 func() uintptr
	x11Type                    func() uintptr
	isA                        func(uintptr, uintptr) bool
	atom                       func(string, bool) uintptr
	getClipboard               func(uintptr) uintptr
	getOwner                   func(uintptr) uintptr
	selectionOwner             func(uintptr, uintptr) uintptr
	xid                        func(uintptr) uintptr
	xdisplay                   func(uintptr) uintptr
	newObject                  func(uintptr, uintptr) uintptr
	unref                      func(uintptr)
	targetList                 func(uintptr, uint32) uintptr
	addTextTargets             func(uintptr, uint32)
	targetTable                func(uintptr, *int32) uintptr
	freeTargets                func(uintptr, int32)
	unrefTargets               func(uintptr)
	setOwner                   func(uintptr, uintptr, uint32, uintptr, uintptr, uintptr) bool
	setText                    func(uintptr, unsafe.Pointer, int32) bool
	grab                       func(uintptr) int32
	ungrab                     func(uintptr) int32
	flush                      func(uintptr) int32
	xatom                      func(uintptr, string, bool) uintptr
	xowner                     func(uintptr, uintptr) uintptr
	xsetOwner                  func(uintptr, uintptr, uintptr, uintptr) int32
	getCallback, clearCallback uintptr
	sources                    map[uintptr]*gtkLease
}

var gtk gtkAPI
var gtkOnce sync.Once

func loadGTK() {
	gtkOnce.Do(func() {
		libs := make(map[string]uintptr)
		for _, name := range []string{"libgtk-3.so.0", "libgdk-3.so.0", "libgobject-2.0.so.0", "libX11.so.6"} {
			lib, err := purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL)
			if err != nil {
				return
			}
			libs[name] = lib
		}
		bindings := []struct {
			lib, name string
			fn        any
		}{
			{"libgdk-3.so.0", "gdk_display_get_default", &gtk.getDisplay},
			{"libgdk-3.so.0", "gdk_x11_display_get_type", &gtk.x11Type},
			{"libgobject-2.0.so.0", "g_type_check_instance_is_a", &gtk.isA},
			{"libgdk-3.so.0", "gdk_atom_intern", &gtk.atom},
			{"libgtk-3.so.0", "gtk_clipboard_get", &gtk.getClipboard},
			{"libgtk-3.so.0", "gtk_clipboard_get_owner", &gtk.getOwner},
			{"libgdk-3.so.0", "gdk_selection_owner_get_for_display", &gtk.selectionOwner},
			{"libgdk-3.so.0", "gdk_x11_window_get_xid", &gtk.xid},
			{"libgdk-3.so.0", "gdk_x11_display_get_xdisplay", &gtk.xdisplay},
			{"libgobject-2.0.so.0", "g_object_new", &gtk.newObject},
			{"libgobject-2.0.so.0", "g_object_unref", &gtk.unref},
			{"libgtk-3.so.0", "gtk_target_list_new", &gtk.targetList},
			{"libgtk-3.so.0", "gtk_target_list_add_text_targets", &gtk.addTextTargets},
			{"libgtk-3.so.0", "gtk_target_table_new_from_list", &gtk.targetTable},
			{"libgtk-3.so.0", "gtk_target_table_free", &gtk.freeTargets},
			{"libgtk-3.so.0", "gtk_target_list_unref", &gtk.unrefTargets},
			{"libgtk-3.so.0", "gtk_clipboard_set_with_owner", &gtk.setOwner},
			{"libgtk-3.so.0", "gtk_selection_data_set_text", &gtk.setText},
			{"libX11.so.6", "XGrabServer", &gtk.grab},
			{"libX11.so.6", "XUngrabServer", &gtk.ungrab},
			{"libX11.so.6", "XFlush", &gtk.flush},
			{"libX11.so.6", "XInternAtom", &gtk.xatom},
			{"libX11.so.6", "XGetSelectionOwner", &gtk.xowner},
			{"libX11.so.6", "XSetSelectionOwner", &gtk.xsetOwner},
		}
		for _, binding := range bindings {
			address, err := purego.Dlsym(libs[binding.lib], binding.name)
			if err != nil {
				return
			}
			purego.RegisterFunc(binding.fn, address)
		}
		gtk.sources = make(map[uintptr]*gtkLease)
		gtk.getCallback = purego.NewCallback(func(_ uintptr, selection uintptr, _ uint32, owner uintptr) { provideGTK(selection, owner) })
		gtk.clearCallback = purego.NewCallback(func(_ uintptr, owner uintptr) { releaseGTK(owner) })
		gtk.ok = true
	})
}

func provideGTK(selection, owner uintptr) {
	p := gtk.sources[owner]
	if p == nil || !p.active {
		return
	}
	var zero byte
	ptr := unsafe.Pointer(&zero)
	if len(p.data) != 0 {
		ptr = unsafe.Pointer(&p.data[0])
	}
	gtk.setText(selection, ptr, int32(len(p.data)))
}

func releaseGTK(owner uintptr) {
	if p := gtk.sources[owner]; p != nil {
		p.active = false
		clear(p.data)
		p.data = nil
		p.awaitingClear = false
		delete(gtk.sources, owner)
		// GTK has detached its weak ownership notification before this callback.
		// Unref earlier would call GTK's unconditional cached clear operation.
		gtk.unref(owner)
	}
}

func gtkContext() (display, board, atom uintptr, err error) {
	loadGTK()
	if !gtk.ok {
		return 0, 0, 0, ErrUnsupported
	}
	display = gtk.getDisplay()
	if display == 0 {
		return 0, 0, 0, ErrUnavailable
	}
	if !gtk.isA(display, gtk.x11Type()) {
		return 0, 0, 0, ErrUnsupported
	}
	atom = gtk.atom("CLIPBOARD", false)
	board = gtk.getClipboard(atom)
	if board == 0 {
		return 0, 0, 0, ErrUnavailable
	}
	return display, board, atom, nil
}

func write(value []byte) (*Lease, error) {
	display, board, atom, err := gtkContext()
	if err != nil {
		return nil, err
	}
	// GDK records the new X request serial on every set. Its SelectionClear
	// dispatcher rejects events older than that acquisition, so a queued clear
	// from an earlier lease cannot unset this new provider.
	owner := gtk.newObject(80, 0) // G_TYPE_OBJECT; no properties.
	if owner == 0 {
		return nil, ErrUnavailable
	}
	p := &gtkLease{owner: owner, data: bytes.Clone(value), active: true}
	gtk.sources[owner] = p
	list := gtk.targetList(0, 0)
	if list == 0 {
		releaseGTK(owner)
		return nil, ErrUnavailable
	}
	gtk.addTextTargets(list, 0)
	var n int32
	targets := gtk.targetTable(list, &n)
	if targets == 0 || n <= 0 {
		if targets != 0 {
			gtk.freeTargets(targets, n)
		}
		gtk.unrefTargets(list)
		releaseGTK(owner)
		return nil, ErrUnavailable
	}
	accepted := gtk.setOwner(board, targets, uint32(n), gtk.getCallback, gtk.clearCallback, owner)
	gtk.freeTargets(targets, n)
	gtk.unrefTargets(list)
	if !accepted {
		releaseGTK(owner)
		return nil, ErrWrite
	}
	// A foreign owner is never adopted as our lease. GDK performs a real
	// XGetSelectionOwner and maps only windows belonging to this GDK display.
	window := gtk.selectionOwner(display, atom)
	if gtk.getOwner(board) != owner || !p.active {
		p.active = false
		clear(p.data)
		p.data = nil
		return nil, ErrWrite
	}
	if window == 0 {
		p.active = false
		clear(p.data)
		p.data = nil
		return &Lease{native: p}, ErrWrite
	}
	p.window = gtk.xid(window)
	if p.window == 0 {
		p.active = false
		clear(p.data)
		p.data = nil
		return &Lease{native: p}, ErrWrite
	}
	return &Lease{native: p}, nil
}

func clearOwned(lease *Lease) Result {
	p, ok := lease.native.(*gtkLease)
	if !ok || p == nil {
		return Superseded
	}
	p.active = false
	clear(p.data)
	p.data = nil
	// GObject addresses and GTK's hidden XID can be reused. The concrete Go
	// provider identity must still match this acquisition, not only its address.
	if gtk.sources[p.owner] != p {
		return Superseded
	}
	display, board, selection, err := gtkContext()
	if err != nil {
		return Unavailable
	}
	if gtk.getOwner(board) != p.owner {
		return Superseded
	}
	if p.awaitingClear {
		return Cleared
	}
	dpy := gtk.xdisplay(display)
	if dpy == 0 {
		return Unavailable
	}
	atom := gtk.xatom(dpy, "CLIPBOARD", false)
	if atom == 0 {
		return Unavailable
	}
	if p.window == 0 {
		// A partial acquisition may regain its metadata on a later cleanup attempt.
		// Only this exact current GObject can authorize binding a local owner XID.
		window := gtk.selectionOwner(display, selection)
		if window == 0 {
			return Superseded
		}
		p.window = gtk.xid(window)
		if p.window == 0 {
			return Unavailable
		}
	}
	return clearX11(p, dpy, atom)
}

func clearX11(p *gtkLease, display, atom uintptr) Result {
	// Only X server metadata operations occur under this extremely short grab.
	// Never call GTK (which can pump events), providers, or timestamp helpers.
	gtk.grab(display)
	defer func() { gtk.ungrab(display); gtk.flush(display) }()
	if gtk.xowner(display, atom) != p.window {
		return Superseded
	}
	gtk.xsetOwner(display, atom, 0, 0) // None, CurrentTime.
	if gtk.xowner(display, atom) != 0 {
		return Unavailable
	}
	p.awaitingClear = true
	return Cleared
}
