//go:build darwin

package browserhost

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// otherTTYDev returns another /dev/ttysNNN device than dev, so a declared
// terminal can be a real node that is still not the peer's terminal.
func otherTTYDev(dev uint64) uint64 {
	unit, _ := devUnit(dev)
	if unit == 1 {
		return darwinDev(ttyMajor, 2)
	}
	return darwinDev(ttyMajor, 1)
}

// otherTTYName returns a real tty node other than dev's, or a syntactically
// valid node that does not exist.
func otherTTYName(dev uint64) string {
	unit, _ := devUnit(otherTTYDev(dev))
	return darwinTTYPath(unit)
}

// brokerTTYOtherNode returns a real, stat-able pty node other than dev's.
func brokerTTYOtherNode(dev uint64) (path string, other uint64, ok bool) {
	unit, _ := devUnit(dev)
	for candidate := uint32(0); candidate <= maxTTYUnit; candidate++ {
		if candidate == unit {
			continue
		}
		node := darwinTTYPath(candidate)
		if _, nodeDev, _, ok := ttyNodeIdentity(node); ok && nodeDev != dev {
			return node, nodeDev, true
		}
	}
	return "", 0, false
}

// brokerTTYForeignDev returns a non-zero device number that no Darwin pty
// session can have (another major).
func brokerTTYForeignDev() uint64 { return darwinDev(4, 1) }

// TestDarwinTTYDevEncoding pins the Darwin encoding against the real PTY
// probe: e_tdev 0x10000001 for /dev/ttys001, and stat /dev/ttysNNN plus
// fstat(open(/dev/ttysNNN)) report the same raw dev number (major 16).
func TestDarwinTTYDevEncoding(t *testing.T) {
	if got := darwinDev(ttyMajor, 1); got != 0x10000001 {
		t.Fatalf("darwinDev(16,1) = 0x%08x, want 0x10000001", got)
	}
	for _, tc := range []struct {
		dev  uint64
		unit uint32
		path string
		ok   bool
	}{
		{0x10000001, 1, "/dev/ttys001", true},
		{0x10000000, 0, "/dev/ttys000", true}, // unit zero is a valid pty
		{0x100003e7, 999, "/dev/ttys999", true},
		{0x02000000, 0, "", false}, // /dev/tty alias, not a pty node
		{0x04000001, 0, "", false}, // the draft's wrong major
		{0x00000100, 0, "", false}, // the draft's wrong stat-style major
		{0x100003e8, 0, "", false}, // unit beyond /dev/ttysNNN
		{0, 0, "", false},
	} {
		unit, ok := devUnit(tc.dev)
		if ok != tc.ok || unit != tc.unit {
			t.Fatalf("devUnit(0x%08x) = %d,%v want %d,%v", tc.dev, unit, ok, tc.unit, tc.ok)
		}
		gotPath := darwinTTYPath(unit)
		if ok && gotPath != tc.path {
			t.Fatalf("path for 0x%08x = %q, want %q", tc.dev, gotPath, tc.path)
		}
		if ok {
			if nameUnit, nameOK := darwinTTYUnitOfName(tc.path); !nameOK || nameUnit != tc.unit {
				t.Fatalf("%s name unit = %d,%v", tc.path, nameUnit, nameOK)
			}
		}
	}
	// The handle check requires exactly the attested device.
	if _, ok := handleTTYIdentity(0x10000001, 0x10000001, true); !ok {
		t.Fatal("matching handle rejected")
	}
	for _, bad := range []struct {
		attested, handle uint64
		char             bool
	}{
		{0x10000001, 0x02000000, true}, // /dev/tty alias
		{0x10000001, 0x10000002, true}, // another unit
		{0x10000001, 0x10000001, false},
		{0x02000000, 0x02000000, true}, // alias as the attested value
	} {
		if _, ok := handleTTYIdentity(bad.attested, bad.handle, bad.char); ok {
			t.Fatalf("handle 0x%08x accepted for attested 0x%08x", bad.handle, bad.attested)
		}
	}

	// The real live nodes match the kernel encoding this build derives.
	unit, _ := devUnit(otherTTYDev(0))
	for _, candidate := range []uint32{0, unit} {
		node := darwinTTYPath(candidate)
		var info unix.Stat_t
		if unix.Stat(node, &info) != nil {
			continue // this host has no such pty right now
		}
		_, nodeDev, _, ok := ttyNodeIdentity(node)
		if !ok || nodeDev != uint64(info.Rdev) || nodeDev != darwinDev(ttyMajor, candidate) {
			t.Fatalf("%s: node identity 0x%08x,%v, stat rdev 0x%08x", node, nodeDev, ok, info.Rdev)
		}
		f, e := openTTYNode(node)
		if e != nil {
			t.Fatalf("%s: open: %v", node, e)
		}
		dev, char, ok := fstatTTYHandle(f)
		f.Close()
		if !ok || !char || dev != nodeDev {
			t.Fatalf("%s: fstat handle 0x%08x,%v,%v want 0x%08x", node, dev, char, ok, nodeDev)
		}
	}
}

// TestDarwinVerifyCLIRunTTYOtherKernelTerminal proves the broker refusal when
// the peer's kernel terminal is a different real pty than the declared one
// (both nodes exist on this host), and unavailability when that node does not
// exist here, so the two replies are never confused.
func TestDarwinVerifyCLIRunTTYOtherKernelTerminal(t *testing.T) {
	peer := Peer{User: "UID 501", PID: 994, Process: "/fixture/bin/locklark"}
	node, dev := trustableTTYNode(t)
	platform := CLIRunTTYPlatform()

	declaredOther, otherDev, real := brokerTTYOtherNode(dev)
	if real {
		withTTYSeams(t, declaredOther, otherDev, true, nil)
		if e := verifyCLIRunTTY(peer, node, platform, ""); !errors.Is(e, errCLIRunInvalid) || errors.Is(e, errCLIRunUnavailable) {
			t.Fatalf("declared %s, kernel %s: %v", node, declaredOther, e)
		}
		if e := verifyCLIRunTTY(peer, declaredOther, platform, ""); e != nil {
			t.Fatalf("declared %s, kernel %s: %v", declaredOther, declaredOther, e)
		}
		// The same declarations reversed stay consistent.
		withTTYSeams(t, node, dev, true, nil)
		if e := verifyCLIRunTTY(peer, declaredOther, platform, ""); !errors.Is(e, errCLIRunInvalid) {
			t.Fatalf("declared %s, kernel %s: %v", declaredOther, node, e)
		}
	}

	// A kernel device whose node does not exist here is unavailable, never a
	// refusal, so an absent pty cannot be reported as a mismatch.
	missing := otherTYSMissingDevice(t, dev)
	withTTYSeams(t, darwinTTYPath(mustUnit(missing)), missing, true, nil)
	if e := verifyCLIRunTTY(peer, node, platform, ""); !errors.Is(e, errCLIRunUnavailable) || errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("missing kernel node: %v", e)
	}
}

// mustUnit returns the unit of a device otherTYSMissingDevice produced.
func mustUnit(dev uint64) uint32 {
	unit, _ := devUnit(dev)
	return unit
}

// otherTYSMissingDevice returns a pty device that has no node on this host.
func otherTYSMissingDevice(t *testing.T, dev uint64) uint64 {
	t.Helper()
	unit, _ := devUnit(dev)
	for candidate := uint32(0); candidate <= maxTTYUnit; candidate++ {
		if candidate == unit {
			continue
		}
		if _, err := os.Stat(darwinTTYPath(candidate)); err != nil {
			return darwinDev(ttyMajor, candidate)
		}
	}
	t.Fatal("every /dev/ttysNNN exists; cannot construct a missing node")
	return 0
}

// TestDarwinCurrentTTYIdentityRealPTY is the client-side smoke test: the test
// binary's own controlling pty is attested and identified through the
// production opener. It skips only when the process truly has no controlling
// terminal (and fails instead under the PTY smoke fixture).
func TestDarwinCurrentTTYIdentityRealPTY(t *testing.T) {
	node, nodeDev := trustableTTYNode(t)
	name, peerID, e := CurrentTTYIdentity()
	if e != nil {
		t.Fatalf("CurrentTTYIdentity: %v", e)
	}
	unit, _ := devUnit(nodeDev)
	if name != node || peerID != encodeTTYPeerID(unit) {
		t.Fatalf("identity %q %q, want %q %q", name, peerID, node, encodeTTYPeerID(unit))
	}
	if kinfo, e := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid()); e != nil || uint64(uint32(kinfo.Eproc.Tdev)) != nodeDev {
		t.Fatalf("kernel e_tdev does not confirm %s: %v", node, e)
	}
	var info unix.Stat_t
	if e := unix.Stat(name, &info); e != nil || uint64(info.Rdev) != nodeDev {
		t.Fatalf("stat %s does not confirm 0x%08x: %v", name, nodeDev, e)
	}
	t.Logf("attested controlling terminal %s dev=0x%08x unit=%d peer_id=%s", name, nodeDev, unit, peerID)
}
