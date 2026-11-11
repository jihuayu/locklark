//go:build linux

package browserhost

import (
	"os"
	"strconv"
	"testing"
)

// otherTTYDev returns another devpts minor than dev, so a declared terminal
// can be a real node that is still not the peer's terminal.
func otherTTYDev(dev uint64) uint64 {
	minor := devMinor(dev)
	if minor == 1 {
		minor = 2
	} else {
		minor = 1
	}
	return linuxDev(ttyMajor, minor)
}

// otherTTYName returns a real tty node other than dev's, or a syntactically
// valid node that does not exist.
func otherTTYName(dev uint64) string {
	return "/dev/pts/" + strconv.FormatUint(uint64(devMinor(otherTTYDev(dev))), 10)
}

// brokerTTYOtherNode returns a real, stat-able /dev/pts node other than dev's.
func brokerTTYOtherNode(dev uint64) (path string, other uint64, ok bool) {
	own := devMinor(dev)
	var candidates []uint32
	for minor := uint32(0); minor <= 255; minor++ {
		if minor != own {
			candidates = append(candidates, minor)
		}
	}
	for _, minor := range candidates {
		node := "/dev/pts/" + strconv.FormatUint(uint64(minor), 10)
		if _, nodeDev, _, ok := ttyNodeIdentity(node); ok && nodeDev != dev {
			return node, nodeDev, true
		}
	}
	return "", 0, false
}

// brokerTTYForeignDev returns a non-zero device number that no devpts node
// can have (another major).
func brokerTTYForeignDev() uint64 { return linuxDev(4, 1) }

// TestLinuxTTYDevEncoding pins the Linux kernel dev_t encoding shared by
// tty_nr and stat, including /dev/pts/0 as a valid unit zero.
func TestLinuxTTYDevEncoding(t *testing.T) {
	for _, tc := range []struct {
		dev  uint64
		unit uint32
		ok   bool
	}{
		{0x880, 0, true},     // /dev/pts/0: unit zero is a valid pty
		{0x881, 1, true},     // /dev/pts/1
		{0x88200, 512, true}, // minor above 255 spans bits 20-31
		{0x500, 0, false},    // /dev/tty class is never used as an identity
		{0, 0, false},
	} {
		unit, ok := devUnit(tc.dev)
		if ok != tc.ok || unit != tc.unit {
			t.Fatalf("devUnit(0x%x) = %d,%v want %d,%v", tc.dev, unit, ok, tc.unit, tc.ok)
		}
		if ok {
			if major, minor := devMajor(tc.dev), devMinor(tc.dev); linuxDev(major, minor) != tc.dev {
				t.Fatalf("round trip for 0x%x: %d,%d -> 0x%x", tc.dev, major, minor, linuxDev(major, minor))
			}
		}
	}
	if _, ok := handleTTYIdentity(0x881, 0x881, true); !ok {
		t.Fatal("matching handle rejected")
	}
	for _, bad := range []struct {
		attested, handle uint64
		char             bool
	}{
		{0x881, 0x500, true}, // /dev/tty class
		{0x881, 0x880, true}, // another unit
		{0x881, 0x881, false},
	} {
		if _, ok := handleTTYIdentity(bad.attested, bad.handle, bad.char); ok {
			t.Fatalf("handle 0x%x accepted for attested 0x%x", bad.handle, bad.attested)
		}
	}
	for _, path := range []string{"/dev/pts/0", "/dev/pts/17", "/dev/pts/x", "/dev/pts/01", "/dev/pts/", "/dev/tty"} {
		_, nameOK := linuxPTSUnitOfName(path)
		_, exists := os.Stat(path)
		if nameOK && exists != nil {
			continue
		}
		if nameOK != (path == "/dev/pts/0" || path == "/dev/pts/17") {
			t.Fatalf("linuxPTSUnitOfName(%q) = %v", path, nameOK)
		}
	}
	// A real /dev/pts node, when present, matches the kernel encoding.
	for _, minor := range []uint32{0, devMinor(otherTTYDev(0))} {
		node := "/dev/pts/" + strconv.FormatUint(uint64(minor), 10)
		path, nodeDev, unit, ok := ttyNodeIdentity(node)
		if !ok {
			continue
		}
		if path != node || nodeDev != linuxDev(ttyMajor, minor) || unit != minor {
			t.Fatalf("%s: identity 0x%x unit %d", node, nodeDev, unit)
		}
	}
}
