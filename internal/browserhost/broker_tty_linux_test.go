//go:build linux

package browserhost

import (
	"math"
	"os"
	"path/filepath"
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

// TestLinuxTTYNrSignedDecoding pins tty_nr decoding for values with the high
// bit of the new_encode_dev word set: the kernel prints them as negative
// signed ints, and they must decode to the exact 32-bit device, not a
// sign-extended uint64. Zero and impossible (out of int32) values fail closed.
func TestLinuxTTYNrSignedDecoding(t *testing.T) {
	// Sign-bit encoding for devpts major 136, minor 524288.
	signed := int64(-2147454976)
	dev, ok := ttyNrDev(signed)
	if !ok || dev != 0x80008800 {
		t.Fatalf("ttyNrDev(%d) = 0x%x,%v want 0x80008800,true", signed, dev, ok)
	}
	if major, minor := devMajor(dev), devMinor(dev); major != 136 || minor != 524288 {
		t.Fatalf("decode 0x%x = %d,%d want 136,524288", dev, major, minor)
	}
	if unit, unitOK := devUnit(dev); !unitOK || unit != 524288 {
		t.Fatalf("devUnit(0x%x) = %d,%v want 524288,true", dev, unit, unitOK)
	}
	// The unsigned 32-bit word encodes the same device, and sign extension
	// (uint64(-2147454976)) must not have been used.
	if dev != uint64(uint32(0x80008800)) || dev == uint64(signed) {
		t.Fatalf("decoded 0x%x is not the unsigned 32-bit word", dev)
	}
	for _, tc := range []struct {
		tty int64
		dev uint64
		ok  bool
	}{
		{0, 0, false},
		{0x880, 0x880, true},
		{math.MinInt32, 0x80000000, true},
		{math.MaxInt32, 0x7fffffff, true},
		{-1, 0xffffffff, true},
		{math.MinInt32 - 1, 0, false},
		{math.MaxInt32 + 1, 0, false},
		{math.MinInt64, 0, false},
		{math.MaxInt64, 0, false},
	} {
		got, gotOK := ttyNrDev(tc.tty)
		if gotOK != tc.ok || got != tc.dev {
			t.Fatalf("ttyNrDev(%d) = 0x%x,%v want 0x%x,%v", tc.tty, got, gotOK, tc.dev, tc.ok)
		}
	}
}

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

// mountNamespacePath is checked against temporary symlinks only: one pointing
// at this broker's own mount namespace stands in for the same namespace, one
// pointing elsewhere for a distinct namespace. No privileges or unshare are
// needed.
func TestLinuxMountNamespacePathIdentity(t *testing.T) {
	dir := t.TempDir()
	same := filepath.Join(dir, "same")
	if err := os.Symlink("/proc/self/ns/mnt", same); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	info, ok := mountNamespacePath(same)
	if !ok {
		t.Fatalf("self namespace symlink %s rejected", same)
	}
	self, err := os.Stat("/proc/self/ns/mnt")
	if err != nil || !os.SameFile(self, info) {
		t.Fatalf("returned identity is not the self namespace: %v", err)
	}

	// A distinct identity: another namespace object when one is visible, else
	// a regular file, which differs from the namespace in type and inode.
	other := filepath.Join(dir, "other")
	if _, err := os.Stat("/proc/1/ns/mnt"); err == nil {
		if err := os.Symlink("/proc/1/ns/mnt", other); err != nil {
			t.Fatal(err)
		}
	} else {
		// A regular file has a different inode and mode; it is a distinct
		// identity even where no second namespace is visible.
		regular := filepath.Join(dir, "regular")
		if err := os.WriteFile(regular, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(regular, other); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := mountNamespacePath(other); ok {
		t.Fatalf("distinct namespace identity %s accepted", other)
	}

	// Missing and unstatable paths fail closed.
	for _, path := range []string{
		filepath.Join(dir, "missing"),
		filepath.Join(dir, "dangling"),
		"",
	} {
		if _, ok := mountNamespacePath(path); ok {
			t.Fatalf("unstatable path %q accepted", path)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	if _, ok := mountNamespacePath(filepath.Join(dir, "dangling")); ok {
		t.Fatal("dangling namespace path accepted")
	}
}

// TestLinuxSelfMountNamespaceAttestation checks that this process's own
// controlling terminal is still attested when peer and broker share one mount
// namespace; a process without a controlling terminal fails closed.
func TestLinuxSelfMountNamespaceAttestation(t *testing.T) {
	path, dev, unit, ok := peerControllingTerminal(os.Getpid())
	if !ok {
		if path, _, _, selfOK := peerControllingTerminal(os.Getpid()); selfOK {
			t.Fatalf("inconsistent self attestations: %q", path)
		}
	}
	if want := "/dev/pts/" + strconv.FormatUint(uint64(devMinor(dev)), 10); path != want || unit != devMinor(dev) {
		t.Fatalf("self attestation = %q unit %d want %q", path, unit, want)
	}
}
