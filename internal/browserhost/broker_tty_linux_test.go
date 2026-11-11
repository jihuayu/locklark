//go:build linux

package browserhost

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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
	signed := int64(-2147448832)
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
	// (uint64(-2147448832)) must not have been used.
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

	// A distinct identity: a temporary regular file, reached through a
	// symlink. PID 1 often shares the caller's mount namespace, so it cannot
	// stand in for a different one; a regular file has its own inode and mode
	// and so is deterministically not the self namespace under os.SameFile.
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.Symlink(regular, other); err != nil {
		t.Fatal(err)
	}
	if otherInfo, err := os.Stat(other); err != nil || os.SameFile(self, otherInfo) {
		t.Fatalf("distinct fixture is not a distinct identity: %v", err)
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

// TestLinuxSelfMountNamespaceAttestation checks self-attestation when peer and
// broker share one mount namespace. A process without a controlling terminal
// must yield the empty unavailable result and nothing else; only a positive
// result has a path and unit to check. This is not positive TTY coverage: see
// TestLinuxCurrentTTYIdentityRealPTY.
func TestLinuxSelfMountNamespaceAttestation(t *testing.T) {
	path, dev, unit, ok := peerControllingTerminal(os.Getpid())
	if !ok {
		if path != "" || dev != 0 || unit != 0 {
			t.Fatalf("unavailable self attestation = %q 0x%x %d, want empty", path, dev, unit)
		}
		if path, _, _, selfOK := peerControllingTerminal(os.Getpid()); selfOK {
			t.Fatalf("inconsistent self attestations: %q", path)
		}
		return
	}
	if want := "/dev/pts/" + strconv.FormatUint(uint64(devMinor(dev)), 10); path != want || unit != devMinor(dev) {
		t.Fatalf("self attestation = %q unit %d want %q", path, unit, want)
	}
}

// mountinfoFixture returns a mountinfo listing with one root, one proc, and the
// given extra records, in the kernel's field order: mount ID, parent ID,
// major:minor, root, mount point, mount options, zero or more optional
// tag[:value] fields, "-", filesystem type, mount source, super options.
func mountinfoFixture(extra ...string) string {
	lines := []string{
		"22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
		"23 22 0:52 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw",
	}
	return strings.Join(append(lines, extra...), "\n") + "\n"
}

// TestLinuxParseSingleDevptsMount pins the pure mountinfo parser: exactly one
// devpts record is accepted, zero or duplicate (bind) records are rejected as
// ambiguous, and a malformed listing rejects the whole input. Optional fields
// follow the kernel grammar (tag[:value]), and unknown tags are ignored.
func TestLinuxParseSingleDevptsMount(t *testing.T) {
	devpts := "108 27 0:47 / /dev/pts rw,nosuid,noexec,relatime shared:50 master:27 - devpts devpts rw,gid=5,mode=620,ptmxmode=000"
	unbindable := "108 27 0:47 / /dev/pts rw,nosuid,noexec,relatime unbindable - devpts devpts rw,gid=5,mode=620,ptmxmode=000"
	unknown := "108 27 0:47 / /dev/pts rw,nosuid,noexec,relatime readonly future_tag - devpts devpts rw,gid=5,mode=620,ptmxmode=000"
	noOptional := "108 27 0:47 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=000"
	bindA := "109 27 0:47 / /srv/pty-bind rw,nosuid,noexec,relatime shared:50 master:27 - devpts devpts rw,gid=5,mode=620,ptmxmode=000"
	bindB := "110 27 0:48 / /dev/pts-2 rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=000"
	optional := "111 22 0:53 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 master:1 propagate_from:2 - cgroup2 cgroup2 rw,nsdelegate"

	for _, tc := range []struct {
		name   string
		data   string
		id     string
		path   string
		accept bool
	}{
		{"exactly one devpts", mountinfoFixture(devpts, optional), "108", "/dev/pts", true},
		{"devpts only", devpts + "\n", "108", "/dev/pts", true},
		{"devpts with unbindable optional", mountinfoFixture(unbindable), "108", "/dev/pts", true},
		{"devpts with unknown optional tag", mountinfoFixture(unknown), "108", "/dev/pts", true},
		{"devpts with no optional fields", mountinfoFixture(noOptional), "108", "/dev/pts", true},
		{"devpts with tab separated fields", strings.ReplaceAll(noOptional, " ", "\t") + "\n", "108", "/dev/pts", true},
		{"no devpts", mountinfoFixture(optional), "", "", false},
		{"empty input", "", "", "", false},
		{"two bind devpts records", mountinfoFixture(devpts, bindA), "", "", false},
		{"two devpts instances", mountinfoFixture(devpts, bindB), "", "", false},
		{"devpts named as mount source only", mountinfoFixture("120 22 0:54 / /srv/pts rw - tmpfs devpts rw"), "", "", false},
		{"missing filesystem type", mountinfoFixture("121 22 0:55 / /dev/pts rw - "), "", "", false},
		{"missing mount source", mountinfoFixture("121 22 0:55 / /dev/pts rw - devpts"), "", "", false},
		{"missing separator", mountinfoFixture("122 22 0:56 / /dev/pts rw devpts devpts rw"), "", "", false},
		{"two separators", mountinfoFixture("122 22 0:56 / /dev/pts rw - - devpts rw"), "", "", false},
		{"too few fields before separator", mountinfoFixture("123 22 0:57 / - devpts devpts rw"), "", "", false},
		{"non-numeric mount id", mountinfoFixture("x23 22 0:57 / /dev/pts rw - devpts devpts rw"), "", "", false},
		{"non-numeric parent id", mountinfoFixture("123 p22 0:57 / /dev/pts rw - devpts devpts rw"), "", "", false},
		{"devpts mount major:minor without colon", mountinfoFixture("126 22 047 / /dev/pts rw - devpts devpts rw"), "", "", false},
		{"non-numeric major", mountinfoFixture("126 22 0x:47 / /dev/pts rw - devpts devpts rw"), "", "", false},
		{"malformed line beside valid devpts", mountinfoFixture(devpts, "garbage"), "", "", false},
		{"lone separator beside valid devpts", mountinfoFixture(devpts, "-"), "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSingleDevptsMount([]byte(tc.data))
			if ok != tc.accept {
				t.Fatalf("accept = %v, want %v", ok, tc.accept)
			}
			if got.id != tc.id || got.path != tc.path {
				t.Fatalf("mount = %+v, want id %q path %q", got, tc.id, tc.path)
			}
			if !ok && got != (devptsMount{}) {
				t.Fatalf("rejected input returned %+v", got)
			}
		})
	}
}

// TestLinuxPeerDevptsMounts checks the read side of the devpts check against
// this process's own /proc entry: it accepts only when this process's real
// mountinfo parses to exactly one devpts mount, and always with that record's
// identity. A path with no mountinfo is unavailable.
func TestLinuxPeerDevptsMounts(t *testing.T) {
	base := "/proc/" + strconv.Itoa(os.Getpid())
	want, wantOK := parseSingleDevptsMount(mustReadMountinfo(t, base+"/mountinfo"))
	got, ok := peerDevptsMounts(base)
	if ok != wantOK || got != want {
		t.Fatalf("peerDevptsMounts(self) = %+v,%v want %+v,%v", got, ok, want, wantOK)
	}
	t.Logf("self mountinfo single devpts %+v ok=%v", want, wantOK)
	if _, ok := peerDevptsMounts(t.TempDir()); ok {
		t.Fatal("directory without mountinfo accepted")
	}
}

// mustReadMountinfo reads one real mountinfo file, failing the test if this
// host does not expose it.
func mustReadMountinfo(t *testing.T, path string) []byte {
	t.Helper()
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatalf("read %s: %v", path, e)
	}
	return data
}

// TestLinuxCurrentTTYIdentityRealPTY is the Linux client-side smoke test: the
// test binary's own controlling pty is attested through the devpts mount check
// and identified through the production CurrentTTYIdentity path. It skips only
// when the process truly has no controlling terminal (and fails instead under
// the PTY smoke fixture).
func TestLinuxCurrentTTYIdentityRealPTY(t *testing.T) {
	node, nodeDev := trustableTTYNode(t)
	name, peerID, e := CurrentTTYIdentity()
	if e != nil {
		t.Fatalf("CurrentTTYIdentity: %v", e)
	}
	unit, _ := devUnit(nodeDev)
	if name != node || peerID != encodeTTYPeerID(unit) {
		t.Fatalf("identity %q %q, want %q %q", name, peerID, node, encodeTTYPeerID(unit))
	}
	if got, ok := parseTTYPeerID(peerID); !ok || got != unit {
		t.Fatalf("peer id %q does not round trip to unit %d", peerID, unit)
	}
	var info unix.Stat_t
	if e := unix.Stat(name, &info); e != nil || uint64(info.Rdev) != nodeDev {
		t.Fatalf("stat %s does not confirm 0x%08x: %v", name, nodeDev, e)
	}
	t.Logf("attested controlling terminal %s dev=0x%08x unit=%d peer_id=%s", name, nodeDev, unit, peerID)
}
