//go:build darwin

package browserhost

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// cliRunTTYAttestedPlatform reports whether this build can attest a peer's
// controlling terminal. Every CLI-run is unavailable when it cannot.
func cliRunTTYAttestedPlatform() bool { return true }

// peerTTYAttestationAvailable reports whether this build can prove, from the
// kernel, that a peer's controlling terminal is the terminal object this
// broker inspects. kinfo_proc.e_tdev names the peer's session controlling
// terminal, and the matching /dev/ttysNNN node is stat'ed against it.
const peerTTYAttestationAvailable = true

// ttyCharDevice is the Darwin S_IFCHR file type.
const ttyCharDevice = unix.S_IFCHR

// ttyMajor is the Darwin tty major number: every pty live node is
// /dev/ttysNNN, and a pty session's kinfo_proc.e_tdev names that node.
// A real PTY probe reports e_tdev 0x10000001 and both stat(/dev/ttys001) and
// fstat(open(/dev/ttys001)) report the same raw Rdev 0x10000001 (major 16,
// minor 1), so e_tdev and the node's st_rdev share one encoding.
const ttyMajor = 16

// maxTTYUnit is the largest unit a live pty node can have: /dev/ttysNNN is
// three digits, and /dev/ttys000 (unit zero) is a valid pty session.
const maxTTYUnit = 999

// darwinTTYUnset is the kernel's "no controlling terminal" e_tdev.
const darwinTTYUnset = int32(-1)

// darwinDev is one Darwin dev_t in the raw form the kernel reports for a pty
// session: 8-bit major in bits 24-31 and the minor in bits 0-23, so
// /dev/ttysNNN has e_tdev and st_rdev 0x10000000|NNN.
func darwinDev(major, minor uint32) uint64 { return uint64(major)<<24 | uint64(minor&0xffffff) }

// devUnit returns the terminal unit of one Darwin tty device number, in the
// raw encoding shared by e_tdev and a live node's st_rdev. Unit zero is a
// valid pty; only a non-tty major or an unnameable unit has none. /dev/tty is
// a cloning-device alias (major 2) and is never a terminal identity here.
func devUnit(dev uint64) (uint32, bool) {
	if dev == 0 || uint32(dev>>24) != ttyMajor {
		return 0, false
	}
	unit := uint32(dev & 0xffffff)
	if unit > maxTTYUnit {
		return 0, false
	}
	return unit, true
}

// handleTTYIdentity verifies an opened terminal handle against the
// kernel-attested controlling terminal: the handle must be a character device
// whose fstat Rdev is exactly the attested device and whose major names a pty.
// It returns the terminal unit.
func handleTTYIdentity(attestedDev, handleDev uint64, charDevice bool) (uint32, bool) {
	if !charDevice || handleDev == 0 || handleDev != attestedDev {
		return 0, false
	}
	return devUnit(handleDev)
}

// attestedTTYNode accepts a kernel-reported device only when its single
// possible /dev node both has the shape this build derives and stats to that
// same device under the local path policy. The path is display text only
// after that stat, so a stale or forged device number never names a node.
func attestedTTYNode(dev uint64) (path string, ok bool) {
	unit, ok := devUnit(dev)
	if !ok {
		return "", false
	}
	path = darwinTTYPath(unit)
	if !cliRunTTYNameValid(path) {
		return "", false
	}
	if _, statDev, nodeUnit, statOK := ttyNodeIdentity(path); !statOK || statDev != dev || nodeUnit != unit {
		return "", false
	}
	return path, true
}

// peerControllingTerminal returns the kernel-reported controlling terminal of
// one live process: kinfo_proc.e_tdev, the dev_t of the peer's session
// controlling terminal. Nothing the peer writes can choose this value. The fd
// shortcut (/dev/fd/PID/0) is deliberately not used: it reads the peer's
// descriptor table, not its controlling terminal, and a peer can point fd 0 at
// any terminal it holds. /dev/tty is not used either: it is a cloning-device
// alias whose rdev is not the controlling terminal's identity.
//
// The device is mapped back to the single /dev node that names it, and that
// node is accepted only when stat proves it is exactly this device under the
// local path policy. unit is the terminal's own unit number.
func peerControllingTerminal(pid int) (path string, rdev uint64, unit uint32, ok bool) {
	if pid <= 0 {
		return "", 0, 0, false
	}
	// kern.proc.pid always fills exactly one kinfo_proc, and the PID in the
	// answer must be the requested one, so a vanished or reused PID never
	// contributes another process's terminal.
	kinfo, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if e != nil || kinfo == nil || int(kinfo.Proc.P_pid) != pid || !darwinDevValid(kinfo.Eproc.Tdev) {
		return "", 0, 0, false
	}
	// e_tdev is an int32. Only -1 marks "no terminal"; any other negative
	// value is not a device this build understands and yields no ttysNNN
	// node, but refuse it here instead of relying on that.
	if kinfo.Eproc.Tdev < 0 {
		return "", 0, 0, false
	}
	dev := uint64(uint32(kinfo.Eproc.Tdev))
	path, ok = attestedTTYNode(dev)
	if !ok {
		return "", 0, 0, false
	}
	unit, _ = devUnit(dev)
	return path, dev, unit, true
}

// darwinTTYPath is the one node name for a pty unit this build can attest:
// /dev/ttysNNN, zero padded to three digits.
func darwinTTYPath(unit uint32) string {
	if unit > maxTTYUnit {
		return ""
	}
	var digits [3]byte
	digits[0] = byte('0' + unit/100)
	digits[1] = byte('0' + unit/10%10)
	digits[2] = byte('0' + unit%10)
	return "/dev/ttys" + string(digits[:])
}

// darwinTTYUnitOfName extracts the unit of one exactly shaped /dev/ttysNNN
// path, or reports false for any other path shape.
func darwinTTYUnitOfName(path string) (uint32, bool) {
	const prefix = "/dev/ttys"
	if !strings.HasPrefix(path, prefix) || len(path) != len(prefix)+3 {
		return 0, false
	}
	var unit uint32
	for _, c := range []byte(path[len(prefix):]) {
		if c < '0' || c > '9' {
			return 0, false
		}
		unit = unit*10 + uint32(c-'0')
	}
	return unit, true
}

// darwinDevValid reports whether the kernel reported a controlling terminal.
// The sign extension of the int32 field is stripped by the uint32 conversion.
func darwinDevValid(dev int32) bool { return dev != 0 && dev != darwinTTYUnset }

// TTYPeerIdentity returns the OS identity of one terminal device path: its
// device type and device number. ok is false unless path is a character
// device the local path policy accepts, so symlinks, FIFOs, regular files,
// and paths owned or writable by another account never become an identity.
func TTYPeerIdentity(path string) (device uint32, rdev uint64, ok bool) {
	_, dev, _, ok := ttyNodeIdentity(path)
	if !ok {
		return 0, 0, false
	}
	return ttyCharDevice, dev, true
}

// ttyNodeIdentity stats one terminal node under the local path policy. The
// node name must be /dev/ttysNNN and its raw st_rdev must be exactly that
// unit under the pty major, so the returned device is directly comparable
// with kinfo_proc.e_tdev.
func ttyNodeIdentity(path string) (node string, dev uint64, unit uint32, ok bool) {
	if !cliRunTTYNameValid(path) || !trustedTTYDevice(path) {
		return "", 0, 0, false
	}
	unit, ok = darwinTTYUnitOfName(path)
	if !ok || unit > maxTTYUnit {
		return "", 0, 0, false
	}
	var info unix.Stat_t
	if unix.Stat(path, &info) != nil || info.Mode&unix.S_IFMT != ttyCharDevice || info.Rdev == 0 {
		return "", 0, 0, false
	}
	dev = uint64(info.Rdev)
	if dev != darwinDev(ttyMajor, unit) {
		return "", 0, 0, false
	}
	return path, dev, unit, true
}

// openTTYNode opens one kernel-derived terminal node for reading and writing.
// O_NOCTTY keeps the open from ever becoming this process's controlling
// terminal; O_NONBLOCK keeps it from waiting on carrier. The path must be the
// exact /dev/ttysNNN shape the kernel lookup produced.
func openTTYNode(path string) (*os.File, error) {
	if _, ok := darwinTTYUnitOfName(path); !ok || !cliRunTTYPathValid(path) {
		return nil, errCLIRunUnavailable
	}
	f, e := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if e != nil || f == nil {
		return nil, errCLIRunUnavailable
	}
	return f, nil
}

// fstatTTYHandle returns the device number and character-device type of one
// open handle. It reads the handle itself with fstat, never a path name.
func fstatTTYHandle(f *os.File) (dev uint64, charDevice bool, ok bool) {
	raw, e := f.SyscallConn()
	if e != nil {
		return 0, false, false
	}
	var info unix.Stat_t
	var statErr error
	if raw.Control(func(fd uintptr) {
		statErr = unix.Fstat(int(fd), &info)
	}) != nil || statErr != nil || info.Rdev == 0 {
		return 0, false, false
	}
	return uint64(info.Rdev), info.Mode&unix.S_IFMT == ttyCharDevice, true
}

// trustedTTYDevice is the local path policy for a terminal device: the
// device itself and every ancestor directory must be owned by this user or
// root, must not be a symlink, and the final component must be a device. Other
// accounts must not be able to replace the path a peer's terminal is named by.
var trustedTTYDevice = func(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, current), current)
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return false
		}
	}
	return true
}
