//go:build linux

package browserhost

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// ttyMajor is the devpts major number on Linux.
const ttyMajor = 136

// ttyCharDevice is the Linux S_IFCHR file type.
const ttyCharDevice = unix.S_IFCHR

// linuxDev is one dev_t in the kernel's new_encode_dev form used by tty_nr and
// stat: major in bits 8-19, minor in the low 8 bits plus bits 20-31.
func linuxDev(major, minor uint32) uint64 {
	return uint64(major)<<8 | uint64(minor&0xff) | uint64(minor&0xfff00)<<12
}

// devMajor and devMinor decode one stat / tty_nr device number.
func devMajor(dev uint64) uint32 { return uint32(dev>>8) & 0xfff }
func devMinor(dev uint64) uint32 { return uint32(dev&0xff) | uint32(dev>>12)&0xfff00 }

// devUnit returns the terminal unit of one Linux tty device number. The unit
// is the devpts minor, and /dev/pts/0 is a valid pty session terminal, so
// minor zero is a unit like any other; only another major has no unit here.
func devUnit(dev uint64) (uint32, bool) {
	if devMajor(dev) != ttyMajor {
		return 0, false
	}
	return devMinor(dev), true
}

// handleTTYIdentity verifies an opened terminal handle (fstat device and
// whether it is a character device) against the kernel-attested controlling
// terminal, and returns the terminal unit. Linux reports one device encoding
// for both tty_nr and stat, so the handle must be exactly the attested device.
func handleTTYIdentity(attestedDev, handleDev uint64, charDevice bool) (uint32, bool) {
	if !charDevice || handleDev == 0 || handleDev != attestedDev {
		return 0, false
	}
	return devUnit(handleDev)
}

// cliRunTTYAttestedPlatform reports whether this build can attest a peer's
// controlling terminal. Every CLI-run is unavailable when it cannot.
func cliRunTTYAttestedPlatform() bool { return true }

// peerTTYAttestationAvailable is false for this legacy AttestCLIRunTTY path.
// Linux tty_nr alone names only a devpts major/minor, and nothing here
// distinguishes two terminal instances that reuse it. A separate same-session
// CLI-run proof path can qualify a connection; this constant is not a global
// gate and never authorizes that path by itself.
const peerTTYAttestationAvailable = false

// peerControllingTerminal returns the kernel-reported controlling terminal of
// one live process: field 7 (tty_nr) of /proc/PID/stat, encoded with the
// kernel's own dev_t encoding (new_encode_dev). Nothing the peer writes can
// choose this value. The peer's fd 0 is not consulted: it is the peer's
// descriptor table, not its controlling terminal.
//
// A tty_nr is only a devpts major/minor, and separate devpts mounts in
// different mount namespaces, or in one mount namespace, can reuse it, so the
// peer's mount namespace must be this broker's and the peer's mountinfo must
// name exactly one devpts mount before tty_nr names this broker's /dev/pts/N.
// The namespace identity and the mountinfo read are compared before and after
// reading stat, so a peer that changes mount namespace or mounts while it is
// looked up is rejected rather than resolved against either view.
//
// This lookup supports the client's self-description (CurrentTTYIdentity). The
// separate same-session association also uses it as one parser, but tty_nr
// alone is not a peer-CTTY association and is never sufficient authority.
func peerControllingTerminal(pid int) (path string, rdev uint64, unit uint32, ok bool) {
	if pid <= 0 {
		return "", 0, 0, false
	}
	base := "/proc/" + strconv.Itoa(pid)
	before, ok := peerDevptsMounts(base)
	if !ok {
		return "", 0, 0, false
	}
	stat, e := os.ReadFile(base + "/stat")
	if e != nil {
		return "", 0, 0, false
	}
	after, ok := peerDevptsMounts(base)
	if !ok || !after.equal(before) {
		return "", 0, 0, false
	}
	// tty_nr is field 7 (1-based). Fields after the parenthesised command
	// name start at field 3, so tty_nr is the fifth token in that tail.
	end := -1
	for i := len(stat) - 1; i >= 0; i-- {
		if stat[i] == ')' {
			end = i
			break
		}
	}
	if end < 0 {
		return "", 0, 0, false
	}
	var fields [5][]byte
	tokens := 0
	start := -1
	for i := end + 1; i < len(stat) && tokens < len(fields); i++ {
		if stat[i] == ' ' {
			if start >= 0 {
				fields[tokens] = stat[start:i]
				tokens++
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 && tokens < len(fields) {
		fields[tokens] = stat[start:]
		tokens++
	}
	if tokens < len(fields) {
		return "", 0, 0, false
	}
	tty, e := strconv.ParseInt(string(fields[4]), 10, 64)
	if e != nil {
		return "", 0, 0, false
	}
	dev, ok := ttyNrDev(tty)
	if !ok {
		return "", 0, 0, false
	}
	path, ok = attestedTTYNode(dev)
	if !ok {
		return "", 0, 0, false
	}
	minor, _ := devUnit(dev)
	return path, dev, minor, true
}

// devptsMount is the identity of the one devpts mount a peer's mountinfo may
// name: the mount ID and mount point of PTS 9. Every other field of a devpts
// record is kernel-owned mount state and can change after a remount, so it is
// not compared.
type devptsMount struct {
	id   string
	path string
}

// equal reports whether two reads observe the same single devpts mount.
func (d devptsMount) equal(other devptsMount) bool {
	return d.id != "" && d == other
}

// peerDevptsMounts verifies that base's process shares this broker's mount
// namespace and names exactly one devpts mount in /proc/PID/mountinfo, and
// returns that mount's identity. A read error, a namespace mismatch, any
// malformed mountinfo line, no devpts record, or more than one devpts record
// (for example a bind mount or a second devpts instance in one namespace) is
// ambiguous and returns false.
func peerDevptsMounts(base string) (devptsMount, bool) {
	if _, ok := mountNamespacePath(base + "/ns/mnt"); !ok {
		return devptsMount{}, false
	}
	data, e := os.ReadFile(base + "/mountinfo")
	if e != nil {
		return devptsMount{}, false
	}
	return parseSingleDevptsMount(data)
}

// parseSingleDevptsMount parses /proc/PID/mountinfo and returns the identity of
// its single devpts mount. Each line is split on whitespace (spaces, tabs and
// newlines inside paths and sources are kernel-escaped, so they never split a
// field) and must be one well-formed record: mount ID, parent ID,
// major:minor, root, mount point and mount options, then exactly one "-"
// separator, then exactly filesystem type, mount source and super options. The
// IDs and major:minor must parse as integers. The optional fields between mount
// options and the separator are zero or more tag[:value] tokens; unknown tags
// are ignored, as the kernel's documentation requires. The filesystem type is
// the first field after "-". Any malformed line rejects the whole input, so
// no listing is ever trusted partially.
func parseSingleDevptsMount(data []byte) (devptsMount, bool) {
	var found devptsMount
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		sep := -1
		for i, field := range fields {
			if field == "-" {
				sep = i
				break
			}
		}
		// After "-" the kernel writes exactly three fields: filesystem type,
		// mount source and super options. A record with fewer or more fields is
		// incomplete or contrary to the documented format and is rejected.
		if sep < 6 || len(fields) != sep+4 {
			return devptsMount{}, false
		}
		if !decimalUint(fields[0]) || !decimalUint(fields[1]) || !majorMinor(fields[2]) {
			return devptsMount{}, false
		}
		if fields[sep+1] == "devpts" {
			count++
			found = devptsMount{id: fields[0], path: fields[4]}
		}
	}
	if count != 1 {
		return devptsMount{}, false
	}
	return found, true
}

// decimalUint reports whether s is one or more decimal digits.
func decimalUint(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// majorMinor reports whether s is one decimal major:minor pair.
func majorMinor(s string) bool {
	major, minor, ok := strings.Cut(s, ":")
	return ok && decimalUint(major) && decimalUint(minor)
}

// mountNamespacePath stats one /proc/PID/ns/mnt link and accepts it only when
// it identifies this broker's own mount namespace (/proc/self/ns/mnt). Any
// failure to stat either side, an unreadable namespace, or a distinct
// namespace file identity is a mismatch and fails closed. The comparison uses
// os.SameFile on os.Stat results, whose FileInfo describes the namespace
// object the link resolves to, not the /proc link itself.
func mountNamespacePath(path string) (os.FileInfo, bool) {
	self, err := os.Stat("/proc/self/ns/mnt")
	if err != nil {
		return nil, false
	}
	peer, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if !os.SameFile(self, peer) {
		return nil, false
	}
	return peer, true
}

// ttyNrDev decodes field 7 (tty_nr) of /proc/PID/stat into a dev_t. The kernel
// formats tty_nr as a signed int holding new_encode_dev(): minors above the
// low 8 bits set the 32-bit sign bit (e.g. minor 524288 is 0x80008800, printed
// as -2147448832), so the value is taken modulo 2^32 without sign extension.
// Zero means no controlling terminal, and a value outside int32 cannot be a
// kernel tty_nr; both are rejected rather than guessed at.
func ttyNrDev(tty int64) (uint64, bool) {
	if tty == 0 || tty < math.MinInt32 || tty > math.MaxInt32 {
		return 0, false
	}
	return uint64(uint32(tty)), true
}

// attestedTTYNode accepts a kernel-reported device only when its single
// possible /dev/pts/N node both has the shape this build derives and stats to
// that same device under the local path policy. The path is display text only
// after that stat, so a stale or forged device number never names a node.
func attestedTTYNode(dev uint64) (path string, ok bool) {
	minor, ok := devUnit(dev)
	if !ok {
		return "", false
	}
	path = "/dev/pts/" + strconv.FormatUint(uint64(minor), 10)
	if !cliRunTTYPathValid(path) {
		return "", false
	}
	if _, statDev, nodeUnit, statOK := ttyNodeIdentity(path); !statOK || statDev != dev || nodeUnit != minor {
		return "", false
	}
	return path, true
}

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

// ttyNodeIdentity stats one terminal node under the local path policy.
func ttyNodeIdentity(path string) (node string, dev uint64, unit uint32, ok bool) {
	if !cliRunTTYNameValid(path) || !trustedTTYDevice(path) {
		return "", 0, 0, false
	}
	var info unix.Stat_t
	if unix.Stat(path, &info) != nil || info.Mode&unix.S_IFMT != ttyCharDevice || info.Rdev == 0 {
		return "", 0, 0, false
	}
	dev = uint64(info.Rdev)
	minor, valid := devUnit(dev)
	if !valid {
		return "", 0, 0, false
	}
	return path, dev, minor, true
}

// openTTYNode opens one kernel-derived terminal node for reading and writing.
// O_NOCTTY keeps the open from ever becoming this process's controlling
// terminal; O_NONBLOCK keeps it from waiting on carrier. The path must be the
// exact /dev/pts/N shape peerControllingTerminal produced.
func openTTYNode(path string) (*os.File, error) {
	if _, ok := linuxPTSUnitOfName(path); !ok || !cliRunTTYPathValid(path) {
		return nil, errCLIRunUnavailable
	}
	f, e := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if e != nil || f == nil {
		return nil, errCLIRunUnavailable
	}
	return f, nil
}

// linuxPTSUnitOfName extracts the minor of one exactly shaped /dev/pts/N
// path (decimal digits, no sign, no leading zero unless it is just "0").
func linuxPTSUnitOfName(path string) (uint32, bool) {
	const prefix = "/dev/pts/"
	if !strings.HasPrefix(path, prefix) {
		return 0, false
	}
	digits := path[len(prefix):]
	if digits == "" || len(digits) > 10 || digits[0] == '0' && len(digits) > 1 {
		return 0, false
	}
	minor, e := strconv.ParseUint(digits, 10, 32)
	return uint32(minor), e == nil
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
