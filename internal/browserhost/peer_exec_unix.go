//go:build unix

package browserhost

import (
	"io/fs"
	"os"
	"strconv"
	"syscall"
)

// platformFileOwner reads the owning uid from the non-portable stat record.
func platformFileOwner(info fs.FileInfo) (uid uint32, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// trustedPeerExecutable accepts a browser host at any directory only when the
// canonical path is a regular file with a group/other write-free mode, an owner
// execute bit, and ownership by the effective user that the socket check
// authenticated the peer against.
func trustedPeerExecutable(process, peerUser, goos string) bool {
	uid := os.Geteuid()
	if goos == "windows" || peerUser != "UID "+strconv.Itoa(uid) {
		return false
	}
	info, e := os.Stat(process)
	if e != nil {
		return false
	}
	owner, ok := platformFileOwner(info)
	return ok && owner == uint32(uid) && trustedPeerExecMode(info.Mode())
}

// trustedPeerExecMode requires a plain permission mode: no type or setuid/
// setgid/sticky bits, owner execute, and no group or other write.
func trustedPeerExecMode(mode fs.FileMode) bool {
	return mode == mode.Perm() && mode.IsRegular() && mode&0o100 != 0 && mode&0o022 == 0
}
