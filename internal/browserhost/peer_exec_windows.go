//go:build windows

package browserhost

import (
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows does not expose POSIX owner/group bits through fs.FileInfo. The
// equivalent trust facts come from the file security descriptor instead.

// trustedPeerExecutable accepts a browser host at any directory only when the
// canonical path is a regular file owned by the SID that authenticated the peer
// (Peer.User), with no allow ACE granting write, delete, ACL or ownership
// rights to any other SID, and whose on-disk bytes start with a PE image
// header. Reparse points are refused even though canonicalExecutablePath
// already resolved them.
func trustedPeerExecutable(process, peerUser, goos string) bool {
	if goos != "windows" || !strings.HasPrefix(process, `\\?\`) {
		if !filepath.IsAbs(process) {
			return false
		}
	}
	if !strings.HasPrefix(peerUser, "SID S-") {
		return false
	}
	sid, e := windows.StringToSid(strings.TrimPrefix(peerUser, "SID "))
	if e != nil || sid == nil {
		return false
	}
	wide, e := windows.UTF16PtrFromString(process)
	if e != nil {
		return false
	}
	if attrs, e := windows.GetFileAttributes(wide); e != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return false
	}
	handle, e := windows.CreateFile(wide, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return false
	}
	f := os.NewFile(uintptr(handle), process)
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !trustedPeerExecMode(info.Mode()) {
		return false
	}
	sd, e := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || peerExecDescriptor(sd, sid) != nil {
		return false
	}
	return peerExecutableImage(f)
}

// trustedPeerExecMode is the os-level half on Windows: a plain regular file
// (os never reports execute bits or group/other modes there).
func trustedPeerExecMode(mode fs.FileMode) bool {
	return mode == mode.Perm() && mode.IsRegular()
}

func peerExecDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.Equals(user) {
		return ErrProtocol
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrProtocol
	}
	dangerous := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES)
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return ErrProtocol
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			// Object-typed allow ACEs do not expose a well-formed SID at
			// SidStart, so their mask cannot be attributed to any SID.
			return ErrProtocol
		}
		if uint32(ace.Mask)&dangerous != 0 && !user.Equals((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return ErrProtocol
		}
	}
	return nil
}

// peerExecutableImage checks the DOS and PE headers so a script or data file
// renamed to .exe is not treated as the browser host.
func peerExecutableImage(f *os.File) bool {
	var dos [0x40]byte
	if _, e := io.ReadFull(f, dos[:]); e != nil || dos[0] != 'M' || dos[1] != 'Z' {
		return false
	}
	offset := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	if offset < int64(len(dos)) || offset > 1<<20 {
		return false
	}
	var pe [4]byte
	if _, e := f.ReadAt(pe[:], offset); e != nil {
		return false
	}
	return pe[0] == 'P' && pe[1] == 'E' && pe[2] == 0 && pe[3] == 0
}
