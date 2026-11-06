//go:build windows

package teamsync

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func anchorDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, file, immediate bool) error {
	trusted := func(sid *windows.SID) bool {
		if sid.Equals(user) {
			return true
		}
		switch sid.String() {
		case "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
			return true
		}
		return false
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trusted(owner) {
		return ErrAnchor
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrAnchor
	}
	dangerous := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | 0x0040)
	if file {
		dangerous |= windows.GENERIC_READ | windows.GENERIC_WRITE | windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	if immediate {
		dangerous |= windows.GENERIC_WRITE | 0x0002 /* FILE_ADD_FILE */ | 0x0004 /* FILE_ADD_SUBDIRECTORY */ | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return ErrAnchor
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrAnchor
		}
		if uint32(ace.Mask)&dangerous != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return ErrAnchor
		}
	}
	return nil
}
func anchorWindowsChain(path string, file bool) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrAnchor
	}
	first := true
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return ErrAnchor
		}
		if first && file {
			if !st.Mode().IsRegular() || st.Size() > 8<<20 {
				return ErrAnchor
			}
		} else if !st.IsDir() {
			return ErrAnchor
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		immediate := first && !file || !first && current == filepath.Dir(path) && file
		if e != nil || anchorDescriptor(sd, user.User.Sid, first && file, immediate) != nil {
			return ErrAnchor
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedAnchorParent(path string) error { return anchorWindowsChain(path, false) }
func trustedAnchorFile(path string) error   { return anchorWindowsChain(path, true) }
func createAnchorFile(path string) (*os.File, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, ErrAnchor
	}
	sd, e := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return nil, ErrAnchor
	}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, ErrAnchor
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, ErrAnchor
	}
	return os.NewFile(uintptr(h), path), nil
}
func publishAnchorFile(tmp, path string) error {
	from, e := windows.UTF16PtrFromString(tmp)
	if e != nil {
		return e
	}
	to, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	// No MOVEFILE_REPLACE_EXISTING: the final name must still be absent.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
func openAnchorFile(path string, flags int) (*os.File, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, ErrAnchor
	}
	f, e := os.OpenFile(path, flags, 0600)
	if e != nil {
		return nil, ErrAnchor
	}
	after, e := f.Stat()
	user, ue := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || ue != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() > 8<<20 {
		f.Close()
		return nil, ErrAnchor
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || anchorDescriptor(sd, user.User.Sid, true, false) != nil {
		f.Close()
		return nil, ErrAnchor
	}
	return f, nil
}
