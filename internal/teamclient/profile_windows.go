//go:build windows

package teamclient

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func profileDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, file, immediate bool) error {
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
		return ErrProfile
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrProfile
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
			return ErrProfile
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrProfile
		}
		if uint32(ace.Mask)&dangerous != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return ErrProfile
		}
	}
	return nil
}
func profileWindowsChain(path string, file bool) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrProfile
	}
	first := true
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return ErrProfile
		}
		if first && file {
			if !st.Mode().IsRegular() || st.Size() > 32<<20 {
				return ErrProfile
			}
		} else if !st.IsDir() {
			return ErrProfile
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		immediate := first && !file || !first && current == filepath.Dir(path) && file
		if e != nil || profileDescriptor(sd, user.User.Sid, first && file, immediate) != nil {
			return ErrProfile
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedProfileParent(path string) error { return profileWindowsChain(path, false) }
func trustedProfileFile(path string) error   { return profileWindowsChain(path, true) }
func createProfileFile(path string) (*os.File, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, ErrProfile
	}
	sd, e := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return nil, ErrProfile
	}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, ErrProfile
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, ErrProfile
	}
	return os.NewFile(uintptr(h), path), nil
}
func openProfileFile(path string, flags int) (*os.File, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, ErrProfile
	}
	f, e := os.OpenFile(path, flags, 0600)
	if e != nil {
		return nil, ErrProfile
	}
	after, e := f.Stat()
	user, ue := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || ue != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || !profileUniqueFile(path, after) || after.Size() > 32<<20 {
		f.Close()
		return nil, ErrProfile
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || profileDescriptor(sd, user.User.Sid, true, false) != nil {
		f.Close()
		return nil, ErrProfile
	}
	return f, nil
}

func lockProfileIdentity(f *os.File) error {
	var overlapped windows.Overlapped
	if windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) != nil {
		return ErrProfile
	}
	return nil
}

func equalProfilePath(a, b string) bool { return strings.EqualFold(a, b) }
func profileUniqueFile(path string, _ os.FileInfo) bool {
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) == nil && info.NumberOfLinks == 1
}
