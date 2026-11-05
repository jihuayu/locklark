package management

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func trustedDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, file bool) error {
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
		return ErrUnavailable
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrUnavailable
	}
	// Ancestors must not let unrelated users replace existing children or change
	// access control. Mere permission to create a new root-level directory is not
	// permission to overwrite an existing protected configuration path.
	dangerous := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | 0x0040 /* FILE_DELETE_CHILD */)
	if file {
		dangerous |= windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return ErrUnavailable
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrUnavailable
		}
		if uint32(ace.Mask)&dangerous != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return ErrUnavailable
		}
	}
	return nil
}
func openTrustedConfiguration(path string) (*os.File, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, ErrUnavailable
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, ErrUnavailable
	}
	first := true
	for current := absolute; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
		if first && (!st.Mode().IsRegular() || st.Size() > 64<<10) || !first && !st.IsDir() {
			return nil, ErrUnavailable
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil || trustedDescriptor(sd, user.User.Sid, first) != nil {
			return nil, ErrUnavailable
		}
		first = false
		if filepath.Dir(current) == current {
			break
		}
	}
	f, e := os.Open(absolute)
	if e != nil {
		return nil, ErrUnavailable
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 {
		f.Close()
		return nil, ErrUnavailable
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || trustedDescriptor(sd, user.User.Sid, true) != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

func trustedConnectionParent(path string) error {
	current, e := filepath.Abs(filepath.Dir(path))
	if e != nil {
		return ErrUnavailable
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrUnavailable
	}
	for {
		st, e := os.Lstat(current)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil || trustedDescriptor(sd, user.User.Sid, false) != nil {
			return ErrUnavailable
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}
func privateConnectionFile(f *os.File) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrUnavailable
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrUnavailable
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrUnavailable
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return ErrUnavailable
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrUnavailable
		}
		if uint32(ace.Mask)&uint32(windows.FILE_READ_DATA|windows.GENERIC_READ|windows.GENERIC_ALL) != 0 && !((*windows.SID)(unsafe.Pointer(&ace.SidStart))).Equals(user.User.Sid) {
			return ErrUnavailable
		}
	}
	return nil
}
