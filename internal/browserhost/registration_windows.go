package browserhost

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func registrationTrustedSID(sid, user *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.Equals(user) {
		return true
	}
	switch sid.String() {
	case "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
		return true
	}
	return false
}
func registrationDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, file bool) error {
	owner, _, e := sd.Owner()
	if e != nil || !registrationTrustedSID(owner, user) {
		return ErrProtocol
	}
	// For directories the data/append bits mean ADD_FILE/ADD_SUBDIRECTORY.
	// Reject unrelated creation as well as replacement and ACL changes.
	mask := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x0040)
	return registrationACL(sd, user, mask)
}

// Higher existing ancestors may allow creation of unrelated new children. Each
// existing child in our path is checked separately and cannot be deleted,
// replaced or have its ACL/owner changed by that principal. The immediate
// publication/binary parent always uses the stricter descriptor above.
func registrationAncestorDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	owner, _, e := sd.Owner()
	if e != nil || !registrationTrustedSID(owner, user) {
		return ErrProtocol
	}
	return registrationACL(sd, user, uint32(windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.GENERIC_ALL|windows.GENERIC_WRITE|windows.FILE_WRITE_EA|windows.FILE_WRITE_ATTRIBUTES|0x0040))
}
func registrationACL(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, dangerous uint32) error {
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrProtocol
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return ErrProtocol
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrProtocol
		}
		if uint32(ace.Mask)&dangerous != 0 && !registrationTrustedSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user) {
			return ErrProtocol
		}
	}
	return nil
}
func registrationChain(path string, file bool) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrProtocol
	}
	first := file
	depth := 0
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil || first && !st.Mode().IsRegular() || !first && !st.IsDir() {
			return ErrProtocol
		}
		wide, e := windows.UTF16PtrFromString(current)
		if e != nil {
			return ErrProtocol
		}
		attrs, e := windows.GetFileAttributes(wide)
		if e != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrProtocol
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			return ErrProtocol
		}
		var trustErr error
		if depth == 0 || file && depth == 1 {
			trustErr = registrationDescriptor(sd, user.User.Sid, first)
		} else {
			trustErr = registrationAncestorDescriptor(sd, user.User.Sid)
		}
		if trustErr != nil {
			return ErrProtocol
		}
		first = false
		depth++
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedRegistrationParent(dir string) error { return registrationChain(dir, false) }
func trustedRegistrationFile(path string, executable bool) error {
	if registrationChain(path, true) != nil {
		return ErrProtocol
	}
	wide, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return ErrProtocol
	}
	handle, e := windows.CreateFile(wide, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return ErrProtocol
	}
	f := os.NewFile(uintptr(handle), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return ErrProtocol
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrProtocol
	}
	sd, e := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrProtocol
	}
	return registrationDescriptor(sd, user.User.Sid, true)
}
func registrationAttributes() (*windows.SecurityAttributes, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		return nil, e
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}
func createRegistrationDirectory(path string) error {
	attributes, e := registrationAttributes()
	if e != nil {
		return e
	}
	wide, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	return windows.CreateDirectory(wide, attributes)
}
func privateRegistrationTemp(dir string) (*os.File, error) {
	attributes, e := registrationAttributes()
	if e != nil {
		return nil, e
	}
	for n := 0; n < 8; n++ {
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return nil, e
		}
		path := filepath.Join(dir, ".locklark-native-"+hex.EncodeToString(b[:])+".tmp")
		wide, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return nil, e
		}
		handle, e := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if e == windows.ERROR_FILE_EXISTS {
			continue
		}
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(handle), path), nil
	}
	return nil, ErrProtocol
}
func publishRegistrationTemp(temp, target string, replace bool) error {
	from, e := windows.UTF16PtrFromString(temp)
	if e != nil {
		return e
	}
	to, e := windows.UTF16PtrFromString(target)
	if e != nil {
		return e
	}
	if replace {
		return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	}
	return windows.MoveFile(from, to)
}
