//go:build windows

package teamfiles

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The trusted identities are deliberately identical to descriptor's existing
// owner/ACE trust set: the current process user, Local System, BUILTIN\
// Administrators and TrustedInstaller. A directory leaf is private only when no
// other identity can read, list, traverse or write it, and no other identity
// has an inheritable ACE. Ancestors keep descriptor's existing
// readable-but-not-replaceable policy; they are not required to be unreadable.
func privateTrustedSID(sid, user *windows.SID) bool {
	if sid.Equals(user) {
		return true
	}
	switch sid.String() {
	case "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
		return true
	}
	return false
}

func privateDirectoryDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	if descriptor(sd, user, false, true, true) != nil {
		return ErrFile
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return ErrFile
	}
	read := uint32(windows.GENERIC_READ | windows.FILE_READ_DATA | windows.FILE_READ_EA |
		windows.FILE_READ_ATTRIBUTES | windows.FILE_TRAVERSE | windows.GENERIC_EXECUTE)
	inherit := uint32(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, n, &ace) != nil {
			return ErrFile
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrFile
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if privateTrustedSID(sid, user) {
			continue
		}
		if uint32(ace.Mask)&read != 0 || uint32(ace.Header.AceFlags)&inherit != 0 {
			return ErrFile
		}
	}
	return nil
}

func privateDirectory(path string) error {
	if chain(path, false, true) != nil {
		return ErrFile
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrFile
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrFile
	}
	return privateDirectoryDescriptor(sd, user.User.Sid)
}

func validatePrivateParent(path string) error {
	return privateDirectory(path)
}

func validatePrivateWorkspace(path string) error {
	return privateDirectory(path)
}

func validatePrivateFile(path string) error {
	if chain(path, true, true) != nil {
		return ErrFile
	}
	return nil
}

func ensurePrivateWorkspace(path string) error {
	if validatePrivateWorkspace(path) == nil {
		return nil
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrFile
	}
	if trustedParent(filepath.Dir(path)) != nil {
		return ErrFile
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrFile
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return ErrFile
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrFile
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) && !errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return ErrFile
		}
	}
	return validatePrivateWorkspace(path)
}
