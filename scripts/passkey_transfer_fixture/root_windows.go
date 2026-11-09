//go:build windows

package main

// Windows private-root policy for the passkey transfer acceptance fixture.
//
// Windows has no 0700 mode: os.Chmod only toggles the read-only attribute and
// an inherited DACL normally grants SYSTEM, Administrators and often other
// principals read access. The fixture therefore checks the native security
// descriptor instead of POSIX permission bits: the root must be an absolute,
// clean directory (never a reparse point) owned by the current user with a
// protected DACL that names only the current user, LocalSystem, Builtin
// Administrators and TrustedInstaller. Any other principal, including
// Everyone, is refused even when its mask happens to be harmless.

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// privateRoot requires an absolute, clean, owner-private directory.
func privateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errFixtureRefused
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errFixtureRefused
	}
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return errFixtureRefused
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errFixtureRefused
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errFixtureRefused
	}
	sd, err := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return errFixtureRefused
	}
	owner, defaulted, err := sd.Owner()
	// Elevated creators may be assigned Administrators as owner; the DACL is
	// still required to be the explicit current-user-only policy below.
	if err != nil || defaulted || owner == nil || !(owner.Equals(user.User.Sid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return errFixtureRefused
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errFixtureRefused
	}
	acl, defaulted, err := sd.DACL()
	if err != nil || defaulted || acl == nil || acl.AceCount == 0 {
		return errFixtureRefused
	}
	effective := false
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errFixtureRefused
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !trustedRootSID(sid, user.User.Sid) {
			return errFixtureRefused
		}
		effective = true
	}
	if !effective {
		return errFixtureRefused
	}
	return nil
}

// trustedRootSID is the complete set of principals allowed to hold an effective
// ACE on the private root.
func trustedRootSID(sid, current *windows.SID) bool {
	if sid.Equals(current) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	// TrustedInstaller secures OS-managed content; x/sys/windows has no named
	// constant for this well-known SID.
	const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	return sid.IsValid() && sid.String() == trustedInstaller
}
