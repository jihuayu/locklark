//go:build windows

package main

// Windows creation and verification of the passkey-transfer fixture files.
//
// Windows cannot express privacy with os.WriteFile/os.Chmod: those only toggle
// the read-only attribute and leave the inherited DACL in place, which grants
// SYSTEM, Administrators and often other principals read access. The transfer
// CLI refuses private inputs whose DACL grants read to another principal, so a
// POSIX-mode fixture is not equivalent here. These helpers therefore create the
// file with an explicit owner and a protected DACL, and the negative case
// installs a real Everyone read ACE instead of a mode bit. Outputs are checked
// against the same native ACL rules (owner is the current user, protected DACL,
// only trusted principals) rather than a meaningless Mode().Perm().

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const passkeyTransferEveryoneSID = "S-1-1-0"

func passkeyTransferCurrentSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, errors.New("current process user unavailable")
	}
	return user.User.Sid, nil
}

func passkeyTransferCurrentUserSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := passkeyTransferCurrentSID()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	return sid
}

// passkeyTransferWritePrivate creates an owner-protected, owner-only file.
func passkeyTransferWritePrivate(t *testing.T, path string, content []byte) {
	t.Helper()
	sid := passkeyTransferCurrentUserSID(t).String()
	passkeyTransferWriteFile(t, path, content, "O:"+sid+"D:P(A;;FA;;;"+sid+")")
}

// passkeyTransferWriteShared creates the same bytes but installs a real
// protected Everyone read ACE, the Windows equivalent of a 0644 fixture.
func passkeyTransferWriteShared(t *testing.T, path string, content []byte) {
	t.Helper()
	sid := passkeyTransferCurrentUserSID(t).String()
	passkeyTransferWriteFile(t, path, content, "O:"+sid+"D:P(A;;FA;;;"+sid+")(A;;FR;;;"+passkeyTransferEveryoneSID+")")
}

// passkeyTransferWriteFile recreates the path so CREATE_NEW always applies the
// exact descriptor, including when a test rewrites one fixture path with a
// different privacy class.
func passkeyTransferWriteFile(t *testing.T, path string, content []byte, sddl string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reset fixture file: %v", err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("fixture security descriptor: %v", err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("fixture path: %v", err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("create fixture file: %v", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		t.Fatalf("create fixture file: invalid file handle")
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		t.Fatalf("write fixture file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fixture file: %v", err)
	}
}

// passkeyTransferPrivateFileError reports whether path is a regular file owned
// by the current user with a protected DACL that names only trusted principals
// and grants the owner effective read/write access.
func passkeyTransferPrivateFileError(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("transfer fixture unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("transfer fixture is not a regular file")
	}
	current, err := passkeyTransferCurrentSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return errors.New("transfer fixture security descriptor unavailable")
	}
	owner, defaulted, err := sd.Owner()
	if err != nil || defaulted || owner == nil || !owner.Equals(current) {
		return errors.New("transfer fixture is not owned by the current user")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("transfer fixture DACL is not protected")
	}
	acl, defaulted, err := sd.DACL()
	if err != nil || defaulted || acl == nil {
		return errors.New("transfer fixture DACL unavailable")
	}
	ownerWritable := false
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil || ace == nil {
			return errors.New("transfer fixture DACL unreadable")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("transfer fixture DACL has a non-allow entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !passkeyTransferTrustedOutputSID(sid, current) {
			return errors.New("transfer fixture DACL grants another principal")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 && sid.Equals(current) &&
			uint32(ace.Mask)&(windows.FILE_READ_DATA|windows.FILE_WRITE_DATA) == windows.FILE_READ_DATA|windows.FILE_WRITE_DATA {
			ownerWritable = true
		}
	}
	if !ownerWritable {
		return errors.New("transfer fixture DACL does not grant the owner read/write")
	}
	return nil
}

// passkeyTransferTrustedOutputSID mirrors the typed-file reader: only the
// current user, LocalSystem and Builtin Administrators may hold an ACE. In
// particular an Everyone allow ACE fails even when its mask would not be enough
// to read the file.
func passkeyTransferTrustedOutputSID(sid, current *windows.SID) bool {
	return sid.Equals(current) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// passkeyTransferAssertOwnerPrivate fails the test unless the path is an
// owner-private regular file. It never prints file content.
func passkeyTransferAssertOwnerPrivate(t *testing.T, path string) {
	t.Helper()
	if err := passkeyTransferPrivateFileError(path); err != nil {
		t.Fatalf("output is not an owner-private regular file: %v", err)
	}
}
