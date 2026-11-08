//go:build windows

package main

// Bounded, owner-only read of `personal add-item --input` on Windows.
//
// CreateFile opens the final reparse point itself, so a symlink/junction is
// detected rather than followed. The handle must be a disk file, owned by the
// current process user, with a non-nil DACL that grants access only to the
// current user, LocalSystem or Builtin Administrators. Unknown ACE types and
// any ACE for another principal are refused. Any error is the fixed
// errTypedInputRefused and a partially read buffer is cleared.

import (
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readTypedPersonalFile(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errTypedInputRefused
	}
	handle, err := windows.CreateFile(
		name,
		windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, errTypedInputRefused
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errTypedInputRefused
	}
	defer file.Close()

	fileType, err := windows.GetFileType(handle)
	if err != nil || fileType != windows.FILE_TYPE_DISK {
		return nil, errTypedInputRefused
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, errTypedInputRefused
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, errTypedInputRefused
	}
	size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	if size < 0 || size > maxTypedInputBytes {
		return nil, errTypedInputRefused
	}
	if !validPrivateTypedWindowsSecurity(handle) {
		return nil, errTypedInputRefused
	}

	raw, err := io.ReadAll(io.LimitReader(file, int64(maxTypedInputBytes)+1))
	if err != nil || len(raw) > maxTypedInputBytes {
		clear(raw)
		return nil, errTypedInputRefused
	}
	return raw, nil
}

func validPrivateTypedWindowsSecurity(handle windows.Handle) bool {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return false
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	owner, defaulted, err := sd.Owner()
	if err != nil || defaulted || owner == nil || !owner.Equals(current.User.Sid) {
		return false
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || defaulted || dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return false
		}
		// Only plain allow ACEs are understood. Audit, deny, object and
		// conditional ACEs are refused rather than guessed at.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !trustedTypedFileSID(sid, current.User.Sid) {
			return false
		}
	}
	return true
}

// trustedTypedFileSID is the complete set of principals allowed to hold an ACE
// on the private input file. In particular, an ACE for any other user or group
// is refused even when its mask happens not to include FILE_READ_DATA.
func trustedTypedFileSID(sid, current *windows.SID) bool {
	return sid.Equals(current) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}
