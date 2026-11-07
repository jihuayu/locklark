//go:build windows

package personal

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writePrivateRunFile creates a new file with a protected, current-user-only
// DACL before any content is written. Sharing is disabled so no other handle
// can be opened during the write window.
func writePrivateRunFile(path string, content []byte, mode os.FileMode) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return errors.New("invalid run bundle file handle")
	}
	if _, err = file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
