package management

import (
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func createConnection(path string) (*os.File, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		return nil, e
	}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	attr := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attr, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}
