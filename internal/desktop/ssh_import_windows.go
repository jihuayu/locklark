//go:build windows

package desktop

import (
	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func openSSHImport(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return nil, personal.ErrSSHKey
	}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, personal.ErrSSHKey
	}
	h, e := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_OVERLAPPED, 0)
	if e != nil {
		return nil, personal.ErrSSHKey
	}
	var info windows.ByHandleFileInformation
	typ, typeErr := windows.GetFileType(h)
	if windows.GetFileInformationByHandle(h, &info) != nil || typeErr != nil || typ != windows.FILE_TYPE_DISK || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(h)
		return nil, personal.ErrSSHKey
	}
	return os.NewFile(uintptr(h), path), nil
}
