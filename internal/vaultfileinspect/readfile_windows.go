//go:build windows

package vaultfileinspect

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// readRegular opens the final path component itself (never following a
// reparse point), requires a disk file with no reparse/directory attributes,
// then performs a bounded read from that exact handle.
func readRegular(path string, max int64) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("input")
	}
	handle, err := windows.CreateFile(
		name,
		windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, errors.New("input")
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("input")
	}
	defer f.Close()
	fileType, err := windows.GetFileType(handle)
	if err != nil || fileType != windows.FILE_TYPE_DISK {
		return nil, errors.New("input")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, errors.New("input")
	}
	size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	if size < 0 || size > max {
		return nil, errors.New("input")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		clear(raw)
		return nil, errors.New("input")
	}
	return raw, nil
}
