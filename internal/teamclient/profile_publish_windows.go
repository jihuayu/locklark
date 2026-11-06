package teamclient

import "golang.org/x/sys/windows"

// Same-directory, no-replace move. Windows cannot fsync directory handles
// like Unix; request write-through from the filesystem before returning.
func publishProfile(tmp, path string) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
