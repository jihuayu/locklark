package pluginstore

import "golang.org/x/sys/windows"

func publish(tmp, path string) error {
	from, e := windows.UTF16PtrFromString(tmp)
	if e != nil {
		return e
	}
	to, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
