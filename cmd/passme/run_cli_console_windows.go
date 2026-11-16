package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func openRunCLIConsole() (*os.File, *os.File, error) {
	open := func(name string) (*os.File, error) {
		wide, e := windows.UTF16PtrFromString(name)
		if e != nil {
			return nil, errRunCLIConsole
		}
		// Nil SECURITY_ATTRIBUTES creates non-inheritable handles. The
		// child continues to use only its original standard streams.
		handle, e := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if e != nil {
			return nil, errRunCLIConsole
		}
		var mode uint32
		if windows.GetConsoleMode(handle, &mode) != nil {
			windows.CloseHandle(handle)
			return nil, errRunCLIConsole
		}
		return os.NewFile(uintptr(handle), name), nil
	}
	input, e := open("CONIN$")
	if e != nil {
		return nil, nil, errRunCLIConsole
	}
	output, e := open("CONOUT$")
	if e != nil {
		input.Close()
		return nil, nil, errRunCLIConsole
	}
	return input, output, nil
}
