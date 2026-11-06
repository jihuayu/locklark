package teamconsent

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
)

func openTerminal() (*os.File, *os.File, error) {
	open := func(name string) (*os.File, error) {
		wide, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, ErrTrust
		}
		h, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			return nil, ErrTrust
		}
		return os.NewFile(uintptr(h), name), nil
	}
	input, err := open("CONIN$")
	if err != nil {
		return nil, nil, ErrTrust
	}
	output, err := open("CONOUT$")
	if err != nil {
		input.Close()
		return nil, nil, ErrTrust
	}
	return input, output, nil
}
func prepareInput(f *os.File) (func(context.Context) (byte, error), func() error, error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return nil, nil, ErrTrust
	}
	if windows.SetConsoleMode(h, mode&^(windows.ENABLE_MOUSE_INPUT|windows.ENABLE_WINDOW_INPUT)) != nil {
		return nil, nil, ErrTrust
	}
	read := func(ctx context.Context) (byte, error) {
		var b [1]byte
		for ctx.Err() == nil {
			status, err := windows.WaitForSingleObject(h, 100)
			if err != nil {
				return 0, ErrTrust
			}
			if status == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
			if status != windows.WAIT_OBJECT_0 || ctx.Err() != nil {
				return 0, ErrTrust
			}
			var n uint32
			if windows.ReadFile(h, b[:], &n, nil) != nil || n != 1 {
				return 0, ErrTrust
			}
			return b[0], nil
		}
		return 0, ErrTrust
	}
	return read, func() error { return windows.SetConsoleMode(h, mode) }, nil
}
