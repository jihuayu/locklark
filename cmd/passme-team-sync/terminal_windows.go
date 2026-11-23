//go:build windows

package main

import (
	"context"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func terminalSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
func prepareTerminalInput(console *os.File) (func(context.Context) (byte, error), func() error, error) {
	handle := windows.Handle(console.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return nil, nil, errCommand
	}
	// Only character input may satisfy the wait; avoid mouse/window events
	// causing a blocking read while the hidden prompt is being cancelled.
	if windows.SetConsoleMode(handle, mode&^(windows.ENABLE_MOUSE_INPUT|windows.ENABLE_WINDOW_INPUT)) != nil {
		return nil, nil, errCommand
	}
	restore := func() error { return windows.SetConsoleMode(handle, mode) }
	read := func(ctx context.Context) (byte, error) {
		var input [1]byte
		defer clear(input[:])
		for ctx.Err() == nil {
			status, e := windows.WaitForSingleObject(handle, 100)
			if e != nil {
				return 0, errCommand
			}
			if status == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
			if status != windows.WAIT_OBJECT_0 {
				return 0, errCommand
			}
			if ctx.Err() != nil {
				return 0, errCommand
			}
			var n uint32
			if windows.ReadFile(handle, input[:], &n, nil) != nil || n != 1 {
				return 0, errCommand
			}
			return input[0], nil
		}
		return 0, errCommand
	}
	return read, restore, nil
}
