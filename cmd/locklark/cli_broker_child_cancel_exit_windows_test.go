//go:build windows

package main

import (
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// watchCLIBrokerReadyChildExit pins the announced child before cancellation.
// The SYNCHRONIZE handle names that process even if its PID is reused; the
// returned proof accepts only the signaled state and only within the short
// post-cancellation exit window.
func watchCLIBrokerReadyChildExit(t *testing.T, pid int) func() bool {
	t.Helper()
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		t.Fatal("real child exit handle unavailable")
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return func() bool {
		wait := uint32(cliBrokerReadyChildExitWait / time.Millisecond)
		if wait == 0 {
			// WaitForSingleObject treats zero as an infinite wait.
			wait = 1
		}
		event, err := windows.WaitForSingleObject(handle, wait)
		return err == nil && event == windows.WAIT_OBJECT_0
	}
}

// cliBrokerReadyChildClosed accepts an orderly peer close, or the reset that
// Windows may report when the terminated child's socket is torn down. It
// deliberately excludes timeouts, aborts, and every other socket error.
func cliBrokerReadyChildClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, windows.WSAECONNRESET)
}
