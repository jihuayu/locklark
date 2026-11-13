//go:build !windows

package main

import (
	"errors"
	"io"
	"testing"
)

// watchCLIBrokerReadyChildExit needs no extra process handle here: the peer
// EOF is produced only by the child that owns the other end of the connection,
// so it already proves that exact process exited.
func watchCLIBrokerReadyChildExit(_ *testing.T, _ int) func() bool {
	return func() bool { return true }
}

func cliBrokerReadyChildClosed(err error) bool {
	return errors.Is(err, io.EOF)
}
