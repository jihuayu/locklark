//go:build !unix && !windows

package main

import (
	"context"
	"os"
)

func terminalSignals() []os.Signal { return []os.Signal{os.Interrupt} }
func prepareTerminalInput(*os.File) (func(context.Context) (byte, error), func() error, error) {
	return nil, nil, errCommand
}
