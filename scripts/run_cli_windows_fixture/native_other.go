//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

func newPrivateRoot() (string, error) { return "", errors.New("Windows acceptance only") }
func privateRoot(string) error        { return errors.New("Windows acceptance only") }
func privateRootFailure(error) string { return "unknown" }
func consoleMode() (uint32, error)    { return 0, errors.New("Windows acceptance only") }
func detachConsole(*exec.Cmd)         { panic("Windows acceptance only") }
func detachOwnConsole() error         { return errors.New("Windows acceptance only") }
func ownConsoleAbsent() bool          { return false }
func isPipe(*os.File) bool            { return false }
func ownProcessTree() error           { return errors.New("Windows acceptance only") }
