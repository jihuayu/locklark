//go:build !windows

package main

import (
	"errors"
	"os/exec"
)

func newPrivateRoot() (string, error) { return "", errors.New("Windows acceptance only") }
func privateRoot(string) error        { return errors.New("Windows acceptance only") }
func consoleMode() (uint32, error)    { return 0, errors.New("Windows acceptance only") }
func detachConsole(*exec.Cmd)         { panic("Windows acceptance only") }
func ownProcessTree() error           { return errors.New("Windows acceptance only") }
