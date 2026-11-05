//go:build !unix && !windows

package browserhost

import "os"

func trustedRegistrationParent(string) error             { return ErrProtocol }
func trustedRegistrationFile(string, bool) error         { return ErrProtocol }
func createRegistrationDirectory(string) error           { return ErrProtocol }
func privateRegistrationTemp(string) (*os.File, error)   { return nil, ErrProtocol }
func publishRegistrationTemp(string, string, bool) error { return ErrProtocol }
