//go:build !unix && !windows

package management

import "os"

func openTrustedConfiguration(string) (*os.File, error) { return nil, ErrUnavailable }

func trustedConnectionParent(string) error { return ErrUnavailable }
func privateConnectionFile(*os.File) error { return ErrUnavailable }
