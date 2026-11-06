//go:build !unix && !windows

package teamfiles

import "os"

func trustedParent(string) error                   { return ErrFile }
func trustedFile(string, bool) error               { return ErrFile }
func createLocalFile(string) (*os.File, error)     { return nil, ErrFile }
func openLocalFile(string, bool) (*os.File, error) { return nil, ErrFile }
func publishLocalFile(string, string) error        { return ErrFile }
func equalPath(a, b string) bool                   { return a == b }
func validPlatformPath(string) bool                { return false }
