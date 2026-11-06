//go:build !unix && !windows

package teamclient

import "os"

func trustedProfileParent(string) error             { return ErrProfile }
func trustedProfileFile(string) error               { return ErrProfile }
func createProfileFile(string) (*os.File, error)    { return nil, ErrProfile }
func openProfileFile(string, int) (*os.File, error) { return nil, ErrProfile }

func lockProfileIdentity(*os.File) error { return ErrProfile }

func equalProfilePath(a, b string) bool          { return a == b }
func profileUniqueFile(string, os.FileInfo) bool { return false }
