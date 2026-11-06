//go:build !unix && !windows

package teamsync

import "os"

func trustedAnchorParent(string) error             { return ErrAnchor }
func trustedAnchorFile(string) error               { return ErrAnchor }
func createAnchorFile(string) (*os.File, error)    { return nil, ErrAnchor }
func publishAnchorFile(string, string) error       { return ErrAnchor }
func openAnchorFile(string, int) (*os.File, error) { return nil, ErrAnchor }
