//go:build !unix && !windows

package teamfiles

func validatePrivateParent(string) error    { return ErrFile }
func validatePrivateWorkspace(string) error { return ErrFile }
func validatePrivateFile(string) error      { return ErrFile }
func ensurePrivateWorkspace(string) error   { return ErrFile }
