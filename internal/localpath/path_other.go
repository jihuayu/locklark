//go:build !unix

package localpath

func TrustedTemporaryParent(string) (string, error) { return "", ErrUntrusted }
