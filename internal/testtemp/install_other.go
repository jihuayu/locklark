//go:build !windows

package testtemp

func install() (func() error, error) {
	return func() error { return nil }, nil
}
