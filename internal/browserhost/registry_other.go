//go:build !windows

package browserhost

func RegisterUser(browser, manifest string, replace bool) error { return ErrProtocol }
