//go:build !linux

package personal

// CheckRunBundleProgramPinPreflight is a no-op on non-Linux platforms. The
// Linux shebang restriction exists because a sealed descriptor execution
// rewrites a script's $0; other platforms keep their own execution policy,
// including the existing explicit refusal of every pinned program where no
// byte-snapshot primitive is implemented. This helper is not a native pin
// guarantee and does not weaken any platform's execution checks.
func CheckRunBundleProgramPinPreflight(program string, expectedSHA256 string) error {
	return nil
}
