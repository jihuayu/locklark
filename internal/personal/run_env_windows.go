package personal

import "golang.org/x/sys/windows"

// Use the OS directory rather than an inherited, caller-controlled variable.
func runBaseEnvironment() ([]string, error) {
	root, e := windows.GetWindowsDirectory()
	if e != nil {
		return nil, e
	}
	return []string{"SystemRoot=" + root}, nil
}
