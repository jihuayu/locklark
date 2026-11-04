//go:build !unix

package personal

import "os"

func openArchive(path string) (*os.File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, ErrArchiveType
	}
	// decodeArchive also validates the opened handle. Nonblocking Unix flags
	// are unavailable here; platform-specific special files need native tests.
	return os.Open(path)
}
