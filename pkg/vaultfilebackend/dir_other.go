//go:build !darwin && !linux

package vaultfilebackend

import "os"

// The local-directory driver is implemented and tested only for darwin and
// linux. A Windows driver (LockFileEx and a no-replace publication equivalent)
// must first pass RunConformance and the multi-process race tests before it is
// enabled; until then OpenDir compiles and returns ErrUnsupported.

func openLockFile(string) (*os.File, error) {
	return nil, deniedMsg(nil, "the local directory backend is unsupported on this platform")
}

func readLockFile(*os.File, int) ([]byte, error) {
	return nil, deniedMsg(nil, "unsupported platform")
}

func writeLockFile(*os.File, []byte) error { return deniedMsg(nil, "unsupported platform") }

func tryLock(*os.File) (bool, error) { return false, deniedMsg(nil, "unsupported platform") }

func unlock(*os.File) error { return deniedMsg(nil, "unsupported platform") }

func openPrivateFile(string) (*os.File, error) {
	return nil, deniedMsg(nil, "unsupported platform")
}

func linkNoReplace(string, string) error { return deniedMsg(nil, "unsupported platform") }

func privateDir(os.FileInfo) bool { return false }

func ownedByEUID(os.FileInfo) bool { return false }

func privateFile(os.FileInfo) bool { return false }
