//go:build windows

package testtemp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func install() (func() error, error) {
	public, err := windows.KnownFolderPath(windows.FOLDERID_Public, 0)
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	for attempt := 0; attempt < 16; attempt++ {
		var suffix [12]byte
		if _, err = rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		root := filepath.Join(public, "locklark-test-temp-"+hex.EncodeToString(suffix[:]))
		wide, err := windows.UTF16PtrFromString(root)
		if err != nil {
			return nil, err
		}
		switch err = windows.CreateDirectory(wide, &attributes); {
		case errors.Is(err, windows.ERROR_ALREADY_EXISTS), errors.Is(err, windows.ERROR_FILE_EXISTS):
			continue
		case err != nil:
			return nil, err
		}
		oldTMP, hadTMP := os.LookupEnv("TMP")
		oldTEMP, hadTEMP := os.LookupEnv("TEMP")
		if err = os.Setenv("TMP", root); err != nil {
			_ = os.Remove(root)
			return nil, err
		}
		if err = os.Setenv("TEMP", root); err != nil {
			_ = os.Remove(root)
			restoreEnv("TMP", oldTMP, hadTMP)
			return nil, err
		}
		return func() error {
			restoreEnv("TMP", oldTMP, hadTMP)
			restoreEnv("TEMP", oldTEMP, hadTEMP)
			return os.RemoveAll(root)
		}, nil
	}
	return nil, errors.New("private test temp name collision")
}

func restoreEnv(name, value string, present bool) {
	if present {
		_ = os.Setenv(name, value)
		return
	}
	_ = os.Unsetenv(name)
}
