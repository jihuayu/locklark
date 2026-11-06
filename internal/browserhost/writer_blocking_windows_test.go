//go:build windows

package browserhost

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func forceBlockingStdout() error {
	kind, err := windows.GetFileType(windows.Handle(os.Stdout.Fd()))
	if err != nil || kind != windows.FILE_TYPE_PIPE {
		return errors.New("stdout is not the inherited pipe")
	}
	return nil
}
