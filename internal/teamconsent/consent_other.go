//go:build !unix && !windows

package teamconsent

import (
	"context"
	"os"
)

func openTerminal() (*os.File, *os.File, error) { return nil, nil, ErrTrust }
func prepareInput(*os.File) (func(context.Context) (byte, error), func() error, error) {
	return nil, nil, ErrTrust
}
