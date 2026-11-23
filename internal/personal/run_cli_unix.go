//go:build !windows

package personal

import (
	"os"

	"github.com/jihuayu/passme/internal/localpath"
)

func createRunCLITemp() (string, error) {
	parent, e := localpath.TrustedTemporaryParent(os.TempDir())
	if e != nil {
		return "", ErrRunTemporary
	}
	return os.MkdirTemp(parent, "passme-run-cli-")
}
