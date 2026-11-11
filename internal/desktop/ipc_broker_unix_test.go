//go:build linux || darwin

package desktop

import (
	"path/filepath"

	"github.com/jihuayu/locklark/internal/localpath"
)

// desktopBrokerTrusted reports whether endpoint is a socket path whose parent
// directory passes localpath.TrustedTemporaryParent, the guard the Unix broker
// applies in listenLocal. A non-nil error means the real listener would refuse
// this endpoint and the caller must use the explicit fallback.
func desktopBrokerTrusted(endpoint string) error {
	_, e := localpath.TrustedTemporaryParent(filepath.Dir(endpoint))
	return e
}
