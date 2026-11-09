//go:build !linux && !windows

package personal

import (
	"context"
	"os"
	"os/exec"
)

// newRunBundleCommand is the fallback for platforms with no implemented exact
// program-byte pin (Darwin, the BSDs, Solaris, Plan 9 and the WebAssembly
// targets). A request that carries an expected program digest is refused
// explicitly with ErrRunProgramPinUnsupported: this platform cannot snapshot and
// seal the approved bytes, so it must not start an image that was only verified
// through a name that may have changed since the approval. With no expected
// digest the ordinary direct exec is preserved for compatibility; that is a
// documented unpinned security scope, not an exact-byte guarantee.
//
// Darwin was researched and has no supported way to close the gap with public
// API only. macOS libc does not provide fexecve, and Go exposes no equivalent
// (golang.org/x/sys/unix has no fexecve wrapper for darwin), so a Mach-O image
// cannot be started from an already-open descriptor; executing "/dev/fd/N" is
// not a supported Mach-O exec path. A private 0700 copy or an advisory flock
// gives no immutability against another process of the same user, and copying a
// signed Mach-O breaks its code signature. Darwin therefore keeps the
// explicit fail-closed refusal instead of a best-effort snapshot that would
// silently weaken the approval. See docs/cli-run-program-pin.md.
func newRunBundleCommand(ctx context.Context, program string, args []string, expectedSHA256 string) (*exec.Cmd, func(), error) {
	if expectedSHA256 != "" {
		return nil, nil, ErrRunProgramPinUnsupported
	}
	info, err := os.Stat(program)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode().Perm()&0o111 == 0 {
		return nil, nil, ErrRunResult
	}
	return exec.CommandContext(ctx, program, args...), func() {}, nil
}
