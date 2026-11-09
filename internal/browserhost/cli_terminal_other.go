//go:build !linux

package browserhost

// Non-Linux CLI terminal attestation.
//
// The attestation contract is Linux-specific: it is derived from /proc/<pid>,
// /proc/<sid> and /proc/<pid>/exe. On other platforms this package refuses
// unconditionally instead of approximating the identity from peer.Process, a
// GUI session, a code-signing check or any other weaker signal. A refusal is
// stable and predictable, so callers cannot accidentally ship a CLI broker
// that believes it has a terminal scope when it does not.
//
// VerifyCLITerminal is implemented once in cli_terminal.go and therefore also
// reports false everywhere on these platforms: it re-derives the identity via
// AttestCLITerminal, which always refuses here.

// AttestCLITerminal always refuses on non-Linux platforms. It returns the zero
// identity together with ErrCLITerminalUnsupported; it never synthesises an
// identity from peer.User or peer.Process.
func AttestCLITerminal(_ Peer) (CLITerminalIdentity, error) {
	return CLITerminalIdentity{}, ErrCLITerminalUnsupported
}
