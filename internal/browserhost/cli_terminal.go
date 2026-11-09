package browserhost

// CLI terminal attestation.
//
// A CLI run is scoped to the controlling terminal that hosts the authenticated
// peer, so a later lease can be bound to "this terminal, this session leader,
// this executable" instead of to whatever the client claims. This file, and
// its per-OS companions, only *describe* kernel state; nothing here creates,
// extends or approves a lease, opens a GUI surface, touches credentials, or
// talks to the network.
//
// The single trusted input is the peer PID that the kernel attached to the
// authenticated socket (see authenticatedPeer). peer.User and peer.Process are
// never consulted: the identity below is derived exclusively from kernel state
// for that PID (/proc/<pid>, /proc/<sid> and /proc/<pid>/exe). Attestation is
// all-or-nothing. On any doubt the functions refuse; they never fabricate a
// placeholder identity and never degrade to caller-supplied values.

import (
	"crypto/subtle"
	"errors"
)

var (
	// ErrCLITerminalUnsupported is returned by AttestCLITerminal on a platform
	// that does not expose the kernel state this attestation requires. Callers
	// must treat it as a refusal: there is no fallback identity and no
	// emulation of another platform's semantics.
	ErrCLITerminalUnsupported = errors.New("browserhost: CLI terminal attestation is unsupported on this platform")

	// ErrCLITerminalNoTTY is returned when the authenticated peer has no
	// controlling terminal, so a run cannot be scoped to one.
	ErrCLITerminalNoTTY = errors.New("browserhost: CLI peer has no controlling terminal")

	// ErrCLITerminalRefused is returned for every other refusal: the peer has
	// vanished or its PID was recycled, the process or its /proc entry is not
	// owned by the broker's uid, the session/tty topology is inconsistent, or
	// the executable image could not be hashed within bounds.
	ErrCLITerminalRefused = errors.New("browserhost: CLI peer terminal attestation refused")
)

// CLITerminalIdentity is an immutable, kernel-derived description of the
// terminal that hosts an authenticated CLI peer. Every field is produced by
// AttestCLITerminal from kernel state for peer.PID; callers must treat the
// value as read-only evidence (there are no setters and no constructor that
// accepts caller data).
//
// Numeric terminal/session fields are the raw kernel encodings:
//   - PeerPID is the authenticated peer PID and PeerStart is its kernel
//     start-time tick. The tick clock is coarse, so a start value alone is not
//     unique; only the PID+birth pair binds one process.
//   - TTYDevice is the controlling terminal device number (tty_nr).
//   - SessionID is the peer's session id, which is also the PID of its session
//     leader. SessionID and SessionLeaderStart bind the leader the same way:
//     the leader PID and its birth tick are both required.
//   - ExecutableSHA256 is the lowercase hex SHA-256 of the executable image
//     reached through /proc/<pid>/exe.
type CLITerminalIdentity struct {
	PeerPID            uint32
	UID                uint32
	TTYDevice          uint64
	SessionID          uint32
	SessionLeaderStart uint64
	PeerStart          uint64
	ExecutablePath     string
	ExecutableSHA256   string
}

// VerifyCLITerminal reports whether the peer's freshly re-derived terminal
// identity is exactly expected.
//
// The expected value is re-checked against the kernel rather than trusted, so
// a caller cannot widen a lease by handing in a forged or zero identity. Any
// refusal (no /proc entry, no controlling terminal, unsupported platform,
// unreadable executable, unstable process) yields false; there is no partial
// match and no "process name" fallback. The expected PeerPID must equal the
// PID the kernel reports for the authenticated peer; a matching PeerStart tick
// alone is not enough to identify a process. peer.Process, peer.User, the
// command line, the environment and every other caller-supplied string are
// ignored.
//
// Verification costs one full executable hash, so it is meant for one-shot
// per-run decisions, not for tight loops.
func VerifyCLITerminal(peer Peer, expected CLITerminalIdentity) bool {
	if !expected.wellFormed() {
		return false
	}
	actual, err := AttestCLITerminal(peer)
	if err != nil {
		return false
	}
	return actual.equal(expected)
}

// equal compares two attested identities. The executable digest is compared in
// constant time; the remaining fields are kernel numbers and paths.
func (id CLITerminalIdentity) equal(other CLITerminalIdentity) bool {
	if id.PeerPID != other.PeerPID ||
		id.UID != other.UID ||
		id.TTYDevice != other.TTYDevice ||
		id.SessionID != other.SessionID ||
		id.SessionLeaderStart != other.SessionLeaderStart ||
		id.PeerStart != other.PeerStart ||
		id.ExecutablePath != other.ExecutablePath {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(id.ExecutableSHA256), []byte(other.ExecutableSHA256)) == 1
}

// wellFormed reports whether a value could have come from AttestCLITerminal.
// UID 0 is legitimate (a root-run broker), so it is not rejected here.
func (id CLITerminalIdentity) wellFormed() bool {
	if id.PeerPID == 0 || id.TTYDevice == 0 || id.SessionID == 0 || id.SessionLeaderStart == 0 || id.PeerStart == 0 {
		return false
	}
	if id.ExecutablePath == "" {
		return false
	}
	if len(id.ExecutableSHA256) != 64 {
		return false
	}
	for i := 0; i < len(id.ExecutableSHA256); i++ {
		c := id.ExecutableSHA256[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
