package browserhost

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CLIRunMaxTTYIdentity bounds the declared terminal name of a CLI-run scope,
// on the client before anything is sent and on the broker after it is
// received.
const CLIRunMaxTTYIdentity = 1024

// The CLI-run scope carries two terminal fields with different trust:
//
//   - The client's declared terminal name is the one its kernel controlling
//     terminal names, re-opened and checked against that kernel value
//     (CurrentTTYIdentity). It is display data and a name check only; it is
//     never authority. A declared device number (peer ID) is deliberately not
//     sent: it would prove nothing, so the client does not send one.
//   - The peer's real controlling terminal is read by the broker from the
//     kernel for Peer.PID (AttestCLIRunTTY): kinfo_proc.e_tdev on Darwin. Only
//     the broker can do that. On Linux this legacy attestation remains
//     unavailable; a separate same-session CLI-run proof path may qualify a
//     connection. The client helper is still only request/display data here.
//
// Before native approval the declared name's stat device must equal the
// kernel-attested controlling-terminal device, and the attested node is
// stat'ed again to confirm the kernel value. A failure to establish either
// identity is reported as unavailable, never refused; a disagreement between
// two established identities is refused. A platform without an attestation
// implementation, or without a proof of which terminal the peer attests,
// makes every brokered CLI-run unavailable, so a declared string is never
// treated as authenticated. On Linux the client helper still describes its
// own terminal, but that description is only request/display data.
//
// peerTTYAttestor is the broker-side kernel lookup, and currentTTYNodeOpener
// the client-side node handle. Both are unexported seams for tests only; no
// request field or exported option can select them, and production code never
// replaces them.
var peerTTYAttestor = peerControllingTerminal

// CLIRunTTYPlatform identifies the platform whose terminal naming rules
// produced a declared TTY name. The name is platform-specific (/dev/ttysNNN on
// darwin, /dev/pts/N on linux), so a request for one platform never matches
// another platform's peer view.
func CLIRunTTYPlatform() string { return runtime.GOOS }

// currentTTYNodeOpener opens one terminal node by path. It is the one
// unexported client seam for tests, which point it at a fixture handle; the
// production default opens the node the kernel named. The path is always one
// this build derived from the kernel, never a caller's string.
var currentTTYNodeOpener = openTTYNode

// CurrentTTYIdentity derives the declared terminal identity of this process:
// the name of its kernel controlling-terminal node and the client-form unit of
// that terminal. It is the client's declared terminal name and is not trusted
// by the broker on its own: the broker compares it with the terminal it attests
// from the kernel for this process.
//
// The identity is self-attested through the same kernel lookup the broker
// uses (peerTTYAttestor(os.Getpid())). That lookup yields the single /dev node
// naming this process's controlling terminal; only that exact node is opened,
// never /dev/tty, whose device number is not the terminal's identity. The
// opened handle must be a real terminal (TIOCGETA / TCGETS with a termios
// buffer), its fstat mode and device must be exactly the kernel-attested
// terminal, and a second kernel attestation must report the same path and
// device, so a terminal that changed or vanished mid-check never yields a
// name.
//
// It fails closed: no controlling terminal, unsupported platform, a handle
// that is not a terminal or not the attested node, or a changed identity all
// yield errCLIRunUnavailable.
func CurrentTTYIdentity() (name, peerID string, err error) {
	if !cliRunTTYAttestationEnabled() {
		return "", "", errCLIRunUnavailable
	}
	first, ok := attestSelfTTY()
	if !ok {
		return "", "", errCLIRunUnavailable
	}
	unit, ok := currentTTYNodeHandle(first)
	if !ok {
		return "", "", errCLIRunUnavailable
	}
	second, ok := attestSelfTTY()
	if !ok || second != first {
		return "", "", errCLIRunUnavailable
	}
	return second.path, encodeTTYPeerID(unit), nil
}

// cliRunTTYAttestationEnabled reports whether a checkpoint may attest a
// controlling terminal: the platform has an implementation, and no test has
// forced the unsupported-platform path (see attestationPlatformDisabled).
func cliRunTTYAttestationEnabled() bool {
	return cliRunTTYAttestedPlatform() && !attestationPlatformDisabled
}

// cliRunTTYPeerAttestationAvailable reports whether this build's legacy
// AttestCLIRunTTY path can prove peer terminal ownership. It is false on Linux;
// the separate same-session proof path has its own qualification and is not
// controlled by this flag. It gates only the legacy peer attestation, so the
// client's CurrentTTYIdentity keeps working.
func cliRunTTYPeerAttestationAvailable() bool { return peerTTYAttestationAvailable }

// selfTTY is the kernel view of this process's controlling terminal.
type selfTTY struct {
	path string
	dev  uint64
}

// attestSelfTTY asks the kernel for this process's controlling terminal and
// returns its node path and device.
func attestSelfTTY() (selfTTY, bool) {
	path, dev, _, ok := peerTTYAttestor(os.Getpid())
	if !ok || !cliRunTTYPathValid(path) {
		return selfTTY{}, false
	}
	return selfTTY{path: path, dev: dev}, true
}

// currentTTYNodeHandle opens exactly the kernel-attested node, proves through
// the platform terminal ioctl that it is a terminal, checks that its fstat
// mode and device are exactly the attested terminal, and returns the
// terminal unit.
func currentTTYNodeHandle(self selfTTY) (uint32, bool) {
	f, e := currentTTYNodeOpener(self.path)
	if e != nil || f == nil {
		return 0, false
	}
	defer f.Close()
	if !ttyHandleIsTerminal(f) {
		return 0, false
	}
	dev, charDevice, ok := fstatTTYHandle(f)
	if !ok || dev != self.dev {
		return 0, false
	}
	return handleTTYIdentity(self.dev, dev, charDevice)
}

// CLIRunTTYAttestation is the broker's kernel view of the authenticated peer's
// controlling terminal, for comparison with the declared scope. Dev is the
// kernel device number of the peer's controlling terminal (Darwin
// kinfo_proc.e_tdev, Linux tty_nr in the kernel's dev_t encoding). Name and
// Unit come from stat'ing the single /dev node that names that device; a
// kernel value whose node does not stat to it yields no attestation.
type CLIRunTTYAttestation struct {
	Name string
	Dev  uint64
	Unit uint32
}

// AttestCLIRunTTY returns the kernel-attested controlling-terminal identity of
// the authenticated peer process, or errCLIRunUnavailable when the platform or
// the kernel lookup cannot establish one. It never consults the request.
// Only the peer's real CTTY qualifies: a peer without a controlling terminal
// (for example a daemon or a test process started without a tty) is
// unavailable, never "any tty it happens to hold open".
//
// Linux is explicitly unavailable before any lookup: no kernel interface
// available to the broker proves that the tty_nr device of a peer is the same
// terminal object this broker inspects. A device number alone names a
// major/minor, which distinct terminal instances can reuse, so a peer's
// declared or kernel-reported name cannot stand in for that proof. That makes
// every brokered CLI-run unavailable on Linux until such an association
// exists, so no native approval or lease authority is issued there. The
// Linux client helper (CurrentTTYIdentity) still describes its own terminal,
// but only as request/display data; it is never authority.
func AttestCLIRunTTY(peer Peer) (CLIRunTTYAttestation, error) {
	if !cliRunTTYPeerAttestationAvailable() || !cliRunTTYAttestationEnabled() || peer.PID == 0 {
		return CLIRunTTYAttestation{}, errCLIRunUnavailable
	}
	path, dev, unit, ok := peerTTYAttestor(int(peer.PID))
	if !ok || !cliRunTTYPathValid(path) {
		return CLIRunTTYAttestation{}, errCLIRunUnavailable
	}
	return CLIRunTTYAttestation{Name: path, Dev: dev, Unit: unit}, nil
}

// peerTTYTerminalDev returns the verified device number of the authenticated
// peer's controlling terminal: the attested path is stat'ed again and its
// device must still be the kernel-reported one, so a node replaced between
// the two reads cannot slip through.
func peerTTYTerminalDev(peer Peer) (uint64, bool) {
	if !cliRunTTYAttestationEnabled() || peer.PID == 0 {
		return 0, false
	}
	path, dev, _, ok := peerTTYAttestor(int(peer.PID))
	if !ok || !cliRunTTYPathValid(path) {
		return 0, false
	}
	_, nodeDev, _, ok := ttyNodeIdentity(path)
	if !ok || nodeDev != dev {
		return 0, false
	}
	return dev, true
}

// cliRunTTYPathValid is the shape check for a terminal node path the kernel
// lookup produced: one clean absolute path under /dev. It is not an identity
// check; trust in the node itself comes from ttyNodeIdentity.
func cliRunTTYPathValid(path string) bool {
	return cliRunTTYNameValid(path) && strings.HasPrefix(path, "/dev/")
}

// verifyCLIRunTTY refuses a request whose declared terminal is not the
// kernel-attested controlling terminal of the authenticated peer. Its
// arguments are the declared scope fields, not the scope type, so the check
// depends on nothing else in the request.
//
// It returns errCLIRunUnavailable when the identity cannot be established: an
// unsupported platform, a peer without a kernel controlling terminal, or an
// attested device node that cannot be stat'ed under the local path policy. The
// broker reports that as the explicit protocol "unavailable" reply. Anything
// else is errCLIRunInvalid and is a refusal: a platform label from another
// platform, a request carrying a peer ID (the broker never trusts a declared
// device number), a declared name that does not project to a trusted device
// node, or a declared device that differs from the attested e_tdev /
// tty_nr device. The declared path is only a display name; the compared
// identity is always the kernel device of the peer's controlling terminal.
func verifyCLIRunTTY(peer Peer, tty, ttyPlatform, ttyPeerID string) error {
	if ttyPlatform != CLIRunTTYPlatform() || ttyPeerID != "" {
		return errCLIRunInvalid
	}
	attested, e := AttestCLIRunTTY(peer)
	if e != nil {
		return e
	}
	dev, ok := peerTTYTerminalDev(peer)
	if !ok || dev != attested.Dev {
		return errCLIRunUnavailable
	}
	declared, ok := projectTTYPath(tty)
	if !ok || declared != tty {
		return errCLIRunInvalid
	}
	_, nodeDev, _, ok := ttyNodeIdentity(declared)
	if !ok {
		return errCLIRunUnavailable
	}
	if nodeDev != dev {
		return errCLIRunInvalid
	}
	return nil
}

// encodeTTYPeerID is the fixed client-side form of one terminal unit: the
// unit number as 8 hex digits. The broker never accepts it as authority; it is
// compared only with the unit of the handle it was derived from.
func encodeTTYPeerID(unit uint32) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], unit)
	return hex.EncodeToString(raw[:])
}

// parseTTYPeerID decodes encodeTTYPeerID's exact form. The broker rejects any
// request that carries one, but the client-side round trip is kept exact.
func parseTTYPeerID(value string) (unit uint32, ok bool) {
	if len(value) != 8 {
		return 0, false
	}
	raw, e := hex.DecodeString(value)
	if e != nil || len(raw) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(raw), true
}

// projectTTYPath maps a caller-owned console path (for example /dev/fd/0) to
// the one clean absolute node it names, and reports false for anything that is
// not such a path. The result is still only a declared name; the broker checks
// that it is the same device as the peer's CTTY.
func projectTTYPath(path string) (string, bool) {
	if path == "" || !filepath.IsAbs(path) || len(path) > CLIRunMaxTTYIdentity || strings.ContainsRune(path, 0) {
		return "", false
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved || len(resolved) > CLIRunMaxTTYIdentity {
		return "", false
	}
	return resolved, true
}

// cliRunTTYNameValid is the shape check for a declared TTY name: one clean
// absolute device path. It is not an identity check.
func cliRunTTYNameValid(value string) bool {
	return value != "" && len(value) <= CLIRunMaxTTYIdentity && filepath.IsAbs(value) &&
		filepath.Clean(value) == value && !strings.ContainsRune(value, 0) && !strings.HasSuffix(value, "/")
}

// errCLIRunUnavailable reports that this platform cannot attest a peer's
// controlling terminal. It is only used inside the broker to choose the
// explicit "unavailable" reply; it must never be treated as fallback evidence
// by a caller that has already sent a request.
var errCLIRunUnavailable = errors.New("desktop browser broker CLI-run terminal unavailable")
