//go:build linux

package browserhost

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// errLinuxPeerCTTYUnavailable is the fixed failure result of the qualified CTTY
// association wrapper. It carries no PID, session, path, device, or syscall
// text. The association is not approval, authorization, or a lease.
var errLinuxPeerCTTYUnavailable = errors.New("linux peer CTTY association unavailable")

// linuxPeerCTTYAssociation binds a broker-owned CTTY object to one same-session
// Unix-socket peer. It owns both the candidate snapshot and the held slave fd.
// It proves only this association; it does not authorize a request or provide a
// lease.
type linuxPeerCTTYAssociation struct {
	mu       sync.Mutex
	proof    *linuxPeerProof
	held     *linuxOwnedTTY
	snapshot linuxPeerCTTYSnapshot
	closed   bool
}

type linuxPeerCTTYSnapshot struct {
	peerSID   int
	brokerSID int
	identity  linuxPeerIdentity
}

// newLinuxPeerCTTYAssociation takes ownership of held and a fresh candidate
// snapshot from conn. On every error it retires both. Success requires two
// stable snapshots and the kernel's exact-held-slave TIOCGSID check.
func newLinuxPeerCTTYAssociation(conn *net.UnixConn, held *linuxOwnedTTY) (*linuxPeerCTTYAssociation, error) {
	if held == nil {
		return nil, errLinuxPeerCTTYUnavailable
	}
	if conn == nil {
		_ = held.Close()
		return nil, errLinuxPeerCTTYUnavailable
	}
	proof, err := linuxPeerProofFromConn(conn)
	if err != nil {
		_ = held.Close()
		return nil, errLinuxPeerCTTYUnavailable
	}
	a := &linuxPeerCTTYAssociation{proof: proof, held: held}
	a.mu.Lock()
	before, ok := a.snapshotLocked()
	var after linuxPeerCTTYSnapshot
	if ok {
		after, ok = a.snapshotLocked()
	}
	a.mu.Unlock()
	if !ok || before != after {
		_ = a.Close()
		return nil, errLinuxPeerCTTYUnavailable
	}
	a.snapshot = before
	return a, nil
}

// live re-runs the association checks under the wrapper lock. A closed wrapper,
// a changed process identity, session, candidate, or held object is not live.
func (a *linuxPeerCTTYAssociation) live() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.snapshot.peerSID <= 0 {
		return false
	}
	current, ok := a.snapshotLocked()
	return ok && current == a.snapshot
}

func (a *linuxPeerCTTYAssociation) binding() (CLIRunTerminalBinding, bool) {
	if a == nil {
		return CLIRunTerminalBinding{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return CLIRunTerminalBinding{}, false
	}
	current, ok := a.snapshotLocked()
	if !ok || current != a.snapshot {
		return CLIRunTerminalBinding{}, false
	}
	tty, ok := a.held.bindingIdentity()
	if !ok {
		return CLIRunTerminalBinding{}, false
	}
	nsDev, nsIno, ok := linuxMountNamespaceIdentity()
	if !ok {
		return CLIRunTerminalBinding{}, false
	}
	return linuxTerminalBindingDigest(current.peerSID, tty, nsDev, nsIno), true
}

func linuxMountNamespaceIdentity() (uint64, uint64, bool) {
	info, err := os.Stat("/proc/self/ns/mnt")
	if err != nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), true
}

func linuxTerminalBindingDigest(sid int, tty linuxTTYBindingIdentity, nsDev, nsIno uint64) CLIRunTerminalBinding {
	h := sha256.New()
	_, _ = h.Write([]byte("locklark/linux/ctty-terminal-binding/v1\x00"))
	var raw [8]byte
	for _, value := range []uint64{
		uint64(sid), tty.dev, tty.rdev, tty.ino,
		uint64(tty.uid), uint64(tty.gid), uint64(tty.mode), nsDev, nsIno,
	} {
		binary.BigEndian.PutUint64(raw[:], value)
		_, _ = h.Write(raw[:])
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return CLIRunTerminalBinding{digest: digest}
}

func (a *linuxPeerCTTYAssociation) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return errors.Join(a.proof.Close(), a.held.Close())
}

// snapshotLocked requires a.mu and the candidate's own lifetime locks. TIOCGSID
// succeeds only when this process's signal->tty is the exact held slave; then
// peerSID==brokerSID plus the peer's tty_nr==held Rdev binds the peer's CTTY,
// because one session has one controlling terminal.
func (a *linuxPeerCTTYAssociation) snapshotLocked() (linuxPeerCTTYSnapshot, bool) {
	if a.closed || a.proof == nil || a.held == nil {
		return linuxPeerCTTYSnapshot{}, false
	}
	if !a.proof.live() || !a.held.valid() {
		return linuxPeerCTTYSnapshot{}, false
	}
	peerSID, err := unix.Getsid(a.proof.pid)
	if err != nil || peerSID <= 0 {
		return linuxPeerCTTYSnapshot{}, false
	}
	brokerSID, err := unix.Getsid(os.Getpid())
	if err != nil || brokerSID <= 0 || peerSID != brokerSID {
		return linuxPeerCTTYSnapshot{}, false
	}
	heldSID, ok := a.held.sessionID()
	if !ok || heldSID != brokerSID {
		return linuxPeerCTTYSnapshot{}, false
	}
	if a.proof.stat.ttyDev == 0 || a.proof.stat.ttyDev != a.held.identity.dev ||
		a.proof.tty.dev != a.held.identity.dev {
		return linuxPeerCTTYSnapshot{}, false
	}
	path, dev, _, ok := peerControllingTerminal(a.proof.pid)
	if !ok || dev != a.held.identity.dev || path != a.proof.tty.path {
		return linuxPeerCTTYSnapshot{}, false
	}
	current, ok := readLinuxPeerIdentity(a.proof.pid, a.proof.uid)
	if !ok || current != (linuxPeerIdentity{stat: a.proof.stat, exe: a.proof.exe}) {
		return linuxPeerCTTYSnapshot{}, false
	}
	return linuxPeerCTTYSnapshot{peerSID: peerSID, brokerSID: brokerSID, identity: current}, true
}
