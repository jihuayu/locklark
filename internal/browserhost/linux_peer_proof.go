//go:build linux

package browserhost

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// errLinuxPeerProofUnavailable is the fixed failure result of the private
// Linux peer snapshot helper. It carries no PID, path, device, or syscall text.
// The helper records a limited candidate snapshot; it is not authorization,
// attestation, CTTY association, or a lease proof.
//
// Equal mount namespaces and one visible devpts do not rule out a retained
// hidden or prior CTTY instance with the same 136:N. Holding this slave fd pins
// only this devpts instance's index, not the peer's signal->tty origin.
//
// tty_jobctrl.c rejects TIOCGSID/TIOCGPGRP on a slave when the caller's
// signal->tty is not that real_tty; a different-session broker therefore gets
// ENOTTY. Re-reading those ioctls cannot establish peer association. A future
// same-session or kernel-qualified strategy needs separate implementation and
// a real platform proof. The real-child PTY test is a controlled same-fixture
// positive, not a general proof of CTTY origin.
var errLinuxPeerProofUnavailable = errors.New("linux peer proof unavailable")

// linuxPeerProof is one private, unexported snapshot candidate for a
// Unix-socket peer. It owns a pidfd and one opened broker-visible TTY candidate
// until Close. It does not prove peer signal->tty origin and is not wired into
// authenticatedPeer, the broker, or any authorization/approval/lease path.
type linuxPeerProof struct {
	uid   uint32
	pid   int
	pidfd *linuxOwnedPidFD
	ttyfd *linuxOwnedTTY
	stat  linuxPeerStat
	exe   linuxPeerExecIdentity
	tty   linuxPeerTTYIdentity
}

// linuxOwnedPidFD owns one pidfd obtained from SO_PEERPIDFD. Every fd access
// and poll shares one mutex with Close, so live never observes a raw fd after
// it may have been closed and reused. Close is idempotent so a proof can be
// retired on every error path.
type linuxOwnedPidFD struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

func newLinuxOwnedPidFD(fd int) (*linuxOwnedPidFD, error) {
	if fd < 0 {
		return nil, errLinuxPeerProofUnavailable
	}
	unix.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "locklark-linux-peer-pidfd")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errLinuxPeerProofUnavailable
	}
	return &linuxOwnedPidFD{file: file}, nil
}

func (p *linuxOwnedPidFD) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
}

// live polls the owned pidfd while holding the same lock Close uses. It never
// returns the descriptor to a caller, so no unlocked fd can be closed and
// reused between the lookup and the poll.
func (p *linuxOwnedPidFD) live() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.file == nil {
		return false
	}
	poll := []unix.PollFd{{Fd: int32(p.file.Fd()), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	return err == nil && n == 0
}

func (p *linuxPeerProof) Close() error {
	if p == nil {
		return nil
	}
	return errors.Join(p.pidfd.Close(), p.ttyfd.Close())
}

// live reports only that the held pidfd has no exit event and the held TTY
// candidate still passes local fstat/path checks. It does not re-associate that
// candidate with the peer's signal->tty. Before TTY acquisition only the pidfd
// is checked.
func (p *linuxPeerProof) live() bool {
	return p != nil && p.pidfd.live() && p.ttyfd.valid()
}

type linuxPeerStat struct {
	startTime uint64
	ttyDev    uint64
}

type linuxPeerExecIdentity struct {
	dev  uint64
	ino  uint64
	uid  uint32
	gid  uint32
	mode uint32
}

type linuxPeerTTYIdentity struct {
	path string
	dev  uint64
	ino  uint64
	uid  uint32
	gid  uint32
	mode uint32
}

// linuxOwnedTTY pins one opened broker-visible TTY candidate for the snapshot
// lifetime. Fstat and local path/identity checks share a mutex with Close; no
// raw descriptor accessor exists.
type linuxOwnedTTY struct {
	mu       sync.Mutex
	file     *os.File
	identity linuxPeerTTYIdentity
	closed   bool
}

func (p *linuxOwnedTTY) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
}

// sessionID reads TIOCGSID from exactly this held slave under the same mutex
// as Close. The kernel returns ENOTTY unless the caller's signal->tty is this
// real tty, so success is the broker-session ownership check used by the
// qualified association wrapper.
func (p *linuxOwnedTTY) sessionID() (int, bool) {
	if p == nil {
		return 0, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.file == nil {
		return 0, false
	}
	sid, err := unix.IoctlGetInt(int(p.file.Fd()), unix.TIOCGSID)
	if err != nil || sid <= 0 {
		return 0, false
	}
	return sid, true
}

// valid rechecks only this fd's local object and current path. A matching
// dev_t/inode is not proof that the peer holds or originated this TTY.
func (p *linuxOwnedTTY) valid() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.file == nil || !trustedTTYDevice(p.identity.path) {
		return false
	}
	var opened unix.Stat_t
	if unix.Fstat(int(p.file.Fd()), &opened) != nil || !validLinuxPeerTTYStat(&opened, p.identity.dev, p.identity.uid) {
		return false
	}
	if uint64(opened.Rdev) != p.identity.dev || uint64(opened.Ino) != p.identity.ino ||
		opened.Uid != p.identity.uid || opened.Gid != p.identity.gid || opened.Mode != p.identity.mode {
		return false
	}
	var path unix.Stat_t
	if unix.Stat(p.identity.path, &path) != nil || !sameLinuxPeerTTYStat(&opened, &path) {
		return false
	}
	return true
}

type linuxPeerIdentity struct {
	stat linuxPeerStat
	exe  linuxPeerExecIdentity
}

// linuxPeerProofFromConn records a limited candidate only from the supplied
// connected Unix socket. It reads SO_PEERCRED and SO_PEERPIDFD in one syscall
// section, holds the pidfd, and checks a broker-visible TTY node whose dev_t
// matches the peer's current /proc tty_nr. It does not prove that the peer's
// signal->tty originated from that node or authorize anything. Callers cannot
// name a PID or terminal path.
func linuxPeerProofFromConn(conn *net.UnixConn) (*linuxPeerProof, error) {
	if conn == nil {
		return nil, errLinuxPeerProofUnavailable
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, errLinuxPeerProofUnavailable
	}
	var cred *unix.Ucred
	var credErr error
	pidfdFD := -1
	var pidfdErr error
	if controlErr := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credErr != nil {
			return
		}
		pidfdFD, pidfdErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); controlErr != nil {
		if pidfdFD >= 0 {
			_ = unix.Close(pidfdFD)
		}
		return nil, errLinuxPeerProofUnavailable
	}
	if credErr != nil || cred == nil || cred.Pid <= 0 || cred.Uid != uint32(os.Geteuid()) {
		if pidfdFD >= 0 {
			_ = unix.Close(pidfdFD)
		}
		return nil, errLinuxPeerProofUnavailable
	}
	if pidfdErr != nil || pidfdFD < 0 {
		if pidfdFD >= 0 {
			_ = unix.Close(pidfdFD)
		}
		return nil, errLinuxPeerProofUnavailable
	}
	pidfd, err := newLinuxOwnedPidFD(pidfdFD)
	if err != nil {
		return nil, errLinuxPeerProofUnavailable
	}
	proof := &linuxPeerProof{uid: cred.Uid, pid: int(cred.Pid), pidfd: pidfd}
	fail := func() (*linuxPeerProof, error) {
		_ = proof.Close()
		return nil, errLinuxPeerProofUnavailable
	}
	if !pidfd.live() {
		return fail()
	}
	before, ok := readLinuxPeerIdentity(proof.pid, proof.uid)
	if !ok {
		return fail()
	}
	// Reuse the existing Linux tty_nr/mount/devpts parser. The pidfd, the
	// stable starttime/exe snapshots, and the dev/inode/owner check below are
	// what turn that parse into a peer proof; production trust stays disabled.
	path, dev, _, ok := peerControllingTerminal(proof.pid)
	if !ok || !pidfd.live() {
		return fail()
	}
	middle, ok := readLinuxPeerIdentity(proof.pid, proof.uid)
	if !ok || before != middle || middle.stat.ttyDev != dev {
		return fail()
	}
	if !pidfd.live() {
		return fail()
	}
	tty, ok := openLinuxPeerTTY(path, dev, proof.uid)
	if !ok {
		return fail()
	}
	proof.ttyfd = tty
	proof.tty = tty.identity
	after, ok := readLinuxPeerIdentity(proof.pid, proof.uid)
	if !ok || middle != after || !proof.live() {
		return fail()
	}
	proof.stat, proof.exe = after.stat, after.exe
	return proof, nil
}

func readLinuxPeerIdentity(pid int, uid uint32) (linuxPeerIdentity, bool) {
	stat, ok := readLinuxPeerStat(pid)
	if !ok {
		return linuxPeerIdentity{}, false
	}
	exe, ok := readLinuxPeerExecIdentity(pid, uid)
	if !ok {
		return linuxPeerIdentity{}, false
	}
	return linuxPeerIdentity{stat: stat, exe: exe}, true
}

func readLinuxPeerStat(pid int) (linuxPeerStat, bool) {
	if pid <= 0 {
		return linuxPeerStat{}, false
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return linuxPeerStat{}, false
	}
	return parseLinuxPeerStat(data)
}

// parseLinuxPeerStat reads field 7 (tty_nr) and field 22 (starttime) from a
// procfs stat line. The command name may contain spaces and parentheses; the
// last ')' is the same boundary the kernel's own parsers use.
func parseLinuxPeerStat(data []byte) (linuxPeerStat, bool) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return linuxPeerStat{}, false
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return linuxPeerStat{}, false
	}
	tty, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return linuxPeerStat{}, false
	}
	dev, ok := ttyNrDev(tty)
	if !ok {
		return linuxPeerStat{}, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return linuxPeerStat{}, false
	}
	return linuxPeerStat{startTime: start, ttyDev: dev}, true
}

func readLinuxPeerExecIdentity(pid int, uid uint32) (linuxPeerExecIdentity, bool) {
	if pid <= 0 {
		return linuxPeerExecIdentity{}, false
	}
	info, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil || !trustedPeerExecMode(info.Mode()) {
		return linuxPeerExecIdentity{}, false
	}
	owner, ok := platformFileOwner(info)
	if !ok || owner != uid {
		return linuxPeerExecIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 || stat.Uid != uid {
		return linuxPeerExecIdentity{}, false
	}
	return linuxPeerExecIdentity{
		dev: uint64(stat.Dev), ino: uint64(stat.Ino),
		uid: stat.Uid, gid: stat.Gid, mode: stat.Mode,
	}, true
}

// openLinuxPeerTTY opens one broker-visible candidate path and checks its
// local dev/inode/owner identity. It does not establish peer signal->tty
// origin; the held fd only prevents this devpts index from being freed.
func openLinuxPeerTTY(path string, wantDev uint64, uid uint32) (*linuxOwnedTTY, bool) {
	if !trustedTTYDevice(path) {
		return nil, false
	}
	var before unix.Stat_t
	if unix.Stat(path, &before) != nil || !validLinuxPeerTTYStat(&before, wantDev, uid) {
		return nil, false
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	keep := false
	defer func() {
		if !keep {
			_ = unix.Close(fd)
		}
	}()
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || !validLinuxPeerTTYStat(&opened, wantDev, uid) || !sameLinuxPeerTTYStat(&before, &opened) {
		return nil, false
	}
	var after unix.Stat_t
	if unix.Stat(path, &after) != nil || !sameLinuxPeerTTYStat(&opened, &after) {
		return nil, false
	}
	file := os.NewFile(uintptr(fd), "locklark-linux-peer-tty")
	if file == nil {
		return nil, false
	}
	keep = true
	return &linuxOwnedTTY{
		file: file,
		identity: linuxPeerTTYIdentity{
			path: path, dev: uint64(opened.Rdev), ino: uint64(opened.Ino),
			uid: opened.Uid, gid: opened.Gid, mode: opened.Mode,
		},
	}, true
}

func validLinuxPeerTTYStat(stat *unix.Stat_t, wantDev uint64, uid uint32) bool {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFCHR || stat.Rdev != wantDev || stat.Ino == 0 {
		return false
	}
	if stat.Uid != 0 && stat.Uid != uid {
		return false
	}
	_, ok := devUnit(uint64(stat.Rdev))
	return ok
}

func sameLinuxPeerTTYStat(a, b *unix.Stat_t) bool {
	return a != nil && b != nil &&
		a.Dev == b.Dev && a.Rdev == b.Rdev && a.Ino == b.Ino &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode
}
