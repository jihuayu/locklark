//go:build linux

package browserhost

// Linux CLI terminal attestation.
//
// Everything below is derived from kernel state for the authenticated peer
// PID. In particular we never read /proc/<pid>/cmdline, never read
// /proc/<pid>/environ, never open any file the peer names, and never use
// peer.Process (which authenticatedPeer only fills from a readlink it did not
// verify against the running image). The executable digest comes from an
// ordinary file opened through the kernel-provided /proc/<pid>/exe link, and
// the whole image is hashed, so a renamed or wrapper binary cannot impersonate
// another.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	// procStatReadLimit bounds how many bytes we ever read from one
	// /proc/<pid>/stat file. The kernel formats that file in well under 1 KiB
	// and never emits a partial tail, so a longer read means this is not a
	// plain kernel stat file and we refuse instead of parsing a prefix.
	procStatReadLimit = 4096
	// procCommMax bounds the (kernel-capped) comm field. A longer run cannot
	// have come from the kernel's %s formatting of task->comm.
	procCommMax = 256
	// cliTerminalMaxExecutableBytes is the hard cap on the executable image we
	// will hash. A larger image cannot be fully attested inside these bounds
	// and is refused rather than partially hashed.
	cliTerminalMaxExecutableBytes = 256 << 20
	// procLinkMax bounds a /proc/<pid>/exe readlink result: PATH_MAX plus room
	// for the kernel's " (deleted)" suffix.
	procLinkMax = unix.PathMax + 32
)

var (
	errProcStatMalformed = errors.New("browserhost: malformed proc stat")
	errProcFileTooLarge  = errors.New("browserhost: proc file exceeds bounded read")
)

// procStat is the bounded subset of /proc/<pid>/stat this package relies on.
// Field numbering follows proc(5): pid=1, comm=2, state=3, session=6, tty_nr=7,
// starttime=22.
type procStat struct {
	PID        uint32
	Comm       string
	State      byte
	SessionID  uint32
	TTY        int64
	StartTicks uint64
}

// AttestCLITerminal derives the terminal identity of the authenticated peer
// from kernel state for peer.PID on Linux.
//
// The derivation is deliberately narrow: the peer's /proc entry must be owned
// by the broker's effective uid, the peer must be alive with a controlling
// terminal (tty_nr != 0) and a session (sid > 0), and the session leader's
// entry must agree with the peer about uid, session and terminal. The peer's
// /proc/<pid>/stat is read before and after the executable hash and must keep
// the same pid, comm, session, terminal and creation ticks, and the same
// /proc inode. Start ticks are coarse, so the pid and its birth tick are
// checked together rather than treating either as unique. The final sample is
// also re-checked for liveness, because procStatStable intentionally ignores
// the scheduling state. The executable itself is opened through
// /proc/<pid>/exe as an ordinary, regular, bounded file, hashed in full, and
// fstat'ed before and after the read so a swapped or mutated image is
// rejected.
//
// Any failure is a fixed refusal (ErrCLITerminalNoTTY when the process truly
// has no controlling terminal, ErrCLITerminalRefused otherwise) and returns the
// zero identity. peer.User and peer.Process are ignored.
func AttestCLITerminal(peer Peer) (CLITerminalIdentity, error) {
	var zero CLITerminalIdentity
	if peer.PID == 0 || peer.PID > math.MaxInt32 {
		return zero, refusef("peer pid is not a process id")
	}
	pid := peer.PID
	euid := uint32(os.Geteuid())

	dirBefore, err := statOwnedProcDir(pid, euid)
	if err != nil {
		return zero, err
	}
	peerBefore, err := readProcStat(pid)
	if err != nil {
		return zero, err
	}
	if peerBefore.PID != pid {
		return zero, refusef("proc stat does not describe the peer pid")
	}
	if err := checkPeerProcStat(peerBefore); err != nil {
		return zero, err
	}
	leaderBefore, err := attestSessionLeader(peerBefore, euid)
	if err != nil {
		return zero, err
	}
	exePath, digest, err := attestExecutable(pid)
	if err != nil {
		return zero, err
	}

	// Before/after: the process must be the same birth and the same /proc
	// entry, otherwise the evidence above may belong to a recycled PID.
	peerAfter, err := readProcStat(pid)
	if err != nil {
		return zero, err
	}
	if err := checkFinalPeerStat(peerBefore, peerAfter); err != nil {
		return zero, err
	}
	leaderAfter, err := readProcStat(leaderBefore.PID)
	if err != nil {
		return zero, err
	}
	if err := checkFinalLeaderStat(peerAfter, leaderBefore, leaderAfter); err != nil {
		return zero, err
	}
	if _, err := statOwnedProcDir(leaderAfter.PID, euid); err != nil {
		return zero, err
	}
	dirAfter, err := statOwnedProcDir(pid, euid)
	if err != nil {
		return zero, err
	}
	if dirBefore.Ino != dirAfter.Ino || dirBefore.Dev != dirAfter.Dev || dirBefore.Uid != dirAfter.Uid {
		return zero, refusef("peer proc entry changed during attestation")
	}

	id := CLITerminalIdentity{
		PeerPID:            peerBefore.PID,
		UID:                euid,
		TTYDevice:          uint64(peerBefore.TTY),
		SessionID:          peerBefore.SessionID,
		SessionLeaderStart: leaderBefore.StartTicks,
		PeerStart:          peerBefore.StartTicks,
		ExecutablePath:     exePath,
		ExecutableSHA256:   digest,
	}
	if !id.wellFormed() {
		return zero, refusef("derived identity is incomplete")
	}
	return id, nil
}

// refusef builds a wrapped refusal so callers can match ErrCLITerminalRefused
// with errors.Is while diagnostics stay readable.
func refusef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCLITerminalRefused, fmt.Sprintf(format, args...))
}

func refuseErrf(msg string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrCLITerminalRefused, msg, err)
}

// statOwnedProcDir stats /proc/<pid> itself and requires a directory owned by
// the broker's effective uid. The check is on kernel ownership, not on the
// (untrusted) peer credentials the connection reported.
func statOwnedProcDir(pid, euid uint32) (unix.Stat_t, error) {
	var st unix.Stat_t
	path := "/proc/" + strconv.FormatUint(uint64(pid), 10)
	if err := unix.Stat(path, &st); err != nil {
		return st, refuseErrf("cannot stat peer process entry", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return st, refusef("peer process entry is not a directory")
	}
	if st.Uid != euid {
		return st, refusef("peer process entry is owned by another uid")
	}
	return st, nil
}

// readProcStat reads and parses one bounded /proc/<pid>/stat.
func readProcStat(pid uint32) (procStat, error) {
	raw, err := readProcFileBounded("/proc/"+strconv.FormatUint(uint64(pid), 10)+"/stat", procStatReadLimit)
	if err != nil {
		return procStat{}, refuseErrf("cannot read process stat", err)
	}
	st, err := parseProcStat(raw)
	if err != nil {
		return procStat{}, refuseErrf("process stat is not kernel formatted", err)
	}
	return st, nil
}

// checkPeerProcStat rejects peers that cannot host a scoped CLI run: dead,
// sessionless, or terminal-less processes. tty_nr == 0 is the fixed no-tty
// refusal; there is no substitute identity for a pipeline or a daemon.
func checkPeerProcStat(st procStat) error {
	switch st.State {
	case 'Z', 'X', 'x':
		return refusef("peer process is not running")
	}
	if st.SessionID == 0 {
		return refusef("peer has no session")
	}
	if st.TTY == 0 {
		return fmt.Errorf("%w: peer has no controlling terminal", ErrCLITerminalNoTTY)
	}
	if st.TTY < 0 {
		return refusef("peer controlling terminal device is invalid")
	}
	if st.StartTicks == 0 {
		return refusef("peer start time is missing")
	}
	return nil
}

// checkFinalPeerStat applies the post-hash peer gate. procStatStable excludes
// State so ordinary running/sleeping churn is not instability, but that means a
// peer which becomes a zombie while its executable is being hashed can keep
// the same pid, start tick, session and terminal. Re-running the full peer
// check on the final sample refuses that case.
func checkFinalPeerStat(before, after procStat) error {
	if !procStatStable(before, after) {
		return refusef("peer process changed during attestation")
	}
	return checkPeerProcStat(after)
}

// attestSessionLeader resolves /proc/<sid>/stat and requires it to be the
// session leader of the peer's session, owned by the same uid, alive, and
// sharing the peer's controlling terminal. Because tty_nr is per-session in
// the kernel, a disagreement means the peer's evidence is inconsistent.
func attestSessionLeader(peer procStat, euid uint32) (procStat, error) {
	sid := peer.SessionID
	if _, err := statOwnedProcDir(sid, euid); err != nil {
		return procStat{}, err
	}
	leader, err := readProcStat(sid)
	if err != nil {
		return procStat{}, err
	}
	if err := checkSessionLeaderTopology(peer, leader); err != nil {
		return procStat{}, err
	}
	return leader, nil
}

// checkSessionLeaderTopology validates a leader sample against the peer's
// session sample. It is shared by the initial derivation and the final
// post-hash re-check, so a leader that becomes a zombie or changes terminal
// topology during attestation is rejected at either point.
func checkSessionLeaderTopology(peer, leader procStat) error {
	if leader.PID != peer.SessionID {
		return refusef("session leader pid does not match the session id")
	}
	switch leader.State {
	case 'Z', 'X', 'x':
		return refusef("session leader is not running")
	}
	if leader.SessionID != peer.SessionID {
		return refusef("session leader is not in its own session")
	}
	if leader.TTY <= 0 {
		return fmt.Errorf("%w: session leader has no controlling terminal", ErrCLITerminalNoTTY)
	}
	if leader.TTY != peer.TTY {
		return refusef("peer and session leader disagree about the controlling terminal")
	}
	if leader.StartTicks == 0 {
		return refusef("session leader start time is missing")
	}
	if leader.StartTicks > peer.StartTicks {
		return refusef("session leader is younger than the peer")
	}
	return nil
}

// checkFinalLeaderStat applies the post-hash leader gate: the leader must be
// the same PID/birth pair that was attested initially, and it must still be a
// live session leader with the peer's terminal.
func checkFinalLeaderStat(peerAfter, leaderBefore, leaderAfter procStat) error {
	if !procStatStable(leaderBefore, leaderAfter) {
		return refusef("session leader changed during attestation")
	}
	return checkSessionLeaderTopology(peerAfter, leaderAfter)
}

// attestExecutable resolves /proc/<pid>/exe and hashes the executable image it
// points at. The link target is only used as a display path; the digest comes
// from an ordinary file opened through the link and fstat'ed before and after
// the bounded read. The kernel-resolved target is also stat'ed before the open
// and again after the hash, and its dev/inode/type must match the hashed fd at
// both points. A same-path re-exec therefore refuses even though the readlink
// text and the old descriptor stay unchanged.
func attestExecutable(pid uint32) (string, string, error) {
	link := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe"
	path, err := os.Readlink(link)
	if err != nil {
		return "", "", refuseErrf("cannot resolve executable link", err)
	}
	if path == "" || len(path) > procLinkMax {
		return "", "", refusef("executable path is not a kernel path")
	}
	linkBefore, err := statExecutableLink(link)
	if err != nil {
		return "", "", err
	}
	f, err := os.Open(link)
	if err != nil {
		return "", "", refuseErrf("cannot open executable image", err)
	}
	defer f.Close()

	var before unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &before); err != nil {
		return "", "", refuseErrf("cannot stat executable image", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", "", refusef("executable image is not an ordinary file")
	}
	if !sameExecutableFile(before, linkBefore) {
		return "", "", refusef("executable image changed before it was opened")
	}
	if err := checkExecutableSize(before.Size); err != nil {
		return "", "", err
	}

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, cliTerminalMaxExecutableBytes+1))
	if err != nil {
		return "", "", refuseErrf("cannot hash executable image", err)
	}
	if n > cliTerminalMaxExecutableBytes {
		return "", "", refusef("executable image exceeds the attestation bound")
	}
	if n != before.Size {
		return "", "", refusef("executable image size changed during attestation")
	}

	var after unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &after); err != nil {
		return "", "", refuseErrf("cannot re-stat executable image", err)
	}
	if !fileStatStable(before, after) {
		return "", "", refusef("executable image changed during attestation")
	}
	pathAfter, err := os.Readlink(link)
	if err != nil || pathAfter != path {
		return "", "", refusef("executable link changed during attestation")
	}
	if err := checkExecutableLinkCurrent(link, after); err != nil {
		return "", "", err
	}
	return path, hex.EncodeToString(h.Sum(nil)), nil
}

// statExecutableLink follows /proc/<pid>/exe to the image the kernel currently
// has installed for the process and returns its metadata. The link text is not
// evidence: only the resolved dev/inode/type is compared with the hashed fd.
func statExecutableLink(link string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Stat(link, &st); err != nil {
		return st, refuseErrf("cannot stat current executable", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return st, refusef("current executable is not an ordinary file")
	}
	return st, nil
}

// checkExecutableLinkCurrent re-resolves /proc/<pid>/exe and requires the image
// there to still be the exact inode that was hashed. A same-path re-exec keeps
// the readlink text and the already-open old descriptor unchanged while the
// live process moves to a new inode; only this dev/inode/type comparison
// detects it.
func checkExecutableLinkCurrent(link string, hashed unix.Stat_t) error {
	current, err := statExecutableLink(link)
	if err != nil {
		return err
	}
	if !sameExecutableFile(hashed, current) {
		return refusef("current executable inode no longer matches the hashed image")
	}
	return nil
}

// sameExecutableFile reports whether two stat results are the same executable
// object: same device, same inode and same file type. Timestamps and size are
// deliberately not part of this identity; they are covered by fileStatStable
// for the descriptor that was actually read.
func sameExecutableFile(hashed, current unix.Stat_t) bool {
	return hashed.Dev == current.Dev &&
		hashed.Ino == current.Ino &&
		hashed.Mode&unix.S_IFMT == current.Mode&unix.S_IFMT
}

// checkExecutableSize enforces the ordinary-file size bounds. Size 0 is a
// refusal: an empty image cannot be a real executable.
func checkExecutableSize(size int64) error {
	if size <= 0 {
		return refusef("executable image is empty")
	}
	if size > cliTerminalMaxExecutableBytes {
		return refusef("executable image exceeds the attestation bound")
	}
	return nil
}

// procStatStable reports whether two reads of /proc/<pid>/stat describe the
// same, unchanged process. The PID and its starttime ticks are checked
// together: the tick clock is coarse, so a birth tick alone is not unique, but
// a PID whose birth tick changed was recycled and both reads must be
// discarded. State is deliberately excluded: a live process legitimately moves
// between running and sleeping between the two reads.
func procStatStable(a, b procStat) bool {
	return a.PID == b.PID &&
		a.Comm == b.Comm &&
		a.SessionID == b.SessionID &&
		a.TTY == b.TTY &&
		a.StartTicks == b.StartTicks
}

// fileStatStable reports whether two fstats of the same descriptor describe an
// unchanged file. Device, inode, size and timestamps together catch a replaced
// image and a concurrent rewrite.
func fileStatStable(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev &&
		a.Ino == b.Ino &&
		a.Mode == b.Mode &&
		a.Size == b.Size &&
		a.Mtim == b.Mtim &&
		a.Ctim == b.Ctim
}

// readProcFileBounded reads at most limit bytes from a proc file. A file that
// is larger than limit, or that cannot be read, is an error; the parser never
// sees a prefix of a longer line and never streams an unbounded proc file.
func readProcFileBounded(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, limit+1)
	n, err := io.ReadFull(f, buf)
	switch {
	case err == nil:
		return nil, errProcFileTooLarge
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return buf[:n], nil
	default:
		return nil, err
	}
}

// parseProcStat parses one /proc/<pid>/stat line. It is a pure function of its
// input so malformed, truncated, overflowed and adversarial lines can be
// tested without a live process.
//
// comm is delimited by the first '(' and the *last* ')' on the line, because
// the kernel permits parenthesis characters inside comm. Everything after that
// ')' must be single-space separated decimal fields; only the fields this
// package needs are range-checked, the rest are validated as well-formed.
func parseProcStat(raw []byte) (procStat, error) {
	var st procStat
	if len(raw) > procStatReadLimit {
		return st, errProcStatMalformed
	}
	line := bytes.TrimSuffix(raw, []byte("\n"))
	if len(line) == 0 || bytes.IndexByte(line, 0) >= 0 {
		return st, errProcStatMalformed
	}
	open := bytes.IndexByte(line, '(')
	if open < 2 || line[open-1] != ' ' {
		return st, errProcStatMalformed
	}
	pid, err := parseProcUint(line[:open-1], 32)
	if err != nil {
		return st, err
	}
	closeIdx := bytes.LastIndexByte(line, ')')
	if closeIdx < open+1 {
		return st, errProcStatMalformed
	}
	comm := line[open+1 : closeIdx]
	if len(comm) > procCommMax {
		return st, errProcStatMalformed
	}
	rest := line[closeIdx+1:]
	if len(rest) == 0 || rest[0] != ' ' {
		return st, errProcStatMalformed
	}
	fields := bytes.Split(rest[1:], []byte(" "))
	// state .. starttime need the first twenty tail fields.
	if len(fields) < 20 {
		return st, errProcStatMalformed
	}
	for i := 0; i < 20; i++ {
		if len(fields[i]) == 0 {
			return st, errProcStatMalformed
		}
	}
	if len(fields[0]) != 1 || !isProcStateByte(fields[0][0]) {
		return st, errProcStatMalformed
	}
	session, err := parseProcUint(fields[3], 32)
	if err != nil {
		return st, err
	}
	tty, err := parseProcInt(fields[4], 32)
	if err != nil {
		return st, err
	}
	start, err := parseProcUint(fields[19], 64)
	if err != nil {
		return st, err
	}
	st.PID = uint32(pid)
	st.Comm = string(comm)
	st.State = fields[0][0]
	st.SessionID = uint32(session)
	st.TTY = tty
	st.StartTicks = start
	return st, nil
}

func isProcStateByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// parseProcUint parses an unsigned decimal field of the given bit size,
// rejecting signs, empty fields, non-digits and overflow.
func parseProcUint(b []byte, bits int) (uint64, error) {
	if len(b) == 0 {
		return 0, errProcStatMalformed
	}
	v, err := strconv.ParseUint(string(b), 10, bits)
	if err != nil {
		return 0, errProcStatMalformed
	}
	return v, nil
}

// parseProcInt parses a signed decimal field of the given bit size. tty_nr is
// an int in the kernel, so it is parsed signed; negative values are rejected
// later as invalid terminal devices rather than here.
func parseProcInt(b []byte, bits int) (int64, error) {
	if len(b) == 0 {
		return 0, errProcStatMalformed
	}
	v, err := strconv.ParseInt(string(b), 10, bits)
	if err != nil {
		return 0, errProcStatMalformed
	}
	return v, nil
}
