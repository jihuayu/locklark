//go:build linux

package browserhost

// Tests for CLI terminal attestation.
//
// The parser tests are pure: they feed hand-built and adversarial
// /proc/<pid>/stat lines to parseProcStat and never touch a process. The
// staleness tests are pure too: they drive procStatStable/fileStatStable with
// mutated snapshots, which is how a recycled PID or a swapped executable looks
// to the code. The end-to-end tests use a real Linux PTY and a real child
// process: the child calls setsid(2) and makes the pty its controlling
// terminal (SysProcAttr.Setsid + Setctty), so the attested identity is checked
// against a kernel-provided tty_nr/session/start-time rather than a fixture.
// The only process these tests ever signal is their own child.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	cliTerminalHelperEnv = "BROWSERHOST_CLI_TERMINAL_HELPER_PROCESS"
	cliTerminalReadyLine = "ready"
	cliTerminalDialEnv   = "BROWSERHOST_CLI_TERMINAL_DIAL_SOCKET"

	// Test-only control channel for the same-path re-exec regression. Nothing
	// in the product reads these; only the helper copy of this test binary.
	cliTerminalReexecPathEnv = "BROWSERHOST_CLI_TERMINAL_REEXEC_PATH"
	cliTerminalReexecNextEnv = "BROWSERHOST_CLI_TERMINAL_REEXEC_NEXT_PATH"
	cliTerminalReexecDoneEnv = "BROWSERHOST_CLI_TERMINAL_REEXEC_DONE"
)

// TestCLITerminalHelperProcess is not a real test. It is re-executed as the
// peer process by the attestation tests: it announces readiness on stdout (the
// pty or pipe) and blocks until its stdin delivers a byte. It never signals
// anything and never inspects the parent's state.
func TestCLITerminalHelperProcess(t *testing.T) {
	if os.Getenv(cliTerminalHelperEnv) != "1" {
		t.Skip("helper process for CLI terminal attestation tests")
	}
	if path := os.Getenv(cliTerminalDialEnv); path != "" {
		conn, err := net.Dial("unix", path)
		if err != nil {
			os.Exit(4)
		}
		defer conn.Close()
	}
	if _, err := os.Stdout.WriteString(cliTerminalReadyLine + "\n"); err != nil {
		os.Exit(3)
	}
	if next := os.Getenv(cliTerminalReexecNextEnv); next != "" && os.Getenv(cliTerminalReexecDoneEnv) != "1" {
		target := os.Getenv(cliTerminalReexecPathEnv)
		buf := make([]byte, 1)
		if _, err := os.Stdin.Read(buf); err != nil {
			os.Exit(5)
		}
		if target == "" || target == next {
			os.Exit(6)
		}
		// Atomically put inode B at the exact pathname inode A is running
		// from, then exec that same pathname. The PID, start time and
		// readlink text are unchanged; only the resolved inode changes.
		if err := os.Rename(next, target); err != nil {
			os.Exit(7)
		}
		env := append(os.Environ(), cliTerminalReexecDoneEnv+"=1")
		if err := unix.Exec(target, []string{target, "-test.run=^TestCLITerminalHelperProcess$"}, env); err != nil {
			os.Exit(8)
		}
		os.Exit(9)
	}
	buf := make([]byte, 1)
	_, _ = os.Stdin.Read(buf)
}

// testProcStatLine builds a kernel-shaped /proc/<pid>/stat line. The tail is
// assembled positionally so field indices match proc(5) exactly: session is
// field 6, tty_nr field 7, starttime field 22.
func testProcStatLine(pid, comm, state, session, tty, start string) string {
	f := []string{pid, "(" + comm + ")", state, "1", "1", session, tty}
	// Fields 1..21 (through itrealvalue) are positional filler; starttime is
	// field 22, so the builder must hold 21 entries before appending it.
	for len(f) < 21 {
		f = append(f, "0")
	}
	f = append(f, start, "0", "0")
	return strings.Join(f, " ")
}

func TestParseProcStatAcceptsKernelShape(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		pid     uint32
		comm    string
		state   byte
		session uint32
		tty     int64
		start   uint64
	}{
		{
			name:    "simple",
			line:    testProcStatLine("1234", "sh", "S", "5678", "34816", "900"),
			pid:     1234,
			comm:    "sh",
			state:   'S',
			session: 5678,
			tty:     34816,
			start:   900,
		},
		{
			name:    "comm with spaces and parens",
			line:    testProcStatLine("77", "a b)c(d", "R", "77", "34817", "1"),
			pid:     77,
			comm:    "a b)c(d",
			state:   'R',
			session: 77,
			tty:     34817,
			start:   1,
		},
		{
			name:    "empty comm",
			line:    testProcStatLine("9", "", "S", "9", "1025", "42"),
			pid:     9,
			comm:    "",
			state:   'S',
			session: 9,
			tty:     1025,
			start:   42,
		},
		{
			name:    "zombie state",
			line:    testProcStatLine("10", "defunct", "Z", "10", "0", "43"),
			pid:     10,
			comm:    "defunct",
			state:   'Z',
			session: 10,
			tty:     0,
			start:   43,
		},
		{
			name:    "trailing newline and extra fields",
			line:    testProcStatLine("4294967294", "max", "S", "4294967294", "34818", "18446744073709551615") + " 1 2 3\n",
			pid:     4294967294,
			comm:    "max",
			state:   'S',
			session: 4294967294,
			tty:     34818,
			start:   18446744073709551615,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, err := parseProcStat([]byte(tc.line))
			if err != nil {
				t.Fatalf("parseProcStat(%q): %v", tc.line, err)
			}
			if st.PID != tc.pid || st.Comm != tc.comm || st.State != tc.state ||
				st.SessionID != tc.session || st.TTY != tc.tty || st.StartTicks != tc.start {
				t.Fatalf("parsed %+v, want pid=%d comm=%q state=%c session=%d tty=%d start=%d",
					st, tc.pid, tc.comm, tc.state, tc.session, tc.tty, tc.start)
			}
		})
	}
}

func TestParseProcStatRejectsMalformed(t *testing.T) {
	good := testProcStatLine("1234", "sh", "S", "5678", "34816", "900")
	tests := []struct {
		name string
		line string
	}{
		{"empty", ""},
		{"only newline", "\n"},
		{"no parens", "1234 sh S 1 1 5678 34816 0"},
		{"missing space before comm", "1234(sh) S 1 1 5678 34816 0"},
		{"no pid", "(sh) S 1 1 5678 34816 0"},
		{"leading space before pid", " 1234 (sh) S 1 1 5678 34816 0"},
		{"signed pid", "+1234 (sh) S 1 1 5678 34816 0"},
		{"non numeric pid", "pid (sh) S 1 1 5678 34816 0"},
		{"pid overflow", "4294967296 (sh) S 1 1 5678 34816 0"},
		{"huge pid", "99999999999999999999 (sh) S 1 1 5678 34816 0"},
		{"unterminated comm", strings.Replace(good, ")", "", 1)},
		{"truncated tail", "1234 (sh) S 1 1 5678 34816 0"},
		{"short tail", "1234 (sh) S 1 1 5678 34816 0 0 0 0 0 0 0 0 0 0 0 0"},
		{"double space in tail", "1234 (sh) S  1 1 5678 34816 0 0 0 0 0 0 0 0 0 0 0 0 900 0 0"},
		{"two letter state", testProcStatLine("1234", "sh", "SS", "5678", "34816", "900")},
		{"numeric state", testProcStatLine("1234", "sh", "1", "5678", "34816", "900")},
		{"empty state", testProcStatLine("1234", "sh", "", "5678", "34816", "900")},
		{"non numeric session", testProcStatLine("1234", "sh", "S", "sid", "34816", "900")},
		{"session overflow", testProcStatLine("1234", "sh", "S", "4294967296", "34816", "900")},
		{"session huge", testProcStatLine("1234", "sh", "S", "18446744073709551616", "34816", "900")},
		{"tty overflow", testProcStatLine("1234", "sh", "S", "5678", "2147483648", "900")},
		{"tty non numeric", testProcStatLine("1234", "sh", "S", "5678", "pts/0", "900")},
		{"start overflow", testProcStatLine("1234", "sh", "S", "5678", "34816", "18446744073709551616")},
		{"start junk", testProcStatLine("1234", "sh", "S", "5678", "34816", "900x")},
		{"embedded NUL", strings.Replace(good, "sh", "s\x00h", 1)},
		{"comm too long", testProcStatLine("1234", strings.Repeat("x", procCommMax+1), "S", "5678", "34816", "900")},
		{"oversized buffer", strings.Repeat("1", procStatReadLimit+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if st, err := parseProcStat([]byte(tc.line)); err == nil {
				t.Fatalf("parseProcStat(%q) = %+v, want error", tc.line, st)
			} else if !errors.Is(err, errProcStatMalformed) {
				t.Fatalf("parseProcStat(%q) error = %v, want errProcStatMalformed", tc.line, err)
			}
		})
	}
}

// TestParseProcStatNegativeTTYIsParsedButRefused separates parsing from policy:
// a negative tty_nr is a well-formed kernel field, but it is not a terminal and
// must never attest.
func TestParseProcStatNegativeTTYIsParsedButRefused(t *testing.T) {
	line := testProcStatLine("1234", "sh", "S", "1234", "-1", "900")
	st, err := parseProcStat([]byte(line))
	if err != nil {
		t.Fatalf("parseProcStat negative tty: %v", err)
	}
	if st.TTY != -1 {
		t.Fatalf("tty = %d, want -1", st.TTY)
	}
	if err := checkPeerProcStat(st); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("checkPeerProcStat(negative tty) = %v, want ErrCLITerminalRefused", err)
	}
}

func TestCheckPeerProcStatRefusals(t *testing.T) {
	base := procStat{PID: 1234, Comm: "sh", State: 'S', SessionID: 1234, TTY: 34816, StartTicks: 900}
	if err := checkPeerProcStat(base); err != nil {
		t.Fatalf("baseline must be accepted: %v", err)
	}
	noTTY := base
	noTTY.TTY = 0
	if err := checkPeerProcStat(noTTY); !errors.Is(err, ErrCLITerminalNoTTY) {
		t.Fatalf("no tty = %v, want ErrCLITerminalNoTTY", err)
	}
	noSession := base
	noSession.SessionID = 0
	if err := checkPeerProcStat(noSession); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("no session = %v, want ErrCLITerminalRefused", err)
	}
	noStart := base
	noStart.StartTicks = 0
	if err := checkPeerProcStat(noStart); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("no start time = %v, want ErrCLITerminalRefused", err)
	}
	for _, state := range []byte{'Z', 'X', 'x'} {
		dead := base
		dead.State = state
		if err := checkPeerProcStat(dead); !errors.Is(err, ErrCLITerminalRefused) {
			t.Fatalf("state %q = %v, want ErrCLITerminalRefused", state, err)
		}
	}
}

// TestProcStatStableDetectsRecycledPID covers staleness purely: a recycled PID
// reuses the number but never the creation ticks, comm or session.
func TestProcStatStableDetectsRecycledPID(t *testing.T) {
	base := procStat{PID: 4242, Comm: "sh", State: 'S', SessionID: 4242, TTY: 34816, StartTicks: 700}
	if !procStatStable(base, base) {
		t.Fatal("identical snapshots must be stable")
	}
	// Scheduling churn is not instability: state is excluded on purpose.
	churn := base
	churn.State = 'R'
	if !procStatStable(base, churn) {
		t.Fatal("state churn must not be treated as an unstable process")
	}
	mutations := []struct {
		name   string
		mutate func(*procStat)
	}{
		{"different pid", func(v *procStat) { v.PID++ }},
		{"recycled comm", func(v *procStat) { v.Comm = "evil" }},
		{"different session", func(v *procStat) { v.SessionID++ }},
		{"different tty", func(v *procStat) { v.TTY++ }},
		{"recycled birth", func(v *procStat) { v.StartTicks++ }},
	}
	for _, m := range mutations {
		other := base
		m.mutate(&other)
		if procStatStable(base, other) {
			t.Errorf("%s: snapshots wrongly considered stable", m.name)
		}
		if procStatStable(other, base) {
			t.Errorf("%s: reverse direction wrongly considered stable", m.name)
		}
	}
}

// TestFileStatStableDetectsSwap covers the executable side of staleness: the
// same fd must keep describing the same inode, size and timestamps.
func TestFileStatStableDetectsSwap(t *testing.T) {
	base := unix.Stat_t{
		Dev:  10,
		Ino:  20,
		Mode: unix.S_IFREG | 0o755,
		Size: 4096,
		Mtim: unix.Timespec{Sec: 100, Nsec: 200},
		Ctim: unix.Timespec{Sec: 100, Nsec: 200},
	}
	if !fileStatStable(base, base) {
		t.Fatal("identical fstats must be stable")
	}
	mutations := []struct {
		name   string
		mutate func(*unix.Stat_t)
	}{
		{"different device", func(v *unix.Stat_t) { v.Dev++ }},
		{"different inode", func(v *unix.Stat_t) { v.Ino++ }},
		{"different mode", func(v *unix.Stat_t) { v.Mode = unix.S_IFREG | 0o700 }},
		{"different size", func(v *unix.Stat_t) { v.Size++ }},
		{"different mtime", func(v *unix.Stat_t) { v.Mtim.Nsec++ }},
		{"different ctime", func(v *unix.Stat_t) { v.Ctim.Sec++ }},
	}
	for _, m := range mutations {
		other := base
		m.mutate(&other)
		if fileStatStable(base, other) {
			t.Errorf("%s: fstats wrongly considered stable", m.name)
		}
	}
}

func TestCheckExecutableSizeBounds(t *testing.T) {
	for _, size := range []int64{-1, 0, cliTerminalMaxExecutableBytes + 1} {
		if err := checkExecutableSize(size); !errors.Is(err, ErrCLITerminalRefused) {
			t.Fatalf("checkExecutableSize(%d) = %v, want refusal", size, err)
		}
	}
	for _, size := range []int64{1, 4096, cliTerminalMaxExecutableBytes} {
		if err := checkExecutableSize(size); err != nil {
			t.Fatalf("checkExecutableSize(%d) = %v, want nil", size, err)
		}
	}
}

func TestReadProcFileBoundedRefusesOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stat")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProcFileBounded(path, 16); !errors.Is(err, errProcFileTooLarge) {
		t.Fatalf("bounded read of oversized file = %v, want errProcFileTooLarge", err)
	}
	got, err := readProcFileBounded(path, 32)
	if err != nil {
		t.Fatalf("bounded read at exact limit: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("read %d bytes, want 32", len(got))
	}
	if _, err := readProcFileBounded(filepath.Join(dir, "missing"), 16); err == nil {
		t.Fatal("bounded read of a missing file must fail")
	}
}

// TestParseProcStatRealKernel parses the live kernel's own line and checks it
// against values the kernel reports through other syscalls.
func TestParseProcStatRealKernel(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatalf("read /proc/self/stat: %v", err)
	}
	st, err := parseProcStat(raw)
	if err != nil {
		t.Fatalf("parseProcStat(/proc/self/stat): %v", err)
	}
	if st.PID != uint32(os.Getpid()) {
		t.Fatalf("pid = %d, want %d", st.PID, os.Getpid())
	}
	sid, err := unix.Getsid(0)
	if err != nil {
		t.Fatalf("getsid: %v", err)
	}
	if st.SessionID != uint32(sid) {
		t.Fatalf("session = %d, want %d", st.SessionID, sid)
	}
	if st.StartTicks == 0 {
		t.Fatal("start ticks must be non-zero")
	}
	if comm, err := os.ReadFile("/proc/self/comm"); err == nil {
		if want := strings.TrimRight(string(comm), "\n"); st.Comm != want {
			t.Fatalf("comm = %q, want %q", st.Comm, want)
		}
	}
}

func TestAttestCLITerminalRefusesUnattestablePeer(t *testing.T) {
	// PID 0 is not a process id and is refused before any /proc access.
	if id, err := AttestCLITerminal(Peer{}); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("zero pid = (%+v, %v), want ErrCLITerminalRefused", id, err)
	} else if id != (CLITerminalIdentity{}) {
		t.Fatalf("refusal fabricated identity %+v", id)
	}

	raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Skipf("no /proc/sys/kernel/pid_max: %v", err)
	}
	pidMax, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pidMax <= 0 || pidMax >= int(^uint32(0)) {
		t.Skipf("unusable pid_max %q: %v", raw, err)
	}
	peer := Peer{User: "UID forged", PID: uint32(pidMax + 1), Process: "/bin/sh"}
	id, err := AttestCLITerminal(peer)
	if !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("nonexistent pid = (%+v, %v), want ErrCLITerminalRefused", id, err)
	}
	if id != (CLITerminalIdentity{}) {
		t.Fatalf("refusal fabricated identity %+v", id)
	}
	expected := CLITerminalIdentity{
		PeerPID:            1,
		TTYDevice:          1,
		SessionID:          1,
		SessionLeaderStart: 1,
		PeerStart:          1,
		ExecutablePath:     "/bin/sh",
		ExecutableSHA256:   strings.Repeat("a", 64),
	}
	if VerifyCLITerminal(peer, expected) {
		t.Fatal("VerifyCLITerminal accepted a peer that cannot be attested")
	}
}

func TestVerifyCLITerminalRejectsMalformedExpectation(t *testing.T) {
	peer := Peer{PID: uint32(os.Getpid())}
	base := CLITerminalIdentity{
		PeerPID:            uint32(os.Getpid()),
		TTYDevice:          34816,
		SessionID:          7,
		SessionLeaderStart: 11,
		PeerStart:          12,
		ExecutablePath:     "/usr/bin/true",
		ExecutableSHA256:   strings.Repeat("a", 64),
	}
	if VerifyCLITerminal(peer, CLITerminalIdentity{}) {
		t.Fatal("zero identity must never verify")
	}
	missingPeerPID := base
	missingPeerPID.PeerPID = 0
	if VerifyCLITerminal(peer, missingPeerPID) {
		t.Fatal("identity without a peer pid must never verify")
	}
	missingPath := base
	missingPath.ExecutablePath = ""
	if VerifyCLITerminal(peer, missingPath) {
		t.Fatal("identity without an executable path must never verify")
	}
	shortDigest := base
	shortDigest.ExecutableSHA256 = "abc"
	if VerifyCLITerminal(peer, shortDigest) {
		t.Fatal("short digest must never verify")
	}
	upperDigest := base
	upperDigest.ExecutableSHA256 = strings.Repeat("A", 64)
	if VerifyCLITerminal(peer, upperDigest) {
		t.Fatal("non-lowercase-hex digest must never verify")
	}
}

// openTestPTY allocates a fresh pty pair. The slave is opened O_NOCTTY so it
// does not become the test process's terminal.
func openTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx on this host: %v", err)
	}
	if err := unix.IoctlSetPointerInt(mfd, uint(unix.TIOCSPTLCK), 0); err != nil {
		_ = unix.Close(mfd)
		t.Fatalf("unlock pty: %v", err)
	}
	number, err := unix.IoctlGetInt(mfd, uint(unix.TIOCGPTN))
	if err != nil {
		_ = unix.Close(mfd)
		t.Fatalf("pty number: %v", err)
	}
	sfd, err := unix.Open(fmt.Sprintf("/dev/pts/%d", number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(mfd)
		t.Fatalf("open pty slave: %v", err)
	}
	master = os.NewFile(uintptr(mfd), "ptmx")
	slave = os.NewFile(uintptr(sfd), "pts")
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	return master, slave
}

// startHelperPeer re-executes this test binary as the helper peer, restricted
// to the helper test only.
func startHelperPeer(t *testing.T, attrs *syscall.SysProcAttr) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestCLITerminalHelperProcess$")
	cmd.Env = append(os.Environ(), cliTerminalHelperEnv+"=1")
	cmd.SysProcAttr = attrs
	return cmd
}

// readReadyLine waits (bounded) for the helper's readiness banner.
func readReadyLine(t *testing.T, r io.Reader) {
	t.Helper()
	readReadyLineFrom(t, bufio.NewReader(r))
}

// readReadyLineFrom reads one readiness banner from a shared buffered reader,
// so a re-exec helper can announce itself a second time without losing bytes
// that the first read buffered.
func readReadyLineFrom(t *testing.T, r *bufio.Reader) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		line, err := r.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if got := strings.TrimRight(line, "\r\n"); got != cliTerminalReadyLine {
			done <- fmt.Errorf("unexpected helper banner %q", got)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("helper never became ready: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for helper readiness")
	}
}

func hashFileForTest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestAttestCLITerminalLinuxPTY attests a real, live child that owns a real
// pty as its controlling terminal.
func TestAttestCLITerminalLinuxPTY(t *testing.T) {
	master, slave := openTestPTY(t)
	cmd := startHelperPeer(t, &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0})
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	var waitOnce sync.Once
	var waitErr error
	waitHelper := func() error {
		waitOnce.Do(func() { waitErr = cmd.Wait() })
		return waitErr
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = waitHelper()
	})
	// The child holds its own copies of the slave; drop the parent's so the pty
	// is only owned by the peer.
	_ = slave.Close()

	peerPID := uint32(cmd.Process.Pid)
	readReadyLine(t, master)

	peer := Peer{User: "UID forged", PID: peerPID, Process: "/definitely/not/the/executable"}
	id, err := AttestCLITerminal(peer)
	if err != nil {
		t.Fatalf("AttestCLITerminal(real pty peer): %v", err)
	}
	if id.UID != uint32(os.Geteuid()) {
		t.Fatalf("uid = %d, want euid %d", id.UID, os.Geteuid())
	}
	if id.PeerPID != peerPID {
		t.Fatalf("peer pid = %d, want helper pid %d", id.PeerPID, peerPID)
	}
	if id.TTYDevice == 0 {
		t.Fatal("tty device must be recorded for a peer on a pty")
	}
	// The helper called setsid(2), so it leads its own session.
	if id.SessionID != peerPID {
		t.Fatalf("session = %d, want helper pid %d", id.SessionID, peerPID)
	}
	if id.SessionLeaderStart != id.PeerStart {
		t.Fatalf("session leader start %d, peer start %d: helper leads its own session",
			id.SessionLeaderStart, id.PeerStart)
	}
	if id.PeerStart == 0 {
		t.Fatal("peer start ticks must be non-zero")
	}
	if id.ExecutablePath == peer.Process {
		t.Fatal("attestation trusted peer.Process instead of /proc/<pid>/exe")
	}
	selfExe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatalf("readlink /proc/self/exe: %v", err)
	}
	if id.ExecutablePath != selfExe {
		t.Fatalf("executable path = %q, want the running binary %q", id.ExecutablePath, selfExe)
	}
	if want := hashFileForTest(t, "/proc/self/exe"); id.ExecutableSHA256 != want {
		t.Fatalf("executable digest = %q, want %q", id.ExecutableSHA256, want)
	}

	// Independent /proc cross-check: the recorded session must really be the
	// peer's kernel session, and that session's leader must really carry the
	// recorded tty device and creation ticks. This keeps the identity from
	// being self-referential.
	peerRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", peerPID))
	if err != nil {
		t.Fatalf("read peer stat: %v", err)
	}
	livePeer, err := parseProcStat(peerRaw)
	if err != nil {
		t.Fatalf("parse peer stat: %v", err)
	}
	if livePeer.PID != id.PeerPID || livePeer.SessionID != id.SessionID || livePeer.TTY != int64(id.TTYDevice) || livePeer.StartTicks != id.PeerStart {
		t.Fatalf("identity %+v disagrees with live peer stat %+v", id, livePeer)
	}
	leaderRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", id.SessionID))
	if err != nil {
		t.Fatalf("read session leader stat: %v", err)
	}
	liveLeader, err := parseProcStat(leaderRaw)
	if err != nil {
		t.Fatalf("parse session leader stat: %v", err)
	}
	if liveLeader.PID != id.SessionID || liveLeader.SessionID != id.SessionID {
		t.Fatalf("session leader stat %+v does not describe session %d", liveLeader, id.SessionID)
	}
	if liveLeader.TTY != int64(id.TTYDevice) {
		t.Fatalf("session leader tty = %d, want %d", liveLeader.TTY, id.TTYDevice)
	}
	if liveLeader.StartTicks != id.SessionLeaderStart {
		t.Fatalf("session leader start = %d, want %d", liveLeader.StartTicks, id.SessionLeaderStart)
	}

	// Attestation is deterministic: two reads of the same live peer agree.
	again, err := AttestCLITerminal(peer)
	if err != nil {
		t.Fatalf("second attestation: %v", err)
	}
	if again != id {
		t.Fatalf("attestation is not stable:\n first %+v\nsecond %+v", id, again)
	}

	// Verify re-derives from the kernel, so a forged peer.Process or peer.User
	// cannot change the answer.
	if !VerifyCLITerminal(peer, id) {
		t.Fatal("VerifyCLITerminal rejected a freshly attested identity")
	}
	if !VerifyCLITerminal(Peer{PID: peerPID}, id) {
		t.Fatal("VerifyCLITerminal must ignore peer.Process and peer.User")
	}
	// Start ticks are quantized, so a different PID can share PeerStart. This
	// is an actual owned-process fixture: id is the live helper's identity and
	// only PeerPID is changed.
	sameTickWrongPID := id
	sameTickWrongPID.PeerPID++
	if sameTickWrongPID.PeerStart != id.PeerStart {
		t.Fatal("test setup: PID mutation changed the birth tick")
	}
	if VerifyCLITerminal(Peer{PID: peerPID}, sameTickWrongPID) {
		t.Fatal("identity confirmed for a different PID sharing the same birth tick")
	}
	if VerifyCLITerminal(Peer{PID: uint32(os.Getpid())}, id) {
		t.Fatal("identity verified for a different peer pid")
	}

	tampered := []struct {
		name   string
		mutate func(*CLITerminalIdentity)
	}{
		{"peer pid", func(v *CLITerminalIdentity) { v.PeerPID++ }},
		{"uid", func(v *CLITerminalIdentity) { v.UID++ }},
		{"tty device", func(v *CLITerminalIdentity) { v.TTYDevice++ }},
		{"session id", func(v *CLITerminalIdentity) { v.SessionID++ }},
		{"session leader start", func(v *CLITerminalIdentity) { v.SessionLeaderStart++ }},
		{"peer start", func(v *CLITerminalIdentity) { v.PeerStart++ }},
		{"executable path", func(v *CLITerminalIdentity) { v.ExecutablePath += ".evil" }},
		{"executable digest", func(v *CLITerminalIdentity) { v.ExecutableSHA256 = strings.Repeat("0", 64) }},
	}
	for _, tc := range tampered {
		wrong := id
		tc.mutate(&wrong)
		if VerifyCLITerminal(peer, wrong) {
			t.Errorf("VerifyCLITerminal accepted a tampered %s", tc.name)
		}
	}

	// Let the helper exit on its own; we never signal anything but our child.
	if _, err := master.Write([]byte("q\n")); err != nil {
		t.Logf("write quit to pty: %v", err)
	}
	exitDone := make(chan error, 1)
	go func() { exitDone <- waitHelper() }()
	select {
	case err := <-exitDone:
		if err != nil {
			t.Fatalf("helper exit: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper did not exit after the quit byte")
	}
}

// TestAttestCLITerminalLinuxNoTTYRefused proves the fixed no-terminal refusal:
// the helper runs in its own session with pipes, so its tty_nr is 0.
func TestAttestCLITerminalLinuxNoTTYRefused(t *testing.T) {
	cmd := startHelperPeer(t, &syscall.SysProcAttr{Setsid: true})
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	var waitOnce sync.Once
	waitHelper := func() {
		waitOnce.Do(func() { _ = cmd.Wait() })
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		waitHelper()
	})
	readReadyLine(t, stdout)

	peer := Peer{User: "UID forged", PID: uint32(cmd.Process.Pid), Process: "/bin/sh"}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", peer.PID))
	if err != nil {
		t.Fatalf("read helper stat: %v", err)
	}
	st, err := parseProcStat(raw)
	if err != nil {
		t.Fatalf("parse helper stat: %v", err)
	}
	if st.TTY != 0 {
		t.Fatalf("helper tty_nr = %d, want 0 for a detached pipe-only child", st.TTY)
	}

	id, err := AttestCLITerminal(peer)
	if !errors.Is(err, ErrCLITerminalNoTTY) {
		t.Fatalf("AttestCLITerminal(no tty peer) = (%+v, %v), want ErrCLITerminalNoTTY", id, err)
	}
	if id != (CLITerminalIdentity{}) {
		t.Fatalf("no-tty refusal fabricated identity %+v", id)
	}
	expected := CLITerminalIdentity{
		PeerPID:            peer.PID,
		TTYDevice:          1,
		SessionID:          peer.PID,
		SessionLeaderStart: st.StartTicks,
		PeerStart:          st.StartTicks,
		ExecutablePath:     "/bin/sh",
		ExecutableSHA256:   strings.Repeat("a", 64),
	}
	if VerifyCLITerminal(peer, expected) {
		t.Fatal("VerifyCLITerminal accepted a peer without a controlling terminal")
	}
}

// TestAttestCLITerminalPeerPIDFromSocketCredentials proves that the attested
// PID is the kernel's peer credential of an authenticated socket, not a value a
// client could claim on the wire. The child connects to a real UNIX listener
// before announcing readiness and holds the connection for its lifetime; the
// parent reads SO_PEERCRED (through authenticatedPeer) and attests exactly that
// kernel-reported PID. No PID is ever read from the socket, and the peer's
// claimed process string is ignored.
func TestAttestCLITerminalPeerPIDFromSocketCredentials(t *testing.T) {
	master, slave := openTestPTY(t)
	dir, err := os.MkdirTemp("", "clitter")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	cmd := startHelperPeer(t, &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0})
	cmd.Env = append(cmd.Env, cliTerminalDialEnv+"="+sock)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	var waitOnce sync.Once
	var waitErr error
	waitHelper := func() error {
		waitOnce.Do(func() { waitErr = cmd.Wait() })
		return waitErr
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = waitHelper()
	})
	_ = slave.Close()
	readReadyLine(t, master)

	if err := ln.(*net.UnixListener).SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("listener deadline: %v", err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept peer: %v", err)
	}
	defer conn.Close()
	_ = ln.Close()

	peer, err := authenticatedPeer(conn)
	if err != nil {
		t.Fatalf("authenticatedPeer: %v", err)
	}
	if peer.PID == 0 {
		t.Fatal("SO_PEERCRED produced no pid")
	}
	if peer.PID != uint32(cmd.Process.Pid) {
		t.Fatalf("SO_PEERCRED pid = %d, spawned child is %d", peer.PID, cmd.Process.Pid)
	}

	// Attest the authenticated peer, with a deliberately false process string:
	// only kernel state for peer.PID may contribute.
	forged := Peer{User: "UID forged", PID: peer.PID, Process: "/bin/false"}
	id, err := AttestCLITerminal(forged)
	if err != nil {
		t.Fatalf("attest authenticated peer: %v", err)
	}
	if id.PeerPID != peer.PID {
		t.Fatalf("peer pid = %d, want SO_PEERCRED pid %d", id.PeerPID, peer.PID)
	}
	if id.SessionID != peer.PID {
		t.Fatalf("session = %d, want %d (helper called setsid)", id.SessionID, peer.PID)
	}
	if id.TTYDevice == 0 {
		t.Fatal("authenticated peer must report its pty device")
	}
	if id.ExecutablePath == forged.Process {
		t.Fatal("attestation trusted the peer's claimed process path")
	}
	if id.ExecutableSHA256 == strings.Repeat("0", 64) {
		t.Fatal("executable digest was never computed")
	}
	if !VerifyCLITerminal(peer, id) {
		t.Fatal("VerifyCLITerminal rejected the authenticated peer's own identity")
	}

	if _, err := master.Write([]byte("q\n")); err != nil {
		t.Logf("write quit to pty: %v", err)
	}
	exitDone := make(chan error, 1)
	go func() { exitDone <- waitHelper() }()
	select {
	case err := <-exitDone:
		if err != nil {
			t.Fatalf("helper exit: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper did not exit after the quit byte")
	}
}

// copyExecutableForTest copies the test binary so the regression can run two
// distinct inodes from the same pathname. Only files owned by the test are
// created and executed.
func copyExecutableForTest(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy %s: %v", dst, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", dst, err)
	}
}

// TestCheckExecutableLinkCurrentRejectsSamePathReexec is the synthetic
// same-path regression. The child starts as inode A; the test opens
// /proc/<pid>/exe so the old descriptor stays pinned to A; the child then
// atomically renames inode B over the same pathname and execs it. PID birth,
// readlink text and the old descriptor all stay on A, but /proc/<pid>/exe now
// resolves to a different inode, so the final gate must refuse A's digest even
// though it was correctly hashed from a stable descriptor.
func TestCheckExecutableLinkCurrentRejectsSamePathReexec(t *testing.T) {
	dir := t.TempDir()
	peerPath := filepath.Join(dir, "peer")
	nextPath := filepath.Join(dir, "peer.next")
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	copyExecutableForTest(t, self, peerPath)
	copyExecutableForTest(t, self, nextPath)

	cmd := exec.Command(peerPath, "-test.run=^TestCLITerminalHelperProcess$")
	cmd.Env = append(os.Environ(),
		cliTerminalHelperEnv+"=1",
		cliTerminalReexecPathEnv+"="+peerPath,
		cliTerminalReexecNextEnv+"="+nextPath,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	var waitOnce sync.Once
	var waitErr error
	waitHelper := func() error {
		waitOnce.Do(func() { waitErr = cmd.Wait() })
		return waitErr
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = waitHelper()
	})

	pid := uint32(cmd.Process.Pid)
	link := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe"
	ready := bufio.NewReader(stdout)
	readReadyLineFrom(t, ready)

	// The first image is live and the final gate accepts the old descriptor.
	stateBefore, err := readProcStat(pid)
	if err != nil {
		t.Fatalf("read helper stat before reexec: %v", err)
	}
	pathBefore, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink before reexec: %v", err)
	}
	if pathBefore != peerPath {
		t.Fatalf("initial executable path = %q, want %q", pathBefore, peerPath)
	}
	oldFD, err := os.Open(link)
	if err != nil {
		t.Fatalf("open initial executable: %v", err)
	}
	defer oldFD.Close()
	var oldBefore unix.Stat_t
	if err := unix.Fstat(int(oldFD.Fd()), &oldBefore); err != nil {
		t.Fatalf("fstat initial executable: %v", err)
	}
	if err := checkExecutableLinkCurrent(link, oldBefore); err != nil {
		t.Fatalf("final gate rejected the live first image: %v", err)
	}
	if _, err := stdin.Write([]byte("x")); err != nil {
		t.Fatalf("trigger reexec: %v", err)
	}
	readReadyLineFrom(t, ready)

	// Same PID and birth, same /proc/<pid>/exe text, and the old descriptor is
	// still the very same inode A. Replacing the pathname does change A's
	// ctime/link count, but not the dev/inode/type the gate compares.
	stateAfter, err := readProcStat(pid)
	if err != nil {
		t.Fatalf("read helper stat after reexec: %v", err)
	}
	if !procStatStable(stateBefore, stateAfter) {
		t.Fatalf("PID/birth changed across reexec: before %+v after %+v", stateBefore, stateAfter)
	}
	pathAfter, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink after reexec: %v", err)
	}
	if pathAfter != pathBefore {
		t.Fatalf("readlink text changed across reexec: before %q after %q", pathBefore, pathAfter)
	}
	var oldAfter unix.Stat_t
	if err := unix.Fstat(int(oldFD.Fd()), &oldAfter); err != nil {
		t.Fatalf("fstat old executable after reexec: %v", err)
	}
	if !sameExecutableFile(oldBefore, oldAfter) || oldBefore.Size != oldAfter.Size {
		t.Fatalf("old executable descriptor changed identity across reexec: before %+v after %+v", oldBefore, oldAfter)
	}

	var current unix.Stat_t
	if err := unix.Stat(link, &current); err != nil {
		t.Fatalf("stat current executable: %v", err)
	}
	if current.Mode&unix.S_IFMT != unix.S_IFREG {
		t.Fatalf("current executable mode = %#o, want a regular file", current.Mode)
	}
	if sameExecutableFile(oldAfter, current) {
		t.Fatalf("same-path reexec did not change the resolved inode: old %+v current %+v", oldAfter, current)
	}
	if err := checkExecutableLinkCurrent(link, oldAfter); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final inode gate = %v, want ErrCLITerminalRefused for old image A while B runs", err)
	}
	if err := checkExecutableLinkCurrent(link, current); err != nil {
		t.Fatalf("final inode gate rejected the currently running image B: %v", err)
	}

	_ = stdin.Close()
	exitDone := make(chan error, 1)
	go func() { exitDone <- waitHelper() }()
	select {
	case err := <-exitDone:
		if err != nil {
			t.Fatalf("helper exit: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper did not exit after stdin closed")
	}
}

// TestCLITerminalIdentityBindsPeerPIDAndBirth covers the coarse-tick case with
// controlled identities: two processes can share PeerStart, so PeerPID must be
// part of wellFormed and exact equality.
func TestCLITerminalIdentityBindsPeerPIDAndBirth(t *testing.T) {
	base := CLITerminalIdentity{
		PeerPID:            4242,
		UID:                1000,
		TTYDevice:          34816,
		SessionID:          4242,
		SessionLeaderStart: 700,
		PeerStart:          700,
		ExecutablePath:     "/usr/bin/true",
		ExecutableSHA256:   strings.Repeat("a", 64),
	}
	if !base.wellFormed() {
		t.Fatal("baseline identity must be well formed")
	}
	sameTickDifferentPID := base
	sameTickDifferentPID.PeerPID = 5252
	if sameTickDifferentPID.PeerStart != base.PeerStart {
		t.Fatal("test setup: PID change must not change PeerStart")
	}
	if !sameTickDifferentPID.wellFormed() {
		t.Fatal("identity with another PID must still be well formed")
	}
	if base.equal(sameTickDifferentPID) {
		t.Fatal("identities with the same birth tick but different PIDs compared equal")
	}
	missingPID := base
	missingPID.PeerPID = 0
	if missingPID.wellFormed() {
		t.Fatal("identity without a peer PID considered well formed")
	}
	differentBirth := base
	differentBirth.PeerStart++
	if base.equal(differentBirth) {
		t.Fatal("identities with the same PID but different birth ticks compared equal")
	}
}

// TestFinalLeaderCheckRefusesZombieAndTopologyChange drives the final leader
// gate with controlled snapshots. Liveness is checked separately from
// procStatStable, which deliberately ignores State.
func TestFinalLeaderCheckRefusesZombieAndTopologyChange(t *testing.T) {
	peer := procStat{PID: 101, Comm: "peer", State: 'S', SessionID: 77, TTY: 34816, StartTicks: 700}
	leader := procStat{PID: 77, Comm: "leader", State: 'S', SessionID: 77, TTY: 34816, StartTicks: 699}
	if err := checkFinalLeaderStat(peer, leader, leader); err != nil {
		t.Fatalf("baseline final leader sample rejected: %v", err)
	}

	zombie := leader
	zombie.State = 'Z'
	if !procStatStable(leader, zombie) {
		t.Fatal("state churn must not be treated as a changed process")
	}
	if err := checkFinalLeaderStat(peer, leader, zombie); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final leader gate = %v, want refusal for zombie leader", err)
	}

	wrongTTY := leader
	wrongTTY.TTY++
	if err := checkFinalLeaderStat(peer, wrongTTY, wrongTTY); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final leader gate = %v, want refusal for terminal disagreement", err)
	}

	wrongSession := leader
	wrongSession.SessionID++
	if err := checkFinalLeaderStat(peer, wrongSession, wrongSession); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final leader gate = %v, want refusal for session disagreement", err)
	}

	younger := leader
	younger.StartTicks = peer.StartTicks + 1
	if err := checkFinalLeaderStat(peer, younger, younger); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final leader gate = %v, want refusal for a leader younger than the peer", err)
	}

	changedBirth := leader
	changedBirth.StartTicks++
	if err := checkFinalLeaderStat(peer, leader, changedBirth); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final leader gate = %v, want refusal for a changed leader birth", err)
	}
}

// TestCheckFinalPeerStatRefusesZombieAfterHash runs a real owned PTY helper,
// hashes its executable, then lets it exit without reaping so the final
// /proc/<pid>/stat sample is a zombie with the same PID/start/session/tty.
func TestCheckFinalPeerStatRefusesZombieAfterHash(t *testing.T) {
	master, slave := openTestPTY(t)
	cmd := startHelperPeer(t, &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0})
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	var waitOnce sync.Once
	var waitErr error
	waitHelper := func() error {
		waitOnce.Do(func() { waitErr = cmd.Wait() })
		return waitErr
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = waitHelper()
	})
	_ = slave.Close()

	pid := uint32(cmd.Process.Pid)
	readReadyLine(t, master)
	before, err := readProcStat(pid)
	if err != nil {
		t.Fatalf("read helper stat before exit: %v", err)
	}
	if err := checkPeerProcStat(before); err != nil {
		t.Fatalf("helper must be attestable before exit: %v", err)
	}
	if _, _, err := attestExecutable(pid); err != nil {
		t.Fatalf("hash helper executable before exit: %v", err)
	}

	// Let the helper exit but do not reap it yet: as its parent, the test
	// process keeps it visible as a zombie in /proc/<pid>/stat.
	if _, err := master.Write([]byte("q\n")); err != nil {
		t.Logf("write quit to pty: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var after procStat
	for {
		after, err = readProcStat(pid)
		if err == nil && after.State == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper did not become a visible zombie: last %+v err %v", after, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after.PID != before.PID || after.StartTicks != before.StartTicks {
		t.Fatalf("zombie lost the pid/birth pair: before %+v after %+v", before, after)
	}
	// This host also clears tty_nr on exit, so the real fixture may fail the
	// topology comparison as well as the liveness check; either way the final
	// gate must refuse. The controlled zombie test below isolates liveness.
	if err := checkFinalPeerStat(before, after); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final peer gate = %v, want refusal for zombie after hash", err)
	}

	exitDone := make(chan error, 1)
	go func() { exitDone <- waitHelper() }()
	select {
	case err := <-exitDone:
		if err != nil {
			t.Fatalf("helper exit: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper did not exit after the quit byte")
	}
}

// TestCheckFinalPeerStatRefusesZombieWithStableFields isolates the liveness
// re-check: every stable field (PID, birth, comm, session, tty) is unchanged
// and only State moves to zombie, exactly the case procStatStable cannot see.
func TestCheckFinalPeerStatRefusesZombieWithStableFields(t *testing.T) {
	before := procStat{PID: 101, Comm: "peer", State: 'S', SessionID: 101, TTY: 34816, StartTicks: 700}
	zombie := before
	zombie.State = 'Z'
	if !procStatStable(before, zombie) {
		t.Fatal("test setup: state-only change must look stable to procStatStable")
	}
	if err := checkFinalPeerStat(before, zombie); !errors.Is(err, ErrCLITerminalRefused) {
		t.Fatalf("final peer gate = %v, want refusal for a stable-field zombie", err)
	}
}
