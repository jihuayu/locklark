//go:build linux

package browserhost

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	linuxPeerProofHelperEnv    = "LOCKLARK_LINUX_PEER_PROOF_HELPER"
	linuxPeerProofSocketEnv    = "LOCKLARK_LINUX_PEER_PROOF_SOCKET"
	linuxPeerProofNonceEnv     = "LOCKLARK_LINUX_PEER_PROOF_NONCE"
	linuxPeerProofFixedNonce   = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	linuxPeerProofHelperWait   = 5 * time.Second
	linuxPeerProofSocketPrefix = "llp-"
)

// TestParseLinuxPeerStat uses synthetic procfs bytes only. It is not a
// real-process or kernel proof.
func TestParseLinuxPeerStat(t *testing.T) {
	dev := linuxDev(ttyMajor, 7)
	valid := []byte("123 (lock lark) S 1 2 3 " + strconv.FormatUint(dev, 10) + " 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 21")
	stat, ok := parseLinuxPeerStat(valid)
	if !ok || stat.ttyDev != dev || stat.startTime != 987654 {
		t.Fatalf("parseLinuxPeerStat = %#v,%v", stat, ok)
	}
	// A command name can contain both spaces and ')' before the delimiter.
	if _, ok := parseLinuxPeerStat([]byte("123 (x) y) S 1 2 3 " + strconv.FormatUint(dev, 10) + " 5 6 7 8 9 10 11 12 13 14 15 16 17 18 7 21")); !ok {
		t.Fatal("parenthesised command name was rejected")
	}
	for name, raw := range map[string][]byte{
		"missing-close": []byte("123 (locklark S 1"),
		"short":         []byte("123 (locklark) S 1 2 3 " + strconv.FormatUint(dev, 10)),
		"no-tty":        []byte("123 (locklark) S 1 2 3 0 5 6 7 8 9 10 11 12 13 14 15 16 17 18 7 21"),
		"zero-start":    []byte("123 (locklark) S 1 2 3 " + strconv.FormatUint(dev, 10) + " 5 6 7 8 9 10 11 12 13 14 15 16 17 18 0 21"),
		"bad-start":     []byte("123 (locklark) S 1 2 3 " + strconv.FormatUint(dev, 10) + " 5 6 7 8 9 10 11 12 13 14 15 16 17 18 nope 21"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := parseLinuxPeerStat(raw); ok {
				t.Fatal("malformed stat accepted")
			}
		})
	}
}

func TestLinuxOwnedPidFDCloseIsIdempotent(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal("pidfd unavailable")
	}
	owned, err := newLinuxOwnedPidFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.Close() })
	foreign, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal("foreign pidfd unavailable")
	}
	t.Cleanup(func() { _ = unix.Close(foreign) })
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatal("owned pidfd was not open before Close")
	}
	if !owned.live() {
		t.Fatal("owned pidfd is not live")
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("Close did not close the owned descriptor")
	}
	if owned.live() {
		t.Fatal("closed owned pidfd is still live")
	}
	if _, err := unix.FcntlInt(uintptr(foreign), unix.F_GETFD, 0); err != nil {
		t.Fatal("Close affected a foreign fd")
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxOwnedPidFDLiveCloseConcurrent(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal("pidfd unavailable")
	}
	owned, err := newLinuxOwnedPidFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.Close() })
	start := make(chan struct{})
	stop := make(chan struct{})
	var liveWG, closeWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		liveWG.Add(1)
		go func() {
			defer liveWG.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
					_ = owned.live()
					runtime.Gosched()
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		closeWG.Add(1)
		go func() {
			defer closeWG.Done()
			<-start
			_ = owned.Close()
		}()
	}
	close(start)
	closeWG.Wait()
	close(stop)
	liveWG.Wait()
	if owned.live() {
		t.Fatal("closed pidfd became live")
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxPeerProofNilAndClosed(t *testing.T) {
	var proof *linuxPeerProof
	if proof.live() || proof.Close() != nil {
		t.Fatal("nil proof is live or not closeable")
	}
	if got, err := linuxPeerProofFromConn(nil); got != nil || err == nil {
		t.Fatalf("nil conn = %#v,%v", got, err)
	}
	if _, ok := readLinuxPeerStat(0); ok {
		t.Fatal("zero PID was accepted as a process identity")
	}
	if _, ok := readLinuxPeerExecIdentity(os.Getpid(), uint32(os.Geteuid())+1); ok {
		t.Fatal("wrong owner was accepted as a peer executable")
	}
}

// TestLinuxPeerProofRealChildUnixSocket is the root-runnable real boundary.
// It starts the test binary as a real child with a PTY controlling terminal
// and pipes for stdio, then proves the child's SO_PEERCRED/SO_PEERPIDFD
// identity over a real Unix socket. It does not run native approval, a lease,
// or T4_06, and it never treats the child PID or path as caller authority.
func TestLinuxPeerProofRealChildUnixSocket(t *testing.T) {
	master, slave, slavePath, slaveDev := linuxPeerProofPTY(t)
	_ = master
	defer slave.Close()

	dir, err := os.MkdirTemp("", linuxPeerProofSocketPrefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	endpoint := filepath.Join(dir, "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxPeerProofHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		linuxPeerProofHelperEnv+"=1",
		linuxPeerProofSocketEnv+"="+endpoint,
		linuxPeerProofNonceEnv+"="+linuxPeerProofFixedNonce,
	)
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.ExtraFiles = []*os.File{slave}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var conn *net.UnixConn
	waited := false
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
		if !waited {
			_ = cmd.Wait()
		}
	}()
	if err := listener.SetDeadline(time.Now().Add(linuxPeerProofHelperWait)); err != nil {
		t.Fatal(err)
	}
	conn, err = listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(linuxPeerProofHelperWait))

	proof, err := linuxPeerProofFromConn(conn)
	if err != nil {
		t.Fatal("linux peer proof unavailable")
	}
	defer func() { _ = proof.Close() }()
	if proof.pid != cmd.Process.Pid || proof.uid != uint32(os.Geteuid()) {
		t.Fatal("peer proof did not match the real child PID/UID")
	}
	if !proof.live() || proof.stat.startTime == 0 || proof.exe.ino == 0 || proof.tty.ino == 0 {
		t.Fatal("peer proof lacks live process or terminal identity")
	}
	if proof.tty.path != slavePath || proof.tty.dev != slaveDev || proof.tty.uid != 0 && proof.tty.uid != uint32(os.Geteuid()) {
		t.Fatal("peer proof did not match the real PTY")
	}
	if _, ok := openLinuxPeerTTY(slavePath, slaveDev^1, proof.uid); ok {
		t.Fatal("wrong terminal device was accepted")
	}
	if got := linuxPeerStdioPipeCount(cmd.Process.Pid); got != 3 {
		t.Fatalf("child stdio pipes = %d, want 3", got)
	}

	nonce := make([]byte, len(linuxPeerProofFixedNonce))
	if _, err := io.ReadFull(conn, nonce); err != nil || string(nonce) != linuxPeerProofFixedNonce {
		t.Fatal("fixed nonce handshake failed")
	}
	if err := proof.Close(); err != nil || proof.live() {
		t.Fatal("peer proof close did not retire the pidfd")
	}
	if err := proof.Close(); err != nil {
		t.Fatal("peer proof close was not idempotent")
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	waited = true
	if waitErr != nil {
		t.Fatal("helper child failed")
	}
}

func TestLinuxPeerProofHelperProcess(t *testing.T) {
	if os.Getenv(linuxPeerProofHelperEnv) != "1" {
		return
	}
	endpoint := os.Getenv(linuxPeerProofSocketEnv)
	nonce := os.Getenv(linuxPeerProofNonceEnv)
	conn, err := net.DialTimeout("unix", endpoint, linuxPeerProofHelperWait)
	if err != nil {
		os.Exit(2)
	}
	_ = conn.SetDeadline(time.Now().Add(linuxPeerProofHelperWait))
	if _, err := io.WriteString(conn, nonce); err != nil {
		_ = conn.Close()
		os.Exit(2)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		_ = conn.Close()
		os.Exit(2)
	}
	_ = conn.Close()
	os.Exit(0)
}

func linuxPeerProofPTY(t *testing.T) (master, slave *os.File, path string, dev uint64) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("pty unavailable")
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	unit, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	path = "/dev/pts/" + strconv.Itoa(unit)
	slave, err = os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		_ = slave.Close()
		t.Fatal(err)
	}
	return master, slave, path, uint64(stat.Rdev)
}

func linuxPeerStdioPipeCount(pid int) int {
	count := 0
	for fd := 0; fd < 3; fd++ {
		target, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/" + strconv.Itoa(fd))
		if err == nil && strings.HasPrefix(target, "pipe:[") {
			count++
		}
	}
	return count
}
