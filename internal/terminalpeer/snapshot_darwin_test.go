//go:build darwin && cgo

package terminalpeer

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	helperEnv       = "LOCKLARK_TERMINAL_PEER_TEST_HELPER"
	helperSocketEnv = "LOCKLARK_TERMINAL_PEER_TEST_SOCKET"
	helperModeEnv   = "LOCKLARK_TERMINAL_PEER_TEST_MODE"
	helperExecEnv   = "LOCKLARK_TERMINAL_PEER_TEST_EXEC"
)

// TestDarwinPeerSnapshotOwnedPTY is the real component smoke. It owns a
// private directory, a Unix listener, and real PTY pairs; it starts the same
// final test binary as a child so the child has a real controlling terminal.
// The same binary is then used for the real exec and exit transitions.
func TestDarwinPeerSnapshotOwnedPTY(t *testing.T) {
	dir := privatePeerDir(t)
	listener := listenPeer(t, dir)

	t.Run("baseline", func(t *testing.T) {
		peer := startPeer(t, listener, dir, "baseline", "hold")
		observation, err := Observe(peer.conn)
		if err != nil {
			t.Fatalf("baseline observation failed: %v", err)
		}
		if observation.state.observed.pid != int32(peer.cmd.Process.Pid) {
			t.Fatal("baseline PID did not match the owned child")
		}
		if observation.state.observed.pidVersion <= 0 {
			t.Fatal("baseline token generation missing")
		}
		if observation.state.observed.euid != uint32(os.Geteuid()) {
			t.Fatal("baseline credential did not match this user")
		}
		if observation.state.observed.ttyDev != peer.ttyDev {
			t.Fatal("baseline controlling terminal did not match the owned PTY")
		}
		if !sameFilePath(observation.state.observed.path, peer.executable) {
			t.Fatal("baseline token-bound path did not name the running child")
		}
		if err := observation.Revalidate(peer.conn); err != nil {
			t.Fatalf("baseline revalidation failed: %v", err)
		}
		t.Log("terminal_peer_snapshot baseline=true")
	})

	t.Run("exec_refused", func(t *testing.T) {
		peer := startPeer(t, listener, dir, "exec", "exec")
		observation, err := Observe(peer.conn)
		if err != nil {
			t.Fatalf("pre-exec observation failed: %v", err)
		}
		oldToken := observation.state.observed.token
		peer.signal(t)
		changed := waitTokenChange(t, peer.conn, oldToken)
		if changed.pid != observation.state.observed.pid {
			t.Fatal("real exec changed the peer PID")
		}
		if changed.pidVersion == observation.state.observed.pidVersion {
			t.Fatal("real exec did not change the token generation")
		}
		if changed.path == observation.state.observed.path {
			t.Fatal("real exec did not change the token-bound path")
		}
		credential, err := readPeerCredential(changed.pid)
		if err != nil {
			t.Fatal("post-exec credential unavailable")
		}
		if credential.startSec != observation.state.observed.startSec || credential.startUsec != observation.state.observed.startUsec {
			t.Fatal("real exec changed the process start pair")
		}
		if credential.ttyDev != observation.state.observed.ttyDev {
			t.Fatal("real exec changed the controlling terminal")
		}
		if err := observation.Revalidate(peer.conn); !errors.Is(err, ErrMismatch) {
			t.Fatal("post-exec revalidation did not return ErrMismatch")
		}
		t.Log("terminal_peer_snapshot exec_refused=true")
	})

	t.Run("exit_refused", func(t *testing.T) {
		peer := startPeer(t, listener, dir, "exit", "exit")
		observation, err := Observe(peer.conn)
		if err != nil {
			t.Fatalf("pre-exit observation failed: %v", err)
		}
		peer.signal(t)
		peer.wait(t, 5*time.Second)
		if err := observation.Revalidate(peer.conn); !errors.Is(err, ErrMismatch) {
			t.Fatal("post-exit revalidation did not return ErrMismatch")
		}
		t.Log("terminal_peer_snapshot exit_refused=true")
	})

	t.Run("different_peer_tty_refused", func(t *testing.T) {
		first := startPeer(t, listener, dir, "first", "hold")
		second := startPeer(t, listener, dir, "second", "hold")
		firstObservation, err := Observe(first.conn)
		if err != nil {
			t.Fatalf("first peer observation failed: %v", err)
		}
		secondObservation, err := Observe(second.conn)
		if err != nil {
			t.Fatalf("second peer observation failed: %v", err)
		}
		if firstObservation.state.observed.pid == secondObservation.state.observed.pid {
			t.Fatal("different peers shared a PID")
		}
		if firstObservation.state.observed.ttyDev == secondObservation.state.observed.ttyDev {
			t.Fatal("different peers shared a controlling terminal")
		}
		if firstObservation.state.observed.token == secondObservation.state.observed.token {
			t.Fatal("different peers shared an audit token")
		}
		if err := firstObservation.Revalidate(second.conn); !errors.Is(err, ErrMismatch) {
			t.Fatal("first observation accepted the second peer's socket")
		}
		if err := secondObservation.Revalidate(first.conn); !errors.Is(err, ErrMismatch) {
			t.Fatal("second observation accepted the first peer's socket")
		}
		if err := firstObservation.Revalidate(first.conn); err != nil {
			t.Fatalf("first peer same-socket revalidation failed: %v", err)
		}
		if err := secondObservation.Revalidate(second.conn); err != nil {
			t.Fatalf("second peer same-socket revalidation failed: %v", err)
		}
		t.Log("terminal_peer_snapshot different_peer_tty_refused=true")
	})
}

// TestDarwinPeerSnapshotHelper is the same test binary under a child
// environment. It connects over the real Unix socket and, for the exec mode,
// clears FD_CLOEXEC so the descriptor survives a real exec of sleep. The child
// keeps the same PID and controlling terminal across that exec.
func TestDarwinPeerSnapshotHelper(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("subprocess-only peer helper")
	}
	socketPath := os.Getenv(helperSocketEnv)
	mode := os.Getenv(helperModeEnv)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		os.Exit(2)
	}
	defer conn.Close()

	switch mode {
	case "hold":
		_, _ = io.Copy(io.Discard, conn)
	case "exec":
		var signal [1]byte
		if _, err := io.ReadFull(conn, signal[:]); err != nil {
			os.Exit(3)
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			os.Exit(4)
		}
		var clearErr error
		if err := raw.Control(func(fd uintptr) {
			_, clearErr = unix.FcntlInt(fd, unix.F_SETFD, 0)
		}); err != nil || clearErr != nil {
			os.Exit(5)
		}
		program := os.Getenv(helperExecEnv)
		if program == "" {
			os.Exit(6)
		}
		_ = unix.Exec(program, []string{program, "30"}, os.Environ())
		os.Exit(7)
	case "exit":
		var signal [1]byte
		if _, err := io.ReadFull(conn, signal[:]); err != nil {
			os.Exit(8)
		}
		os.Exit(0)
	default:
		os.Exit(9)
	}
}

type peerProcess struct {
	cmd        *exec.Cmd
	conn       *net.UnixConn
	master     *os.File
	log        *os.File
	executable string
	ttyDev     uint32
	done       chan struct{}
	stopOnce   sync.Once
}

// privatePeerDir creates a 0700 parent and removes it only after a passing
// test. A failed run retains its 0600 peer logs for diagnosis.
func privatePeerDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "locklark-terminal-peer-")
	if err != nil {
		t.Fatal("private peer directory unavailable")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private peer directory mode unavailable")
	}
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		_ = os.RemoveAll(dir)
	})
	return dir
}

func listenPeer(t *testing.T, dir string) *net.UnixListener {
	t.Helper()
	path := filepath.Join(dir, "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("unix listener unavailable")
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func startPeer(t *testing.T, listener *net.UnixListener, dir, name, mode string) *peerProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	program := "/bin/sleep"
	if info, err := os.Stat(program); err != nil || info.IsDir() {
		t.Fatal("real exec target unavailable")
	}
	master, slave, ttyDev := openPTY(t)
	log, err := os.OpenFile(filepath.Join(dir, "peer-"+name+".log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private peer log unavailable")
	}
	cmd := exec.Command(executable, "-test.run=^TestDarwinPeerSnapshotHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		helperEnv+"=1",
		helperSocketEnv+"="+filepath.Join(dir, "peer.sock"),
		helperModeEnv+"="+mode,
		helperExecEnv+"="+program,
	)
	cmd.Stdin = slave
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		_ = master.Close()
		_ = log.Close()
		t.Fatal("peer child did not start")
	}
	_ = slave.Close()
	peer := &peerProcess{
		cmd:        cmd,
		master:     master,
		log:        log,
		executable: executable,
		ttyDev:     ttyDev,
		done:       make(chan struct{}),
	}
	go func() {
		_ = cmd.Wait()
		close(peer.done)
	}()
	t.Cleanup(func() { peer.stop(t) })

	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal("unix listener deadline unavailable")
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("peer child did not connect")
	}
	peer.conn = conn
	return peer
}

// openPTY creates a real owned PTY pair and returns its controlling-terminal
// device from the slave's fstat. The master stays open for the peer lifetime.
func openPTY(t *testing.T) (*os.File, *os.File, uint32) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("pty master unavailable")
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		_ = unix.Close(fd)
		t.Fatal("pty grant unavailable")
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		_ = unix.Close(fd)
		t.Fatal("pty unlock unavailable")
	}
	name, err := ptyName(fd)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal("pty name unavailable")
	}
	slaveFD, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal("pty slave unavailable")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(slaveFD, &stat); err != nil {
		_ = unix.Close(slaveFD)
		_ = unix.Close(fd)
		t.Fatal("pty slave identity unavailable")
	}
	master := os.NewFile(uintptr(fd), "pty-master")
	slave := os.NewFile(uintptr(slaveFD), "pty-slave")
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	return master, slave, uint32(stat.Rdev)
}

func ptyName(fd int) (string, error) {
	var buffer [128]byte
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TIOCPTYGNAME),
		uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return "", errno
	}
	for index, value := range buffer {
		if value != 0 {
			continue
		}
		if index == 0 {
			return "", ErrMalformed
		}
		return string(buffer[:index]), nil
	}
	return "", ErrMalformed
}

func (p *peerProcess) signal(t *testing.T) {
	t.Helper()
	if p.conn == nil {
		t.Fatal("peer connection unavailable")
	}
	if err := p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal("peer write deadline unavailable")
	}
	if _, err := p.conn.Write([]byte{1}); err != nil {
		t.Fatal("peer signal unavailable")
	}
	_ = p.conn.SetWriteDeadline(time.Time{})
}

func (p *peerProcess) wait(t *testing.T, limit time.Duration) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(limit):
		t.Fatal("peer did not exit within bound")
	}
}

// stop is the bounded finally cleanup: kill, reap once, close descriptors, and
// close the private log last. A timeout fails the test rather than leaking a
// child silently.
func (p *peerProcess) stop(t *testing.T) {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		if p.done != nil {
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
				t.Errorf("peer process cleanup timed out")
			}
		}
		if p.conn != nil {
			_ = p.conn.Close()
		}
		if p.master != nil {
			_ = p.master.Close()
		}
		if p.log != nil {
			_ = p.log.Close()
		}
	})
}

func waitTokenChange(t *testing.T, conn *net.UnixConn, previous peerToken) peerSample {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sample, err := readPeerSample(conn)
		if err == nil && sample.token != previous {
			return sample
		}
		if time.Now().After(deadline) {
			t.Fatal("peer exec was not observed within bound")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sameFilePath(first, second string) bool {
	if filepath.Clean(first) == filepath.Clean(second) {
		return true
	}
	resolvedFirst, firstErr := filepath.EvalSymlinks(first)
	resolvedSecond, secondErr := filepath.EvalSymlinks(second)
	return firstErr == nil && secondErr == nil && resolvedFirst == resolvedSecond
}
