//go:build darwin && cgo

package terminalpeer

import (
	"encoding/binary"
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

	"golang.org/x/sys/unix"
)

const (
	descriptorHelperArg = "locklark-terminal-peer-descriptor-helper"
	descriptorStepLimit = 5 * time.Second
	descriptorHoldLimit = 15 * time.Second
	descriptorConnected = 1
	descriptorStart     = 2
	descriptorReady     = 3
	descriptorProbe     = 4
	descriptorRelease   = 5
	descriptorReaped    = 6
)

var descriptorPayload = [...]byte{0x6c, 0x6c, 0x72, 0x31, 0x62}

// TestDarwinPeerServerDuplicate owns every wrapper of one accepted socket.
// Closing the original wrapper must leave its duplicate observable; closing
// the final duplicate must deliver EOF before the owned peer is reaped.
func TestDarwinPeerServerDuplicate(t *testing.T) {
	dir := privatePeerDir(t)
	listener := listenPeer(t, dir)
	peer := startPeer(t, listener, dir, "duplicate", "hold")
	observation, err := Observe(peer.conn)
	if err != nil {
		t.Fatal("duplicate baseline observation unavailable")
	}
	file, err := peer.conn.File()
	if err != nil {
		t.Fatal("server descriptor duplication unavailable")
	}
	wrapped, wrapErr := net.FileConn(file)
	closeErr := file.Close()
	if wrapErr != nil {
		t.Fatal("duplicate server wrapper unavailable")
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	if closeErr != nil {
		t.Fatal("intermediate server descriptor did not close")
	}
	duplicate, ok := wrapped.(*net.UnixConn)
	if !ok {
		t.Fatal("duplicate server wrapper was not a Unix connection")
	}
	identity, err := socketIdentity(duplicate)
	if err != nil || identity != observation.state.socket {
		t.Fatal("server duplicate did not retain the kernel socket identity")
	}
	if err := observation.Revalidate(duplicate); err != nil {
		t.Fatal("same-socket duplicate revalidation failed")
	}
	other := startPeer(t, listener, dir, "different-socket", "hold")
	if err := observation.Revalidate(other.conn); !errors.Is(err, ErrMismatch) {
		t.Fatal("duplicate observation accepted a different socket")
	}
	if err := peer.conn.Close(); err != nil {
		t.Fatal("original server wrapper did not close")
	}
	if err := observation.Revalidate(duplicate); err != nil {
		t.Fatal("live duplicate revalidation failed after original wrapper closed")
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal("final server duplicate did not close")
	}
	peer.wait(t, descriptorStepLimit)
	if peer.cmd.ProcessState == nil || !peer.cmd.ProcessState.Success() {
		t.Fatal("duplicate peer did not exit successfully after EOF")
	}
	t.Log("terminal_peer_descriptor server_duplicate=true original_closed=true different_socket_refused=true eof_reaped=true")
}

// TestDarwinPeerClientInheritance first observes the real connector A, then
// holds its real child B after B writes through an inherited client socket.
// A supplies the PID of the child it owns and reaps over a private pipe; B's
// private self-report is checked against that held child and the kernel token.
// This tests a current accessor observation, not original-connector authority.
func TestDarwinPeerClientInheritance(t *testing.T) {
	dir := privatePeerDir(t)
	listener := listenPeer(t, dir)
	peer := startDescriptorPeer(t, listener, dir)
	original, err := Observe(peer.conn)
	if err != nil {
		t.Fatal("connector observation unavailable")
	}
	if original.state.observed.pid != int32(peer.cmd.Process.Pid) || original.state.observed.ttyDev != peer.ttyDev {
		t.Fatal("connector observation did not name the owned PTY process")
	}
	if !writeDescriptorPipe(peer.control, []byte{descriptorStart}) {
		t.Fatal("inheritance start control unavailable")
	}
	var heldPID [4]byte
	if !readDescriptorPipe(peer.report, heldPID[:], time.Now().Add(descriptorStepLimit)) {
		t.Fatal("owned child identity unavailable")
	}
	childPID := int32(binary.BigEndian.Uint32(heldPID[:]))
	var ready [5]byte
	if !readDescriptorPipe(peer.report, ready[:], time.Now().Add(descriptorStepLimit)) || ready[4] != descriptorReady {
		t.Fatal("inherited client write was not confirmed")
	}
	if childPID <= 0 || childPID == int32(peer.cmd.Process.Pid) || int32(binary.BigEndian.Uint32(ready[:4])) != childPID {
		t.Fatal("accessor self-report did not match the held owned child")
	}
	if err := peer.conn.SetReadDeadline(time.Now().Add(descriptorStepLimit)); err != nil {
		t.Fatal("inherited client read deadline unavailable")
	}
	var received [len(descriptorPayload)]byte
	if _, err := io.ReadFull(peer.conn, received[:]); err != nil || received != descriptorPayload {
		t.Fatal("inherited client fixed write was not received")
	}
	current, err := readPeerSample(peer.conn)
	if err != nil || current.pid != childPID || current.token == original.state.observed.token {
		t.Fatal("current kernel token did not name the held accessor child")
	}
	if err := original.Revalidate(peer.conn); !errors.Is(err, ErrMismatch) {
		t.Fatal("connector observation accepted the inherited accessor")
	}
	fresh, err := Observe(peer.conn)
	if err != nil {
		t.Fatal("current accessor observation unavailable")
	}
	credential, err := readPeerCredential(childPID)
	if err != nil {
		t.Fatal("held accessor credential unavailable")
	}
	got := fresh.state.observed
	if got.pid != childPID || got.token != current.token || got.pidVersion != current.pidVersion ||
		got.euid != credential.euid || got.startSec != credential.startSec || got.startUsec != credential.startUsec ||
		got.ttyDev != credential.ttyDev || got.ttyDev != peer.ttyDev || !sameFilePath(got.path, peer.executable) {
		t.Fatal("fresh observation did not describe the current owned accessor")
	}
	if err := fresh.Revalidate(peer.conn); err != nil {
		t.Fatal("held current accessor revalidation failed")
	}
	if !writeDescriptorPipe(peer.control, []byte{descriptorProbe}) {
		t.Fatal("held accessor liveness control unavailable")
	}
	var acknowledgment [1]byte
	if !readDescriptorPipe(peer.report, acknowledgment[:], time.Now().Add(descriptorStepLimit)) || acknowledgment[0] != descriptorProbe {
		t.Fatal("held accessor did not acknowledge its private control pipe")
	}
	if !writeDescriptorPipe(peer.control, []byte{descriptorRelease}) {
		t.Fatal("held accessor release control unavailable")
	}
	if !readDescriptorPipe(peer.report, acknowledgment[:], time.Now().Add(descriptorStepLimit)) || acknowledgment[0] != descriptorReaped {
		t.Fatal("connector did not confirm reaping its owned accessor child")
	}
	peer.wait(t, descriptorStepLimit)
	if peer.waitErr != nil {
		t.Fatal("connector helper did not exit successfully")
	}
	var eof [1]byte
	if n, err := peer.conn.Read(eof[:]); n != 0 || err != io.EOF {
		t.Fatal("inherited client references did not close before connector exit")
	}
	t.Log("terminal_peer_descriptor client_inherited=true current_accessor_child=true connector_refused=true fresh_current_only=true child_reaped=true connector_reaped=true")
}

// TestDarwinPeerDescriptorHelper runs only in the final component test binary's
// owned subprocesses. Its fixed argv selects a mode; all paths and process
// identities travel only over inherited private pipes and are never printed.
func TestDarwinPeerDescriptorHelper(t *testing.T) {
	args := os.Args
	if len(args) < 3 || args[len(args)-2] != descriptorHelperArg {
		t.Skip("subprocess-only descriptor helper")
	}
	var code int
	switch args[len(args)-1] {
	case "connector":
		code = runDescriptorConnector()
	case "accessor":
		code = runDescriptorAccessor()
	default:
		code = 1
	}
	os.Exit(code)
}

type descriptorPeer struct {
	cmd        *exec.Cmd
	conn       *net.UnixConn
	control    *os.File
	report     *os.File
	master     *os.File
	log        *os.File
	executable string
	ttyDev     uint32
	done       chan struct{}
	waitErr    error
	stopOnce   sync.Once
}

func startDescriptorPeer(t *testing.T, listener *net.UnixListener, dir string) *descriptorPeer {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("descriptor test executable unavailable")
	}
	master, slave, ttyDev := openPTY(t)
	controlRead, controlWrite := descriptorPipe(t)
	reportRead, reportWrite := descriptorPipe(t)
	log, err := os.OpenFile(filepath.Join(dir, "peer-inheritance.log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private descriptor log unavailable")
	}
	cmd := descriptorCommand(executable, "connector")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, log, log
	cmd.ExtraFiles = []*os.File{controlRead, reportWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	peer := &descriptorPeer{cmd: cmd, control: controlWrite, report: reportRead, master: master, log: log,
		executable: executable, ttyDev: ttyDev}
	t.Cleanup(func() { peer.stop(t) })
	if err := cmd.Start(); err != nil {
		t.Fatal("connector helper did not start")
	}
	peer.done = make(chan struct{})
	go func() {
		peer.waitErr = cmd.Wait()
		close(peer.done)
	}()
	// Parent copies must close now: otherwise the control EOF used by finally
	// cleanup, or the report EOF used to detect a failed helper, could be hidden.
	_ = controlRead.Close()
	_ = reportWrite.Close()
	_ = slave.Close()
	path := []byte(filepath.Join(dir, "peer.sock"))
	if len(path) > 255 || !writeDescriptorPipe(controlWrite, append([]byte{byte(len(path))}, path...)) {
		t.Fatal("private connector initialization unavailable")
	}
	if err := listener.SetDeadline(time.Now().Add(descriptorStepLimit)); err != nil {
		t.Fatal("descriptor listener deadline unavailable")
	}
	peer.conn, err = listener.AcceptUnix()
	if err != nil {
		t.Fatal("connector helper did not connect")
	}
	var connected [1]byte
	if !readDescriptorPipe(reportRead, connected[:], time.Now().Add(descriptorStepLimit)) || connected[0] != descriptorConnected {
		t.Fatal("connector private readiness unavailable")
	}
	return peer
}

func descriptorCommand(executable, mode string) *exec.Cmd {
	return exec.Command(executable, "-test.run=^TestDarwinPeerDescriptorHelper$", "-test.count=1", "--", descriptorHelperArg, mode)
}

func descriptorPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal("private descriptor pipe unavailable")
	}
	t.Cleanup(func() {
		_ = read.Close()
		_ = write.Close()
	})
	return read, write
}

func (p *descriptorPeer) wait(t *testing.T, limit time.Duration) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(limit):
		t.Fatal("connector helper did not exit within bound")
	}
}

func (p *descriptorPeer) stop(t *testing.T) {
	p.stopOnce.Do(func() {
		// Release B (or A before handoff) before waiting for A to reap B. No
		// parent duplicate of the control writer may keep that EOF hidden.
		_ = p.control.Close()
		if p.conn != nil {
			_ = p.conn.Close()
		}
		if p.done != nil {
			select {
			case <-p.done:
			case <-time.After(descriptorHoldLimit + 2*descriptorStepLimit):
				_ = p.cmd.Process.Kill()
				select {
				case <-p.done:
				case <-time.After(descriptorStepLimit):
					t.Error("connector process reap timed out")
				}
				t.Error("connector hierarchy cleanup exceeded its bound")
			}
		}
		_ = p.report.Close()
		_ = p.master.Close()
		_ = p.log.Close()
	})
}

func runDescriptorConnector() int {
	control := os.NewFile(3, "private-control")
	report := os.NewFile(4, "private-report")
	defer control.Close()
	defer report.Close()
	var size [1]byte
	if !readDescriptorPipe(control, size[:], time.Now().Add(descriptorStepLimit)) || size[0] == 0 {
		return 2
	}
	path := make([]byte, int(size[0]))
	if !readDescriptorPipe(control, path, time.Now().Add(descriptorStepLimit)) {
		return 3
	}
	connected, err := net.DialTimeout("unix", string(path), descriptorStepLimit)
	if err != nil {
		return 4
	}
	conn, ok := connected.(*net.UnixConn)
	if !ok {
		_ = connected.Close()
		return 5
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if !writeDescriptorPipe(report, []byte{descriptorConnected}) {
		return 6
	}
	var start [1]byte
	if !readDescriptorPipe(control, start[:], time.Now().Add(descriptorHoldLimit)) {
		return 0 // Parent finally cleanup closed the control writer.
	}
	if start[0] != descriptorStart {
		return 7
	}
	client, err := conn.File()
	if err != nil {
		return 8
	}
	defer client.Close()
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return 9
	}
	defer gateRead.Close()
	defer gateWrite.Close()
	executable, err := os.Executable()
	if err != nil {
		return 10
	}
	child := descriptorCommand(executable, "accessor")
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{client, gateRead, control, report}
	if err := child.Start(); err != nil {
		return 11
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = child.Wait()
		close(done)
	}()
	defer func() {
		select {
		case <-done:
			return
		default:
			_ = child.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(descriptorStepLimit):
			// Exit with a fixed failure if even a killed child cannot be reaped.
			os.Exit(12)
		}
	}()
	_ = gateRead.Close()
	// No A socket access is permitted after the gate opens. Close both of
	// A's client references before B can wrap or write the inherited socket.
	closeConnErr := conn.Close()
	conn = nil
	closeClientErr := client.Close()
	if closeConnErr != nil || closeClientErr != nil {
		return 13
	}
	var heldPID [4]byte
	binary.BigEndian.PutUint32(heldPID[:], uint32(child.Process.Pid))
	if !writeDescriptorPipe(report, heldPID[:]) || !writeDescriptorPipe(gateWrite, []byte{descriptorStart}) {
		return 14
	}
	_ = gateWrite.Close()
	select {
	case <-done:
	case <-time.After(descriptorHoldLimit + descriptorStepLimit):
		return 15
	}
	if waitErr != nil || !writeDescriptorPipe(report, []byte{descriptorReaped}) {
		return 16
	}
	return 0
}

func runDescriptorAccessor() int {
	client := os.NewFile(3, "inherited-client")
	gate := os.NewFile(4, "private-gate")
	control := os.NewFile(5, "private-control")
	report := os.NewFile(6, "private-report")
	defer client.Close()
	defer gate.Close()
	defer control.Close()
	defer report.Close()
	var signal [1]byte
	if !readDescriptorPipe(gate, signal[:], time.Now().Add(descriptorStepLimit)) || signal[0] != descriptorStart {
		return 17
	}
	conn, err := net.FileConn(client)
	_ = client.Close()
	if err != nil {
		return 18
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(descriptorStepLimit)); err != nil {
		return 19
	}
	if n, err := conn.Write(descriptorPayload[:]); err != nil || n != len(descriptorPayload) {
		return 20
	}
	var ready [5]byte
	binary.BigEndian.PutUint32(ready[:4], uint32(os.Getpid()))
	ready[4] = descriptorReady
	if !writeDescriptorPipe(report, ready[:]) {
		return 21
	}
	deadline := time.Now().Add(descriptorHoldLimit)
	for {
		if !readDescriptorPipe(control, signal[:], deadline) {
			return 0 // Parent finally cleanup closes this writer on failure.
		}
		switch signal[0] {
		case descriptorProbe:
			if !writeDescriptorPipe(report, []byte{descriptorProbe}) {
				return 22
			}
		case descriptorRelease:
			return 0
		default:
			return 23
		}
	}
}

// Each pipe has one reader and a protocol totaling fewer than PIPE_BUF bytes.
// Poll before every read bounds a short read or EOF without a blocked reader
// goroutine that could retain a descriptor during cleanup.
func readDescriptorPipe(file *os.File, data []byte, deadline time.Time) bool {
	for offset := 0; offset < len(data); {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		fds := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
		count, err := unix.Poll(fds, int((remaining+time.Millisecond-1)/time.Millisecond))
		if err == unix.EINTR {
			continue
		}
		if err != nil || count == 0 || fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			return false
		}
		n, err := file.Read(data[offset:])
		if err != nil || n == 0 {
			return false
		}
		offset += n
	}
	return true
}

func writeDescriptorPipe(file *os.File, data []byte) bool {
	n, err := file.Write(data)
	return err == nil && n == len(data)
}
