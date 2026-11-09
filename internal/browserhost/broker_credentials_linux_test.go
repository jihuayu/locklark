//go:build linux

package browserhost

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/sys/unix"
)

// These tests use real owned UNIX sockets only. They prove that the broker
// authenticates the writer of every request byte (SCM_CREDENTIALS), not just
// the process that created the connection (SO_PEERCRED). No GUI, no
// credentials and no unrelated processes are involved.

const credWriterEnv = "LOCKLARK_CRED_TEST_WRITER_HEX"

// TestCredTestWriterChild is the exec'd helper process. The test body writes
// the hex payload from its environment to the socket it inherited on fd 3 and
// exits; it is skipped in normal test runs.
func TestCredTestWriterChild(t *testing.T) {
	payload := os.Getenv(credWriterEnv)
	if payload == "" {
		t.Skip("helper process only")
	}
	raw, e := hex.DecodeString(payload)
	if e != nil {
		t.Fatalf("helper payload: %v", e)
	}
	f := os.NewFile(3, "inherited-socket")
	if f == nil {
		t.Fatal("helper: no inherited socket on fd 3")
	}
	if _, e := f.Write(raw); e != nil {
		t.Fatalf("helper write: %v", e)
	}
	if e := f.Close(); e != nil {
		t.Fatalf("helper close: %v", e)
	}
}

// credListen creates the same private listener production uses, including
// SO_PASSCRED before bind.
func credListen(t *testing.T) *net.UnixListener {
	t.Helper()
	path := brokerTestSocket(t)
	ln, e := listenUnixLocal(path)
	if e != nil {
		t.Fatalf("listenUnixLocal: %v", e)
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatalf("socket mode: %v", e)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(path)
	})
	return ln
}

func credDial(t *testing.T, ln *net.UnixListener) *net.UnixConn {
	t.Helper()
	c, e := net.Dial("unix", ln.Addr().String())
	if e != nil {
		t.Fatalf("dial: %v", e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.UnixConn)
}

func credDialPath(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, e := net.Dial("unix", path)
	if e != nil {
		t.Fatalf("dial %s: %v", path, e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.UnixConn)
}

// credAccept returns the production guard around one accepted connection and
// the connection-level peer the broker authenticated from SO_PEERCRED.
func credAccept(t *testing.T, ln *net.UnixListener) (net.Conn, Peer) {
	t.Helper()
	_ = ln.SetDeadline(time.Now().Add(2 * time.Second))
	raw, e := ln.Accept()
	if e != nil {
		t.Fatalf("accept: %v", e)
	}
	peer, e := authenticatedPeer(raw)
	if e != nil {
		_ = raw.Close()
		t.Fatalf("authenticatedPeer: %v", e)
	}
	guarded, e := guardRequestWriter(raw)
	if e != nil {
		_ = raw.Close()
		t.Fatalf("guardRequestWriter: %v", e)
	}
	t.Cleanup(func() { _ = guarded.Close() })
	if e := guarded.SetReadDeadline(time.Now().Add(2 * time.Second)); e != nil {
		t.Fatalf("read deadline: %v", e)
	}
	return guarded, peer
}

func credRead(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, e := io.ReadFull(c, buf); e != nil {
		t.Fatalf("read %d bytes: %v", n, e)
	}
	return buf
}

// credWireFrame serializes one length-prefixed frame.
func credWireFrame(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatalf("marshal: %v", e)
	}
	out := binary.NativeEndian.AppendUint32(make([]byte, 0, 4+len(raw)), uint32(len(raw)))
	return append(out, raw...)
}

// startCredWriterChild forks/execs the test binary with a duplicate of the
// connected socket on fd 3. The child becomes the actual writer while the
// broker still sees the parent as the connection creator.
func startCredWriterChild(t *testing.T, client *net.UnixConn, payload []byte) *exec.Cmd {
	t.Helper()
	file, e := client.File()
	if e != nil {
		t.Fatalf("client File: %v", e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCredTestWriterChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), credWriterEnv+"="+hex.EncodeToString(payload))
	cmd.ExtraFiles = []*os.File{file}
	if e := cmd.Start(); e != nil {
		_ = file.Close()
		t.Fatalf("start writer child: %v", e)
	}
	if e := file.Close(); e != nil {
		t.Fatalf("close parent duplicate: %v", e)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return cmd
}

func waitCredWriterChild(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("writer child: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer child did not exit")
	}
}

func expectUnverifiedWriter(t *testing.T, c net.Conn) {
	t.Helper()
	var one [1]byte
	n, e := c.Read(one[:])
	if n != 0 {
		t.Fatalf("unverified writer data was exposed: %d bytes", n)
	}
	if !errors.Is(e, errUnverifiedWriter) {
		t.Fatalf("got %v, want errUnverifiedWriter", e)
	}
}

// TestListenLocalQueuedBeforeAcceptKeepsWriterCredentials proves SO_PASSCRED is
// enabled before bind/listen: bytes written before Accept already carry the
// real writer's SCM_CREDENTIALS, so the guarded read succeeds rather than
// stalling or refusing.
func TestListenLocalQueuedBeforeAcceptKeepsWriterCredentials(t *testing.T) {
	path := brokerTestSocket(t)
	l, e := listenLocal(path)
	if e != nil {
		t.Fatalf("listenLocal: %v", e)
	}
	defer func() { _ = l.Close() }()

	info, e := os.Lstat(path)
	if e != nil {
		t.Fatalf("socket stat: %v", e)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %v, want private socket 0600", info.Mode())
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatalf("socket owner = %v, want %d", info.Sys(), os.Geteuid())
	}

	client := credDialPath(t, path)
	hello := credWireFrame(t, BrokerHello{V: 1, Mode: "cli-run"})
	// Queued in the accept backlog before the server ever calls Accept.
	if _, e := client.Write(hello); e != nil {
		t.Fatalf("pre-accept write: %v", e)
	}

	conn, e := l.Accept()
	if e != nil {
		t.Fatalf("accept: %v", e)
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("accepted conn type %T", conn)
	}
	if on, e := unix.GetsockoptInt(int(fdOf(t, uc)), unix.SOL_SOCKET, unix.SO_PASSCRED); e != nil || on != 1 {
		t.Fatalf("accepted SO_PASSCRED = %d, %v; want 1", on, e)
	}
	if _, e := authenticatedPeer(conn); e != nil {
		t.Fatalf("authenticatedPeer: %v", e)
	}
	guarded, e := guardRequestWriter(conn)
	if e != nil {
		t.Fatalf("guardRequestWriter: %v", e)
	}
	_ = guarded.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, e := readFrame(guarded, 4096)
	if e != nil {
		t.Fatalf("queued pre-accept frame refused: %v", e)
	}
	if string(raw) != string(hello[4:]) {
		t.Fatal("queued pre-accept frame mismatch")
	}

	// Closing the wrapped listener still removes exactly the socket it created.
	if e := l.Close(); e != nil {
		t.Fatalf("listener close: %v", e)
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatalf("listener did not remove its socket: %v", e)
	}
}

// TestListenLocalKeepsPathChecks pins that the credential hook did not weaken
// the existing owner/path/no-unlink preconditions.
func TestListenLocalKeepsPathChecks(t *testing.T) {
	path := brokerTestSocket(t)
	if e := os.WriteFile(path, []byte("not a socket"), 0600); e != nil {
		t.Fatalf("regular file endpoint: %v", e)
	}
	if l, e := listenLocal(path); e == nil {
		_ = l.Close()
		t.Fatal("listenLocal accepted a pre-existing regular file endpoint")
	}
}

func fdOf(t *testing.T, c *net.UnixConn) uintptr {
	t.Helper()
	raw, e := c.SyscallConn()
	if e != nil {
		t.Fatalf("SyscallConn: %v", e)
	}
	var fd uintptr
	if e := raw.Control(func(v uintptr) { fd = v }); e != nil {
		t.Fatalf("raw control: %v", e)
	}
	return fd
}

// TestGuardedWriterAcceptsPartialFrames proves every fragment of the header and
// body is validated independently: the same writer passes header pieces, body
// pieces and a second frame.
func TestGuardedWriterAcceptsPartialFrames(t *testing.T) {
	ln := credListen(t)
	client := credDial(t, ln)
	guarded, peer := credAccept(t, ln)
	if peer.PID != uint32(os.Getpid()) {
		t.Fatalf("connection creator pid = %d, want %d", peer.PID, os.Getpid())
	}

	first := credWireFrame(t, BrokerHello{V: 1, Mode: "cli-run"})
	header, body := first[:4], first[4:]

	if _, e := client.Write(header[:2]); e != nil {
		t.Fatalf("write header half: %v", e)
	}
	if got := credRead(t, guarded, 2); string(got) != string(header[:2]) {
		t.Fatalf("header half = %x", got)
	}
	if _, e := client.Write(header[2:]); e != nil {
		t.Fatalf("write header tail: %v", e)
	}
	if got := credRead(t, guarded, 2); string(got) != string(header[2:]) {
		t.Fatalf("header tail = %x", got)
	}
	if _, e := client.Write(body[:3]); e != nil {
		t.Fatalf("write body head: %v", e)
	}
	if got := credRead(t, guarded, 3); string(got) != string(body[:3]) {
		t.Fatalf("body head = %q", got)
	}
	if _, e := client.Write(body[3:]); e != nil {
		t.Fatalf("write body tail: %v", e)
	}
	// The header was validated above; finish the straddling body fragment and
	// prove its bytes are still the authenticated writer's frame.
	if got := credRead(t, guarded, len(body)-3); string(got) != string(body[3:]) {
		t.Fatalf("body tail = %q", got)
	}

	second := credWireFrame(t, BrokerHello{V: 1, Mode: "cli-run"})
	if _, e := client.Write(second); e != nil {
		t.Fatalf("write second frame: %v", e)
	}
	if _, e := readFrame(guarded, 4096); e != nil {
		t.Fatalf("second frame refused: %v", e)
	}
}

// TestGuardedWriterRefusesInheritedFDChild is the core regression: the parent
// connects, an exec'd child inherits the descriptor and writes. SO_PEERCRED
// still reports the parent, so only per-message SCM_CREDENTIALS can refuse.
func TestGuardedWriterRefusesInheritedFDChild(t *testing.T) {
	ln := credListen(t)
	client := credDial(t, ln)
	guarded, peer := credAccept(t, ln)
	if peer.PID != uint32(os.Getpid()) {
		t.Fatalf("connection creator pid = %d, want parent %d", peer.PID, os.Getpid())
	}

	payload := credWireFrame(t, BrokerHello{V: 1, Mode: "cli-run"})
	child := startCredWriterChild(t, client, payload)
	waitCredWriterChild(t, child)
	if child.Process.Pid == os.Getpid() {
		t.Fatal("helper ran as the parent process")
	}

	expectUnverifiedWriter(t, guarded)
}

// TestKernelReportsCreatorAndWriterSeparately documents the threat model on a
// real socket: SO_PEERCRED names the connecting parent while SCM_CREDENTIALS
// names the exec'd child that actually wrote the bytes.
func TestKernelReportsCreatorAndWriterSeparately(t *testing.T) {
	ln := credListen(t)
	client := credDial(t, ln)
	_ = ln.SetDeadline(time.Now().Add(2 * time.Second))
	conn, e := ln.Accept()
	if e != nil {
		t.Fatalf("accept: %v", e)
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)
	peer, e := unix.GetsockoptUcred(int(fdOf(t, uc)), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if e != nil {
		t.Fatalf("SO_PEERCRED: %v", e)
	}
	if peer.Pid != int32(os.Getpid()) {
		t.Fatalf("connection creator = %d, want parent %d", peer.Pid, os.Getpid())
	}

	payload := []byte("child-writer")
	child := startCredWriterChild(t, client, payload)
	waitCredWriterChild(t, child)

	raw, e := uc.SyscallConn()
	if e != nil {
		t.Fatalf("SyscallConn: %v", e)
	}
	var (
		n      int
		msgs   []unix.SocketControlMessage
		recvEr error
	)
	buf := make([]byte, 64)
	oob := make([]byte, writerControlBytes)
	if e := raw.Read(func(fd uintptr) bool {
		var oobn int
		n, oobn, _, _, recvEr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
		if recvEr == unix.EAGAIN {
			recvEr = nil
			return false
		}
		if recvEr == nil {
			msgs, recvEr = unix.ParseSocketControlMessage(oob[:oobn])
		}
		return true
	}); e != nil {
		t.Fatalf("recvmsg: %v", e)
	}
	if recvEr != nil {
		t.Fatalf("recvmsg: %v", recvEr)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("writer payload = %q", buf[:n])
	}
	if len(msgs) != 1 || msgs[0].Header.Type != unix.SCM_CREDENTIALS {
		t.Fatalf("ancillary messages = %d", len(msgs))
	}
	writer, e := unix.ParseUnixCredentials(&msgs[0])
	if e != nil {
		t.Fatalf("SCM_CREDENTIALS: %v", e)
	}
	if int(writer.Pid) != child.Process.Pid {
		t.Fatalf("SCM_CREDENTIALS writer = %d, want child %d", writer.Pid, child.Process.Pid)
	}
	if writer.Pid == peer.Pid {
		t.Fatal("kernel attributed the child write to the connection creator")
	}
}

// TestGuardedWriterRefusesWriterChangeMidFrame proves a writer switch after the
// header was accepted is still refused before the body is exposed.
func TestGuardedWriterRefusesWriterChangeMidFrame(t *testing.T) {
	ln := credListen(t)
	client := credDial(t, ln)
	guarded, _ := credAccept(t, ln)

	frame := credWireFrame(t, BrokerHello{V: 1, Mode: "cli-run"})
	header, body := frame[:4], frame[4:]
	if _, e := client.Write(header); e != nil {
		t.Fatalf("write header: %v", e)
	}
	if got := credRead(t, guarded, len(header)); string(got) != string(header) {
		t.Fatalf("header = %x", got)
	}

	child := startCredWriterChild(t, client, body)
	waitCredWriterChild(t, child)
	expectUnverifiedWriter(t, guarded)
}

// TestGuardedWriterMissingAndTruncatedCredentials exercises the ancillary
// parsing directly on a real socket: a zero-length control buffer means the
// kernel reports no credential, and an undersized one truncates it.
func TestGuardedWriterMissingAndTruncatedCredentials(t *testing.T) {
	ln := credListen(t)
	client := credDial(t, ln)
	guarded, _ := credAccept(t, ln)
	verified, ok := guarded.(*verifiedWriterConn)
	if !ok {
		t.Fatalf("guarded conn type %T", guarded)
	}

	if _, e := client.Write([]byte("missing-cred")); e != nil {
		t.Fatalf("write: %v", e)
	}
	buf := make([]byte, 32)
	if n, e := verified.readWithControl(buf, 0); n != 0 || !errors.Is(e, errUnverifiedWriter) {
		t.Fatalf("missing credential: n=%d err=%v", n, e)
	}

	if _, e := client.Write([]byte("trunc-cred")); e != nil {
		t.Fatalf("write: %v", e)
	}
	if n, e := verified.readWithControl(buf, unix.SizeofUcred/2); n != 0 || !errors.Is(e, errUnverifiedWriter) {
		t.Fatalf("truncated credential: n=%d err=%v", n, e)
	}

	// The stream is still ordered and usable for an authenticated writer.
	if _, e := client.Write([]byte("ok")); e != nil {
		t.Fatalf("write: %v", e)
	}
	if got := credRead(t, guarded, 2); string(got) != "ok" {
		t.Fatalf("post-refusal read = %q", got)
	}
}

// TestGuardedWriterRejectsExtraAncillaryClosesRights proves a peer cannot ride
// request bytes on extra control data or leak descriptors into the broker.
func TestGuardedWriterRejectsExtraAncillaryClosesRights(t *testing.T) {
	ln := credListen(t)
	client := credDial(t, ln)
	guarded, _ := credAccept(t, ln)

	var pipe [2]int
	if e := unix.Pipe2(pipe[:], unix.O_CLOEXEC); e != nil {
		t.Fatalf("pipe: %v", e)
	}
	st, e := os.Stat("/proc/self/fd/" + strconv.Itoa(pipe[0]))
	if e != nil {
		_ = unix.Close(pipe[0])
		_ = unix.Close(pipe[1])
		t.Fatalf("stat pipe fd: %v", e)
	}
	ino := st.Sys().(*syscall.Stat_t).Ino
	target := "pipe:[" + strconv.FormatUint(ino, 10) + "]"
	rights := unix.UnixRights(pipe[0])

	raw, e := client.SyscallConn()
	if e != nil {
		t.Fatalf("client SyscallConn: %v", e)
	}
	var sendErr error
	if e := raw.Write(func(fd uintptr) bool {
		sendErr = unix.Sendmsg(int(fd), []byte("rights"), rights, nil, 0)
		if sendErr == unix.EAGAIN {
			sendErr = nil
			return false
		}
		return true
	}); e != nil {
		t.Fatalf("raw write: %v", e)
	}
	if sendErr != nil {
		t.Fatalf("sendmsg rights: %v", sendErr)
	}
	// The kernel already took its own reference to the sent descriptor; drop the
	// local copies so any remaining match is a descriptor the broker received.
	_ = unix.Close(pipe[0])
	_ = unix.Close(pipe[1])

	expectUnverifiedWriter(t, guarded)

	deadline := time.Now().Add(time.Second)
	for {
		if !fdTargetOpen(t, target) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("received SCM_RIGHTS descriptor %s leaked after refusal", target)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fdTargetOpen reports whether any descriptor in this process still points at
// the given /proc/self/fd target (e.g. a specific pipe inode).
func fdTargetOpen(t *testing.T, target string) bool {
	t.Helper()
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatalf("read /proc/self/fd: %v", e)
	}
	for _, entry := range entries {
		link, e := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if e == nil && link == target {
			return true
		}
	}
	return false
}

// TestGuardedWriterDeadlineAndClose proves the wrapper preserves deadline and
// Close semantics instead of blocking in a raw recvmsg loop.
func TestGuardedWriterDeadlineAndClose(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		ln := credListen(t)
		_ = credDial(t, ln)
		guarded, _ := credAccept(t, ln)
		if e := guarded.SetReadDeadline(time.Now().Add(-time.Second)); e != nil {
			t.Fatalf("set past deadline: %v", e)
		}
		var one [1]byte
		if _, e := guarded.Read(one[:]); !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatalf("expired deadline: %v, want os.ErrDeadlineExceeded", e)
		}
	})

	t.Run("close", func(t *testing.T) {
		ln := credListen(t)
		_ = credDial(t, ln)
		guarded, _ := credAccept(t, ln)
		_ = guarded.SetReadDeadline(time.Time{})
		done := make(chan error, 1)
		go func() {
			var one [1]byte
			_, e := guarded.Read(one[:])
			done <- e
		}()
		time.Sleep(50 * time.Millisecond)
		if e := guarded.Close(); e != nil {
			t.Fatalf("close: %v", e)
		}
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("read on a closed guarded conn returned no error")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("read did not unblock after Close")
		}
	})
}

// TestGuardRequestWriterRequiresPasscred pins that a connection whose socket
// never enabled SO_PASSCRED is refused up front instead of silently losing the
// credential check.
func TestGuardRequestWriterRequiresPasscred(t *testing.T) {
	if c, e := net.Pipe(); e == nil {
		if _, e := guardRequestWriter(c); !errors.Is(e, ErrBrokerUnavailable) {
			t.Fatalf("non-UnixConn guard = %v, want ErrBrokerUnavailable", e)
		}
		_ = c.Close()
	}

	path := brokerTestSocket(t)
	plain, e := net.Listen("unix", path)
	if e != nil {
		t.Fatalf("plain listen: %v", e)
	}
	defer plain.Close()
	_ = os.Chmod(path, 0600)
	client, e := net.Dial("unix", path)
	if e != nil {
		t.Fatalf("dial: %v", e)
	}
	defer client.Close()
	conn, e := plain.Accept()
	if e != nil {
		t.Fatalf("accept: %v", e)
	}
	defer conn.Close()
	if _, e := guardRequestWriter(conn); !errors.Is(e, ErrBrokerUnavailable) {
		t.Fatalf("guard without SO_PASSCRED = %v, want ErrBrokerUnavailable", e)
	}
}

// TestWriterCredentialMatches unit-tests the strict ancillary policy.
func TestWriterCredentialMatches(t *testing.T) {
	want := unix.Ucred{Pid: 4242, Uid: 1000, Gid: 1001}
	matching := parseCredMsg(t, want)
	otherPid := parseCredMsg(t, unix.Ucred{Pid: 4243, Uid: want.Uid, Gid: want.Gid})
	otherUid := parseCredMsg(t, unix.Ucred{Pid: want.Pid, Uid: want.Uid + 1, Gid: want.Gid})
	otherGid := parseCredMsg(t, unix.Ucred{Pid: want.Pid, Uid: want.Uid, Gid: want.Gid + 1})
	short := matching
	short.Data = short.Data[:len(short.Data)-4]
	rights := unix.SocketControlMessage{
		Header: unix.Cmsghdr{Level: unix.SOL_SOCKET, Type: unix.SCM_RIGHTS, Len: uint64(unix.CmsgLen(4))},
		Data:   make([]byte, 4),
	}
	wrongType := matching
	wrongType.Header.Type = unix.SCM_RIGHTS

	cases := []struct {
		name string
		msgs []unix.SocketControlMessage
		want bool
	}{
		{"matching", []unix.SocketControlMessage{matching}, true},
		{"missing", nil, false},
		{"duplicate", []unix.SocketControlMessage{matching, matching}, false},
		{"extra rights", []unix.SocketControlMessage{matching, rights}, false},
		{"truncated data", []unix.SocketControlMessage{short}, false},
		{"wrong type", []unix.SocketControlMessage{wrongType}, false},
		{"other pid", []unix.SocketControlMessage{otherPid}, false},
		{"other uid", []unix.SocketControlMessage{otherUid}, false},
		{"other gid", []unix.SocketControlMessage{otherGid}, false},
	}
	for _, tc := range cases {
		if got := writerCredentialMatches(tc.msgs, want); got != tc.want {
			t.Fatalf("%s: writerCredentialMatches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func parseCredMsg(t *testing.T, cred unix.Ucred) unix.SocketControlMessage {
	t.Helper()
	msgs, e := unix.ParseSocketControlMessage(unix.UnixCredentials(&cred))
	if e != nil || len(msgs) != 1 {
		t.Fatalf("parse crafted credentials: %v %d", e, len(msgs))
	}
	return msgs[0]
}

// TestBrokerServeRefusesInheritedWriterBeforeCallback is the end-to-end
// regression through Broker.serve: a hello written by an inherited descriptor
// child must be refused before any broker callback or authority exists, while
// the same hello written by the connecting process is served.
func TestBrokerServeRefusesInheritedWriterBeforeCallback(t *testing.T) {
	endpoint := brokerTestSocket(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(ctx context.Context, peer Peer, req CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
			calls.Add(1)
			return CLIRunBrokerResponse{V: 1}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatalf("broker start: %v", e)
	}
	defer func() { _ = broker.Close() }()

	hello := BrokerHello{V: 1, Mode: "cli-run"}
	request := CLIRunBrokerRequest{
		V:         1,
		VaultPath: "/tmp/synthetic-vault.ll",
		Targets:   []personal.CLIBrokerTarget{{Slot: "SYNTHETIC", ID: "item", Revision: "revision", Field: "password"}},
	}
	parentBytes := append(credWireFrame(t, hello), credWireFrame(t, request)...)

	// Positive control: the same process wrote the hello, so it is served.
	parent := credDialPath(t, endpoint)
	if _, e := parent.Write(parentBytes); e != nil {
		t.Fatalf("parent write: %v", e)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("same-process writer was never served")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = parent.Close()

	before := calls.Load()

	// Inherited descriptor: the parent connects, the exec'd child writes the
	// identical hello and request. SO_PEERCRED still names the parent.
	client := credDialPath(t, endpoint)
	child := startCredWriterChild(t, client, parentBytes)
	waitCredWriterChild(t, child)
	if child.Process.Pid == os.Getpid() {
		t.Fatal("helper ran as the parent process")
	}

	time.Sleep(300 * time.Millisecond)
	if got := calls.Load(); got != before {
		t.Fatalf("callback ran %d extra time(s) for an inherited-descriptor writer", got-before)
	}

	// No challenge or response byte may reach the unauthenticated writer.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if n, e := client.Read(one[:]); e == nil {
		t.Fatalf("broker sent %d bytes to an inherited-descriptor writer", n)
	}
}
