//go:build linux

package browserhost

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Linux broker socket authentication has two distinct layers:
//
//   - The connection credential (SO_PEERCRED) names the process that called
//     connect(2). It is fixed for the lifetime of the connection and is what
//     authenticatedPeer reports.
//   - The writer credential (SCM_CREDENTIALS, delivered only when the receiving
//     socket has SO_PASSCRED) names the process that actually sent each chunk
//     of bytes.
//
// They are not interchangeable. A process can connect and then fork/exec a
// child that inherits the connected file descriptor; the child writes the
// request while SO_PEERCRED still reports the parent as the connection peer.
// Native terminal and executable lease approval must therefore authenticate
// the writer of each request message, not only whoever created the socket.
// The kernel supplies SCM_CREDENTIALS from the sending process; a peer cannot
// claim an arbitrary PID/UID/GID (an explicitly supplied credential is checked
// by the kernel against the sender before it is accepted).
//
// listenUnixLocal sets SO_PASSCRED on the listening socket before bind/listen.
// Accepted sockets inherit the option, so bytes that were already queued in the
// accept backlog before Accept still arrive with the real writer's
// SCM_CREDENTIALS. guardRequestWriter replaces the connection's Read with a
// validator that checks every received chunk, including frame headers, body
// fragments and the v2 read watcher, against the kernel connection credential.
// A mismatch, missing/duplicate/truncated credential or any extra ancillary
// data is refused before the protocol layer can see the bytes, so no callback
// or authority is ever derived from an unauthenticated write.
//
// Scope of the guarantee: the broker authenticates the writer of every byte it
// reads. It does not authenticate buffered bytes it never reads, and on
// non-Linux hosts per-message credentials do not exist (see the !linux build),
// where the connection-level peer check remains the documented boundary.

// writerControlBytes bounds the ancillary buffer for one read. It holds one
// kernel SCM_CREDENTIALS plus several SCM_RIGHTS descriptors, which lets us
// observe and close leaked descriptors instead of silently inheriting them.
// Anything larger is reported by the kernel as MSG_CTRUNC and refused.
const writerControlBytes = 128

// errUnverifiedWriter is returned from the guarded Read when the bytes were not
// written by the process authenticated for the connection.
var errUnverifiedWriter = errors.New("broker: request bytes were not sent by the authenticated peer")

// listenUnixLocal creates the private UNIX listening socket. Unlike a plain
// net.ListenUnix, SO_PASSCRED is enabled after socket(2) and before bind(2), so
// every connection queued for Accept inherits per-message credential delivery.
func listenUnixLocal(path string) (*net.UnixListener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var optErr error
			if err := raw.Control(func(fd uintptr) {
				optErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
			}); err != nil {
				return err
			}
			return optErr
		},
	}
	l, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, err
	}
	ul, ok := l.(*net.UnixListener)
	if !ok {
		_ = l.Close()
		return nil, ErrBrokerUnavailable
	}
	return ul, nil
}

// verifiedWriterConn keeps all normal *net.UnixConn behavior (writes, deadlines,
// addresses, Close and netpoll integration) and overrides only Read.
type verifiedWriterConn struct {
	*net.UnixConn
	raw  syscall.RawConn
	cred unix.Ucred // SO_PEERCRED, i.e. the connection creator
}

// guardRequestWriter installs the per-message writer check. It must be called
// after authenticatedPeer and before the first protocol read. On non-Linux
// hosts there is no per-message credential mechanism, so the connection-level
// peer check remains the documented boundary.
func guardRequestWriter(c net.Conn) (net.Conn, error) {
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return nil, ErrBrokerUnavailable
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, ErrBrokerUnavailable
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return nil, ErrBrokerUnavailable
	}
	if cred.Uid != uint32(os.Geteuid()) || cred.Pid <= 0 {
		return nil, ErrBrokerUnavailable
	}
	// Refuse a socket that never had SO_PASSCRED enabled: without the option the
	// kernel silently delivers no per-message credentials, and a read that only
	// notices that at runtime would turn every refusal into a protocol stall.
	if err := raw.Control(func(fd uintptr) {
		credErr = socketHasPasscred(int(fd))
	}); err != nil || credErr != nil {
		return nil, ErrBrokerUnavailable
	}
	return &verifiedWriterConn{UnixConn: conn, raw: raw, cred: *cred}, nil
}

// socketHasPasscred reports whether a socket delivers per-message credentials.
func socketHasPasscred(fd int) error {
	on, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED)
	if err != nil || on != 1 {
		return ErrBrokerUnavailable
	}
	return nil
}

// Read validates the writer credential of every received chunk before exposing
// its bytes. It never falls back to an unverified UnixConn.Read.
func (c *verifiedWriterConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return c.readWithControl(p, writerControlBytes)
}

// readWithControl is Read with an explicit ancillary buffer size. Production
// code always uses writerControlBytes; tests shrink it to exercise missing or
// truncated credentials on a real socket.
func (c *verifiedWriterConn) readWithControl(p []byte, controlBytes int) (int, error) {
	oob := make([]byte, controlBytes)
	var (
		n         int
		oobn      int
		recvFlags int
		recvErr   error
	)
	// RawConn.Read integrates with the netpoller: the callback performs one
	// non-blocking recvmsg and returns false on EAGAIN/interrupt, which makes
	// RawConn wait for readability while honoring SetReadDeadline and Close.
	if err := c.raw.Read(func(fd uintptr) bool {
		n, oobn, recvFlags, _, recvErr = unix.Recvmsg(
			int(fd), p, oob, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
		switch recvErr {
		case nil:
			return true
		case unix.EAGAIN, unix.EINTR:
			recvErr = nil
			return false
		default:
			return true
		}
	}); err != nil {
		return 0, err
	}
	if recvErr != nil {
		return 0, recvErr
	}
	if oobn < 0 || oobn > len(oob) {
		return 0, errUnverifiedWriter
	}

	// Parse and dispose of ancillary data before deciding anything. Any SCM_RIGHTS
	// descriptors are closed so a rejected peer cannot leave inheritable file
	// descriptors in the broker process (MSG_CMSG_CLOEXEC also keeps them out of
	// an exec between receive and close).
	msgs, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
	closeReceivedRights(msgs)
	if parseErr != nil || recvFlags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return 0, errUnverifiedWriter
	}
	if n == 0 {
		// Orderly EOF carries no request bytes and therefore no authority. Any
		// control data on a zero-length stream read is unexpected and refused.
		if len(msgs) != 0 {
			return 0, errUnverifiedWriter
		}
		return 0, io.EOF
	}
	if !writerCredentialMatches(msgs, c.cred) {
		return 0, errUnverifiedWriter
	}
	return n, nil
}

// writerCredentialMatches requires exactly one complete kernel credential that
// names the same PID, UID and GID as the connection creator. Missing, duplicate
// and extra control messages are all rejected.
func writerCredentialMatches(msgs []unix.SocketControlMessage, want unix.Ucred) bool {
	if len(msgs) != 1 {
		return false
	}
	m := &msgs[0]
	if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_CREDENTIALS || len(m.Data) != unix.SizeofUcred {
		return false
	}
	got, err := unix.ParseUnixCredentials(m)
	if err != nil || got == nil {
		return false
	}
	return got.Pid == want.Pid && got.Uid == want.Uid && got.Gid == want.Gid
}

// closeReceivedRights closes every descriptor delivered through SCM_RIGHTS.
func closeReceivedRights(msgs []unix.SocketControlMessage) {
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
			continue
		}
		for off := 0; off+4 <= len(m.Data); off += 4 {
			fd := int(int32(binary.NativeEndian.Uint32(m.Data[off : off+4])))
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	}
}
