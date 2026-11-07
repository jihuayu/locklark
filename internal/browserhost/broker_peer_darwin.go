//go:build darwin

package browserhost

import (
	"bytes"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func authenticatedPeer(c net.Conn) (Peer, error) {
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, ErrBrokerUnavailable
	}
	raw, e := conn.SyscallConn()
	if e != nil {
		return Peer{}, ErrBrokerUnavailable
	}
	var cred *unix.Xucred
	pid := 0
	var credErr error
	if raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr == nil {
			pid, credErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}) != nil || credErr != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) || pid <= 0 {
		return Peer{}, ErrBrokerUnavailable
	}
	process := ""
	if info, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil {
		process = string(bytes.TrimRight(info.Proc.P_comm[:], "\x00"))
	}
	return Peer{User: "UID " + strconv.FormatUint(uint64(cred.Uid), 10), PID: uint32(pid), Process: process}, nil
}
