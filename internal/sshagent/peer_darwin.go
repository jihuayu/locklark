//go:build darwin

package sshagent

import (
	"bytes"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strconv"
)

func authenticatedPeer(c net.Conn) (Peer, error) {
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, ErrRefused
	}
	raw, e := conn.SyscallConn()
	if e != nil {
		return Peer{}, ErrRefused
	}
	var cred *unix.Xucred
	pid := 0
	if raw.Control(func(fd uintptr) {
		cred, e = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e == nil {
			pid, e = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}) != nil || e != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) || pid <= 0 {
		return Peer{}, ErrRefused
	}
	process := "进程名称不可读取"
	if info, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil {
		process = string(bytes.TrimRight(info.Proc.P_comm[:], "\x00"))
	}
	return Peer{User: "UID " + strconv.FormatUint(uint64(cred.Uid), 10), PID: uint32(pid), Process: process}, nil
}
