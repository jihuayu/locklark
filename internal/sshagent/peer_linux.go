//go:build linux

package sshagent

import (
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
	var peer *unix.Ucred
	if raw.Control(func(fd uintptr) { peer, e = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || e != nil || peer == nil || peer.Uid != uint32(os.Geteuid()) || peer.Pid <= 0 {
		return Peer{}, ErrRefused
	}
	process := "进程路径不可读取"
	if path, err := os.Readlink("/proc/" + strconv.Itoa(int(peer.Pid)) + "/exe"); err == nil && len(path) <= 512 {
		process = path
	}
	return Peer{User: "UID " + strconv.FormatUint(uint64(peer.Uid), 10), PID: uint32(peer.Pid), Process: process}, nil
}
