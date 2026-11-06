//go:build linux

package browserhost

import (
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
	var peer *unix.Ucred
	var credErr error
	if raw.Control(func(fd uintptr) {
		peer, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}) != nil || credErr != nil || peer == nil || peer.Uid != uint32(os.Geteuid()) || peer.Pid <= 0 {
		return Peer{}, ErrBrokerUnavailable
	}
	process := ""
	if path, err := os.Readlink("/proc/" + strconv.Itoa(int(peer.Pid)) + "/exe"); err == nil && len(path) <= 512 {
		process = path
	}
	return Peer{User: "UID " + strconv.FormatUint(uint64(peer.Uid), 10), PID: uint32(peer.Pid), Process: process}, nil
}
