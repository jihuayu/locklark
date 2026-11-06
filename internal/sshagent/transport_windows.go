//go:build windows

package sshagent

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"runtime"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var impersonatePipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func prepareConnection(c net.Conn) (Peer, []byte, error) {
	// Windows impersonates the security context of the last pipe message read.
	// Read exactly one bounded frame before querying the connection token; it is
	// replayed internally only after SID verification, never sent to a handler
	// or native approval UI before authentication succeeds.
	first, e := readFrame(c)
	if e != nil {
		return Peer{}, nil, ErrRefused
	}
	peer, e := authenticatedPeer(c)
	if e != nil {
		clear(first)
		return Peer{}, nil, e
	}
	return peer, first, nil
}

func ownerSID() (string, error) {
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return "", ErrUnavailable
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		return "", ErrUnavailable
	}
	return user.User.Sid.String(), nil
}
func DefaultEndpoint() (string, error) {
	sid, e := ownerSID()
	if e != nil {
		return "", e
	}
	hash := sha256.Sum256([]byte(sid))
	return `\\.\pipe\Locklark-SSH-agent-` + hex.EncodeToString(hash[:8]), nil
}
func listenLocal(path string) (net.Listener, error) {
	want, e := DefaultEndpoint()
	if e != nil || path != want {
		return nil, ErrUnavailable
	}
	sid, e := ownerSID()
	if e != nil {
		return nil, e
	}
	// Pinned go-winio v0.6.2 uses an exclusive FILE_CREATE anchor and sets
	// FILE_PIPE_REJECT_REMOTE_CLIENTS. Never use the system agent's pipe name.
	l, e := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "O:" + sid + "G:" + sid + "D:P(A;;GA;;;" + sid + ")", InputBufferSize: MaxFrame + 4, OutputBufferSize: MaxFrame + 4})
	if e != nil {
		return nil, ErrUnavailable
	}
	return l, nil
}
func authenticatedPeer(conn net.Conn) (Peer, error) {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Peer{}, ErrRefused
	}
	h := windows.Handle(fd.Fd())
	var pid uint32
	if windows.GetNamedPipeClientProcessId(h, &pid) != nil || pid == 0 {
		return Peer{}, ErrRefused
	}
	owner, e := ownerSID()
	if e != nil {
		return Peer{}, ErrRefused
	}
	// Authenticate this pipe's token, rather than inferring SID from a recyclable
	// PID. On failed RevertToSelf this connection worker immediately returns
	// without unlocking its OS thread, causing that thread to be retired.
	runtime.LockOSThread()
	reverted := false
	defer func() {
		if reverted {
			runtime.UnlockOSThread()
		}
	}()
	okImpersonate, _, _ := impersonatePipe.Call(uintptr(h))
	if okImpersonate == 0 {
		reverted = true
		return Peer{}, ErrRefused
	}
	var token windows.Token
	e = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	client := ""
	if e == nil {
		user, err := token.GetTokenUser()
		if err == nil {
			client = user.User.Sid.String()
		}
		_ = token.Close()
	}
	if windows.RevertToSelf() != nil {
		return Peer{}, ErrRefused
	}
	reverted = true
	if e != nil || client == "" || client != owner {
		return Peer{}, ErrRefused
	}
	process := "进程路径不可读取"
	if p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
		var name [512]uint16
		n := uint32(len(name))
		if windows.QueryFullProcessImageName(p, 0, &name[0], &n) == nil {
			process = windows.UTF16ToString(name[:n])
		}
		_ = windows.CloseHandle(p)
	}
	return Peer{User: "SID " + client, PID: pid, Process: process}, nil
}
