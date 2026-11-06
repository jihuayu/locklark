//go:build windows

package sshagent

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func nativeTestEndpoint(t *testing.T) string {
	t.Helper()
	path, e := DefaultEndpoint()
	if e != nil {
		t.Fatal("native pipe identity unavailable")
	}
	return path
}

func TestWindowsPipeOwnerSIDAndProtectedDACL(t *testing.T) {
	path, e := DefaultEndpoint()
	if e != nil {
		t.Fatal("owner identity unavailable")
	}
	listener, e := listenLocal(path)
	if e != nil {
		t.Fatal("private pipe listener unavailable")
	}
	defer listener.Close()
	if other, e := listenLocal(path); e == nil {
		other.Close()
		t.Fatal("existing pipe was taken over")
	}
	if other, e := listenLocal(`\\.\pipe\openssh-ssh-agent`); e == nil {
		other.Close()
		t.Fatal("system agent pipe was accepted")
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Native Windows OpenSSH also requests SECURITY_IDENTIFICATION. Anonymous
	// pipe clients intentionally do not supply a verifiable account token.
	client, e := winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
	if e != nil {
		t.Fatal("private pipe client failed")
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal("pipe accept did not finish")
	}
	defer server.Close()
	fd := server.(interface{ Fd() uintptr }).Fd()
	sd, e := windows.GetSecurityInfo(windows.Handle(fd), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal("pipe descriptor unavailable")
	}
	sid, e := ownerSID()
	if e != nil {
		t.Fatal("owner SID unavailable")
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || owner.String() != sid {
		t.Fatal("pipe owner differs from current user")
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("pipe DACL inherits unrelated permissions")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 1 {
		t.Fatal("pipe DACL is not current-user only")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() != sid {
		t.Fatal("pipe access is not confined to current user SID")
	}
	if writeFrame(client, []byte{11}) != nil {
		t.Fatal("pipe request fixture failed")
	}
	peer, first, e := prepareConnection(server)
	defer clear(first)
	if e != nil || peer.User != "SID "+sid || peer.PID != uint32(os.Getpid()) || len(first) != 1 || first[0] != 11 {
		t.Fatal("pipe peer was not bound to the actual client token/PID")
	}
}
