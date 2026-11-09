//go:build windows

package browserhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var brokerImpersonate = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func ownerSID() (string, error) {
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return "", ErrBrokerUnavailable
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		return "", ErrBrokerUnavailable
	}
	return user.User.Sid.String(), nil
}

func safeBrokerToken(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func DefaultBrokerEndpoint() (string, error) {
	sid, e := ownerSID()
	if e != nil {
		return "", ErrBrokerUnavailable
	}
	hash := sha256.Sum256([]byte(sid))
	suffix := hex.EncodeToString(hash[:8])
	if custom := brokerSocketEnv(); custom != "" && safeBrokerToken(custom) {
		suffix += "-" + custom
	}
	return `\\.\pipe\Locklark-Browser-broker-` + suffix, nil
}

func listenLocal(path string) (net.Listener, error) {
	want, e := DefaultBrokerEndpoint()
	if e != nil || path != want {
		return nil, ErrBrokerUnavailable
	}
	sid, e := ownerSID()
	if e != nil {
		return nil, ErrBrokerUnavailable
	}
	l, e := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "O:" + sid + "G:" + sid + "D:P(A;;GA;;;" + sid + ")", InputBufferSize: MaxInput + 4, OutputBufferSize: MaxOutput + 4})
	if e != nil {
		return nil, ErrBrokerUnavailable
	}
	return l, nil
}

func dialLocal(ctx context.Context, endpoint string) (net.Conn, error) {
	timeout := 300 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	conn, e := winio.DialPipe(endpoint, &timeout)
	if e != nil {
		return nil, ErrBrokerUnavailable
	}
	return conn, nil
}

// brokerEndpointForClient resolves the CLI client's pipe without collapsing
// configuration errors into the fallback-safe "absent" sentinel. An explicit
// custom token that is unsafe is a configuration error, never a missing
// default broker. An identity query failure is also a refusal: without our own
// SID there is no trusted endpoint identity to compare against.
func brokerEndpointForClient() (string, error) {
	if custom := brokerSocketEnv(); custom != "" && !safeBrokerToken(custom) {
		return "", ErrBrokerRefused
	}
	path, e := DefaultBrokerEndpoint()
	if e != nil {
		return "", ErrBrokerRefused
	}
	if !strings.HasPrefix(path, `\\.\pipe\`) || !safeBrokerToken(strings.TrimPrefix(path, `\\.\pipe\`)) {
		return "", ErrBrokerRefused
	}
	return path, nil
}

// authenticatedServerPeer verifies the process listening on the broker pipe
// before any hello or secret request is written. It uses the server process ID
// for the client end of the pipe, opens that process's token and requires the
// token's user SID to equal the current process SID. Every handle is closed.
func authenticatedServerPeer(conn net.Conn) (Peer, error) {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Peer{}, ErrBrokerUnavailable
	}
	var pid uint32
	if windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid) != nil || pid == 0 {
		return Peer{}, ErrBrokerUnavailable
	}
	owner, e := ownerSID()
	if e != nil {
		return Peer{}, ErrBrokerUnavailable
	}
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return Peer{}, ErrBrokerUnavailable
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return Peer{}, ErrBrokerUnavailable
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil || user == nil || user.User.Sid == nil {
		return Peer{}, ErrBrokerUnavailable
	}
	server := user.User.Sid.String()
	if server == "" || server != owner {
		return Peer{}, ErrBrokerUnavailable
	}
	name := ""
	var buf [512]uint16
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(process, 0, &buf[0], &n) == nil {
		name = windows.UTF16ToString(buf[:n])
	}
	return Peer{User: "SID " + server, PID: pid, Process: name}, nil
}

// dialVerifiedBroker validates the pipe name and the server's SID boundary
// before returning a connection. Unverifiable identities are fixed refusals;
// only an absent pipe or a connection that was never established is
// fallback-safe unavailable.
func dialVerifiedBroker(ctx context.Context, endpoint string) (net.Conn, error) {
	if !strings.HasPrefix(endpoint, `\\.\pipe\`) || len(endpoint) > 256 {
		return nil, ErrBrokerRefused
	}
	conn, e := dialLocal(ctx, endpoint)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ErrBrokerRefused
		}
		return nil, ErrBrokerUnavailable
	}
	if _, e := authenticatedServerPeer(conn); e != nil {
		_ = conn.Close()
		return nil, ErrBrokerRefused
	}
	return conn, nil
}

func authenticatedPeer(conn net.Conn) (Peer, error) {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Peer{}, ErrBrokerUnavailable
	}
	h := windows.Handle(fd.Fd())
	var pid uint32
	if windows.GetNamedPipeClientProcessId(h, &pid) != nil || pid == 0 {
		return Peer{}, ErrBrokerUnavailable
	}
	owner, e := ownerSID()
	if e != nil {
		return Peer{}, ErrBrokerUnavailable
	}
	runtime.LockOSThread()
	reverted := false
	defer func() {
		if reverted {
			runtime.UnlockOSThread()
		}
	}()
	okImpersonate, _, _ := brokerImpersonate.Call(uintptr(h))
	if okImpersonate == 0 {
		reverted = true
		return Peer{}, ErrBrokerUnavailable
	}
	var token windows.Token
	e = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	client := ""
	userFailed := false
	if e == nil {
		user, err := token.GetTokenUser()
		if err == nil {
			client = user.User.Sid.String()
		} else {
			userFailed = true
		}
		_ = token.Close()
	}
	if windows.RevertToSelf() != nil {
		return Peer{}, ErrBrokerUnavailable
	}
	reverted = true
	if e != nil || userFailed || client == "" || client != owner {
		return Peer{}, ErrBrokerUnavailable
	}
	process := ""
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

func brokerSocketEnv() string {
	return strings.TrimSpace(os.Getenv("LOCKLARK_BROWSER_SOCKET"))
}
