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

// peerBeforeHello is true on Windows: ImpersonateNamedPipeClient authenticates
// the security context of the last message read from the pipe, so the broker
// reads the bounded hello first and only then queries the client identity.
const peerBeforeHello = true

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
	ctx, cancel := dialBudget(ctx)
	defer cancel()
	// Identification is the least privilege that still lets the broker's
	// OpenThreadToken(TOKEN_QUERY) read the client SID. go-winio's other
	// DialPipe paths open with SECURITY_ANONYMOUS, which cannot be queried.
	conn, e := winio.DialPipeAccessImpLevel(ctx, endpoint, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
	if e != nil {
		return nil, ErrBrokerUnavailable
	}
	return conn, nil
}

// dialBudget bounds a local dial to 300ms and inherits any shorter or already
// canceled caller context.
func dialBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, 300*time.Millisecond)
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
