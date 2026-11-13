package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/clibinding"
)

const (
	// cliBrokerReadyChildMode is the dedicated child mode of the real
	// cancellation unit. TestMain accepts it only in the exact four-argument
	// form, so no suite flag or extra argument can turn a normal test run into
	// this long-lived child.
	cliBrokerReadyChildMode = "locklark-test-child-ready"

	// cliBrokerReadyChildHold is how long the child keeps the ready
	// connection. Cancellation must end it much earlier; the hold is only an
	// upper bound that keeps a leaked child from living forever.
	cliBrokerReadyChildHold = 20 * time.Second

	// cliBrokerReadyChildAcceptWait bounds the parent's wait for the child to
	// connect. It is the readiness barrier, never a process-start sleep.
	cliBrokerReadyChildAcceptWait = 10 * time.Second

	// cliBrokerReadyChildCancelWait is shorter than the fixture's request
	// timeout, so a signal that never reached the watcher cannot be masked by
	// the ordinary run timeout killing the child.
	cliBrokerReadyChildCancelWait = 5 * time.Second

	// cliBrokerReadyChildExitWait is the short deadline used after the SUT
	// returns. A live child still holding the connection cannot produce EOF.
	cliBrokerReadyChildExitWait = 3 * time.Second
)

// runCLIBrokerReadyChild is TestMain's real child process. It derives nothing
// from the broker or the vault: it connects to the parent-owned loopback
// listener, announces the parent's own ready nonce and its PID, and then keeps
// the connection until the run that owns it stops it or the 20-second bound
// expires. It never reads or reports stdin, a factor, the handshake, or any
// other process state.
func runCLIBrokerReadyChild(addr, readyNonce string) int {
	if !validCLIBrokerReadyNonce(readyNonce) || !validCLIBrokerReadyAddr(addr) {
		return 2
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 3
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "%s %d\n", readyNonce, os.Getpid()); err != nil {
		return 4
	}
	// No further output and no stdin. The read only holds the connection: it
	// ends at the parent's close or after the bounded hold, never by consuming
	// test input.
	_ = conn.SetReadDeadline(time.Now().Add(cliBrokerReadyChildHold))
	_, _ = io.Copy(io.Discard, conn)
	return 0
}

func validCLIBrokerReadyNonce(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	clear(decoded)
	return true
}

func validCLIBrokerReadyAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number > 0 && number <= 65535
}

// holdCLIChildIndependentStdin gives the child a stream that cannot reach end
// of file during the test. The brokered runner hands the child this process's
// os.Stdin, so the test owns one end of a pipe and leaves the other end open;
// the child never reads it. This is a stdin fixture, not a synchronization
// helper: readiness is proven only by the listener handshake.
func holdCLIChildIndependentStdin(t *testing.T) {
	t.Helper()
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal("independent child stdin unavailable")
	}
	original := os.Stdin
	os.Stdin = readEnd
	t.Cleanup(func() {
		os.Stdin = original
		readEnd.Close()
		writeEnd.Close()
	})
}

// TestCLIRunBrokerChildCancellationClosesRealProcess is the complete
// replacement for the removed shell/sleep-based
// TestCLIRunBrokerChildCancelledBySignal. It drives the production dispatcher,
// but not the real broker transport: the request seam immediately returns the
// audited reply without changing the request or waiting for the child. The
// parent creates its own crypto/rand ready nonce (never the broker scope
// nonce), listens on loopback, and fixes the child arguments and program digest
// before the call. Once the real test binary has connected and sent the exact
// nonce and PID, the non-blocking signal seam delivers Interrupt. The SUT must
// return the typed terminal broker failure with no local fallback, and a short
// read deadline must observe EOF, proving the child exited. No second
// shell-based child cancellation case is retained.
func TestCLIRunBrokerChildCancellationClosesRealProcess(t *testing.T) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("ready nonce entropy unavailable")
	}
	readyNonce := hex.EncodeToString(random[:])
	clear(random[:])

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("child readiness listener unavailable")
	}
	t.Cleanup(func() { listener.Close() })
	addr := listener.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatal("child readiness listener is not loopback")
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatal("child readiness listener is not TCP")
	}
	if err = tcpListener.SetDeadline(time.Now().Add(cliBrokerReadyChildAcceptWait)); err != nil {
		t.Fatal("child readiness deadline unavailable")
	}

	holdCLIChildIndependentStdin(t)
	f := newCLIBrokerFixture(t)
	installCLIRunBrokerSeams(t, true, f.tty)
	program := cliTestExecutable(t)
	programSHA, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		t.Fatal("child program digest unavailable")
	}
	f.binding.Program, f.binding.ProgramSHA256 = program, programSHA
	if err = f.binding.Validate(); err != nil {
		t.Fatal("child binding fixture invalid")
	}
	wantArgs := []string{cliBrokerReadyChildMode, addr, readyNonce}
	f.request.Program, f.request.Args = program, wantArgs
	if err = f.request.Validate(f.targets); err != nil {
		t.Fatal("child request fixture invalid")
	}
	t.Setenv("LOCKLARK_TEST_TOKEN", "")

	subscribed := make(chan chan<- os.Signal, 1)
	cliRunBrokerSignals = func(ch chan<- os.Signal) { subscribed <- ch }

	requests := 0
	var sent browserhost.CLIRunScope
	cliRunBrokerRequest = func(_ context.Context, req browserhost.CLIRunBrokerRequest) (browserhost.CLIRunBrokerResponse, error) {
		requests++
		sent = req.Scope.Clone()
		// Read only: the request and its containers stay untouched, and the
		// reply is returned immediately. The child is not awaited here.
		return auditedReply("token", cliBrokerFixturePassword), nil
	}
	opens := 0
	installCLIRunLocalConsole(t, func() (*os.File, *os.File, error) {
		opens++
		return nil, nil, errRunCLIConsole
	})

	var brokerSignals chan<- os.Signal
	t.Cleanup(func() {
		if brokerSignals == nil {
			select {
			case brokerSignals = <-subscribed:
			default:
			}
		}
		if brokerSignals != nil {
			select {
			case brokerSignals <- os.Interrupt:
			default:
			}
		}
	})

	result := make(chan error, 1)
	go func() {
		result <- executeCLIAuthenticatedWithBroker(context.Background(), "brokertool", f.binding, f.targets, f.call().Request)
	}()

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal("real child did not connect to the readiness listener")
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(cliBrokerReadyChildAcceptWait))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal("real child did not announce readiness")
	}
	pid, ok := parseCLIBrokerReadyLine(line, readyNonce)
	if !ok {
		t.Fatal("real child readiness handshake was not the exact nonce and PID")
	}
	if pid <= 0 || pid == os.Getpid() {
		t.Fatal("real child readiness PID is not a distinct child")
	}

	select {
	case brokerSignals = <-subscribed:
	case <-time.After(cliBrokerReadyChildCancelWait):
		t.Fatal("broker signal seam was not subscribed")
	}
	select {
	case brokerSignals <- os.Interrupt:
	default:
		t.Fatal("broker signal seam did not accept Interrupt")
	}

	select {
	case err = <-result:
	case <-time.After(cliBrokerReadyChildCancelWait):
		t.Fatal("cancelled child run did not return")
	}
	var terminal cliRunBrokerFailedError
	var exit *childExitStatus
	if !errors.As(err, &terminal) || terminal.cause == nil || errors.As(err, &exit) || err == errCLIRunBrokerAbsent || opens != 0 || requests != 1 {
		t.Fatal("cancelled child run was not a typed terminal failure without fallback")
	}
	if sent.Program != program || sent.ProgramSH != programSHA {
		t.Fatal("broker child program binding is stale")
	}
	if !sameStrings(sent.Args, wantArgs) {
		t.Fatal("broker child request does not carry the exact readiness arguments")
	}
	if sent.Nonce == readyNonce || !isFreshNonce(sent.Nonce) {
		t.Fatal("broker scope nonce is not independent from the readiness nonce")
	}

	_ = conn.SetReadDeadline(time.Now().Add(cliBrokerReadyChildExitWait))
	var one [1]byte
	n, readErr := conn.Read(one[:])
	if n != 0 || !errors.Is(readErr, io.EOF) {
		t.Fatal("real child kept the readiness connection after cancellation")
	}
}

func parseCLIBrokerReadyLine(line, readyNonce string) (int, bool) {
	line = strings.TrimSuffix(line, "\n")
	fields := strings.Split(line, " ")
	if len(fields) != 2 || fields[0] != readyNonce || fields[1] == "" || strings.ContainsRune(line, '\r') {
		return 0, false
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
