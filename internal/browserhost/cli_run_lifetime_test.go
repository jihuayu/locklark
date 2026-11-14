//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// cliRunPreparedProof retains the exact callback-owned prepared map and its
// buffers so a test can prove the broker cleared all of them after a refusal.
type cliRunPreparedProof struct {
	values  map[string][]byte
	buffers [][]byte
}

// serveCLIRunUnix starts one real Unix-socket listener and runs the production
// broker serve path for exactly one accepted connection, including the CLI-run
// hello handshake. The returned channel closes only after the handler has
// returned, including its deferred clears, so a test can inspect retained
// callback buffers without racing them.
func serveCLIRunUnix(t *testing.T, endpoint string, b *Broker) <-chan struct{} {
	t.Helper()
	listener, e := net.Listen("unix", endpoint)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		b.serve(conn)
	}()
	return done
}

// TestCLIRunDisconnect uses a real local Unix socket. The callback waits for
// cancellation and then deliberately returns a synthetic value with no error;
// the server must still refuse and put zero values on the wire.
func TestCLIRunDisconnect(t *testing.T) {
	installCLIRunPassingGate(t)
	for _, tc := range []struct {
		name           string
		disconnect     func(*net.UnixConn) error
		expectResponse bool
	}{
		{
			// First: a real half-close is EOF on the server read side while the
			// client can still observe whether a value frame is returned.
			name: "eof",
			disconnect: func(c *net.UnixConn) error {
				return c.CloseWrite()
			},
			expectResponse: true,
		},
		{
			name: "extra",
			disconnect: func(c *net.UnixConn) error {
				_, e := c.Write([]byte{0x7f})
				return e
			},
			expectResponse: true,
		},
		{
			name: "close",
			disconnect: func(c *net.UnixConn) error {
				return c.Close()
			},
			expectResponse: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := brokerTestSocket(t)
			started := make(chan struct{})
			canceled := make(chan error, 1)
			deadlineOK := make(chan bool, 1)
			var startOnce sync.Once
			var calls atomic.Int64
			synthetic := map[string]string{"SYNTHETIC": "must-not-leak"}
			broker := NewBroker(BrokerCallbacks{
				HandleCLIRun: func(ctx context.Context, _ Peer, _ CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
					calls.Add(1)
					deadline, hasDeadline := ctx.Deadline()
					select {
					case deadlineOK <- hasDeadline && time.Until(deadline) <= CLIRunApprovalMaxLifetime:
					default:
					}
					startOnce.Do(func() { close(started) })
					<-ctx.Done()
					select {
					case canceled <- ctx.Err():
					default:
					}
					// A late/misbehaving approval result must not disclose.
					return CLIRunBrokerResponse{V: 1, Values: synthetic}, nil
				},
			})
			if e := broker.Start(endpoint); e != nil {
				t.Fatal(e)
			}
			defer broker.Close()

			raw, e := net.Dial("unix", endpoint)
			if e != nil {
				t.Fatal(e)
			}
			conn := raw.(*net.UnixConn)
			defer conn.Close()
			hello := []byte(`{"v":1,"mode":"cli-run"}`)
			if e := writeFrame(conn, hello); e != nil {
				t.Fatal(e)
			}
			request, e := json.Marshal(freshCLIRunFixtureRequest())
			if e != nil {
				t.Fatal(e)
			}
			if e := writeFrame(conn, request); e != nil {
				t.Fatal(e)
			}
			clear(request)

			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("broker callback did not start")
			}
			select {
			case ok := <-deadlineOK:
				if !ok {
					t.Fatal("broker callback received an unbounded context")
				}
			default:
				t.Fatal("broker callback did not report its context deadline")
			}
			if e := tc.disconnect(conn); e != nil {
				t.Fatal(e)
			}
			if tc.expectResponse {
				if e := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
					t.Fatal(e)
				}
				response, e := readFrame(conn, MaxOutput)
				if e != nil {
					t.Fatal("no refusal after disconnect:", e)
				}
				var resp CLIRunBrokerResponse
				dec := json.NewDecoder(bytes.NewReader(response))
				dec.DisallowUnknownFields()
				if e := dec.Decode(&resp); e != nil {
					t.Fatal(e)
				}
				clear(response)
				if resp.V != 1 || resp.Error != "refused" || len(resp.Values) != 0 {
					t.Fatalf("disconnect response = %+v", resp)
				}
				// The server closes immediately after the refusal frame once the
				// watcher is gone, so EOF here also proves the watcher exited.
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, e := readFrame(conn, MaxOutput); e == nil {
					t.Fatal("server left the CLI connection open")
				}
			}
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("callback was not canceled by client disconnect")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("callback calls = %d, want exactly 1", got)
			}
		})
	}
}

// TestCLIRunHalfClosePreparedValuesRefused is the real Unix-socket regression
// for the post-callback cancellation window. The callback prepares actual
// session-bound values and a canonical receipt, then blocks until the client
// half-closes its write side. The EOF watcher cancels the server context; the
// callback returns the otherwise-valid prepared success. The client must
// receive only the fixed refusal, no values or receipt may reach the wire,
// and the retained prepared buffers must be cleared.
func TestCLIRunHalfClosePreparedValuesRefused(t *testing.T) {
	installCLIRunPassingGate(t)
	endpoint := brokerTestSocket(t)
	session, row := brokerTestSession(t)
	prepared := make(chan cliRunPreparedProof, 1)
	canceled := make(chan error, 1)
	broker := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(ctx context.Context, _ Peer, req CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
			request, e := CanonicalCLIRunRequest(req.Scope, req.Scope.TempRoot)
			if e != nil {
				return BrokerCLIResponse{}, e
			}
			receipt, values, e := session.PrepareBrokeredRun(ctx, CanonicalCLIRunTargets(req.Targets), request, req.Scope.TempRoot)
			if e != nil {
				return BrokerCLIResponse{}, e
			}
			buffers := make([][]byte, 0, len(values))
			for _, value := range values {
				buffers = append(buffers, value)
			}
			prepared <- cliRunPreparedProof{values: values, buffers: buffers}
			<-ctx.Done()
			canceled <- ctx.Err()
			return BrokerCLIResponse{V: 1, PreparedValues: values, Receipt: receipt}, nil
		},
	})
	handlerDone := serveCLIRunUnix(t, endpoint, broker)

	raw, e := net.Dial("unix", endpoint)
	if e != nil {
		t.Fatal(e)
	}
	conn := raw.(*net.UnixConn)
	defer conn.Close()
	hello := []byte(`{"v":1,"mode":"cli-run"}`)
	if e := writeFrame(conn, hello); e != nil {
		t.Fatal(e)
	}
	req := freshCLIRunFixtureRequest()
	req.VaultPath = session.VaultPath()
	req.Targets = []personal.CLIBrokerTarget{{Slot: "token", ID: row.ID, Revision: row.Revision, Field: "password"}}
	frame, e := json.Marshal(req)
	if e != nil {
		t.Fatal(e)
	}
	if e := writeFrame(conn, frame); e != nil {
		t.Fatal(e)
	}
	clear(frame)

	var proof cliRunPreparedProof
	select {
	case proof = <-prepared:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not prepare values")
	}
	if len(proof.values) == 0 || len(proof.buffers) == 0 {
		t.Fatal("callback did not return prepared values")
	}
	if e := conn.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	select {
	case got := <-canceled:
		if !errors.Is(got, context.Canceled) {
			t.Fatalf("server callback context after half-close = %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("half-close did not cancel the callback context")
	}

	if e := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	response, e := readFrame(conn, MaxOutput)
	if e != nil {
		t.Fatal("no refusal after half-close:", e)
	}
	defer clear(response)
	var resp CLIRunBrokerResponse
	dec := json.NewDecoder(bytes.NewReader(response))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&resp); e != nil {
		t.Fatal(e)
	}
	if resp.V != 1 || resp.Error != cliRunErrorRefused || len(resp.PreparedValues) != 0 || len(resp.Values) != 0 ||
		resp.Receipt != (personal.RunBundlePreparationReceipt{}) {
		t.Fatalf("half-close response leaked a success shape: %+v", resp)
	}
	if bytes.Contains(response, []byte(cliRunValuesField)) || bytes.Contains(response, []byte(cliRunReceiptField)) ||
		bytes.Contains(response, []byte("broker-password")) {
		t.Fatalf("half-close response contained secret fields: %s", response)
	}
	// The refusal is the only frame. A second frame would prove a late payload
	// was written after the cancellation check.
	if e := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	if extra, e := readFrame(conn, MaxOutput); e == nil {
		clear(extra)
		t.Fatal("server wrote a second frame after the refusal")
	}

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serveCLIRun did not return after refusal")
	}
	if len(proof.values) != 0 {
		t.Fatal("prepared value map was not cleared after refusal")
	}
	for _, buffer := range proof.buffers {
		for _, b := range buffer {
			if b != 0 {
				t.Fatal("prepared buffer was not cleared after refusal")
			}
		}
	}
}

func TestCLIRunApprovalAbsoluteCap(t *testing.T) {
	if CLIRunApprovalMaxLifetime != 60*time.Second {
		t.Fatalf("approval lifetime = %s, want absolute 60s", CLIRunApprovalMaxLifetime)
	}
}

// TestCLIRunDeadline proves a short caller deadline remains authoritative
// with the prepared-value path: the callback prepares actual session-bound
// values and a receipt, then blocks until the caller deadline closes the
// connection. The server must cancel the callback and never treat the late
// success as fallback-eligible; the retained prepared buffers must be cleared.
// It uses the existing 500ms caller context and never sleeps for the 60s cap.
func TestCLIRunDeadline(t *testing.T) {
	installCLIRunPassingGate(t)
	endpoint := brokerTestSocket(t)
	session, row := brokerTestSession(t)
	prepared := make(chan cliRunPreparedProof, 1)
	canceled := make(chan error, 1)
	broker := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(ctx context.Context, _ Peer, req CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
			request, e := CanonicalCLIRunRequest(req.Scope, req.Scope.TempRoot)
			if e != nil {
				return BrokerCLIResponse{}, e
			}
			receipt, values, e := session.PrepareBrokeredRun(ctx, CanonicalCLIRunTargets(req.Targets), request, req.Scope.TempRoot)
			if e != nil {
				return BrokerCLIResponse{}, e
			}
			buffers := make([][]byte, 0, len(values))
			for _, value := range values {
				buffers = append(buffers, value)
			}
			prepared <- cliRunPreparedProof{values: values, buffers: buffers}
			<-ctx.Done()
			canceled <- ctx.Err()
			return BrokerCLIResponse{V: 1, PreparedValues: values, Receipt: receipt}, nil
		},
	})
	handlerDone := serveCLIRunUnix(t, endpoint, broker)

	req := freshCLIRunFixtureRequest()
	req.VaultPath = session.VaultPath()
	req.Targets = []personal.CLIBrokerTarget{{Slot: "token", ID: row.ID, Revision: row.Revision, Field: "password"}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	type result struct {
		resp CLIRunBrokerResponse
		err  error
	}
	done := make(chan result, 1)
	begin := time.Now()
	go func() {
		resp, err := RequestCLIRun(ctx, req)
		done <- result{resp: resp, err: err}
	}()
	var proof cliRunPreparedProof
	select {
	case proof = <-prepared:
	case <-time.After(5 * time.Second):
		t.Fatal("server callback did not prepare values")
	}
	if len(proof.values) == 0 || len(proof.buffers) == 0 {
		t.Fatal("callback did not return prepared values")
	}
	select {
	case out := <-done:
		if !errors.Is(out.err, context.DeadlineExceeded) {
			t.Fatalf("early deadline result: %v %+v", out.err, out.resp)
		}
		if len(out.resp.PreparedValues) != 0 || len(out.resp.Values) != 0 {
			t.Fatalf("early deadline returned values: %+v", out.resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequestCLIRun ignored the caller deadline")
	}
	if elapsed := time.Since(begin); elapsed >= 5*time.Second {
		t.Fatalf("early caller deadline took %s", elapsed)
	}
	select {
	case got := <-canceled:
		if !errors.Is(got, context.Canceled) {
			t.Fatalf("server callback context after client deadline = %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server callback was not canceled by caller deadline")
	}

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serveCLIRun did not return after deadline refusal")
	}
	if len(proof.values) != 0 {
		t.Fatal("prepared value map was not cleared after deadline refusal")
	}
	for _, buffer := range proof.buffers {
		for _, b := range buffer {
			if b != 0 {
				t.Fatal("prepared buffer was not cleared after deadline refusal")
			}
		}
	}
}
