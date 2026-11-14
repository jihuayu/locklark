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

// TestCLIRunDisconnect uses a real local Unix socket. The callback waits for
// cancellation and then deliberately returns a synthetic value with no error;
// the server must still refuse and put zero values on the wire.
func TestCLIRunDisconnect(t *testing.T) {
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
			request, e := json.Marshal(CLIRunBrokerRequest{
				V:         1,
				VaultPath: "/synthetic/personal.ll",
				Targets: []personal.CLIBrokerTarget{{
					Slot:     "SYNTHETIC",
					ID:       "0123456789abcdef0123456789abcdef",
					Revision: "fedcba9876543210fedcba9876543210",
					Field:    "password",
				}},
			})
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

func TestCLIRunApprovalAbsoluteCap(t *testing.T) {
	if CLIRunApprovalMaxLifetime != 60*time.Second {
		t.Fatalf("approval lifetime = %s, want absolute 60s", CLIRunApprovalMaxLifetime)
	}
}

// TestCLIRunDeadline proves a short caller deadline remains
// authoritative: the client closes the connection, the server cancels the
// running callback, and no synthetic values are returned.
func TestCLIRunDeadline(t *testing.T) {
	endpoint := brokerTestSocket(t)
	started := make(chan struct{})
	canceled := make(chan error, 1)
	broker := NewBroker(BrokerCallbacks{
		HandleCLIRun: func(ctx context.Context, _ Peer, _ CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
			close(started)
			<-ctx.Done()
			canceled <- ctx.Err()
			return CLIRunBrokerResponse{V: 1, Values: map[string]string{"SYNTHETIC": "must-not-leak"}}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatalf("start %q (%d bytes): %v", endpoint, len(endpoint), e)
	}
	defer broker.Close()

	request := CLIRunBrokerRequest{
		V:         1,
		VaultPath: "/synthetic/personal.ll",
		Targets: []personal.CLIBrokerTarget{{
			Slot:     "SYNTHETIC",
			ID:       "0123456789abcdef0123456789abcdef",
			Revision: "fedcba9876543210fedcba9876543210",
			Field:    "password",
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	type result struct {
		resp CLIRunBrokerResponse
		err  error
	}
	done := make(chan result, 1)
	begin := time.Now()
	go func() {
		resp, err := RequestCLIRun(ctx, request)
		done <- result{resp: resp, err: err}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("server callback did not start")
	}
	select {
	case out := <-done:
		if !errors.Is(out.err, ErrBrokerUnavailable) || len(out.resp.Values) != 0 {
			t.Fatalf("early deadline result: %v %+v", out.err, out.resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequestCLIRun ignored the caller deadline")
	}
	if elapsed := time.Since(begin); elapsed >= 5*time.Second {
		t.Fatalf("early caller deadline took %s", elapsed)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("server callback was not canceled by caller deadline")
	}
}
