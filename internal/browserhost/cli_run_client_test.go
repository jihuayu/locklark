//go:build linux || darwin

package browserhost

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func cliRunTestRequest() CLIRunBrokerRequest {
	return CLIRunBrokerRequest{
		V:         1,
		VaultPath: "/synthetic/cli-run.ll",
		Targets: []personal.CLIBrokerTarget{{
			Slot:     "PASSWORD",
			ID:       strings.Repeat("a", 32),
			Revision: strings.Repeat("b", 64),
			Field:    "password",
		}},
	}
}

func cliRunTestMutations() map[string]func(*CLIRunBrokerRequest) {
	return map[string]func(*CLIRunBrokerRequest){
		"zero version": func(r *CLIRunBrokerRequest) { r.V = 0 },
		"empty vault":  func(r *CLIRunBrokerRequest) { r.VaultPath = "" },
		"no targets":   func(r *CLIRunBrokerRequest) { r.Targets = nil },
		"too many targets": func(r *CLIRunBrokerRequest) {
			many := make([]personal.CLIBrokerTarget, 17)
			for i := range many {
				many[i] = r.Targets[0]
				many[i].Slot = "SLOT"
			}
			r.Targets = many
		},
		"duplicate slots": func(r *CLIRunBrokerRequest) {
			r.Targets = append(r.Targets, r.Targets[0])
		},
		"empty slot":     func(r *CLIRunBrokerRequest) { r.Targets[0].Slot = "" },
		"empty id":       func(r *CLIRunBrokerRequest) { r.Targets[0].ID = "" },
		"empty revision": func(r *CLIRunBrokerRequest) { r.Targets[0].Revision = "" },
		"empty field":    func(r *CLIRunBrokerRequest) { r.Targets[0].Field = "" },
		"unknown field":  func(r *CLIRunBrokerRequest) { r.Targets[0].Field = "secret" },
		"short id":       func(r *CLIRunBrokerRequest) { r.Targets[0].ID = strings.Repeat("a", 16) },
		"oversize id":    func(r *CLIRunBrokerRequest) { r.Targets[0].ID = strings.Repeat("a", 64) },
		"uppercase id":   func(r *CLIRunBrokerRequest) { r.Targets[0].ID = strings.Repeat("A", 32) },
		"nonhex id":      func(r *CLIRunBrokerRequest) { r.Targets[0].ID = strings.Repeat("z", 32) },
		"short revision": func(r *CLIRunBrokerRequest) { r.Targets[0].Revision = strings.Repeat("b", 32) },
		"uppercase revision": func(r *CLIRunBrokerRequest) {
			r.Targets[0].Revision = strings.Repeat("B", 64)
		},
		"non-utf8 slot": func(r *CLIRunBrokerRequest) { r.Targets[0].Slot = "PASS\xffWORD" },
		"oversize slot": func(r *CLIRunBrokerRequest) { r.Targets[0].Slot = strings.Repeat("S", 129) },
	}
}

func TestRequestCLIRunLocalRefusals(t *testing.T) {
	brokerTestSocket(t) // trusted endpoint exists but nothing listens on it
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := cliRunTestMutations()
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			req := cliRunTestRequest()
			mutate(&req)
			resp, e := RequestCLIRun(context.Background(), req)
			if !errors.Is(e, ErrBrokerRefused) {
				t.Fatalf("got %v, want ErrBrokerRefused", e)
			}
			if errors.Is(e, ErrBrokerUnavailable) {
				t.Fatal("invalid request reported fallback-safe unavailable")
			}
			if len(resp.Values) != 0 {
				t.Fatalf("refused request returned values: %#v", resp.Values)
			}
		})
	}
	t.Run("nil context", func(t *testing.T) {
		resp, e := RequestCLIRun(nil, cliRunTestRequest())
		if !errors.Is(e, ErrBrokerRefused) {
			t.Fatalf("got %v, want ErrBrokerRefused", e)
		}
		if len(resp.Values) != 0 {
			t.Fatalf("nil ctx returned values: %#v", resp.Values)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		resp, e := RequestCLIRun(cancelled, cliRunTestRequest())
		if !errors.Is(e, ErrBrokerRefused) {
			t.Fatalf("got %v, want ErrBrokerRefused", e)
		}
		if len(resp.Values) != 0 {
			t.Fatalf("cancelled request returned values: %#v", resp.Values)
		}
	})
}

func TestRequestCLIRunEndpointUnavailableBeforeWrite(t *testing.T) {
	t.Run("untrusted configured parent refuses", func(t *testing.T) {
		old := trustedBrokerParent
		trustedBrokerParent = func(string) (string, error) { return "", errors.New("synthetic untrusted parent") }
		t.Cleanup(func() { trustedBrokerParent = old })
		t.Setenv("LOCKLARK_BROWSER_SOCKET", "")
		resp, e := RequestCLIRun(context.Background(), cliRunTestRequest())
		if !errors.Is(e, ErrBrokerRefused) {
			t.Fatalf("got %v, want ErrBrokerRefused for an untrusted endpoint parent", e)
		}
		if errors.Is(e, ErrBrokerUnavailable) {
			t.Fatal("untrusted endpoint parent reported fallback-safe unavailable")
		}
		if len(resp.Values) != 0 {
			t.Fatalf("unavailable endpoint returned values: %#v", resp.Values)
		}
	})
	t.Run("missing socket", func(t *testing.T) {
		brokerTestSocket(t)
		resp, e := RequestCLIRun(context.Background(), cliRunTestRequest())
		if !errors.Is(e, ErrBrokerUnavailable) {
			t.Fatalf("got %v, want ErrBrokerUnavailable", e)
		}
		if len(resp.Values) != 0 {
			t.Fatalf("missing socket returned values: %#v", resp.Values)
		}
	})
}

// startCLIRunIPC serves one framed cli-run exchange on a real private unix
// socket. A respond that writes nothing drops the response after the full
// request was consumed, modelling a completed effect whose reply was lost.
func startCLIRunIPC(t *testing.T, respond func(net.Conn, CLIRunBrokerRequest)) {
	t.Helper()
	sock := brokerTestSocket(t)
	ln, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(sock, 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		raw, e := readFrame(conn, MaxInput)
		if e != nil {
			return
		}
		var hello BrokerHello
		e = json.Unmarshal(raw, &hello)
		clear(raw)
		if e != nil || hello.V != 1 || hello.Mode != "cli-run" {
			return
		}
		raw, e = readFrame(conn, MaxInput)
		if e != nil {
			return
		}
		var req CLIRunBrokerRequest
		e = json.Unmarshal(raw, &req)
		clear(raw)
		if e != nil {
			return
		}
		respond(conn, req)
	}()
}

func cliRunRespondBody(body string) func(net.Conn, CLIRunBrokerRequest) {
	return func(conn net.Conn, _ CLIRunBrokerRequest) {
		_ = writeFrame(conn, []byte(body))
	}
}

func cliRunRespondOversize(conn net.Conn, _ CLIRunBrokerRequest) {
	var header [4]byte
	binary.NativeEndian.PutUint32(header[:], uint32(MaxOutput)+1)
	_, _ = conn.Write(header[:])
}

func TestRequestCLIRunBrokerSentinelOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		handle func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error)
		want   error
		value  string
	}{
		{
			name: "approved exact slots",
			handle: func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
				return CLIRunBrokerResponse{V: 1, Values: map[string]string{"PASSWORD": "synthetic-secret"}}, nil
			},
			value: "synthetic-secret",
		},
		{
			name: "explicit refusal",
			handle: func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
				return CLIRunBrokerResponse{}, errors.New("refused")
			},
			want: ErrBrokerRefused,
		},
		{
			name: "legitimate unavailable",
			handle: func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
				return CLIRunBrokerResponse{}, ErrBrokerUnavailable
			},
			want: ErrBrokerUnavailable,
		},
		{
			name: "unknown after possible effect",
			handle: func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
				return CLIRunBrokerResponse{}, ErrBrokerUnknown
			},
			want: ErrBrokerUnknown,
		},
		{
			name: "opaque error never echoed",
			handle: func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
				return CLIRunBrokerResponse{}, errors.New("hunter2 peer detail")
			},
			want: ErrBrokerRefused,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			endpoint := brokerTestSocket(t)
			broker := NewBroker(BrokerCallbacks{HandleCLIRun: tc.handle})
			if e := broker.Start(endpoint); e != nil {
				t.Fatal(e)
			}
			defer broker.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, e := RequestCLIRun(ctx, cliRunTestRequest())
			if tc.want != nil {
				if !errors.Is(e, tc.want) {
					t.Fatalf("got %v, want %v", e, tc.want)
				}
				if strings.Contains(e.Error(), "hunter2") || strings.Contains(e.Error(), "synthetic-secret") {
					t.Fatalf("peer detail echoed: %v", e)
				}
				if len(resp.Values) != 0 {
					t.Fatalf("error outcome returned values: %#v", resp.Values)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if len(resp.Values) != 1 || resp.Values["PASSWORD"] != tc.value {
				t.Fatalf("success payload: %#v", resp.Values)
			}
		})
	}
}

func TestRequestCLIRunSlotContract(t *testing.T) {
	oversize := strings.Repeat("a", cliRunMaxValueBytes+1)
	cases := []struct {
		name  string
		body  string
		want  error
		value string
	}{
		{name: "exact slot", body: `{"v":1,"values":{"PASSWORD":"synthetic-secret"}}`, value: "synthetic-secret"},
		{name: "exact empty value", body: `{"v":1,"values":{"PASSWORD":""}}`},
		{name: "missing slot", body: `{"v":1,"values":{}}`, want: ErrBrokerUnknown},
		{name: "extra slot", body: `{"v":1,"values":{"PASSWORD":"synthetic-secret","EXTRA":"synthetic-extra"}}`, want: ErrBrokerUnknown},
		{name: "wrong slot", body: `{"v":1,"values":{"OTHER":"synthetic-secret"}}`, want: ErrBrokerUnknown},
		{name: "oversize value", body: `{"v":1,"values":{"PASSWORD":"` + oversize + `"}}`, want: ErrBrokerUnknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			startCLIRunIPC(t, cliRunRespondBody(tc.body))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, e := RequestCLIRun(ctx, cliRunTestRequest())
			if tc.want != nil {
				if !errors.Is(e, tc.want) {
					t.Fatalf("got %v, want %v", e, tc.want)
				}
				if len(resp.Values) != 0 {
					t.Fatalf("nonconforming success returned values: %#v", resp.Values)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if len(resp.Values) != 1 || resp.Values["PASSWORD"] != tc.value {
				t.Fatalf("success payload: %#v", resp.Values)
			}
		})
	}
}

func TestRequestCLIRunMalformedResponseUnknown(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "wrong version", body: `{"v":2,"error":"refused"}`},
		{name: "unknown field", body: `{"v":1,"error":"refused","detail":"hunter2"}`},
		{name: "error body", body: `{"v":1,"error":"hunter2 from peer"}`},
		{name: "trailing json", body: `{"v":1,"values":{"PASSWORD":"synthetic-secret"}} {"v":1}`},
		{name: "null body", body: `null`},
		{name: "not json", body: `not-json`},
		{name: "array body", body: `[1,2,3]`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			startCLIRunIPC(t, cliRunRespondBody(tc.body))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, e := RequestCLIRun(ctx, cliRunTestRequest())
			if !errors.Is(e, ErrBrokerUnknown) {
				t.Fatalf("got %v, want ErrBrokerUnknown", e)
			}
			if errors.Is(e, ErrBrokerUnavailable) || errors.Is(e, ErrBrokerRefused) {
				t.Fatalf("malformed response reported a fallback-safe sentinel: %v", e)
			}
			if strings.Contains(e.Error(), "hunter2") || strings.Contains(e.Error(), "synthetic-secret") {
				t.Fatalf("peer detail echoed: %v", e)
			}
			if len(resp.Values) != 0 {
				t.Fatalf("malformed response returned values: %#v", resp.Values)
			}
		})
	}
	t.Run("oversize frame", func(t *testing.T) {
		startCLIRunIPC(t, cliRunRespondOversize)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, e := RequestCLIRun(ctx, cliRunTestRequest())
		if !errors.Is(e, ErrBrokerUnknown) {
			t.Fatalf("got %v, want ErrBrokerUnknown", e)
		}
		if len(resp.Values) != 0 {
			t.Fatalf("oversize response returned values: %#v", resp.Values)
		}
	})
}

func TestRequestCLIRunLostResponseAfterEffectUnknown(t *testing.T) {
	received := make(chan CLIRunBrokerRequest, 1)
	startCLIRunIPC(t, func(_ net.Conn, req CLIRunBrokerRequest) {
		received <- req
		// Drop the response and close after the request was fully consumed.
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, e := RequestCLIRun(ctx, cliRunTestRequest())
	if !errors.Is(e, ErrBrokerUnknown) {
		t.Fatalf("got %v, want ErrBrokerUnknown", e)
	}
	if errors.Is(e, ErrBrokerUnavailable) {
		t.Fatal("lost response after request submission reported fallback-safe unavailable")
	}
	if len(resp.Values) != 0 {
		t.Fatalf("lost response returned values: %#v", resp.Values)
	}
	select {
	case req := <-received:
		if req.VaultPath != cliRunTestRequest().VaultPath || len(req.Targets) != 1 || req.Targets[0].Slot != "PASSWORD" {
			t.Fatalf("server did not consume the full request: %#v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("server never consumed the request")
	}
}

func TestRequestCLIRunContextCancelAfterSubmitUnknown(t *testing.T) {
	submitted := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	startCLIRunIPC(t, func(_ net.Conn, _ CLIRunBrokerRequest) {
		close(submitted)
		<-release
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-submitted
		cancel()
	}()
	start := time.Now()
	resp, e := RequestCLIRun(ctx, cliRunTestRequest())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancelled request hung for %v", elapsed)
	}
	select {
	case <-submitted:
	default:
		t.Fatal("server did not receive the request before cancellation")
	}
	if !errors.Is(e, ErrBrokerUnknown) {
		t.Fatalf("got %v, want ErrBrokerUnknown for a cancelled submitted request", e)
	}
	if errors.Is(e, ErrBrokerRefused) {
		t.Fatal("cancellation after submission reported a pre-disclosure refusal")
	}
	if len(resp.Values) != 0 {
		t.Fatalf("cancelled request returned values: %#v", resp.Values)
	}
}

func TestRequestCLIRunContextDeadlineAfterSubmitUnknown(t *testing.T) {
	submitted := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	startCLIRunIPC(t, func(_ net.Conn, _ CLIRunBrokerRequest) {
		close(submitted)
		<-release
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	resp, e := RequestCLIRun(ctx, cliRunTestRequest())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline request hung for %v", elapsed)
	}
	select {
	case <-submitted:
	default:
		t.Fatal("server did not receive the request before the deadline")
	}
	if !errors.Is(e, ErrBrokerUnknown) {
		t.Fatalf("got %v, want ErrBrokerUnknown for a submitted request that timed out", e)
	}
	if errors.Is(e, ErrBrokerRefused) {
		t.Fatal("deadline after submission reported a pre-disclosure refusal")
	}
	if len(resp.Values) != 0 {
		t.Fatalf("deadline request returned values: %#v", resp.Values)
	}
}
