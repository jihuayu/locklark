//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func cliRunV2Session(t *testing.T) (*personal.Session, []CLIRunV2Target) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v2.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	if _, e = s.AddLogin("V2 login", "v2-user", "v2-pass"); e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatalf("fixture rows: %v", e)
	}
	return s, []CLIRunV2Target{
		{Slot: "username", ID: rows[0].ID, Revision: rows[0].Revision, Field: "username"},
		{Slot: "password", ID: rows[0].ID, Revision: rows[0].Revision, Field: "password"},
	}
}

func cliRunV2Params(t *testing.T, s *personal.Session, targets []CLIRunV2Target) CLIRunV2Params {
	t.Helper()
	return CLIRunV2Params{
		VaultPath: s.VaultPath(), Root: filepath.Join(t.TempDir(), "client-root"),
		ProfileID: "docker", Program: filepath.Join(t.TempDir(), "never-started"),
		Args: []string{"run", "--rm", "alpine"}, Directory: t.TempDir(), TimeoutSeconds: 15,
		HelperPath:  []string{t.TempDir()},
		Passthrough: map[string]string{"DOCKER_HOST": "tcp://127.0.0.1:2375"},
		Targets:     targets,
	}
}

func cliRunV2GrantCallback(s *personal.Session, calls *atomic.Int32) func(context.Context, CLIRunV2Scope) (*NativeCLIRunV2, error) {
	return func(ctx context.Context, scope CLIRunV2Scope) (*NativeCLIRunV2, error) {
		if calls != nil {
			calls.Add(1)
		}
		grant, e := s.PrepareRunBundleGrant(ctx, scope.Targets, scope.Request, scope.Root)
		if e != nil {
			return nil, e
		}
		return &NativeCLIRunV2{Session: s, Grant: grant}, nil
	}
}

func TestCLIRunV2RoundTripOverUnixSocket(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, &calls),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()

	result, e := RequestCLIRunV2(context.Background(), cliRunV2Params(t, s, targets))
	if e != nil {
		t.Fatalf("round trip: %v", e)
	}
	if string(result.Values["username"]) != "v2-user" || string(result.Values["password"]) != "v2-pass" {
		t.Fatal("round trip returned unexpected values")
	}
	if !validCLIRunV2WireReceipt(result.Receipt) || result.ScopeDigest == "" || calls.Load() != 1 {
		t.Fatalf("round trip receipt/scope/callback: %+v calls=%d", result.Receipt, calls.Load())
	}
	clear(result.Values)
}

func TestCLIRunV2LockedSessionRefusedWithoutCallback(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, &calls),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	s.Lock()
	if _, e := RequestCLIRunV2(context.Background(), cliRunV2Params(t, s, targets)); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("locked session: %v", e)
	}
	if calls.Load() != 0 {
		t.Fatal("callback ran for a locked session")
	}
}

// TestCLIRunV2LockAfterClaimSuppressesFrame proves that a lock requested after
// the one-use grant was claimed but before the disclosure frame is built still
// refuses: the session lock flag is re-read with one atomic load immediately
// before construction and immediately before the single write.
func TestCLIRunV2LockAfterClaimSuppressesFrame(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	broker := NewBroker(BrokerCallbacks{
		CurrentSession: func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: func(ctx context.Context, scope CLIRunV2Scope) (*NativeCLIRunV2, error) {
			grant, e := s.PrepareRunBundleGrant(ctx, scope.Targets, scope.Request, scope.Root)
			if e != nil {
				return nil, e
			}
			return &NativeCLIRunV2{Session: s, Grant: grant, StillValid: func() error {
				// The grant is already claimed (used) when StillValid runs, so this
				// models a lock that wins after the claim and before any frame byte.
				s.RequestLock()
				return nil
			}}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()

	if _, e := RequestCLIRunV2(context.Background(), cliRunV2Params(t, s, targets)); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("post-claim lock delivered a frame: %v", e)
	}
	if !s.RunBundleDeliveryRevoked() {
		t.Fatal("the session did not record the requested lock")
	}
}

func TestCLIRunV2LocalForgedProfileAndSlotMismatchRefused(t *testing.T) {
	s, targets := cliRunV2Session(t)
	params := cliRunV2Params(t, s, targets)
	params.ProfileID = "not-a-builtin-profile"
	if _, e := RequestCLIRunV2(context.Background(), params); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("forged profile: %v", e)
	}
	params = cliRunV2Params(t, s, targets)
	params.Targets[0].Field = "notes"
	if _, e := RequestCLIRunV2(context.Background(), params); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("slot mismatch: %v", e)
	}
}

func cliRunV2Dial(t *testing.T, endpoint string) net.Conn {
	t.Helper()
	conn, e := net.Dial("unix", endpoint)
	if e != nil {
		t.Fatal(e)
	}
	return conn
}

func cliRunV2ReadChallenge(t *testing.T, conn net.Conn) CLIRunV2Challenge {
	t.Helper()
	raw, e := readFrame(conn, 4096)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	ch, e := decodeCLIRunV2Challenge(raw)
	if e != nil {
		t.Fatal(e)
	}
	return ch
}

func cliRunV2RequestBytes(t *testing.T, params CLIRunV2Params, ch CLIRunV2Challenge) []byte {
	t.Helper()
	raw, e := json.Marshal(buildCLIRunV2Request(params, ch.Nonce, ch.Epoch))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestCLIRunV2ChallengeReplayRefused(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, nil),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	params := cliRunV2Params(t, s, targets)

	conn := cliRunV2Dial(t, endpoint)
	defer conn.Close()
	if e := writeFrame(conn, []byte(`{"v":2,"mode":"cli-run"}`)); e != nil {
		t.Fatal(e)
	}
	first := cliRunV2ReadChallenge(t, conn)
	stale := cliRunV2RequestBytes(t, params, first)
	if e := writeFrame(conn, stale); e != nil {
		t.Fatal(e)
	}
	raw, e := readFrame(conn, MaxOutput)
	if e != nil {
		t.Fatal(e)
	}
	var reply CLIRunV2Reply
	if json.Unmarshal(raw, &reply) != nil || reply.Error != "" {
		t.Fatalf("first exchange refused: %s", raw)
	}
	clear(raw)

	replay := cliRunV2Dial(t, endpoint)
	defer replay.Close()
	if e := writeFrame(replay, []byte(`{"v":2,"mode":"cli-run"}`)); e != nil {
		t.Fatal(e)
	}
	second := cliRunV2ReadChallenge(t, replay)
	if second.Nonce == first.Nonce {
		t.Fatal("per-connection challenge was reused")
	}
	stale = bytes.Clone(stale)
	if e := writeFrame(replay, stale); e != nil {
		t.Fatal(e)
	}
	clear(stale)
	raw, e = readFrame(replay, MaxOutput)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if json.Unmarshal(raw, &reply) != nil || reply.Error != "refused" {
		t.Fatalf("replayed request accepted: %s", raw)
	}
}

func TestCLIRunV2ContextDisconnectCancelsApproval(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	entered := make(chan struct{})
	broker := NewBroker(BrokerCallbacks{
		CurrentSession: func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: func(ctx context.Context, scope CLIRunV2Scope) (*NativeCLIRunV2, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, e := RequestCLIRunV2(ctx, cliRunV2Params(t, s, targets))
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("approval callback never entered")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, ErrBrokerUnknown) {
			t.Fatalf("disconnect outcome: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client blocked after cancellation")
	}
}

func startCLIRunV2FakeServer(t *testing.T, respond func(net.Conn, CLIRunV2Challenge)) string {
	t.Helper()
	endpoint := brokerTestSocket(t)
	listener, e := net.Listen("unix", endpoint)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(endpoint, 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		raw, e := readFrame(conn, 4096)
		if e != nil {
			return
		}
		clear(raw)
		ch := CLIRunV2Challenge{V: cliRunV2Version, Nonce: strings.Repeat("ab", cliRunV2NonceBytes), Epoch: 7}
		out, _ := json.Marshal(ch)
		if writeFrame(conn, out) != nil {
			return
		}
		reqRaw, e := readFrame(conn, MaxInput)
		if e != nil {
			return
		}
		clear(reqRaw)
		respond(conn, ch)
	}()
	return endpoint
}

func TestCLIRunV2ClientRejectsWrongScopeAndPartialReply(t *testing.T) {
	s, targets := cliRunV2Session(t)
	params := cliRunV2Params(t, s, targets)

	wrong := startCLIRunV2FakeServer(t, func(conn net.Conn, ch CLIRunV2Challenge) {
		receipt := CLIRunV2Receipt{Session: strings.Repeat("a", 32), Intent: strings.Repeat("b", 64), TargetDigest: strings.Repeat("c", 64)}
		reply, _ := json.Marshal(CLIRunV2Reply{V: cliRunV2Version, Nonce: ch.Nonce, Epoch: ch.Epoch, ScopeDigest: strings.Repeat("d", 64), Receipt: &receipt, Values: map[string][]byte{"username": []byte("x"), "password": []byte("y")}})
		_ = writeFrame(conn, reply)
	})
	if _, e := RequestCLIRunV2(context.Background(), params); !errors.Is(e, ErrBrokerUnknown) {
		t.Fatalf("wrong scope digest: %v", e)
	}
	_ = wrong

	partial := startCLIRunV2FakeServer(t, func(conn net.Conn, ch CLIRunV2Challenge) {
		_, _ = conn.Write([]byte{0, 0})
	})
	if _, e := RequestCLIRunV2(context.Background(), params); !errors.Is(e, ErrBrokerUnknown) {
		t.Fatalf("partial reply: %v", e)
	}
	_ = partial
}

func TestCLIRunV2StrictJSONRefusedOnServer(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, &calls),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	params := cliRunV2Params(t, s, targets)

	for _, bad := range []func([]byte) []byte{
		func(raw []byte) []byte { return bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":2,"unknown":1`), 1) },
		func(raw []byte) []byte { return bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":2,"v":2`), 1) },
	} {
		conn := cliRunV2Dial(t, endpoint)
		if e := writeFrame(conn, []byte(`{"v":2,"mode":"cli-run"}`)); e != nil {
			t.Fatal(e)
		}
		ch := cliRunV2ReadChallenge(t, conn)
		raw := bad(cliRunV2RequestBytes(t, params, ch))
		if e := writeFrame(conn, raw); e != nil {
			t.Fatal(e)
		}
		clear(raw)
		out, e := readFrame(conn, MaxOutput)
		if e != nil {
			t.Fatal(e)
		}
		var reply CLIRunV2Reply
		if json.Unmarshal(out, &reply) != nil || reply.Error != "refused" {
			t.Fatalf("malformed request accepted: %s", out)
		}
		clear(out)
		conn.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("malformed request reached the approval callback")
	}
}

func TestCLIRunV2V1PathDisabledWhenV2Shipped(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var legacy atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, nil),
		HandleCLIRun: func(context.Context, Peer, CLIRunBrokerRequest) (CLIRunBrokerResponse, error) {
			legacy.Add(1)
			return CLIRunBrokerResponse{V: 1}, nil
		},
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	row := personal.CLIBrokerTarget{Slot: "LOGIN_PASSWORD", ID: targets[0].ID, Revision: targets[0].Revision, Field: "password"}
	req := CLIRunBrokerRequest{V: 1, VaultPath: s.VaultPath(), Targets: []personal.CLIBrokerTarget{row}}
	if _, e := RequestCLIRun(context.Background(), req); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("v1 path after v2 shipped: %v", e)
	}
	if legacy.Load() != 0 {
		t.Fatal("legacy per-field handler ran after v2 shipped")
	}
}

func cliRunV2NeedZeroed(t *testing.T, backings [][]byte) {
	t.Helper()
	if len(backings) == 0 {
		t.Fatal("no value backing arrays captured")
	}
	for _, value := range backings {
		for _, b := range value {
			if b != 0 {
				t.Fatal("decoded credential bytes were not wiped")
			}
		}
	}
}

func cliRunV2RunBundleIntents(t *testing.T, s *personal.Session) int {
	t.Helper()
	events, e := personal.Audit(s.VaultPath(), "fixture", bytes.Repeat([]byte{7}, 16))
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, event := range events {
		if event.Action == "item.run.bundle" && event.Result == "intent" {
			count++
		}
	}
	return count
}

func TestCLIRunV2TextGateRejectsBidiFormat(t *testing.T) {
	for _, bad := range []string{"safe\u202Eevil", "a\u2066b", "x\u200Fy", "z\u2069"} {
		if validCLIRunV2PublicText(bad, 4096) {
			t.Fatalf("format-control text accepted: %q", bad)
		}
	}
	if !validCLIRunV2PublicText("项目/路径", 4096) {
		t.Fatal("normal Chinese text rejected")
	}
	dockerSpec, ok := lookupCLIRunV2Profile("docker")
	if !ok {
		t.Fatal("docker builtin missing")
	}
	base := CLIRunV2Request{
		V: cliRunV2Version, Nonce: strings.Repeat("a", cliRunV2NonceHexLen),
		VaultPath: "/vault.ll", Root: "/root", ProfileID: "docker",
		SpecID: dockerSpec.ID, SpecDigest: cliRunV2SpecDigest(dockerSpec),
		Program: "/bin/true", Directory: "/tmp", TimeoutSeconds: 15,
		Targets: []CLIRunV2Target{{Slot: "username", ID: strings.Repeat("1", 32), Revision: strings.Repeat("2", 64), Field: "username"}},
	}
	if !validCLIRunV2Wire(base) {
		t.Fatal("baseline wire request rejected")
	}
	mutations := map[string]func(*CLIRunV2Request){
		"program":     func(r *CLIRunV2Request) { r.Program = "/bin/\u202Eevil" },
		"directory":   func(r *CLIRunV2Request) { r.Directory = "/tmp/\u2066x" },
		"arg":         func(r *CLIRunV2Request) { r.Args = []string{"--x\u202E"} },
		"passthrough": func(r *CLIRunV2Request) { r.Passthrough = map[string]string{"DOCKER_HOST": "tcp://\u202Ehost"} },
	}
	for name, mutate := range mutations {
		req := base
		mutate(&req)
		if validCLIRunV2Wire(req) {
			t.Fatalf("wire accepted format control in %s", name)
		}
	}
}

func TestCLIRunV2VerifyWipesOnFailurePaths(t *testing.T) {
	request := CLIRunV2Request{
		V: cliRunV2Version, Nonce: strings.Repeat("a", 32), Epoch: 9,
		Targets: []CLIRunV2Target{
			{Slot: "username", ID: strings.Repeat("1", 32), Revision: strings.Repeat("2", 64), Field: "username"},
			{Slot: "password", ID: strings.Repeat("1", 32), Revision: strings.Repeat("2", 64), Field: "password"},
		},
	}
	digest := strings.Repeat("e", 64)
	receipt := &CLIRunV2Receipt{Session: strings.Repeat("a", 32), Intent: strings.Repeat("b", 64), TargetDigest: strings.Repeat("c", 64)}
	mk := func() (CLIRunV2Reply, [][]byte) {
		u, p := []byte("user"), []byte("pass")
		return CLIRunV2Reply{V: cliRunV2Version, Nonce: request.Nonce, Epoch: request.Epoch, ScopeDigest: digest, Receipt: receipt, Values: map[string][]byte{"username": u, "password": p}}, [][]byte{u, p}
	}
	cases := map[string]struct {
		mutate func(*CLIRunV2Reply)
		ctx    context.Context
		want   error
	}{
		"scope mismatch":    {mutate: func(r *CLIRunV2Reply) { r.ScopeDigest = "other" }, ctx: context.Background(), want: ErrBrokerUnknown},
		"nonce mismatch":    {mutate: func(r *CLIRunV2Reply) { r.Nonce = strings.Repeat("b", 32) }, ctx: context.Background(), want: ErrBrokerUnknown},
		"error with values": {mutate: func(r *CLIRunV2Reply) { r.Error = "refused" }, ctx: context.Background(), want: ErrBrokerUnknown},
		"canceled ctx":      {mutate: func(*CLIRunV2Reply) {}, ctx: func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }(), want: ErrBrokerUnknown},
	}
	for name, tc := range cases {
		reply, backings := mk()
		tc.mutate(&reply)
		result, e := verifyCLIRunV2Reply(tc.ctx, request, digest, reply)
		if !errors.Is(e, tc.want) {
			t.Fatalf("%s: %v", name, e)
		}
		if result.Values != nil {
			t.Fatalf("%s: failure returned values", name)
		}
		cliRunV2NeedZeroed(t, backings)
	}

	reply, backings := mk()
	reply.Error = "refused"
	reply.Values = nil
	if _, e := verifyCLIRunV2Reply(context.Background(), request, digest, reply); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("clean refusal: %v", e)
	}
	_ = backings

	reply, backings = mk()
	result, e := verifyCLIRunV2Reply(context.Background(), request, digest, reply)
	if e != nil || !bytes.Equal(result.Values["username"], []byte("user")) || !bytes.Equal(result.Values["password"], []byte("pass")) {
		t.Fatalf("success transfer: %v", e)
	}
	if result.Values["username"][0] == 0 {
		t.Fatal("success unexpectedly wiped transferred values")
	}
	clear(backings[0])
	clear(backings[1])
}

func TestCLIRunV2MismatchedVaultRefusedWithoutCallback(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, &calls),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	params := cliRunV2Params(t, s, targets)
	params.VaultPath = filepath.Join(t.TempDir(), "other-session.ll")
	if _, e := RequestCLIRunV2(context.Background(), params); !errors.Is(e, ErrBrokerRefused) {
		t.Fatalf("mismatched vault: %v", e)
	}
	if calls.Load() != 0 {
		t.Fatal("mismatched vault reached the approval callback")
	}
	if got := cliRunV2RunBundleIntents(t, s); got != 0 {
		t.Fatalf("mismatched vault committed %d run bundle intents", got)
	}
}
