package personal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

// runBundleGrantLateCancel reports cancellation only on the second Err call, so
// a real prepare can run to a committed intent before the post-commit check.
type runBundleGrantLateCancel struct {
	context.Context
	calls int
}

func (c *runBundleGrantLateCancel) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.Canceled
	}
	return nil
}

func runBundleGrantUnlock(t *testing.T, f *bundleTestFixture, idle time.Duration) *Session {
	t.Helper()
	s, err := UnlockSession(f.path, []byte("fixture"), f.key, idle)
	if err != nil {
		t.Fatalf("unlock session: %v", err)
	}
	t.Cleanup(s.Lock)
	return s
}

func runBundleGrantFixture(t *testing.T) (*bundleTestFixture, *Session) {
	t.Helper()
	f := newBundleTestFixture(t)
	return f, runBundleGrantUnlock(t, f, time.Minute)
}

func runBundleGrantSpec(t *testing.T, profile string) cliprofile.Spec {
	t.Helper()
	p, ok := cliprofile.Lookup(profile)
	if !ok {
		t.Fatalf("built-in profile %q missing", profile)
	}
	return p.Spec()
}

// runBundleGrantRequest never starts its program, so the API is required to
// prepare a grant for a program path that does not exist.
func runBundleGrantRequest(t *testing.T, profile string) RunBundleRequest {
	t.Helper()
	return RunBundleRequest{
		Program:        filepath.Join(t.TempDir(), "never-started-program"),
		Args:           []string{"run", "--rm", "alpine"},
		Directory:      t.TempDir(),
		TimeoutSeconds: 15,
		HelperPath:     []string{t.TempDir()},
		Spec:           runBundleGrantSpec(t, profile),
	}
}

func runBundleGrantDockerRequest(t *testing.T) RunBundleRequest {
	t.Helper()
	request := runBundleGrantRequest(t, "docker")
	request.Passthrough = map[string]string{"DOCKER_HOST": "tcp://127.0.0.1:2375"}
	return request
}

func runBundleGrantTargets(f *bundleTestFixture) []BundleTarget {
	return []BundleTarget{
		{Slot: "username", ID: f.loginID, Revision: f.loginRevision, Field: "username"},
		{Slot: "password", ID: f.loginID, Revision: f.loginRevision, Field: "password"},
	}
}

func runBundleGrantWant() map[string][]byte {
	return map[string][]byte{"username": []byte(bundleTestUsername), "password": []byte(bundleTestPassword)}
}

func runBundleGrantAudit(t *testing.T, f *bundleTestFixture) []Event {
	t.Helper()
	events, err := Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatalf("audit unavailable: %v", err)
	}
	return events
}

// runBundleGrantIntentCount counts only committed intents; a refused set still
// journals the same action with a refusal result.
func runBundleGrantIntentCount(events []Event) int {
	count := 0
	for _, event := range events {
		if event.Action == runBundleAction && event.Result == "intent" {
			count++
		}
	}
	return count
}

func runBundleGrantLastEvent(events []Event) (Event, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == runBundleAction {
			return events[i], true
		}
	}
	return Event{}, false
}

func runBundleGrantLastIntent(t *testing.T, events []Event) Event {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == runBundleAction {
			return events[i]
		}
	}
	t.Fatal("run bundle intent missing")
	return Event{}
}

func runBundleGrantPrepare(t *testing.T, s *Session, targets []BundleTarget, request RunBundleRequest) *NativeRunBundleGrant {
	t.Helper()
	grant, err := s.PrepareRunBundleGrant(context.Background(), targets, request, filepath.Join(t.TempDir(), "client-root"))
	if err != nil {
		t.Fatalf("prepare grant: %v", err)
	}
	if grant == nil || grant.state == nil {
		t.Fatal("prepare returned no grant")
	}
	return grant
}

func runBundleGrantReceiptOf(g *NativeRunBundleGrant) RunBundleGrantReceipt {
	g.state.mu.Lock()
	defer g.state.mu.Unlock()
	return g.state.receipt
}

func runBundleGrantValuesOf(g *NativeRunBundleGrant) map[string][]byte {
	if g == nil || g.state == nil {
		return nil
	}
	g.state.mu.Lock()
	defer g.state.mu.Unlock()
	return g.state.values
}

func runBundleGrantUsedOf(g *NativeRunBundleGrant) bool {
	g.state.mu.Lock()
	defer g.state.mu.Unlock()
	return g.state.used
}

func runBundleGrantExpired(g *NativeRunBundleGrant) {
	g.state.mu.Lock()
	defer g.state.mu.Unlock()
	g.state.until = time.Now().Add(-time.Second)
}

func TestRunBundleGrantCommitsIntentBeforeDelivery(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	request := runBundleGrantDockerRequest(t)
	root := filepath.Join(t.TempDir(), "client-root")
	beforeIntents := runBundleGrantIntentCount(runBundleGrantAudit(t, f))
	idleBefore := s.last

	grant, err := s.PrepareRunBundleGrant(context.Background(), targets, request, root)
	if err != nil || grant == nil {
		t.Fatalf("prepare grant: %v", err)
	}
	if grant.state.owner != s || runBundleGrantUsedOf(grant) {
		t.Fatal("grant is not a fresh grant for this session")
	}
	if !s.last.After(idleBefore) {
		t.Fatal("prepare did not renew session idle time")
	}
	now := time.Now()
	if grant.state.until.After(now.Add(maxRunBundleGrantLifetime)) || !now.Before(grant.state.until) {
		t.Fatalf("grant deadline out of bounds: %v", grant.state.until.Sub(now))
	}
	if grant.state.until.After(s.last.Add(s.idle)) {
		t.Fatal("grant outlives the session idle deadline")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("prepare created server-side temporary state under the client root")
	}
	events := runBundleGrantAudit(t, f)
	if got := runBundleGrantIntentCount(events); got != beforeIntents+1 {
		t.Fatalf("expected exactly one new signed intent, got %d", got-beforeIntents)
	}
	intent := runBundleGrantLastIntent(t, events)
	if intent.Result != "intent" || intent.Item != targets[0].ID || intent.BaseRevision != targets[0].Revision {
		t.Fatalf("intent not bound to the full target set: %+v", intent)
	}
	receipt := runBundleGrantReceiptOf(grant)
	if !idOK(receipt.Session) || !digestOK(receipt.Intent) || !digestOK(receipt.TargetDigest) {
		t.Fatal("receipt carries invalid identifiers")
	}
	if receipt.Intent != intent.hash() || receipt.TargetDigest != intent.Link {
		t.Fatal("receipt does not identify the committed intent")
	}
	if last, ok := runBundleGrantLastEvent(events); !ok || last.Result != "intent" || last.hash() != receipt.Intent {
		t.Fatal("intent is not the last recorded run bundle authorization")
	}

	var borrowed map[string][]byte
	captured := map[string][]byte{}
	called := 0
	err = s.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, got RunBundleGrantReceipt) error {
		called++
		if got != receipt {
			t.Fatal("callback receipt differs from the committed binding")
		}
		want := runBundleGrantWant()
		if len(values) != len(want) {
			t.Fatalf("callback saw %d slots, want %d", len(values), len(want))
		}
		for name, value := range want {
			if !bytes.Equal(values[name], value) {
				t.Fatalf("slot %q has the wrong value", name)
			}
		}
		// The intent transaction must already be closed and durable here.
		delivered := runBundleGrantAudit(t, f)
		if runBundleGrantIntentCount(delivered) != beforeIntents+1 || runBundleGrantLastIntent(t, delivered).hash() != receipt.Intent {
			t.Fatal("intent was not committed before the values were handed out")
		}
		borrowed = values
		for name, value := range values {
			captured[name] = value
		}
		return nil
	})
	if err != nil || called != 1 {
		t.Fatalf("consume failed: %v (called %d)", err, called)
	}
	if borrowed == nil || runBundleGrantValuesOf(grant) != nil {
		t.Fatal("grant still holds slot entries after delivery")
	}
	if len(captured) != 2 {
		t.Fatalf("callback captured %d slots", len(captured))
	}
	for name, value := range captured {
		for _, b := range value {
			if b != 0 {
				t.Fatalf("slot %q was not zeroed after the callback", name)
			}
		}
	}
	if !runBundleGrantUsedOf(grant) {
		t.Fatal("grant stayed usable after delivery")
	}

	rawReceipt, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("receipt marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawReceipt, &fields); err != nil {
		t.Fatalf("receipt decode: %v", err)
	}
	if len(fields) != 3 || fields["Session"] == nil || fields["Intent"] == nil || fields["TargetDigest"] == nil {
		t.Fatalf("receipt claims more than authorization: %s", rawReceipt)
	}
	typ := reflect.TypeOf(receipt)
	if typ.NumField() != 3 || typ.Field(0).Name != "Session" || typ.Field(1).Name != "Intent" || typ.Field(2).Name != "TargetDigest" {
		t.Fatal("receipt shape changed")
	}
	journal, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("journal marshal: %v", err)
	}
	for _, secret := range []string{bundleTestPassword, bundleTestUsername, request.Program, request.Directory, root} {
		if bytes.Contains(rawReceipt, []byte(secret)) {
			t.Fatalf("receipt leaked %q", secret)
		}
	}
	for _, secret := range []string{bundleTestPassword, bundleTestUsername, request.Program, request.Directory, root} {
		if bytes.Contains(journal, []byte(secret)) {
			t.Fatalf("journal leaked %q", secret)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("delivery rendered values onto the server filesystem")
	}
	if entries, err := os.ReadDir(request.Directory); err != nil || len(entries) != 0 {
		t.Fatal("a program appears to have run")
	}
}

func TestRunBundleGrantRefusesAnyStaleTargetWithoutPartialValues(t *testing.T) {
	subtests := []struct {
		name   string
		mutate func(*bundleTestFixture, []BundleTarget) []BundleTarget
		want   error
		result string
	}{
		{"stale-first-target", func(_ *bundleTestFixture, targets []BundleTarget) []BundleTarget {
			targets[0].Revision = strings.Repeat("0", 64)
			return targets
		}, ErrConflict, "conflict"},
		{"stale-last-target", func(_ *bundleTestFixture, targets []BundleTarget) []BundleTarget {
			targets[1].Revision = strings.Repeat("1", 64)
			return targets
		}, ErrConflict, "conflict"},
		{"missing-last-target", func(_ *bundleTestFixture, targets []BundleTarget) []BundleTarget {
			targets[1].ID = strings.Repeat("2", 32)
			return targets
		}, ErrNotFound, "not-found"},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			f, s := runBundleGrantFixture(t)
			targets := subtest.mutate(f, runBundleGrantTargets(f))
			request := runBundleGrantDockerRequest(t)
			before := runBundleGrantIntentCount(runBundleGrantAudit(t, f))
			grant, err := s.PrepareRunBundleGrant(context.Background(), targets, request, filepath.Join(t.TempDir(), "client-root"))
			if err != subtest.want || grant != nil {
				t.Fatalf("bad target set accepted: %v", err)
			}
			journal := runBundleGrantAudit(t, f)
			if got := runBundleGrantIntentCount(journal); got != before {
				t.Fatalf("refused set committed %d intents", got-before)
			}
			if last, ok := runBundleGrantLastEvent(journal); !ok || last.Result != subtest.result {
				t.Fatalf("refusal outcome not journaled canonically: %+v", last)
			}
			raw, err := json.Marshal(journal)
			if err != nil {
				t.Fatalf("journal marshal: %v", err)
			}
			for _, secret := range []string{bundleTestPassword, bundleTestUsername, request.Program} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatalf("journal leaked %q after a refused set", secret)
				}
			}
		})
	}
}

func TestRunBundleGrantPinsTrustedProfile(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	before := runBundleGrantIntentCount(runBundleGrantAudit(t, f))
	forged := func(mutate func(*cliprofile.Spec)) cliprofile.Spec {
		spec := runBundleGrantSpec(t, "docker")
		mutate(&spec)
		return spec
	}
	cases := map[string]cliprofile.Spec{
		"unknown-id": forged(func(spec *cliprofile.Spec) { spec.ID = "docker-config-v2" }),
		"env-policy": forged(func(spec *cliprofile.Spec) { spec.Env["LD_PRELOAD"] = "slot:password" }),
		"file-policy": forged(func(spec *cliprofile.Spec) {
			spec.Files = append(spec.Files, cliprofile.FileSpec{RelPath: "git/config", Format: "empty-v1", Mode: 0600})
		}),
		"arg-policy":   forged(func(spec *cliprofile.Spec) { spec.DenyArgs = nil }),
		"slot-policy":  forged(func(spec *cliprofile.Spec) { spec.Slots[0].Optional = true }),
		"limit-policy": forged(func(spec *cliprofile.Spec) { spec.MaxTimeout = 86400 }),
		"token-env-policy": forged(func(spec *cliprofile.Spec) {
			spec.DynamicTokenEnv = true
		}),
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			request := runBundleGrantDockerRequest(t)
			request.Spec = spec
			if spec.DynamicTokenEnv {
				request.TokenEnvName = "DEPLOY_TOKEN"
			}
			grant, err := s.PrepareRunBundleGrant(context.Background(), targets, request, filepath.Join(t.TempDir(), "client-root"))
			if err != ErrRunTarget || grant != nil {
				t.Fatalf("forged spec accepted: %v", err)
			}
		})
	}
	if got := runBundleGrantIntentCount(runBundleGrantAudit(t, f)); got != before {
		t.Fatalf("forged specs committed %d intents", got-before)
	}

	// A caller-chosen token environment is honoured only under the trusted rule.
	wrongEnv := runBundleGrantDockerRequest(t)
	wrongEnv.TokenEnvName = "GH_TOKEN"
	if grant, err := s.PrepareRunBundleGrant(context.Background(), targets, wrongEnv, filepath.Join(t.TempDir(), "client-root")); err != ErrRunTarget || grant != nil {
		t.Fatalf("token environment accepted for a static profile: %v", err)
	}
	tokenTargets := []BundleTarget{{Slot: "token", ID: f.loginID, Revision: f.loginRevision, Field: "password"}}
	for _, name := range []string{"PATH", ""} {
		tokenRequest := runBundleGrantRequest(t, "token")
		tokenRequest.TokenEnvName = name
		if grant, err := s.PrepareRunBundleGrant(context.Background(), tokenTargets, tokenRequest, filepath.Join(t.TempDir(), "client-root")); err != ErrRunTarget || grant != nil {
			t.Fatalf("token environment %q accepted: %v", name, err)
		}
	}
	tokenRequest := runBundleGrantRequest(t, "token")
	tokenRequest.TokenEnvName = "DEPLOY_TOKEN"
	tokenGrant, err := s.PrepareRunBundleGrant(context.Background(), tokenTargets, tokenRequest, filepath.Join(t.TempDir(), "client-root"))
	if err != nil || tokenGrant == nil {
		t.Fatalf("trusted token environment refused: %v", err)
	}
	delivered := 0
	if err := s.ConsumeRunBundleGrant(context.Background(), tokenGrant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
		delivered++
		if len(values) != 1 || !bytes.Equal(values["token"], []byte(bundleTestPassword)) {
			t.Fatal("token slot value mismatch")
		}
		return nil
	}); err != nil || delivered != 1 {
		t.Fatalf("token grant delivery failed: %v", err)
	}
}

func TestRunBundleGrantValidatesRootTargetsAndRequest(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	root := filepath.Join(t.TempDir(), "client-root")
	mutation := func(mutate func(*RunBundleRequest)) RunBundleRequest {
		request := runBundleGrantDockerRequest(t)
		mutate(&request)
		return request
	}
	wrongField := append([]BundleTarget(nil), targets...)
	wrongField[0].Field = "password"
	cases := []struct {
		name    string
		ctx     context.Context
		targets []BundleTarget
		request RunBundleRequest
		root    string
	}{
		{"nil-context", nil, targets, runBundleGrantDockerRequest(t), root},
		{"relative-root", context.Background(), targets, runBundleGrantDockerRequest(t), "relative/root"},
		{"empty-root", context.Background(), targets, runBundleGrantDockerRequest(t), ""},
		{"no-targets", context.Background(), nil, runBundleGrantDockerRequest(t), root},
		{"duplicate-slot", context.Background(), []BundleTarget{targets[0], targets[0]}, runBundleGrantDockerRequest(t), root},
		{"field-mismatch", context.Background(), wrongField, runBundleGrantDockerRequest(t), root},
		{"relative-program", context.Background(), targets, mutation(func(r *RunBundleRequest) { r.Program = "docker" }), root},
		{"zero-timeout", context.Background(), targets, mutation(func(r *RunBundleRequest) { r.TimeoutSeconds = 0 }), root},
		{"denied-passthrough", context.Background(), targets, mutation(func(r *RunBundleRequest) {
			r.Passthrough = map[string]string{"LD_PRELOAD": "x"}
		}), root},
	}
	before := runBundleGrantIntentCount(runBundleGrantAudit(t, f))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			grant, err := s.PrepareRunBundleGrant(c.ctx, c.targets, c.request, c.root)
			if err != ErrRunTarget || grant != nil {
				t.Fatalf("invalid input accepted: %v", err)
			}
		})
	}
	if got := runBundleGrantIntentCount(runBundleGrantAudit(t, f)); got != before {
		t.Fatalf("invalid inputs committed %d intents", got-before)
	}
}

func TestRunBundleGrantConsumeIsOneUseAndZeroizes(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	request := runBundleGrantDockerRequest(t)
	sentinel := errors.New("native writer failed")
	grant := runBundleGrantPrepare(t, s, targets, request)
	captured := map[string][]byte{}
	called := 0
	err := s.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
		called++
		if len(values) != 2 {
			t.Fatalf("callback saw %d slots", len(values))
		}
		for name, value := range values {
			captured[name] = value
		}
		return sentinel
	})
	if err != sentinel || called != 1 {
		t.Fatalf("callback error not propagated: %v", err)
	}
	if len(captured) != 2 {
		t.Fatalf("callback captured %d slots", len(captured))
	}
	for name, value := range captured {
		for _, b := range value {
			if b != 0 {
				t.Fatalf("slot %q survived a failed delivery", name)
			}
		}
	}
	if runBundleGrantValuesOf(grant) != nil || !runBundleGrantUsedOf(grant) {
		t.Fatal("grant kept entries after a failed delivery")
	}
	called = 0
	if err := s.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrRunBundleGrant || called != 0 {
		t.Fatalf("grant was delivered twice: %v", err)
	}
	if err := s.ConsumeRunBundleGrant(nil, grant, func(map[string][]byte, RunBundleGrantReceipt) error { return nil }); err != ErrRunBundleGrant {
		t.Fatalf("nil context accepted: %v", err)
	}
	if err := s.ConsumeRunBundleGrant(context.Background(), nil, func(map[string][]byte, RunBundleGrantReceipt) error { return nil }); err != ErrRunBundleGrant {
		t.Fatalf("nil grant accepted: %v", err)
	}

	// Clear inside the callback must neither deadlock nor touch borrowed bytes.
	inside := runBundleGrantPrepare(t, s, targets, request)
	err = s.ConsumeRunBundleGrant(context.Background(), inside, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
		inside.Clear()
		inside.Discard()
		if !bytes.Equal(values["password"], []byte(bundleTestPassword)) || !bytes.Equal(values["username"], []byte(bundleTestUsername)) {
			t.Fatal("Clear inside the callback disturbed borrowed values")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("clear during delivery: %v", err)
	}
}

// TestRunBundleGrantLockBetweenActiveAndClaimRefusesWithoutCallback pauses in
// the exact window after the session activity check and before the shared claim
// gate. A lock requested there must win, refuse, zero the bytes and never invoke
// the delivery callback.
func TestRunBundleGrantLockBetweenActiveAndClaimRefusesWithoutCallback(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	if s.RunBundleDeliveryRevoked() {
		t.Fatal("fresh session already reports a revoked delivery")
	}
	reached := make(chan struct{})
	resume := make(chan struct{})
	oldSeam := runBundleBeforeClaim
	runBundleBeforeClaim = func() {
		close(reached)
		<-resume
	}
	t.Cleanup(func() { runBundleBeforeClaim = oldSeam })

	called := 0
	done := make(chan error, 1)
	go func() {
		done <- s.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
			called++
			return nil
		})
	}()
	<-reached
	revokedBefore := s.RunBundleDeliveryRevoked()
	s.RequestLock()
	close(resume)
	err := <-done
	if revokedBefore {
		t.Fatal("session was already revoked before RequestLock")
	}
	if err != ErrSessionLocked {
		t.Fatalf("late lock consume error = %v, want ErrSessionLocked", err)
	}
	if called != 0 {
		t.Fatal("delivery callback ran after a lock won the claim gate")
	}
	if !s.RunBundleDeliveryRevoked() {
		t.Fatal("RunBundleDeliveryRevoked did not observe the requested lock")
	}
	if runBundleGrantValuesOf(grant) != nil || !runBundleGrantUsedOf(grant) {
		t.Fatal("late-locked grant kept disclosure bytes")
	}
}

// TestRunBundleGrantRequestLockDoesNotWaitForBorrowedWriter proves the claim
// is the disclosure boundary: once the callback owns the borrowed bytes,
// RequestLock returns without waiting for the writer, and delivery still
// completes. The final broker checks still observe the late lock.
func TestRunBundleGrantRequestLockDoesNotWaitForBorrowedWriter(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	entered := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	done := make(chan error, 1)
	go func() {
		done <- s.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	returned := make(chan struct{})
	go func() {
		s.RequestLock()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("RequestLock waited for the borrowed writer")
	}
	if !s.RunBundleDeliveryRevoked() {
		t.Fatal("late RequestLock was not observable during delivery")
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Fatalf("claimed delivery did not complete: %v", err)
	}
}

func TestRunBundleGrantConcurrentConsumeDeliversOnce(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	delivered, refused := 0, 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
				mu.Lock()
				delivered++
				mu.Unlock()
				if len(values) != 2 {
					t.Errorf("callback saw %d slots", len(values))
				}
				return nil
			})
			switch err {
			case nil:
			case ErrRunBundleGrant:
				mu.Lock()
				refused++
				mu.Unlock()
			default:
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wg.Wait()
	if delivered != 1 || refused != workers-1 {
		t.Fatalf("delivered %d times, refused %d times", delivered, refused)
	}
}

func TestRunBundleGrantRefusesCancelledExpiredAndLocked(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	request := runBundleGrantDockerRequest(t)
	root := filepath.Join(t.TempDir(), "client-root")
	before := runBundleGrantIntentCount(runBundleGrantAudit(t, f))

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if grant, err := s.PrepareRunBundleGrant(cancelled, targets, request, root); err != ErrRunCancelled || grant != nil {
		t.Fatalf("cancelled prepare: %v", err)
	}
	if got := runBundleGrantIntentCount(runBundleGrantAudit(t, f)); got != before {
		t.Fatal("a cancelled prepare committed an intent")
	}

	late := &runBundleGrantLateCancel{Context: context.Background()}
	if grant, err := s.PrepareRunBundleGrant(late, targets, request, root); err != ErrRunCancelled || grant != nil {
		t.Fatalf("post-commit cancellation returned values: %v", err)
	}
	if late.calls < 2 {
		t.Fatal("post-commit cancellation path was not exercised")
	}
	if got := runBundleGrantIntentCount(runBundleGrantAudit(t, f)); got != before+1 {
		t.Fatalf("post-commit cancellation should record exactly one intent, got %d", got-before)
	}

	expired := runBundleGrantPrepare(t, s, targets, request)
	runBundleGrantExpired(expired)
	called := 0
	if err := s.ConsumeRunBundleGrant(context.Background(), expired, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrRunBundleGrant || called != 0 {
		t.Fatalf("expired grant delivered: %v", err)
	}
	if runBundleGrantValuesOf(expired) != nil || !runBundleGrantUsedOf(expired) {
		t.Fatal("expired grant kept disclosure bytes")
	}

	locked := runBundleGrantPrepare(t, s, targets, request)
	s.Lock()
	called = 0
	if err := s.ConsumeRunBundleGrant(context.Background(), locked, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrSessionLocked || called != 0 {
		t.Fatalf("locked session delivered: %v", err)
	}
	if runBundleGrantValuesOf(locked) != nil {
		t.Fatal("locked session kept grant bytes")
	}
	if grant, err := s.PrepareRunBundleGrant(context.Background(), targets, request, root); err != ErrSessionLocked || grant != nil {
		t.Fatalf("locked prepare: %v", err)
	}
}

func TestRunBundleGrantDeadlineIsCappedBySessionIdle(t *testing.T) {
	f := newBundleTestFixture(t)
	s := runBundleGrantUnlock(t, f, 2*time.Second)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	remaining := grant.state.until.Sub(time.Now())
	if remaining <= 0 || remaining > 2*time.Second {
		t.Fatalf("grant deadline %v is not capped by the session idle window", remaining)
	}
	if grant.state.until.After(s.last.Add(s.idle)) {
		t.Fatal("grant outlives the session idle deadline")
	}
	if grant.state.until.After(time.Now().Add(maxRunBundleGrantLifetime)) {
		t.Fatal("grant outlives the maximum grant lifetime")
	}
}

func TestRunBundleGrantRejectsForeignSession(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	other := runBundleGrantUnlock(t, f, time.Minute)
	called := 0
	if err := other.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrRunBundleGrant || called != 0 {
		t.Fatalf("foreign session consumed a grant: %v", err)
	}
	if runBundleGrantValuesOf(grant) == nil {
		t.Fatal("a foreign attempt destroyed the owner's grant")
	}
	if err := s.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != nil || called != 1 {
		t.Fatalf("owner could not consume after a foreign refusal: %v", err)
	}
}

func TestRunBundleGrantPrivateValuesCannotLeak(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	request := runBundleGrantDockerRequest(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), request)
	secrets := []string{bundleTestPassword, bundleTestUsername, request.Program, request.Directory}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, value := range []any{grant, *grant} {
			text := fmt.Sprintf(format, value)
			if text != "[native run bundle grant]" {
				t.Fatalf("%s printed %q", format, text)
			}
			for _, secret := range secrets {
				if strings.Contains(text, secret) {
					t.Fatalf("%s leaked %q", format, secret)
				}
			}
		}
	}
	for _, value := range []any{grant, *grant} {
		raw, err := json.Marshal(value)
		if err == nil {
			t.Fatalf("grant serialized as %s", raw)
		}
		if !errors.Is(err, ErrRunBundleGrant) {
			t.Fatalf("unexpected JSON refusal: %v", err)
		}
	}
	captured := map[string][]byte{}
	for name, value := range runBundleGrantValuesOf(grant) {
		captured[name] = value
	}
	grant.Discard()
	if runBundleGrantValuesOf(grant) != nil || !runBundleGrantUsedOf(grant) {
		t.Fatal("discard kept grant state")
	}
	if len(captured) != 2 {
		t.Fatalf("discard captured %d slots", len(captured))
	}
	for name, value := range captured {
		for _, b := range value {
			if b != 0 {
				t.Fatalf("slot %q was not zeroed by discard", name)
			}
		}
	}
	grant.Clear()
	grant.Discard()
	var absent *NativeRunBundleGrant
	absent.Clear()
	absent.Discard()
}

func TestRunBundleGrantCallbackMapMutationStillZeroizes(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	targets := runBundleGrantTargets(f)
	request := runBundleGrantDockerRequest(t)
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			grant := runBundleGrantPrepare(t, s, targets, request)
			original := runBundleGrantValuesOf(grant)
			if len(original) != 2 {
				t.Fatalf("prepared %d slots", len(original))
			}
			backing := map[string][]byte{}
			for name, value := range original {
				backing[name] = value
			}
			consume := func() (err error) {
				if mode == "panic" {
					defer func() { recover() }()
				}
				return s.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
					if len(values) != 2 {
						t.Fatalf("callback saw %d slots", len(values))
					}
					delete(values, "username")
					values["password"] = []byte("replacement")
					if len(values) != 1 || string(values["password"]) != "replacement" {
						t.Fatal("callback did not receive an independent map copy")
					}
					if mode == "panic" {
						panic("native writer panicked")
					}
					return errors.New("native writer failed")
				})
			}
			if err := consume(); mode == "error" && err == nil {
				t.Fatal("callback error was lost")
			}
			for name, value := range backing {
				for _, b := range value {
					if b != 0 {
						t.Fatalf("original %q backing array survived callback mutation", name)
					}
				}
			}
			if runBundleGrantValuesOf(grant) != nil || !runBundleGrantUsedOf(grant) {
				t.Fatal("grant state survived the callback")
			}
		})
	}
}

func TestRunBundleGrantLockedForeignSessionCannotClear(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	original := runBundleGrantValuesOf(grant)
	if len(original) != 2 {
		t.Fatalf("prepared %d slots", len(original))
	}
	other := runBundleGrantUnlock(t, f, time.Minute)
	other.Lock()
	called := 0
	if err := other.ConsumeRunBundleGrant(context.Background(), grant, func(map[string][]byte, RunBundleGrantReceipt) error {
		called++
		return nil
	}); err != ErrRunBundleGrant || called != 0 {
		t.Fatalf("a locked foreign session consumed or refused wrongly: %v", err)
	}
	if runBundleGrantValuesOf(grant) == nil {
		t.Fatal("a locked foreign session cleared the owner's grant")
	}
	for name, value := range original {
		if len(value) == 0 {
			t.Fatalf("slot %q lost its bytes to a locked foreign session", name)
		}
	}
	delivered := 0
	if err := s.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
		delivered++
		if !bytes.Equal(values["username"], []byte(bundleTestUsername)) || !bytes.Equal(values["password"], []byte(bundleTestPassword)) {
			t.Fatal("owner delivery changed after a locked foreign attempt")
		}
		return nil
	}); err != nil || delivered != 1 {
		t.Fatalf("owner delivery after a locked foreign attempt: %v (called %d)", err, delivered)
	}
}

func TestRunBundleGrantConcurrentClearDuringDelivery(t *testing.T) {
	f, s := runBundleGrantFixture(t)
	grant := runBundleGrantPrepare(t, s, runBundleGrantTargets(f), runBundleGrantDockerRequest(t))
	original := runBundleGrantValuesOf(grant)
	if len(original) != 2 {
		t.Fatalf("prepared %d slots", len(original))
	}
	started := make(chan struct{})
	var clears sync.WaitGroup
	for i := 0; i < 4; i++ {
		clears.Add(1)
		go func() {
			defer clears.Done()
			<-started
			grant.Clear()
			grant.Discard()
		}()
	}
	done := make(chan error, 1)
	go func() {
		done <- s.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, _ RunBundleGrantReceipt) error {
			close(started)
			time.Sleep(20 * time.Millisecond)
			if !bytes.Equal(values["password"], []byte(bundleTestPassword)) {
				return errors.New("borrowed bytes were cleared mid-delivery")
			}
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("delivery during concurrent clear: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock between Clear and Consume")
	}
	clears.Wait()
	for name, value := range original {
		for _, b := range value {
			if b != 0 {
				t.Fatalf("slot %q was not zeroed after concurrent clear", name)
			}
		}
	}
	if runBundleGrantValuesOf(grant) != nil {
		t.Fatal("grant kept entries after concurrent clear")
	}
}
