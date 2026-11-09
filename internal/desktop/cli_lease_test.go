package desktop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

// leaseClock is an explicit test clock for the cache and approval deadlines.
// Nothing here is terminal evidence: the OS-proof tests live with the
// browserhost attestation and are deliberately not claimed here.
type leaseClock struct {
	t time.Time
}

func (c *leaseClock) now() time.Time          { return c.t }
func (c *leaseClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type leaseSeamState struct {
	identity      browserhost.CLITerminalIdentity
	programSHA256 string
	failAttest    bool
	failProgram   bool
}

func newLeaseSeamState() *leaseSeamState {
	return &leaseSeamState{
		identity: browserhost.CLITerminalIdentity{
			UID:                uint32(os.Geteuid()),
			TTYDevice:          34816,
			SessionID:          4242,
			SessionLeaderStart: 900,
			PeerStart:          1000,
			ExecutablePath:     "/usr/local/bin/locklark",
			ExecutableSHA256:   strings.Repeat("ab", 32),
		},
		programSHA256: strings.Repeat("cd", 32),
	}
}

func (s *leaseSeamState) reset() {
	*s = *newLeaseSeamState()
}

func sameCLITerminalIdentity(a, b browserhost.CLITerminalIdentity) bool {
	return a == b
}

// installLeaseSeams replaces the kernel attestation and program hash with
// explicit public values. This is wiring/cache evidence only, never a claim
// that a real terminal was attested.
func installLeaseSeams(t *testing.T, state *leaseSeamState) {
	t.Helper()
	oldAttest, oldVerify, oldHash := cliLeaseAttest, cliLeaseVerify, cliLeaseHashProgram
	cliLeaseAttest = func(browserhost.Peer) (browserhost.CLITerminalIdentity, error) {
		if state.failAttest {
			return browserhost.CLITerminalIdentity{}, errors.New("attestation refused")
		}
		return state.identity, nil
	}
	cliLeaseVerify = func(_ browserhost.Peer, expected browserhost.CLITerminalIdentity) bool {
		if state.failAttest {
			return false
		}
		return sameCLITerminalIdentity(state.identity, expected)
	}
	cliLeaseHashProgram = func(string) (string, error) {
		if state.failProgram {
			return "", errors.New("program proof refused")
		}
		return state.programSHA256, nil
	}
	t.Cleanup(func() {
		cliLeaseAttest, cliLeaseVerify, cliLeaseHashProgram = oldAttest, oldVerify, oldHash
	})
}

func newLeaseFixture(t *testing.T, state *leaseSeamState) (*cliV2Fixture, *leaseClock) {
	t.Helper()
	installLeaseSeams(t, state)
	f := newCLIRunV2Fixture(t)
	clock := &leaseClock{t: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	f.app.cliLeases.now = clock.now
	return f, clock
}

func (f *cliV2Fixture) scopeWithEpoch(t *testing.T, epoch uint64) browserhost.CLIRunV2Scope {
	t.Helper()
	scope := f.scope(t)
	scope.Epoch = epoch
	return scope
}

func leaseEntryExpiry(t *testing.T, cache *cliLeaseCache) time.Time {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) != 1 {
		t.Fatalf("lease entries = %d, want 1", len(cache.entries))
	}
	return cache.entries[0].expires
}

func startCLIRunV2(t *testing.T, f *cliV2Fixture, scope browserhost.CLIRunV2Scope) (*cliV2Call, *cliRunV2Pending) {
	t.Helper()
	call := callPrepareCLIRunV2(f.app, context.Background(), scope)
	pending := waitCLIRunV2Pending(t, f.app)
	return call, pending
}

func consumeLeaseGrant(t *testing.T, session *personal.Session, grant *personal.NativeRunBundleGrant) (string, personal.RunBundleGrantReceipt) {
	t.Helper()
	var value string
	var receipt personal.RunBundleGrantReceipt
	if err := session.ConsumeRunBundleGrant(context.Background(), grant, func(values map[string][]byte, r personal.RunBundleGrantReceipt) error {
		value = string(values["token"])
		receipt = r
		return nil
	}); err != nil {
		t.Fatalf("consume grant: %v", err)
	}
	return value, receipt
}

// establishLease drives one explicit terminal-lease approval and consumes its
// first fresh intent.
func establishLease(t *testing.T, f *cliV2Fixture, scope browserhost.CLIRunV2Scope) personal.RunBundleGrantReceipt {
	t.Helper()
	call, pending := startCLIRunV2(t, f, scope)
	if !pending.proofOK {
		t.Fatal("terminal proof was not captured")
	}
	if pending.leaseIntent {
		t.Fatal("a published approval already carried a lease intent")
	}
	f.app.approveCLIRunV2Lease(pending.id)
	native, err := call.wait(t)
	if err != nil || native == nil || native.Grant == nil || native.Revalidate == nil || native.StillValid == nil {
		t.Fatalf("lease approval: native=%#v err=%v", native, err)
	}
	if native.Session != f.session {
		t.Fatal("lease approval returned a foreign session")
	}
	value, receipt := consumeLeaseGrant(t, f.session, native.Grant)
	if value != "v2-password" || !cliV2TestHex(receipt.Intent, 32) {
		t.Fatalf("lease value/receipt: %q %#v", value, receipt)
	}
	return receipt
}

// TestCLILeaseDialogRevalidatesExactPeerStart proves a dialog approval is
// still the exact per-connection process after the owner decision. A recycled
// or replaced peer (including its birth ticks) refuses instead of granting.
func TestCLILeaseDialogRevalidatesExactPeerStart(t *testing.T) {
	for _, lease := range []bool{false, true} {
		state := newLeaseSeamState()
		f, _ := newLeaseFixture(t, state)
		call, pending := startCLIRunV2(t, f, f.scope(t))
		if !pending.proofOK {
			t.Fatal("terminal proof was not captured")
		}
		// The peer process changes between publication and the owner decision.
		state.identity.PeerStart++
		if lease {
			f.app.approveCLIRunV2Lease(pending.id)
		} else {
			f.app.decideCLIRunV2(pending.id, true)
		}
		if native, err := call.wait(t); err == nil || native != nil {
			t.Fatalf("changed peer approved lease=%v: native=%#v err=%v", lease, native, err)
		}
		if f.app.cliLeases.len() != 0 {
			t.Fatalf("changed peer created a lease (lease=%v)", lease)
		}
	}
}

// TestCLILeaseReuseCommitsFreshIntents proves that two runs under one lease are
// two distinct item.run.bundle intents, that the second run skipped the dialog,
// and that use never moved the absolute deadline.
func TestCLILeaseReuseCommitsFreshIntents(t *testing.T) {
	state := newLeaseSeamState()
	f, clock := newLeaseFixture(t, state)
	base := f.scope(t)
	first := establishLease(t, f, base)
	if f.app.cliLeases.len() != 1 {
		t.Fatalf("cache size after lease approval = %d", f.app.cliLeases.len())
	}
	expiry := leaseEntryExpiry(t, f.app.cliLeases)

	// A new CLI process on the same terminal has a different PeerStart, and the
	// next run legitimately has a fresh nonce, temporary root and scope digest.
	state.identity.PeerStart += 500
	clock.advance(30 * time.Second)
	secondScope := cloneCLIRunV2Scope(base)
	secondScope.Root = filepath.Join(t.TempDir(), "second-root")
	secondScope.Nonce = strings.Repeat("77", 16)
	secondScope.ScopeDigest = strings.Repeat("66", 32)
	native, err := f.app.PrepareCLIRunV2(context.Background(), secondScope)
	if err != nil || native == nil || native.Grant == nil {
		t.Fatalf("lease reuse: native=%#v err=%v", native, err)
	}
	if currentCLIRunV2Pending(f.app) != nil {
		t.Fatal("lease reuse published a new approval dialog")
	}
	value, second := consumeLeaseGrant(t, f.session, native.Grant)
	if value != "v2-password" {
		t.Fatalf("second value = %q", value)
	}
	if first.Intent == second.Intent {
		t.Fatal("lease reuse reused the first intent instead of committing a new one")
	}
	if got := leaseEntryExpiry(t, f.app.cliLeases); !got.Equal(expiry) {
		t.Fatalf("lease deadline moved on use: %v -> %v", expiry, got)
	}
	if f.app.cliLeases.len() != 1 {
		t.Fatalf("lease reuse duplicated the cache entry: %d", f.app.cliLeases.len())
	}
}

// TestCLILeaseOneShotNeverCaches proves the default primary button remains a
// pure one-shot approval.
func TestCLILeaseOneShotNeverCaches(t *testing.T) {
	state := newLeaseSeamState()
	f, _ := newLeaseFixture(t, state)

	call, pending := startCLIRunV2(t, f, f.scope(t))
	f.app.decideCLIRunV2(pending.id, true)
	native, err := call.wait(t)
	if err != nil || native == nil || native.Grant == nil {
		t.Fatalf("one-shot approval: native=%#v err=%v", native, err)
	}
	consumeLeaseGrant(t, f.session, native.Grant)
	if f.app.cliLeases.len() != 0 {
		t.Fatal("one-shot approval cached a lease")
	}

	// The next identical request must still require an explicit decision.
	call2, pending2 := startCLIRunV2(t, f, f.scope(t))
	if pending2.leaseIntent {
		t.Fatal("second pending carried a lease intent")
	}
	f.app.decideCLIRunV2(pending2.id, false)
	if _, err := call2.wait(t); err == nil {
		t.Fatal("refused second request was approved")
	}
}

// TestCLILeaseProofUnavailableKeepsOneShot proves unsupported/no-TTY style
// attestation never fabricates a lease identity but leaves one-shot usable.
func TestCLILeaseProofUnavailableKeepsOneShot(t *testing.T) {
	state := newLeaseSeamState()
	state.failAttest = true
	f, _ := newLeaseFixture(t, state)

	call, pending := startCLIRunV2(t, f, f.scope(t))
	if pending.proofOK {
		t.Fatal("refused attestation reported a valid proof")
	}
	f.app.decideCLIRunV2(pending.id, true)
	native, err := call.wait(t)
	if err != nil || native == nil || native.Grant == nil {
		t.Fatalf("one-shot without proof: native=%#v err=%v", native, err)
	}
	consumeLeaseGrant(t, f.session, native.Grant)
	if f.app.cliLeases.len() != 0 {
		t.Fatal("a refused attestation created a lease")
	}

	// A forged lease click cannot turn a proof-less request into a lease.
	call2, pending2 := startCLIRunV2(t, f, f.scope(t))
	f.app.approveCLIRunV2Lease(pending2.id)
	if native, err := call2.wait(t); err == nil || native != nil {
		t.Fatalf("proof-less lease click returned native=%#v err=%v", native, err)
	}
	if f.app.cliLeases.len() != 0 {
		t.Fatal("a proof-less lease click cached an entry")
	}
}

// TestCLILeaseExactScopeAndTerminalDoNotReuse verifies that every meaningful
// scope or terminal change falls back to an explicit dialog instead of reusing
// the lease. Spec-only binding is covered in the pure key test below.
func TestCLILeaseExactScopeAndTerminalDoNotReuse(t *testing.T) {
	state := newLeaseSeamState()
	f, _ := newLeaseFixture(t, state)
	base := f.scope(t)
	establishLease(t, f, base)

	cases := []struct {
		name   string
		mutate func(scope *browserhost.CLIRunV2Scope, state *leaseSeamState)
	}{
		{"args-prefix", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.Args = s.Request.Args[:1]
		}},
		{"args-value", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.Args = append([]string(nil), s.Request.Args...)
			s.Request.Args[1] = "--other-model"
		}},
		{"program", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.Program = "/usr/local/bin/other"
		}},
		{"cwd", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.Directory = "/srv/other"
		}},
		{"timeout", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.TimeoutSeconds++
		}},
		{"helper-path", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.HelperPath = []string{"/usr/bin"}
		}},
		{"passthrough", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.Passthrough["NO_COLOR"] = "0"
		}},
		{"revision", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Targets[0].Revision = strings.Repeat("ef", 32)
		}},
		{"target-id", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Targets[0].ID = strings.Repeat("12", 16)
		}},
		{"spec-digest", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.SpecDigest = strings.Repeat("34", 32)
		}},
		{"spec-image", func(s *browserhost.CLIRunV2Scope, _ *leaseSeamState) {
			s.Request.Spec.Env = map[string]string{"LEASE_TEST": "literal:1"}
		}},
		{"tty", func(_ *browserhost.CLIRunV2Scope, st *leaseSeamState) {
			st.identity.TTYDevice++
		}},
		{"session-leader-birth", func(_ *browserhost.CLIRunV2Scope, st *leaseSeamState) {
			st.identity.SessionLeaderStart++
		}},
		{"session-id", func(_ *browserhost.CLIRunV2Scope, st *leaseSeamState) {
			st.identity.SessionID++
		}},
		{"cli-path", func(_ *browserhost.CLIRunV2Scope, st *leaseSeamState) {
			st.identity.ExecutablePath = "/opt/other/locklark"
		}},
		{"cli-hash", func(_ *browserhost.CLIRunV2Scope, st *leaseSeamState) {
			st.identity.ExecutableSHA256 = strings.Repeat("56", 32)
		}},
		{"program-hash", func(_ *browserhost.CLIRunV2Scope, st *leaseSeamState) {
			st.programSHA256 = strings.Repeat("78", 32)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state.reset()
			scope := cloneCLIRunV2Scope(base)
			tc.mutate(&scope, state)
			// A changed scope may no longer be a valid trusted request; either a
			// hard refusal or a fresh dialog is acceptable. It must never reuse.
			call := callPrepareCLIRunV2(f.app, context.Background(), scope)
			deadline := time.Now().Add(5 * time.Second)
			for currentCLIRunV2Pending(f.app) == nil && time.Now().Before(deadline) {
				select {
				case <-call.done:
					if call.err == nil || call.native != nil {
						t.Fatalf("%s reused the lease: native=%#v err=%v", tc.name, call.native, call.err)
					}
					return
				default:
				}
				time.Sleep(time.Millisecond)
			}
			pending := currentCLIRunV2Pending(f.app)
			if pending == nil {
				t.Fatalf("%s neither refused nor published a dialog", tc.name)
			}
			f.app.decideCLIRunV2(pending.id, false)
			if _, err := call.wait(t); err == nil {
				t.Fatalf("%s dialog was approved after a mutation", tc.name)
			}
		})
	}
	if f.app.cliLeases.len() != 1 {
		t.Fatalf("mismatched requests changed the lease cache: %d", f.app.cliLeases.len())
	}
}

// TestCLILeaseTTLIsAbsoluteAndNeverExtended pins the five-minute cap: reuse at
// any time before the original deadline works, later it does not, and the
// deadline itself never moves.
func TestCLILeaseTTLIsAbsoluteAndNeverExtended(t *testing.T) {
	state := newLeaseSeamState()
	f, clock := newLeaseFixture(t, state)
	base := f.scope(t)
	establishLease(t, f, base)
	expiry := leaseEntryExpiry(t, f.app.cliLeases)
	if !expiry.Equal(clock.t.Add(cliLeaseTTL)) {
		t.Fatalf("lease expiry = %v, want %v", expiry, clock.t.Add(cliLeaseTTL))
	}

	for _, d := range []time.Duration{time.Minute, 3 * time.Minute, 59 * time.Second} {
		clock.advance(d)
		state.identity.PeerStart++
		next := cloneCLIRunV2Scope(base)
		next.Root = filepath.Join(t.TempDir(), "reuse-root")
		next.Nonce = strings.Repeat("55", 16)
		native, err := f.app.PrepareCLIRunV2(context.Background(), next)
		if err != nil || native == nil || native.Grant == nil {
			t.Fatalf("reuse at %v: native=%#v err=%v", clock.t, native, err)
		}
		consumeLeaseGrant(t, f.session, native.Grant)
		if got := leaseEntryExpiry(t, f.app.cliLeases); !got.Equal(expiry) {
			t.Fatalf("deadline extended on use: %v -> %v", expiry, got)
		}
	}

	clock.advance(2 * time.Second)
	fresh := cloneCLIRunV2Scope(base)
	fresh.Root = filepath.Join(t.TempDir(), "expired-root")
	call, pending := startCLIRunV2(t, f, fresh)
	if pending.proofOK != true {
		t.Fatal("expired lease request lost its proof")
	}
	f.app.decideCLIRunV2(pending.id, false)
	if _, err := call.wait(t); err == nil {
		t.Fatal("expired lease still approved without a dialog")
	}
	f.app.decideCLIRunV2(pending.id, false)
}

// TestCLILeaseLockAndEpochRevoke proves lock and session epoch changes purge the
// cache and refuse any reuse.
func TestCLILeaseLockAndEpochRevoke(t *testing.T) {
	state := newLeaseSeamState()
	f, _ := newLeaseFixture(t, state)
	establishLease(t, f, f.scope(t))

	// An epoch change through the unlock path purges the cache.
	oldEpoch := f.epoch()
	f.app.generation++
	f.app.notifyBrowserBrokerUnlocked()
	if f.epoch() == oldEpoch {
		t.Fatal("epoch did not change")
	}
	if f.app.cliLeases.len() != 0 {
		t.Fatal("epoch change did not purge the lease cache")
	}
	// A scope pinned to the old epoch is refused outright.
	if native, err := f.app.PrepareCLIRunV2(context.Background(), f.scopeWithEpoch(t, oldEpoch)); err == nil || native != nil {
		t.Fatalf("stale epoch reused a lease: native=%#v err=%v", native, err)
	}

	// Establish another lease and lock the vault.
	establishLease(t, f, f.scope(t))
	if f.app.cliLeases.len() != 1 {
		t.Fatal("second lease was not stored")
	}
	f.app.Lock()
	if f.app.cliLeases.len() != 0 {
		t.Fatal("lock did not purge the lease cache")
	}
	if native, err := f.app.PrepareCLIRunV2(context.Background(), f.scopeWithEpoch(t, f.epoch())); err == nil || native != nil {
		t.Fatalf("locked broker prepared native=%#v err=%v", native, err)
	}
}

// TestCLILeaseLateDecisionCannotLeaseNewerRequest proves that a late lease click
// for a retired request can never decide or lease the newer request.
func TestCLILeaseLateDecisionCannotLeaseNewerRequest(t *testing.T) {
	state := newLeaseSeamState()
	f, _ := newLeaseFixture(t, state)

	ctxA, cancelA := context.WithCancel(context.Background())
	callA := callPrepareCLIRunV2(f.app, ctxA, f.scope(t))
	pendingA := waitCLIRunV2Pending(t, f.app)
	cancelA()
	if native, err := callA.wait(t); err == nil || native != nil {
		t.Fatalf("cancelled request A native=%#v err=%v", native, err)
	}

	callB, pendingB := startCLIRunV2(t, f, f.scope(t))
	f.app.approveCLIRunV2Lease(pendingA.id)
	if pendingDecided(f.app, pendingB) {
		t.Fatal("late lease click decided the newer request")
	}
	if f.app.cliLeases.len() != 0 {
		t.Fatal("late lease click created a lease")
	}
	f.app.decideCLIRunV2(pendingB.id, true)
	nativeB, err := callB.wait(t)
	if err != nil || nativeB == nil || nativeB.Grant == nil {
		t.Fatalf("newer one-shot approval: native=%#v err=%v", nativeB, err)
	}
	consumeLeaseGrant(t, f.session, nativeB.Grant)
	if f.app.cliLeases.len() != 0 {
		t.Fatal("late lease click promoted the newer one-shot approval")
	}

	// The next request still needs an explicit dialog.
	callC, pendingC := startCLIRunV2(t, f, f.scope(t))
	f.app.decideCLIRunV2(pendingC.id, false)
	if _, err := callC.wait(t); err == nil {
		t.Fatal("a late lease click left a reusable lease")
	}
}

// TestCLILeaseCacheBoundsAndPrunesBeforeCapacity pins the cache size and the
// prune-before-capacity order with explicit public keys only.
func TestCLILeaseCacheBoundsAndPrunesBeforeCapacity(t *testing.T) {
	state := newLeaseSeamState()
	f, clock := newLeaseFixture(t, state)
	cache := f.app.cliLeases
	base := f.scope(t)
	terminal := cliLeaseTerminal{
		UID: state.identity.UID, TTYDevice: state.identity.TTYDevice,
		SessionID: state.identity.SessionID, SessionLeaderStart: state.identity.SessionLeaderStart,
		ExecutablePath: state.identity.ExecutablePath, ExecutableSHA256: state.identity.ExecutableSHA256,
	}
	for i := 0; i < cliLeaseMax; i++ {
		scope := cloneCLIRunV2Scope(base)
		scope.Request.Program = "/usr/bin/program-" + intString(i)
		key, ok := cliLeaseKeyFor(scope, f.session, terminal, state.programSHA256)
		if !ok {
			t.Fatalf("key %d refused", i)
		}
		if err := cache.add(key, clock.t.Add(cliLeaseTTL)); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if cache.len() != cliLeaseMax {
		t.Fatalf("cache size = %d, want %d", cache.len(), cliLeaseMax)
	}
	extra := cloneCLIRunV2Scope(base)
	extra.Request.Program = "/usr/bin/program-extra"
	extraKey, ok := cliLeaseKeyFor(extra, f.session, terminal, state.programSHA256)
	if !ok {
		t.Fatal("extra key refused")
	}
	if err := cache.add(extraKey, clock.t.Add(cliLeaseTTL)); !errors.Is(err, errCLILeaseFull) {
		t.Fatalf("full cache add error = %v", err)
	}
	if cache.len() != cliLeaseMax {
		t.Fatalf("full cache changed size: %d", cache.len())
	}

	// Expiry is pruned before capacity, so a later lease is accepted.
	clock.advance(cliLeaseTTL + time.Second)
	if cache.len() != 0 {
		t.Fatalf("expired cache was not pruned: %d", cache.len())
	}
	if err := cache.add(extraKey, clock.t.Add(cliLeaseTTL)); err != nil {
		t.Fatalf("add after prune: %v", err)
	}
	if cache.len() != 1 {
		t.Fatalf("cache size after prune = %d", cache.len())
	}
}

// TestCLILeaseKeyBindsExactPublicScopeAndExcludesRunScopedNoise pins the key
// itself: every command/spec/target/terminal field must change it, while the
// per-connection nonce, temporary root and scope digest must not.
func TestCLILeaseKeyBindsExactPublicScopeAndExcludesRunScopedNoise(t *testing.T) {
	state := newLeaseSeamState()
	f, clock := newLeaseFixture(t, state)
	base := f.scope(t)
	terminal := cliLeaseTerminal{
		UID: state.identity.UID, TTYDevice: state.identity.TTYDevice,
		SessionID: state.identity.SessionID, SessionLeaderStart: state.identity.SessionLeaderStart,
		ExecutablePath: state.identity.ExecutablePath, ExecutableSHA256: state.identity.ExecutableSHA256,
	}
	key, ok := cliLeaseKeyFor(base, f.session, terminal, state.programSHA256)
	if !ok {
		t.Fatal("base key refused")
	}
	if err := f.app.cliLeases.add(key, clock.t.Add(cliLeaseTTL)); err != nil {
		t.Fatal(err)
	}

	// Run-scoped noise is excluded.
	for name, mutate := range map[string]func(*browserhost.CLIRunV2Scope){
		"nonce": func(s *browserhost.CLIRunV2Scope) { s.Nonce = strings.Repeat("99", 16) },
		"root":  func(s *browserhost.CLIRunV2Scope) { s.Root = "/tmp/another-client-root" },
		"scope-digest": func(s *browserhost.CLIRunV2Scope) {
			s.ScopeDigest = strings.Repeat("88", 32)
		},
	} {
		scope := cloneCLIRunV2Scope(base)
		mutate(&scope)
		other, ok := cliLeaseKeyFor(scope, f.session, terminal, state.programSHA256)
		if !ok || !key.equal(other) {
			t.Fatalf("%s changed the lease key", name)
		}
		if _, ok := f.app.cliLeases.match(other); !ok {
			t.Fatalf("%s did not match the stored lease", name)
		}
	}

	// Every genuine scope field changes the key and cannot match.
	for name, mutate := range map[string]func(*browserhost.CLIRunV2Scope){
		"args": func(s *browserhost.CLIRunV2Scope) {
			s.Request.Args = append([]string(nil), s.Request.Args...)
			s.Request.Args[0] = "other"
		},
		"cwd":         func(s *browserhost.CLIRunV2Scope) { s.Request.Directory = "/srv/other" },
		"timeout":     func(s *browserhost.CLIRunV2Scope) { s.Request.TimeoutSeconds++ },
		"helper":      func(s *browserhost.CLIRunV2Scope) { s.Request.HelperPath = []string{"/bin"} },
		"passthrough": func(s *browserhost.CLIRunV2Scope) { s.Request.Passthrough["NO_COLOR"] = "0" },
		"spec-id": func(s *browserhost.CLIRunV2Scope) {
			s.SpecID = "other-spec"
			s.Request.Spec.ID = "other-spec"
			s.Spec.ID = "other-spec"
		},
		"spec-digest":     func(s *browserhost.CLIRunV2Scope) { s.SpecDigest = strings.Repeat("11", 32) },
		"spec-image":      func(s *browserhost.CLIRunV2Scope) { s.Request.Spec.Dirs = []string{"other"} },
		"target-revision": func(s *browserhost.CLIRunV2Scope) { s.Targets[0].Revision = strings.Repeat("22", 32) },
		"target-index": func(s *browserhost.CLIRunV2Scope) {
			s.Targets[0].ID = strings.Repeat("33", 16)
		},
	} {
		scope := cloneCLIRunV2Scope(base)
		mutate(&scope)
		other, ok := cliLeaseKeyFor(scope, f.session, terminal, state.programSHA256)
		if !ok {
			t.Fatalf("%s key refused", name)
		}
		if key.equal(other) {
			t.Fatalf("%s did not change the lease key", name)
		}
		if _, ok := f.app.cliLeases.match(other); ok {
			t.Fatalf("%s matched the stored lease", name)
		}
	}

	// Terminal and program image bindings.
	for name, mutate := range map[string]func(*cliLeaseTerminal){
		"uid":          func(t *cliLeaseTerminal) { t.UID++ },
		"tty":          func(t *cliLeaseTerminal) { t.TTYDevice++ },
		"session":      func(t *cliLeaseTerminal) { t.SessionID++ },
		"leader-birth": func(t *cliLeaseTerminal) { t.SessionLeaderStart++ },
		"cli-path":     func(t *cliLeaseTerminal) { t.ExecutablePath = "/opt/other" },
		"cli-hash":     func(t *cliLeaseTerminal) { t.ExecutableSHA256 = strings.Repeat("44", 32) },
	} {
		otherTerminal := terminal
		mutate(&otherTerminal)
		other, ok := cliLeaseKeyFor(base, f.session, otherTerminal, state.programSHA256)
		if !ok {
			t.Fatalf("%s terminal key refused", name)
		}
		if key.equal(other) {
			t.Fatalf("%s did not change the lease key", name)
		}
		if _, ok := f.app.cliLeases.match(other); ok {
			t.Fatalf("%s terminal matched the stored lease", name)
		}
	}
	other, ok := cliLeaseKeyFor(base, f.session, terminal, strings.Repeat("55", 32))
	if !ok || key.equal(other) {
		t.Fatal("program image digest did not change the lease key")
	}
}

// TestCLILeaseKeyBindsTokenEnv uses the dynamic-token profile to prove the
// token environment name is part of the exact key.
func TestCLILeaseKeyBindsTokenEnv(t *testing.T) {
	state := newLeaseSeamState()
	f, _ := newLeaseFixture(t, state)
	profile, ok := cliprofile.Lookup("token")
	if !ok {
		t.Fatal("missing token profile")
	}
	spec := profile.Spec()
	row := f.row
	scope := browserhost.CLIRunV2Scope{
		Peer:       browserhost.Peer{User: "UID 1000", PID: 4242, Process: "/usr/local/bin/locklark"},
		VaultPath:  f.session.VaultPath(),
		Root:       "/tmp/client-root",
		ProfileID:  "token",
		SpecID:     spec.ID,
		SpecDigest: strings.Repeat("ab", 32),
		Spec:       spec,
		Request: personal.RunBundleRequest{
			Program: "/usr/bin/env", Args: []string{"run"}, Directory: "/tmp",
			TimeoutSeconds: 30, TokenEnvName: "LEASE_TOKEN", Spec: cliprofile.CloneSpec(spec),
		},
		Targets:     []personal.BundleTarget{{Slot: "token", ID: row.ID, Revision: row.Revision, Field: "password"}},
		ScopeDigest: strings.Repeat("ab", 32),
	}
	terminal := cliLeaseTerminal{
		UID: state.identity.UID, TTYDevice: state.identity.TTYDevice,
		SessionID: state.identity.SessionID, SessionLeaderStart: state.identity.SessionLeaderStart,
		ExecutablePath: state.identity.ExecutablePath, ExecutableSHA256: state.identity.ExecutableSHA256,
	}
	key, ok := cliLeaseKeyFor(scope, f.session, terminal, state.programSHA256)
	if !ok {
		t.Fatal("token-env key refused")
	}
	changed := cloneCLIRunV2Scope(scope)
	changed.Request.TokenEnvName = "OTHER_TOKEN"
	other, ok := cliLeaseKeyFor(changed, f.session, terminal, state.programSHA256)
	if !ok || key.equal(other) {
		t.Fatal("token environment name did not change the lease key")
	}
}

// TestCLILeaseApprovalViewShowsLeaseOnlyWithProof pins the UI contract: the
// five-minute button exists only with real proof, public terminal/SID and the
// exact TTL are escaped text, and all decision buttons stay pinned together.
func TestCLILeaseApprovalViewShowsLeaseOnlyWithProof(t *testing.T) {
	state := newLeaseSeamState()
	f, _ := newLeaseFixture(t, state)
	scope := f.scope(t)
	terminal, ok := stableCLILeaseTerminal(state.identity)
	if !ok {
		t.Fatal("test identity is not well formed")
	}
	pending := &cliRunV2Pending{
		id: "lease-layout", scope: cloneCLIRunV2Scope(scope), decision: make(chan bool, 1),
		proofOK: true, terminal: terminal, attested: state.identity,
		programSHA256: state.programSHA256,
	}
	f.app.brokerMu.Lock()
	f.app.cliV2Pending = pending
	f.app.brokerMu.Unlock()
	t.Cleanup(func() {
		f.app.brokerMu.Lock()
		if f.app.cliV2Pending == pending {
			f.app.cliV2Pending = nil
		}
		f.app.brokerMu.Unlock()
	})

	const width, height = 640, 480
	view := ui.NewTester(f.app.cliV2ApprovalView, width, height)
	if !view.HasText(cliV2ApproveLabel) || !view.HasText(cliV2LeaseLabel) || !view.HasText(cliV2RefuseLabel) {
		t.Fatal("approval view is missing one of the three decisions")
	}
	if !view.HasText("终端/SID: TTY " + uint64String(terminal.TTYDevice) + " · SID " + uintString(terminal.SessionID)) {
		t.Fatal("approval view did not show the public terminal/SID")
	}
	if !view.HasText("终端租约有效期: " + cliLeaseTTLLabel() + "，到期不会续期。") {
		t.Fatal("approval view did not show the exact TTL")
	}
	rects := make(map[string]ui.Rect)
	for _, label := range []string{cliV2ApproveLabel, cliV2LeaseLabel, cliV2RefuseLabel} {
		rect, ok := view.Find(label)
		if !ok {
			t.Fatalf("%s missing", label)
		}
		if rect.X < 0 || rect.Y < 0 || rect.X+rect.W > width || rect.Y+rect.H > height {
			t.Fatalf("%s is outside the window: %#v", label, rect)
		}
		if rect.Y < height/2 {
			t.Fatalf("%s is not pinned below the scroll area: %#v", label, rect)
		}
		rects[label] = rect
	}
	if rects[cliV2ApproveLabel].Y != rects[cliV2LeaseLabel].Y || rects[cliV2LeaseLabel].Y != rects[cliV2RefuseLabel].Y {
		t.Fatal("decision buttons are not on one pinned row")
	}

	if err := view.Click(cliV2LeaseLabel); err != nil {
		t.Fatalf("lease button is not clickable: %v", err)
	}
	select {
	case approved := <-pending.decision:
		if !approved {
			t.Fatal("lease button refused instead of approving")
		}
	case <-time.After(time.Second):
		t.Fatal("lease button did not decide the request")
	}
	f.app.brokerMu.Lock()
	leaseIntent := pending.leaseIntent
	f.app.brokerMu.Unlock()
	if !leaseIntent {
		t.Fatal("lease button did not capture the lease intent")
	}
	// A late one-shot click can never clear the captured lease decision.
	f.app.decideCLIRunV2(pending.id, true)
	select {
	case <-pending.decision:
		t.Fatal("a late click produced a second decision")
	default:
	}

	// Without proof the view keeps the one-shot and refusal buttons only.
	noProof := &cliRunV2Pending{id: "no-proof", scope: cloneCLIRunV2Scope(scope), decision: make(chan bool, 1)}
	f.app.brokerMu.Lock()
	f.app.cliV2Pending = noProof
	f.app.brokerMu.Unlock()
	noProofView := ui.NewTester(f.app.cliV2ApprovalView, width, height)
	if noProofView.HasText(cliV2LeaseLabel) {
		t.Fatal("lease button was offered without terminal proof")
	}
	if !noProofView.HasText(cliV2ApproveLabel) || !noProofView.HasText(cliV2RefuseLabel) {
		t.Fatal("one-shot/refusal buttons disappeared without proof")
	}
}

// TestHashCLIProgramRefusesSymlinksAndNonExecutables is real ordinary-file
// evidence (not terminal evidence): only a bounded, executable, regular file is
// hashed.
func TestHashCLIProgramRefusesSymlinksAndNonExecutables(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "program")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := hashCLIProgram(program)
	if err != nil {
		t.Fatalf("hash regular program: %v", err)
	}
	sum := sha256.Sum256([]byte("#!/bin/sh\nexit 0\n"))
	if first != hex.EncodeToString(sum[:]) {
		t.Fatalf("program hash = %s", first)
	}
	if err := os.WriteFile(program, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := hashCLIProgram(program)
	if err != nil || second == first {
		t.Fatalf("changed program hash: %s %v", second, err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(program, link); err != nil {
		t.Fatal(err)
	}
	if _, err := hashCLIProgram(link); err == nil {
		t.Fatal("symlinked program was hashed")
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hashCLIProgram(plain); err == nil {
		t.Fatal("non-executable program was hashed")
	}
	if _, err := hashCLIProgram(dir); err == nil {
		t.Fatal("directory was hashed as a program")
	}
	if _, err := hashCLIProgram("relative/program"); err == nil {
		t.Fatal("relative program path was hashed")
	}
}
