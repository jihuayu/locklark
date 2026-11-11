package teamsync

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
)

// preflight runs one decoded request through the private per-call budget seam,
// exactly as ServeHTTP does, but without the network or write-grant layers.
func preflight(t *testing.T, s *server, r *http.Request, budget int) response {
	t.Helper()
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var q request
	if decode(raw, &q) != nil {
		t.Fatal("undecodable preflight request")
	}
	out, e := s.handle(r, q, budget)
	if e != nil {
		t.Fatal("handler refused to decide a response", e)
	}
	return out
}

// assertSignedEnvelope checks the envelope is canonical, signed by the trusted
// sequencer, bound to this request and within the budget the caller set.
func assertSignedEnvelope(t *testing.T, f *syncFixture, r *http.Request, out response, budget int) {
	t.Helper()
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	var q request
	if decode(raw, &q) != nil {
		t.Fatal("undecodable request")
	}
	encoded := encode(out)
	if budget > 0 && len(encoded) > budget {
		t.Fatalf("response is %d bytes, over its %d byte budget", len(encoded), budget)
	}
	if len(encoded) > MaxResponseBytes {
		t.Fatalf("response is %d bytes, over MaxResponseBytes", len(encoded))
	}
	if out.Protocol != protocol || out.Nonce != q.Proof.Nonce || out.RequestDigest != digest("request", q) || len(out.Signature) != ed25519.SignatureSize || !ed25519.Verify(f.seq.Public().(ed25519.PublicKey), out.signingBytes(), out.Signature) {
		t.Fatal("response envelope is not the signed answer to this request")
	}
	var back response
	if decode(encoded, &back) != nil {
		t.Fatal("response envelope does not decode canonically")
	}
	if out.History != nil && out.HistoryDigest != digest("history", out.History) || out.History == nil && out.HistoryDigest != "" {
		t.Fatal("history digest does not cover the carried history")
	}
	if out.Receipt != nil && out.ReceiptDigest != digest("receipt", out.Receipt) || out.Receipt == nil && out.ReceiptDigest != "" {
		t.Fatal("receipt digest does not cover the carried receipt")
	}
}

func assertCapacity(t *testing.T, out response) {
	t.Helper()
	if out.Status != "capacity" || out.History != nil || out.Receipt != nil || out.Head != (directory.Checkpoint{}) || out.HistoryDigest != "" || out.ReceiptDigest != "" {
		t.Fatalf("status = %q, want a bare signed capacity refusal", out.Status)
	}
}

func serverAnchor(t *testing.T, f *syncFixture) directory.Checkpoint {
	t.Helper()
	cp, e := f.anchors.Load()
	if e != nil {
		t.Fatal("cannot load persistent server anchor", e)
	}
	return cp
}

func databaseBytes(t *testing.T, f *syncFixture) []byte {
	t.Helper()
	raw, e := os.ReadFile(f.path)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// budgetBetween picks a local response limit above the signed capacity refusal
// of f and below its full answer of fullLen bytes.
func budgetBetween(t *testing.T, f *syncFixture, fullLen int) int {
	t.Helper()
	capacityLen := len(encode(response{Status: "capacity", Protocol: protocol, RequestDigest: strings.Repeat("0", 64), Nonce: strings.Repeat("0", 64), Signature: make([]byte, ed25519.SignatureSize)}))
	budget := (capacityLen + fullLen) / 2
	if budget <= capacityLen || budget >= fullLen {
		t.Fatalf("capacity refusal (%d bytes) and full response (%d bytes) leave no separating budget", capacityLen, fullLen)
	}
	return budget
}

func ownedPublication(t *testing.T, f *syncFixture) *publication {
	t.Helper()
	p, snapshot, e := directory.Build(f.cfg, f.owner, f.publisher, f.first.Checkpoint(), f.members, f.items)
	if e != nil {
		t.Fatal("cannot build owned publication", e)
	}
	return &publication{Proposal: p, Snapshot: snapshot}
}

// TestReadPreflightRefusesCapacityBeforeAnchorAdvance pins that a read whose
// exact signed envelope exceeds its budget is refused as signed capacity and
// leaves the persistent anchor untouched, while the same read under
// MaxResponseBytes still advances it.
func TestReadPreflightRefusesCapacityBeforeAnchorAdvance(t *testing.T) {
	// The probe has its own directory, anchor and handler: its in-budget read
	// advances its anchor, so it cannot also serve as the over-budget fixture.
	probe, probeServer := lifecycleFixture(t)
	fullRequest := lifecycleRequest(probe, nil)
	full := preflight(t, probeServer, fullRequest, MaxResponseBytes)
	if full.Status != "current" || full.History == nil || full.Head != probe.first.Checkpoint() {
		t.Fatal("full read did not return the current history")
	}
	assertSignedEnvelope(t, probe, fullRequest, full, MaxResponseBytes)
	fullLen := len(encode(full))
	if cp := serverAnchor(t, probe); cp != probe.first.Checkpoint() {
		t.Fatal("in-budget read did not advance the probe anchor to its head")
	}
	budget := budgetBetween(t, probe, fullLen)

	f, s := lifecycleFixture(t)
	initial := serverAnchor(t, f)
	smallRequest := lifecycleRequest(f, nil)
	small := preflight(t, s, smallRequest, budget)
	assertCapacity(t, small)
	assertSignedEnvelope(t, f, smallRequest, small, budget)
	if cp := serverAnchor(t, f); cp != initial {
		t.Fatalf("oversize read moved the anchor to version %d, want %d", cp.Version, initial.Version)
	}
}

// TestReadPreflightSerializesConcurrentReads pins that response preflight and
// the anchor CAS of concurrent reads stay in one critical section: with a
// budget that fits only the capacity refusal, both requests are told capacity,
// neither reports a false anchor error, and the persistent anchor never moves.
func TestReadPreflightSerializesConcurrentReads(t *testing.T) {
	probe, probeServer := lifecycleFixture(t)
	full := preflight(t, probeServer, lifecycleRequest(probe, nil), MaxResponseBytes)
	if full.Status != "current" || full.History == nil {
		t.Fatal("probe read did not return the current history")
	}
	budget := budgetBetween(t, probe, len(encode(full)))

	f, s := lifecycleFixture(t)
	initial := serverAnchor(t, f)
	before := databaseBytes(t, f)
	// Each worker carries its own copy: both requests are read concurrently.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	// The first request finishes its directory read and holds s.mu there; the
	// second is started meanwhile, so it begins behind the same critical section.
	var held atomic.Bool
	s.hooks = &serverLifecycleHooks{afterRead: func() {
		if !held.CompareAndSwap(false, true) {
			return
		}
		once.Do(func() { close(entered) })
		<-release
	}}

	type result struct {
		out   response
		nonce string
		err   error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		// Each worker carries its own request: both are read concurrently.
		req := signedLifecycleRequest(f, nil, strings.Repeat(string(rune('a'+i)), 64))
		wg.Add(1)
		go func(req *http.Request) {
			defer wg.Done()
			// Report through a channel: no t.Fatal may run off the test goroutine.
			raw, e := io.ReadAll(req.Body)
			if e == nil {
				var q request
				if e = decode(raw, &q); e == nil {
					var out response
					out, e = s.handle(req, q, budget)
					results <- result{nonce: q.Proof.Nonce, out: out, err: e}
					return
				}
			}
			results <- result{err: e}
		}(req)
	}
	lifecycleWait(t, entered)
	close(release)
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	lifecycleWait(t, finished)
	close(results)
	nonces := map[string]bool{}
	for r := range results {
		if r.err != nil {
			t.Fatalf("read refused to decide a response: %v", r.err)
		}
		assertCapacity(t, r.out)
		assertSignedEnvelope(t, f, signedLifecycleRequest(f, nil, r.nonce), r.out, budget)
		nonces[r.out.Nonce] = true
	}
	if len(nonces) != 2 {
		t.Fatal("concurrent reads shared one nonce")
	}
	if cp := serverAnchor(t, f); cp != initial {
		t.Fatalf("capacity-refused reads advanced the anchor to %#v", cp)
	}
	if !bytes.Equal(before, databaseBytes(t, f)) {
		t.Fatal("capacity-refused reads mutated the directory")
	}
}

// TestPublishPreflightRefusesCapacityBeforeCommitOrAdvance pins that an
// oversize projected commit response is refused as signed capacity without
// calling directory.Commit and without touching the database or the anchor,
// and that the same publication then commits under a budget that fits.
func TestPublishPreflightRefusesCapacityBeforeCommitOrAdvance(t *testing.T) {
	probe, probeServer := lifecycleFixture(t)
	pub := ownedPublication(t, probe)
	var probeCommits atomic.Int32
	probeServer.hooks = &serverLifecycleHooks{afterCommitGrant: func() { probeCommits.Add(1) }}
	fullRequest := lifecycleRequest(probe, pub)
	full := preflight(t, probeServer, fullRequest, MaxResponseBytes)
	if full.Status != "committed" || full.Receipt == nil {
		t.Fatalf("full publish preflight status = %q", full.Status)
	}
	if probeCommits.Load() != 1 || serverAnchor(t, probe) != full.Head {
		t.Fatal("in-budget publish did not commit and advance the probe anchor")
	}
	assertSignedEnvelope(t, probe, fullRequest, full, MaxResponseBytes)
	projectedLen := len(encode(full))
	if projectedLen <= 400 {
		t.Fatalf("full committed envelope is only %d bytes", projectedLen)
	}
	budget := budgetBetween(t, probe, projectedLen)

	f, s := lifecycleFixture(t)
	initial := serverAnchor(t, f)
	before := databaseBytes(t, f)
	pub = ownedPublication(t, f)
	var commits atomic.Int32
	s.hooks = &serverLifecycleHooks{afterCommitGrant: func() { commits.Add(1) }}

	smallRequest := lifecycleRequest(f, pub)
	small := preflight(t, s, smallRequest, budget)
	assertCapacity(t, small)
	assertSignedEnvelope(t, f, smallRequest, small, budget)
	if commits.Load() != 0 {
		t.Fatal("oversize publish reached the commit")
	}
	if cp := serverAnchor(t, f); cp != initial {
		t.Fatalf("oversize publish advanced the anchor to version %d", cp.Version)
	}
	if !bytes.Equal(before, databaseBytes(t, f)) {
		t.Fatal("oversize publish mutated the database")
	}
	view, e := directory.Read(f.path, f.cfg, f.cfg.Genesis())
	if e != nil || view.Receipt.Checkpoint() != f.first.Checkpoint() {
		t.Fatal("oversize publish moved the committed head", e)
	}

	// The same publication commits once its response fits, and the actual
	// serialized receipt envelope is exactly as long as the projection.
	exactRequest := lifecycleRequest(f, pub)
	exact := preflight(t, s, exactRequest, projectedLen)
	if exact.Status != "committed" || exact.Receipt == nil || exact.Head.Version != 2 {
		t.Fatalf("fitting publish status = %q", exact.Status)
	}
	assertSignedEnvelope(t, f, exactRequest, exact, projectedLen)
	if commits.Load() != 1 {
		t.Fatal("fitting publish did not reach the commit exactly once")
	}
	if got := len(encode(exact)); got != projectedLen {
		t.Fatalf("actual committed envelope is %d bytes, projection %d", got, projectedLen)
	}
	if cp := serverAnchor(t, f); cp != exact.Head {
		t.Fatal("committed publish did not advance the anchor to the new head")
	}
}
