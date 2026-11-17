package teamsync

import (
	"bytes"
	"context"
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

// readyRequest returns the signed query of r without consuming its body.
func readyRequest(t *testing.T, r *http.Request) request {
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
	return q
}

// preparedLen returns the exact encoded length prepare would give out for this
// request under budget: the signed envelope itself when it fits, otherwise the
// signed capacity refusal that replaces it.
func preparedLen(t *testing.T, s *server, q request, out response, budget int) int {
	t.Helper()
	if !s.prepare(context.Background(), q, &out, budget) {
		t.Fatal("budget cannot carry even a signed capacity refusal")
	}
	return len(encode(out))
}

// publicationProjection measures, on a pristine fixture, the exact signed
// envelopes its first publication would produce: the projected committed
// receipt answer and the projected full read of the history that commit would
// leave. It mirrors server.handle: one ReadTrusted at the persisted anchor for
// that request's proof anchor, the equal-length receipt projection, and
// ProjectHistory over the same candidate snapshot. Nothing is committed and the
// anchor does not move. The returned request is left readable for handle.
func publicationProjection(t *testing.T, f *syncFixture, s *server, pub *publication) (int, int, *http.Request) {
	t.Helper()
	r := lifecycleRequest(f, pub)
	q := readyRequest(t, r)
	anchor := serverAnchor(t, f)
	trusted, e := directory.ReadTrusted(f.path, f.cfg, anchor, q.Proof.Anchor)
	if e != nil {
		t.Fatal("cannot read the target directory", e)
	}
	head := trusted.Checkpoint()
	if head != q.Publication.Proposal.Parent {
		t.Fatal("target publication does not extend the target head")
	}
	projection := directory.Receipt{Proposal: q.Publication.Proposal, Signature: make([]byte, ed25519.SignatureSize)}
	projection.Proposal.Epoch = head.Version + 1
	projection.Proposal.Scope = strings.Repeat("0", len(f.cfg.Genesis().Scope))
	if head.Version > 0 {
		projection.Proposal.Parent.Hash = strings.Repeat("0", 64)
	}
	projected := response{Status: "committed", Head: projection.Checkpoint(), Receipt: &projection}
	committedLen := preparedLen(t, s, q, projected, MaxResponseBytes)
	if projected.Status != "committed" || projected.Receipt == nil {
		t.Fatal("receipt projection does not fit MaxResponseBytes")
	}
	h, e := trusted.ProjectHistory(projection, q.Publication.Snapshot)
	if e != nil {
		t.Fatal("cannot project the post-commit history", e)
	}
	full := response{Status: "current", Head: projection.Checkpoint(), History: &h}
	readLen := preparedLen(t, s, q, full, MaxResponseBytes)
	if full.Status != "current" || full.History == nil {
		t.Fatal("projected post-commit read does not fit MaxResponseBytes")
	}
	if cp := serverAnchor(t, f); cp != anchor {
		t.Fatal("publication projection moved the anchor")
	}
	return committedLen, readLen, r
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
// and that the same publication then commits under MaxResponseBytes and reads
// back the complete post-commit history.
func TestPublishPreflightRefusesCapacityBeforeCommitOrAdvance(t *testing.T) {
	target, targetServer := lifecycleFixture(t)
	initial := serverAnchor(t, target)
	before := databaseBytes(t, target)
	pub := ownedPublication(t, target)
	committedLen, readLen, smallRequest := publicationProjection(t, target, targetServer, pub)
	if committedLen <= 400 || readLen <= committedLen {
		t.Fatalf("committed projection (%d bytes) and read projection (%d bytes) do not separate", committedLen, readLen)
	}
	budget := budgetBetween(t, target, committedLen)

	var commits atomic.Int32
	targetServer.hooks = &serverLifecycleHooks{afterCommitGrant: func() { commits.Add(1) }}

	small := preflight(t, targetServer, smallRequest, budget)
	assertCapacity(t, small)
	assertSignedEnvelope(t, target, smallRequest, small, budget)
	if commits.Load() != 0 {
		t.Fatal("oversize publish reached the commit")
	}
	if cp := serverAnchor(t, target); cp != initial {
		t.Fatalf("oversize publish advanced the anchor to version %d", cp.Version)
	}
	if !bytes.Equal(before, databaseBytes(t, target)) {
		t.Fatal("oversize publish mutated the database")
	}
	view, e := directory.Read(target.path, target.cfg, target.cfg.Genesis())
	if e != nil || view.Receipt.Checkpoint() != target.first.Checkpoint() {
		t.Fatal("oversize publish moved the committed head", e)
	}

	// The same publication commits under MaxResponseBytes: a receipt-only
	// fitting budget is no longer sufficient because the post-commit read must
	// fit too. Its actual receipt envelope and its actual post-commit read are
	// exactly as long as measured before the commit.
	exactRequest := lifecycleRequest(target, pub)
	exact := preflight(t, targetServer, exactRequest, MaxResponseBytes)
	if exact.Status != "committed" || exact.Receipt == nil || exact.Head.Version != 2 || commits.Load() != 1 {
		t.Fatalf("MaxResponseBytes publish status = %q", exact.Status)
	}
	assertSignedEnvelope(t, target, exactRequest, exact, MaxResponseBytes)
	if got := len(encode(exact)); got != committedLen {
		t.Fatalf("actual committed envelope is %d bytes, projection %d", got, committedLen)
	}
	if cp := serverAnchor(t, target); cp != exact.Head {
		t.Fatal("committed publish did not advance the anchor to the new head")
	}
	readRequest := lifecycleRequest(target, nil)
	read := preflight(t, targetServer, readRequest, MaxResponseBytes)
	if read.Status != "current" || read.History == nil || read.Head != exact.Head || len(read.History.Receipts) != 2 {
		t.Fatalf("post-commit read status = %q", read.Status)
	}
	assertSignedEnvelope(t, target, readRequest, read, MaxResponseBytes)
	if got := len(encode(read)); got != readLen {
		t.Fatalf("actual post-commit read is %d bytes, projection %d", got, readLen)
	}
	if cp := serverAnchor(t, target); cp != exact.Head {
		t.Fatal("post-commit read did not advance the anchor to the new head")
	}
}

// TestPublishPreflightRefusesFullReadCapacityBeforeCommitOrAdvance pins the gap
// the receipt preflight alone leaves open: a projected publish receipt response
// that fits the call's budget, whose projected post-commit read response does
// not. Such a commit would be acknowledged and then leave the retained history
// unreadable as capacity.
//
// The target candidate is measured exactly before handle runs, through the same
// ReadTrusted, equal-length receipt projection and ProjectHistory the server
// uses. The low budget fits the receipt projection but not the projected read,
// and must also fit the signed capacity refusal. The guard is checked under
// that private budget seam, exactly as ServeHTTP passes MaxResponseBytes; it is
// not a product limit.
func TestPublishPreflightRefusesFullReadCapacityBeforeCommitOrAdvance(t *testing.T) {
	target, targetServer := lifecycleFixture(t)
	initial := serverAnchor(t, target)
	before := databaseBytes(t, target)
	pub := ownedPublication(t, target)
	committedLen, readLen, smallRequest := publicationProjection(t, target, targetServer, pub)

	capacityLen := len(encode(response{Status: "capacity", Protocol: protocol, RequestDigest: strings.Repeat("0", 64), Nonce: strings.Repeat("0", 64), Signature: make([]byte, ed25519.SignatureSize)}))
	budget := (committedLen + readLen) / 2
	if capacityLen >= budget || committedLen > budget || budget >= readLen {
		t.Fatalf("budget %d does not separate capacity (%d), receipt projection (%d) and read projection (%d)", budget, capacityLen, committedLen, readLen)
	}

	var commits atomic.Int32
	targetServer.hooks = &serverLifecycleHooks{afterCommitGrant: func() { commits.Add(1) }}

	// The same target request under the low budget is refused as signed
	// capacity before the commit hook, with no database or anchor change.
	small := preflight(t, targetServer, smallRequest, budget)
	assertCapacity(t, small)
	assertSignedEnvelope(t, target, smallRequest, small, budget)
	if commits.Load() != 0 {
		t.Fatal("capacity-refused publish reached the commit")
	}
	if cp := serverAnchor(t, target); cp != initial {
		t.Fatalf("capacity-refused publish advanced the anchor to version %d", cp.Version)
	}
	if !bytes.Equal(before, databaseBytes(t, target)) {
		t.Fatal("capacity-refused publish mutated the database")
	}
	if view, e := directory.Read(target.path, target.cfg, target.cfg.Genesis()); e != nil || view.Receipt.Checkpoint() != target.first.Checkpoint() {
		t.Fatal("capacity-refused publish moved the committed head", e)
	}

	// The same publication commits under MaxResponseBytes, and the actual
	// post-commit read is exactly as long as the measured projection.
	normalRequest := lifecycleRequest(target, pub)
	normal := preflight(t, targetServer, normalRequest, MaxResponseBytes)
	if normal.Status != "committed" || normal.Receipt == nil || normal.Head.Version != 2 || commits.Load() != 1 {
		t.Fatalf("MaxResponseBytes publish status = %q", normal.Status)
	}
	assertSignedEnvelope(t, target, normalRequest, normal, MaxResponseBytes)
	if got := len(encode(normal)); got != committedLen {
		t.Fatalf("actual committed envelope is %d bytes, projection %d", got, committedLen)
	}
	if cp := serverAnchor(t, target); cp != normal.Head {
		t.Fatal("committed publish did not advance the anchor to the new head")
	}
	readRequest := lifecycleRequest(target, nil)
	read := preflight(t, targetServer, readRequest, MaxResponseBytes)
	if read.Status != "current" || read.History == nil || read.Head != normal.Head || len(read.History.Receipts) != 2 || len(read.History.Snapshot.Database) == 0 {
		t.Fatal("committed publish left no readable post-commit history")
	}
	assertSignedEnvelope(t, target, readRequest, read, MaxResponseBytes)
	if got := len(encode(read)); got != readLen {
		t.Fatalf("actual post-commit read is %d bytes, projection %d", got, readLen)
	}
	if view, e := directory.AssembleHistory(target.cfg, target.cfg.Genesis(), normal.Head, *read.History); e != nil || view.Receipt.Checkpoint() != normal.Head {
		t.Fatal("post-commit read is not the committed history", e)
	}
	if cp := serverAnchor(t, target); cp != normal.Head {
		t.Fatal("post-commit read did not advance the anchor to the new head")
	}

	// Legacy boundary: the committed history already reads over the low budget,
	// so read returns signed capacity under it and moves nothing.
	legacyRequest := lifecycleRequest(target, nil)
	legacy := preflight(t, targetServer, legacyRequest, budget)
	assertCapacity(t, legacy)
	assertSignedEnvelope(t, target, legacyRequest, legacy, budget)
	if cp := serverAnchor(t, target); cp != normal.Head {
		t.Fatalf("capacity-refused read moved the anchor to version %d", cp.Version)
	}
	// A valid publication extending that history is refused the same way,
	// before the commit hook, with no database or anchor change.
	legacyBefore := databaseBytes(t, target)
	legacyProposal, legacySnapshot, e := directory.Build(target.cfg, target.owner, target.publisher, normal.Head, target.members, target.items)
	if e != nil {
		t.Fatal("cannot build legacy publication", e)
	}
	legacyPublishRequest := lifecycleRequest(target, &publication{Proposal: legacyProposal, Snapshot: legacySnapshot})
	legacyPublish := preflight(t, targetServer, legacyPublishRequest, budget)
	assertCapacity(t, legacyPublish)
	assertSignedEnvelope(t, target, legacyPublishRequest, legacyPublish, budget)
	if commits.Load() != 1 {
		t.Fatal("publish extending an unreadable history reached the commit")
	}
	if cp := serverAnchor(t, target); cp != normal.Head {
		t.Fatalf("publish extending an unreadable history moved the anchor to version %d", cp.Version)
	}
	if !bytes.Equal(legacyBefore, databaseBytes(t, target)) {
		t.Fatal("publish extending an unreadable history mutated the database")
	}
	if view, e := directory.Read(target.path, target.cfg, normal.Head); e != nil || view.Receipt.Checkpoint() != normal.Head {
		t.Fatal("publish extending an unreadable history moved the committed head", e)
	}
}
