package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
)

type requestCounts struct{ opens atomic.Int32 }

func countReads(s *server) *requestCounts {
	c := &requestCounts{}
	s.hooks = &serverLifecycleHooks{beforeRead: func() { c.opens.Store(0) }, afterRead: func() { c.opens.Add(1) }}
	return c
}

// TestRequestReadsDirectoryOnce pins the #102 accept criterion: each read and
// publish request reads the BoltDB directory once, and the trusted head and
// rollback decision stay those of Read.
func TestRequestReadsDirectoryOnce(t *testing.T) {
	f, s := lifecycleFixture(t)
	counts := countReads(s)
	for round := range 3 {
		if _, e := f.client(t, round%2).Fetch(context.Background()); e != nil {
			t.Fatal("read request failed", e)
		}
		if n := counts.opens.Load(); n != 1 {
			t.Fatalf("round %d read the BoltDB directory %d times", round, n)
		}
	}
	c := f.ownerClient(t)
	if _, e := c.Fetch(context.Background()); e != nil {
		t.Fatal(e)
	}
	if n := counts.opens.Load(); n != 1 {
		t.Fatalf("publish-side read opened the directory %d times", n)
	}
	// Only a version-1 anchor can be on the genesis prefix, and only version 1
	// hashes can advance it, so a forged head is rejected before authorization.
	unknown := directory.Checkpoint{Scope: f.cfg.Genesis().Scope, Version: 1, Hash: "00"}
	if _, e := directory.Read(f.path, f.cfg, unknown); e == nil {
		t.Fatal("forged checkpoint verified by Read")
	}
	if view, e := directory.AssembleHistory(f.cfg, unknown, f.first.Checkpoint(), directory.History{}); e == nil || view.Receipt.Proposal.Epoch != 0 {
		t.Fatal("empty history assembled a view", e)
	}
}

// TestRequestProofAnchorRefusalReadsOnce checks the rollback refusal still
// returns invalid after exactly one directory read: the proof-anchor view is
// rebuilt from the same verified history instead of a second BoltDB open.
func TestRequestProofAnchorRefusalReadsOnce(t *testing.T) {
	f, s := lifecycleFixture(t)
	counts := countReads(s)
	unknown := directory.Checkpoint{Scope: f.cfg.Genesis().Scope, Version: 1, Hash: strings.Repeat("00", 32)}
	q := request{Proof: requestProof{Protocol: protocol, Scope: f.cfg.Genesis().Scope, Action: "read", Kind: "owner",
		ID: publicKey(f.owner), Nonce: strings.Repeat("e", 64), Anchor: unknown, BodyDigest: digest("payload", nil)}}
	q.Proof.Signature = ed25519.Sign(f.owner, q.Proof.signingBytes())
	r := lifecycleRequest(f, nil)
	r.Body = io.NopCloser(bytes.NewReader(encode(q)))
	w := newLifecycleWriter()
	s.ServeHTTP(w, r)
	var out response
	if decode(w.body.Bytes(), &out) != nil || out.Status != "invalid" {
		t.Fatalf("rollback status = %q, want invalid", out.Status)
	}
	if n := counts.opens.Load(); n != 1 {
		t.Fatalf("refused request read the directory %d times", n)
	}
}

// TestRequestProofAnchorSelectsHeadAuthority pins the single-pass proof-anchor
// semantics: a plain genesis Read succeeds, a genesis proof anchor is proven
// without widening anything, a non-genesis anchor on the chain is accepted,
// and an off-chain anchor is refused after exactly one directory read.
func TestRequestProofAnchorSelectsHeadAuthority(t *testing.T) {
	f, s := lifecycleFixture(t)
	counts := countReads(s)
	unknown := directory.Checkpoint{Scope: f.cfg.Genesis().Scope, Version: 1, Hash: strings.Repeat("00", 32)}
	serve := func(anchor directory.Checkpoint) (string, error) {
		q := request{Proof: requestProof{Protocol: protocol, Scope: f.cfg.Genesis().Scope, Action: "read", Kind: "owner",
			ID: publicKey(f.owner), Nonce: strings.Repeat("e", 64), Anchor: anchor, BodyDigest: digest("payload", nil)}}
		q.Proof.Signature = ed25519.Sign(f.owner, q.Proof.signingBytes())
		r := lifecycleRequest(f, nil)
		r.Body = io.NopCloser(bytes.NewReader(encode(q)))
		w := newLifecycleWriter()
		s.ServeHTTP(w, r)
		var out response
		if decode(w.body.Bytes(), &out) != nil {
			t.Fatal("undecodable response")
		}
		return out.Status, nil
	}
	if view, e := directory.Read(f.path, f.cfg, f.cfg.Genesis()); e != nil || view.Receipt.Checkpoint() != f.first.Checkpoint() {
		t.Fatal("plain genesis Read failed", e)
	}
	for _, anchor := range []directory.Checkpoint{f.cfg.Genesis(), f.first.Checkpoint()} {
		if status, _ := serve(anchor); status != "current" {
			t.Fatalf("anchor %v status = %q, want current", anchor.Version, status)
		}
		if n := counts.opens.Load(); n != 1 {
			t.Fatalf("anchor %v read the directory %d times", anchor.Version, n)
		}
	}
	if status, _ := serve(unknown); status != "invalid" {
		t.Fatalf("off-chain anchor status = %q, want invalid", status)
	}
	if n := counts.opens.Load(); n != 1 {
		t.Fatalf("refused request read the directory %d times", n)
	}
}
