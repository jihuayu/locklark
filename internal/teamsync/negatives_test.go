package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/vault"
)

func TestHTTPSFreshSignedForkAndIllegalTransitionRejected(t *testing.T) {
	var mode atomic.Int32
	var f *syncFixture
	var fork directory.History
	f = newSyncFixture(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cw := &captureWriter{w: w, header: make(http.Header)}
			next.ServeHTTP(cw, r)
			if r.URL.Path == ReadPath && mode.Load() != 0 {
				var out response
				if json.Unmarshal(cw.body.Bytes(), &out) == nil && out.History != nil {
					if mode.Load() == 1 {
						out.History = &fork
					} else {
						receipt := &out.History.Receipts[1]
						receipt.Proposal.Members[1].Role = "writer"
						p := receipt.Proposal
						p.Signature = nil
						receipt.Proposal.Signature = ed25519.Sign(f.keys[0], append([]byte("locklark/team-directory/proposal/v1\x00"), encode(p)...))
						r := *receipt
						r.Signature = nil
						receipt.Signature = ed25519.Sign(f.seq, append([]byte("locklark/team-directory/receipt/v1\x00"), encode(r)...))
					}
					out.Head = out.History.Receipts[len(out.History.Receipts)-1].Checkpoint()
					out.HistoryDigest = digest("history", out.History)
					out.Signature = ed25519.Sign(f.seq, out.signingBytes())
					cw.body.Reset()
					cw.body.Write(encode(out))
				}
			}
			cw.flush()
		})
	})
	initial, e := os.ReadFile(f.path)
	if e != nil {
		t.Fatal(e)
	}
	p, s, e := directory.BuildUpdate(f.cfg, f.keys[0], f.first, f.items)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = directory.Commit(f.path, f.cfg, f.seq, p, s); e != nil {
		t.Fatal(e)
	}
	branchPath := filepath.Join(f.root, "other-branch.db")
	if os.WriteFile(branchPath, initial, 0600) != nil {
		t.Fatal("branch fixture failed")
	}
	branchItems := append([]vault.Item(nil), f.items...)
	branchItems[0].Title = "Other branch"
	p, s, e = directory.BuildUpdate(f.cfg, f.keys[0], f.first, branchItems)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = directory.Commit(branchPath, f.cfg, f.seq, p, s); e != nil {
		t.Fatal(e)
	}
	_, fork, e = directory.ReadHistory(branchPath, f.cfg, f.cfg.Genesis())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = directory.VerifyHistory(f.cfg, f.cfg.Genesis(), fork); e != nil {
		t.Fatal("fork counterexample invalid", e)
	}
	client := f.client(t, 0)
	current, e := client.Fetch(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	mode.Store(1)
	state, e := client.Fetch(context.Background())
	if !errors.Is(e, ErrInvalid) || client.Checkpoint() != current.Checkpoint() {
		t.Fatal("fresh sequencer assertion bypassed retained fork checkpoint", e)
	}
	assertZeroState(t, state)
	mode.Store(2)
	fresh := f.client(t, 0)
	state, e = fresh.Fetch(context.Background())
	if !errors.Is(e, ErrInvalid) {
		t.Fatal("fresh sequencer signature bypassed full writer ACL history", e)
	}
	assertZeroState(t, state)
}

func TestHTTPSDoesNotFollowRedirectOrUseOldPolicy(t *testing.T) {
	var visits atomic.Int32
	trap := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { visits.Add(1) }))
	defer trap.Close()
	f := newSyncFixture(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, trap.URL, http.StatusTemporaryRedirect)
		})
	})
	client := f.client(t, 0)
	state, e := client.Fetch(context.Background())
	if !errors.Is(e, ErrTransport) || visits.Load() != 0 {
		t.Fatal("client forwarded signed authorization to redirect", e)
	}
	assertZeroState(t, state)
	legacy, e := directory.NewConfig(directory.Pins{Team: strings.Repeat("a", 32), Vault: strings.Repeat("b", 32), Owners: []string{publicKey(f.owner)}, Sequencer: publicKey(f.seq), Publisher: publicKey(f.publisher)})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = NewDeviceClient(legacy, f.endpoint, f.members[0].Devices[0], f.keys[0], f.anchor(t)); !errors.Is(e, ErrInvalid) {
		t.Fatal("legacy policy upgraded implicitly")
	}
	if _, e = NewHandler(f.path, legacy, f.seq, legacy.Genesis(), f.anchors); !errors.Is(e, ErrInvalid) {
		t.Fatal("server accepted legacy policy")
	}
}

func TestHTTPSAuthenticationSelectorsAndContentTypeBound(t *testing.T) {
	f := newSyncFixture(t, nil)
	client := f.client(t, 0)
	newRequest := func() request {
		q := request{Proof: requestProof{Protocol: protocol, Scope: f.cfg.Genesis().Scope, Action: "read", Kind: "device", ID: f.members[0].Devices[0].ID, Nonce: strings.Repeat("a", 64), Anchor: f.cfg.Genesis()}}
		q.Proof.BodyDigest = digest("payload", q.Publication)
		return q
	}
	for _, alter := range []func(*request){
		func(q *request) { q.Proof.Scope = strings.Repeat("b", 64) },
		func(q *request) { q.Proof.Action = "publish" },
		func(q *request) { q.Proof.Nonce = strings.Repeat("A", 64) },
		func(q *request) { q.Proof.Kind = "owner"; q.Proof.ID = publicKey(f.owner) },
		func(q *request) { q.Proof.ID = f.members[1].Devices[0].ID },
		func(q *request) { q.Proof.Anchor.Scope = strings.Repeat("c", 64) },
	} {
		q := newRequest()
		alter(&q)
		q.Proof.Signature = ed25519.Sign(f.keys[0], q.Proof.signingBytes())
		r, _ := http.NewRequest(http.MethodPost, f.endpoint.URL+ReadPath, bytes.NewReader(encode(q)))
		r.Header.Set("Content-Type", "application/json")
		reply, e := client.http.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := io.ReadAll(reply.Body)
		reply.Body.Close()
		if reply.StatusCode == 200 {
			var out response
			if json.Unmarshal(raw, &out) != nil || out.Status == "current" || out.Status == "committed" || out.History != nil || out.Receipt != nil {
				t.Fatal("signed selector rebinding authorized read")
			}
		} else if reply.StatusCode != 400 {
			t.Fatal("unexpected invalid selector classification")
		}
	}
	for _, contentType := range []string{"", "text/plain", "application/json; charset=utf-8"} {
		q := newRequest()
		q.Proof.Signature = ed25519.Sign(f.keys[0], q.Proof.signingBytes())
		r, _ := http.NewRequest(http.MethodPost, f.endpoint.URL+ReadPath, bytes.NewReader(encode(q)))
		r.Header.Set("Content-Type", contentType)
		reply, e := client.http.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		reply.Body.Close()
		if reply.StatusCode != 400 {
			t.Fatal("unsupported content type authorized request")
		}
	}
}
