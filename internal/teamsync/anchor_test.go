package teamsync

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jihuayu/locklark/internal/directory"
)

func TestFileAnchorExplicitInitializationAndCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.db")
	if _, e := OpenFileAnchorStore(path); !errors.Is(e, ErrAnchor) {
		t.Fatal("missing anchor initialized implicitly")
	}
	initial := directory.Checkpoint{Scope: strings.Repeat("a", 64)}
	a, e := CreateFileAnchorStore(path, initial)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = CreateFileAnchorStore(path, initial); !errors.Is(e, ErrAnchor) {
		t.Fatal("anchor was overwritten")
	}
	other, e := OpenFileAnchorStore(path)
	if e != nil {
		t.Fatal(e)
	}
	candidates := []directory.Checkpoint{{Scope: initial.Scope, Version: 1, Hash: strings.Repeat("b", 64)}, {Scope: initial.Scope, Version: 1, Hash: strings.Repeat("c", 64)}}
	stores := []*FileAnchorStore{a, other}
	errs := make([]error, 2)
	var workers sync.WaitGroup
	for i := range stores {
		workers.Add(1)
		go func(i int) { defer workers.Done(); errs[i] = stores[i].Advance(initial, candidates[i]) }(i)
	}
	workers.Wait()
	wins := 0
	for _, e := range errs {
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrAnchor) {
			t.Fatal(e)
		}
	}
	if wins != 1 {
		t.Fatal("anchor CAS had multiple winners")
	}
	current, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	if a.Advance(current, initial) == nil {
		t.Fatal("anchor rollback accepted")
	}
	if a.Advance(initial, current) == nil {
		t.Fatal("stale expected anchor accepted")
	}
	again, e := a.Load()
	if e != nil || again != current {
		t.Fatal("failed anchor changed persisted checkpoint")
	}
	link := filepath.Join(filepath.Dir(path), "alias")
	if os.Symlink(path, link) == nil {
		if _, e = OpenFileAnchorStore(link); e == nil {
			t.Fatal("anchor symlink accepted")
		}
	}
}

type faultAnchor struct {
	AnchorStore
	mu   sync.Mutex
	fail bool
}

func (a *faultAnchor) Advance(old, next directory.Checkpoint) error {
	a.mu.Lock()
	failed := a.fail
	a.mu.Unlock()
	if failed && next != old {
		return ErrAnchor
	}
	return a.AnchorStore.Advance(old, next)
}
func (a *faultAnchor) set(fail bool) { a.mu.Lock(); a.fail = fail; a.mu.Unlock() }

func TestHTTPAnchorFailuresNeverClaimSuccess(t *testing.T) {
	var serverAnchor *faultAnchor
	f := newSyncFixture(t, func(h http.Handler) http.Handler {
		s := h.(*server)
		serverAnchor = &faultAnchor{AnchorStore: s.anchors}
		s.anchors = serverAnchor
		return h
	})
	c := f.client(t, 0)
	serverAnchor.set(true)
	out, e := c.Fetch(context.Background())
	if !errors.Is(e, ErrAnchor) {
		t.Fatal("server anchor failure returned read success", e)
	}
	assertZeroState(t, out)
	serverAnchor.set(false)
	if _, e = c.Fetch(context.Background()); e != nil {
		t.Fatal(e)
	}
	p, s, e := directory.BuildUpdate(f.cfg, f.keys[0], f.first, f.items)
	if e != nil {
		t.Fatal(e)
	}
	serverAnchor.set(true)
	if receipt, e := c.Publish(context.Background(), p, s); !errors.Is(e, ErrUnknown) || !reflect.DeepEqual(receipt, directory.Receipt{}) {
		t.Fatal("post-commit server anchor failure acknowledged publication", e)
	}
	out, e = c.Fetch(context.Background())
	if !errors.Is(e, ErrAnchor) {
		t.Fatal("server claimed a head with unpersisted anchor", e)
	}
	assertZeroState(t, out)
	serverAnchor.set(false)
	status, e := c.Reconcile(context.Background(), p)
	if e != nil || status.State != PublishCommitted {
		t.Fatal("server DB-ahead-anchor recovery failed", e)
	}
	// The client also withholds success and its local head on persistence failure.
	client := f.client(t, 0)
	local := &faultAnchor{AnchorStore: client.anchors, fail: true}
	client.anchors = local
	before := client.Checkpoint()
	out, e = client.Fetch(context.Background())
	if !errors.Is(e, ErrAnchor) || client.Checkpoint() != before {
		t.Fatal("client anchor failure returned success or advanced local head", e)
	}
	assertZeroState(t, out)
	local.set(false)
	state, e := client.Fetch(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	second, snapshot, e := directory.BuildUpdate(f.cfg, f.keys[0], state.View().Receipt, f.items)
	if e != nil {
		t.Fatal(e)
	}
	local.set(true)
	if _, e = client.Publish(context.Background(), second, snapshot); !errors.Is(e, ErrUnknown) {
		t.Fatal("post-commit client anchor failure not unknown", e)
	}
	if client.Checkpoint() != state.Checkpoint() {
		t.Fatal("failed local publish anchor changed acknowledged head")
	}
	local.set(false)
	status, e = client.Reconcile(context.Background(), second)
	if e != nil || status.State != PublishCommitted {
		t.Fatal("client anchor recovery failed", e)
	}
}
