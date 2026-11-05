package personal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/gateway"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func liveRequest() LivePullRequest {
	return LivePullRequest{Repository: gateway.Repository{ID: "1445507532", Owner: "jihuayu", Name: "locklark"}, Number: 18, Address: "140.82.112.6"}
}
func TestLivePullIntentPrecedesUpstream(t *testing.T) {
	path, key, target := revealFixture(t)
	request := liveRequest()
	prepare := func(r *LivePullRequest) (result, error) {
		return command(path, "fixture", key, livePullAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: "password"}, commandOption{livePull: r})
	}
	called := 0
	receipt, e := livePull(context.Background(), target, request, prepare, func(_ context.Context, got LivePullRequest, value []byte) (gateway.PullResult, error) {
		called++
		if got != request || string(value) != "private-value\t\"quoted\"\n" {
			t.Fatal("wrong scoped credential")
		}
		events, e := Audit(path, "fixture", key)
		if e != nil {
			t.Fatal("upstream before database close", e)
		}
		if len(events) < 2 || events[len(events)-2].Action != livePullAction || events[len(events)-2].Result != "intent" {
			t.Fatal("upstream before durable intent")
		}
		return gateway.PullResult{Number: 18, State: "open"}, nil
	})
	if e != nil || called != 1 || receipt.Status != "result-received" || receipt.Result.Number != 18 {
		t.Fatal("live action", e)
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ev := range events {
		if ev.hash() == receipt.Intent {
			found = true
			if ev.Link != receipt.TargetDigest || ev.BaseRevision != target.Revision {
				t.Fatal("target not bound")
			}
		}
	}
	if !found {
		t.Fatal("intent absent")
	}
	raw, _ := json.Marshal([]any{receipt, events})
	for _, s := range []string{"private-value", "jihuayu", "140.82.112.6"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatal("credential or target leaked")
		}
	}
	rows, e := List(path, "fixture", key)
	if e != nil || rows[0].Revision != target.Revision {
		t.Fatal("invoke changed item revision", e)
	}
	archive := filepath.Join(t.TempDir(), "backup.llb")
	kit, e := Backup(path, archive, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := NewSecret()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(fresh)
	restored := filepath.Join(t.TempDir(), "restored.ll")
	if e = Restore(archive, restored, "fixture", key, kit, fresh); e != nil {
		t.Fatal("restore with live intent", e)
	}
	if _, e = List(restored, "fixture", fresh); e != nil {
		t.Fatal("restored live history", e)
	}
}

func TestLivePullFailureDoesNotSend(t *testing.T) {
	path, key, target := revealFixture(t)
	request := liveRequest()
	calls := 0
	send := func(context.Context, LivePullRequest, []byte) (gateway.PullResult, error) {
		calls++
		return gateway.PullResult{}, errors.New("private upstream value")
	}
	prepare := func(r *LivePullRequest) (result, error) {
		return command(path, "fixture", key, livePullAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: "password"}, commandOption{livePull: r})
	}
	target.Revision = strings.Repeat("0", 64)
	if _, e := livePull(context.Background(), target, request, prepare, send); e != ErrConflict || calls != 0 {
		t.Fatal("stale reached network", e)
	}
	rows, e := List(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	target.Revision = rows[0].Revision
	db, e := existing(path)
	if e != nil {
		t.Fatal(e)
	}
	injected := errors.New("rollback")
	_, e = livePull(context.Background(), target, request, func(r *LivePullRequest) (result, error) {
		return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
			return db.Update(func(tx *bolt.Tx) error {
				if e := fn(tx); e != nil {
					return e
				}
				return injected
			})
		}, "fixture", key, livePullAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: "password"}, commandOption{livePull: r})
	}, send)
	db.Close()
	if e != injected || calls != 0 {
		t.Fatal("rollback reached network", e)
	}
	r, e := livePull(context.Background(), target, request, prepare, send)
	if e != ErrLivePullResult || calls != 1 || !reflect.DeepEqual(r, LivePullReceipt{}) || strings.Contains(e.Error(), "private") {
		t.Fatal("upstream error exposed", e)
	}
	target.Revision, e = SetTrashed(path, "fixture", key, target.ID, target.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = livePull(context.Background(), target, request, prepare, send); e != ErrTrashed || calls != 1 {
		t.Fatal("trash reached network", e)
	}
}

func TestLivePullRequestBounds(t *testing.T) {
	for _, change := range []func(*LivePullRequest){func(r *LivePullRequest) { r.Number = 0 }, func(r *LivePullRequest) { r.Address = "127.0.0.1" }, func(r *LivePullRequest) { r.Address = "api.github.com" }, func(r *LivePullRequest) { r.Repository.Name = "../other" }, func(r *LivePullRequest) { r.Repository.ID = "01" }} {
		r := liveRequest()
		change(&r)
		if r.Validate() == nil {
			t.Fatal("invalid target accepted")
		}
	}
	r := liveRequest()
	if e := r.Validate(); e != nil {
		t.Fatal(e)
	}
}

func TestLivePullBindingAndFailureBoundaries(t *testing.T) {
	r := liveRequest()
	key := bytes.Repeat([]byte{1}, 32)
	digest, e := r.binding(key)
	if e != nil || !digestOK(digest) {
		t.Fatal(e)
	}
	for _, change := range []func(*LivePullRequest){func(r *LivePullRequest) { r.Number++ }, func(r *LivePullRequest) { r.Address = "140.82.112.5" }, func(r *LivePullRequest) { r.Repository.ID = "12345" }, func(r *LivePullRequest) { r.Repository.Owner = "other" }, func(r *LivePullRequest) { r.Repository.Name = "other" }} {
		other := r
		change(&other)
		got, e := other.binding(key)
		if e != nil || got == digest {
			t.Fatal("target substitution")
		}
	}
	got, e := r.binding(bytes.Repeat([]byte{2}, 32))
	if e != nil || got == digest {
		t.Fatal("cross-vault binding")
	}
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}
	for _, kind := range []string{"close", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value := []byte("synthetic-private-token")
			calls := 0
			_, e := livePull(ctx, target, r, func(*LivePullRequest) (result, error) {
				if kind == "cancel" {
					cancel()
					return result{value: value}, nil
				}
				return commandWithClose(func() (result, error) { return result{value: value}, nil }, func() error { return errors.New("close") })
			}, func(context.Context, LivePullRequest, []byte) (gateway.PullResult, error) {
				calls++
				return gateway.PullResult{}, nil
			})
			if e == nil || calls != 0 || !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("failure released credential", e)
			}
		})
	}
	// Actual production adapter rejects short token bytes before RoundTrip.
	if _, e := executeLivePull(context.Background(), r, []byte("short")); e == nil {
		t.Fatal("invalid production credential accepted")
	}
}
