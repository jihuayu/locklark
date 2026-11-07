package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestDesktopSnapshotProjectionAndThreeAuditIntents(t *testing.T) {
	s, path, key := v2Session(t)
	sub, err := s.CreateVault("Scoped", "", "", v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	first := v2LoginItem()
	first.Title = "Alpha snapshot-needle"
	if _, _, err = s.AddItem(first, v2Gate(t, s)); err != nil {
		t.Fatal(err)
	}
	other := v2LoginItem()
	other.Title = "Beta"
	other.VaultID = sub.ID
	other.Favorite = false
	if _, _, err = s.AddItem(other, v2Gate(t, s)); err != nil {
		t.Fatal(err)
	}
	archived := v2LoginItem()
	archived.Title = "Archived"
	id, rev, err := s.AddItem(archived, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetState(id, rev, "item.archive"); err != nil {
		t.Fatal(err)
	}
	favorite := true
	filters := []ItemFilter{
		{State: "active", SortBy: "title"},
		{State: "active", Query: "snapshot-needle", SortBy: "title"},
		{State: "all", VaultID: sub.ID, SortBy: "title"},
		{State: "archived", SortBy: "title"},
		{State: "active", Favorite: &favorite, Tag: "work", Category: vault.CategoryLogin, SortBy: "title"},
		{State: "trashed", SortBy: "title"},
	}
	for n, filter := range filters {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			rows, e := s.ListByFilter(filter)
			if e != nil {
				t.Fatal(e)
			}
			all, e := s.ListByFilter(ItemFilter{State: "all", VaultID: filter.VaultID, SortBy: "title"})
			if e != nil {
				t.Fatal(e)
			}
			vaults, e := s.ListVaults()
			if e != nil {
				t.Fatal(e)
			}
			before, e := s.Audit()
			if e != nil {
				t.Fatal(e)
			}
			snap, e := s.ListDesktopSnapshot(filter)
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(rows, snap.Rows) || !reflect.DeepEqual(all, snap.All) || !reflect.DeepEqual(vaults, snap.Vaults) {
				t.Fatal("snapshot projections differ from original three APIs")
			}
			after, e := s.Audit()
			if e != nil {
				t.Fatal(e)
			}
			appended := after[len(before) : len(after)-1]
			action := "item.list"
			if filter.Query != "" {
				action = searchAction
			}
			if len(appended) != 3 {
				t.Fatalf("expected three intents, got %d", len(appended))
			}
			for j, want := range []string{action, "item.list", v2ListVaultsAction} {
				ev := appended[j]
				if ev.Action != want || ev.Result != "succeeded" || ev.Item != "" || ev.BaseRevision != "" {
					t.Fatal("audit semantics changed")
				}
				prev := before[len(before)-1]
				if j > 0 {
					prev = appended[j-1]
				}
				if ev.Previous != prev.hash() || ev.Sequence != prev.Sequence+1 {
					t.Fatal("audit chain broken")
				}
			}
			if filter.Query != "" && !digestOK(appended[0].Link) {
				t.Fatal("search binding missing")
			}
			eventJSON, _ := json.Marshal(appended)
			if bytes.Contains(eventJSON, []byte("snapshot-needle")) {
				t.Fatal("raw query in audit")
			}
			raw, _ := json.Marshal(snap)
			for _, secret := range []string{"old-password", "concealed-value", "v2 notes", v2OTPConfig} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("concealed value in metadata snapshot")
				}
			}
			if len(snap.Rows) > 0 && len(snap.Rows[0].Tags) > 0 {
				snap.Rows[0].Tags[0] = "caller-mutated"
				again, e := s.ListDesktopSnapshot(filter)
				if e != nil {
					t.Fatal(e)
				}
				for _, row := range again.Rows {
					if len(row.Tags) > 0 && row.Tags[0] == "caller-mutated" {
						t.Fatal("caller mutation reached stored state")
					}
				}
			}
		})
	}
	// Full cold authentication must replay all three linked read actions.
	s.Lock()
	reopened, e := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Lock()
	if _, e = reopened.ListDesktopSnapshot(ItemFilter{State: "all", SortBy: "title"}); e != nil {
		t.Fatal(e)
	}
}

func TestDesktopSnapshotRefusesLockedExpiredInvalidAndTampered(t *testing.T) {
	cases := []string{"locked", "expired", "invalid-filter", "history", "snapshot"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			s, path, _ := v2Session(t)
			if _, _, e := s.AddItem(v2LoginItem(), v2Gate(t, s)); e != nil {
				t.Fatal(e)
			}
			filter := ItemFilter{State: "active", SortBy: "title"}
			if _, e := s.ListDesktopSnapshot(filter); e != nil {
				t.Fatal(e)
			}
			switch name {
			case "locked":
				s.Lock()
			case "expired":
				s.mu.Lock()
				s.last = time.Now().Add(-2 * time.Minute)
				s.mu.Unlock()
			case "invalid-filter":
				filter.State = "unsupported"
			case "history":
				mutateVault(t, path, func(b *bolt.Bucket) error {
					events := b.Bucket(eventsKey)
					key := eventKey(2)
					raw := bytes.Clone(events.Get(key))
					raw[len(raw)-1] ^= 1
					return events.Put(key, raw)
				})
			case "snapshot":
				mutateVault(t, path, func(b *bolt.Bucket) error {
					raw := bytes.Clone(b.Get(snapshotKey))
					raw[len(raw)-1] ^= 1
					return b.Put(snapshotKey, raw)
				})
			}
			snap, e := s.ListDesktopSnapshot(filter)
			if e == nil || len(snap.Rows) != 0 || len(snap.All) != 0 || len(snap.Vaults) != 0 {
				t.Fatal("refusal returned partial metadata")
			}
			if (name == "locked" || name == "expired") && !errors.Is(e, ErrSessionLocked) {
				t.Fatal("expected locked refusal")
			}
		})
	}
	var absent *Session
	if _, e := absent.ListDesktopSnapshot(ItemFilter{}); !errors.Is(e, ErrSessionLocked) {
		t.Fatal("nil session accepted")
	}
}

func BenchmarkDesktopSnapshot(b *testing.B) {
	for _, history := range []int{1000, 10000} {
		for _, batched := range []bool{false, true} {
			name := "three-reads"
			if batched {
				name = "one-snapshot"
			}
			b.Run(fmt.Sprintf("%d/%s", history, name), func(b *testing.B) {
				path, key := newBenchVault(b, history, false)
				s, e := UnlockSession(path, []byte("fixture"), key, 15*time.Minute)
				if e != nil {
					b.Fatal(e)
				}
				defer s.Lock()
				filter := ItemFilter{State: "active", Query: "one", SortBy: "title"}
				run := func() error {
					if batched {
						_, e := s.ListDesktopSnapshot(filter)
						return e
					}
					if _, e := s.ListByFilter(filter); e != nil {
						return e
					}
					if _, e := s.ListByFilter(ItemFilter{State: "all", SortBy: "title"}); e != nil {
						return e
					}
					_, e := s.ListVaults()
					return e
				}
				if e = run(); e != nil {
					b.Fatal(e)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					if e = run(); e != nil {
						b.Fatal(e)
					}
				}
			})
		}
	}
}
