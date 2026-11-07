package personal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func fillBenchHistory(b *testing.B, path, pw string, key []byte, target uint64) {
	b.Helper()
	db, err := existing(path)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucket)
		var slot account.Slot
		var s vault.Snapshot
		if json.Unmarshal(bkt.Get(slotKey), &slot) != nil || json.Unmarshal(bkt.Get(snapshotKey), &s) != nil {
			return invalid
		}
		opened, err := account.Unwrap(pw, key, slot)
		if err != nil {
			return err
		}
		defer clear(opened)
		var id identity
		if json.Unmarshal(opened, &id) != nil {
			return invalid
		}
		defer id.clear()
		a, err := auditCipher(id)
		if err != nil {
			return err
		}
		var tip auditTip
		if readSealed(a, tipKey, bkt.Get(tipKey), &tip) != nil {
			return invalid
		}
		for tip.Count < target {
			ev, err := appendEvent(bkt, id, tip, s, "audit.list", "", "succeeded", "")
			if err != nil {
				return err
			}
			tip = auditTipAfter(ev, s, tip.Origin)
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
}

func newBenchVault(b *testing.B, history int, restored bool) (string, []byte) {
	b.Helper()
	b.StopTimer()
	defer b.StartTimer()
	pw := "fixture"
	key := bytes.Repeat([]byte{7}, 16)
	if restored {
		src := filepath.Join(b.TempDir(), "source.ll")
		if err := Create(src, pw, key); err != nil {
			b.Fatal(err)
		}
		for _, title := range []string{"one", "two", "three"} {
			if _, err := AddLogin(src, pw, key, title, "owner", "value-"+title); err != nil {
				b.Fatal(err)
			}
		}
		fillBenchHistory(b, src, pw, key, uint64(history))
		archive1 := filepath.Join(b.TempDir(), "first.llb")
		kit1, err := Backup(src, archive1, pw, key)
		if err != nil {
			b.Fatal(err)
		}
		key1 := bytes.Repeat([]byte{8}, 16)
		restored1 := filepath.Join(b.TempDir(), "restored1.ll")
		if err = Restore(archive1, restored1, pw, key, kit1, key1); err != nil {
			b.Fatal(err)
		}
		archive2 := filepath.Join(b.TempDir(), "second.llb")
		kit2, err := Backup(restored1, archive2, pw, key1)
		if err != nil {
			b.Fatal(err)
		}
		key2 := bytes.Repeat([]byte{9}, 16)
		restored2 := filepath.Join(b.TempDir(), "restored2.ll")
		if err = Restore(archive2, restored2, pw, key1, kit2, key2); err != nil {
			b.Fatal(err)
		}
		fillBenchHistory(b, restored2, pw, key2, uint64(history))
		return restored2, key2
	}
	path := filepath.Join(b.TempDir(), "vault.ll")
	if err := Create(path, pw, key); err != nil {
		b.Fatal(err)
	}
	for _, title := range []string{"one", "two", "three"} {
		if _, err := AddLogin(path, pw, key, title, "owner", "value-"+title); err != nil {
			b.Fatal(err)
		}
	}
	if history > 1 {
		fillBenchHistory(b, path, pw, key, uint64(history-1))
	}
	return path, key
}

func openBenchSession(b *testing.B, path string, key []byte) *Session {
	b.Helper()
	s, err := UnlockSession(path, []byte("fixture"), key, 15*time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	return s
}

func benchmarkReadAuthenticated(b *testing.B, s *Session) {
	b.Run("forced-cold-full-verifier", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.clearAuditCache()
			if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("warm-verified-prefix", func(b *testing.B) {
		b.ReportAllocs()
		if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchmarkSessionList(b *testing.B, s *Session) {
	b.Run("forced-cold-full-verifier", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.clearAuditCache()
			if _, err := s.List("active"); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("warm-verified-prefix", func(b *testing.B) {
		b.ReportAllocs()
		if _, err := s.List("active"); err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := s.List("active"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAuditCacheReadAuthenticatedItems(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("history-%d", n), func(b *testing.B) {
			path, key := newBenchVault(b, n, false)
			s := openBenchSession(b, path, key)
			b.StopTimer()
			defer func() { s.Lock() }()
			b.StartTimer()
			benchmarkReadAuthenticated(b, s)
		})
	}
}

func BenchmarkAuditCacheSessionList(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("history-%d", n), func(b *testing.B) {
			path, key := newBenchVault(b, n, false)
			s := openBenchSession(b, path, key)
			b.StopTimer()
			defer func() { s.Lock() }()
			b.StartTimer()
			benchmarkSessionList(b, s)
		})
	}
}

func BenchmarkAuditCacheRestoredChain(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("history-%d", n), func(b *testing.B) {
			path, key := newBenchVault(b, n, true)
			s := openBenchSession(b, path, key)
			b.StopTimer()
			defer func() { s.Lock() }()
			b.StartTimer()
			benchmarkReadAuthenticated(b, s)
		})
	}
}
