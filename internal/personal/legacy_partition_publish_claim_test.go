package personal

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestLegacyPartitionPublishClaimArbitratesDeadlinesAtGrant(t *testing.T) {
	base := time.Now()
	for _, tc := range []struct {
		name         string
		last         time.Time
		idle         time.Duration
		fullUnlock   time.Time
		sample       time.Time
		cancel       bool
		want         error
		wantMaterial bool
	}{
		{
			name: "full-factor-deadline-at-grant", last: base, idle: time.Hour,
			fullUnlock: base, sample: base.Add(passkeyTransferFullFactorWindow),
			want: ErrFullFactorRequired, wantMaterial: true,
		},
		{
			name: "idle-deadline-at-grant", last: base, idle: time.Minute,
			fullUnlock: base, sample: base.Add(time.Minute),
			want: ErrSessionLocked,
		},
		{
			name: "idle-and-full-factor-deadline-at-grant", last: base, idle: time.Minute,
			fullUnlock: base, sample: base.Add(passkeyTransferFullFactorWindow),
			want: ErrFullFactorRequired,
		},
		{
			name: "canceled-and-idle-deadline-at-grant", last: base, idle: time.Minute,
			fullUnlock: base, sample: base.Add(time.Minute), cancel: true,
			want: context.Canceled,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			s := &Session{
				path:       root,
				material:   []byte("synthetic-claim-material"),
				slotDigest: [32]byte{1},
				last:       tc.last,
				idle:       tc.idle,
				fullUnlock: tc.fullUnlock,
			}
			claim, err := s.BeginLegacyPartitionPublishClaim()
			if err != nil {
				t.Fatal("CLAIM_BEGIN_FAILED")
			}
			defer claim.Release(s)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			queued := make(chan struct{}, 1)
			legacyPartitionClaimTestHook = func(stage string) time.Time {
				switch stage {
				case "before-save-mu":
					if tc.cancel {
						cancel()
					}
					select {
					case queued <- struct{}{}:
					default:
					}
				case "sample-time":
					return tc.sample
				}
				return time.Time{}
			}
			t.Cleanup(func() { legacyPartitionClaimTestHook = nil })

			s.saveMu.Lock()
			result := make(chan error, 1)
			go func() {
				result <- claim.Claim(ctx, s, LegacyPartitionPhasePrepare)
			}()
			<-queued
			s.saveMu.Unlock()

			if got := <-result; !errors.Is(got, tc.want) {
				t.Fatalf("claim error = %v, want typed deadline", got)
			}
			if claim.phase != 0 {
				t.Fatal("CLAIM_PHASE_ADVANCED")
			}
			if claim.gate == nil || claim.gate.Pending() {
				t.Fatal("CLAIM_GATE_NOT_CANCELLED")
			}
			if tc.wantMaterial {
				if len(s.material) == 0 {
					t.Fatal("CLAIM_MATERIAL_CLEARED_EARLY")
				}
			} else if len(s.material) != 0 {
				t.Fatal("CLAIM_MATERIAL_NOT_CLEARED")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("CLAIM_PERFORMED_FILESYSTEM_WORK")
			}
		})
	}
}
