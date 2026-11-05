package personal

import (
	"sync"
	"sync/atomic"
	"time"
)

// One gate arbitrates persistence of either a mutation or an authenticated
// refusal audit. A commit-won gate never by itself means the data was saved.
type MutationGate struct {
	mu    sync.Mutex
	state atomic.Uint32
	until time.Time
}

func NewMutationGate(until time.Time) *MutationGate { return &MutationGate{until: until} }
func (g *MutationGate) Cancel() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state.CompareAndSwap(0, 2)
}
func (g *MutationGate) CommitWon() bool { return g != nil && g.state.Load() == 1 }
func (g *MutationGate) Pending() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !time.Now().Before(g.until) {
		g.state.CompareAndSwap(0, 2)
	}
	return g.state.Load() == 0
}
func (g *MutationGate) Shorten(until time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if until.Before(g.until) {
		g.until = until
	}
}
func (g *MutationGate) win() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !time.Now().Before(g.until) {
		g.state.CompareAndSwap(0, 2)
		return false
	}
	return g.state.CompareAndSwap(0, 1)
}
func (*MutationGate) String() string               { return "[mutation gate]" }
func (*MutationGate) GoString() string             { return "[mutation gate]" }
func (*MutationGate) MarshalJSON() ([]byte, error) { return nil, ErrMutationRefused }

// BrowserSaveGate preserves the browser API while sharing neutral arbitration.
type BrowserSaveGate = MutationGate

func NewBrowserSaveGate(until time.Time) *BrowserSaveGate { return NewMutationGate(until) }
