package personal

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Opt-in HIBP checks must work after a system quick unlock exactly as after a
// password unlock: the session starts with the production client installed.
func TestSystemUnlockInitializesHIBPClient(t *testing.T) {
	path, key, _ := revealFixture(t)
	store := &testSystemStore{values: map[string][]byte{}}
	full, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if full.hibp == nil {
		t.Fatal("password unlock has no HIBP client")
	}
	if err = full.EnableSystemUnlock(store); err != nil {
		full.Lock()
		t.Fatal(err)
	}
	full.Lock()

	s, err := UnlockWithSystemContext(context.Background(), path, store, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	if s.hibp == nil {
		t.Fatal("system quick unlock left the HIBP client uninitialized")
	}
	if !s.fullUnlock.IsZero() {
		t.Fatal("system quick unlock fabricated a full-factor unlock timestamp")
	}
	// Swap in the synthetic transport so the opt-in scan is exercised
	// end-to-end without touching the network.
	sum := sha1.Sum([]byte("private-value\t\"quoted\"\n"))
	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))
	lookup := &fakeRangeLookup{results: map[string]map[string]int{hexSum[:5]: {hexSum[5:]: 7}}}
	s.hibp = lookup
	report, err := s.WatchtowerContext(context.Background(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.HIBPChecked || report.HIBPError != "" || report.Counts.Vulnerable != 1 {
		t.Fatalf("checked report after system unlock=%+v", report)
	}
	if got := lookup.prefixes(); len(got) == 0 {
		t.Fatal("opt-in HIBP scan skipped the synthetic lookup after system unlock")
	}
}
