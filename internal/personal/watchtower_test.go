package personal

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRangeLookup records only the five-character prefixes the production
// LookupCandidates transport hands it. It deliberately ignores cancellation so
// the package-level guards are exercised even when a transport misbehaves.
type fakeRangeLookup struct {
	mu      sync.Mutex
	calls   []string
	results map[string]map[string]int
	onCall  func()
}

func (f *fakeRangeLookup) Lookup(_ context.Context, prefix string) (map[string]int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, prefix)
	onCall := f.onCall
	f.mu.Unlock()
	if onCall != nil {
		onCall()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.results[prefix], nil
}

func (f *fakeRangeLookup) prefixes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func watchtowerFixture(t *testing.T) (string, []byte, *Session) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "watchtower.ll")
	key := bytes.Repeat([]byte{7}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	if _, err := AddLogin(path, "fixture", key, "known", "fixture-user", "password"); err != nil {
		t.Fatal(err)
	}
	session, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return path, key, session
}

func auditActions(t *testing.T, path string, key []byte) []string {
	t.Helper()
	events, err := Audit(path, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	actions := make([]string, 0, len(events))
	for _, event := range events {
		actions = append(actions, event.Action)
	}
	return actions
}

func countAction(actions []string, want string) int {
	n := 0
	for _, action := range actions {
		if action == want {
			n++
		}
	}
	return n
}

func TestWatchtowerContextOfflineDefaultNeverLookup(t *testing.T) {
	path, key, session := watchtowerFixture(t)
	defer session.Lock()
	lookup := &fakeRangeLookup{}
	session.hibp = lookup
	report, err := session.Watchtower("", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(lookup.prefixes()) != 0 || report.HIBPChecked || report.HIBPError != "" {
		t.Fatalf("offline scan touched HIBP: %+v %v", report, lookup.prefixes())
	}
	actions := auditActions(t, path, key)
	if countAction(actions, watchtowerAction) != 1 || countAction(actions, hibpAction) != 0 {
		t.Fatalf("offline audit actions=%v", actions)
	}
}

func TestWatchtowerContextNilAndPreCanceledRefused(t *testing.T) {
	path, key, session := watchtowerFixture(t)
	defer session.Lock()
	lookup := &fakeRangeLookup{}
	session.hibp = lookup
	before := len(auditActions(t, path, key))
	if _, err := session.WatchtowerContext(nil, "", true); !errors.Is(err, ErrWatchtowerContext) {
		t.Fatalf("nil context: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.WatchtowerContext(canceled, "", true); !errors.Is(err, ErrWatchtowerContext) {
		t.Fatalf("pre-canceled context: %v", err)
	}
	if len(lookup.prefixes()) != 0 {
		t.Fatalf("refused context queried: %v", lookup.prefixes())
	}
	if actions := auditActions(t, path, key); len(actions) != before+1 || countAction(actions, watchtowerAction) != 0 || countAction(actions, hibpAction) != 0 {
		t.Fatalf("refused context audited: %v", actions)
	}
}

func TestWatchtowerContextHIBPPrefixOnlyAndAudit(t *testing.T) {
	path, key, session := watchtowerFixture(t)
	defer session.Lock()
	sum := sha1.Sum([]byte("password"))
	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))
	lookup := &fakeRangeLookup{results: map[string]map[string]int{hexSum[:5]: {hexSum[5:]: 42}}}
	session.hibp = lookup
	report, err := session.WatchtowerContext(context.Background(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.HIBPChecked || report.HIBPError != "" || report.Counts.Vulnerable != 1 {
		t.Fatalf("checked report=%+v", report)
	}
	if got := lookup.prefixes(); len(got) != 1 || got[0] != hexSum[:5] {
		t.Fatalf("prefixes=%v", got)
	}
	if len(report.Findings) != 1 || report.Findings[0].BreachCount != 42 || !containsFlag(report.Findings[0].Flags, "vulnerable") {
		t.Fatalf("finding=%+v", report.Findings)
	}
	actions := auditActions(t, path, key)
	if countAction(actions, watchtowerAction) != 1 || countAction(actions, hibpAction) != 2 {
		t.Fatalf("HIBP audit actions=%v", actions)
	}
	raw, err := json.Marshal(struct {
		Events []Event `json:"events"`
		Report any     `json:"report"`
	}{func() []Event { events, _ := Audit(path, "fixture", key); return events }(), report})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", hexSum, hexSum[:5], hexSum[5:], "fixture-user"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("audit/report leaked %q", secret)
		}
	}
}

func TestWatchtowerContextCanceledDuringLookupNeverClean(t *testing.T) {
	path, key, session := watchtowerFixture(t)
	defer session.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	lookup := &fakeRangeLookup{
		results: map[string]map[string]int{"5BAA6": {}},
		onCall:  cancel,
	}
	session.hibp = lookup
	if _, err := session.WatchtowerContext(ctx, "", true); !errors.Is(err, ErrWatchtowerContext) {
		t.Fatalf("canceled lookup: %v", err)
	}
	if len(lookup.prefixes()) != 1 {
		t.Fatalf("lookup calls=%v", lookup.prefixes())
	}
	actions := auditActions(t, path, key)
	if countAction(actions, watchtowerAction) != 1 || countAction(actions, hibpAction) != 1 {
		t.Fatalf("canceled audit actions=%v", actions)
	}
	if _, err := session.WatchtowerContext(ctx, "", true); !errors.Is(err, ErrWatchtowerContext) {
		t.Fatalf("replayed context: %v", err)
	}
	if len(lookup.prefixes()) != 1 {
		t.Fatalf("replayed context queried: %v", lookup.prefixes())
	}
}

func TestWatchtowerContextLockDuringLookupNoLateFinal(t *testing.T) {
	path, key, session := watchtowerFixture(t)
	lookup := &fakeRangeLookup{
		results: map[string]map[string]int{"5BAA6": {}},
		onCall:  session.RequestLock,
	}
	session.hibp = lookup
	if _, err := session.WatchtowerContext(context.Background(), "", true); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("lock during lookup: %v", err)
	}
	actions := auditActions(t, path, key)
	if countAction(actions, hibpAction) != 1 {
		t.Fatalf("late final audited: %v", actions)
	}
}

func containsFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

func TestWatchtowerOldAPIContract(t *testing.T) {
	path, _, session := watchtowerFixture(t)
	defer session.Lock()
	if _, err := session.Watchtower("not-an-origin", false); !errors.Is(err, invalid) {
		t.Fatalf("old API invalid site: %v", err)
	}
	lookup := &fakeRangeLookup{results: map[string]map[string]int{"5BAA6": {"1E4C9B93F3F0682250B6CF8331B7EE68FD8": 7}}}
	session.hibp = lookup
	report, err := session.Watchtower("", true)
	if err != nil || !report.HIBPChecked || report.Counts.Vulnerable != 1 {
		t.Fatalf("old API HIBP report=%+v err=%v", report, err)
	}
	if len(lookup.prefixes()) != 1 {
		t.Fatalf("old API lookup=%v", lookup.prefixes())
	}
	_ = path
}
