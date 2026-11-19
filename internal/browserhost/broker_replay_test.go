package browserhost

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// replayClock is a test seam for time.Now. Its readings derive from a real
// time.Now(), so they carry a monotonic component, and only the test moves
// time, deterministically, by advance.
type replayClock struct {
	mu      sync.Mutex
	base    time.Time
	elapsed time.Duration
	err     error
}

func newReplayClock() *replayClock { return &replayClock{base: time.Now()} }

func (c *replayClock) Read() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return time.Time{}, c.err
	}
	return c.base.Add(c.elapsed), nil
}

func (c *replayClock) advance(d time.Duration) {
	c.mu.Lock()
	c.elapsed += d
	c.mu.Unlock()
}

func (c *replayClock) setErr(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

func replayCache(slots int, ttl time.Duration, clock *replayClock) *cliRunNonceCache {
	c := newCLIRunNonceCacheSlots(ttl, slots)
	c.now = clock.Read
	return c
}

// replayReserve records a nonce-shaped key for one fixture peer.
func replayReserve(c *cliRunNonceCache, n int) bool {
	key := cliRunNonceKey(replayPeer(), strings.Repeat("0", 31)+strconv.FormatInt(int64(n), 16))
	return c.reserve(cliRunNonceDigest(key))
}

func replayPeer() Peer { return Peer{User: "UID 501", PID: 42, Process: "/bin/locklark"} }

func replayLive(t *testing.T, c *cliRunNonceCache) int {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	live := 0
	for _, e := range c.entries[:c.fixed] {
		if e.digest != ([sha256.Size]byte{}) {
			live++
		}
	}
	return live
}

func TestCLIRunNonceCacheIsFixedAndBounded(t *testing.T) {
	// The bound must be real slot storage inside the value: a time and a digest
	// per slot, never a slice that could grow.
	bound := cliRunNonceSlots * (int(unsafe.Sizeof(time.Time{})) + sha256.Size)
	full := newCLIRunNonceCache(cliRunNonceTTL)
	if size := int(unsafe.Sizeof(*full)); size < bound {
		t.Fatalf("cliRunNonceCache is %d bytes, smaller than its %d-byte slots", size, bound)
	}
	if full.fixed != cliRunNonceSlots || len(full.entries) != cliRunNonceSlots {
		t.Fatalf("production cache has %d fixed of %d slots", full.fixed, len(full.entries))
	}
	if full.ttl != cliRunNonceTTL {
		t.Fatalf("production TTL %v, want %v", full.ttl, cliRunNonceTTL)
	}
	for _, tc := range []struct{ slots, want int }{{0, cliRunNonceSlots}, {-1, cliRunNonceSlots}, {cliRunNonceSlots, cliRunNonceSlots}, {cliRunNonceSlots + 1, cliRunNonceSlots}, {3, 3}} {
		if got := newCLIRunNonceCacheSlots(time.Minute, tc.slots).fixed; got != tc.want {
			t.Fatalf("slots %d: active %d, want %d", tc.slots, got, tc.want)
		}
	}
	var nilCache *cliRunNonceCache
	if nilCache.reserve(cliRunNonceDigest("x")) {
		t.Fatal("nil cache accepted a nonce")
	}
}

func TestCLIRunNonceCacheFullRefusesWithoutEvicting(t *testing.T) {
	c := replayCache(4, time.Minute, newReplayClock())
	for i := 0; i < 4; i++ {
		if !replayReserve(c, i) {
			t.Fatalf("nonce %d refused with capacity free", i)
		}
	}
	if replayReserve(c, 99) {
		t.Fatal("full cache accepted a new nonce")
	}
	for i := 0; i < 4; i++ {
		if replayReserve(c, i) {
			t.Fatalf("recorded nonce %d was replayed or evicted", i)
		}
	}
	if live := replayLive(t, c); live != 4 {
		t.Fatalf("occupancy changed to %d", live)
	}
}

func TestCLIRunNonceCacheReleasesAtExactTTLOnly(t *testing.T) {
	clock := newReplayClock()
	c := replayCache(1, 30*time.Second, clock)
	if !replayReserve(c, 1) || replayReserve(c, 1) {
		t.Fatal("first record or replay check failed")
	}
	clock.advance(30*time.Second - time.Nanosecond)
	if replayReserve(c, 1) {
		t.Fatal("nonce released before its full TTL")
	}
	if replayReserve(c, 2) {
		t.Fatal("slot freed before the full TTL")
	}
	clock.advance(time.Nanosecond) // exactly one TTL after recording
	if !replayReserve(c, 2) {
		t.Fatal("slot was not reused at exactly the TTL boundary")
	}
	if replayReserve(c, 2) || replayReserve(c, 1) {
		t.Fatal("nonce recorded at the boundary was accepted twice")
	}
}

func TestCLIRunNonceCacheConcurrentDuplicateRecordsOnce(t *testing.T) {
	const workers = 64
	c := replayCache(8, time.Minute, newReplayClock())
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if replayReserve(c, 7) {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("concurrent duplicate recorded %d times, want 1", got)
	}
}

func TestCLIRunNonceCachePeerSeparationAndCaseFolding(t *testing.T) {
	clock := newReplayClock()
	c := replayCache(4, time.Minute, clock)
	peer := replayPeer()
	nonce := strings.Repeat("ab", 16)
	lower := cliRunNonceDigest(cliRunNonceKey(peer, nonce))
	upper := cliRunNonceDigest(cliRunNonceKey(peer, strings.ToUpper(nonce)))
	if lower != upper {
		t.Fatal("hex case changes the replay key")
	}
	if !c.reserve(lower) || c.reserve(upper) {
		t.Fatal("case-variant nonce was not treated as a replay")
	}
	for _, other := range []Peer{
		{User: peer.User, PID: peer.PID + 1, Process: peer.Process},
		{User: "UID 999", PID: peer.PID, Process: peer.Process},
		{User: peer.User, PID: peer.PID, Process: peer.Process + "x"},
	} {
		if !c.reserve(cliRunNonceDigest(cliRunNonceKey(other, nonce))) {
			t.Fatalf("peer %+v was blocked by another peer's nonce", other)
		}
	}
	// The raw nonce is not stored: only a keyed digest reaches the cache.
	if lower == sha256.Sum256([]byte(nonce)) || lower == sha256.Sum256([]byte(peer.User+nonce)) {
		t.Fatal("replay key is an unbound hash of the raw nonce")
	}
}

func TestCLIRunNonceMalformedRejectedBeforeCapacity(t *testing.T) {
	for _, bad := range []string{
		"",
		strings.Repeat("ab", 15),
		strings.Repeat("ab", 65),
		strings.Repeat("ab", 16) + "a",
		strings.Repeat("ab", 15) + "zz",
		strings.Repeat("ab", 15) + "a\x00",
	} {
		if validCLIRunNonce(bad) {
			t.Fatalf("malformed nonce of length %d accepted", len(bad))
		}
	}
	for _, ok := range []string{strings.Repeat("ab", 16), strings.Repeat("AB", 64)} {
		if !validCLIRunNonce(ok) {
			t.Fatalf("valid nonce of length %d refused", len(ok))
		}
	}

	saved := brokerCLIRunNonces
	brokerCLIRunNonces = replayCache(1, time.Minute, newReplayClock())
	t.Cleanup(func() { brokerCLIRunNonces = saved })
	peer, nonce := replayPeer(), strings.Repeat("cd", 16)
	if e := consumeCLIRunNonce(peer, "not-a-nonce"); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("malformed nonce returned %v", e)
	}
	if e := consumeCLIRunNonce(peer, nonce); e != nil {
		t.Fatalf("malformed nonce consumed capacity: %v", e)
	}
}

func TestCLIRunNonceConsumeRecordsBeforeApproval(t *testing.T) {
	saved := brokerCLIRunNonces
	brokerCLIRunNonces = replayCache(2, time.Minute, newReplayClock())
	t.Cleanup(func() { brokerCLIRunNonces = saved })
	peer, nonce := replayPeer(), strings.Repeat("cd", 16)

	if e := consumeCLIRunNonce(peer, nonce); e != nil {
		t.Fatalf("first use refused: %v", e)
	}
	if e := consumeCLIRunNonce(peer, strings.ToUpper(nonce)); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("case-variant replay returned %v, want errCLIRunInvalid", e)
	}
	other := peer
	other.PID++
	if e := consumeCLIRunNonce(other, nonce); e != nil {
		t.Fatalf("another peer was blocked: %v", e)
	}
	if e := consumeCLIRunNonce(peer, strings.Repeat("ef", 16)); !errors.Is(e, errCLIRunInvalid) {
		t.Fatalf("full cache returned %v, want errCLIRunInvalid", e)
	}
}

func TestCLIRunNonceClockFailureFailsClosed(t *testing.T) {
	clock := newReplayClock()
	c := replayCache(2, time.Minute, clock)
	peer, nonce := replayPeer(), strings.Repeat("cd", 16)
	key := cliRunNonceDigest(cliRunNonceKey(peer, nonce))
	if !c.reserve(key) || replayLive(t, c) != 1 {
		t.Fatal("setup record failed")
	}
	clock.advance(time.Hour) // far past the TTL, but never observed as expired
	clock.setErr(errors.New("clock unavailable"))
	if c.reserve(key) || c.reserve(cliRunNonceDigest("another-nonce")) {
		t.Fatal("a failed clock read recorded a nonce")
	}
	if live := replayLive(t, c); live != 1 {
		t.Fatalf("failed clock read expired a record: occupancy %d", live)
	}
	// A zero reading without an error is a failed read too.
	c.now = func() (time.Time, error) { return time.Time{}, nil }
	if c.reserve(key) || replayLive(t, c) != 1 {
		t.Fatal("zero clock reading was accepted or expired a record")
	}
	// The clock recovers and reveals an hour that passed unseen: the recorded
	// nonce may now be released, but a record made after the outage still holds.
	c.now = clock.Read
	clock.setErr(nil)
	peer2 := peer
	peer2.PID++
	key2 := cliRunNonceDigest(cliRunNonceKey(peer2, nonce))
	if !c.reserve(key2) || c.reserve(key2) {
		t.Fatal("fresh record was not held for a full TTL after recovery")
	}
	if !c.reserve(key) {
		t.Fatal("recorded nonce was not released after an observed hour")
	}
	clock.advance(time.Minute - time.Nanosecond)
	if c.reserve(key) {
		t.Fatal("nonce released before its full observed TTL")
	}
	clock.advance(time.Nanosecond)
	if !c.reserve(key) {
		t.Fatal("recorded nonce was not released after a full TTL")
	}
}
