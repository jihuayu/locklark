package browserhost

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bounds for the process-local CLI-run nonce replay cache. The cache has
// exactly cliRunNonceSlots slots and never grows. A recorded nonce is released
// only after it has outlived the full TTL; once released its slot is reused. A
// full cache of unexpired nonces refuses new nonces instead of evicting one:
// a recorded nonce is never forgotten before it expires.
const (
	cliRunNonceSlots = 4096
	cliRunNonceTTL   = 2 * time.Minute
)

// cliRunNonceCache consumes each CLI-run nonce at most once per authenticated
// OS user, independent of a process's PID or executable path. A nonce is
// recorded atomically under a mutex before any later approval result, and
// recording it is final: no outcome (approved, refused, cancelled, timed out,
// or never delivered) ever removes or shortens it.
//
// Only a digest of the authenticated user label and the case-folded nonce is
// kept, never the raw nonce.
//
// Expiry is elapsed time measured as now.Sub(created). The production clock
// (time.Now) gives time values that carry a Go monotonic reading, so both
// created and now share one monotonic timeline and a wall-clock step (NTP or a
// manual clock change) cannot make expiry fire early. Any Add on such a value
// keeps its monotonic reading, so the test seam that does base := time.Now()
// and returns base.Add(elapsed) measures the same way. A wall-only value
// such as time.Unix carries no monotonic reading; the cache takes it at face
// value and this file does not simulate wall-clock rollback. A zero or failed
// clock read fails closed: nothing is recorded and nothing expires.
type cliRunNonceCache struct {
	mu  sync.Mutex
	now func() (time.Time, error) // time.Now in production
	// fixed is the active slot count: entries[:fixed], never grown.
	ttl   time.Duration
	fixed int
	// entries holds one record per slot; digest is zero while the slot is free.
	entries [cliRunNonceSlots]cliRunNonceEntry
}

type cliRunNonceEntry struct {
	created time.Time
	digest  [sha256.Size]byte
}

// newCLIRunNonceCache returns the fixed cliRunNonceSlots-slot cache.
func newCLIRunNonceCache(ttl time.Duration) *cliRunNonceCache {
	return newCLIRunNonceCacheSlots(ttl, cliRunNonceSlots)
}

// newCLIRunNonceCacheSlots builds a cache using the first slots of the fixed
// entry array, for tests that need few slots. Slots outside (0, cliRunNonceSlots]
// use the full array; the TTL is clamped to (0, cliRunNonceTTL].
func newCLIRunNonceCacheSlots(ttl time.Duration, slots int) *cliRunNonceCache {
	if ttl <= 0 || ttl > cliRunNonceTTL {
		ttl = cliRunNonceTTL
	}
	if slots < 1 || slots > cliRunNonceSlots {
		slots = cliRunNonceSlots
	}
	return &cliRunNonceCache{
		// time.Now carries a monotonic reading, so expiry is monotonic.
		now:   func() (time.Time, error) { return time.Now(), nil },
		ttl:   ttl,
		fixed: slots,
	}
}

// reserve records digest unless it is already recorded and unexpired. It
// returns true only for the call that records it. On a failed or zero clock
// read it records nothing and expires nothing; when every active slot holds an
// unexpired record it records nothing. The caller holds no lock.
func (c *cliRunNonceCache) reserve(digest [sha256.Size]byte) bool {
	if c == nil || digest == ([sha256.Size]byte{}) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.read()
	if err != nil || now.IsZero() {
		return false
	}
	for _, e := range c.entries[:c.fixed] {
		if e.digest == digest && now.Sub(e.created) < c.ttl {
			return false
		}
	}
	for i := range c.entries[:c.fixed] {
		e := &c.entries[i]
		if e.digest == ([sha256.Size]byte{}) || now.Sub(e.created) >= c.ttl {
			*e = cliRunNonceEntry{created: now, digest: digest}
			return true
		}
	}
	return false // full of unexpired records: fail closed, evict nothing
}

// read returns the current time; a nil seam fails closed. Callers hold c.mu.
func (c *cliRunNonceCache) read() (time.Time, error) {
	if c.now == nil {
		return time.Time{}, errors.New("cli run nonce cache clock unavailable")
	}
	return c.now()
}

// cliRunNonceDigest hashes the caller-composed cache key, so neither the raw
// nonce nor the peer label is stored.
func cliRunNonceDigest(key string) [sha256.Size]byte {
	return sha256.Sum256([]byte("locklark/cli-run/nonce/v1\x00" + key))
}

// cliRunNonceKey binds a case-folded nonce to the authenticated OS user. The
// user label comes from the transport-authenticated Peer, never from request
// data. PID and Process are deliberately absent: a new process run by the same
// user may use a fresh nonce, but it must not be able to replay a nonce already
// consumed by another process of that user. The length prefix keeps distinct
// pairs from colliding.
func cliRunNonceKey(peer Peer, nonce string) string {
	return peer.User + "\x00" + strconv.Itoa(len(nonce)) + ":" + strings.ToLower(nonce)
}

// CLIRun nonce shape: 16 to 64 bytes of hex.
const (
	cliRunNonceMinHex = 32
	cliRunNonceMaxHex = 128
)

// validCLIRunNonce accepts only an even-length hex string of 32 to 128
// characters (16 to 64 bytes).
func validCLIRunNonce(value string) bool {
	if len(value) < cliRunNonceMinHex || len(value) > cliRunNonceMaxHex || len(value)%2 != 0 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !cliRunNonceHexDigit(value[i]) {
			return false
		}
	}
	return true
}

func cliRunNonceHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// consumeCLIRunNonce records nonce for the authenticated OS user before any
// approval result. A missing authenticated user label or a malformed nonce is
// rejected before the cache is touched, so it consumes no capacity. It returns
// errCLIRunInvalid for a malformed, unauthenticated, or replayed nonce, a full
// cache, or an unavailable clock: the request is refused in every case.
func consumeCLIRunNonce(peer Peer, nonce string) error {
	if peer.User == "" || !validCLIRunNonce(nonce) {
		return errCLIRunInvalid
	}
	if !brokerCLIRunNonces.reserve(cliRunNonceDigest(cliRunNonceKey(peer, nonce))) {
		return errCLIRunInvalid
	}
	return nil
}

// brokerCLIRunNonces is the process-wide replay cache for brokered CLI-runs.
var brokerCLIRunNonces = newCLIRunNonceCache(cliRunNonceTTL)
