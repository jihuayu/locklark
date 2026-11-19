package brokerlease

import (
	"crypto/sha256"
	"sync"
)

// MaxAdmissionsPerLease is the fixed nonce capacity of one lease instance. A
// lease that exhausts this budget refuses further admissions; it never evicts a
// live consumed nonce to make room for a replay.
const MaxAdmissionsPerLease = 256

// Nonce is one per-use value supplied by the owner. The core stores only a
// digest of it and never returns the value.
type Nonce [32]byte

type nonceDigest [sha256.Size]byte

type nonceCache struct {
	mu      sync.Mutex
	entries [MaxAdmissionsPerLease]nonceDigest
	used    int
}

// consume records nonce at most once. The caller must hold no nonceCache lock.
// A full cache refuses rather than evicting an unexpired record. There is no
// release operation: a successful consumption is final for the lease lifetime.
func (c *nonceCache) consume(nonce Nonce) error {
	if nonce == (Nonce{}) {
		return ErrNonce
	}
	digest := nonceDigest(sha256.Sum256(nonce[:]))
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < c.used; i++ {
		if c.entries[i] == digest {
			return ErrNonceReplay
		}
	}
	if c.used == len(c.entries) {
		return ErrNonceCapacity
	}
	c.entries[c.used] = digest
	c.used++
	return nil
}
