package personal

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	bolt "go.etcd.io/bbolt"
)

// The session-local audit cache stores only verification verdicts for an exact
// ciphertext prefix. It never stores event bodies, plaintext items, passwords,
// seeds or passkey material. Cache entries are treated as immutable: callers
// always receive clones of the revision map.
const (
	auditFingerprintDomain = "locklark/personal/audit-prefix/v1\x00"
	auditArchiveDomain     = "locklark/personal/audit-archive/v1\x00"
	maxAuditEventBytes     = 8192
)

// auditCache binds a verified prefix to the immutable session identity (slot
// digest plus an audit-public-key digest) and to the exact authenticated tip.
type auditCache struct {
	slotDigest    [32]byte
	auditPub      [32]byte
	count         uint64
	last          string
	origin        string
	prefix        [32]byte
	revisions     map[string]string
	archiveDigest [32]byte
	archiveValid  bool
	hashedBytes   uint64
}

func cloneRevisions(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (c *auditCache) clone() *auditCache {
	if c == nil {
		return nil
	}
	return &auditCache{
		slotDigest:    c.slotDigest,
		auditPub:      c.auditPub,
		count:         c.count,
		last:          c.last,
		origin:        c.origin,
		prefix:        c.prefix,
		revisions:     cloneRevisions(c.revisions),
		archiveDigest: c.archiveDigest,
		archiveValid:  c.archiveValid,
		hashedBytes:   c.hashedBytes,
	}
}

// auditFingerprint hashes every persisted event ciphertext in key order. Each
// record is domain separated and framed with its fixed-width sequence key and
// raw length, so reordered, inserted, deleted, nested, empty, malformed or
// oversized entries cannot preserve a prefix digest. prefixCount selects how
// many initial records are folded into the second digest.
func auditFingerprint(events *bolt.Bucket, tipCount, prefixCount uint64) (count uint64, full, prefix [32]byte, hashed uint64, err error) {
	if events == nil || tipCount == 0 || prefixCount > tipCount {
		return 0, full, prefix, 0, invalid
	}
	fullHash := sha256.New()
	fullHash.Write([]byte(auditFingerprintDomain))
	var prefixHash hash.Hash
	if prefixCount > 0 {
		prefixHash = sha256.New()
		prefixHash.Write([]byte(auditFingerprintDomain))
	}
	err = events.ForEach(func(k, raw []byte) error {
		count++
		if len(k) != 8 || binary.BigEndian.Uint64(k) != count || count > tipCount {
			return invalid
		}
		if len(raw) == 0 || len(raw) > maxAuditEventBytes {
			return invalid
		}
		writeAuditFrame(fullHash, count, raw)
		if prefixHash != nil && count <= prefixCount {
			writeAuditFrame(prefixHash, count, raw)
		}
		hashed += uint64(len(raw))
		return nil
	})
	if err != nil {
		return 0, full, prefix, hashed, err
	}
	if count != tipCount {
		return 0, full, prefix, hashed, invalid
	}
	copy(full[:], fullHash.Sum(nil))
	if prefixHash != nil {
		copy(prefix[:], prefixHash.Sum(nil))
	} else {
		prefix = full
	}
	return count, full, prefix, hashed, nil
}

func writeAuditFrame(h hash.Hash, sequence uint64, raw []byte) {
	var frame [16]byte
	binary.BigEndian.PutUint64(frame[0:8], sequence)
	binary.BigEndian.PutUint64(frame[8:16], uint64(len(raw)))
	h.Write(frame[:])
	h.Write(raw)
}

// archiveFingerprint is a fast integrity check over the exact persisted archive
// ciphertext. Authentication of the anchor still comes from the sealed tip.
func archiveFingerprint(raw []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(auditArchiveDomain))
	writeAuditFrame(h, 0, raw)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func eventKey(sequence uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, sequence)
}

// replayAuditTail verifies only events after the cached prefix using exactly
// the signature, link, sequence and revision replay rules used for cold
// history. The cached prefix hash and the authenticated tip bound the result.
func replayAuditTail(a cipher.AEAD, events *bolt.Bucket, cachedCount uint64, cachedLast string, tip auditTip, pub ed25519.PublicKey, revisions map[string]string, want bool) (uint64, string, []Event, error) {
	prev := cachedLast
	count := cachedCount
	if count > tip.Count {
		return 0, "", nil, invalid
	}
	var rows []Event
	cursor := events.Cursor()
	k, raw := cursor.Seek(eventKey(count + 1))
	for ; k != nil; k, raw = cursor.Next() {
		count++
		if len(k) != 8 || binary.BigEndian.Uint64(k) != count || count > tip.Count || len(raw) == 0 || len(raw) > maxAuditEventBytes {
			return 0, "", nil, invalid
		}
		var ev Event
		if readSealed(a, eventLabel(k), raw, &ev) != nil {
			return 0, "", nil, invalid
		}
		next, err := replayAuditEvent(ev, count, prev, tip.Origin, pub, revisions)
		if err != nil {
			return 0, "", nil, err
		}
		prev = next
		if want {
			rows = append(rows, ev)
		}
	}
	if count != tip.Count || prev != tip.Last {
		return 0, "", nil, invalid
	}
	return count, prev, rows, nil
}

// Session cache accessors are leaf locks. Session.mu may be held by callers;
// no code takes Session.mu while holding auditMu.
func (s *Session) getAuditCache(slotDigest, auditPub [32]byte) *auditCache {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	c := s.audit
	if c == nil || c.slotDigest != slotDigest || c.auditPub != auditPub {
		return nil
	}
	return c
}

func (s *Session) setAuditCache(c *auditCache) {
	if s == nil || c == nil {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	// RequestLock must prevent a late population from resurrecting the cache.
	if s.lockRequested.Load() {
		return
	}
	s.audit = c.clone()
}

func (s *Session) clearAuditCache() {
	if s == nil {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.audit = nil
}
