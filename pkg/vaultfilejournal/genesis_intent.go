package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// A genesis intent is opaque local bookkeeping. Its public checkpoint fields
// are comparison inputs, not a trust anchor established by this package.
type GenesisIntent struct {
	Name               string
	VaultID            string
	OwnerRootKeyID     string
	OwnerRootPublicKey []byte
	PolicySeq          uint64
	PolicyDigest       []byte
	OperationID        string
	SealedBytes        []byte
}

var (
	ErrPendingGenesisIntent = errors.New("vault file journal: pending genesis intent")
	ErrGenesisMismatch      = errors.New("vault file journal: genesis intent mismatch")
)

const (
	genesisIntentKey           = "genesis-intent"
	genesisAttemptKey          = "genesis-attempt"
	genesisIntentMagic         = "LLGI"
	genesisIntentVersion       = uint16(1)
	genesisIntentPrefix        = 4 + 2 + 2 + 1 + 1 + 1 + 8 + 4 + 32 + 32
	genesisIntentDigestSize    = sha256.Size
	genesisIntentDigestDomain  = "locklark vault-file genesis intent v1\x00"
	genesisAttemptMagic        = "LLGA"
	genesisAttemptVersion      = uint16(1)
	genesisAttemptRecordSize   = 4 + 2 + sha256.Size
	genesisAttemptDigestDomain = "locklark vault-file genesis attempt v1\x00"
	MaxGenesisIntentRecordSize = genesisIntentPrefix + vaultfilebackend.MaxNameSize + 3*MaxOperationIDBytes + MaxProposalBytes + genesisIntentDigestSize
)

func validGenesisIntent(i GenesisIntent) bool {
	return vaultfilebackend.ValidName(i.Name) && validOperationID(i.VaultID) &&
		validOperationID(i.OwnerRootKeyID) && validOperationID(i.OperationID) &&
		len(i.OwnerRootPublicKey) == 32 && i.PolicySeq == 0 && len(i.PolicyDigest) == 32 &&
		validWorkingBytes(i.SealedBytes)
}

func cloneGenesisIntent(i GenesisIntent) GenesisIntent {
	i.Name = string(bytes.Clone([]byte(i.Name)))
	i.VaultID = string(bytes.Clone([]byte(i.VaultID)))
	i.OwnerRootKeyID = string(bytes.Clone([]byte(i.OwnerRootKeyID)))
	i.OperationID = string(bytes.Clone([]byte(i.OperationID)))
	i.OwnerRootPublicKey = bytes.Clone(i.OwnerRootPublicKey)
	i.PolicyDigest = bytes.Clone(i.PolicyDigest)
	i.SealedBytes = bytes.Clone(i.SealedBytes)
	return i
}

func sameGenesisIntent(a, b GenesisIntent) bool {
	return a.Name == b.Name && a.VaultID == b.VaultID &&
		a.OwnerRootKeyID == b.OwnerRootKeyID && bytes.Equal(a.OwnerRootPublicKey, b.OwnerRootPublicKey) &&
		a.PolicySeq == b.PolicySeq && bytes.Equal(a.PolicyDigest, b.PolicyDigest) &&
		a.OperationID == b.OperationID && bytes.Equal(a.SealedBytes, b.SealedBytes)
}

func encodeGenesisIntent(i GenesisIntent) []byte {
	length := genesisIntentPrefix + len(i.Name) + len(i.VaultID) + len(i.OwnerRootKeyID) + len(i.OperationID) + len(i.SealedBytes)
	buf := make([]byte, length+genesisIntentDigestSize)
	copy(buf[:4], genesisIntentMagic)
	binary.BigEndian.PutUint16(buf[4:6], genesisIntentVersion)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(i.Name)))
	buf[8], buf[9], buf[10] = byte(len(i.VaultID)), byte(len(i.OwnerRootKeyID)), byte(len(i.OperationID))
	binary.BigEndian.PutUint64(buf[11:19], i.PolicySeq)
	binary.BigEndian.PutUint32(buf[19:23], uint32(len(i.SealedBytes)))
	copy(buf[23:55], i.OwnerRootPublicKey)
	copy(buf[55:87], i.PolicyDigest)
	off := genesisIntentPrefix
	off += copy(buf[off:], i.Name)
	off += copy(buf[off:], i.VaultID)
	off += copy(buf[off:], i.OwnerRootKeyID)
	off += copy(buf[off:], i.OperationID)
	off += copy(buf[off:], i.SealedBytes)
	h := sha256.New()
	_, _ = h.Write([]byte(genesisIntentDigestDomain))
	_, _ = h.Write(buf[:off])
	copy(buf[off:], h.Sum(nil))
	return buf
}

// decodeGenesisIntent checks the complete length and checksum before copying
// any field. A checksum is corruption detection, never authentication.
func decodeGenesisIntent(raw []byte) (GenesisIntent, error) {
	if len(raw) < genesisIntentPrefix+genesisIntentDigestSize || len(raw) > MaxGenesisIntentRecordSize ||
		!bytes.Equal(raw[:4], []byte(genesisIntentMagic)) || binary.BigEndian.Uint16(raw[4:6]) != genesisIntentVersion {
		return GenesisIntent{}, ErrCorrupt
	}
	nName := uint64(binary.BigEndian.Uint16(raw[6:8]))
	nVault, nRoot, nOp := uint64(raw[8]), uint64(raw[9]), uint64(raw[10])
	nBytes := uint64(binary.BigEndian.Uint32(raw[19:23]))
	if nName == 0 || nName > vaultfilebackend.MaxNameSize || nVault == 0 || nVault > MaxOperationIDBytes ||
		nRoot == 0 || nRoot > MaxOperationIDBytes || nOp == 0 || nOp > MaxOperationIDBytes ||
		nBytes == 0 || nBytes > MaxProposalBytes ||
		uint64(len(raw)) != uint64(genesisIntentPrefix+genesisIntentDigestSize)+nName+nVault+nRoot+nOp+nBytes {
		return GenesisIntent{}, ErrCorrupt
	}
	body := raw[:len(raw)-genesisIntentDigestSize]
	h := sha256.New()
	_, _ = h.Write([]byte(genesisIntentDigestDomain))
	_, _ = h.Write(body)
	if !bytes.Equal(h.Sum(nil), raw[len(body):]) {
		return GenesisIntent{}, ErrCorrupt
	}
	off := genesisIntentPrefix
	readString := func(n uint64) string {
		s := string(raw[off : off+int(n)])
		off += int(n)
		return s
	}
	i := GenesisIntent{Name: readString(nName), VaultID: readString(nVault),
		OwnerRootKeyID: readString(nRoot), OperationID: readString(nOp),
		OwnerRootPublicKey: bytes.Clone(raw[23:55]), PolicySeq: binary.BigEndian.Uint64(raw[11:19]),
		PolicyDigest: bytes.Clone(raw[55:87]), SealedBytes: bytes.Clone(raw[off : off+int(nBytes)])}
	if !validGenesisIntent(i) {
		return GenesisIntent{}, ErrCorrupt
	}
	return i, nil
}

func genesisIntentPresent(tx *bolt.Tx) bool {
	b := tx.Bucket([]byte(bucketName))
	return b != nil && (b.Get([]byte(genesisIntentKey)) != nil || b.Bucket([]byte(genesisIntentKey)) != nil ||
		b.Get([]byte(genesisAttemptKey)) != nil || b.Bucket([]byte(genesisAttemptKey)) != nil)
}

func encodeGenesisAttempt(intentRaw []byte) []byte {
	buf := make([]byte, genesisAttemptRecordSize)
	copy(buf[:4], genesisAttemptMagic)
	binary.BigEndian.PutUint16(buf[4:6], genesisAttemptVersion)
	h := sha256.New()
	_, _ = h.Write([]byte(genesisAttemptDigestDomain))
	_, _ = h.Write(intentRaw)
	copy(buf[6:], h.Sum(nil))
	return buf
}

// readGenesisIntentState accepts exactly the old single intent value, or that
// value plus a versioned attempt marker bound to its full canonical encoding.
// An isolated, malformed or foreign marker is never a fresh attempt.
func readGenesisIntentState(tx *bolt.Tx) (GenesisIntent, bool, error) {
	count := 0
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if !bytes.Equal(name, []byte(bucketName)) {
			return ErrCorrupt
		}
		count++
		return nil
	}); err != nil || count != 1 {
		return GenesisIntent{}, false, ErrCorrupt
	}
	b := tx.Bucket([]byte(bucketName))
	var intentRaw, attemptRaw []byte
	if err := b.ForEach(func(k, v []byte) error {
		if v == nil {
			return ErrCorrupt
		}
		switch {
		case bytes.Equal(k, []byte(genesisIntentKey)):
			intentRaw = v
		case bytes.Equal(k, []byte(genesisAttemptKey)):
			attemptRaw = v
		default:
			return ErrCorrupt
		}
		return nil
	}); err != nil || intentRaw == nil {
		return GenesisIntent{}, false, ErrCorrupt
	}
	intent, err := decodeGenesisIntent(intentRaw)
	if err != nil || !bytes.Equal(encodeGenesisIntent(intent), intentRaw) {
		return GenesisIntent{}, false, ErrCorrupt
	}
	if attemptRaw != nil && !bytes.Equal(attemptRaw, encodeGenesisAttempt(intentRaw)) {
		return GenesisIntent{}, false, ErrCorrupt
	}
	return intent, attemptRaw != nil, nil
}

func readGenesisIntentOnly(tx *bolt.Tx) (GenesisIntent, error) {
	intent, _, err := readGenesisIntentState(tx)
	return intent, err
}

func (j *Journal) initializeGenesisIntent(intent GenesisIntent) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		found := false
		if err := tx.ForEach(func(_ []byte, _ *bolt.Bucket) error {
			found = true
			return nil
		}); err != nil || found {
			return ErrJournalNotEmpty
		}
		b, err := tx.CreateBucket([]byte(bucketName))
		if err != nil {
			return err
		}
		return b.Put([]byte(genesisIntentKey), encodeGenesisIntent(intent))
	})
}

// CreateNewGenesisIntent exclusively creates one private journal containing
// only the exact opaque intent. Any failure after creation preserves its inode
// for review. It never contacts a backend or verifies sealed-file crypto.
func CreateNewGenesisIntent(path string, intent GenesisIntent) error {
	return createNewGenesisIntent(path, intent)
}

// IntentJournal exposes no legacy Save, InitializeState or working edit API.
type IntentJournal struct{ journal *Journal }

// GenesisAttemptResult is a verdict from the journal's atomic claim, not a
// caller assertion. Only NewlyClaimed permits this invocation to call Create.
type GenesisAttemptResult uint8

const (
	GenesisAttemptNewlyClaimed GenesisAttemptResult = iota + 1
	GenesisAttemptPreviouslyClaimed
)

// OpenExistingIntent opens only an existing, strict single-intent journal.
func OpenExistingIntent(path string) (*IntentJournal, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		checkPrivateDir(filepath.Dir(path)) != nil {
		return nil, ErrInvalid
	}
	j, err := openExistingIntentOnlyDatabase(path)
	if err != nil {
		return nil, err
	}
	return &IntentJournal{journal: j}, nil
}

func (g *IntentJournal) Close() error {
	if g == nil || g.journal == nil {
		return ErrClosed
	}
	return g.journal.Close()
}

// Load returns independent copies of the exact pending intent.
func (g *IntentJournal) Load() (GenesisIntent, error) {
	if g == nil || g.journal == nil {
		return GenesisIntent{}, ErrClosed
	}
	j := g.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return GenesisIntent{}, ErrClosed
	}
	var intent GenesisIntent
	err := j.db.View(func(tx *bolt.Tx) error {
		var err error
		intent, err = readGenesisIntentOnly(tx)
		return err
	})
	return intent, err
}

// ClaimGenesisAttempt atomically binds a one-time Create attempt to the exact
// pending intent. A committed marker survives restart; subsequent calls must
// only read and resolve, never Create again. If the commit result is an error,
// the caller cannot know whether the marker committed and must not Create.
// The crash window after marker commit but before Create remains Unknown:
// safety deliberately does not imply that publication will eventually occur.
func (g *IntentJournal) ClaimGenesisAttempt(expected GenesisIntent) (GenesisAttemptResult, error) {
	return g.claimGenesisAttemptWithUpdate(expected, nil)
}

// update is a private deterministic commit-result seam; production uses Bolt.
func (g *IntentJournal) claimGenesisAttemptWithUpdate(expected GenesisIntent, update func(func(*bolt.Tx) error) error) (GenesisAttemptResult, error) {
	if g == nil || g.journal == nil {
		return 0, ErrClosed
	}
	if !validGenesisIntent(expected) {
		return 0, ErrInvalid
	}
	expected = cloneGenesisIntent(expected)
	defer clear(expected.SealedBytes)
	j := g.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return 0, ErrClosed
	}
	if update == nil {
		update = j.db.Update
	}
	var result GenesisAttemptResult
	err := update(func(tx *bolt.Tx) error {
		stored, attempted, err := readGenesisIntentState(tx)
		if err != nil {
			return err
		}
		if !sameGenesisIntent(stored, expected) {
			return ErrGenesisMismatch
		}
		if attempted {
			result = GenesisAttemptPreviouslyClaimed
			return nil
		}
		if err := tx.Bucket([]byte(bucketName)).Put([]byte(genesisAttemptKey), encodeGenesisAttempt(encodeGenesisIntent(stored))); err != nil {
			return err
		}
		result = GenesisAttemptNewlyClaimed
		return nil
	})
	if err != nil {
		return 0, err
	}
	return result, nil
}

// AckGenesis is local bookkeeping only. The caller must independently verify
// that readback is authoritative, cryptographically valid and exactly this G.
// It rechecks the full intent and exact readback in one Bolt transaction.
// A storage or commit-result error does not prove whether that transaction
// committed. Close and reopen: only the exact original single-intent record,
// or the exact single generation-0 State with BaseBytes = WorkingBytes = G and
// the supplied revision, can resolve the local outcome. Any other shape needs
// review. Neither shape proves a remote write or the readback's authority.
func (g *IntentJournal) AckGenesis(expected GenesisIntent, readback []byte, revision vaultfilebackend.Revision) error {
	return g.ackGenesisWithUpdate(expected, readback, revision, nil)
}

// update is a private test seam: tests can cause a real Bolt callback to roll
// back or discard its committed result. Production always uses db.Update.
func (g *IntentJournal) ackGenesisWithUpdate(expected GenesisIntent, readback []byte, revision vaultfilebackend.Revision, update func(func(*bolt.Tx) error) error) error {
	if g == nil || g.journal == nil {
		return ErrClosed
	}
	if !validGenesisIntent(expected) || len(readback) == 0 || len(readback) > MaxProposalBytes ||
		len(revision) == 0 || len(revision) > MaxStateRevisionBytes {
		return ErrInvalid
	}
	expected = cloneGenesisIntent(expected)
	readback = bytes.Clone(readback)
	revision = vaultfilebackend.Revision(bytes.Clone([]byte(revision)))
	j := g.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	if update == nil {
		update = j.db.Update
	}
	return update(func(tx *bolt.Tx) error {
		stored, err := readGenesisIntentOnly(tx)
		if err != nil {
			return err
		}
		if !sameGenesisIntent(stored, expected) || !bytes.Equal(stored.SealedBytes, readback) {
			return ErrGenesisMismatch
		}
		b := tx.Bucket([]byte(bucketName))
		if err := b.Put([]byte(stateKey), encodeState(State{
			BaseBytes: stored.SealedBytes, WorkingBytes: stored.SealedBytes,
			RemoteRevision: revision, Generation: 0,
		})); err != nil {
			return fmt.Errorf("vault file journal: ack genesis state: %w", err)
		}
		if err := b.Delete([]byte(genesisAttemptKey)); err != nil {
			return fmt.Errorf("vault file journal: ack genesis attempt: %w", err)
		}
		return b.Delete([]byte(genesisIntentKey))
	})
}
