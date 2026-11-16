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
	genesisIntentMagic         = "LLGI"
	genesisIntentVersion       = uint16(1)
	genesisIntentPrefix        = 4 + 2 + 2 + 1 + 1 + 1 + 8 + 4 + 32 + 32
	genesisIntentDigestSize    = sha256.Size
	genesisIntentDigestDomain  = "locklark vault-file genesis intent v1\x00"
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
	return b != nil && (b.Get([]byte(genesisIntentKey)) != nil || b.Bucket([]byte(genesisIntentKey)) != nil)
}

// readGenesisIntentOnly requires one top-level journal bucket with exactly one
// value, so no old or unknown writer state can coexist with this lifecycle.
func readGenesisIntentOnly(tx *bolt.Tx) (GenesisIntent, error) {
	count := 0
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if !bytes.Equal(name, []byte(bucketName)) {
			return ErrCorrupt
		}
		count++
		return nil
	}); err != nil || count != 1 {
		return GenesisIntent{}, ErrCorrupt
	}
	b := tx.Bucket([]byte(bucketName))
	count = 0
	if err := b.ForEach(func(k, v []byte) error {
		if !bytes.Equal(k, []byte(genesisIntentKey)) || v == nil {
			return ErrCorrupt
		}
		count++
		return nil
	}); err != nil || count != 1 {
		return GenesisIntent{}, ErrCorrupt
	}
	return decodeGenesisIntent(b.Get([]byte(genesisIntentKey)))
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
		return b.Delete([]byte(genesisIntentKey))
	})
}
