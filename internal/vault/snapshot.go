// Package vault implements the signed, offline storage experiment. There is one
// synthetic vault per trust anchor. It is not a production membership service.
package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"filippo.io/age"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"github.com/jihuayu/locklark/third_party/gokeepasslib/wrappers"
)

type Snapshot struct {
	Epoch                         uint64
	Database, Envelope, Signature []byte
}

const MaxPayload = 16 << 20

// The stored KDBX snapshot exceeds MaxPayload: KDBX headers, the attachment
// index and protected-value framing add per-item overhead, and the personal
// store persists the snapshot as JSON (base64 inflates binary by 4/3) next to
// the account metadata in the same small value. authenticateState therefore
// admits everything this bound allows on decode, and seal rejects anything
// that could not be read back.
func MaxStoredSnapshot() int { return maxStoredSnapshot }

const maxStoredSnapshot = 30 << 20

var ErrSnapshot = errors.New("invalid or unexpected snapshot")

// The signature binds both exact artifacts and their epoch before any KDBX
// header is parsed. The caller supplies the independently pinned public key.
func (s Snapshot) signed() []byte {
	b := []byte("locklark/m0/vault-snapshot/v1\x00")
	b = binary.BigEndian.AppendUint64(b, s.Epoch)
	for _, p := range [][]byte{s.Database, s.Envelope} {
		h := sha256.Sum256(p)
		b = append(b, h[:]...)
	}
	return b
}

func Seal(payload []byte, epoch uint64, recipients []*age.X25519Recipient, signer ed25519.PrivateKey) (Snapshot, error) {
	return seal(payload, nil, epoch, recipients, signer)
}

func seal(payload []byte, items []Item, epoch uint64, recipients []*age.X25519Recipient, signer ed25519.PrivateKey) (Snapshot, error) {
	if epoch == 0 || len(recipients) == 0 || len(recipients) > 64 || len(payload) > MaxPayload || len(signer) != ed25519.PrivateKeySize {
		return Snapshot{}, ErrSnapshot
	}
	allowed := make([]age.Recipient, 0, len(recipients))
	seen := make(map[string]bool)
	for _, r := range recipients {
		if r == nil || seen[r.String()] {
			return Snapshot{}, ErrSnapshot
		}
		seen[r.String()] = true
		allowed = append(allowed, r)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return Snapshot{}, err
	}
	defer clear(key)
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	// This transforms a random per-epoch file key, not an account password.
	db.Header.FileHeaders.KdfParameters.UUID = kdbx.KdfArgon2id
	db.Header.FileHeaders.KdfParameters.Memory = 16 << 20
	db.Header.FileHeaders.KdfParameters.Iterations = 3
	var err error
	db.Credentials, err = kdbx.NewKeyDataCredentials(key)
	if err != nil {
		return Snapshot{}, err
	}
	if items == nil {
		group := kdbx.NewGroup()
		group.Name = "Locklark"
		e := kdbx.NewEntry()
		e.Values = []kdbx.ValueData{{Key: "Title", Value: kdbx.V{Content: "Preview"}}, {Key: "Notes", Value: kdbx.V{Content: base64.StdEncoding.EncodeToString(payload), Protected: wrappers.NewBoolWrapper(true)}}}
		group.Entries = []kdbx.Entry{e}
		db.Content.Root.Groups = []kdbx.Group{group}
	} else if err := writeItems(db, payload, items); err != nil {
		return Snapshot{}, err
	}
	if err := db.LockProtectedEntries(); err != nil {
		return Snapshot{}, err
	}
	var data, env bytes.Buffer
	if err := kdbx.NewEncoder(&data).Encode(db); err != nil {
		return Snapshot{}, err
	}
	if data.Len() > maxStoredSnapshot {
		return Snapshot{}, ErrSnapshot
	}
	w, err := age.Encrypt(&env, allowed...)
	if err != nil {
		return Snapshot{}, err
	}
	if _, err := w.Write(key); err != nil {
		return Snapshot{}, err
	}
	if err := w.Close(); err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{Epoch: epoch, Database: data.Bytes(), Envelope: env.Bytes()}
	s.Signature = ed25519.Sign(signer, s.signed())
	return s, nil
}

func unwrap(envelope []byte, id *age.X25519Identity) ([]byte, error) {
	if id == nil {
		return nil, ErrSnapshot
	}
	r, err := age.Decrypt(bytes.NewReader(envelope), id)
	if err != nil {
		return nil, err
	}
	k, err := io.ReadAll(io.LimitReader(r, 33))
	if err != nil || len(k) != 32 {
		clear(k)
		return nil, ErrSnapshot
	}
	return k, nil
}

func VerifySnapshot(s Snapshot, authority ed25519.PublicKey, expectedEpoch uint64) error {
	if expectedEpoch == 0 || expectedEpoch != s.Epoch || len(authority) != ed25519.PublicKeySize || len(s.Database) > maxStoredSnapshot || len(s.Envelope) > 128<<10 || !ed25519.Verify(authority, s.signed(), s.Signature) {
		return ErrSnapshot
	}
	return nil
}
func Open(s Snapshot, id *age.X25519Identity, authority ed25519.PublicKey, expectedEpoch uint64) ([]byte, error) {
	data, items, err := OpenItems(s, id, authority, expectedEpoch)
	if err == nil && items != nil {
		clear(data)
		return nil, ErrSnapshot
	}
	return data, err
}

// OpenItems returns nil items only for the previous single-payload preview format.
func OpenItems(s Snapshot, id *age.X25519Identity, authority ed25519.PublicKey, expectedEpoch uint64) ([]byte, []Item, error) {
	if err := VerifySnapshot(s, authority, expectedEpoch); err != nil {
		return nil, nil, err
	}
	// Older previews and new snapshots are both KDBX 4.1. Do not dispatch
	// a signed but unsupported header into an unbounded legacy KDF path.
	var format kdbx.Signature
	if err := binary.Read(bytes.NewReader(s.Database), binary.LittleEndian, &format); err != nil || format != kdbx.DefaultKDBX41Sig {
		return nil, nil, ErrSnapshot
	}
	key, err := unwrap(s.Envelope, id)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	db := kdbx.NewDatabase()
	db.Credentials, err = kdbx.NewKeyDataCredentials(key)
	if err != nil {
		return nil, nil, err
	}
	if err := kdbx.NewDecoder(bytes.NewReader(s.Database)).Decode(db); err != nil {
		return nil, nil, err
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, nil, err
	}
	if db.Content == nil || db.Content.Root == nil || len(db.Content.Root.Groups) != 1 {
		return nil, nil, ErrSnapshot
	}
	g := db.Content.Root.Groups[0]
	if g.Name == itemGroup {
		return readItems(db, g)
	}
	if g.Name != "Locklark" || len(g.Entries) != 1 || g.Entries[0].GetContent("Title") != "Preview" {
		return nil, nil, ErrSnapshot
	}
	data, err := base64.StdEncoding.DecodeString(g.Entries[0].GetContent("Notes"))
	if err != nil || len(data) > MaxPayload {
		return nil, nil, ErrSnapshot
	}
	return data, nil, nil
}
