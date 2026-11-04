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
	kdbx "github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

type Snapshot struct {
	Epoch                         uint64
	Database, Envelope, Signature []byte
}

const MaxPayload = 4 << 20

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
	// The pinned library encodes Argon2d, not the planned Argon2id. This is
	// deliberately limited to synthetic fixtures encrypted with random keys.
	var err error
	db.Credentials, err = kdbx.NewKeyDataCredentials(key)
	if err != nil {
		return Snapshot{}, err
	}
	group := kdbx.NewGroup()
	group.Name = "Locklark"
	e := kdbx.NewEntry()
	e.Values = []kdbx.ValueData{{Key: "Title", Value: kdbx.V{Content: "Preview"}}, {Key: "Notes", Value: kdbx.V{Content: base64.StdEncoding.EncodeToString(payload), Protected: wrappers.NewBoolWrapper(true)}}}
	group.Entries = []kdbx.Entry{e}
	db.Content.Root.Groups = []kdbx.Group{group}
	if err := db.LockProtectedEntries(); err != nil {
		return Snapshot{}, err
	}
	var data, env bytes.Buffer
	if err := kdbx.NewEncoder(&data).Encode(db); err != nil {
		return Snapshot{}, err
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
	if expectedEpoch == 0 || expectedEpoch != s.Epoch || len(authority) != ed25519.PublicKeySize || len(s.Database) > 8<<20 || len(s.Envelope) > 128<<10 || !ed25519.Verify(authority, s.signed(), s.Signature) {
		return ErrSnapshot
	}
	return nil
}
func Open(s Snapshot, id *age.X25519Identity, authority ed25519.PublicKey, expectedEpoch uint64) ([]byte, error) {
	if err := VerifySnapshot(s, authority, expectedEpoch); err != nil {
		return nil, err
	}
	key, err := unwrap(s.Envelope, id)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	db := kdbx.NewDatabase()
	db.Credentials, err = kdbx.NewKeyDataCredentials(key)
	if err != nil {
		return nil, err
	}
	if err := kdbx.NewDecoder(bytes.NewReader(s.Database)).Decode(db); err != nil {
		return nil, err
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, err
	}
	if db.Content == nil || db.Content.Root == nil || len(db.Content.Root.Groups) != 1 || len(db.Content.Root.Groups[0].Entries) != 1 {
		return nil, ErrSnapshot
	}
	return base64.StdEncoding.DecodeString(db.Content.Root.Groups[0].Entries[0].GetContent("Notes"))
}
