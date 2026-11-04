package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/age"
	kdbx "github.com/tobischo/gokeepasslib/v3"
)

func TestSnapshotKDF(t *testing.T) {
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Seal([]byte("fixture"), 1, []*age.X25519Recipient{id.Recipient()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := unwrap(s.Envelope, id)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	db := kdbx.NewDatabase()
	db.Credentials, err = kdbx.NewKeyDataCredentials(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = kdbx.NewDecoder(bytes.NewReader(s.Database)).Decode(db); err != nil {
		t.Fatal(err)
	}
	p := db.Header.FileHeaders.KdfParameters
	if !bytes.Equal(p.UUID, []byte{0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6}) || p.Version != 19 || p.Iterations != 3 || p.Parallelism != 2 || p.Memory != 16<<20 {
		t.Fatal("unexpected new KDF profile")
	}
	s.Database[10] = 3 // force legacy major version, then sign with the fixture authority
	s.Signature = ed25519.Sign(signer, s.signed())
	if _, err := Open(s, id, pub, 1); !errors.Is(err, ErrSnapshot) {
		t.Fatal("accepted non-4.1 header or dispatched to its KDF", err)
	}
}

func TestUnsupportedKDFParameters(t *testing.T) {
	for name, set := range map[string]func(*kdbx.KdfParameters){
		"unknown algorithm":      func(p *kdbx.KdfParameters) { p.UUID = []byte("unknown variant!") },
		"version":                func(p *kdbx.KdfParameters) { p.Version = 16 },
		"iterations would wrap":  func(p *kdbx.KdfParameters) { p.Iterations = 1<<32 + 1 },
		"parallelism would wrap": func(p *kdbx.KdfParameters) { p.Parallelism = 257 },
		"memory would wrap":      func(p *kdbx.KdfParameters) { p.Memory = 1<<32 + 1<<20 },
		"short memory":           func(p *kdbx.KdfParameters) { p.Memory = 1024 },
		"partial KiB":            func(p *kdbx.KdfParameters) { p.Memory++ },
		"extra secret":           func(p *kdbx.KdfParameters) { p.SecretKey = []byte{1} },
		"associated data":        func(p *kdbx.KdfParameters) { p.AssocData = []byte{1} },
	} {
		t.Run(name, func(t *testing.T) {
			db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
			db.Credentials = kdbx.NewPasswordCredentials("synthetic")
			p := db.Header.FileHeaders.KdfParameters
			p.UUID = kdbx.KdfArgon2id
			set(p)
			var out bytes.Buffer
			if e := kdbx.NewEncoder(&out).Encode(db); !errors.Is(e, kdbx.ErrCorruptedDatabase) {
				t.Fatal("unsupported parameters did not fail closed", e)
			}
		})
	}
}
