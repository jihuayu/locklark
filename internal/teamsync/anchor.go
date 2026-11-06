package teamsync

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	bolt "go.etcd.io/bbolt"
)

type AnchorStore interface {
	Load() (directory.Checkpoint, error)
	Advance(expected, next directory.Checkpoint) error
}

type FileAnchorStore struct{ path string }

var anchorBucket = []byte("locklark.team-sync.anchor/v1")
var anchorKey = []byte("checkpoint")

func validAnchor(cp directory.Checkpoint) bool {
	return canonicalHex(cp.Scope, 32) && cp.Version <= 1024 && ((cp.Version == 0 && cp.Hash == "") || (cp.Version > 0 && canonicalHex(cp.Hash, 32)))
}
func CreateFileAnchorStore(path string, initial directory.Checkpoint) (*FileAnchorStore, error) {
	return createFileAnchorStore(path, initial, initializeFileAnchor)
}
func createFileAnchorStore(path string, initial directory.Checkpoint, initialize func(string, directory.Checkpoint) error) (*FileAnchorStore, error) {
	if !filepath.IsAbs(path) || !validAnchor(initial) || trustedAnchorParent(filepath.Dir(path)) != nil {
		return nil, ErrAnchor
	}
	// Even an empty or malformed final file is an existing anchor, never a
	// placeholder that Create may adopt or repair. The publish also enforces
	// no replacement if another creator wins after this check.
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return nil, ErrAnchor
	}
	var random [16]byte
	if _, e := rand.Read(random[:]); e != nil {
		return nil, ErrAnchor
	}
	tmp := filepath.Join(filepath.Dir(path), ".locklark-anchor-"+hex.EncodeToString(random[:]))
	f, e := createAnchorFile(tmp)
	if e != nil {
		return nil, ErrAnchor
	}
	owned, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, ErrAnchor
	}
	defer removeOwnedAnchorTemp(tmp, owned)
	if f.Close() != nil {
		return nil, ErrAnchor
	}
	if initialize(tmp, initial) != nil {
		return nil, ErrAnchor
	}
	current, e := os.Lstat(tmp)
	if e != nil || !os.SameFile(owned, current) {
		return nil, ErrAnchor
	}
	staged, e := (&FileAnchorStore{path: tmp}).Load()
	if e != nil || staged != initial || trustedAnchorParent(filepath.Dir(path)) != nil {
		return nil, ErrAnchor
	}
	current, e = os.Lstat(tmp)
	if e != nil || !os.SameFile(owned, current) {
		return nil, ErrAnchor
	}
	if publishAnchorFile(tmp, path) != nil || removeOwnedAnchorTemp(tmp, owned) != nil {
		return nil, ErrAnchor
	}
	return &FileAnchorStore{path: path}, nil
}
func removeOwnedAnchorTemp(path string, owned os.FileInfo) error {
	current, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || !current.Mode().IsRegular() || !os.SameFile(owned, current) {
		return ErrAnchor
	}
	return os.Remove(path)
}
func initializeFileAnchor(path string, initial directory.Checkpoint) error {
	s := &FileAnchorStore{path: path}
	db, e := s.open(false)
	if e != nil {
		return ErrAnchor
	}
	e = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket(anchorBucket)
		if e != nil {
			return e
		}
		return b.Put(anchorKey, encode(initial))
	})
	if e == nil {
		e = db.Sync()
	}
	closed := db.Close()
	if e != nil || closed != nil {
		return ErrAnchor
	}
	return nil
}
func OpenFileAnchorStore(path string) (*FileAnchorStore, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrAnchor
	}
	s := &FileAnchorStore{path: path}
	if _, e := s.Load(); e != nil {
		return nil, ErrAnchor
	}
	return s, nil
}
func (s *FileAnchorStore) open(readOnly bool) (*bolt.DB, error) {
	if s == nil || trustedAnchorFile(s.path) != nil {
		return nil, ErrAnchor
	}
	return bolt.Open(s.path, 0600, &bolt.Options{ReadOnly: readOnly, Timeout: time.Second, OpenFile: func(path string, flags int, _ os.FileMode) (*os.File, error) {
		return openAnchorFile(path, flags&^os.O_CREATE)
	}})
}
func loadAnchor(tx *bolt.Tx) (directory.Checkpoint, error) {
	var cp directory.Checkpoint
	count := 0
	if tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		count++
		if !bytes.Equal(name, anchorBucket) {
			return ErrAnchor
		}
		return nil
	}) != nil || count != 1 {
		return cp, ErrAnchor
	}
	b := tx.Bucket(anchorBucket)
	count = 0
	if b.ForEach(func(k, v []byte) error {
		count++
		if !bytes.Equal(k, anchorKey) || len(v) > 1024 {
			return ErrAnchor
		}
		return decode(v, &cp)
	}) != nil || count != 1 || !validAnchor(cp) {
		return directory.Checkpoint{}, ErrAnchor
	}
	return cp, nil
}
func (s *FileAnchorStore) Load() (directory.Checkpoint, error) {
	db, e := s.open(true)
	if e != nil {
		return directory.Checkpoint{}, ErrAnchor
	}
	var out directory.Checkpoint
	e = db.View(func(tx *bolt.Tx) error { var e error; out, e = loadAnchor(tx); return e })
	closed := db.Close()
	if e != nil || closed != nil {
		return directory.Checkpoint{}, ErrAnchor
	}
	return out, nil
}
func (s *FileAnchorStore) Advance(expected, next directory.Checkpoint) error {
	if !validAnchor(expected) || !validAnchor(next) || expected.Scope != next.Scope || next.Version < expected.Version || (next.Version == expected.Version && next != expected) {
		return ErrAnchor
	}
	db, e := s.open(false)
	if e != nil {
		return ErrAnchor
	}
	e = db.Update(func(tx *bolt.Tx) error {
		current, e := loadAnchor(tx)
		if e != nil || current != expected {
			return ErrAnchor
		}
		return tx.Bucket(anchorBucket).Put(anchorKey, encode(next))
	})
	closed := db.Close()
	if e != nil || closed != nil {
		return ErrAnchor
	}
	return nil
}
