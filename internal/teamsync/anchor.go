package teamsync

import (
	"bytes"
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
	if !filepath.IsAbs(path) || !validAnchor(initial) || trustedAnchorParent(filepath.Dir(path)) != nil {
		return nil, ErrAnchor
	}
	f, e := createAnchorFile(path)
	if e != nil {
		return nil, ErrAnchor
	}
	if f.Close() != nil {
		return nil, ErrAnchor
	}
	s := &FileAnchorStore{path: path}
	db, e := s.open(false)
	if e != nil {
		return nil, ErrAnchor
	}
	e = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket(anchorBucket)
		if e != nil {
			return e
		}
		return b.Put(anchorKey, encode(initial))
	})
	closed := db.Close()
	if e != nil || closed != nil {
		return nil, ErrAnchor
	}
	return s, nil
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
