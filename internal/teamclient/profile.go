package teamclient

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	bolt "go.etcd.io/bbolt"
)

const maxProfileBytes = 32 << 20

var profileBucket = []byte("locklark/teamclient/bootstrap-profile/v1")
var profileKey = []byte("record")

// Only public bindings, signed proofs and encrypted artifact bytes are durable.
// An independent, never-removed identity lease serializes OS transitions even
// after profile restoration. No transaction or cancellation lock spans OS/HTTP.
type profileRecord struct {
	Path            string                    `json:"path"`
	Version         int                       `json:"version"`
	Revision        uint64                    `json:"revision"`
	Kind            string                    `json:"kind"`
	Phase           BootstrapPhase            `json:"phase"`
	Sequencer       *SequencerDescriptor      `json:"sequencer,omitempty"`
	Owner           *OwnerDescriptor          `json:"owner,omitempty"`
	Roles           map[string]BootstrapPhase `json:"roles"`
	Artifact        []byte                    `json:"artifact,omitempty"`
	BuildAttempt    bool                      `json:"build_attempt,omitempty"`
	BuildID         string                    `json:"build_id,omitempty"`
	FinalizeAttempt bool                      `json:"finalize_attempt,omitempty"`
	Init            *serviceIntent            `json:"init,omitempty"`
}
type serviceIntent struct {
	Artifact        []byte             `json:"artifact"`
	Digest          string             `json:"digest"`
	Directory       string             `json:"directory"`
	Anchor          string             `json:"anchor"`
	AdoptionAttempt bool               `json:"adoption_attempt"`
	CreateAttempt   bool               `json:"create_attempt"`
	Receipt         *directory.Receipt `json:"receipt,omitempty"`
}
type profileLease struct {
	db       *bolt.DB
	path     string
	identity *os.File
}

func strictCanonical(raw []byte, v any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrProfile
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrProfile
	}
	encoded, e := json.Marshal(v)
	if e != nil || !bytes.Equal(raw, encoded) {
		return ErrProfile
	}
	return nil
}
func validPhase(p BootstrapPhase) bool {
	return p == BootstrapPreparing || p == BootstrapPending || p == BootstrapUnknown || p == BootstrapActive
}
func validateProfile(r profileRecord) error {
	if r.Version != 1 || r.Revision == 0 || !distinctPaths(r.Path) || !validPhase(r.Phase) || len(r.Artifact) > MaxBootstrapArtifactBytes {
		return ErrProfile
	}
	if r.BuildAttempt && !validHex(r.BuildID, 16) || !r.BuildAttempt && r.BuildID != "" || r.FinalizeAttempt && (!r.BuildAttempt || len(r.Artifact) == 0) {
		return ErrProfile
	}
	switch r.Kind {
	case "sequencer":
		if r.Sequencer == nil || r.Owner != nil || !validSequencer(*r.Sequencer) || len(r.Roles) != 1 || !validPhase(r.Roles["sequencer"]) || r.Artifact != nil || r.BuildAttempt || r.BuildID != "" || r.FinalizeAttempt {
			return ErrProfile
		}
	case "owner":
		if r.Owner == nil || r.Sequencer != nil || !validOwner(*r.Owner) || len(r.Roles) != 3 || !validPhase(r.Roles["owner"]) || !validPhase(r.Roles["publisher"]) || !validPhase(r.Roles["device"]) || r.Init != nil {
			return ErrProfile
		}
	default:
		return ErrProfile
	}
	if r.Init != nil {
		i := r.Init
		if len(i.Artifact) == 0 || len(i.Artifact) > MaxBootstrapArtifactBytes || !validHex(i.Digest, 32) || !distinctPaths(r.Path, r.Path+".identity-lease", i.Directory, i.Anchor) {
			return ErrProfile
		}
	}
	return nil
}
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if equalProfilePath(filepath.Clean(a), filepath.Clean(b)) {
		return true
	}
	x, xe := os.Lstat(a)
	y, ye := os.Lstat(b)
	return xe == nil && ye == nil && os.SameFile(x, y)
}
func distinctPaths(paths ...string) bool {
	for n, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return false
		}
		for _, q := range paths[:n] {
			if samePath(p, q) {
				return false
			}
		}
	}
	return true
}
func canonicalProfilePath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrProfile
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return "", ErrProfile
	}
	path = filepath.Join(parent, filepath.Base(path))
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || !profileUniqueFile(path, st) {
			return "", ErrProfile
		}
	} else if !os.IsNotExist(e) {
		return "", ErrProfile
	}
	return path, nil
}

func openProfile(path string) (*profileLease, error) {
	canonical, e := canonicalProfilePath(path)
	if e != nil || trustedProfileFile(canonical) != nil {
		return nil, ErrProfile
	}
	path = canonical
	identity, e := openProfileFile(path+".identity-lease", os.O_RDWR)
	if e != nil {
		return nil, ErrProfile
	}
	if e = lockProfileIdentity(identity); e != nil {
		identity.Close()
		return nil, ErrProfile
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, OpenFile: func(name string, flags int, _ os.FileMode) (*os.File, error) {
		return openProfileFile(name, flags&^os.O_CREATE)
	}})
	if e != nil {
		identity.Close()
		return nil, ErrProfile
	}
	p := &profileLease{db, path, identity}
	if r, e := p.load(); e != nil || r.Path != path {
		db.Close()
		identity.Close()
		return nil, ErrProfile
	}
	return p, nil
}
func (p *profileLease) close() error {
	db := p.db.Close()
	identity := p.identity.Close()
	if db != nil || identity != nil {
		return ErrProfile
	}
	return nil
}
func (p *profileLease) load() (r profileRecord, err error) {
	err = p.db.View(func(tx *bolt.Tx) error {
		count := 0
		if tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			count++
			if !bytes.Equal(name, profileBucket) {
				return ErrProfile
			}
			return nil
		}) != nil || count != 1 {
			return ErrProfile
		}
		b := tx.Bucket(profileBucket)
		count = 0
		if b.ForEach(func(k, v []byte) error {
			count++
			if !bytes.Equal(k, profileKey) {
				return ErrProfile
			}
			return strictCanonical(v, &r, maxProfileBytes)
		}) != nil || count != 1 {
			return ErrProfile
		}
		return validateProfile(r)
	})
	if err != nil {
		return profileRecord{}, ErrProfile
	}
	return r, nil
}
func (p *profileLease) save(r *profileRecord) error {
	r.Revision++
	if validateProfile(*r) != nil {
		return ErrProfile
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > maxProfileBytes {
		return ErrProfile
	}
	e = p.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(profileBucket).Put(profileKey, raw) })
	if e != nil {
		return ErrProfile
	}
	return nil
}
func createProfile(path string, r profileRecord) error {
	canonical, e := canonicalProfilePath(path)
	if e != nil || canonical != path || r.Path != path || trustedProfileParent(filepath.Dir(path)) != nil || validateProfile(r) != nil {
		return ErrProfile
	}
	if !absent(path) {
		return ErrProfile
	}
	identity, e := createProfileFile(path + ".identity-lease")
	if e != nil {
		return ErrProfile
	}
	defer identity.Close()
	if lockProfileIdentity(identity) != nil {
		return ErrProfile
	}
	var token [16]byte
	if _, e := rand.Read(token[:]); e != nil {
		return ErrProfile
	}
	tmp := filepath.Join(filepath.Dir(path), ".locklark-team-profile-"+hex.EncodeToString(token[:]))
	f, e := createProfileFile(tmp)
	if e != nil {
		return ErrProfile
	}
	owned, e := f.Stat()
	if e != nil {
		f.Close()
		return ErrProfile
	}
	defer removeOwnedProfileTemporary(tmp, owned)
	if f.Close() != nil {
		return ErrProfile
	}
	db, e := bolt.Open(tmp, 0600, &bolt.Options{Timeout: time.Second, OpenFile: func(name string, flags int, _ os.FileMode) (*os.File, error) {
		return openProfileFile(name, flags&^os.O_CREATE)
	}})
	if e != nil {
		return ErrProfile
	}
	raw, e := json.Marshal(r)
	if e == nil {
		e = db.Update(func(tx *bolt.Tx) error {
			b, e := tx.CreateBucket(profileBucket)
			if e != nil {
				return e
			}
			return b.Put(profileKey, raw)
		})
	}
	closed := db.Close()
	if e != nil || closed != nil || publishProfile(tmp, path) != nil {
		return ErrProfile
	}
	return nil
}
func removeOwnedProfileTemporary(path string, owned os.FileInfo) bool {
	current, e := os.Lstat(path)
	if e != nil || owned == nil || current.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return os.SameFile(owned, current) && os.Remove(path) == nil
}
