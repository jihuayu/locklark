package preview

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"

	"filippo.io/age"
	"filippo.io/edwards25519"
	bolt "go.etcd.io/bbolt"
)

var errSession = errors.New("invalid, unregistered or inactive agent session")

const proofDomain = "locklark/agent-request/v1\x00"
const registryDomain = "locklark/agent-registration/v1\x00"

var registryBucket = []byte("agent-sessions-v1")

type SessionProof struct {
	Public    string `json:"public"`
	Audience  string `json:"audience"`
	Signature []byte `json:"signature"`
}

func NewSessionKey(path string) (string, error) {
	if filepath.Ext(path) != ".sessionkey" {
		return "", errors.New("new .sessionkey file required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	defer clear(priv)
	seed := priv.Seed()
	defer clear(seed)
	if err = write(filepath.Dir(path), filepath.Base(path), seed); err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}
func validPublic(s string) bool {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != s {
		return false
	}
	p, err := new(edwards25519.Point).SetBytes(raw)
	return err == nil && bytes.Equal(raw, p.Bytes()) && new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 0
}
func (p SessionProof) wellFormed() bool {
	if !validPublic(p.Public) || len(p.Signature) != ed25519.SignatureSize {
		return false
	}
	r, err := age.ParseX25519Recipient(p.Audience)
	return err == nil && r.String() == p.Audience
}
func proofMessage(q Request) []byte {
	p := *q.Auth
	p.Signature = nil
	q.Auth = &p
	q.Review = ""
	q.SenderStatus = ""
	q.State = "pending"
	b, _ := json.Marshal(q)
	return append([]byte(proofDomain), b...)
}
func signRequest(q *Request, seed []byte, audience string) error {
	if len(seed) != ed25519.SeedSize {
		return errSession
	}
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	q.Auth = &SessionProof{Public: hex.EncodeToString(priv[32:]), Audience: audience}
	q.Auth.Signature = ed25519.Sign(priv, proofMessage(*q))
	return nil
}

type SessionChange struct {
	ScopeAction string    `json:"scope_action"`
	ScopeRef    string    `json:"scope_ref"`
	ScopeEpoch  uint64    `json:"scope_epoch"`
	Sequence    uint64    `json:"sequence"`
	Session     string    `json:"session"`
	Public      string    `json:"public"`
	Audience    string    `json:"audience"`
	Action      string    `json:"action"`
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
	Expires     time.Time `json:"expires"`
}
type sessionEntry struct {
	Change SessionChange `json:"change"`
	Sig    []byte        `json:"signature"`
}
type sessionRegistry struct {
	changes []SessionChange
	latest  map[string]SessionChange
	seq     uint64
	head    [32]byte
}

func registryMessage(c SessionChange, prev [32]byte) []byte {
	raw, _ := json.Marshal(c)
	return append(append([]byte(registryDomain), prev[:]...), raw...)
}
func readRegistry(tx *bolt.Tx, id *age.X25519Identity, authority ed25519.PublicKey) (sessionRegistry, error) {
	reg := sessionRegistry{latest: map[string]SessionChange{}}
	b := tx.Bucket(registryBucket)
	if b == nil {
		return reg, nil
	}
	err := b.ForEach(func(k, v []byte) error {
		if len(k) != 8 || len(v) > 8192 {
			return errSession
		}
		stream, err := age.Decrypt(bytes.NewReader(v), id)
		if err != nil {
			return errSession
		}
		raw, err := io.ReadAll(io.LimitReader(stream, 4097))
		if err != nil || len(raw) > 4096 {
			return errSession
		}
		var e sessionEntry
		if json.Unmarshal(raw, &e) != nil {
			return errSession
		}
		c := e.Change
		if c.Sequence != reg.seq+1 || binary.BigEndian.Uint64(k) != c.Sequence || c.Audience != id.Recipient().String() || !ed25519.Verify(authority, registryMessage(c, reg.head), e.Sig) {
			return errSession
		}
		reg.seq = c.Sequence
		reg.head = sha256.Sum256(e.Sig)
		reg.latest[c.Session] = c
		reg.changes = append(reg.changes, c)
		return nil
	})
	return reg, err
}
func EnrollSession(device, session, public, reason string) (SessionChange, error) {
	return changeSession(device, session, public, reason, false, time.Now)
}
func RevokeSession(device, session, reason string) (SessionChange, error) {
	return changeSession(device, session, "", reason, true, time.Now)
}
func changeSession(device, session, public, reason string, revoke bool, clock func() time.Time) (SessionChange, error) {
	if !validSession(session) || session == systemSession || !validReason(reason) || (!revoke && !validPublic(public)) {
		return SessionChange{}, errSession
	}
	id, err := mailIdentity(device)
	if err != nil {
		return SessionChange{}, err
	}
	signer, err := localSigner(device, "decision")
	if err != nil {
		return SessionChange{}, err
	}
	defer clear(signer)
	var c SessionChange
	err = withHistory(device, id, true, func(b *bolt.Bucket, _ history) error {
		reg, err := readRegistry(b.Tx(), id, signer.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		now := clock().UTC()
		old, exists := reg.latest[session]
		if revoke {
			if !exists {
				return errSession
			}
			if old.Action == "revoked" {
				c = old
				return nil
			}
			c = old
			c.Action = "revoked"
			c.At = now
			c.Reason = reason
		} else {
			if exists {
				return errSession
			}
			for _, x := range reg.latest {
				if x.Public == public {
					return errSession
				}
			}
			c = SessionChange{ScopeAction: FixtureAction, ScopeRef: FixtureRef, ScopeEpoch: 3, Session: session, Public: public, Audience: id.Recipient().String(), Action: "enrolled", Reason: reason, At: now, Expires: now.Add(24 * time.Hour)}
		}
		c.Sequence = reg.seq + 1
		e := sessionEntry{c, ed25519.Sign(signer, registryMessage(c, reg.head))}
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, id.Recipient())
		if err != nil {
			return err
		}
		if err = json.NewEncoder(w).Encode(e); err != nil {
			return err
		}
		if err = w.Close(); err != nil {
			return err
		}
		store, err := b.Tx().CreateBucketIfNotExists(registryBucket)
		if err != nil {
			return err
		}
		return store.Put(binary.BigEndian.AppendUint64(nil, c.Sequence), buf.Bytes())
	})
	if err != nil {
		return SessionChange{}, err
	}
	return c, nil
}
func sessionStatus(q Request, reg sessionRegistry, audience string, now time.Time) string {
	if q.Auth == nil {
		return "unsigned"
	}
	p := q.Auth
	if !p.wellFormed() || p.Audience != audience {
		return "invalid"
	}
	pub, _ := hex.DecodeString(p.Public)
	if !ed25519.Verify(pub, proofMessage(q), p.Signature) {
		return "invalid"
	}
	c, ok := reg.latest[q.Session]
	if !ok || c.Public != p.Public {
		return "unregistered"
	}
	if c.ScopeAction != q.Action || c.ScopeRef != q.Ref || c.ScopeEpoch != q.Epoch {
		return "out-of-scope"
	}
	if c.Action == "revoked" {
		return "revoked"
	}
	if now.Before(c.At) || !now.Before(c.Expires) {
		return "inactive"
	}
	created, err := time.Parse(time.RFC3339Nano, q.Created)
	if err != nil || created.Before(c.At) || !created.Before(c.Expires) {
		return "inactive"
	}
	return "verified"
}
func SessionHistory(device, session string) ([]SessionChange, error) {
	if !validSession(session) {
		return nil, errSession
	}
	id, err := mailIdentity(device)
	if err != nil {
		return nil, err
	}
	pub, err := read(device, "decision.pub", 32)
	if err != nil || len(pub) != 32 {
		return nil, errSession
	}
	rows := []SessionChange{}
	err = withHistory(device, id, false, func(b *bolt.Bucket, _ history) error {
		reg, err := readRegistry(b.Tx(), id, pub)
		if err != nil {
			return err
		}
		for _, c := range reg.changes {
			if c.Session == session {
				rows = append(rows, c)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}
