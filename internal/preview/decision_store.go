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
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	bolt "go.etcd.io/bbolt"
)

var errDecision = errors.New("decision journal or request binding is invalid")
var journal = []byte("signed-decisions-v1")

const decisionDomain = "locklark/local-decision/v1\x00"

type Decision struct {
	Request Request    `json:"request"`
	Result  string     `json:"result"`
	Reason  string     `json:"reason"`
	At      time.Time  `json:"at"`
	Expires *time.Time `json:"expires,omitempty"`
	Target  string     `json:"target_digest,omitempty"`
}
type entry struct {
	Decision  Decision `json:"decision"`
	Signature []byte   `json:"signature"`
	Event     Event    `json:"event"`
	Proof     []byte   `json:"proof"`
}

func requestDigest(q Request) string {
	q.Review = ""
	raw, _ := json.Marshal(q)
	h := sha256.Sum256(append([]byte("locklark/local-review/v1\x00"), raw...))
	return hex.EncodeToString(h[:])
}
func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == id
}
func decisionBytes(d Decision) []byte {
	b, _ := json.Marshal(d)
	return append([]byte(decisionDomain), b...)
}
func auditAction(d Decision) string {
	h := sha256.Sum256(decisionBytes(d))
	return "decision." + d.Request.ID + "." + hex.EncodeToString(h[:])
}
func unwrapLocal(device, name string) ([]byte, error) {
	data, err := read(device, name+".slot", 4096)
	if err != nil {
		return nil, err
	}
	secret, err := read(device, "fixture.secret", 16)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	var slot account.Slot
	if json.Unmarshal(data, &slot) != nil {
		return nil, errDecision
	}
	return account.Unwrap(fixturePassword, secret, slot)
}
func mailIdentity(device string) (*age.X25519Identity, error) {
	key, err := unwrapLocal(device, "approval")
	if err != nil {
		return nil, err
	}
	defer clear(key)
	id, err := age.ParseX25519Identity(string(key))
	if err != nil {
		return nil, errDecision
	}
	return id, nil
}
func setupDecisions(dir string, secret, id []byte) error {
	for _, name := range []string{"decision", "journal"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		defer clear(priv)
		slot, err := account.Wrap(fixturePassword, secret, id, priv)
		if err != nil {
			return err
		}
		if err = writeJSON(dir, name+".slot", slot); err != nil {
			return err
		}
		if err = write(dir, name+".pub", pub); err != nil {
			return err
		}
	}
	db, err := bolt.Open(filepath.Join(dir, "decisions.db"), 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket(journal); return err })
	closeErr := db.Close()
	if err != nil {
		return err
	}
	return closeErr
}

type history struct {
	decisions []Decision
	chain     payload
}

func loadHistory(b *bolt.Bucket, id *age.X25519Identity, pub, auditPub []byte) (history, error) {
	var h history
	seen := map[string]bool{}
	if b == nil || len(pub) != 32 || len(auditPub) != 32 {
		return h, errDecision
	}
	err := b.ForEach(func(k, v []byte) error {
		if len(k) != 8 || binary.BigEndian.Uint64(k) != uint64(len(h.decisions)+1) || len(v) > 16384 {
			return errDecision
		}
		r, err := age.Decrypt(bytes.NewReader(v), id)
		if err != nil {
			return errDecision
		}
		raw, err := io.ReadAll(io.LimitReader(r, 8193))
		if err != nil || len(raw) > 8192 {
			return errDecision
		}
		var e entry
		if json.Unmarshal(raw, &e) != nil {
			return errDecision
		}
		d := e.Decision
		if !ed25519.Verify(pub, decisionBytes(d), e.Signature) || !validID(d.Request.ID) || seen[d.Request.ID] || d.Request.Review != requestDigest(d.Request) || e.Event.Action != auditAction(d) || e.Event.Session != d.Request.Session || e.Event.Result != d.Result || e.Event.Reason != d.Reason {
			return errDecision
		}
		seen[d.Request.ID] = true
		h.decisions = append(h.decisions, d)
		h.chain.Events = append(h.chain.Events, e.Event)
		h.chain.Proofs = append(h.chain.Proofs, e.Proof)
		return nil
	})
	if err != nil {
		return history{}, err
	}
	if len(h.decisions) > 0 {
		if _, err = checkChain(h.chain, auditPub, nil); err != nil {
			return history{}, err
		}
	}
	return h, nil
}
func withHistory(device string, id *age.X25519Identity, update bool, fn func(*bolt.Bucket, history) error) error {
	pub, err := read(device, "decision.pub", 32)
	if err != nil {
		return err
	}
	auditPub, err := read(device, "journal.pub", 32)
	if err != nil {
		return err
	}
	path := filepath.Join(device, "decisions.db")
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return errDecision
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: !update})
	if err != nil {
		return err
	}
	do := db.View
	if update {
		do = db.Update
	}
	err = do(func(tx *bolt.Tx) error {
		b := tx.Bucket(journal)
		h, err := loadHistory(b, id, pub, auditPub)
		if err != nil {
			return err
		}
		return fn(b, h)
	})
	closeErr := db.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func appendDecision(b *bolt.Bucket, h history, d Decision, priv, auditKey ed25519.PrivateKey, id *age.X25519Identity) error {
	h.chain.signedRecord(auditKey, d.Request.Session, "owner", auditAction(d), d.Reason, d.Result)
	i := len(h.chain.Events) - 1
	e := entry{d, ed25519.Sign(priv, decisionBytes(d)), h.chain.Events[i], h.chain.Proofs[i]}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, id.Recipient())
	if err != nil {
		return err
	}
	if err = json.NewEncoder(w).Encode(e); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return b.Put(binary.BigEndian.AppendUint64(nil, uint64(i+1)), out.Bytes())
}
