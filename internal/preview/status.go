package preview

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"
)

const statusPurpose = "request-status"

type PollConfig struct{ Private, Exchange, Key, Recipient, Host, Session string }
type Status struct {
	ID         string    `json:"request_id"`
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observed_at"`
}
type statusReply struct {
	Query  string
	Status Status
	Sig    []byte
}

func (r statusReply) proof() []byte { r.Sig = nil; return message("locklark/status-reply/v1\x00", r) }
func (c PollConfig) Start(id, review string) (string, error) {
	if c.Private == "" || c.Exchange == "" {
		return "", errInvoke
	}
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return "", err
	}
	poll := hex.EncodeToString(n[:])
	dir := filepath.Join(c.Private, poll)
	if err := prepareEnvelope(dir, c.Key, c.Recipient, c.Host, c.Session, id, review, statusPurpose, poll); err != nil {
		return "", err
	}
	query, err := read(dir, "query.age", 8192)
	if err != nil {
		return "", err
	}
	if err = WriteReply(filepath.Join(c.Exchange, poll+".query.age"), query); err != nil {
		return "", err
	}
	return poll, nil
}
func (c PollConfig) Read(id, review, poll string) (*Status, error) {
	if !validID(id) || !validID(poll) || !hexSize(review, 32) {
		return nil, errInvoke
	}
	local, err := read(filepath.Join(c.Private, poll), "attempt.private", 8192)
	if err != nil {
		return nil, errInvoke
	}
	defer clear(local)
	var a localAttempt
	if json.Unmarshal(local, &a) != nil {
		return nil, errInvoke
	}
	t := a.Ticket
	seed, err := readPath(c.Key, 32)
	if err != nil || len(seed) != 32 {
		return nil, errInvoke
	}
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	host, err := readPath(c.Host, 32)
	if err != nil || len(host) != 32 || !bytes.Equal(host, a.Host) {
		return nil, errInvoke
	}
	audience, err := readPath(c.Recipient, 256)
	if err != nil {
		return nil, errInvoke
	}
	if t.ID != id || t.Review != review || t.Nonce != poll || t.Purpose != statusPurpose || t.Session != c.Session || t.Audience != string(bytes.TrimSpace(audience)) || t.Public != hex.EncodeToString(priv[32:]) || !ed25519.Verify(ed25519.PublicKey(priv[32:]), t.proof(), t.Signature) {
		return nil, errInvoke
	}
	key, err := age.ParseX25519Identity(a.Key)
	if err != nil || key.Recipient().String() != t.Reply {
		return nil, errInvoke
	}
	data, err := read(c.Exchange, poll+".status.age", 8192)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errInvoke
	}
	var reply statusReply
	if unsealJSON(key, data, 4096, &reply) != nil || reply.Query != t.digest() || reply.Status.ID != id || !ed25519.Verify(host, reply.proof(), reply.Sig) {
		return nil, errInvoke
	}
	return &reply.Status, nil
}
func AnswerStatus(device, inbox, exchange, poll string) error {
	if !validID(poll) || device == "" || inbox == "" || exchange == "" {
		return errInvoke
	}
	id, err := mailIdentity(device)
	if err != nil {
		return errInvoke
	}
	t, err := readEnvelope(filepath.Join(exchange, poll+".query.age"), id, statusPurpose)
	if err != nil || t.Nonce != poll {
		return errInvoke
	}
	signer, err := localSigner(device, "decision")
	if err != nil {
		return errInvoke
	}
	defer clear(signer)
	var encrypted []byte
	err = withHistory(device, id, false, func(b *bolt.Bucket, h history) error {
		var q Request
		var d *Decision
		for i := range h.decisions {
			if h.decisions[i].Request.ID == t.ID {
				d = &h.decisions[i]
				q = d.Request
				break
			}
		}
		if d == nil {
			var ok bool
			q, ok = openRequest(inbox, t.ID+".request.age", id)
			if !ok {
				return errInvoke
			}
		}
		if q.Session != t.Session || q.Review != t.Review || q.Auth == nil || q.Auth.Public != t.Public || q.Auth.Audience != t.Audience {
			return errInvoke
		}
		reg, e := readRegistry(b.Tx(), id, signer.Public().(ed25519.PublicKey))
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		if sessionStatus(q, reg, t.Audience, now) != "verified" {
			return errInvoke
		}
		state := "pending"
		if d == nil {
			created, e := time.Parse(time.RFC3339Nano, q.Created)
			if e != nil {
				return errInvoke
			}
			if now.Before(created) {
				state = "not-yet-valid"
			} else if !now.Before(created.Add(24 * time.Hour)) {
				state = "expired"
			} else if q.Pull != nil && !q.Pull.Valid() {
				state = "module-inactive"
			}
		} else {
			state = stateAt(q, *d, now)
			if u, ok := h.uses[t.ID]; ok {
				state = "consumed-" + u.State
				if u.State == "revoked" {
					state = "approval-revoked"
				}
			}
		}
		reply := statusReply{Query: t.digest(), Status: Status{t.ID, state, now}}
		reply.Sig = ed25519.Sign(signer, reply.proof())
		recipient, e := age.ParseX25519Recipient(t.Reply)
		if e != nil {
			return e
		}
		encrypted, e = sealJSON(recipient, reply)
		return e
	})
	if err != nil {
		return errInvoke
	}
	return WriteReply(filepath.Join(exchange, poll+".status.age"), encrypted)
}
