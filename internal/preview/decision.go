package preview

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"
)

var errChanged = errors.New("request changed, missing, expired or already decided; review again")

// Decide records a local disposition, not a redeemable grant. A synthetic
// approve may only target the exact fixed, independently decrypted fixture.
func Decide(inbox, device, bundle, id, review, choice, reason string) (Decision, error) {
	if !validID(id) || len(review) != 64 || (choice != "approve" && choice != "deny") || !validReason(reason) {
		return Decision{}, errDecision
	}
	actor, err := mailIdentity(device)
	if err != nil {
		return Decision{}, err
	}
	q, ok := openRequest(inbox, id+".request.age", actor)
	if !ok || q.Review != review {
		return Decision{}, errChanged
	}
	d := Decision{Request: q, Reason: strings.TrimSpace(reason), Result: "denied"}
	if choice == "approve" {
		if !supportedAction(q) || bundle == "" {
			return Decision{}, errChanged
		}
		p, err := readPayload(bundle, device, q.Epoch)
		if err != nil {
			return Decision{}, err
		}
		defer clear(p.Archive)
		base, err := fixtureArchive()
		if err != nil {
			return Decision{}, err
		}
		expected, err := editedFixture(base)
		if err != nil || !bytes.Equal(p.Archive, expected) {
			return Decision{}, errChanged
		}
		if q.Pull != nil {
			value, e := fixturePasswordField(p.Archive)
			if e != nil {
				return Decision{}, errChanged
			}
			clear(value)
		}
		h := sha256.Sum256(p.Archive)
		d.Snapshot = p.pin
		d.Target = hex.EncodeToString(h[:])
		d.Result = "approved"
	}
	signer, err := localSigner(device, "decision")
	if err != nil {
		return Decision{}, err
	}
	defer clear(signer)
	auditSigner, err := localSigner(device, "journal")
	if err != nil {
		return Decision{}, err
	}
	defer clear(auditSigner)
	err = withHistory(device, actor, true, func(b *bolt.Bucket, h history) error {
		now := time.Now().UTC()
		reg, err := readRegistry(b.Tx(), actor, signer.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		d.Request.SenderStatus = sessionStatus(q, reg, actor.Recipient().String(), now)
		if choice == "approve" && d.Request.SenderStatus != "verified" {
			return errSession
		}
		for _, old := range h.decisions {
			if old.Request.ID == id {
				if old.Request.Review == review && old.Result == d.Result && old.Reason == d.Reason {
					d = old
					return nil
				}
				return errChanged
			}
		}
		d.At = now
		if choice == "approve" {
			created, err := time.Parse(time.RFC3339Nano, q.Created)
			deadline := created.Add(24 * time.Hour)
			if err != nil || created.After(d.At) || !d.At.Before(deadline) {
				return errChanged
			}
			until := d.At.Add(2 * time.Minute)
			if x := reg.latest[q.Session].Expires; x.Before(deadline) {
				deadline = x
			}
			if until.After(deadline) {
				until = deadline
			}
			d.Expires = &until
		}
		return appendDecision(b, h, d, signer, auditSigner, actor)
	})
	if err != nil {
		return Decision{}, err
	}
	return d, nil
}
func localSigner(device, name string) (ed25519.PrivateKey, error) {
	raw, err := unwrapLocal(device, name)
	if err != nil {
		return nil, err
	}
	pub, err := read(device, name+".pub", 32)
	if err != nil || len(raw) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(raw[:32]), raw) || !bytes.Equal(raw[32:], pub) {
		clear(raw)
		return nil, errDecision
	}
	return ed25519.PrivateKey(raw), nil
}
func Decisions(device, session string) ([]Decision, error) {
	if !validSession(session) {
		return nil, errInput
	}
	id, err := mailIdentity(device)
	if err != nil {
		return nil, err
	}
	rows := []Decision{}
	err = withHistory(device, id, false, func(_ *bolt.Bucket, h history) error {
		for _, d := range h.decisions {
			if d.Request.Session == session {
				rows = append(rows, d)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}
func overlayDecisions(rows []Request, device string, id *age.X25519Identity) error {
	if _, err := os.Stat(filepath.Join(device, "decision.pub")); errors.Is(err, os.ErrNotExist) {
		if _, dbErr := os.Stat(filepath.Join(device, "decisions.db")); errors.Is(dbErr, os.ErrNotExist) {
			for i := range rows {
				rows[i].SenderStatus = "unsigned"
				if rows[i].Auth != nil {
					rows[i].SenderStatus = "unregistered"
				}
			}
			return nil
		} // older fixture without a journal
		return errDecision
	}
	authority, err := read(device, "decision.pub", 32)
	if err != nil || len(authority) != 32 {
		return errSession
	}
	return withHistory(device, id, false, func(b *bolt.Bucket, h history) error {
		reg, err := readRegistry(b.Tx(), id, authority)
		if err != nil {
			return err
		}
		byID := make(map[string]Decision, len(h.decisions))
		for _, d := range h.decisions {
			byID[d.Request.ID] = d
		}
		now := time.Now().UTC()
		for i, q := range rows {
			rows[i].SenderStatus = sessionStatus(q, reg, id.Recipient().String(), now)
			created, err := time.Parse(time.RFC3339Nano, q.Created)
			if created.After(now) {
				rows[i].State = "not-yet-valid"
			}
			if err != nil || !now.Before(created.Add(24*time.Hour)) {
				rows[i].State = "expired"
			}
			if d, ok := byID[q.ID]; ok {
				rows[i].State = stateAt(q, d, now)
				if u, used := h.uses[q.ID]; used && u.Review == q.Review {
					rows[i].State = "consumed-" + u.State
					if u.State == "revoked" {
						rows[i].State = "approval-revoked"
					}
				}
				if rows[i].State == "approved" && rows[i].SenderStatus != "verified" {
					rows[i].State = "approval-inactive"
				}
			}
		}
		return nil
	})
}
func stateAt(q Request, d Decision, now time.Time) string {
	switch {
	case q.Review != d.Request.Review:
		return "conflict"
	case d.Result == "approved" && now.Before(d.At):
		return "not-yet-valid"
	case d.Expires != nil && !now.Before(*d.Expires):
		return "expired"
	default:
		return d.Result
	}
}
