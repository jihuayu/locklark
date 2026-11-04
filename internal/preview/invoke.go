package preview

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"
)

func authorization(h history, t invocation) (Decision, error) {
	for _, d := range h.decisions {
		q := d.Request
		if t.ID != q.ID {
			continue
		}
		if d.Result != "approved" || d.Expires == nil || q.Review != t.Review || q.Session != t.Session || q.Auth == nil || q.Auth.Public != t.Public || q.Auth.Audience != t.Audience || q.SenderStatus != "verified" || q.Action != FixtureAction || q.Epoch != 3 || q.Ref != FixtureRef {
			return Decision{}, errInvoke
		}
		return d, nil
	}
	return Decision{}, errInvoke
}
func currentSession(tx *bolt.Tx, id *age.X25519Identity, owner []byte, d Decision, now time.Time) error {
	reg, err := readRegistry(tx, id, owner)
	if err != nil {
		return err
	}
	if sessionStatus(d.Request, reg, id.Recipient().String(), now) != "verified" {
		return errInvoke
	}
	return nil
}
func Invoke(device, bundle, ticket string) ([]byte, error) {
	return runInvocation(device, bundle, ticket, inspectMetadata)
}
func runInvocation(device, bundle, path string, execute func([]byte) (FieldMetadata, error)) ([]byte, error) {
	return runInvocationAt(device, bundle, path, execute, time.Now)
}
func runInvocationAt(device, bundle, path string, execute func([]byte) (FieldMetadata, error), clock func() time.Time) ([]byte, error) {
	id, err := mailIdentity(device)
	if err != nil {
		return nil, err
	}
	t, err := readTicket(path, id)
	if err != nil {
		return nil, err
	}
	owner, err := localSigner(device, "decision")
	if err != nil {
		return nil, err
	}
	defer clear(owner)
	auditKey, err := localSigner(device, "journal")
	if err != nil {
		return nil, err
	}
	defer clear(auditKey)
	var target encryptedSnapshot
	var expectedArchive string
	record := useRecord{UseReport: UseReport{ID: t.ID, Session: t.Session, Review: t.Review, Attempt: t.digest(), State: "unknown"}}
	err = withHistory(device, id, true, func(b *bolt.Bucket, h history) error {
		if b.Tx().Bucket(useAnchor) == nil {
			return errInvoke
		}
		d, err := authorization(h, t)
		if err != nil {
			return err
		}
		if _, used := h.uses[t.ID]; used {
			return errInvoke
		}
		if err = currentSession(b.Tx(), id, owner.Public().(ed25519.PublicKey), d, clock().UTC()); err != nil {
			return err
		}
		sealed, err := readEncrypted(bundle, device, d.Request.Epoch)
		if err != nil {
			return err
		}
		if d.Snapshot == "" || sealed.pin() != d.Snapshot {
			return errInvoke
		}
		now := clock().UTC()
		if now.Before(d.At) || !now.Before(*d.Expires) {
			return errInvoke
		}
		if err = currentSession(b.Tx(), id, owner.Public().(ed25519.PublicKey), d, now); err != nil {
			return err
		}
		target = sealed
		expectedArchive = d.Target
		return appendUse(b, h, record, owner, auditKey, id)
	})
	if err != nil {
		return nil, err
	}
	// No callback runs until bbolt has committed and closed the intent transaction.
	// A crash or lost result leaves "unknown"; there is deliberately no retry path.
	var metadata FieldMetadata
	p, actionErr := target.unlock(device)
	if actionErr == nil {
		defer clear(p.Archive)
		sum := sha256.Sum256(p.Archive)
		if hex.EncodeToString(sum[:]) != expectedArchive {
			actionErr = errInvoke
		} else {
			metadata, actionErr = execute(p.Archive)
		}
	}
	record.State = "failed"
	if actionErr == nil {
		reply := signedReply{Ticket: t.digest(), Metadata: metadata}
		reply.Sig = ed25519.Sign(owner, reply.proof())
		recipient, err := age.ParseX25519Recipient(t.Reply)
		if err != nil {
			return nil, errInvoke
		}
		record.Reply, err = sealJSON(recipient, reply)
		if err != nil {
			return nil, err
		}
		record.State = "succeeded"
	}
	err = withHistory(device, id, true, func(b *bolt.Bucket, h history) error { return appendUse(b, h, record, owner, auditKey, id) })
	if err != nil {
		return nil, err
	}
	if actionErr != nil {
		return nil, errors.New("metadata action failed; approval already consumed")
	}
	return receiptForTicket(device, id, t)
}
func InvocationReceipt(device, path string) ([]byte, error) {
	id, err := mailIdentity(device)
	if err != nil {
		return nil, err
	}
	t, err := readTicket(path, id)
	if err != nil {
		return nil, err
	}
	return receiptForTicket(device, id, t)
}
func receiptForTicket(device string, id *age.X25519Identity, t invocation) ([]byte, error) {
	pub, err := read(device, "decision.pub", 32)
	if err != nil || len(pub) != 32 {
		return nil, errInvoke
	}
	var got []byte
	err = withHistory(device, id, false, func(b *bolt.Bucket, h history) error {
		d, err := authorization(h, t)
		if err != nil {
			return err
		}
		if err = currentSession(b.Tx(), id, pub, d, time.Now().UTC()); err != nil {
			return err
		}
		u, ok := h.uses[t.ID]
		if !ok || u.State != "succeeded" || u.Attempt != t.digest() {
			return errInvoke
		}
		got = append([]byte(nil), u.Reply...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return got, nil
}
func Executions(device, session string) ([]UseReport, error) {
	if !validSession(session) {
		return nil, errInvoke
	}
	id, err := mailIdentity(device)
	if err != nil {
		return nil, err
	}
	rows := []UseReport{}
	err = withHistory(device, id, false, func(_ *bolt.Bucket, h history) error {
		for _, u := range h.uses {
			if u.Session == session {
				rows = append(rows, u.UseReport)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}
func WriteReply(path string, b []byte) error {
	return write(filepath.Dir(path), filepath.Base(path), b)
}
