package preview

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/gateway"
	bolt "go.etcd.io/bbolt"
)

var useAnchor = []byte("local-journal-tip-v1")
var tipKey = []byte("head")

func tipMessage(n int, h [32]byte) []byte {
	b := binary.BigEndian.AppendUint64([]byte("locklark/journal-tip/v1\x00"), uint64(n))
	return append(b, h[:]...)
}
func signTip(n int, h [32]byte, key ed25519.PrivateKey) []byte {
	return ed25519.Sign(key, tipMessage(n, h))
}
func tip(p payload) (int, [32]byte) {
	n := len(p.Proofs)
	if n == 0 {
		return 0, [32]byte{}
	}
	return n, sha256.Sum256(p.Proofs[n-1])
}
func verifyTip(tx *bolt.Tx, h history, key ed25519.PublicKey) error {
	b := tx.Bucket(useAnchor)
	if b == nil {
		if len(h.uses) > 0 {
			return errInvoke
		}
		return nil
	}
	n, head := tip(h.chain)
	if !ed25519.Verify(key, tipMessage(n, head), b.Get(tipKey)) {
		return errInvoke
	}
	return nil
}
func updateTip(tx *bolt.Tx, p payload, key ed25519.PrivateKey) error {
	b := tx.Bucket(useAnchor)
	if b == nil {
		return nil
	} // previous generation, decisions only
	n, h := tip(p)
	return b.Put(tipKey, signTip(n, h, key))
}

type UseReport struct {
	Pull    *gateway.PullIntent `json:"pull,omitempty"`
	Reason  string              `json:"reason,omitempty"`
	ID      string              `json:"id"`
	Session string              `json:"session"`
	Review  string              `json:"review"`
	Attempt string              `json:"attempt"`
	State   string              `json:"state"`
}
type useRecord struct {
	UseReport
	Reply []byte `json:"reply,omitempty"`
}

func useBytes(u useRecord) []byte { return message("locklark/use/v1\x00", u) }
func useAction(u useRecord) string {
	sum := sha256.Sum256(useBytes(u))
	return "invoke." + u.ID + "." + hex.EncodeToString(sum[:])
}
func ingestUse(h *history, e entry, key ed25519.PublicKey) error {
	u := *e.Use
	if !validID(u.ID) || (u.State != "revoked" && !hexSize(u.Attempt, 32)) || !ed25519.Verify(key, useBytes(u), e.Signature) || e.Event.Action != useAction(u) || e.Event.Session != u.Session || e.Event.Result != u.State {
		return errInvoke
	}
	var found bool
	for _, d := range h.decisions {
		if d.Request.ID == u.ID && d.Result == "approved" && d.Request.Review == u.Review && d.Request.Session == u.Session {
			if (u.Pull == nil) != (d.Request.Pull == nil) || (u.Pull != nil && *d.Request.Pull != *u.Pull) {
				return errInvoke
			}
			found = true
			break
		}
	}
	if !found {
		return errInvoke
	}
	old, ok := h.uses[u.ID]
	switch u.State {
	case "revoked":
		if ok || u.Attempt != "" || len(u.Reply) != 0 || !validReason(u.Reason) || e.Event.Actor != "owner" || e.Event.Reason != u.Reason {
			return errInvoke
		}
	case "unknown":
		if ok || len(u.Reply) != 0 {
			return errInvoke
		}
	case "succeeded", "failed":
		if !ok || old.State != "unknown" || old.Attempt != u.Attempt || (u.State == "succeeded") != (len(u.Reply) > 0) {
			return errInvoke
		}
	default:
		return errInvoke
	}
	h.uses[u.ID] = u
	return nil
}
func appendUse(b *bolt.Bucket, h history, u useRecord, owner, auditKey ed25519.PrivateKey, id *age.X25519Identity) error {
	if b.Tx().Bucket(useAnchor) == nil {
		return errInvoke
	}
	actor, reason := "executor", "signed fixture metadata invocation"
	if u.Pull != nil {
		reason = "signed recorded GitHub PR invocation"
	}
	if u.State == "revoked" {
		actor = "owner"
		reason = u.Reason
	}
	h.chain.signedRecord(auditKey, u.Session, actor, useAction(u), reason, u.State)
	i := len(h.chain.Events) - 1
	e := entry{Use: &u, Signature: ed25519.Sign(owner, useBytes(u)), Event: h.chain.Events[i], Proof: h.chain.Proofs[i]}
	if err := ingestUse(&h, e, owner.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	data, err := sealJSON(id.Recipient(), e)
	if err != nil {
		return err
	}
	if len(data) > 16384 {
		return errInvoke
	}
	if err = b.Put(binary.BigEndian.AppendUint64(nil, uint64(i+1)), data); err != nil {
		return err
	}
	return updateTip(b.Tx(), h.chain, auditKey)
}
