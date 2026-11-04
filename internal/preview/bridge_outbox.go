package preview

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/gateway"
)

type outbox struct {
	Binding   []byte
	Receipt   Submitted
	Wire, MAC []byte
}

func mac(seed []byte, v any) []byte {
	m := hmac.New(sha256.New, seed)
	m.Write(message("locklark/private-outbox/v1\x00", v))
	return m.Sum(nil)
}
func (o outbox) signature(seed []byte) []byte { o.MAC = nil; return mac(seed, o) }

// The private reservation must win before the relay can observe a request.
// A lost MCP reply, a crash between publication steps, or concurrent identical
// calls all re-publish the same ciphertext and request ID.
func SubmitBridgePull(c PollConfig, inbox string, p BridgeProfile, requestKey, reason string, n int, plan []byte) (Submitted, error) {
	if !validID(requestKey) || !validReason(reason) || c.Session != p.Session {
		return Submitted{}, errSession
	}
	target, e := gateway.RecordedIntent(p.Scope.Repo, n, plan)
	if e != nil || target.PullScope != p.Scope {
		return Submitted{}, errSession
	}
	seed, e := readPath(c.Key, 32)
	if e != nil || len(seed) != 32 {
		return Submitted{}, errSession
	}
	defer clear(seed)
	binding := mac(seed, struct {
		Session, Signer, Audience, Key, Reason string
		Target                                 gateway.PullIntent
	}{c.Session, p.Public, p.Audience, requestKey, reason, target})
	name := requestKey + ".outbox"
	raw, e := read(c.Private, name, 24576)
	if errors.Is(e, os.ErrNotExist) {
		tmp, e := os.MkdirTemp(c.Private, ".prepare-")
		if e != nil {
			return Submitted{}, errSession
		}
		// This directory is private and holds only the one signed, encrypted request.
		defer os.Remove(tmp)
		// Preserve the ID even if the private reservation is lost. A surviving
		// relay or holder record must conflict instead of permitting two grants.
		sum := mac(seed, struct{ Purpose, Session, Audience, Key string }{"request-id/v1", c.Session, p.Audience, requestKey})
		var rec Submitted
		_, e = submitWithID(tmp, c.Recipient, c.Session, reason, gateway.PullSlot, c.Key, &rec, &target, hex.EncodeToString(sum[:16]))
		if e != nil {
			return Submitted{}, errSession
		}
		child := rec.ID + ".request.age"
		defer os.Remove(filepath.Join(tmp, child))
		wire, e := read(tmp, child, 8192)
		if e != nil {
			return Submitted{}, errSession
		}
		candidate := outbox{Binding: binding, Receipt: rec, Wire: wire}
		candidate.MAC = candidate.signature(seed)
		data, e := json.Marshal(candidate)
		if e != nil {
			return Submitted{}, errSession
		}
		e = WriteReply(filepath.Join(c.Private, name), data)
		if e != nil && !errors.Is(e, os.ErrExist) {
			return Submitted{}, errSession
		}
		raw, e = read(c.Private, name, 24576)
		if e != nil {
			return Submitted{}, errSession
		}
	} else if e != nil {
		return Submitted{}, errSession
	}
	var o outbox
	if json.Unmarshal(raw, &o) != nil || !hmac.Equal(o.MAC, o.signature(seed)) || !hmac.Equal(o.Binding, binding) || !validID(o.Receipt.ID) || !hexSize(o.Receipt.Review, 32) || o.Receipt.State != "pending" {
		return Submitted{}, errSession
	}
	if !timeActive(p) {
		return Submitted{}, errSession
	}
	filename := o.Receipt.ID + ".request.age"
	e = WriteReply(filepath.Join(inbox, filename), o.Wire)
	if errors.Is(e, os.ErrExist) {
		existing, err := read(inbox, filename, 8192)
		if err != nil || !bytes.Equal(existing, o.Wire) {
			return Submitted{}, errSession
		}
	} else if e != nil {
		return Submitted{}, errSession
	}
	return o.Receipt, nil
}
