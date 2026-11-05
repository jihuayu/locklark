package preview

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/gateway"
)

type resultAttempt struct {
	Local  localAttempt
	Wire   []byte
	Target gateway.PullIntent
}
type deliveryBinding struct{ Session, Signer, Audience, Host, ID, Review string }
type BridgeResult struct {
	State  string          `json:"state"`
	ID     string          `json:"request_id"`
	Result *RecordedResult `json:"result,omitempty"`
}

func resultKeys(c PollConfig, p BridgeProfile, id, review string) (cipher.AEAD, deliveryBinding, error) {
	var b deliveryBinding
	if c.Session != p.Session || !validID(id) || !hexSize(review, 32) || !timeActive(p) {
		return nil, b, errInvoke
	}
	seed, e := readPath(c.Key, 32)
	if e != nil || len(seed) != 32 {
		return nil, b, errInvoke
	}
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	if hex.EncodeToString(priv[32:]) != p.Public {
		return nil, b, errInvoke
	}
	pk, e := readPath(c.Host, 32)
	if e != nil || len(pk) != 32 || !ed25519.Verify(pk, p.proof(), p.Sig) {
		return nil, b, errInvoke
	}
	audience, e := readPath(c.Recipient, 256)
	if e != nil || string(bytes.TrimSpace(audience)) != p.Audience {
		return nil, b, errInvoke
	}
	k, e := hkdf.Key(sha256.New, seed, nil, "locklark/bridge-result-storage/v1", 32)
	if e != nil {
		return nil, b, e
	}
	defer clear(k)
	block, e := aes.NewCipher(k)
	if e != nil {
		return nil, b, e
	}
	aead, e := cipher.NewGCMWithRandomNonce(block)
	b = deliveryBinding{p.Session, p.Public, p.Audience, hex.EncodeToString(pk), id, review}
	return aead, b, e
}
func loadResultAttempt(c PollConfig, p BridgeProfile, id, review string, newTarget *gateway.PullIntent) (resultAttempt, error) {
	var saved resultAttempt
	aead, b, e := resultKeys(c, p, id, review)
	if e != nil {
		return saved, e
	}
	associated := message("locklark/bridge-result-state/v1\x00", b)
	name := id + ".replykey"
	raw, e := read(c.Private, name, 16384)
	if errors.Is(e, os.ErrNotExist) && newTarget != nil {
		// Publication follows private reservation. If a public artifact exists,
		// a competing submit may just have reserved the identity; reload it.
		// Never replace a lost receiver with one that cannot open its receipt.
		for _, suffix := range []string{".invoke.age", ".result.age"} {
			_, markerErr := os.Lstat(filepath.Join(c.Exchange, id+suffix))
			if markerErr == nil {
				raw, e = read(c.Private, name, 16384)
				if e != nil {
					return saved, errInvoke
				}
				break
			}
			if !errors.Is(markerErr, os.ErrNotExist) {
				return saved, errInvoke
			}
		}
	}
	if errors.Is(e, os.ErrNotExist) && newTarget != nil {
		if !newTarget.Valid() || newTarget.PullScope != p.Scope {
			return saved, errInvoke
		}
		state, wire, e := newEnvelope(c.Key, c.Recipient, c.Host, c.Session, id, review, "", "")
		if e != nil {
			return saved, e
		}
		data, e := json.Marshal(resultAttempt{state, wire, *newTarget})
		if e != nil {
			return saved, e
		}
		sealed := aead.Seal(nil, nil, data, associated)
		clear(data)
		e = WriteReply(filepath.Join(c.Private, name), sealed)
		if e != nil && !errors.Is(e, os.ErrExist) {
			return saved, e
		}
		raw, e = read(c.Private, name, 16384)
		if e != nil {
			return saved, e
		}
	} else if e != nil {
		return saved, errInvoke
	}
	data, e := aead.Open(nil, nil, raw, associated)
	if e != nil {
		return saved, errInvoke
	}
	defer clear(data)
	if json.Unmarshal(data, &saved) != nil {
		return saved, errInvoke
	}
	t := saved.Local.Ticket
	if t.ID != id || t.Review != review || t.Session != p.Session || t.Public != p.Public || t.Audience != p.Audience || t.Purpose != "" || hex.EncodeToString(saved.Local.Host) != b.Host || saved.Target.PullScope != p.Scope || !saved.Target.Known() || (newTarget != nil && *newTarget != saved.Target) {
		return resultAttempt{}, errInvoke
	}
	return saved, nil
}

// Prepare only while submitting/retrying a request. A separate holder command
// must still confirm the decision and explicitly execute the recorded action.
func SubmitBridgeAction(c PollConfig, inbox string, p BridgeProfile, key, reason string, n int, plan []byte) (Submitted, error) {
	target, e := gateway.RecordedIntent(p.Scope.Repo, n, plan)
	if e != nil {
		return Submitted{}, e
	}
	rec, e := SubmitBridgePull(c, inbox, p, key, reason, n, plan)
	if e != nil {
		return Submitted{}, e
	}
	a, e := loadResultAttempt(c, p, rec.ID, rec.Review, &target)
	if e != nil {
		return Submitted{}, e
	}
	name := rec.ID + ".invoke.age"
	e = WriteReply(filepath.Join(c.Exchange, name), a.Wire)
	if errors.Is(e, os.ErrExist) {
		existing, err := read(c.Exchange, name, 8192)
		if err != nil || !bytes.Equal(a.Wire, existing) {
			return Submitted{}, errInvoke
		}
	} else if e != nil {
		return Submitted{}, e
	}
	return rec, nil
}

// Collect never prepares or publishes a ticket, issues an approval, or invokes
// a callback. Missing local recipient state is terminal for that recipient.
func CollectBridgeResult(c PollConfig, p BridgeProfile, id, review string) (BridgeResult, error) {
	a, e := loadResultAttempt(c, p, id, review, nil)
	if e != nil {
		return BridgeResult{}, errInvoke
	}
	data, e := read(c.Exchange, id+".result.age", 8192)
	if errors.Is(e, os.ErrNotExist) {
		return BridgeResult{State: "awaiting-receipt", ID: id}, nil
	}
	if e != nil {
		return BridgeResult{}, errInvoke
	}
	r, e := decodeReply(a.Local, data)
	if e != nil || r.Pull == nil || r.Pull.Source != a.Target.Backend || r.Pull.Pull.Number != a.Target.Number {
		return BridgeResult{}, errInvoke
	}
	return BridgeResult{State: "succeeded", ID: id, Result: r.Pull}, nil
}
