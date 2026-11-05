package preview

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jihuayu/locklark/internal/gateway"
	bolt "go.etcd.io/bbolt"
)

func timeActive(p BridgeProfile) bool {
	now := time.Now().UTC()
	return !now.Before(p.Issued) && now.Before(p.Expires)
}

const profileLife = 5 * time.Minute

type BridgeProfile struct {
	Session, Public, Audience string
	Scope                     gateway.PullScope
	Issued, Expires           time.Time
	Sig                       []byte
}

func (p BridgeProfile) proof() []byte {
	p.Sig = nil
	return message("locklark/stdio-profile/v1\x00", p)
}
func ExportBridgeProfile(device, session, path string) error {
	id, e := mailIdentity(device)
	if e != nil {
		return errSession
	}
	key, e := localSigner(device, "decision")
	if e != nil {
		return errSession
	}
	defer clear(key)
	var raw []byte
	e = withHistory(device, id, false, func(b *bolt.Bucket, _ history) error {
		reg, e := readRegistry(b.Tx(), id, key.Public().(ed25519.PublicKey))
		if e != nil {
			return e
		}
		c, ok := reg.latest[session]
		now := time.Now().UTC()
		if !ok || c.Action != "enrolled" || c.PullScope == nil || now.Before(c.At) || !now.Before(c.Expires) {
			return errSession
		}
		scope := *c.PullScope
		if !scope.Known() || !safeRepo(scope.Repo) {
			return errSession
		}
		until := now.Add(profileLife)
		if c.Expires.Before(until) {
			until = c.Expires
		}
		p := BridgeProfile{c.Session, c.Public, c.Audience, scope, now, until, nil}
		p.Sig = ed25519.Sign(key, p.proof())
		raw, e = json.Marshal(p)
		return e
	})
	if e != nil {
		return errSession
	}
	return WriteReply(path, raw)
}
func LoadBridgeProfile(path string, c PollConfig) (BridgeProfile, error) {
	var p BridgeProfile
	raw, e := readPath(path, 4096)
	if e != nil || json.Unmarshal(raw, &p) != nil {
		return p, errSession
	}
	host, e := readPath(c.Host, 32)
	if e != nil || !validPublic(hex.EncodeToString(host)) || !ed25519.Verify(host, p.proof(), p.Sig) {
		return BridgeProfile{}, errSession
	}
	audience, e := readPath(c.Recipient, 256)
	if e != nil || string(bytes.TrimSpace(audience)) != p.Audience {
		return BridgeProfile{}, errSession
	}
	seed, e := readPath(c.Key, 32)
	if e != nil || len(seed) != 32 {
		return BridgeProfile{}, errSession
	}
	defer clear(seed)
	signer := ed25519.NewKeyFromSeed(seed)
	defer clear(signer)
	now := time.Now().UTC()
	if !p.Scope.Known() || !safeRepo(p.Scope.Repo) || hex.EncodeToString(signer[32:]) != p.Public || !validSession(p.Session) || (c.Session != "" && c.Session != p.Session) || now.Before(p.Issued) || !now.Before(p.Expires) || p.Expires.Sub(p.Issued) > profileLife {
		return BridgeProfile{}, errSession
	}
	return p, nil
}
