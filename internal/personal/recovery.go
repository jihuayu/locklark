package personal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const backupDomain = "locklark/personal/backup/v1"
const maxArchive = 32 << 20
const maxChains = 32

// Chain is verification material only. Signatures are kept byte-for-byte.
type Chain struct {
	Public ed25519.PublicKey `json:"audit_public"`
	Events []Event           `json:"events"`
}
type payload struct {
	Generation string
	Epoch      uint64
	Items      []vault.Item
	Chains     []Chain
}
type signedBackup struct {
	Body      payload
	Signature []byte
}
type envelope struct {
	Version    int
	Generation string
	Share      account.Slot
	Data       []byte
}

func NewRecovery() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	defer clear(raw[:])
	return "LLR1-" + b32.EncodeToString(raw[:]), nil
}
func kitBytes(kit string) ([]byte, error) {
	if len(kit) != 57 || !strings.HasPrefix(kit, "LLR1-") {
		return nil, invalid
	}
	raw, err := b32.DecodeString(kit[5:])
	if err != nil || len(raw) != 32 || b32.EncodeToString(raw) != kit[5:] {
		clear(raw)
		return nil, invalid
	}
	return raw, nil
}
func generation(kit string) (string, error) {
	raw, err := kitBytes(kit)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:16]), nil
}
func digestOK(s string) bool {
	p, e := hex.DecodeString(s)
	return e == nil && len(p) == 32 && hex.EncodeToString(p) == s
}
func digest(v any) (string, error) {
	p, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	defer clear(p)
	h := sha256.Sum256(p)
	return hex.EncodeToString(h[:]), nil
}
func aeadBackup(share []byte, kit, gen string) (cipher.AEAD, error) {
	g, err := generation(kit)
	if err != nil || g != gen || len(share) != 32 {
		return nil, invalid
	}
	raw, _ := kitBytes(kit)
	defer clear(raw)
	k, err := hkdf.Key(sha256.New, share, raw, backupDomain+"/"+gen, 32)
	if err != nil {
		return nil, invalid
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, invalid
	}
	return cipher.NewGCMWithRandomNonce(block)
}
func payloadProof(p payload) ([]byte, error) {
	d, e := digest(p)
	return []byte(backupDomain + "/manifest/" + d), e
}
func verifyChains(chains []Chain) error {
	if len(chains) == 0 || len(chains) > maxChains {
		return invalid
	}
	seen := map[string]bool{}
	for idx, c := range chains {
		if len(c.Public) != ed25519.PublicKeySize || seen[string(c.Public)] || len(c.Events) < 2 {
			return invalid
		}
		seen[string(c.Public)] = true
		first, last := c.Events[0], c.Events[len(c.Events)-1]
		if idx == 0 {
			if first.Action != "vault.create" {
				return invalid
			}
		} else {
			d, e := digest(chains[:idx])
			if e != nil || first.Action != "vault.restore" || first.Link != d {
				return invalid
			}
		}
		if last.Action != "backup.prepare" {
			return invalid
		}
		prev := ""
		for j, ev := range c.Events {
			if ev.verify(c.Public, uint64(j+1), prev) != nil {
				return invalid
			}
			prev = ev.hash()
		}
	}
	return nil
}
func encodeArchive(p payload, pw string, key, accountID []byte, kit string, priv ed25519.PrivateKey) ([]byte, error) {
	if verifyChains(p.Chains) != nil {
		return nil, invalid
	}
	proof, err := payloadProof(p)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(signedBackup{p, ed25519.Sign(priv, proof)})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > maxArchive/2 {
		return nil, invalid
	}
	share := make([]byte, 32)
	defer clear(share)
	if _, err = rand.Read(share); err != nil {
		return nil, err
	}
	slot, err := account.Wrap(pw, key, accountID, share)
	if err != nil {
		return nil, invalid
	}
	a, err := aeadBackup(share, kit, p.Generation)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{1, p.Generation, slot, a.Seal(nil, nil, raw, []byte(backupDomain+"/"+p.Generation))})
}
func decodeArchive(path, pw string, key []byte, kit string) (*payload, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > maxArchive {
		return nil, invalid
	}
	b, e := io.ReadAll(io.LimitReader(f, maxArchive+1))
	if e != nil || len(b) > maxArchive {
		return nil, invalid
	}
	var env envelope
	if json.Unmarshal(b, &env) != nil || env.Version != 1 {
		return nil, invalid
	}
	g, e := generation(kit)
	if e != nil || g != env.Generation {
		return nil, invalid
	}
	share, e := account.Unwrap(pw, key, env.Share)
	if e != nil {
		return nil, invalid
	}
	defer clear(share)
	a, e := aeadBackup(share, kit, g)
	if e != nil {
		return nil, e
	}
	plain, e := a.Open(nil, nil, env.Data, []byte(backupDomain+"/"+g))
	if e != nil {
		return nil, invalid
	}
	defer clear(plain)
	var body signedBackup
	if json.Unmarshal(plain, &body) != nil {
		return nil, invalid
	}
	p := &body.Body
	if p.Generation != g || p.Items == nil || p.Epoch == 0 || p.Epoch == ^uint64(0) || verifyChains(p.Chains) != nil {
		return nil, invalid
	}
	last := p.Chains[len(p.Chains)-1]
	proof, e := payloadProof(*p)
	if e != nil || last.Events[len(last.Events)-1].Link != g || !ed25519.Verify(last.Public, proof, body.Signature) {
		return nil, invalid
	}
	return p, nil
}

var archiveKey = []byte("archived-audit/v1")

func loadChains(b *bolt.Bucket, i identity, anchor string) ([]Chain, error) {
	raw := b.Get(archiveKey)
	if anchor == "" {
		if raw != nil {
			return nil, invalid
		}
		return nil, nil
	}
	if !digestOK(anchor) || len(raw) > maxArchive {
		return nil, invalid
	}
	a, e := auditCipher(i)
	if e != nil {
		return nil, invalid
	}
	p, e := a.Open(nil, nil, raw, archiveKey)
	if e != nil {
		return nil, invalid
	}
	defer clear(p)
	var chains []Chain
	if json.Unmarshal(p, &chains) != nil {
		return nil, invalid
	}
	d, e := digest(chains)
	if e != nil || d != anchor || verifyChains(chains) != nil {
		return nil, invalid
	}
	return chains, nil
}
func initializeRecovered(b *bolt.Bucket, i identity, p *payload) error {
	a, e := auditCipher(i)
	if e != nil {
		return e
	}
	enc, e := sealedJSON(a, archiveKey, p.Chains)
	if e != nil {
		return e
	}
	if e = b.Put(archiveKey, enc); e != nil {
		return e
	}
	anchor, e := digest(p.Chains)
	if e != nil {
		return e
	}
	s, e := seal(b, i, p.Epoch+1, p.Items)
	if e != nil {
		return e
	}
	tip := auditTip{}
	ev, e := appendLinked(b, i, tip, s, "vault.restore", "", "succeeded", "", anchor)
	if e != nil {
		return e
	}
	for _, it := range p.Items {
		if !idOK(it.ID) {
			return invalid
		}
		tip = auditTip{Count: ev.Sequence, Last: ev.hash(), Origin: anchor}
		ev, e = appendEvent(b, i, tip, s, "item.restore", it.ID, "succeeded", "")
		if e != nil {
			return e
		}
	}
	return nil
}
func Backup(src, dest, pw string, key []byte, kit string) error {
	if _, e := generation(kit); e != nil {
		return e
	}
	if _, e := os.Lstat(dest); e == nil {
		return os.ErrExist
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(dest), ".locklark-backup-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	r, e := command(src, pw, key, "backup.prepare", vault.Item{}, nil, kit)
	if e != nil {
		return e
	}
	if _, e = f.Write(r.archive); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return publish(f.Name(), dest)
}
func Restore(src, dest, pw string, oldKey []byte, kit string, newKey []byte) error {
	if len(newKey) != 16 || bytes.Equal(oldKey, newKey) {
		return invalid
	}
	p, e := decodeArchive(src, pw, oldKey, kit)
	if e != nil {
		return e
	}
	return create(dest, pw, newKey, p)
}
func ArchivedAudit(path, pw string, key []byte) ([]Chain, error) {
	r, e := command(path, pw, key, "audit.archived", vault.Item{}, nil)
	return r.chains, e
}
