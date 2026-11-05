// Package directory implements a bounded, local trusted team sequencer. It
// stores public membership metadata and signed ciphertext, never private keys.
// Its signatures alone do not establish the latest remote state.
package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"filippo.io/age"
	"filippo.io/edwards25519"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrInvalid = errors.New("invalid team directory configuration, proposal or evidence")
var ErrConflict = errors.New("team directory parent changed; reread trusted state")
var ErrStorage = errors.New("team directory storage failed; outcome may be committed")
var ErrExists = errors.New("team directory already exists")
var ErrCapacity = errors.New("team directory version capacity reached")

const maxVersions = 1024
const maxRecord = 128 << 10

// Owners use a 1-of-N policy. All signing roles must have independent keys.
// Pins must come from a trusted bootstrap, never the directory or relay itself.
type Pins struct {
	Team, Vault          string
	Owners               []string
	Sequencer, Publisher string
}
type Config struct {
	requirePossession    bool
	scope                string
	owners               map[string]ed25519.PublicKey
	sequencer, publisher ed25519.PublicKey
	reserved             map[string]bool
}
type Checkpoint struct {
	Scope   string `json:"scope"`
	Version uint64 `json:"version"`
	Hash    string `json:"hash"`
}

// NewConfig stores owner assertions. NewConfigWithPossession additionally
// requires a device admission proving both private keys; neither proves that
// keys cannot be copied or that they belong to one physical machine.
type Device struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Signing    string `json:"signing"`
}

// Role is directory metadata, not an enforced operation ACL. Every registered
// device receives the whole snapshot; publication still requires an owner.
type Member struct {
	ID      string   `json:"id"`
	Role    string   `json:"role"`
	Devices []Device `json:"devices"`
}
type Proposal struct {
	Scope          string      `json:"scope"`
	Parent         Checkpoint  `json:"parent"`
	Epoch          uint64      `json:"epoch"`
	Mode           string      `json:"mode"`
	Members        []Member    `json:"members"`
	SnapshotDigest string      `json:"snapshot_digest"`
	Owner          string      `json:"owner"`
	Signature      []byte      `json:"signature"`
	Admissions     []Admission `json:"admissions,omitempty"`
}
type Receipt struct {
	Proposal  Proposal `json:"proposal"`
	Signature []byte   `json:"signature"`
}
type View struct {
	Receipt  Receipt        `json:"receipt"`
	Snapshot vault.Snapshot `json:"snapshot"`
}

func hexSize(raw string, n int) bool {
	if len(raw) != 2*n {
		return false
	}
	b, err := hex.DecodeString(raw)
	return err == nil && len(b) == n && hex.EncodeToString(b) == raw
}
func signingKey(raw string) (ed25519.PublicKey, error) {
	if !hexSize(raw, 32) {
		return nil, ErrInvalid
	}
	b, _ := hex.DecodeString(raw)
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil || !bytes.Equal(p.Bytes(), b) || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(b), nil
}
func NewConfig(pins Pins) (*Config, error) {
	if !hexSize(pins.Team, 16) || !hexSize(pins.Vault, 16) || len(pins.Owners) < 1 || len(pins.Owners) > 8 {
		return nil, ErrInvalid
	}
	c := &Config{owners: map[string]ed25519.PublicKey{}, reserved: map[string]bool{}}
	owners := append([]string(nil), pins.Owners...)
	sort.Strings(owners)
	parts := []string{pins.Team, pins.Vault}
	for _, raw := range append(owners, pins.Sequencer, pins.Publisher) {
		key, err := signingKey(raw)
		if err != nil || c.reserved[raw] {
			return nil, ErrInvalid
		}
		c.reserved[raw] = true
		if raw == pins.Sequencer {
			c.sequencer = key
		} else if raw == pins.Publisher {
			c.publisher = key
		} else {
			c.owners[raw] = key
		}
	}
	// Length framing and the owner count separate every field and signing role.
	parts = append(parts, owners...)
	parts = append(parts, pins.Sequencer, pins.Publisher)
	h := sha256.New()
	h.Write([]byte("locklark/team-directory/config/v1\x00"))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(owners))))
	for _, p := range parts {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
		h.Write([]byte(p))
	}
	c.scope = hex.EncodeToString(h.Sum(nil))
	return c, nil
}
func (c *Config) valid() bool {
	return c != nil && hexSize(c.scope, 32) && len(c.owners) > 0 && len(c.sequencer) == 32 && len(c.publisher) == 32
}
func (c *Config) Genesis() Checkpoint {
	if !c.valid() {
		return Checkpoint{}
	}
	return Checkpoint{Scope: c.scope}
}
func (c *Config) validCheckpoint(cp Checkpoint) bool {
	return c.valid() && cp.Scope == c.scope && cp.Version <= maxVersions && ((cp.Version == 0 && cp.Hash == "") || (cp.Version > 0 && hexSize(cp.Hash, 32)))
}

// The only values passed here are this package's fixed structs of strings,
// integers and slices. They cannot contain cycles or custom JSON marshalers.
func encoded(v any) []byte { raw, _ := json.Marshal(v); return raw }
func (p Proposal) proof() []byte {
	p.Signature = nil
	return append([]byte("locklark/team-directory/proposal/v1\x00"), encoded(p)...)
}
func (r Receipt) proof() []byte {
	r.Signature = nil
	return append([]byte("locklark/team-directory/receipt/v1\x00"), encoded(r)...)
}
func (r Receipt) Checkpoint() Checkpoint {
	h := sha256.Sum256(append([]byte("locklark/team-directory/head/v1\x00"), encoded(r)...))
	return Checkpoint{r.Proposal.Scope, r.Proposal.Epoch, hex.EncodeToString(h[:])}
}
func snapshotDigest(s vault.Snapshot) string {
	h := sha256.New()
	h.Write([]byte("locklark/team-directory/snapshot/v1\x00"))
	h.Write(binary.BigEndian.AppendUint64(nil, s.Epoch))
	for _, part := range [][]byte{s.Database, s.Envelope, s.Signature} {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(part))))
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func cloneMembers(members []Member) []Member {
	out := make([]Member, len(members))
	copy(out, members)
	for i := range out {
		out[i].Devices = append([]Device(nil), members[i].Devices...)
	}
	return out
}
func (c *Config) roster(members []Member, empty bool) ([]*age.X25519Recipient, error) {
	if !c.valid() || members == nil || len(members) > 64 || (!empty && len(members) == 0) {
		return nil, ErrInvalid
	}
	ids, enc, sign := map[string]bool{}, map[string]bool{}, map[string]bool{}
	recipients := make([]*age.X25519Recipient, 0)
	previous := ""
	for _, m := range members {
		if !hexSize(m.ID, 16) || m.ID <= previous || ids[m.ID] || m.Role != "reader" && m.Role != "writer" || len(m.Devices) == 0 || len(m.Devices) > 64 {
			return nil, ErrInvalid
		}
		previous = m.ID
		ids[m.ID] = true
		deviceID := ""
		for _, d := range m.Devices {
			if len(d.Signing) != 64 || len(d.Encryption) != 62 || !hexSize(d.ID, 16) || d.ID <= deviceID || ids[d.ID] || enc[d.Encryption] || sign[d.Signing] || c.reserved[d.Signing] {
				return nil, ErrInvalid
			}
			if _, err := signingKey(d.Signing); err != nil {
				return nil, err
			}
			recipient, err := age.ParseX25519Recipient(d.Encryption)
			if err != nil || recipient.String() != d.Encryption {
				return nil, ErrInvalid
			}
			ids[d.ID], enc[d.Encryption], sign[d.Signing] = true, true, true
			deviceID = d.ID
			recipients = append(recipients, recipient)
			if len(recipients) > 64 {
				return nil, ErrInvalid
			}
		}
	}
	return recipients, nil
}
func validPrivate(k ed25519.PrivateKey) bool {
	if len(k) != ed25519.PrivateKeySize {
		return false
	}
	canonical := ed25519.NewKeyFromSeed(k[:32])
	defer clear(canonical)
	return bytes.Equal(k, canonical)
}
func (c *Config) owner(k ed25519.PrivateKey) (string, error) {
	if !c.valid() || !validPrivate(k) {
		return "", ErrInvalid
	}
	pub := hex.EncodeToString(k.Public().(ed25519.PublicKey))
	if c.owners[pub] == nil {
		return "", ErrInvalid
	}
	return pub, nil
}

// Build always creates fresh encryption material from the complete, independently
// supplied items. It never recovers data or reuses a historical snapshot key.
// Members must be in canonical ID order. Recipients cannot be supplied separately.
func Build(c *Config, owner, publisher ed25519.PrivateKey, parent Checkpoint, members []Member, items []vault.Item, admissions ...Admission) (Proposal, vault.Snapshot, error) {
	who, err := c.owner(owner)
	if err != nil || !c.validCheckpoint(parent) || parent.Version >= maxVersions || !validPrivate(publisher) || !bytes.Equal(publisher.Public().(ed25519.PublicKey), c.publisher) {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	recipients, err := c.roster(members, false)
	if err != nil {
		return Proposal{}, vault.Snapshot{}, err
	}
	members = cloneMembers(members)
	if len(admissions) > 64 {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	// Validate bounds before copying/sorting caller-owned proof buffers.
	for _, proof := range admissions {
		if VerifyAdmission(c, proof.Challenge.Enrollment, proof) != nil {
			return Proposal{}, vault.Snapshot{}, ErrInvalid
		}
	}
	proofs := orderedAdmissions(admissions)
	if c.verifyAdmissions(Proposal{Parent: parent, Mode: "active", Members: members, Admissions: proofs}) != nil {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	s, err := vault.SealItems([]byte("locklark/team/items/v1/"+c.scope), items, parent.Version+1, recipients, publisher)
	if err != nil {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	p := Proposal{Scope: c.scope, Parent: parent, Epoch: s.Epoch, Mode: "active", Members: members, SnapshotDigest: snapshotDigest(s), Owner: who, Admissions: proofs}
	p.Signature = ed25519.Sign(owner, p.proof())
	return p, s, nil
}

// Freeze retires the entire roster, including the last device, and publishes no
// ciphertext. Resuming requires fresh identities/keys and independently held data.
func Freeze(c *Config, owner ed25519.PrivateKey, parent Checkpoint) (Proposal, error) {
	who, err := c.owner(owner)
	if err != nil || !c.validCheckpoint(parent) || parent.Version == 0 || parent.Version >= maxVersions {
		return Proposal{}, ErrInvalid
	}
	p := Proposal{Scope: c.scope, Parent: parent, Epoch: parent.Version + 1, Mode: "frozen", Members: []Member{}, Owner: who}
	p.Signature = ed25519.Sign(owner, p.proof())
	return p, nil
}
func (c *Config) verifyProposal(p Proposal) error {
	if !c.valid() || p.Scope != c.scope || !c.validCheckpoint(p.Parent) || p.Epoch != p.Parent.Version+1 || p.Epoch > maxVersions || !hexSize(p.Owner, 32) || len(c.owners[p.Owner]) != ed25519.PublicKeySize || len(p.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	switch p.Mode {
	case "active":
		if !hexSize(p.SnapshotDigest, 32) {
			return ErrInvalid
		}
		if _, err := c.roster(p.Members, false); err != nil {
			return err
		}
	case "frozen":
		if p.Parent.Version == 0 || p.SnapshotDigest != "" || p.Members == nil || len(p.Members) != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if c.verifyAdmissions(p) != nil {
		return ErrInvalid
	}
	if !ed25519.Verify(c.owners[p.Owner], p.proof(), p.Signature) {
		return ErrInvalid
	}
	return nil
}
func (c *Config) verifySnapshot(p Proposal, s vault.Snapshot) error {
	if p.Mode == "frozen" {
		if s.Epoch != 0 || len(s.Database) != 0 || len(s.Envelope) != 0 || len(s.Signature) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if vault.VerifySnapshot(s, c.publisher, p.Epoch) != nil || snapshotDigest(s) != p.SnapshotDigest {
		return ErrInvalid
	}
	return nil
}
func (c *Config) verifyReceipt(r Receipt) error {
	if c.verifyProposal(r.Proposal) != nil || !ed25519.Verify(c.sequencer, r.proof(), r.Signature) {
		return ErrInvalid
	}
	return nil
}
