package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jihuayu/locklark/internal/vault"
)

// NewConfigWithWriterACL permits data-only publications by admitted writer
// devices. It pins a distinct policy scope, requires dual-key admission, and
// leaves membership, roles and freezing exclusively under owner authority.
// This is a new-directory policy, not a migration of existing history.
func NewConfigWithWriterACL(pins Pins) (*Config, error) {
	c, err := NewConfigWithPossession(pins)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(append([]byte("locklark/team-directory/writer-acl/v1\x00"), []byte(c.scope)...))
	c.scope = hex.EncodeToString(h[:])
	c.writerACL = true
	return c, nil
}

// BuildUpdate constructs a candidate from a signed parent, retaining its exact
// roster. A valid receipt alone is not proof of current authorization: Commit
// replays the trusted local history and checks the exact parent in its transaction.
// Writers already know plaintext; their signatures cannot prove that a malicious
// author encrypted only to the roster. Honest clients use this recipient builder.
func BuildUpdate(c *Config, signer ed25519.PrivateKey, parent Receipt, items []vault.Item) (Proposal, vault.Snapshot, error) {
	if !c.valid() || !c.writerACL || !validPrivate(signer) || c.verifyReceipt(parent) != nil || parent.Proposal.Mode != "active" || parent.Proposal.Epoch >= maxVersions {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	public := hex.EncodeToString(signer.Public().(ed25519.PublicKey))
	device := ""
	for _, m := range parent.Proposal.Members {
		if m.Role != "writer" {
			continue
		}
		for _, d := range m.Devices {
			if d.Signing == public {
				device = d.ID
			}
		}
	}
	if device == "" {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	members := cloneMembers(parent.Proposal.Members)
	recipients, err := c.roster(members, false)
	if err != nil {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	s, err := vault.SealItems([]byte("locklark/team/items/v1/"+c.scope), items, parent.Proposal.Epoch+1, recipients, signer)
	if err != nil {
		return Proposal{}, vault.Snapshot{}, ErrInvalid
	}
	p := Proposal{Scope: c.scope, Parent: parent.Checkpoint(), Epoch: s.Epoch, Mode: "active", Members: members, SnapshotDigest: snapshotDigest(s), AuthorDevice: device}
	p.Signature = ed25519.Sign(signer, p.proof())
	return p, s, nil
}

// proposalSigner establishes signature self-consistency only. Writer authority
// is checked separately against the preceding verified state by verifyTransition.
// Call only after roster validation (which bounds and canonicalizes all keys).
func (c *Config) proposalSigner(p Proposal) (ed25519.PublicKey, error) {
	if p.AuthorDevice == "" {
		if !hexSize(p.Owner, 32) || len(c.owners[p.Owner]) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		return c.owners[p.Owner], nil
	}
	if !c.writerACL || !hexSize(p.AuthorDevice, 16) || p.Owner != "" || p.Mode != "active" || p.Parent.Version == 0 || len(p.Admissions) != 0 {
		return nil, ErrInvalid
	}
	for _, m := range p.Members {
		for _, d := range m.Devices {
			if d.ID == p.AuthorDevice {
				return signingKey(d.Signing)
			}
		}
	}
	return nil, ErrInvalid
}

func (c *Config) snapshotSigner(p Proposal) (ed25519.PublicKey, error) {
	if p.Mode == "frozen" {
		return nil, nil
	}
	if p.AuthorDevice == "" {
		return bytes.Clone(c.publisher), nil
	}
	return c.proposalSigner(p)
}

func (c *Config) verifyTransition(e *evolution, p Proposal) error {
	if p.AuthorDevice != "" {
		if !c.writerACL || e.mode != "active" || p.Mode != "active" || len(p.Admissions) != 0 || !bytes.Equal(encoded(e.roster), encoded(p.Members)) {
			return ErrInvalid
		}
		authorized := false
		for _, m := range e.roster {
			if m.Role != "writer" {
				continue
			}
			for _, d := range m.Devices {
				if d.ID == p.AuthorDevice {
					authorized = true
				}
			}
		}
		if !authorized {
			return ErrInvalid
		}
	}
	return c.verifyNewDevices(e, p)
}
