package directory

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestRetiredIDsAndKeysCannotBeReused(t *testing.T) {
	f := setup(t)
	path, first, _ := initialize(t, f)
	p, s, err := Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members[1:], f.items)
	if err != nil {
		t.Fatal(err)
	}
	head, err := Commit(path, f.cfg, f.sequencer, p, s)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	base := Member{ID: fmt.Sprintf("%032x", 12), Role: "reader", Devices: []Device{{ID: fmt.Sprintf("%032x", 23), Encryption: fresh.Recipient().String(), Signing: public(signing(16))}}}
	for _, test := range []struct {
		name   string
		change func(*Member)
	}{
		{"member ID", func(m *Member) { m.ID = f.members[0].ID }},
		{"device ID", func(m *Member) { m.Devices[0].ID = f.members[0].Devices[0].ID }},
		{"encryption key", func(m *Member) { m.Devices[0].Encryption = f.members[0].Devices[0].Encryption }},
		{"signing key", func(m *Member) { m.Devices[0].Signing = f.members[0].Devices[0].Signing }},
		{"move active device", func(m *Member) { m.Devices[0] = f.members[1].Devices[0] }},
		{"change active device key", func(m *Member) { m.ID = f.members[1].ID; m.Devices[0].ID = f.members[1].Devices[0].ID }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := cloneMembers([]Member{base})[0]
			test.change(&m)
			// The proposal replaces the whole roster; no duplicates within this request.
			p, s, err := Build(f.cfg, f.owner, f.publisher, head.Checkpoint(), []Member{m}, f.items)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Commit(path, f.cfg, f.sequencer, p, s); err != ErrInvalid {
				t.Fatal("retired or moved identity accepted", err)
			}
		})
	}
}
func TestPinsRosterAndModeBounds(t *testing.T) {
	f := setup(t)
	pins := Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.other), public(f.owner)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)}
	cfg, err := NewConfig(pins)
	if err != nil || cfg.Genesis() != f.cfg.Genesis() {
		t.Fatal("owner order affects scope", err)
	}
	pins.Owners[0] = public(signing(40))
	if cfg.Genesis() != f.cfg.Genesis() {
		t.Fatal("pins alias")
	}
	for _, alter := range []func(*Pins){
		func(p *Pins) { p.Owners = []string{public(f.owner), public(f.owner)} },
		func(p *Pins) { p.Sequencer = public(f.owner) }, func(p *Pins) { p.Publisher = p.Sequencer },
		func(p *Pins) { p.Owners = []string{fmt.Sprintf("%064x", 0)} }, func(p *Pins) { p.Vault = "bad" },
	} {
		p := pins
		alter(&p)
		if _, err := NewConfig(p); err == nil {
			t.Fatal("invalid pins accepted")
		}
	}
	for _, alter := range []func([]Member){
		func(m []Member) { m[0].Devices[0].Signing = public(f.owner) },
		func(m []Member) { m[0].Devices[0].Encryption = m[0].Devices[1].Encryption },
		func(m []Member) { m[0].Devices[0].Signing = m[0].Devices[1].Signing },
		func(m []Member) { m[1].ID = m[0].Devices[0].ID },
		func(m []Member) { m[0], m[1] = m[1], m[0] },
		func(m []Member) { m[0].Devices[0].Encryption = "AGE1INVALID" },
	} {
		m := cloneMembers(f.members)
		alter(m)
		if _, _, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), m, f.items); err == nil {
			t.Fatal("invalid roster accepted")
		}
	}
	if _, _, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), []Member{}, f.items); err == nil {
		t.Fatal("empty active directory")
	}
	if _, err := Freeze(f.cfg, f.owner, f.cfg.Genesis()); err == nil {
		t.Fatal("frozen genesis")
	}
	if _, _, err := Build(f.cfg, signing(42), f.publisher, f.cfg.Genesis(), f.members, f.items); err == nil {
		t.Fatal("unknown owner")
	}
	cp := f.cfg.Genesis()
	cp.Version = maxVersions
	cp.Hash = fmt.Sprintf("%064x", 1)
	if _, _, err := Build(f.cfg, f.owner, f.publisher, cp, f.members, f.items); err == nil {
		t.Fatal("capacity bypass")
	}
	path, first, _ := initialize(t, f)
	freeze, err := Freeze(f.cfg, f.owner, first.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	freeze.Members = cloneMembers(f.members)
	freeze.Signature = ed25519.Sign(f.owner, freeze.proof())
	if err = f.cfg.verifyProposal(freeze); err == nil {
		t.Fatal("frozen roster not empty")
	}
	foreign, err := NewConfig(Pins{Team: fmt.Sprintf("%032x", 3), Vault: pins.Vault, Owners: []string{public(f.owner)}, Sequencer: pins.Sequencer, Publisher: pins.Publisher})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Read(path, foreign, foreign.Genesis()); err == nil {
		t.Fatal("cross-scope directory")
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err = Read(missing, f.cfg, f.cfg.Genesis()); err == nil {
		t.Fatal("missing directory silently initialized")
	}
}

func TestOversizedUntrustedKeys(t *testing.T) {
	f := setup(t)
	members := cloneMembers(f.members)
	members[0].Devices[0].Signing = strings.Repeat("a", 1<<20)
	if _, _, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), members, f.items); err != ErrInvalid {
		t.Fatal("oversized device key", err)
	}
	p, _, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	p.Owner = strings.Repeat("a", 1<<20)
	if err = f.cfg.verifyProposal(p); err != ErrInvalid {
		t.Fatal("oversized owner key", err)
	}
}
