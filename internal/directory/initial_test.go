package directory

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
)

func initialFixture(t *testing.T, policy string) (fixture, Proposal, vault.Snapshot) {
	t.Helper()
	f := setup(t)
	pins := Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.owner), public(f.other)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)}
	var err error
	switch policy {
	case "legacy":
	case "possession":
		f.cfg, err = NewConfigWithPossession(pins)
	case "writer":
		f.cfg, err = NewConfigWithWriterACL(pins)
	default:
		t.Fatal("unknown test policy")
	}
	if err != nil {
		t.Fatal("synthetic configuration failed")
	}
	var proofs []Admission
	if policy != "legacy" {
		index := 0
		for _, member := range f.members {
			for _, device := range member.Devices {
				proofs = append(proofs, attest(t, f, f.cfg.Genesis(), member.ID, device, f.devices[index], signing(byte(10+index))))
				index++
			}
		}
	}
	p, s, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), f.members, f.items, proofs...)
	if err != nil {
		t.Fatal("synthetic initial Build failed")
	}
	return f, p, s
}

func cloneInitialProposal(p Proposal) Proposal {
	p.Members = cloneMembers(p.Members)
	p.Admissions = cloneAdmissions(p.Admissions)
	p.Signature = bytes.Clone(p.Signature)
	return p
}

func cloneInitialSnapshot(s vault.Snapshot) vault.Snapshot {
	s.Database, s.Envelope, s.Signature = bytes.Clone(s.Database), bytes.Clone(s.Envelope), bytes.Clone(s.Signature)
	return s
}

func TestVerifyInitialRealBuildMatchesCreate(t *testing.T) {
	for _, policy := range []string{"legacy", "possession", "writer"} {
		t.Run(policy, func(t *testing.T) {
			f, p, s := initialFixture(t, policy)
			if VerifyInitial(f.cfg, p, s) != nil {
				t.Fatal("valid initial artifacts refused")
			}
			path := filepath.Join(t.TempDir(), "initial.db")
			r, err := Create(path, f.cfg, f.sequencer, p, s)
			if err != nil || r.Proposal.Epoch != 1 || r.Proposal.Parent != f.cfg.Genesis() {
				t.Fatal("Create disagreed with pure initial verification")
			}
			if _, err = Read(path, f.cfg, r.Checkpoint()); err != nil {
				t.Fatal("created bootstrap failed normal history verification")
			}
		})
	}
}

func TestVerifyInitialRejectsNoninitialAndMalformedProposals(t *testing.T) {
	f, base, snapshot := initialFixture(t, "writer")
	first := Receipt{Proposal: base}
	first.Signature = ed25519.Sign(f.sequencer, first.proof())
	next, nextSnapshot, err := Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members, f.items)
	if err != nil || f.cfg.verifyProposal(next) != nil || f.cfg.verifySnapshot(next, nextSnapshot) != nil {
		t.Fatal("valid noninitial test publication failed")
	}
	if VerifyInitial(f.cfg, next, nextSnapshot) != ErrInvalid {
		t.Fatal("valid later publication accepted as genesis")
	}
	frozen, err := Freeze(f.cfg, f.owner, first.Checkpoint())
	if err != nil || VerifyInitial(f.cfg, frozen, vault.Snapshot{}) != ErrInvalid {
		t.Fatal("later frozen publication accepted as genesis")
	}
	for _, test := range []struct {
		name   string
		change func(*Proposal)
	}{
		{"scope", func(p *Proposal) { p.Scope = fmt.Sprintf("%064x", 91) }},
		{"parent scope", func(p *Proposal) { p.Parent.Scope = fmt.Sprintf("%064x", 92) }},
		{"parent hash", func(p *Proposal) { p.Parent.Hash = fmt.Sprintf("%064x", 93) }},
		{"epoch", func(p *Proposal) { p.Epoch = 2 }},
		{"mode", func(p *Proposal) { p.Mode = "frozen" }},
		{"empty roster", func(p *Proposal) { p.Members = []Member{} }},
		{"role", func(p *Proposal) { p.Members[0].Role = "owner" }},
		{"signature", func(p *Proposal) { p.Signature[0] ^= 1 }},
		{"unsigned", func(p *Proposal) { p.Signature = nil }},
		{"device genesis", func(p *Proposal) { p.Owner = ""; p.AuthorDevice = p.Members[0].Devices[0].ID }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := cloneInitialProposal(base)
			test.change(&p)
			if test.name != "signature" && test.name != "unsigned" {
				p.Signature = ed25519.Sign(f.owner, p.proof())
			}
			if VerifyInitial(f.cfg, p, snapshot) != ErrInvalid {
				t.Fatal("invalid initial proposal accepted")
			}
		})
	}
	p := cloneInitialProposal(base)
	p.Owner = public(signing(91))
	p.Signature = ed25519.Sign(signing(91), p.proof())
	if VerifyInitial(f.cfg, p, snapshot) != ErrInvalid {
		t.Fatal("self-consistent unpinned owner accepted")
	}
}

func TestVerifyInitialRequiresEveryGenesisAdmission(t *testing.T) {
	f, base, snapshot := initialFixture(t, "writer")
	for _, test := range []struct {
		name   string
		change func(*Proposal)
	}{
		{"all omitted", func(p *Proposal) { p.Admissions = nil }},
		{"one omitted", func(p *Proposal) { p.Admissions = p.Admissions[1:] }},
		{"duplicate", func(p *Proposal) { p.Admissions = append(p.Admissions, p.Admissions[0]) }},
		{"unordered", func(p *Proposal) { p.Admissions[0], p.Admissions[1] = p.Admissions[1], p.Admissions[0] }},
		{"nonce", func(p *Proposal) { p.Admissions[0].Nonce[0] ^= 1 }},
		{"device signature", func(p *Proposal) { p.Admissions[0].Signature[0] ^= 1 }},
		{"challenge signature", func(p *Proposal) { p.Admissions[0].Challenge.Signature[0] ^= 1 }},
		{"enrollment", func(p *Proposal) { p.Admissions[0].Challenge.Enrollment.Member = f.members[1].ID }},
		{"other parent", func(p *Proposal) {
			proof := &p.Admissions[0]
			proof.Challenge.Enrollment.Parent = Checkpoint{Scope: f.cfg.scope, Version: 1, Hash: fmt.Sprintf("%064x", 96)}
			proof.Challenge.Signature = ed25519.Sign(f.owner, proof.Challenge.proof())
			proof.Signature = ed25519.Sign(signing(10), proof.proof())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := cloneInitialProposal(base)
			test.change(&p)
			p.Signature = ed25519.Sign(f.owner, p.proof())
			if test.name == "all omitted" || test.name == "one omitted" {
				if f.cfg.verifyProposal(p) != nil || f.cfg.verifySnapshot(p, snapshot) != nil {
					t.Fatal("missing-admission fixture did not isolate transition authorization")
				}
			}
			if VerifyInitial(f.cfg, p, snapshot) != ErrInvalid {
				t.Fatal("unproven genesis roster accepted")
			}
			path := filepath.Join(t.TempDir(), "refused.db")
			if _, err := Create(path, f.cfg, f.sequencer, p, snapshot); err != ErrInvalid {
				t.Fatal("Create disagreed on invalid admission")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("invalid admission published a directory")
			}
		})
	}
}

func TestVerifyInitialRejectsSnapshotAndPinChanges(t *testing.T) {
	f, p, base := initialFixture(t, "writer")
	recipients, err := f.cfg.roster(p.Members, false)
	if err != nil {
		t.Fatal("synthetic roster failed")
	}
	foreign, err := vault.SealItems([]byte("locklark/team/items/v1/"+f.cfg.scope), f.items, 1, recipients, signing(97))
	if err != nil {
		t.Fatal("synthetic foreign publisher failed")
	}
	foreignProposal := cloneInitialProposal(p)
	foreignProposal.SnapshotDigest = snapshotDigest(foreign)
	foreignProposal.Signature = ed25519.Sign(f.owner, foreignProposal.proof())
	if f.cfg.verifyProposal(foreignProposal) != nil || VerifyInitial(f.cfg, foreignProposal, foreign) != ErrInvalid {
		t.Fatal("owner-authenticated snapshot from unpinned publisher accepted")
	}
	for _, test := range []struct {
		name   string
		change func(*vault.Snapshot)
	}{
		{"epoch", func(s *vault.Snapshot) { s.Epoch++ }},
		{"database", func(s *vault.Snapshot) { s.Database[0] ^= 1 }},
		{"envelope", func(s *vault.Snapshot) { s.Envelope[0] ^= 1 }},
		{"signature", func(s *vault.Snapshot) { s.Signature[0] ^= 1 }},
		{"missing", func(s *vault.Snapshot) { *s = vault.Snapshot{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, proposal := cloneInitialSnapshot(base), cloneInitialProposal(p)
			test.change(&s)
			proposal.SnapshotDigest = snapshotDigest(s)
			proposal.Signature = ed25519.Sign(f.owner, proposal.proof())
			if VerifyInitial(f.cfg, proposal, s) != ErrInvalid {
				t.Fatal("owner-signed tampered snapshot accepted")
			}
		})
	}
	for _, change := range []func(*Pins){
		func(p *Pins) { p.Team = fmt.Sprintf("%032x", 91) },
		func(p *Pins) { p.Vault = fmt.Sprintf("%032x", 92) },
		func(p *Pins) { p.Owners = []string{public(signing(93))} },
		func(p *Pins) { p.Sequencer = public(signing(94)) },
		func(p *Pins) { p.Publisher = public(signing(95)) },
	} {
		pins := Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.owner), public(f.other)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)}
		change(&pins)
		cfg, err := NewConfigWithWriterACL(pins)
		if err != nil || VerifyInitial(cfg, p, base) != ErrInvalid {
			t.Fatal("foreign pins accepted initial artifacts")
		}
	}
	for _, cfg := range []*Config{nil, {}} {
		if VerifyInitial(cfg, p, base) != ErrInvalid {
			t.Fatal("invalid configuration accepted")
		}
	}
	if VerifyInitial(f.cfg, Proposal{}, vault.Snapshot{}) != ErrInvalid {
		t.Fatal("empty initial evidence accepted")
	}
}

func TestVerifyInitialDoesNotMutateSharedInputs(t *testing.T) {
	f, p, s := initialFixture(t, "writer")
	proposalBefore, snapshotBefore := encoded(p), encoded(s)
	configBefore := *f.cfg
	configBefore.owners = make(map[string]ed25519.PublicKey, len(f.cfg.owners))
	for id, key := range f.cfg.owners {
		configBefore.owners[id] = bytes.Clone(key)
	}
	configBefore.reserved = make(map[string]bool, len(f.cfg.reserved))
	for id, reserved := range f.cfg.reserved {
		configBefore.reserved[id] = reserved
	}
	configBefore.sequencer, configBefore.publisher = bytes.Clone(f.cfg.sequencer), bytes.Clone(f.cfg.publisher)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); errors <- VerifyInitial(f.cfg, p, s) }()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal("concurrent verification changed authorization")
		}
	}
	invalid := cloneInitialProposal(p)
	invalid.Admissions = nil
	invalid.Signature = ed25519.Sign(f.owner, invalid.proof())
	invalidBefore := encoded(invalid)
	if VerifyInitial(f.cfg, invalid, s) != ErrInvalid || !bytes.Equal(encoded(invalid), invalidBefore) {
		t.Fatal("failed transition verification mutated caller-owned evidence")
	}
	if !bytes.Equal(encoded(p), proposalBefore) || !bytes.Equal(encoded(s), snapshotBefore) || !reflect.DeepEqual(*f.cfg, configBefore) {
		t.Fatal("pure verification mutated caller-owned artifacts or pins")
	}
}

func TestVerifyInitialEnforcesCreateReceiptCapacityWithoutSigning(t *testing.T) {
	f, _, _ := initialFixture(t, "writer")
	member := Member{ID: fmt.Sprintf("%032x", 10), Role: "writer"}
	var proofs []Admission
	for index := range 64 {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal("synthetic device generation failed")
		}
		key := signing(byte(10 + index))
		device := Device{ID: fmt.Sprintf("%032x", 100+index), Encryption: identity.Recipient().String(), Signing: public(key)}
		member.Devices = append(member.Devices, device)
		proof := attest(t, f, f.cfg.Genesis(), member.ID, device, identity, key)
		// Authentic owner/device signatures can attest opaque challenge bytes
		// up to the protocol bound. Verification does not decrypt those bytes.
		proof.Challenge.Ciphertext = bytes.Repeat([]byte{65}, 1024)
		proof.Challenge.Signature = ed25519.Sign(f.owner, proof.Challenge.proof())
		proof.Signature = ed25519.Sign(key, proof.proof())
		proofs = append(proofs, proof)
	}
	p, s, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), []Member{member}, f.items, proofs...)
	if err != nil || f.cfg.verifyProposal(p) != nil || f.cfg.verifySnapshot(p, s) != nil {
		t.Fatal("oversized authentic receipt fixture failed")
	}
	state := newEvolution()
	if f.cfg.verifyTransition(state, p) != nil || state.advance(p) != nil {
		t.Fatal("oversized fixture did not isolate receipt capacity")
	}
	if VerifyInitial(f.cfg, p, s) != ErrInvalid {
		t.Fatal("oversized initial receipt accepted")
	}
	if _, err := Create(filepath.Join(t.TempDir(), "oversized.db"), f.cfg, f.sequencer, p, s); err != ErrInvalid {
		t.Fatal("Create disagreed with pure receipt capacity check")
	}
}
