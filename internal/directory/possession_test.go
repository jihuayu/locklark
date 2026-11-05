package directory

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"
)

func possessionConfig(t *testing.T, f fixture) *Config {
	t.Helper()
	c, e := NewConfigWithPossession(Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.owner), public(f.other)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)})
	if e != nil {
		t.Fatal(e)
	}
	return c
}

type possessionReadRequest struct {
	Pins   Pins
	Anchor Checkpoint
	Path   string
}

func TestPossessionReopenSubprocess(t *testing.T) {
	path := os.Getenv("LOCKLARK_POSSESSION_READ_REQUEST")
	if path == "" {
		return
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("cannot read synthetic request")
	}
	var request possessionReadRequest
	if json.Unmarshal(raw, &request) != nil {
		t.Fatal("invalid synthetic request")
	}
	c, e := NewConfigWithPossession(request.Pins)
	if e != nil {
		t.Fatal(e)
	}
	view, e := Read(request.Path, c, request.Anchor)
	if e != nil || view.Receipt.Checkpoint() != request.Anchor {
		t.Fatal("fresh process could not verify public admission history", e)
	}
}

func TestPossessionNewDeviceAtomicAdmissionAndHistory(t *testing.T) {
	f := setup(t)
	f.cfg = possessionConfig(t, f)
	initial := cloneMembers(f.members[:1])
	initial[0].Devices = initial[0].Devices[:1]
	proof := attest(t, f, f.cfg.Genesis(), initial[0].ID, initial[0].Devices[0], f.devices[0], signing(10))
	p, s, e := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), initial, f.items, proof)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "team.db")
	first, e := Create(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	p, s, e = Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members[:1], f.items)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Commit(path, f.cfg, f.sequencer, p, s); e != ErrInvalid {
		t.Fatal("new device without proof", e)
	}
	proof = attest(t, f, first.Checkpoint(), f.members[0].ID, f.members[0].Devices[1], f.devices[1], signing(11))
	p, s, e = Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members[:1], f.items, proof)
	if e != nil {
		t.Fatal(e)
	}
	db, e := open(path, false, false)
	if e != nil {
		t.Fatal(e)
	}
	injected := errors.New("injected")
	r, e := commitWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if e := fn(tx); e != nil {
				return e
			}
			return injected
		})
	}, f.cfg, f.sequencer, p, s, false)
	db.Close()
	if e != ErrStorage || !reflect.DeepEqual(r, Receipt{}) {
		t.Fatal("failed commit receipt", e)
	}
	view, e := Read(path, f.cfg, first.Checkpoint())
	if e != nil || view.Receipt.Checkpoint() != first.Checkpoint() {
		t.Fatal("partial admission after rollback", e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for j := 0; j < 2; j++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := Commit(path, f.cfg, f.sequencer, p, s); errs <- e }()
	}
	wg.Wait()
	close(errs)
	ok, conflict := 0, 0
	for e := range errs {
		if e == nil {
			ok++
		} else if e == ErrConflict {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal("concurrent admission replay")
	}
	view, e = Read(path, f.cfg, first.Checkpoint())
	if e != nil {
		t.Fatal(e)
	}
	// A fresh process verifies the history using only trusted public pins and
	// its checkpoint; no device/owner/sequencer private key is handed to it.
	request := possessionReadRequest{Pins: Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.owner), public(f.other)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)}, Anchor: view.Receipt.Checkpoint(), Path: path}
	raw, e := json.Marshal(request)
	if e != nil {
		t.Fatal(e)
	}
	requestPath := filepath.Join(t.TempDir(), "public-request.json")
	if e = os.WriteFile(requestPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	testExecutable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(testExecutable, "-test.run=^TestPossessionReopenSubprocess$")
	cmd.Env = append(os.Environ(), "LOCKLARK_POSSESSION_READ_REQUEST="+requestPath)
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fresh verifier failed: %v %s", e, output)
	}
	if _, _, e = Build(f.cfg, f.owner, f.publisher, view.Receipt.Checkpoint(), f.members[:1], f.items, proof); e != ErrInvalid {
		t.Fatal("stale admission reused", e)
	}
	// Even correctly signed records cannot omit mandatory historical evidence.
	forged := view.Receipt
	forged.Proposal.Admissions = nil
	forged.Proposal.Signature = ed25519.Sign(f.owner, forged.Proposal.proof())
	forged.Signature = ed25519.Sign(f.sequencer, forged.proof())
	db, e = open(path, false, false)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Bucket(recordsKey).Put(binary.BigEndian.AppendUint64(nil, forged.Proposal.Epoch), encoded(forged))
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Read(path, f.cfg, first.Checkpoint()); e != ErrInvalid {
		t.Fatal("missing historical proof accepted", e)
	}
}
func attest(t *testing.T, f fixture, parent Checkpoint, member string, device Device, identity *age.X25519Identity, key ed25519.PrivateKey) Admission {
	t.Helper()
	enrollment := Enrollment{Parent: parent, Member: member, Device: device}
	challenge, e := IssueChallenge(f.cfg, f.owner, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := AnswerChallenge(f.cfg, enrollment, challenge, identity, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyAdmission(f.cfg, enrollment, proof); e != nil {
		t.Fatal(e)
	}
	return proof
}

func TestPossessionRequiredAndPersistent(t *testing.T) {
	f := setup(t)
	legacy := f.cfg
	f.cfg = possessionConfig(t, f)
	if f.cfg.Genesis() == legacy.Genesis() {
		t.Fatal("proof policy not pinned into scope")
	}
	parent := f.cfg.Genesis()
	path := filepath.Join(t.TempDir(), "verified.db")
	p, s, e := Build(f.cfg, f.owner, f.publisher, parent, f.members, f.items)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Create(path, f.cfg, f.sequencer, p, s); e != ErrInvalid {
		t.Fatal("unproven roster accepted", e)
	}
	proofs := []Admission{}
	index := 0
	for _, m := range f.members {
		for _, d := range m.Devices {
			proofs = append(proofs, attest(t, f, parent, m.ID, d, f.devices[index], signing(byte(10+index))))
			index++
		}
	}
	p, s, e = Build(f.cfg, f.owner, f.publisher, parent, f.members, f.items, proofs...)
	if e != nil {
		t.Fatal(e)
	}
	// A caller changing proof buffers after Build cannot change a signed proposal.
	proofs[0].Nonce[0] ^= 1
	first, e := Create(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Read(path, legacy, legacy.Genesis()); e == nil {
		t.Fatal("verification policy downgraded")
	}
	if _, e = Read(path, possessionConfig(t, f), first.Checkpoint()); e != nil {
		t.Fatal("proofs did not survive reopen", e)
	}
	p, s, e = Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members[1:], f.items)
	if e != nil {
		t.Fatal(e)
	}
	second, e := Commit(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal("unchanged remaining device needed new proof", e)
	}
	// Even valid fresh ownership proofs cannot resurrect retired keys/identities.
	proofs = nil
	for j, d := range f.members[0].Devices {
		proofs = append(proofs, attest(t, f, second.Checkpoint(), f.members[0].ID, d, f.devices[j], signing(byte(10+j))))
	}
	p, s, e = Build(f.cfg, f.owner, f.publisher, second.Checkpoint(), f.members, f.items, proofs...)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Commit(path, f.cfg, f.sequencer, p, s); e != ErrInvalid {
		t.Fatal("proof bypassed tombstones", e)
	}
}

func TestPossessionRejectsShadowKeysAndRebinding(t *testing.T) {
	f := setup(t)
	f.cfg = possessionConfig(t, f)
	enrollment := Enrollment{Parent: f.cfg.Genesis(), Member: f.members[0].ID, Device: f.members[0].Devices[0]}
	challenge, e := IssueChallenge(f.cfg, f.owner, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	for _, pair := range []struct {
		id  *age.X25519Identity
		key ed25519.PrivateKey
	}{{f.devices[1], signing(10)}, {f.devices[0], signing(11)}} {
		if _, e = AnswerChallenge(f.cfg, enrollment, challenge, pair.id, pair.key); e != ErrInvalid {
			t.Fatal("one private key sufficed", e)
		}
	}
	proof, e := AnswerChallenge(f.cfg, enrollment, challenge, f.devices[0], signing(10))
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Enrollment){func(e *Enrollment) { e.Member = fmt.Sprintf("%032x", 40) }, func(e *Enrollment) { e.Device.ID = fmt.Sprintf("%032x", 41) }, func(e *Enrollment) { e.Parent.Version = 1; e.Parent.Hash = fmt.Sprintf("%064x", 1) }} {
		changed := enrollment
		change(&changed)
		if VerifyAdmission(f.cfg, changed, proof) == nil {
			t.Fatal("admission rebound")
		}
	}
	for _, change := range []func(*Admission){func(p *Admission) { p.Nonce[0] ^= 1 }, func(p *Admission) { p.Challenge.Ciphertext[0] ^= 1 }, func(p *Admission) { p.Signature[0] ^= 1 }, func(p *Admission) { p.Challenge.Signature[0] ^= 1 }} {
		changed := cloneAdmissions([]Admission{proof})[0]
		change(&changed)
		if VerifyAdmission(f.cfg, enrollment, changed) == nil {
			t.Fatal("tampered admission accepted")
		}
	}
	if _, e = IssueChallenge(f.cfg, signing(45), enrollment); e != ErrInvalid {
		t.Fatal("untrusted issuer", e)
	}
	if _, _, e = Build(f.cfg, f.owner, f.publisher, enrollment.Parent, f.members, f.items, proof, proof); e != ErrInvalid {
		t.Fatal("duplicate proof accepted", e)
	}
}
