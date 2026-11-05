package directory

import (
	"bytes"
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

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func writerFixture(t *testing.T) (fixture, string, Receipt) {
	t.Helper()
	f := setup(t)
	var e error
	f.cfg, e = NewConfigWithWriterACL(Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.owner), public(f.other)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)})
	if e != nil {
		t.Fatal(e)
	}
	var proofs []Admission
	for i, d := range append(append([]Device(nil), f.members[0].Devices...), f.members[1].Devices...) {
		member := f.members[0].ID
		if i == 2 {
			member = f.members[1].ID
		}
		proofs = append(proofs, attest(t, f, f.cfg.Genesis(), member, d, f.devices[i], signing(byte(10+i))))
	}
	p, s, e := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), f.members, f.items, proofs...)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "team.db")
	r, e := Create(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	return f, path, r
}

func TestWriterPublicationAndDemotion(t *testing.T) {
	f, path, first := writerFixture(t)
	if _, _, e := BuildUpdate(f.cfg, signing(12), first, f.items); e != ErrInvalid {
		t.Fatal("reader built update", e)
	}
	items := append([]vault.Item(nil), f.items...)
	items[0].Password = "writer-updated-synthetic"
	p, s, e := BuildUpdate(f.cfg, signing(10), first, items)
	if e != nil {
		t.Fatal(e)
	}
	if p.Owner != "" || p.AuthorDevice != f.members[0].Devices[0].ID {
		t.Fatal("wrong author")
	}
	second, e := Commit(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	view, e := Read(path, f.cfg, first.Checkpoint())
	if e != nil || !bytes.Equal(view.SnapshotSigner, signing(10).Public().(ed25519.PublicKey)) {
		t.Fatal("writer signer", e)
	}
	for _, id := range f.devices {
		_, got, e := vault.OpenItems(view.Snapshot, id, view.SnapshotSigner, 2)
		if e != nil || len(got) != 1 || got[0].Password != items[0].Password {
			t.Fatal("read writer data", e)
		}
	}
	stale, staleData, e := BuildUpdate(f.cfg, signing(10), second, items)
	if e != nil {
		t.Fatal(e)
	}
	members := cloneMembers(f.members)
	members[0].Role = "reader"
	p, s, e = Build(f.cfg, f.owner, f.publisher, second.Checkpoint(), members, items)
	if e != nil {
		t.Fatal(e)
	}
	demoted, e := Commit(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Commit(path, f.cfg, f.sequencer, stale, staleData); e != ErrConflict {
		t.Fatal("stale writer", e)
	}
	if _, _, e = BuildUpdate(f.cfg, signing(10), demoted, items); e != ErrInvalid {
		t.Fatal("demoted writer", e)
	}
	// Forge a self-consistent writer proposal claiming the old role at the NEW parent.
	stale.Parent = demoted.Checkpoint()
	stale.Epoch = stale.Parent.Version + 1
	stale, staleData = sealWriterCandidate(t, f, stale, signing(10))
	if f.cfg.verifyProposal(stale) != nil {
		t.Fatal("negative case must pass standalone signature checks")
	}
	if _, e = Commit(path, f.cfg, f.sequencer, stale, staleData); e != ErrInvalid {
		t.Fatal("self-grant accepted by transaction", e)
	}
	// Correctly sequencer-signed historical forgery must still fail transition authorization.
	forged := Receipt{Proposal: stale}
	forged.Signature = ed25519.Sign(f.sequencer, forged.proof())
	db, e := open(path, false, false)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if e := b.Bucket(recordsKey).Put(binary.BigEndian.AppendUint64(nil, stale.Epoch), encoded(forged)); e != nil {
			return e
		}
		return b.Put(snapshotKey, encoded(staleData))
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Read(path, f.cfg, first.Checkpoint()); e != ErrInvalid {
		t.Fatal("self-granted historical writer accepted", e)
	}
}

func sealWriterCandidate(t *testing.T, f fixture, p Proposal, key ed25519.PrivateKey) (Proposal, vault.Snapshot) {
	t.Helper()
	recipients, e := f.cfg.roster(p.Members, false)
	if e != nil {
		t.Fatal(e)
	}
	s, e := vault.SealItems([]byte("locklark/team/items/v1/"+f.cfg.scope), f.items, p.Epoch, recipients, key)
	if e != nil {
		t.Fatal(e)
	}
	p.SnapshotDigest = snapshotDigest(s)
	p.Signature = ed25519.Sign(key, p.proof())
	return p, s
}

func TestWriterReaderAndRollback(t *testing.T) {
	f, path, first := writerFixture(t)
	p, s, e := BuildUpdate(f.cfg, signing(10), first, f.items)
	if e != nil {
		t.Fatal(e)
	}
	// The reader signs an otherwise valid proposal and snapshot. This cannot
	// fail merely due to BuildUpdate's UI guard or a mismatching snapshot key.
	q := p
	q.AuthorDevice = f.members[1].Devices[0].ID
	q, data := sealWriterCandidate(t, f, q, signing(12))
	if f.cfg.verifyProposal(q) != nil || f.cfg.verifySnapshot(q, data) != nil {
		t.Fatal("reader negative must pass signature checks")
	}
	if _, e = Commit(path, f.cfg, f.sequencer, q, data); e != ErrInvalid {
		t.Fatal("reader publication", e)
	}
	db, e := open(path, false, false)
	if e != nil {
		t.Fatal(e)
	}
	r, e := commitWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if e := fn(tx); e != nil {
				return e
			}
			return errors.New("injected rollback")
		})
	}, f.cfg, f.sequencer, p, s, false)
	db.Close()
	if e != ErrStorage || !reflect.DeepEqual(r, Receipt{}) {
		t.Fatal("failed update returned receipt", e)
	}
	view, e := Read(path, f.cfg, first.Checkpoint())
	if e != nil || view.Receipt.Checkpoint() != first.Checkpoint() {
		t.Fatal("partial writer commit", e)
	}
	if !bytes.Equal(view.SnapshotSigner, f.publisher.Public().(ed25519.PublicKey)) {
		t.Fatal("owner snapshot signer")
	}
	second, e := Commit(path, f.cfg, f.sequencer, p, s)
	if e != nil {
		t.Fatal(e)
	}
	// A different process verifies the writer history with public pins only.
	request := possessionReadRequest{Pins: Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.owner), public(f.other)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)}, Anchor: second.Checkpoint(), Path: path}
	raw, e := json.Marshal(request)
	if e != nil {
		t.Fatal(e)
	}
	requestPath := filepath.Join(t.TempDir(), "public.json")
	if e = os.WriteFile(requestPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(executable, "-test.run=^TestWriterReopenSubprocess$")
	cmd.Env = append(os.Environ(), "LOCKLARK_WRITER_READ_REQUEST="+requestPath)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fresh verifier: %v %s", e, out)
	}
	frozen, e := Freeze(f.cfg, f.owner, second.Checkpoint())
	if e != nil {
		t.Fatal(e)
	}
	last, e := Commit(path, f.cfg, f.sequencer, frozen, vault.Snapshot{})
	if e != nil {
		t.Fatal(e)
	}
	view, e = Read(path, f.cfg, last.Checkpoint())
	if e != nil || view.SnapshotSigner != nil {
		t.Fatal("frozen signer", e)
	}
	if _, _, e = BuildUpdate(f.cfg, signing(10), last, f.items); e != ErrInvalid {
		t.Fatal("writer after freeze", e)
	}
	view, e = Read(path, f.cfg, Checkpoint{})
	if e != ErrInvalid || !reflect.DeepEqual(view, View{}) {
		t.Fatal("failed read nonzero", e)
	}
}

func TestWriterReopenSubprocess(t *testing.T) {
	path := os.Getenv("LOCKLARK_WRITER_READ_REQUEST")
	if path == "" {
		return
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("public request unavailable")
	}
	var request possessionReadRequest
	if json.Unmarshal(raw, &request) != nil {
		t.Fatal("invalid request")
	}
	c, e := NewConfigWithWriterACL(request.Pins)
	if e != nil {
		t.Fatal(e)
	}
	view, e := Read(request.Path, c, request.Anchor)
	if e != nil || view.Receipt.Checkpoint() != request.Anchor || len(view.SnapshotSigner) != ed25519.PublicKeySize {
		t.Fatal("fresh writer history", e)
	}
}

func TestWriterCannotChangeAuthority(t *testing.T) {
	f, path, first := writerFixture(t)
	p, s, e := BuildUpdate(f.cfg, signing(10), first, f.items)
	if e != nil {
		t.Fatal(e)
	}
	currentProof := attest(t, f, first.Checkpoint(), f.members[0].ID, f.members[0].Devices[0], f.devices[0], signing(10))
	mutations := map[string]func(*Proposal){
		"both authors":    func(p *Proposal) { p.Owner = public(f.owner) },
		"neither author":  func(p *Proposal) { p.AuthorDevice = "" },
		"freeze":          func(p *Proposal) { p.Mode = "frozen"; p.Members = []Member{}; p.SnapshotDigest = "" },
		"remove member":   func(p *Proposal) { p.Members = p.Members[:1] },
		"change role":     func(p *Proposal) { p.Members[1].Role = "writer" },
		"change key":      func(p *Proposal) { p.Members[1].Devices[0].Signing = public(signing(45)) },
		"extra admission": func(p *Proposal) { p.Admissions = []Admission{currentProof} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			q := p
			q.Members = cloneMembers(p.Members)
			mutate(&q)
			q.Signature = ed25519.Sign(signing(10), q.proof())
			if _, e := Commit(path, f.cfg, f.sequencer, q, s); e != ErrInvalid {
				t.Fatal("writer changed authority", e)
			}
		})
	}
	q := p
	q.Parent = f.cfg.Genesis()
	q.Epoch = 1
	q.Signature = ed25519.Sign(signing(10), q.proof())
	if _, e = Create(filepath.Join(t.TempDir(), "bad.db"), f.cfg, f.sequencer, q, s); e != ErrInvalid {
		t.Fatal("writer genesis", e)
	}
	for _, c := range []*Config{setup(t).cfg, possessionConfig(t, f)} {
		q := p
		q.Scope = c.scope
		q.Parent.Scope = c.scope
		q.Signature = ed25519.Sign(signing(10), q.proof())
		if c.verifyProposal(q) != ErrInvalid {
			t.Fatal("writer accepted under legacy policy")
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
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
		t.Fatal("writer CAS failed")
	}
}
