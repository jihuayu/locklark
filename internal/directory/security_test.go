package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func initialize(t *testing.T, f fixture) (string, Receipt, vault.Snapshot) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "team.db")
	p, s, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Create(path, f.cfg, f.sequencer, p, s)
	if err != nil {
		t.Fatal(err)
	}
	return path, r, s
}
func TestFreezeAndIndependentRebuild(t *testing.T) {
	f := setup(t)
	path, first, old := initialize(t, f)
	stale, staleSnapshot, err := Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	freeze, err := Freeze(f.cfg, f.other, first.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := Commit(path, f.cfg, f.sequencer, freeze, vault.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Read(path, f.cfg, first.Checkpoint())
	if err != nil || v.Receipt.Proposal.Mode != "frozen" || v.Snapshot.Epoch != 0 || len(v.Snapshot.Database) != 0 {
		t.Fatal("frozen view", err)
	}
	if _, err = Commit(path, f.cfg, f.sequencer, stale, staleSnapshot); err != ErrConflict {
		t.Fatal("pre-freeze publication", err)
	}
	again, err := Freeze(f.cfg, f.owner, frozen.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Commit(path, f.cfg, f.sequencer, again, vault.Snapshot{}); err != ErrInvalid {
		t.Fatal("repeated freeze", err)
	}
	p, s, err := Build(f.cfg, f.owner, f.publisher, frozen.Checkpoint(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Commit(path, f.cfg, f.sequencer, p, s); err != ErrInvalid {
		t.Fatal("retired roster resumed", err)
	}
	device, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	fresh := []Member{{ID: fmt.Sprintf("%032x", 30), Role: "writer", Devices: []Device{{ID: fmt.Sprintf("%032x", 31), Encryption: device.Recipient().String(), Signing: public(signing(15))}}}}
	p, s, err = Build(f.cfg, f.owner, f.publisher, frozen.Checkpoint(), fresh, f.items)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := Commit(path, f.cfg, f.sequencer, p, s)
	if err != nil || resumed.Proposal.Epoch != 3 {
		t.Fatal("independent rebuild", err)
	}
	for _, former := range f.devices {
		if _, _, err := vault.OpenItems(s, former, f.publisher.Public().(ed25519.PublicKey), 3); err == nil {
			t.Fatal("former device regained access")
		}
	}
	if _, items, err := vault.OpenItems(s, device, f.publisher.Public().(ed25519.PublicKey), 3); err != nil || len(items) != 1 {
		t.Fatal("new device", err)
	}
	// Revocation does not erase previously copied ciphertext or keys.
	if _, _, err := vault.OpenItems(old, f.devices[0], f.publisher.Public().(ed25519.PublicKey), 1); err != nil {
		t.Fatal("historical data claim changed", err)
	}
}
func TestTwoOwnersCASAndCheckpointRollback(t *testing.T) {
	f := setup(t)
	path, first, _ := initialize(t, f)
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type attempt struct {
		receipt Receipt
		err     error
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan attempt, 2)
	for _, owner := range []ed25519.PrivateKey{f.owner, f.other} {
		p, s, err := Build(f.cfg, owner, f.publisher, first.Checkpoint(), f.members, f.items)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := Commit(path, f.cfg, f.sequencer, p, s)
			results <- attempt{r, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	var winner Receipt
	for r := range results {
		if r.err == nil {
			successes++
			winner = r.receipt
		} else if r.err == ErrConflict {
			conflicts++
			if !reflect.DeepEqual(r.receipt, Receipt{}) {
				t.Fatal("loser received receipt")
			}
		} else {
			t.Fatal(r.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("both owners committed", successes, conflicts)
	}
	if v, err := Read(path, f.cfg, first.Checkpoint()); err != nil || v.Receipt.Checkpoint() != winner.Checkpoint() {
		t.Fatal("ancestor checkpoint", err)
	}
	bad := winner.Checkpoint()
	bad.Hash = fmt.Sprintf("%064x", 1)
	if _, err := Read(path, f.cfg, bad); err == nil {
		t.Fatal("same-version fork")
	}
	rolled := filepath.Join(t.TempDir(), "old.db")
	if err = os.WriteFile(rolled, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(rolled, f.cfg, winner.Checkpoint()); err == nil {
		t.Fatal("rolled-back directory accepted newer checkpoint")
	}
	if _, err := Read(rolled, f.cfg, first.Checkpoint()); err != nil {
		t.Fatal("checkpoint is a lower bound, not remote freshness", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("team-private-value"), f.owner.Seed(), f.sequencer.Seed(), f.publisher.Seed(), []byte(f.devices[0].String())} {
		if bytes.Contains(raw, secret) {
			t.Fatal("directory stored private material")
		}
	}
}
func TestStorageFailuresNeverReturnReceipt(t *testing.T) {
	f := setup(t)
	path, first, _ := initialize(t, f)
	p, s, err := Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members[1:], f.items)
	if err != nil {
		t.Fatal(err)
	}
	db, err := open(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := commitWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return fmt.Errorf("injected private storage detail")
		})
	}, f.cfg, f.sequencer, p, s, false)
	db.Close()
	if err != ErrStorage || !reflect.DeepEqual(r, Receipt{}) {
		t.Fatal("rollback receipt", err)
	}
	if v, err := Read(path, f.cfg, first.Checkpoint()); err != nil || v.Receipt.Checkpoint() != first.Checkpoint() {
		t.Fatal("rollback state", err)
	}
	db, err = open(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err = commitWithClose(func() (Receipt, error) { return commitWithUpdate(db.Update, f.cfg, f.sequencer, p, s, false) }, func() error {
		if err := db.Close(); err != nil {
			return err
		}
		return fmt.Errorf("injected close failure")
	})
	if err != ErrStorage || !reflect.DeepEqual(r, Receipt{}) {
		t.Fatal("close failure receipt", err)
	}
	if v, err := Read(path, f.cfg, first.Checkpoint()); err != nil || v.Receipt.Proposal.Epoch != 2 {
		t.Fatal("unknown commit could not be reread", err)
	}
	before, _ := os.ReadFile(path)
	genesis, s, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := Create(path, f.cfg, f.sequencer, genesis, s); err != ErrExists || !reflect.DeepEqual(r, Receipt{}) {
		t.Fatal("existing path", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing directory replaced")
	}
}
func TestTamperedEvidenceAndUnauthorizedOwners(t *testing.T) {
	f := setup(t)
	path, first, _ := initialize(t, f)
	p, s, err := Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*Proposal){
		func(p *Proposal) { p.Owner = public(signing(30)); p.Signature = ed25519.Sign(signing(30), p.proof()) },
		func(p *Proposal) { p.Epoch++ }, func(p *Proposal) { p.Scope = fmt.Sprintf("%064x", 1) },
		func(p *Proposal) { p.Members[0].Role = "owner" }, func(p *Proposal) { p.SnapshotDigest = fmt.Sprintf("%064x", 2) },
	} {
		q := p
		q.Members = cloneMembers(p.Members)
		alter(&q)
		if r, err := Commit(path, f.cfg, f.sequencer, q, s); err == nil || !reflect.DeepEqual(r, Receipt{}) {
			t.Fatal("forged proposal")
		}
	}
	broken := s
	broken.Envelope = bytes.Clone(s.Envelope)
	broken.Envelope[0] ^= 1
	if _, err := Commit(path, f.cfg, f.sequencer, p, broken); err == nil {
		t.Fatal("changed envelope")
	}
	if _, err := Commit(path, f.cfg, f.owner, p, s); err == nil {
		t.Fatal("owner used as sequencer")
	}
	db, err := open(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		records := tx.Bucket(bucket).Bucket(recordsKey)
		key := binary.BigEndian.AppendUint64(nil, 1)
		var receipt Receipt
		if !canonical(records.Get(key), &receipt) {
			return ErrInvalid
		}
		receipt.Signature[0] ^= 1
		return records.Put(key, encoded(receipt))
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, f.cfg, first.Checkpoint()); err == nil {
		t.Fatal("tampered stored record")
	}
}

func TestFrozenRollbackAndSnapshotTampering(t *testing.T) {
	f := setup(t)
	path, first, _ := initialize(t, f)
	p, err := Freeze(f.cfg, f.owner, first.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	db, err := open(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := commitWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return fmt.Errorf("rollback freeze")
		})
	}, f.cfg, f.sequencer, p, vault.Snapshot{}, false)
	db.Close()
	if err != ErrStorage || !reflect.DeepEqual(r, Receipt{}) {
		t.Fatal("freeze rollback receipt", err)
	}
	v, err := Read(path, f.cfg, first.Checkpoint())
	if err != nil || v.Receipt.Proposal.Mode != "active" || len(v.Snapshot.Database) == 0 {
		t.Fatal("freeze rollback removed snapshot", err)
	}
	db, err = open(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		var snapshot vault.Snapshot
		if !canonical(b.Get(snapshotKey), &snapshot) {
			return ErrInvalid
		}
		snapshot.Envelope[0] ^= 1
		return b.Put(snapshotKey, encoded(snapshot))
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, f.cfg, first.Checkpoint()); err == nil {
		t.Fatal("tampered stored ciphertext accepted")
	}
}
