package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"filippo.io/age"
	"fmt"
	"github.com/jihuayu/locklark/internal/vault"
	"path/filepath"
	"testing"
)

type fixture struct {
	cfg                                *Config
	owner, other, sequencer, publisher ed25519.PrivateKey
	members                            []Member
	devices                            []*age.X25519Identity
	items                              []vault.Item
}

func signing(n byte) ed25519.PrivateKey  { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func public(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
func setup(t *testing.T) fixture {
	t.Helper()
	f := fixture{owner: signing(1), other: signing(2), sequencer: signing(3), publisher: signing(4), items: []vault.Item{{ID: "login", Kind: "login", Title: "synthetic team", Password: "team-private-value"}}}
	var err error
	f.cfg, err = NewConfig(Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(f.owner), public(f.other)}, Sequencer: public(f.sequencer), Publisher: public(f.publisher)})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		f.devices = append(f.devices, id)
	}
	f.members = []Member{{ID: fmt.Sprintf("%032x", 10), Role: "writer", Devices: []Device{{ID: fmt.Sprintf("%032x", 20), Encryption: f.devices[0].Recipient().String(), Signing: public(signing(10))}, {ID: fmt.Sprintf("%032x", 21), Encryption: f.devices[1].Recipient().String(), Signing: public(signing(11))}}}, {ID: fmt.Sprintf("%032x", 11), Role: "reader", Devices: []Device{{ID: fmt.Sprintf("%032x", 22), Encryption: f.devices[2].Recipient().String(), Signing: public(signing(12))}}}}
	return f
}
func TestPersistentDirectoryRevocation(t *testing.T) {
	f := setup(t)
	path := filepath.Join(t.TempDir(), "team.db")
	p, s, err := Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Create(path, f.cfg, f.sequencer, p, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range f.devices {
		if _, _, err := vault.OpenItems(s, device, f.publisher.Public().(ed25519.PublicKey), 1); err != nil {
			t.Fatal(err)
		}
	}
	// Removing a member excludes both of that member's independently keyed devices.
	p, s, err = Build(f.cfg, f.other, f.publisher, first.Checkpoint(), f.members[1:], f.items)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Commit(path, f.cfg, f.sequencer, p, s)
	if err != nil {
		t.Fatal(err)
	}
	view, err := Read(path, f.cfg, first.Checkpoint())
	if err != nil || view.Receipt.Checkpoint() != second.Checkpoint() {
		t.Fatal("durable checkpoint", err)
	}
	for i, device := range f.devices {
		_, items, err := vault.OpenItems(view.Snapshot, device, f.publisher.Public().(ed25519.PublicKey), 2)
		if i < 2 && err == nil {
			t.Fatal("revoked device opened new ciphertext")
		}
		if i == 2 && (err != nil || len(items) != 1 || items[0].Password != "team-private-value") {
			t.Fatal("remaining device", err)
		}
	}
	if _, err := Commit(path, f.cfg, f.sequencer, p, s); err != ErrConflict {
		t.Fatal("replayed proposal", err)
	}
	p, s, err = Build(f.cfg, f.owner, f.publisher, second.Checkpoint(), f.members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(path, f.cfg, f.sequencer, p, s); err == nil {
		t.Fatal("revoked identity resurrected")
	}
}

func TestRevokeOneDeviceKeepsSibling(t *testing.T) {
	f := setup(t)
	path, first, _ := initialize(t, f)
	members := cloneMembers(f.members)
	members[0].Devices = members[0].Devices[1:]
	p, s, err := Build(f.cfg, f.owner, f.publisher, first.Checkpoint(), members, f.items)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(path, f.cfg, f.sequencer, p, s); err != nil {
		t.Fatal(err)
	}
	for i, device := range f.devices {
		_, _, err := vault.OpenItems(s, device, f.publisher.Public().(ed25519.PublicKey), 2)
		if i == 0 && err == nil || i != 0 && err != nil {
			t.Fatal("single device revocation", i, err)
		}
	}
}
