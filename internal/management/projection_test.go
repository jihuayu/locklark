package management

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"filippo.io/age"
	"fmt"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifiedProjectionRejectsRollbackAndLeaksNoVaultData(t *testing.T) {
	signing := func(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
	public := func(key ed25519.PrivateKey) string { return hex.EncodeToString(key.Public().(ed25519.PublicKey)) }
	owner, seq, publisher, deviceSigner := signing(1), signing(2), signing(3), signing(4)
	pins := directory.Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{public(owner)}, Sequencer: public(seq), Publisher: public(publisher)}
	cfg, e := directory.NewConfig(pins)
	if e != nil {
		t.Fatal(e)
	}
	device, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	members := []directory.Member{{ID: fmt.Sprintf("%032x", 3), Role: "reader", Devices: []directory.Device{{ID: fmt.Sprintf("%032x", 4), Encryption: device.Recipient().String(), Signing: public(deviceSigner)}}}}
	items := []vault.Item{{ID: "entry", Kind: "login", Title: "never-web-title", Username: "never-web-user", Password: "never-web-password"}}
	proposal, snapshot, e := directory.Build(cfg, owner, publisher, cfg.Genesis(), members, items)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "team.db")
	receipt, e := directory.Create(path, cfg, seq, proposal, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	first, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	read := DirectoryReader(path, cfg, receipt.Checkpoint())
	summary, e := read()
	if e != nil {
		t.Fatal(e)
	}
	if len(summary.Members) != 1 || len(summary.Members[0].Devices) != 1 || summary.Checkpoint != receipt.Checkpoint() {
		t.Fatal("bad projection")
	}
	raw, _ := json.Marshal(summary)
	for _, secret := range []string{"never-web-", device.String(), "snapshot", "encryption", "signing", "database", "password", "username"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("non-allowlisted value projected")
		}
	}
	proposal, snapshot, e = directory.Build(cfg, owner, publisher, receipt.Checkpoint(), members, items)
	if e != nil {
		t.Fatal(e)
	}
	second, e := directory.Commit(path, cfg, seq, proposal, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	read = DirectoryReader(path, cfg, second.Checkpoint())
	if _, e = read(); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, first, 0600); e != nil {
		t.Fatal(e)
	}
	summary, e = read()
	if e == nil || len(summary.Members) != 0 || summary.Checkpoint.Version != 0 {
		t.Fatal("rollback served stale metadata")
	}
}
func TestPrivateConnectionDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection.json")
	c := Connection{Version: 1, URL: "http://127.0.0.1:3418", Token: strings.Repeat("a", 64)}
	if e := WriteConnection(path, c); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	c.Token = strings.Repeat("b", 64)
	if e = WriteConnection(path, c); e == nil {
		t.Fatal("connection overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing credential changed")
	}
}
