// Integration fixture only. All keys and vault content are freshly synthetic.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"filippo.io/age"
	"flag"
	"fmt"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/management"
	"github.com/jihuayu/locklark/internal/vault"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", "", "new fixture directory")
	flag.Parse()
	if *out == "" {
		panic("fixture output required")
	}
	if e := os.MkdirAll(*out, 0700); e != nil {
		panic(e)
	}
	key := func() ed25519.PrivateKey {
		_, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			panic(e)
		}
		return k
	}
	pub := func(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
	owner, seq, publisher := key(), key(), key()
	defer clear(owner)
	defer clear(seq)
	defer clear(publisher)
	pins := directory.Pins{Team: fmt.Sprintf("%032x", 1), Vault: fmt.Sprintf("%032x", 2), Owners: []string{pub(owner)}, Sequencer: pub(seq), Publisher: pub(publisher)}
	cfg, e := directory.NewConfigWithWriterACL(pins)
	if e != nil {
		panic(e)
	}
	members := []directory.Member{}
	proofs := []directory.Admission{}
	for i := 0; i < 2; i++ {
		signer := key()
		defer clear(signer)
		identity, e := age.GenerateX25519Identity()
		if e != nil {
			panic(e)
		}
		device := directory.Device{ID: fmt.Sprintf("%032x", 20+i), Encryption: identity.Recipient().String(), Signing: pub(signer)}
		member := directory.Member{ID: fmt.Sprintf("%032x", 10+i), Role: []string{"writer", "reader"}[i], Devices: []directory.Device{device}}
		enrollment := directory.Enrollment{Parent: cfg.Genesis(), Member: member.ID, Device: device}
		challenge, e := directory.IssueChallenge(cfg, owner, enrollment)
		if e != nil {
			panic(e)
		}
		proof, e := directory.AnswerChallenge(cfg, enrollment, challenge, identity, signer)
		if e != nil {
			panic(e)
		}
		proofs = append(proofs, proof)
		members = append(members, member)
	}
	proposal, snapshot, e := directory.Build(cfg, owner, publisher, cfg.Genesis(), members, []vault.Item{{ID: "login", Kind: "login", Title: "never-web-title", Username: "never-web-user", Password: "never-web-password"}}, proofs...)
	if e != nil {
		panic(e)
	}
	receipt, e := directory.Create(filepath.Join(*out, "team.db"), cfg, seq, proposal, snapshot)
	if e != nil {
		panic(e)
	}
	encoded, e := json.Marshal(management.Configuration{Pins: pins, Anchor: receipt.Checkpoint(), Policy: "writer-acl-v1"})
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(*out, "config.json"), encoded, 0600); e != nil {
		panic(e)
	}
}
