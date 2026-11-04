package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
)

func TestRecoveryRejectsResignedHistory(t *testing.T) {
	dir := t.TempDir()
	src, archive, forged, dest := filepath.Join(dir, "source"), filepath.Join(dir, "backup"), filepath.Join(dir, "forged"), filepath.Join(dir, "restored")
	pw, key, fresh := "synthetic-master", bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
	var err error
	if err = Create(src, pw, key); err != nil {
		t.Fatal(err)
	}
	kit, err := Backup(src, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodeArchive(archive, pw, key, kit)
	if err != nil {
		t.Fatal(err)
	}
	pub, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker knows every decryption factor, but never changes the
	// independently saved recovery material used below.
	chain := &p.Chains[0]
	chain.Public = pub
	prev := ""
	for j := range chain.Events {
		ev := &chain.Events[j]
		ev.UTC = "2001-01-01T00:00:00Z"
		ev.Previous = prev
		ev.Signature = ed25519.Sign(attacker, ev.proof())
		prev = ev.hash()
	}
	if err = verifyChains(p.Chains); err != nil {
		t.Fatal("attack fixture is not a valid signed history", err)
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	resealed, err := encodeArchive(*p, pw, key, env.Share.Account, kit, attacker)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(forged, resealed, 0600); err != nil {
		t.Fatal(err)
	}
	// This really is a decryptable, correctly signed replacement. It passes
	// when paired with the attacker's own checkpoint, but the original kit
	// must never accept it.
	h := sha256.Sum256(resealed)
	forgedKit := kit[:57] + "-" + b32.EncodeToString(h[:])
	if _, err = decodeArchive(forged, pw, key, forgedKit); err != nil {
		t.Fatal("replacement is not independently valid", err)
	}
	if err = Restore(forged, dest, pw, key, kit, fresh); !errors.Is(err, ErrRecoverySource) {
		t.Fatal("accepted an attacker-replaced and re-signed entire history with the original offline material")
	}
	if _, err = os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("failed recovery left a vault")
	}
}

func TestRecoveryLimitsAreNotCredentialErrors(t *testing.T) {
	if err := verifyChains(make([]Chain, maxChains+1)); !errors.Is(err, ErrHistoryLimit) {
		t.Fatal("history limit reported as invalid credentials", err)
	}
	path := filepath.Join(t.TempDir(), "oversize")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxArchive + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	kit, err := newRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeArchive(path, "synthetic", make([]byte, 16), kit); !errors.Is(err, ErrArchiveLimit) {
		t.Fatal("capacity limit reported as invalid credentials", err)
	}
}

func recoveryFixture(t *testing.T) (string, string, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	src, archive := filepath.Join(dir, "source"), filepath.Join(dir, "backup")
	pw, key := "synthetic-master", bytes.Repeat([]byte{3}, 16)
	if err := Create(src, pw, key); err != nil {
		t.Fatal(err)
	}
	kit, err := Backup(src, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	return archive, pw, key, kit
}

func TestPreparedRecoveryPinsPayloadAndRefusesLateTarget(t *testing.T) {
	archive, pw, key, kit := recoveryFixture(t)
	fresh := bytes.Repeat([]byte{4}, 16)
	dest := filepath.Join(t.TempDir(), "restored")
	r, err := PrepareRestore(archive, dest, pw, key, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = os.WriteFile(archive, []byte("replaced after validation"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = r.Publish(fresh); err != nil {
		t.Fatal("reopened untrusted source", err)
	}
	if _, err = List(dest, pw, fresh); err != nil {
		t.Fatal(err)
	}

	// Remove the first target, then introduce an unrelated file after the
	// second preflight. Atomic publication must keep its original bytes.
	if err = os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	archive, pw, key, kit = recoveryFixture(t)
	r2, err := PrepareRestore(archive, dest, pw, key, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	sentinel := []byte("concurrent writer owns this path")
	if err = os.WriteFile(dest, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err = r2.Publish(fresh); !errors.Is(err, os.ErrExist) {
		t.Fatal("late target overwritten", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatal("late target changed", err)
	}
	files, err := os.ReadDir(filepath.Dir(dest))
	if err != nil || len(files) != 1 {
		t.Fatal("temporary recovery files left behind", err)
	}
}

func TestLegacyAndIncompleteRecoveryFailExplicitly(t *testing.T) {
	archive, pw, key, kit := recoveryFixture(t)
	dest := filepath.Join(t.TempDir(), "restored")
	legacy := "LLR1-" + kit[5:57]
	if _, err := PrepareRestore(archive, dest, pw, key, legacy); !errors.Is(err, ErrLegacyRecovery) {
		t.Fatal("legacy kit downgraded", err)
	}
	if _, err := PrepareRestore(archive, dest, pw, key, kit[:57]); err == nil {
		t.Fatal("accepted material without a checkpoint")
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Version = 1
	raw, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(archive, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = PrepareRestore(archive, dest, pw, key, kit); !errors.Is(err, ErrLegacyRecovery) {
		t.Fatal("legacy archive downgraded", err)
	}
	if _, err = os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("legacy rejection left a vault")
	}
}

func TestBackupPlaintextAndHistoryLimits(t *testing.T) {
	archive, pw, key, kit := recoveryFixture(t)
	p, err := decodeArchive(archive, pw, key, kit)
	if err != nil {
		t.Fatal(err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.Items = []vault.Item{{ID: strings.Repeat("a", 32), Kind: "login", Password: strings.Repeat("x", maxArchive/2)}}
	if _, err = encodeArchive(*p, pw, key, make([]byte, 16), kit, signer); !errors.Is(err, ErrArchiveLimit) {
		t.Fatal("plaintext capacity hidden", err)
	}
	p.Chains = make([]Chain, maxChains+1)
	if _, err = encodeArchive(*p, pw, key, make([]byte, 16), kit, signer); !errors.Is(err, ErrHistoryLimit) {
		t.Fatal("history capacity hidden", err)
	}

	// Authenticated input must also observe the plaintext cap, even if its
	// on-disk JSON remains below the larger file limit.
	share := bytes.Repeat([]byte{9}, 32)
	gen, err := generation(kit)
	if err != nil {
		t.Fatal(err)
	}
	a, err := aeadBackup(share, kit, gen)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := account.Wrap(pw, key, make([]byte, 16), share)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope{2, gen, slot, a.Seal(nil, nil, bytes.Repeat([]byte{' '}, maxArchive/2+1), []byte(backupDomain+"/"+gen))})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(archive, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	kit = kit[:57] + "-" + b32.EncodeToString(h[:])
	if _, err = decodeArchive(archive, pw, key, kit); !errors.Is(err, ErrArchiveLimit) {
		t.Fatal("decrypted plaintext capacity hidden", err)
	}
}
