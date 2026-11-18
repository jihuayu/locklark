package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
)

func TestLegacyVaultSplitPreflight(t *testing.T) {
	pw := strings.Repeat("p", 16)
	key := make([]byte, 16)
	kit, err := newRecovery()
	if err != nil {
		t.Fatal("could not generate recovery material")
	}
	gen, err := generation(kit)
	if err != nil {
		t.Fatal("could not derive archive generation")
	}
	signer := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(signer)
	id := func(n int) string { return fmt.Sprintf("%032x", n) }
	first := Event{
		Sequence: 1, UTC: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
		Session: id(1), Actor: "local-owner", Action: "vault.create", Result: "succeeded",
	}
	first.Signature = ed25519.Sign(signer, first.proof())
	last := first
	last.Sequence, last.Session, last.Previous = 2, id(2), first.hash()
	last.Action, last.Link = "backup.prepare", gen
	last.Signature = ed25519.Sign(signer, last.proof())
	chain := Chain{Public: signer.Public().(ed25519.PublicKey), Events: []Event{first, last}}

	const assignedVault = "Vault-A"
	makePayload := func() payload {
		stamp := time.Unix(2, 0).UTC()
		content := []byte{1, 2, 3}
		items := []vault.Item{
			{
				ID: id(10), Kind: string(vault.CategoryLogin), Title: "record", VaultID: assignedVault,
				ImportSource: []byte{4, 5}, State: "trashed", PreviousState: "archived", TrashedAt: &stamp,
				History: []vault.ItemHistoryEntry{{Timestamp: 1, Action: "edit", Title: "prior"}},
				Attachments: []vault.AttachmentMeta{{
					ID: id(20), FileName: "record.bin", Size: int64(len(content)),
					Protected: true, SHA256: vault.AttachmentSHA256(content), Content: content,
				}},
			},
			{ID: id(11), Kind: string(vault.CategoryLogin), Title: "record", State: "archived"},
			{ID: id(12), Kind: string(vault.CategoryLogin), Title: "record", VaultID: assignedVault},
			{ID: id(13), Kind: string(vault.CategoryLogin), Title: "record", VaultID: vault.DefaultVaultID},
		}
		return payload{
			Generation: gen, Epoch: 1, Items: items, Chains: []Chain{chain},
			Vaults: []vault.VaultMeta{
				{ID: "Vault-B", Name: "empty"},
				{ID: assignedVault, Name: "assigned"},
			},
			Attachments: collectBackupAttachments(items),
		}
	}
	pin := func(raw []byte) string {
		sum := sha256.Sum256(raw)
		return kit + "-" + b32.EncodeToString(sum[:])
	}
	encode := func(t *testing.T, p payload) []byte {
		t.Helper()
		raw, err := encodeArchive(p, pw, key, make([]byte, 16), kit, signer)
		if err != nil {
			t.Fatal("could not encode synthetic archive")
		}
		return raw
	}
	want := []LegacyVaultSplitGroup{
		{ItemIndexes: []int{1, 3}},
		{},
		{ItemIndexes: []int{0, 2}, HistoryEntries: 1, IndexedAttachments: 1},
	}

	p := makePayload()
	raw := encode(t, p)
	original, originalKey := bytes.Clone(raw), bytes.Clone(key)
	got, err := PreflightLegacyVaultSplit(raw, pw, key, pin(raw))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("verified source partition differs")
	}
	if !bytes.Equal(raw, original) || !bytes.Equal(key, originalKey) {
		t.Fatal("preflight modified caller input")
	}
	checked, err := verifyRecoveryArchive(raw, pw, key, pin(raw), true)
	if err != nil {
		t.Fatal("could not recheck the source")
	}
	defer clearAuthenticatedItems(checked.Items)
	again, err := reconcileLegacyVaultSplit(checked)
	if err != nil || !reflect.DeepEqual(again, want) || !reflect.DeepEqual(checked.Items, p.Items) {
		t.Fatal("partition changed source records or their ordering")
	}
	if got, err := PreflightLegacyVaultSplit(append(bytes.Clone(raw), ' '), pw, key, pin(raw)); got != nil || !errors.Is(err, ErrRecoverySource) {
		t.Fatal("archive outside the pinned checkpoint was accepted")
	}

	for i, change := range []struct {
		mutate func(*payload)
		want   error
	}{
		{func(p *payload) { p.Vaults = append(p.Vaults, p.Vaults[0]) }, invalid},
		{func(p *payload) {
			alias := p.Vaults[0]
			alias.ID = strings.ToLower(alias.ID)
			p.Vaults = append(p.Vaults, alias)
		}, invalid},
		{func(p *payload) { p.Vaults[0].ID = vault.DefaultVaultID }, invalid},
		{func(p *payload) { p.Items[0].VaultID = strings.ToLower(assignedVault) }, ErrBackupMissingSubVault},
		{func(p *payload) { p.Items[1].ID = p.Items[0].ID }, invalid},
		{func(p *payload) { p.Items = nil }, invalid},
		{func(p *payload) { p.Items[0].Kind = "unsupported" }, invalid},
		{func(p *payload) { p.Attachments[0].ItemID = p.Items[1].ID }, invalid},
		{func(p *payload) { p.Attachments[0].Content = []byte{3, 2, 1} }, invalid},
		{func(p *payload) {
			a := &p.Items[0].Attachments[0]
			a.Content, a.Size, a.SHA256 = nil, 0, vault.AttachmentSHA256(nil)
			p.Attachments = nil
		}, invalid},
	} {
		p := makePayload()
		change.mutate(&p)
		raw := encode(t, p)
		got, err := PreflightLegacyVaultSplit(raw, pw, key, pin(raw))
		if got != nil || !errors.Is(err, change.want) {
			t.Fatalf("source refusal case %d differed", i)
		}
	}

	nonCanonical := legacySplitNonCanonicalArchive(t, raw, pw, key, kit)
	legacy, err := verifyRecoveryArchive(nonCanonical, pw, key, pin(nonCanonical), false)
	if err != nil {
		t.Fatal("recovery compatibility changed")
	}
	defer clearAuthenticatedItems(legacy.Items)
	if got, err := PreflightLegacyVaultSplit(nonCanonical, pw, key, pin(nonCanonical)); got != nil || !errors.Is(err, invalid) {
		t.Fatal("a field discarded by the legacy decoder was accepted")
	}
}

func legacySplitNonCanonicalArchive(t *testing.T, raw []byte, pw string, key []byte, kit string) []byte {
	t.Helper()
	var env envelope
	if json.Unmarshal(raw, &env) != nil {
		t.Fatal("could not decode synthetic envelope")
	}
	share, err := account.Unwrap(pw, key, env.Share)
	if err != nil {
		t.Fatal("could not unwrap synthetic archive")
	}
	defer clear(share)
	a, err := aeadBackup(share, kit, env.Generation)
	if err != nil {
		t.Fatal("could not open synthetic cipher")
	}
	aad := []byte(backupDomain + "/" + env.Generation)
	plain, err := a.Open(nil, nil, env.Data, aad)
	if err != nil {
		t.Fatal("could not decrypt synthetic archive")
	}
	defer clear(plain)
	nonCanonical := append([]byte(`{"unsupported":0,`), plain[1:]...)
	defer clear(nonCanonical)
	env.Data = a.Seal(nil, nil, nonCanonical, aad)
	resealed, err := json.Marshal(env)
	if err != nil {
		t.Fatal("could not reseal synthetic archive")
	}
	return resealed
}
