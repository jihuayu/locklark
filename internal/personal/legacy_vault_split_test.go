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
	mixedGroups := []LegacyVaultSplitGroup{
		{ItemIndexes: []int{1, 3}},
		{},
		{ItemIndexes: []int{0, 2}, HistoryEntries: 1, IndexedAttachments: 1},
	}
	checkPartition := func(t *testing.T, raw []byte, want []LegacyVaultSplitGroup) {
		t.Helper()
		got, err := PreflightLegacyVaultSplit(raw, pw, key, pin(raw))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("verified source partition differs")
		}
	}

	t.Run("mixed_vaults", func(t *testing.T) {
		p := makePayload()
		raw := encode(t, p)
		original, originalKey := bytes.Clone(raw), bytes.Clone(key)
		checkPartition(t, raw, mixedGroups)
		if !bytes.Equal(raw, original) || !bytes.Equal(key, originalKey) {
			t.Fatal("preflight modified caller input")
		}
		checked, err := verifyRecoveryArchive(raw, pw, key, pin(raw), true)
		if err != nil {
			t.Fatal("could not recheck the source")
		}
		defer clearAuthenticatedItems(checked.Items)
		again, err := reconcileLegacyVaultSplit(checked)
		if err != nil || !reflect.DeepEqual(again, mixedGroups) || !reflect.DeepEqual(checked, &p) {
			t.Fatal("partition changed source records or their ordering")
		}
	})

	t.Run("omitted_vault_id", func(t *testing.T) {
		p := makePayload()
		record, err := json.Marshal(p.Items[1])
		var fields map[string]json.RawMessage
		if err != nil || json.Unmarshal(record, &fields) != nil {
			t.Fatal("could not inspect the encoded record")
		}
		defer clear(record)
		if _, present := fields["vault_id"]; present {
			t.Fatal("expected the archived record to omit its vault ID")
		}
		raw := encode(t, p)
		checkPartition(t, raw, mixedGroups)
		legacy, err := verifyRecoveryArchive(raw, pw, key, pin(raw), false)
		if err != nil {
			t.Fatal("legacy decoding refused an omitted vault ID")
		}
		defer clearAuthenticatedItems(legacy.Items)
		if legacy.Items[1].VaultID != "" || legacy.Items[1].EffectiveVaultID() != vault.DefaultVaultID {
			t.Fatal("legacy decoding changed the raw or effective vault ID")
		}
	})

	t.Run("default_only", func(t *testing.T) {
		p := makePayload()
		p.Items = []vault.Item{p.Items[1], p.Items[3]}
		p.Vaults = nil
		p.Attachments = nil
		checkPartition(t, encode(t, p), []LegacyVaultSplitGroup{{ItemIndexes: []int{0, 1}}})
	})

	t.Run("accumulate_counts", func(t *testing.T) {
		p := makePayload()
		history := p.Items[0].History[0]
		p.Items[2].History = []vault.ItemHistoryEntry{history, history}
		first := p.Items[0].Attachments[0]
		second := first
		first.ID, second.ID = id(21), id(22)
		p.Items[2].Attachments = []vault.AttachmentMeta{first, second}
		p.Attachments = collectBackupAttachments(p.Items)
		checkPartition(t, encode(t, p), []LegacyVaultSplitGroup{
			{ItemIndexes: []int{1, 3}}, {},
			{ItemIndexes: []int{0, 2}, HistoryEntries: 3, IndexedAttachments: 3},
		})
	})

	t.Run("wrong_checkpoint", func(t *testing.T) {
		raw := encode(t, makePayload())
		other := append(bytes.Clone(raw), ' ')
		if got, err := PreflightLegacyVaultSplit(other, pw, key, pin(raw)); got != nil || !errors.Is(err, ErrRecoverySource) {
			t.Fatal("archive outside the pinned checkpoint was accepted")
		}
	})

	for _, change := range []struct {
		name   string
		mutate func(*payload)
		want   error
	}{
		{"duplicate_declaration", func(p *payload) { p.Vaults = append(p.Vaults, p.Vaults[0]) }, invalid},
		{"case_alias_declaration", func(p *payload) {
			alias := p.Vaults[0]
			alias.ID = strings.ToLower(alias.ID)
			p.Vaults = append(p.Vaults, alias)
		}, invalid},
		{"reserved_default_declaration", func(p *payload) { p.Vaults[0].ID = vault.DefaultVaultID }, invalid},
		{"dangling_vault", func(p *payload) { p.Items[0].VaultID = strings.ToLower(assignedVault) }, ErrBackupMissingSubVault},
		{"duplicate_item", func(p *payload) { p.Items[1].ID = p.Items[0].ID }, invalid},
		{"omitted_items", func(p *payload) { p.Items = nil }, invalid},
		{"unsupported_item", func(p *payload) { p.Items[0].Kind = "unsupported" }, invalid},
		{"dangling_attachment", func(p *payload) { p.Attachments[0].ItemID = p.Items[1].ID }, invalid},
		{"unverifiable_attachment", func(p *payload) { p.Attachments[0].Content = []byte{3, 2, 1} }, invalid},
	} {
		t.Run(change.name, func(t *testing.T) {
			p := makePayload()
			change.mutate(&p)
			raw := encode(t, p)
			got, err := PreflightLegacyVaultSplit(raw, pw, key, pin(raw))
			if got != nil || !errors.Is(err, change.want) {
				t.Fatal("source refusal differed")
			}
		})
	}

	t.Run("omitted_empty_attachment", func(t *testing.T) {
		p := makePayload()
		a := &p.Items[0].Attachments[0]
		a.Content, a.Size, a.SHA256 = nil, 0, vault.AttachmentSHA256(nil)
		p.Attachments = nil
		raw := encode(t, p)
		legacy, err := verifyRecoveryArchive(raw, pw, key, pin(raw), false)
		if err != nil {
			t.Fatal("legacy decoding refused a reconstructible attachment")
		}
		defer clearAuthenticatedItems(legacy.Items)
		if got, err := PreflightLegacyVaultSplit(raw, pw, key, pin(raw)); got != nil || !errors.Is(err, invalid) {
			t.Fatal("preflight accepted an omitted attachment record")
		}
	})

	t.Run("unsupported_encoding", func(t *testing.T) {
		raw := encode(t, makePayload())
		nonCanonical := legacySplitNonCanonicalArchive(t, raw, pw, key, kit)
		legacy, err := verifyRecoveryArchive(nonCanonical, pw, key, pin(nonCanonical), false)
		if err != nil {
			t.Fatal("recovery compatibility changed")
		}
		defer clearAuthenticatedItems(legacy.Items)
		if got, err := PreflightLegacyVaultSplit(nonCanonical, pw, key, pin(nonCanonical)); got != nil || !errors.Is(err, invalid) {
			t.Fatal("a field discarded by the legacy decoder was accepted")
		}
	})
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
