package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// recoveryV2Session creates a real encrypted personal database and returns an
// unlocked session for exercising the public v2 item/vault surface.
func recoveryV2Session(t *testing.T, path, pw string, key []byte) *Session {
	t.Helper()
	if err := Create(path, pw, key); err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte(pw), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Lock)
	return s
}

func TestRecoveryRoundTripPreservesV2AttachmentBytes(t *testing.T) {
	dir := t.TempDir()
	src, archive, restored := filepath.Join(dir, "source.ll"), filepath.Join(dir, "backup.llb"), filepath.Join(dir, "restored.ll")
	pw, key, fresh := "synthetic-recovery-attachment", bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x32}, 16)
	s := recoveryV2Session(t, src, pw, key)

	// Binary, non-UTF-8 bytes with NULs exercise the KDBX binary path rather
	// than any text-only attachment shortcut.
	content := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x80, 0x7f, 0x41, 0x42}
	id, _, err := s.AddItem(vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Synthetic attachment login",
		URL:      "https://attachment.example.test/",
		Username: "synthetic-user",
		Password: "synthetic-password",
		Attachments: []vault.AttachmentMeta{{
			FileName: "synthetic-binary.bin",
			MIMEType: "application/octet-stream",
			Content:  content,
		}},
	}, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	before := readStoredItems(t, src, pw, key)
	if len(before) != 1 || before[0].ID != id || len(before[0].Attachments) != 1 || !bytes.Equal(before[0].Attachments[0].Content, content) || before[0].Attachments[0].Size != int64(len(content)) {
		t.Fatalf("source attachment was not stored as binary content: %+v", before)
	}
	attID := before[0].Attachments[0].ID

	kit, err := Backup(src, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, content) || bytes.Contains(raw, []byte("synthetic-binary.bin")) {
		t.Fatal("attachment bytes or name appeared in the encrypted archive envelope")
	}
	if err = Restore(archive, restored, pw, key, kit, fresh); err != nil {
		t.Fatalf("restore of a vault with a V2 attachment failed: %v", err)
	}
	after := readStoredItems(t, restored, pw, fresh)
	if len(after) != 1 || after[0].ID != id || len(after[0].Attachments) != 1 {
		t.Fatalf("restored attachment metadata was lost: %+v", after)
	}
	if got := after[0].Attachments[0]; got.ID != attID || got.Size != int64(len(content)) || !bytes.Equal(got.Content, content) {
		t.Fatalf("restored attachment bytes differ: %+v", got)
	}
	s2, err := UnlockSession(restored, []byte(pw), fresh, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Lock()
	rows, err := s2.ListByFilter(ItemFilter{State: "all"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("restored listing failed: %+v %v", rows, err)
	}
	if _, body, err := s2.GetAttachment(id, rows[0].Revision, attID); err != nil || !bytes.Equal(body, content) {
		t.Fatalf("restored attachment could not be read through the v2 API: %v", err)
	}
}

func TestRecoveryRoundTripPreservesCustomSubVaults(t *testing.T) {
	dir := t.TempDir()
	src, archive, restored := filepath.Join(dir, "source.ll"), filepath.Join(dir, "backup.llb"), filepath.Join(dir, "restored.ll")
	pw, key, fresh := "synthetic-recovery-vault", bytes.Repeat([]byte{0x41}, 16), bytes.Repeat([]byte{0x42}, 16)
	s := recoveryV2Session(t, src, pw, key)
	sub, err := s.CreateVault("Synthetic Lab", "isolated sub-vault", "lab", v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := s.AddItem(vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Synthetic sub-vault login",
		URL:      "https://subvault.example.test/",
		Username: "synthetic-sub-user",
		Password: "synthetic-sub-password",
		VaultID:  sub.ID,
	}, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}

	kit, err := Backup(src, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = Restore(archive, restored, pw, key, kit, fresh); err != nil {
		t.Fatalf("restore of a vault with a custom sub-vault failed: %v", err)
	}
	s2, err := UnlockSession(restored, []byte(pw), fresh, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Lock()
	vaults, err := s2.ListVaults()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range vaults {
		if v.ID == sub.ID && v.Name == sub.Name && v.Description == sub.Description && v.Icon == sub.Icon && v.CreatedAt == sub.CreatedAt {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom sub-vault metadata was not restored: got %+v want %+v", vaults, sub)
	}
	rows, err := s2.ListByFilter(ItemFilter{State: "all", VaultID: sub.ID})
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatalf("restored sub-vault item not found: %+v %v", rows, err)
	}
	// Mutating an item in the restored sub-vault exercises the vaultExists
	// check that previously failed with ErrMutationRefused.
	if _, err = s2.SetFavorite(id, rows[0].Revision, true, v2Gate(t, s2)); err != nil {
		t.Fatalf("restored sub-vault item could not be edited: %v", err)
	}
}

func recoveryIdentity(t *testing.T, path, pw string, key []byte) identity {
	t.Helper()
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var i identity
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		var slot account.Slot
		if json.Unmarshal(b.Get(slotKey), &slot) != nil {
			return invalid
		}
		p, err := account.Unwrap(pw, key, slot)
		if err != nil {
			return err
		}
		defer clear(p)
		return json.Unmarshal(p, &i)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(i.clear)
	return i
}

func rewriteRecoveryArchive(t *testing.T, path, kit, pw string, key []byte, i identity, p payload) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(priv)
	raw, err := encodeArchive(p, pw, key, make([]byte, 16), kit, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return kit[:57] + "-" + b32.EncodeToString(sum[:])
}

func TestRecoveryRejectsDroppedOrAlteredBackupAttachments(t *testing.T) {
	dir := t.TempDir()
	src, archive := filepath.Join(dir, "source.ll"), filepath.Join(dir, "backup.llb")
	pw, key, fresh := "synthetic-recovery-tamper", bytes.Repeat([]byte{0x51}, 16), bytes.Repeat([]byte{0x52}, 16)
	s := recoveryV2Session(t, src, pw, key)
	content := []byte{0x00, 0x10, 0x20, 0xff, 0x7f, 0x41}
	if _, _, err := s.AddItem(vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Synthetic tamper login",
		Username: "synthetic-user",
		Password: "synthetic-password",
		Attachments: []vault.AttachmentMeta{{
			FileName: "synthetic-tamper.bin",
			MIMEType: "application/octet-stream",
			Content:  content,
		}},
	}, v2Gate(t, s)); err != nil {
		t.Fatal(err)
	}
	kit, err := Backup(src, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	i := recoveryIdentity(t, src, pw, key)
	cases := []struct {
		name   string
		mutate func(*payload)
	}{
		{"dropped", func(p *payload) { p.Attachments = nil }},
		{"altered", func(p *payload) {
			p.Attachments[0].Content = append([]byte(nil), p.Attachments[0].Content...)
			p.Attachments[0].Content[0] ^= 1
		}},
		{"extraneous", func(p *payload) {
			p.Attachments = append(p.Attachments, backupAttachment{ItemID: p.Items[0].ID, AttachmentID: "not-an-attachment", Content: []byte{1}})
		}},
		{"invalid vault", func(p *payload) {
			p.Vaults = []vault.VaultMeta{{ID: strings.Repeat("a", 32), Name: "Synthetic\nVault"}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Decode a fresh payload because each mutation shares item/attachment
			// slices with the authenticated backup representation.
			p, err := decodeArchive(archive, pw, key, kit)
			if err != nil {
				t.Fatal(err)
			}
			c.mutate(p)
			forged := filepath.Join(t.TempDir(), "forged.llb")
			forgedKit := rewriteRecoveryArchive(t, forged, kit, pw, key, i, *p)
			dest := filepath.Join(t.TempDir(), "restored.ll")
			if err = Restore(forged, dest, pw, key, forgedKit, fresh); err == nil {
				t.Fatal("accepted a re-signed backup with inconsistent attachment metadata")
			}
			if _, err = os.Lstat(dest); !os.IsNotExist(err) {
				t.Fatal("rejected backup left a restored vault")
			}
		})
	}
}

func TestRecoveryRefusesOversizedPayloadCounts(t *testing.T) {
	archive, pw, key, kit := recoveryFixture(t)
	p, err := decodeArchive(archive, pw, key, kit)
	if err != nil {
		t.Fatal(err)
	}
	if err = checkPayloadBounds(p); err != nil {
		t.Fatalf("valid payload refused: %v", err)
	}
	item := func(n int) []vault.Item {
		out := make([]vault.Item, n)
		for i := range out {
			out[i] = vault.Item{ID: fmt.Sprintf("%032x", i+1), Kind: "login"}
		}
		return out
	}
	cases := []struct {
		name string
		payload
	}{
		{"items", payload{Items: item(vault.MaxItems + 1)}},
		{"duplicate item", payload{Items: append(item(1), item(1)...)}},
		{"vaults", payload{Items: item(1), Vaults: make([]vault.VaultMeta, maxVaults+1)}},
		{"item attachments", payload{Items: []vault.Item{{ID: item(1)[0].ID, Kind: "login", Attachments: make([]vault.AttachmentMeta, maxItemAttachments+1)}}}},
		{"attachment records", payload{Items: item(1), Attachments: make([]backupAttachment, maxBackupAttachments+1)}},
		{"orphan attachment record", payload{Items: item(1), Attachments: []backupAttachment{{ItemID: item(2)[1].ID, AttachmentID: "a", Content: []byte{1}}}}},
	}
	for _, c := range cases {
		c.payload.Generation, c.payload.Epoch, c.payload.Chains = p.Generation, p.Epoch, p.Chains
		if !errors.Is(checkPayloadBounds(&c.payload), invalid) {
			t.Fatalf("%s: oversized payload accepted", c.name)
		}
	}
}

// legacyRecoveryPayload is the exact pre-#99 signed body shape. It stays a
// separate type so the compatibility test never accidentally serializes the
// new backup-only fields.
type legacyRecoveryPayload struct {
	Generation string
	Epoch      uint64
	Items      []vault.Item
	Chains     []Chain
}

type legacySignedBackup struct {
	Body      legacyRecoveryPayload
	Signature []byte
}

func TestRecoveryStillRestoresPre99ArchiveShape(t *testing.T) {
	dir := t.TempDir()
	src, archive, restored := filepath.Join(dir, "source.ll"), filepath.Join(dir, "backup.llb"), filepath.Join(dir, "restored.ll")
	pw, key, fresh := "synthetic-recovery-legacy", bytes.Repeat([]byte{0x61}, 16), bytes.Repeat([]byte{0x62}, 16)
	s := recoveryV2Session(t, src, pw, key)
	id, _, err := s.AddItem(vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Synthetic legacy login",
		URL:      "https://legacy.example.test/",
		Username: "synthetic-legacy-user",
		Password: "synthetic-legacy-password",
	}, v2Gate(t, s))
	if err != nil {
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
	i := recoveryIdentity(t, src, pw, key)
	legacy := legacyRecoveryPayload{Generation: p.Generation, Epoch: p.Epoch, Items: p.Items, Chains: p.Chains}
	old, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	current, err := json.Marshal(payload{Generation: p.Generation, Epoch: p.Epoch, Items: p.Items, Chains: p.Chains})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, current) {
		t.Fatal("new payload shape no longer matches the signed pre-#99 body")
	}
	proofDigest, err := digest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(priv)
	proof := []byte(backupDomain + "/manifest/" + proofDigest)
	body, err := json.Marshal(legacySignedBackup{legacy, ed25519.Sign(priv, proof)})
	if err != nil {
		t.Fatal(err)
	}
	share := bytes.Repeat([]byte{0x63}, 32)
	slot, err := account.Wrap(pw, key, make([]byte, 16), share)
	if err != nil {
		t.Fatal(err)
	}
	a, err := aeadBackup(share, kit, legacy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope{2, legacy.Generation, slot, a.Seal(nil, nil, body, []byte(backupDomain+"/"+legacy.Generation))})
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir, "legacy.llb")
	if err = os.WriteFile(legacyPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	legacyKit := kit[:57] + "-" + b32.EncodeToString(sum[:])
	if err = Restore(legacyPath, restored, pw, key, legacyKit, fresh); err != nil {
		t.Fatalf("pre-#99 archive shape no longer restores: %v", err)
	}
	items := readStoredItems(t, restored, pw, fresh)
	if len(items) != 1 || items[0].ID != id || items[0].Password != "synthetic-legacy-password" {
		t.Fatalf("pre-#99 restore changed the item: %+v", items)
	}
}

// pre99Archive writes a backup whose body is re-signed using the exact
// pre-#99 signed payload shape, without Vaults or attachment records.
func pre99Archive(t *testing.T, src, pw string, key []byte, mutate func(*payload)) (string, string) {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "pre99.llb")
	kit, err := Backup(src, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodeArchive(archive, pw, key, kit)
	if err != nil {
		t.Fatal(err)
	}
	mutate(p)
	i := recoveryIdentity(t, src, pw, key)
	legacy := legacyRecoveryPayload{Generation: p.Generation, Epoch: p.Epoch, Items: p.Items, Chains: p.Chains}
	proofDigest, err := digest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(priv)
	body, err := json.Marshal(legacySignedBackup{legacy, ed25519.Sign(priv, []byte(backupDomain+"/manifest/"+proofDigest))})
	if err != nil {
		t.Fatal(err)
	}
	share := bytes.Repeat([]byte{0x71}, 32)
	slot, err := account.Wrap(pw, key, make([]byte, 16), share)
	if err != nil {
		t.Fatal(err)
	}
	a, err := aeadBackup(share, kit, legacy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope{2, legacy.Generation, slot, a.Seal(nil, nil, body, []byte(backupDomain+"/"+legacy.Generation))})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(archive, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return archive, kit[:57] + "-" + b32.EncodeToString(sum[:])
}

func TestRecoveryRejectsItemsReferencingMissingSubVault(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.ll")
	pw, key := "synthetic-recovery-orphan", bytes.Repeat([]byte{0x72}, 16)
	s := recoveryV2Session(t, src, pw, key)
	sub, err := s.CreateVault("Synthetic Orphan", "", "", v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := s.AddItem(vault.Item{
		Kind:     "login",
		Category: vault.CategoryLogin,
		Title:    "Synthetic orphan login",
		Username: "synthetic-orphan-user",
		Password: "synthetic-orphan-password",
		VaultID:  sub.ID,
	}, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	// A pre-#99 archive never carried sub-vault metadata, yet an item may
	// reference a custom VaultID. Restoring it would leave an orphan item that
	// every later edit refuses with ErrMutationRefused.
	archive, kit := pre99Archive(t, src, pw, key, func(p *payload) {
		if len(p.Items) != 1 || p.Items[0].ID != id || p.Items[0].VaultID != sub.ID {
			t.Fatalf("unexpected fixture items: %+v", p.Items)
		}
		p.Items[0].VaultID = sub.ID
	})
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "restored.ll")
	if _, err = PrepareRestore(archive, dest, pw, key, kit); !errors.Is(err, ErrBackupMissingSubVault) {
		t.Fatalf("orphan sub-vault reference was not refused explicitly: %v", err)
	}
	if _, err = os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("refused restore created a destination vault")
	}
	after, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("refused restore modified the source backup")
	}
}
