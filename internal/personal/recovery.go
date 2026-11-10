package personal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const backupDomain = "locklark/personal/backup/v2"
const maxArchive = 32 << 20
const maxChains = 32

var ErrArchiveLimit = errors.New("backup exceeds capacity limit (16 MiB plaintext or 32 MiB file)")
var ErrHistoryLimit = errors.New("backup exceeds history limit (32 segments)")
var ErrLegacyRecovery = errors.New("legacy recovery format has no independent history checkpoint; create a new backup from a trusted source vault")
var ErrRecoverySource = errors.New("backup does not match the independently saved recovery checkpoint")
var ErrArchiveType = errors.New("backup source must be a regular file")

// Chain is verification material only. Signatures are kept byte-for-byte.
type Chain struct {
	Public ed25519.PublicKey `json:"audit_public"`
	Events []Event           `json:"events"`
}

const (
	maxVaults          = 64
	maxItemAttachments = 16
	// maxBackupAttachments mirrors the per-item bound already enforced by
	// vault.ValidateItems so oversized lists are refused before indexing.
	maxBackupAttachments = vault.MaxItems * maxItemAttachments
)

// backupAttachment carries the bytes that vault.AttachmentMeta intentionally
// keeps out of its global JSON representation. It exists only in the
// authenticated recovery payload and is bound back to an item attachment by
// the pair below before validation or restoration.
type backupAttachment struct {
	ItemID       string `json:"item_id"`
	AttachmentID string `json:"attachment_id"`
	Content      []byte `json:"content"`
}

type payload struct {
	Generation string
	Epoch      uint64
	Items      []vault.Item
	Chains     []Chain
	// These fields were appended after the original v2 payload fields. Their
	// omitempty tags keep archives written before #99 byte-for-byte compatible
	// with the existing signed manifest digest.
	Vaults      []vault.VaultMeta  `json:",omitempty"`
	Attachments []backupAttachment `json:",omitempty"`
}

func collectBackupAttachments(items []vault.Item) []backupAttachment {
	var out []backupAttachment
	for _, item := range items {
		for _, att := range item.Attachments {
			out = append(out, backupAttachment{ItemID: item.ID, AttachmentID: att.ID, Content: att.Content})
		}
	}
	return out
}

// checkPayloadBounds rejects oversized counts before any item- or
// attachment-proportional work runs.
func checkPayloadBounds(p *payload) error {
	if p == nil || len(p.Items) > vault.MaxItems || len(p.Vaults) > maxVaults || len(p.Chains) > maxChains {
		return invalid
	}
	attachments := 0
	seenIDs := make(map[string]struct{}, len(p.Items))
	for n := range p.Items {
		if !idOK(p.Items[n].ID) {
			return invalid
		}
		if _, dup := seenIDs[p.Items[n].ID]; dup {
			return invalid
		}
		seenIDs[p.Items[n].ID] = struct{}{}
		if len(p.Items[n].Attachments) > maxItemAttachments {
			return invalid
		}
		attachments += len(p.Items[n].Attachments)
	}
	if attachments > maxBackupAttachments || len(p.Attachments) > attachments {
		return invalid
	}
	return nil
}

// applyBackupAttachments restores attachment bytes into the in-memory item
// model using a single index over the bounded payload. Attachments with
// positive size must have exactly one matching byte record; zero-length
// legacy attachments may predate the backup-only field.
func applyBackupAttachments(p *payload) error {
	if len(p.Items) > vault.MaxItems || len(p.Attachments) > maxBackupAttachments {
		return invalid
	}
	type attachmentKey struct{ item, attachment string }
	index := make(map[attachmentKey]*vault.AttachmentMeta)
	for n := range p.Items {
		for m := range p.Items[n].Attachments {
			att := &p.Items[n].Attachments[m]
			key := attachmentKey{p.Items[n].ID, att.ID}
			if _, dup := index[key]; dup {
				return invalid
			}
			index[key] = att
		}
	}
	seen := make(map[attachmentKey]bool, len(p.Attachments))
	for _, data := range p.Attachments {
		key := attachmentKey{data.ItemID, data.AttachmentID}
		att, ok := index[key]
		if !ok || seen[key] {
			return invalid
		}
		seen[key] = true
		att.Content = data.Content
	}
	for key, att := range index {
		if seen[key] {
			continue
		}
		if att.Size != 0 {
			return invalid
		}
		att.Content = []byte{}
	}
	return nil
}

func validateRecoveredVaults(vaults []vault.VaultMeta) error {
	if len(vaults) == 0 {
		return nil
	}
	if len(vaults) > maxVaults {
		return invalid
	}
	seen := map[string]bool{vault.DefaultVaultID: true}
	for _, v := range vaults {
		if !validVaultMeta(v) || seen[strings.ToLower(v.ID)] {
			return invalid
		}
		seen[strings.ToLower(v.ID)] = true
	}
	raw, e := json.Marshal(vaults)
	if e != nil || len(raw) > 48<<10 {
		return invalid
	}
	return nil
}

type signedBackup struct {
	Body      payload
	Signature []byte
}
type envelope struct {
	Version    int
	Generation string
	Share      account.Slot
	Data       []byte
}

func newRecovery() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	defer clear(raw[:])
	return "LLR2-" + b32.EncodeToString(raw[:]), nil
}
func kitBytes(kit string) ([]byte, error) {
	// A seed is only used while preparing a backup. Only the complete
	// 110-character seed + checkpoint material is accepted for restoration.
	if strings.HasPrefix(kit, "LLR1-") {
		return nil, ErrLegacyRecovery
	}
	if len(kit) == 110 && kit[57] == '-' {
		kit = kit[:57]
	}
	if len(kit) != 57 || !strings.HasPrefix(kit, "LLR2-") {
		return nil, invalid
	}
	raw, err := b32.DecodeString(kit[5:])
	if err != nil || len(raw) != 32 || b32.EncodeToString(raw) != kit[5:] {
		clear(raw)
		return nil, invalid
	}
	return raw, nil
}

func recoveryCheckpoint(kit string) ([]byte, error) {
	if strings.HasPrefix(kit, "LLR1-") {
		return nil, ErrLegacyRecovery
	}
	if len(kit) != 110 || kit[57] != '-' {
		return nil, invalid
	}
	raw, e := b32.DecodeString(kit[58:])
	if e != nil || len(raw) != sha256.Size || b32.EncodeToString(raw) != kit[58:] {
		return nil, invalid
	}
	return raw, nil
}
func generation(kit string) (string, error) {
	raw, err := kitBytes(kit)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:16]), nil
}
func digestOK(s string) bool {
	p, e := hex.DecodeString(s)
	return e == nil && len(p) == 32 && hex.EncodeToString(p) == s
}
func digest(v any) (string, error) {
	p, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	defer clear(p)
	h := sha256.Sum256(p)
	return hex.EncodeToString(h[:]), nil
}
func aeadBackup(share []byte, kit, gen string) (cipher.AEAD, error) {
	g, err := generation(kit)
	if err != nil || g != gen || len(share) != 32 {
		return nil, invalid
	}
	raw, _ := kitBytes(kit)
	defer clear(raw)
	k, err := hkdf.Key(sha256.New, share, raw, backupDomain+"/"+gen, 32)
	if err != nil {
		return nil, invalid
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, invalid
	}
	return cipher.NewGCMWithRandomNonce(block)
}
func payloadProof(p payload) ([]byte, error) {
	d, e := digest(p)
	return []byte(backupDomain + "/manifest/" + d), e
}
func verifyChains(chains []Chain) error {
	if len(chains) > maxChains {
		return ErrHistoryLimit
	}
	if len(chains) == 0 {
		return invalid
	}
	seen := map[string]bool{}
	for idx, c := range chains {
		if len(c.Public) != ed25519.PublicKeySize || seen[string(c.Public)] || len(c.Events) < 2 {
			return invalid
		}
		seen[string(c.Public)] = true
		first, last := c.Events[0], c.Events[len(c.Events)-1]
		if idx == 0 {
			if first.Action != "vault.create" {
				return invalid
			}
		} else {
			d, e := digest(chains[:idx])
			if e != nil || first.Action != "vault.restore" || first.Link != d {
				return invalid
			}
		}
		if last.Action != "backup.prepare" {
			return invalid
		}
		prev := ""
		for j, ev := range c.Events {
			if ev.verify(c.Public, uint64(j+1), prev) != nil {
				return invalid
			}
			prev = ev.hash()
		}
	}
	return nil
}
func encodeArchive(p payload, pw string, key, accountID []byte, kit string, priv ed25519.PrivateKey) ([]byte, error) {
	if e := verifyChains(p.Chains); e != nil {
		return nil, e
	}
	proof, err := payloadProof(p)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(signedBackup{p, ed25519.Sign(priv, proof)})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > maxArchive/2 {
		return nil, ErrArchiveLimit
	}
	share := make([]byte, 32)
	defer clear(share)
	if _, err = rand.Read(share); err != nil {
		return nil, err
	}
	slot, err := account.Wrap(pw, key, accountID, share)
	if err != nil {
		return nil, invalid
	}
	a, err := aeadBackup(share, kit, p.Generation)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{2, p.Generation, slot, a.Seal(nil, nil, raw, []byte(backupDomain+"/"+p.Generation))})
}
func decodeArchive(path, pw string, key []byte, kit string) (*payload, error) {
	f, e := openArchive(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if st.Size() > maxArchive {
		return nil, ErrArchiveLimit
	}
	if !st.Mode().IsRegular() {
		return nil, ErrArchiveType
	}
	b, e := io.ReadAll(io.LimitReader(f, maxArchive+1))
	if e != nil {
		return nil, e
	}
	if len(b) > maxArchive {
		return nil, ErrArchiveLimit
	}
	var env envelope
	if json.Unmarshal(b, &env) != nil {
		return nil, invalid
	}
	if env.Version == 1 {
		return nil, ErrLegacyRecovery
	}
	if env.Version != 2 {
		return nil, invalid
	}
	checkpoint, e := recoveryCheckpoint(kit)
	if e != nil {
		return nil, e
	}
	g, e := generation(kit)
	if e != nil || g != env.Generation {
		return nil, invalid
	}
	h := sha256.Sum256(b)
	if !bytes.Equal(h[:], checkpoint) {
		return nil, ErrRecoverySource
	}
	share, e := account.Unwrap(pw, key, env.Share)
	if e != nil {
		return nil, invalid
	}
	defer clear(share)
	a, e := aeadBackup(share, kit, g)
	if e != nil {
		return nil, e
	}
	plain, e := a.Open(nil, nil, env.Data, []byte(backupDomain+"/"+g))
	if e != nil {
		return nil, invalid
	}
	defer clear(plain)
	if len(plain) > maxArchive/2 {
		return nil, ErrArchiveLimit
	}
	var body signedBackup
	if json.Unmarshal(plain, &body) != nil {
		return nil, invalid
	}
	p := &body.Body
	if p.Generation != g || p.Items == nil || p.Epoch == 0 || p.Epoch == ^uint64(0) {
		return nil, invalid
	}
	if e = checkPayloadBounds(p); e != nil {
		return nil, e
	}
	if e = verifyChains(p.Chains); e != nil {
		return nil, e
	}
	if e = validateRecoveredVaults(p.Vaults); e != nil {
		return nil, e
	}
	if e = applyBackupAttachments(p); e != nil {
		return nil, e
	}
	if vault.ValidateItems([]byte(schema), p.Items) != nil {
		return nil, invalid
	}
	last := p.Chains[len(p.Chains)-1]
	proof, e := payloadProof(*p)
	if e != nil || last.Events[len(last.Events)-1].Link != g || !ed25519.Verify(last.Public, proof, body.Signature) {
		return nil, invalid
	}
	return p, nil
}

var archiveKey = []byte("archived-audit/v1")

func loadChains(b *bolt.Bucket, i identity, anchor string) ([]Chain, error) {
	raw := b.Get(archiveKey)
	if anchor == "" {
		if raw != nil {
			return nil, invalid
		}
		return nil, nil
	}
	if len(raw) > maxArchive {
		return nil, ErrArchiveLimit
	}
	if !digestOK(anchor) {
		return nil, invalid
	}
	a, e := auditCipher(i)
	if e != nil {
		return nil, invalid
	}
	p, e := a.Open(nil, nil, raw, archiveKey)
	if e != nil {
		return nil, invalid
	}
	defer clear(p)
	var chains []Chain
	if json.Unmarshal(p, &chains) != nil {
		return nil, invalid
	}
	d, e := digest(chains)
	if e != nil || d != anchor {
		return nil, invalid
	}
	if e = verifyChains(chains); e != nil {
		return nil, e
	}
	return chains, nil
}
func initializeRecovered(b *bolt.Bucket, i identity, p *payload) error {
	a, e := auditCipher(i)
	if e != nil {
		return e
	}
	enc, e := sealedJSON(a, archiveKey, p.Chains)
	if e != nil {
		return e
	}
	if e = b.Put(archiveKey, enc); e != nil {
		return e
	}
	if len(p.Vaults) > 0 {
		if e = saveVaults(b, i, p.Vaults); e != nil {
			return e
		}
	}
	anchor, e := digest(p.Chains)
	if e != nil {
		return e
	}
	s, e := seal(b, i, p.Epoch+1, p.Items)
	if e != nil {
		return e
	}
	tip := auditTip{}
	ev, e := appendLinked(b, i, tip, s, "vault.restore", "", "succeeded", "", anchor)
	if e != nil {
		return e
	}
	for _, it := range p.Items {
		if !idOK(it.ID) {
			return invalid
		}
		tip = auditTip{Count: ev.Sequence, Last: ev.hash(), Origin: anchor}
		ev, e = appendEvent(b, i, tip, s, "item.restore", it.ID, "succeeded", "")
		if e != nil {
			return e
		}
	}
	return nil
}

// BackupPreparation contains a complete fsynced archive and its independent
// checkpoint. The CLI confirms saving Material before Publish exposes the file.
type BackupPreparation struct {
	dest, temp, material string
}

func (b *BackupPreparation) Material() string { return b.material }
func (b *BackupPreparation) Publish() error   { return publish(b.temp, b.dest) }
func (b *BackupPreparation) Close()           { os.Remove(b.temp) }

func PrepareBackup(src, dest, pw string, key []byte) (*BackupPreparation, error) {
	if _, e := os.Lstat(dest); e == nil {
		return nil, os.ErrExist
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	f, e := os.CreateTemp(filepath.Dir(dest), ".locklark-backup-*")
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			os.Remove(f.Name())
		}
	}()
	defer f.Close()
	kit, e := newRecovery()
	if e != nil {
		return nil, e
	}
	r, e := command(src, pw, key, "backup.prepare", vault.Item{}, nil, commandOption{backup: kit})
	if e != nil {
		return nil, e
	}
	if _, e = f.Write(r.archive); e != nil {
		return nil, e
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	if e = f.Close(); e != nil {
		return nil, e
	}
	checkpoint := sha256.Sum256(r.archive)
	keep = true
	return &BackupPreparation{dest, f.Name(), kit + "-" + b32.EncodeToString(checkpoint[:])}, nil
}

func Backup(src, dest, pw string, key []byte) (string, error) {
	b, e := PrepareBackup(src, dest, pw, key)
	if e != nil {
		return "", e
	}
	defer b.Close()
	if e = b.Publish(); e != nil {
		return "", e
	}
	return b.Material(), nil
}
func Restore(src, dest, pw string, oldKey []byte, kit string, newKey []byte) error {
	r, e := PrepareRestore(src, dest, pw, oldKey, kit)
	if e != nil {
		return e
	}
	defer r.Close()
	return r.Publish(newKey)
}

// Restoration holds the verified payload so publication never reopens an
// untrusted source after the user saves the new key.
type Restoration struct {
	dest, pw string
	oldKey   []byte
	p        *payload
}

// PrepareRestore validates all old factors and probes the destination before
// the CLI issues a new key. The final publication still refuses replacement
// atomically: this probe cannot reserve a name against concurrent writers.
func PrepareRestore(src, dest, pw string, oldKey []byte, kit string) (*Restoration, error) {
	p, e := decodeArchive(src, pw, oldKey, kit)
	if e != nil {
		return nil, e
	}
	if _, e = os.Lstat(dest); e == nil {
		return nil, os.ErrExist
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	f, e := os.CreateTemp(filepath.Dir(dest), ".locklark-preflight-*")
	if e != nil {
		return nil, e
	}
	closeErr := f.Close()
	removeErr := os.Remove(f.Name())
	if closeErr != nil {
		return nil, closeErr
	}
	if removeErr != nil {
		return nil, removeErr
	}
	return &Restoration{dest, pw, bytes.Clone(oldKey), p}, nil
}

func (r *Restoration) Publish(newKey []byte) error {
	if r.p == nil || len(newKey) != 16 || bytes.Equal(r.oldKey, newKey) {
		return invalid
	}
	return create(r.dest, r.pw, newKey, r.p)
}

func (r *Restoration) Close() {
	clear(r.oldKey)
	r.oldKey, r.p, r.pw = nil, nil, ""
}
func ArchivedAudit(path, pw string, key []byte) ([]Chain, error) {
	r, e := command(path, pw, key, "audit.archived", vault.Item{}, nil)
	return r.chains, e
}
