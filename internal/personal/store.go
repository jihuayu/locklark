// Package personal implements the offline single-owner preview. No key material
// is shared with the synthetic gateway or a server.
package personal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var bucket = []byte("locklark.personal/v1")
var slotKey = []byte("device-slot")
var snapshotKey = []byte("snapshot")

type identity struct {
	Device                          string
	Signing, Audit, AuditEncryption []byte
}

func (i *identity) clear() { clear(i.Signing); clear(i.Audit); clear(i.AuditEncryption) }

type Row struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Revision string `json:"revision"`
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func NewSecret() ([]byte, error) { k := make([]byte, 16); _, e := rand.Read(k); return k, e }
func FormatSecret(k []byte) string {
	if len(k) != 16 {
		return ""
	}
	return "LL1-" + b32.EncodeToString(k)
}
func ParseSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "LL1-") {
		return nil, invalid
	}
	k, e := b32.DecodeString(s[4:])
	if e != nil || len(k) != 16 || s != FormatSecret(k) {
		return nil, invalid
	}
	return k, nil
}

const schema = "locklark/personal/items/v1"

func seal(b *bolt.Bucket, i identity, epoch uint64, items []vault.Item) (vault.Snapshot, error) {
	id, e := age.ParseX25519Identity(i.Device)
	if e != nil {
		return vault.Snapshot{}, invalid
	}
	signer := ed25519.NewKeyFromSeed(i.Signing)
	defer clear(signer)
	s, e := vault.SealItems([]byte(schema), items, epoch, []*age.X25519Recipient{id.Recipient()}, signer)
	if e != nil {
		return s, e
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return s, e
	}
	return s, b.Put(snapshotKey, raw)
}

// Build and fsync a complete database before publishing a new, non-overwriting name.
func Create(path, pw string, key []byte) error {
	return create(path, pw, key, nil)
}
func create(path, pw string, key []byte, recovered *payload) error {
	if path == "" || len(key) != 16 {
		return invalid
	}
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, e := os.CreateTemp(filepath.Dir(path), ".locklark-personal-*")
	if e != nil {
		return e
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if e = file.Close(); e != nil {
		return e
	}
	db, e := bolt.Open(tmp, 0600, nil)
	if e != nil {
		return e
	}
	defer db.Close()
	id, e := age.GenerateX25519Identity()
	if e != nil {
		return e
	}
	i := identity{Device: id.String(), Signing: make([]byte, 32), Audit: make([]byte, 32), AuditEncryption: make([]byte, 32)}
	defer i.clear()
	accountID := make([]byte, 16)
	for _, b := range [][]byte{i.Signing, i.Audit, i.AuditEncryption, accountID} {
		if _, e = rand.Read(b); e != nil {
			return e
		}
	}
	plain, e := json.Marshal(i)
	if e != nil {
		return e
	}
	defer clear(plain)
	slot, e := account.Wrap(pw, key, accountID, plain)
	if e != nil {
		return invalid
	}
	wrapped, e := json.Marshal(slot)
	if e != nil {
		return e
	}
	e = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket(bucket)
		if e != nil {
			return e
		}
		if e = b.Put(slotKey, wrapped); e != nil {
			return e
		}
		if _, e = b.CreateBucket(eventsKey); e != nil {
			return e
		}
		if recovered != nil {
			return initializeRecovered(b, i, recovered)
		}
		s, e := seal(b, i, 1, []vault.Item{})
		if e != nil {
			return e
		}
		_, e = appendEvent(b, i, auditTip{}, s, "vault.create", "", "succeeded", "")
		return e
	})
	if e != nil {
		return e
	}
	if e = db.Close(); e != nil {
		return e
	}
	return publish(tmp, path)
}
func existing(path string) (*bolt.DB, error) {
	return bolt.Open(path, 0600, &bolt.Options{Timeout: 10 * time.Second, OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
		f, e := os.OpenFile(name, flags&^os.O_CREATE, mode)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			f.Close()
			return nil, invalid
		}
		return f, nil
	}})
}

type result struct {
	value           []byte
	session, intent string
	rows            []Row
	events          []Event
	id              string
	revision        string
	chains          []Chain
	archive         []byte
}

func command(path, pw string, key []byte, action string, add vault.Item, edit *Edit, backup ...string) (result, error) {
	db, e := existing(path)
	if e != nil {
		return result{}, e
	}
	defer db.Close()
	return commandWithUpdate(db.Update, pw, key, action, add, edit, backup...)
}

// The updater returns only after commit (including bbolt's default fsync).
// Keeping it explicit also permits rollback fault injection in tests.
func commandWithUpdate(update func(func(*bolt.Tx) error) error, pw string, key []byte, action string, add vault.Item, edit *Edit, backup ...string) (result, error) {
	var out result
	var refusal error
	e := update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return invalid
		}
		var slot account.Slot
		raw := b.Get(slotKey)
		if len(raw) > 8192 || json.Unmarshal(raw, &slot) != nil {
			return invalid
		}
		opened, e := account.Unwrap(pw, key, slot)
		if e != nil {
			return invalid
		}
		defer clear(opened)
		var i identity
		if json.Unmarshal(opened, &i) != nil || len(i.Signing) != 32 || len(i.Audit) != 32 || len(i.AuditEncryption) != 32 {
			return invalid
		}
		defer i.clear()
		device, e := age.ParseX25519Identity(i.Device)
		if e != nil {
			return invalid
		}
		var s vault.Snapshot
		raw = b.Get(snapshotKey)
		if len(raw) > 12<<20 || json.Unmarshal(raw, &s) != nil {
			return invalid
		}
		signer := ed25519.NewKeyFromSeed(i.Signing)
		defer clear(signer)
		if vault.VerifySnapshot(s, signer.Public().(ed25519.PublicKey), s.Epoch) != nil {
			return invalid
		}
		revisions := make(map[string]string)
		tip, rows, e := history(b, i, s, action == "audit.list" || action == "backup.prepare", revisions)
		if e != nil {
			return e
		}
		chains, e := loadChains(b, i, tip.Origin)
		if e != nil {
			return e
		}
		var items []vault.Item
		if action != "audit.list" {
			var meta []byte
			meta, items, e = vault.OpenItems(s, device, signer.Public().(ed25519.PublicKey), tip.Epoch)
			if e != nil || items == nil || string(meta) != schema {
				return invalid
			}
		}
		if action != "audit.list" {
			if len(items) != len(revisions) {
				return invalid
			}
			for _, it := range items {
				if revisions[it.ID] == "" {
					return invalid
				}
			}
		}
		outcome := "succeeded"
		switch action {
		case "audit.archived":
			out.chains = chains
		case "backup.prepare":
			if len(backup) != 1 {
				return invalid
			}
		case "item.edit.title", "item.edit.username", "item.edit.password", "item.reveal.username", "item.reveal.password":
			if edit == nil {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				outcome, refusal = "not-found", ErrNotFound
				out.id = "" // never journal an unverified caller-supplied ID
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				for i := range items {
					if items[i].ID == edit.ID {
						if items[i].Kind != "login" {
							return invalid
						}
						if revealAction(action) {
							value := items[i].Username
							if action == "item.reveal.password" {
								value = items[i].Password
							}
							out.value = []byte(value)
							outcome = "intent"
							break
						}
						switch edit.Field {
						case "title":
							items[i].Title = edit.Value
						case "username":
							items[i].Username = edit.Value
						case "password":
							items[i].Password = edit.Value
						}
						break
					}
				}
			}
		case "item.add":
			if strings.TrimSpace(add.Title) == "" || add.Password == "" {
				return errors.New("a title and password are required")
			}
			add.ID, e = randomID()
			if e != nil {
				return e
			}
			items = append(items, add)
			out.id = add.ID
		case "item.list":
			out.rows = make([]Row, 0, len(items))
			for _, it := range items {
				out.rows = append(out.rows, Row{ID: it.ID, Title: it.Title, Revision: revisions[it.ID]})
			}
		case "audit.list":
		default:
			return invalid
		}
		if action == "item.add" || (editAction(action) && refusal == nil) {
			s, e = seal(b, i, s.Epoch+1, items)
			if e != nil {
				return e
			}
		}
		var link string
		if action == "backup.prepare" {
			link, e = generation(backup[0])
			if e != nil {
				return e
			}
			for _, old := range rows {
				if old.Action == action && old.Link == link {
					return invalid
				}
			}
		}
		ev, e := appendLinked(b, i, tip, s, action, out.id, outcome, revisions[out.id], link)
		if e != nil {
			return e
		}
		if revealAction(action) && refusal == nil {
			out.session, out.intent = ev.Session, ev.hash()
		}
		if action == "backup.prepare" {
			auditPriv := ed25519.NewKeyFromSeed(i.Audit)
			defer clear(auditPriv)
			chains = append(chains, Chain{auditPriv.Public().(ed25519.PublicKey), append(rows, ev)})
			p := payload{Generation: link, Epoch: s.Epoch, Items: items, Chains: chains}
			out.archive, e = encodeArchive(p, pw, key, slot.Account, backup[0], auditPriv)
			return e
		}
		if action == "audit.list" {
			out.events = append(rows, ev)
		} else if editAction(action) && refusal == nil {
			out.revision = ev.hash()
		}
		return nil
	})
	if e != nil {
		clear(out.value)
		return result{}, e
	}
	return out, refusal
}
func AddLogin(path, pw string, key []byte, title, user, value string) (string, error) {
	r, e := command(path, pw, key, "item.add", vault.Item{Kind: "login", Title: title, Username: user, Password: value}, nil)
	return r.id, e
}
func List(path, pw string, key []byte) ([]Row, error) {
	r, e := command(path, pw, key, "item.list", vault.Item{}, nil)
	return r.rows, e
}
func Audit(path, pw string, key []byte) ([]Event, error) {
	r, e := command(path, pw, key, "audit.list", vault.Item{}, nil)
	return r.events, e
}
