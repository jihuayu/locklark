// Package personal implements the offline single-owner preview. No key material
// is shared with the synthetic gateway or a server.
package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/totp"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
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
	Kind         string `json:"kind,omitempty"`
	RestoreState string `json:"restore_state,omitempty"`
	Category     string `json:"category,omitempty"`
	Subtitle     string `json:"subtitle,omitempty"`
	State        string `json:"state"`
	ID           string `json:"id"`
	Title        string `json:"title"`
	Revision     string `json:"revision"`
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
	return existingWithReadOnly(path, false)
}
func existingWithReadOnly(path string, readOnly bool) (*bolt.DB, error) {
	return bolt.Open(path, 0600, &bolt.Options{ReadOnly: readOnly, Timeout: 10 * time.Second, OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
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
	sshSeed           []byte
	savePersisted     bool
	browser           *NativeBrowserFill
	material          []byte
	slotDigest        [32]byte
	destinationDigest string
	health            HealthReport
	migration         onepux.MappingReport
	inspection        onepux.Report
	reportDigest      string
	references        ReferenceIndex
	otp               *totp.Config
	profile           password.Profile
	value             []byte
	values            map[string][]byte
	session, intent   string
	rows              []Row
	events            []Event
	id                string
	revision          string
	chains            []Chain
	archive           []byte
	summaries         []ItemSummary
	detail            ItemDetail
	vaults            []vault.VaultMeta
	vaultMeta         vault.VaultMeta
	attachment        vault.AttachmentMeta
	attachmentBytes   []byte
	purged            int
}

type commandOption struct {
	sshState       bool
	ssh            *sshStoreRequest
	browserOTP     *BrowserOTPTarget
	nativeMutation *nativeMutationRequest
	browserSave    *browserSaveRequest
	browser        *BrowserFillTarget
	unlocked       *Session
	run            *RunRequest
	runBundle      *runBundleStoreRequest
	search         *searchRequest
	livePull       *LivePullRequest
	injection      *injectionRequest
	migration      *importRequest
	match          *matchRequest
	export         *exportRequest
	inspection     *inspectionRequest
	backup         string
	generation     *generationRequest
	reference      *referenceRequest
	v2             *v2Request
}

func command(path, pw string, key []byte, action string, add vault.Item, edit *Edit, options ...commandOption) (result, error) {
	db, e := existing(path)
	if e != nil {
		return result{}, e
	}
	return commandWithClose(func() (result, error) { return commandWithUpdate(db.Update, pw, key, action, add, edit, options...) }, db.Close)
}

var ErrCommandClose = errors.New("personal vault close failed; operation may be committed")

func commandWithClose(run func() (result, error), closeDB func() error) (r result, err error) {
	defer func() {
		if closeErr := closeDB(); closeErr != nil && (err == nil || r.savePersisted) {
			r.browser.clear()
			clear(r.value)
			clearBundleValues(r.values)
			clear(r.sshSeed)
			clear(r.material)
			clear(r.archive)
			if r.otp != nil {
				r.otp.Clear()
			}
			r = result{}
			err = ErrCommandClose
		}
	}()
	return run()
}

type authenticatedState struct {
	slot      account.Slot
	opened    []byte
	identity  identity
	snapshot  vault.Snapshot
	tip       auditTip
	rows      []Event
	chains    []Chain
	items     []vault.Item
	revisions map[string]string
	vaults    []vault.VaultMeta
}

func (a *authenticatedState) clear() {
	clear(a.opened)
	a.identity.clear()
	for _, item := range a.items {
		clear(item.SSHSeed)
		clear(item.Passkey)
	}
}

// Both write commands and native read-only revalidation use this complete
// slot, signed snapshot, schema and full history authentication path.
func authenticateState(tx *bolt.Tx, pw string, key []byte, action string, unlocked *Session) (out *authenticatedState, err error) {
	var opened []byte
	var i identity
	var items []vault.Item
	defer func() {
		if err != nil {
			clear(opened)
			i.clear()
			for _, item := range items {
				clear(item.SSHSeed)
				clear(item.Passkey)
			}
		}
	}()
	b := tx.Bucket(bucket)
	if b == nil {
		return nil, invalid
	}
	var slot account.Slot
	raw := b.Get(slotKey)
	if len(raw) > 8192 || json.Unmarshal(raw, &slot) != nil {
		return nil, invalid
	}
	var e error
	if unlocked != nil {
		if action == "desktop.unlock" || action == "backup.prepare" || sha256.Sum256(raw) != unlocked.slotDigest {
			return nil, invalid
		}
		if unlocked.sessionLocked() {
			return nil, ErrSessionLocked
		}
		opened = bytes.Clone(unlocked.material)
	} else {
		opened, e = account.Unwrap(pw, key, slot)
		if e != nil {
			return nil, invalid
		}
	}
	if json.Unmarshal(opened, &i) != nil || len(i.Signing) != 32 || len(i.Audit) != 32 || len(i.AuditEncryption) != 32 {
		return nil, invalid
	}
	device, e := age.ParseX25519Identity(i.Device)
	if e != nil {
		return nil, invalid
	}
	var s vault.Snapshot
	raw = b.Get(snapshotKey)
	if len(raw) > 12<<20 || json.Unmarshal(raw, &s) != nil {
		return nil, invalid
	}
	signer := ed25519.NewKeyFromSeed(i.Signing)
	defer clear(signer)
	if vault.VerifySnapshot(s, signer.Public().(ed25519.PublicKey), s.Epoch) != nil {
		return nil, invalid
	}
	revisions := make(map[string]string)
	tip, rows, e := history(b, i, s, action == "audit.list" || action == "backup.prepare", revisions)
	if e != nil {
		return nil, e
	}
	chains, e := loadChains(b, i, tip.Origin)
	if e != nil {
		return nil, e
	}
	if action != "audit.list" {
		var meta []byte
		meta, items, e = vault.OpenItems(s, device, signer.Public().(ed25519.PublicKey), tip.Epoch)
		if e != nil || items == nil || string(meta) != schema {
			return nil, invalid
		}
	}
	if action != "audit.list" {
		if len(items) != len(revisions) {
			return nil, invalid
		}
		for _, it := range items {
			if revisions[it.ID] == "" {
				return nil, invalid
			}
		}
	}

	vaults, e := loadVaults(b, i)
	if e != nil {
		return nil, e
	}
	return &authenticatedState{slot, opened, i, s, tip, rows, chains, items, revisions, vaults}, nil
}

// The updater returns only after commit (including bbolt's default fsync).
// Keeping it explicit also permits rollback fault injection in tests.
func commandWithUpdate(update func(func(*bolt.Tx) error) error, pw string, key []byte, action string, add vault.Item, edit *Edit, options ...commandOption) (result, error) {
	var option commandOption
	if len(options) > 1 {
		return result{}, invalid
	}
	if len(options) == 1 {
		option = options[0]
	}
	if desktopFieldAction(action) {
		purpose := strings.Split(action, ".")[2]
		if edit == nil || action != "item.desktop."+purpose+"."+edit.Field || !validNativeFieldTarget(RevealTarget{ID: edit.ID, Revision: edit.Revision, Field: edit.Field}, purpose) {
			return result{}, invalid
		}
	}
	if action == "item.edit.notes" && (edit == nil || edit.Field != "notes" || !ValidEditTarget(edit.ID, edit.Revision, edit.Field)) {
		return result{}, invalid
	}
	if option.nativeMutation != nil && (option.unlocked == nil || option.nativeMutation.gate == nil || !(option.sshState || action == sshGenerateAction || action == sshImportAction || action == sshSignAction || action == "item.add" || nativeEditAction(action) || lifecycleAction(action) || trashAction(action) || generatedAction(action) || action == desktopOTPShowAction || action == desktopOTPCopyAction || action == browserOTPAction || v2MutationAction(action))) {
		return result{}, invalid
	}
	if option.sshState && (option.unlocked == nil || option.nativeMutation == nil || !(lifecycleAction(action) || trashAction(action)) || edit == nil || edit.Field != "" || !idOK(edit.ID) || !digestOK(edit.Revision)) {
		return result{}, ErrSSHKey
	}
	if (action == sshGenerateAction || action == sshImportAction || action == sshSignAction) != (option.ssh != nil) || option.ssh != nil && (option.unlocked == nil || option.nativeMutation == nil || (action == sshSignAction) != (option.ssh.sign != nil)) {
		return result{}, ErrSSHSign
	}
	if action == sshSignAction && (edit == nil || edit.Field != "" || option.ssh.target != (SSHKeyTarget{edit.ID, edit.Revision}) || !idOK(edit.ID) || !digestOK(edit.Revision) || !validSSHRequest(*option.ssh.sign)) {
		return result{}, ErrSSHSign
	}
	if browserSaveAction(action) != (option.browserSave != nil) || option.browserSave != nil && (!option.browserSave.valid() || option.unlocked == nil || (action == browserNewAction) != (option.browserSave.target.ID == "")) {
		return result{}, ErrBrowserSaveRefused
	}
	if (action == browserFillAction) != (option.browser != nil) || option.browser != nil && !option.browser.valid() {
		return result{}, ErrBrowserFill
	}
	if option.browser != nil && (edit == nil || edit.ID != option.browser.ID || edit.Revision != option.browser.Revision) {
		return result{}, ErrBrowserFill
	}
	if (action == browserOTPAction) != (option.browserOTP != nil) || option.browserOTP != nil && (!option.browserOTP.valid() || option.unlocked == nil || option.nativeMutation == nil || edit == nil || edit.ID != option.browserOTP.ID || edit.Revision != option.browserOTP.Revision) {
		return result{}, ErrBrowserOTP
	}
	if generatedAction(action) != (option.generation != nil) {
		return result{}, invalid
	}
	if (action == referenceDisclosureAction) != (option.reference != nil) {
		return result{}, invalid
	}
	if (action == inspectionAction) != (option.inspection != nil) || (option.inspection != nil && option.inspection.read == nil) {
		return result{}, invalid
	}
	if (action == matchAction) != (option.match != nil) {
		return result{}, invalid
	}
	if (action == searchAction) != (option.search != nil) || option.search != nil && !option.search.valid() {
		return result{}, ErrSearchQuery
	}
	if migrationAction(action) != (option.migration != nil) {
		return result{}, invalid
	}
	if option.migration != nil && (option.migration.read == nil || action == importAction && !digestOK(option.migration.expected) || action == importPlanAction && option.migration.expected != "") {
		return result{}, invalid
	}
	if (action == exportAction) != (option.export != nil) {
		return result{}, invalid
	}
	if injectAction(action) != (option.injection != nil) || option.injection != nil && !option.injection.valid() {
		return result{}, ErrInjectionTarget
	}
	if runAction(action) != (option.run != nil) || option.run != nil && option.run.Validate() != nil {
		return result{}, ErrRunTarget
	}
	if (action == runBundleAction) != (option.runBundle != nil) || option.runBundle != nil && option.runBundle.validate() != nil {
		return result{}, ErrRunTarget
	}
	if (action == livePullAction) != (option.livePull != nil) || option.livePull != nil && option.livePull.Validate() != nil {
		return result{}, ErrLivePullTarget
	}
	if option.generation != nil && option.nativeMutation == nil && action != "item.regenerate.password" {
		if option.generation.policy.Alphabet != password.DefaultAlphabet {
			return result{}, password.ErrInvalid
		}
		if _, err := password.Validate(option.generation.policy); err != nil {
			return result{}, err
		}
	}
	var out result
	var refusal error
	e := update(func(tx *bolt.Tx) error {
		auth, e := authenticateState(tx, pw, key, action, option.unlocked)
		if e != nil {
			return e
		}
		defer auth.clear()
		b := tx.Bucket(bucket)
		slot, opened, i, s := auth.slot, auth.opened, auth.identity, auth.snapshot
		tip, rows, chains, items, revisions, vaults := auth.tip, auth.rows, auth.chains, auth.items, auth.revisions, auth.vaults
		outcome := "succeeded"
		var profile *password.Profile
		if action == referenceDisclosureAction {
			action, edit, e = option.reference.bind(slot.Account, vaults, items, revisions)
			if e != nil {
				var known bool
				outcome, known = referenceRejection(e)
				if !known {
					return e
				}
				action, refusal = referenceRejectAction, e
			}
		}
		switch action {
		case sshGenerateAction, sshImportAction:
			add.ID, e = randomID()
			if e != nil {
				return e
			}
			if add.Kind != "ssh-key" || len(add.Title) > 1024 || strings.TrimSpace(add.Title) == "" || vault.ValidateItems([]byte(schema), append(append([]vault.Item(nil), items...), add)) != nil {
				outcome, refusal = "native-refused", ErrMutationRefused
				break
			}
			items = append(items, add)
			out.id = add.ID
		case sshSignAction:
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				for _, item := range items {
					if item.ID != edit.ID {
						continue
					}
					if item.Kind != "ssh-key" || item.State != "" || !bytes.Equal(item.SSHPublicKey, option.ssh.sign.PublicKey) {
						outcome, refusal = "native-refused", ErrMutationRefused
						break
					}
					out.sshSeed = bytes.Clone(item.SSHSeed)
					outcome = "intent"
					break
				}
			}
		case browserNewAction, browserUpdateAction:
			rq := option.browserSave
			index := -1
			if action == browserUpdateAction {
				for n := range items {
					if items[n].ID == rq.target.ID {
						index = n
						break
					}
				}
				if index < 0 {
					outcome, refusal = "not-found", ErrNotFound
				} else {
					out.id = rq.target.ID
					site, siteErr := origin.Website(items[index].URL)
					if revisions[out.id] != rq.target.Revision {
						outcome, refusal = "conflict", ErrConflict
					} else if items[index].Kind != "login" || items[index].State != "" || siteErr != nil || site != rq.target.Context.Origin {
						outcome, refusal = "browser-refused", ErrBrowserSaveRefused
					}
				}
			}
			preparedID := ""
			if action == browserNewAction {
				preparedID, e = randomID()
				if e != nil {
					return e
				}
			}
			out.destinationDigest, e = rq.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
			candidate := append([]vault.Item(nil), items...)
			if refusal == nil {
				if action == browserNewAction {
					candidate = append(candidate, vault.Item{ID: preparedID, Kind: "login", Title: rq.target.Title, URL: rq.target.Context.Origin, Username: string(rq.username), Password: string(rq.password)})
				} else {
					candidate[index].Username = string(rq.username)
					candidate[index].Password = string(rq.password)
				}
				if vault.ValidateItems([]byte(schema), candidate) != nil {
					outcome, refusal = "browser-refused", ErrBrowserSaveRefused
				}
			}
			// This is the persistence linearization point for success or a
			// trusted refusal audit. All validation precedes the single CAS.
			if !option.unlocked.winBrowserSave(rq.gate) {
				return ErrBrowserSaveCancelled
			}
			if refusal == nil {
				if action == browserNewAction {
					out.id = preparedID
				}
				items = candidate
			}
		case "desktop.system.enable":
			outcome = "intent"
		case "desktop.system.unlock":
			// Native session authentication and history validation already succeeded.
		case "desktop.unlock":
			out.material = bytes.Clone(opened)
			out.slotDigest = sha256.Sum256(b.Get(slotKey))
		case searchAction:
			out.rows, e = searchRows(items, revisions, *option.search)
			if e != nil {
				return e
			}
		case healthAction:
			out.health, e = localHealth(items, revisions)
			if e != nil {
				return e
			}
			out.reportDigest, e = digest(out.health)
			if e != nil {
				return e
			}
		case importPlanAction, importAction:
			mapped, err := option.migration.mapSource(i.AuditEncryption)
			if err == nil {
				for _, item := range mapped.Items {
					if revisions[item.ID] != "" {
						err = ErrImportDuplicate
						break
					}
				}
			}
			if err == nil && vault.ValidateItems([]byte(schema), append(items, mapped.Items...)) != nil {
				err = onepux.ErrLimit
			}
			if err != nil {
				outcome, refusal = importFailure(err)
				break
			}
			out.migration = mapped.Report
			out.reportDigest, e = digest(mapped.Report)
			if e != nil {
				return e
			}
			if action == importAction {
				s, e = seal(b, i, s.Epoch+1, append(items, mapped.Items...))
				if e != nil {
					return e
				}
				for _, item := range mapped.Items {
					ev, err := appendLinked(b, i, tip, s, "item.import", item.ID, "succeeded", "", "", eventDetails{reportDigest: out.reportDigest})
					if err != nil {
						return err
					}
					tip = auditTip{Count: ev.Sequence, Last: ev.hash(), Origin: tip.Origin}
				}
			}
		case matchAction:
			if option.match.top != option.match.frame {
				outcome, refusal = "cross-origin", ErrCrossOrigin
			} else {
				out.rows, e = matchingRows(items, revisions, option.match.top)
				if e != nil {
					return e
				}
			}
		case exportAction:
			out.archive, e = vault.ExportKDBX(items, option.export.password)
			if e != nil {
				return e
			}
			outcome = "intent"
		case inspectionAction:
			out.inspection, e = option.inspection.inspect()
			if e != nil {
				out.inspection = onepux.Report{}
				outcome, refusal = inspectionFailure(e)
			} else {
				out.reportDigest, e = digest(out.inspection)
				if e != nil {
					return e
				}
			}
		case referenceRejectAction:
			// Persist only the fixed category, never selectors or caller versions.
		case "reference.list":
			out.references, e = makeReferenceIndex(slot.Account, vaults, items, revisions)
			if e != nil {
				return e
			}
		case "audit.archived":
			out.chains = chains
		case "backup.prepare":
			if option.backup == "" {
				return invalid
			}
		case browserOTPAction, browserFillAction, v2AttachmentReadAction, "item.desktop.show.username", "item.desktop.show.password", "item.desktop.copy.username", "item.desktop.copy.password", "item.desktop.show.notes", "item.desktop.copy.notes", "item.desktop.edit.notes", "item.edit.notes", "item.run.username", "item.run.password", livePullAction, "item.inject.username", "item.inject.password", "item.trash", "item.untrash", "item.archive", "item.unarchive", "item.edit.url", "item.edit.title", "item.edit.username", "item.edit.password", "item.edit.otp", "item.reveal.username", "item.reveal.password", "item.reveal.notes", referenceRevealAction, referenceOTPAction, "item.regenerate.password", otpDisclosureAction, desktopOTPShowAction, desktopOTPCopyAction:
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
						if option.sshState && items[i].Kind != "ssh-key" {
							return ErrSSHKey
						}
						v2Read := action == v2AttachmentReadAction || action == referenceRevealAction || action == referenceOTPAction || action == "item.reveal.notes"
						lifecycleTarget := (items[i].Kind == "ssh-key" || items[i].Kind == "document") && (trashAction(action) || lifecycleAction(action))
						if !option.sshState && option.nativeMutation != nil && items[i].Kind != "login" && !v2Read && !v2MutationAction(action) && !lifecycleTarget {
							return ErrMutationRefused
						}
						if items[i].Kind != "login" && !v2Read && !v2MutationAction(action) && !lifecycleTarget {
							return invalid
						}
						if action == browserOTPAction {
							site, err := origin.Website(items[i].URL)
							if items[i].State != "" || err != nil || site != option.browserOTP.Context.Origin {
								outcome, refusal = "browser-refused", ErrBrowserOTP
								break
							}
						}
						if action == browserFillAction {
							site, err := origin.Website(items[i].URL)
							if items[i].State != "" || err != nil || site != option.browser.Context.Origin || len(items[i].Username) > maxBrowserField || len(items[i].Password) > maxBrowserField {
								outcome, refusal = "browser-refused", ErrBrowserFill
								break
							}
							out.browser = &NativeBrowserFill{username: []byte(items[i].Username), password: []byte(items[i].Password)}
							outcome = "intent"
							break
						}
						if trashAction(action) {
							if action == "item.trash" {
								if items[i].State == "trashed" {
									outcome, refusal = "already-trashed", ErrAlreadyTrashed
								} else {
									now := time.Now().UTC()
									items[i].PreviousState, items[i].State, items[i].TrashedAt = items[i].State, "trashed", &now
								}
							} else if items[i].State != "trashed" {
								outcome, refusal = "not-trashed", ErrNotTrashed
							} else {
								items[i].State, items[i].PreviousState, items[i].TrashedAt = items[i].PreviousState, "", nil
							}
							break
						}
						if items[i].State == "trashed" {
							outcome, refusal = "trashed", ErrTrashed
							break
						}
						if lifecycleAction(action) {
							desired := ""
							if action == "item.archive" {
								desired = "archived"
							}
							if items[i].State == desired {
								if desired == "archived" {
									outcome, refusal = "already-archived", ErrAlreadyArchived
								} else {
									outcome, refusal = "already-active", ErrAlreadyActive
								}
							} else {
								items[i].State = desired
							}
							break
						}
						if action == v2AttachmentReadAction {
							if option.v2 == nil {
								return invalid
							}
							found := false
							for _, att := range items[i].Attachments {
								if att.ID == option.v2.attID {
									out.attachment = att
									out.attachment.Content = nil
									out.attachmentBytes = bytes.Clone(att.Content)
									found = true
									break
								}
							}
							if !found {
								return ErrNotFound
							}
							outcome = "intent"
							break
						}
						if otpAction(action) {
							seed := items[i].OTP
							if action == referenceOTPAction {
								if option.reference == nil {
									return invalid
								}
								resolved, typ, err := resolveReferenceField(items[i], option.reference.target.SectionID, option.reference.target.FieldID)
								if err != nil || typ != reference.TypeOTP {
									outcome, refusal = "not-configured", ErrOTPNotConfigured
									break
								}
								seed = resolved
							}
							if seed == "" {
								outcome, refusal = "not-configured", ErrOTPNotConfigured
								break
							}
							out.otp, e = totp.Parse(seed)
							if e != nil {
								return e
							}
							outcome = "intent"
							break
						}
						if readValueAction(action) {
							value := items[i].Username
							switch action {
							case "item.desktop.show.notes", "item.desktop.copy.notes", "item.desktop.edit.notes", "item.reveal.notes":
								value = items[i].Notes
							case "item.reveal.password", "item.inject.password", "item.run.password", "item.desktop.show.password", "item.desktop.copy.password", livePullAction:
								value = items[i].Password
							case referenceRevealAction:
								if option.reference == nil {
									return invalid
								}
								resolved, _, err := resolveReferenceField(items[i], option.reference.target.SectionID, option.reference.target.FieldID)
								if err != nil {
									return err
								}
								value = resolved
							}
							out.value = []byte(value)
							outcome = "intent"
							break
						}
						if action == "item.regenerate.password" {
							if option.nativeMutation != nil {
								if _, err := password.Validate(option.generation.policy); err != nil {
									outcome, refusal = "native-refused", ErrMutationRefused
									break
								}
								candidate := append([]vault.Item(nil), items...)
								candidate[i].Password = strings.Repeat("X", option.generation.policy.Length)
								if vault.ValidateItems([]byte(schema), candidate) != nil {
									outcome, refusal = "native-refused", ErrMutationRefused
									break
								}
							}
							secret, err := option.generation.value()
							if err != nil {
								return err
							}
							items[i].Password = secret.Value()
							out.profile = secret.Profile()
							profile = &out.profile
							break
						}
						if err := validateEditValue(*edit); err != nil {
							if option.nativeMutation != nil && nativeEditAction(action) {
								outcome, refusal = "native-refused", ErrMutationRefused
								break
							}
							return err
						}
						if option.nativeMutation != nil && nativeEditAction(action) {
							probe := append([]vault.Item(nil), items...)
							switch edit.Field {
							case "title":
								probe[i].Title = edit.Value
							case "url":
								probe[i].URL = edit.Value
							case "username":
								probe[i].Username = edit.Value
							case "password":
								probe[i].Password = edit.Value
							case "otp":
								probe[i].OTP = edit.Value
							case "notes":
								probe[i].Notes = edit.Value
							}
							if vault.ValidateItems([]byte(schema), probe) != nil {
								outcome, refusal = "native-refused", ErrMutationRefused
								break
							}
						}
						switch edit.Field {
						case "notes":
							probe := append([]vault.Item(nil), items...)
							probe[i].Notes = edit.Value
							if option.nativeMutation != nil && vault.ValidateItems([]byte(schema), probe) != nil {
								outcome, refusal = "native-refused", ErrMutationRefused
								break
							}
							items[i].Notes = edit.Value
						case "url":
							items[i].URL = edit.Value
						case "title":
							items[i].Title = edit.Value
						case "username":
							items[i].Username = edit.Value
						case "password":
							items[i].Password = edit.Value
						case "otp":
							items[i].OTP = edit.Value
						}
						break
					}
				}
			}
		case "item.add", "item.generate":
			if option.nativeMutation != nil && action == "item.generate" {
				if _, err := password.Validate(option.generation.policy); err != nil {
					outcome, refusal = "native-refused", ErrMutationRefused
					break
				}
			}
			if option.nativeMutation != nil && action != v2AddAction && (!validNativeNew(add) || action == "item.add" && (add.Password == "" || !validBrowserText([]byte(add.Password)))) {
				outcome, refusal = "native-refused", ErrMutationRefused
				break
			}
			if action == "item.generate" && strings.TrimSpace(add.Title) == "" {
				return errors.New("a title is required")
			}
			if strings.TrimSpace(add.Title) == "" || (action == "item.add" && add.Kind != "document" && add.Password == "") || (action == "item.add" && add.Kind == "document" && (strings.TrimSpace(add.Filename) == "" || len(add.Attachment) == 0)) {
				return errors.New("a title and password are required")
			}
			if option.nativeMutation != nil {
				probe := add
				// Personal IDs are canonical lowercase hex; this equal-length
				// validation placeholder cannot collide and is never persisted.
				probe.ID = strings.Repeat("X", 32)
				if action == "item.generate" {
					probe.Password = strings.Repeat("X", option.generation.policy.Length)
				}
				if vault.ValidateItems([]byte(schema), append(append([]vault.Item(nil), items...), probe)) != nil {
					out.id = ""
					outcome, refusal = "native-refused", ErrMutationRefused
					break
				}
			}
			add.ID, e = randomID()
			if e != nil {
				return e
			}
			if action == "item.generate" {
				secret, err := option.generation.value()
				if err != nil {
					return err
				}
				add.Password = secret.Value()
				out.profile = secret.Profile()
				profile = &out.profile
			}
			items = append(items, add)
			out.id = add.ID
		case "item.list", "item.list.archived", "item.list.trashed", "item.list.all":
			out.rows = make([]Row, 0, len(items))
			for _, it := range items {
				if action == "item.list" && it.State != "" || action == "item.list.archived" && it.State != "archived" || action == "item.list.trashed" && it.State != "trashed" {
					continue
				}
				state := "active"
				if it.State != "" {
					state = it.State
				}
				restoreState := ""
				if it.State == "trashed" {
					restoreState = "active"
					if it.PreviousState == "archived" {
						restoreState = "archived"
					}
				}
				out.rows = append(out.rows, Row{Kind: it.Kind, ID: it.ID, Title: it.Title, Revision: revisions[it.ID], State: state, RestoreState: restoreState})
			}
		case v2ListAction:
			if option.v2 == nil {
				return invalid
			}
			out.summaries, e = listByFilter(items, revisions, option.v2.filter)
			if e != nil {
				return e
			}
			if option.v2.filter.Query != "" {
				out.destinationDigest, e = (&searchRequest{query: option.v2.filter.Query, state: option.v2.filter.State}).binding(i.AuditEncryption)
				if e != nil {
					return e
				}
			}
		case v2DetailViewAction, v2DetailInspectAction:
			if edit == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				out.detail = itemDetail(items[idx], rev, action == v2DetailInspectAction)
				if action == v2DetailInspectAction {
					outcome = "intent"
				}
			}
		case v2AddAction:
			if option.v2 != nil {
				return invalid
			}
			add = vault.CloneItem(add)
			add.ID, e = randomID()
			if e != nil {
				return e
			}
			now := time.Now().Unix()
			add.CreatedAt, add.UpdatedAt = now, now
			add, e = normalizeV2Item(add)
			if e != nil {
				return e
			}
			if !vaultExists(vaults, add.VaultID) {
				return ErrMutationRefused
			}
			if vault.ValidateItems([]byte(schema), append(append([]vault.Item(nil), items...), add)) != nil {
				return ErrMutationRefused
			}
			items = append(items, add)
			out.id = add.ID
		case v2EditAction:
			if edit == nil || option.v2 == nil || option.v2.item == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				if items[idx].State == "trashed" {
					outcome, refusal = "trashed", ErrTrashed
					break
				}
				next := vault.CloneItem(*option.v2.item)
				next.ID = items[idx].ID
				next.State, next.PreviousState, next.TrashedAt = items[idx].State, items[idx].PreviousState, items[idx].TrashedAt
				next.CreatedAt = items[idx].CreatedAt
				next.ImportSource = items[idx].ImportSource
				next.SSHSeed = items[idx].SSHSeed
				next.SSHPublicKey = items[idx].SSHPublicKey
				next.Passkey = items[idx].Passkey
				next.Attachments = items[idx].Attachments
				if next.Filename == "" && next.Attachment == nil {
					next.Filename, next.Attachment, next.AttachmentProtected = items[idx].Filename, items[idx].Attachment, items[idx].AttachmentProtected
				}
				if next.Category == "" && next.Kind == "" {
					next.Category, next.Kind = items[idx].Category, items[idx].Kind
				}
				if next.VaultID == "" {
					next.VaultID = items[idx].VaultID
				}
				next.History = autoHistory(items[idx], next)
				next.UpdatedAt = time.Now().Unix()
				next, e = normalizeV2Item(next)
				if e != nil {
					return e
				}
				if !vaultExists(vaults, next.VaultID) {
					return ErrMutationRefused
				}
				candidate := append([]vault.Item(nil), items...)
				candidate[idx] = next
				if vault.ValidateItems([]byte(schema), candidate) != nil {
					return ErrMutationRefused
				}
				items[idx] = next
			}
		case v2FavoriteAction, v2TagsAction:
			if edit == nil || option.v2 == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				if items[idx].State == "trashed" {
					outcome, refusal = "trashed", ErrTrashed
					break
				}
				next := vault.CloneItem(items[idx])
				if action == v2FavoriteAction {
					next.Favorite = option.v2.favorite
				} else {
					next.Tags, e = normalizeTags(option.v2.tags)
					if e != nil {
						return e
					}
				}
				next.UpdatedAt = time.Now().Unix()
				candidate := append([]vault.Item(nil), items...)
				candidate[idx] = next
				if vault.ValidateItems([]byte(schema), candidate) != nil {
					return ErrMutationRefused
				}
				items[idx] = next
			}
		case v2HistoryRestoreAction:
			if edit == nil || option.v2 == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				if items[idx].State == "trashed" {
					outcome, refusal = "trashed", ErrTrashed
					break
				}
				history := vault.CloneHistory(items[idx].History)
				if option.v2.historyIndex < 0 || option.v2.historyIndex >= len(history) {
					return ErrMutationRefused
				}
				next := vault.CloneItem(items[idx])
				entry := history[option.v2.historyIndex]
				snapshot := vault.ItemHistoryEntry{Timestamp: time.Now().Unix(), Action: "restore", Password: next.Password, Title: next.Title, Username: next.Username, Notes: next.Notes, Sections: vault.CloneSections(next.Sections)}
				history = append(history[:option.v2.historyIndex], history[option.v2.historyIndex+1:]...)
				next.Password = entry.Password
				if entry.Title != "" {
					next.Title = entry.Title
				}
				if entry.Username != "" {
					next.Username = entry.Username
				}
				if entry.Notes != "" {
					next.Notes = entry.Notes
				}
				if entry.Sections != nil {
					next.Sections = vault.CloneSections(entry.Sections)
				}
				next.History = appendHistory(history, snapshot)
				next.UpdatedAt = time.Now().Unix()
				candidate := append([]vault.Item(nil), items...)
				candidate[idx] = next
				if vault.ValidateItems([]byte(schema), candidate) != nil {
					return ErrMutationRefused
				}
				items[idx] = next
			}
		case v2PurgeAction:
			if edit == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				if items[idx].State != "trashed" {
					outcome, refusal = "not-trashed", ErrNotTrashed
					break
				}
				items = append(items[:idx:idx], items[idx+1:]...)
			}
		case v2EmptyTrashAction:
			if option.v2 == nil || option.v2.olderThan != nil && *option.v2.olderThan < 0 {
				return invalid
			}
			now := time.Now()
			purged := make([]struct{ id, revision string }, 0)
			kept := make([]vault.Item, 0, len(items))
			for _, it := range items {
				eligible := it.State == "trashed"
				if eligible && option.v2.olderThan != nil {
					eligible = it.TrashedAt != nil && now.Sub(*it.TrashedAt) >= *option.v2.olderThan
				}
				if eligible {
					purged = append(purged, struct{ id, revision string }{it.ID, revisions[it.ID]})
					continue
				}
				kept = append(kept, it)
			}
			out.purged = len(purged)
			if len(purged) == 0 {
				ev, err := appendLinked(b, i, tip, s, v2EmptyTrashAction, "", "succeeded", "", "")
				if err != nil {
					return err
				}
				out.session, out.intent = ev.Session, ev.hash()
				return nil
			}
			s, e = seal(b, i, s.Epoch+1, kept)
			if e != nil {
				return e
			}
			for _, p := range purged {
				if !idOK(p.id) || !digestOK(p.revision) || revisions[p.id] != p.revision {
					return invalid
				}
				ev, err := appendLinked(b, i, tip, s, v2PurgeAction, p.id, "succeeded", p.revision, "")
				if err != nil {
					return err
				}
				tip = auditTip{Count: ev.Sequence, Last: ev.hash(), Origin: tip.Origin}
				out.session, out.intent = ev.Session, ev.hash()
			}
			return nil
		case v2AttachmentAddAction:
			if edit == nil || option.v2 == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				if items[idx].State == "trashed" {
					outcome, refusal = "trashed", ErrTrashed
					break
				}
				if !validAttachmentFileName(option.v2.fileName) || len(option.v2.mimeType) > 256 || len(option.v2.content) > vault.MaxAttachmentSize {
					return ErrMutationRefused
				}
				attID, err := randomID()
				if err != nil {
					return err
				}
				att := vault.AttachmentMeta{ID: attID, FileName: option.v2.fileName, MIMEType: option.v2.mimeType, Size: int64(len(option.v2.content)), SHA256: vault.AttachmentSHA256(option.v2.content), Content: append([]byte(nil), option.v2.content...)}
				next := vault.CloneItem(items[idx])
				next.Attachments = append(next.Attachments, att)
				next.UpdatedAt = time.Now().Unix()
				candidate := append([]vault.Item(nil), items...)
				candidate[idx] = next
				if vault.ValidateItems([]byte(schema), candidate) != nil {
					return ErrMutationRefused
				}
				items[idx] = next
				out.attachment = att
				out.attachment.Content = nil
			}
		case v2AttachmentRemoveAct:
			if edit == nil || option.v2 == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				if items[idx].State == "trashed" {
					outcome, refusal = "trashed", ErrTrashed
					break
				}
				next := vault.CloneItem(items[idx])
				found := false
				kept := next.Attachments[:0]
				for _, att := range next.Attachments {
					if att.ID == option.v2.attID && !found {
						found = true
						continue
					}
					kept = append(kept, att)
				}
				if !found {
					return ErrNotFound
				}
				next.Attachments = kept
				next.UpdatedAt = time.Now().Unix()
				candidate := append([]vault.Item(nil), items...)
				candidate[idx] = next
				if vault.ValidateItems([]byte(schema), candidate) != nil {
					return ErrMutationRefused
				}
				items[idx] = next
			}
		case v2ListVaultsAction:
			out.vaults = listVaultsMeta(vaults)
		case v2CreateVaultAction:
			if option.v2 == nil {
				return invalid
			}
			meta := vault.VaultMeta{Name: strings.TrimSpace(option.v2.vaultName), Description: option.v2.vaultDesc, Icon: option.v2.vaultIcon}
			meta.ID, e = randomID()
			if e != nil {
				return e
			}
			meta.CreatedAt = time.Now().Unix()
			if !validVaultMeta(meta) {
				return ErrMutationRefused
			}
			for _, v := range vaults {
				if strings.EqualFold(v.Name, meta.Name) {
					return ErrMutationRefused
				}
			}
			vaults = append(vaults, meta)
			if e = saveVaults(b, i, vaults); e != nil {
				return e
			}
			out.vaultMeta = meta
		case v2MoveVaultAction:
			if edit == nil || option.v2 == nil || !idOK(edit.ID) || !digestOK(edit.Revision) {
				return invalid
			}
			out.id = edit.ID
			switch rev := revisions[edit.ID]; {
			case rev == "":
				out.id = ""
				outcome, refusal = "not-found", ErrNotFound
			case rev != edit.Revision:
				outcome, refusal = "conflict", ErrConflict
			default:
				idx := findItemIndex(items, edit.ID)
				if idx < 0 {
					out.id = ""
					outcome, refusal = "not-found", ErrNotFound
					break
				}
				if items[idx].State == "trashed" {
					outcome, refusal = "trashed", ErrTrashed
					break
				}
				target := option.v2.targetVaultID
				if target == "" {
					target = vault.DefaultVaultID
				}
				if !vaultExists(vaults, target) {
					return ErrMutationRefused
				}
				next := vault.CloneItem(items[idx])
				next.VaultID = target
				next.UpdatedAt = time.Now().Unix()
				if option.v2.copyItem {
					next.ID, e = randomID()
					if e != nil {
						return e
					}
					next.State, next.PreviousState, next.TrashedAt = "", "", nil
					now := time.Now().Unix()
					next.CreatedAt, next.UpdatedAt = now, now
					next, e = normalizeV2Item(next)
					if e != nil {
						return e
					}
					candidate := append(append([]vault.Item(nil), items...), next)
					if vault.ValidateItems([]byte(schema), candidate) != nil {
						return ErrMutationRefused
					}
					items = append(items, next)
					out.id = next.ID
				} else {
					next, e = normalizeV2Item(next)
					if e != nil {
						return e
					}
					candidate := append([]vault.Item(nil), items...)
					candidate[idx] = next
					if vault.ValidateItems([]byte(schema), candidate) != nil {
						return ErrMutationRefused
					}
					items[idx] = next
				}
			}
		case runBundleAction:
			out.id, out.values, outcome, refusal, e = option.runBundle.extract(items, revisions)
			if e != nil {
				return e
			}
		case "audit.list":
		default:
			return invalid
		}
		var browserOTPLink string
		if action == browserOTPAction && refusal == nil {
			browserOTPLink, e = option.browserOTP.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
		}
		if option.nativeMutation != nil {
			if option.unlocked == nil || !option.unlocked.winBrowserSave(option.nativeMutation.gate) {
				return ErrMutationCancelled
			}
		} else if option.unlocked != nil && !browserSaveAction(action) {
			if option.unlocked.sessionLocked() {
				return ErrSessionLocked
			}
		}
		if ((action == "item.add" || action == "item.generate" || action == sshGenerateAction || action == sshImportAction || action == v2AddAction) && refusal == nil) || ((editAction(action) || browserSaveAction(action) || action == v2PurgeAction) && refusal == nil) {
			s, e = seal(b, i, s.Epoch+1, items)
			if e != nil {
				return e
			}
		}
		var link string
		if action == sshSignAction && refusal == nil {
			link, e = option.ssh.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
			out.destinationDigest = link
		}
		if action == browserOTPAction {
			link = browserOTPLink
		}
		if browserSaveAction(action) {
			link = out.destinationDigest
		}
		if action == browserFillAction && refusal == nil {
			link, e = option.browser.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
		}
		if action == searchAction {
			link, e = option.search.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
			out.destinationDigest = link
		}
		if action == v2ListAction && option.v2 != nil && option.v2.filter.Query != "" {
			link = out.destinationDigest
		}
		if runAction(action) && refusal == nil {
			link, e = option.run.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
			out.destinationDigest = link
		}
		if action == runBundleAction && refusal == nil {
			link, e = option.runBundle.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
			out.destinationDigest = link
		}
		if injectAction(action) && refusal == nil {
			link, e = option.injection.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
			out.destinationDigest = link
		}
		if action == livePullAction && refusal == nil {
			link, e = option.livePull.binding(i.AuditEncryption)
			if e != nil {
				return e
			}
			out.destinationDigest = link
		}
		if action == "backup.prepare" {
			link, e = generation(option.backup)
			if e != nil {
				return e
			}
			for _, old := range rows {
				if old.Action == action && old.Link == link {
					return invalid
				}
			}
		}
		journalAction := action
		if action == v2AddAction {
			// v2AddAction carries no v2 request, so map it explicitly to the
			// stable journal action expected by Event.verify and history.
			journalAction = "item.add"
		} else if option.v2 != nil {
			journalAction = option.v2.JournalAction(action)
		}
		ev, e := appendLinked(b, i, tip, s, journalAction, out.id, outcome, revisions[out.id], link, eventDetails{generation: profile, reportDigest: out.reportDigest})
		if e != nil {
			return e
		}
		if (action == sshSignAction || readValueAction(action) || otpAction(action) || action == inspectionAction || action == exportAction || migrationAction(action) || action == healthAction || action == searchAction) && refusal == nil {
			out.session, out.intent = ev.Session, ev.hash()
		}
		if action == "backup.prepare" {
			auditPriv := ed25519.NewKeyFromSeed(i.Audit)
			defer clear(auditPriv)
			chains = append(chains, Chain{auditPriv.Public().(ed25519.PublicKey), append(rows, ev)})
			p := payload{Generation: link, Epoch: s.Epoch, Items: items, Chains: chains}
			out.archive, e = encodeArchive(p, pw, key, slot.Account, option.backup, auditPriv)
			return e
		}
		if action == "audit.list" {
			out.events = append(rows, ev)
		} else if (editAction(action) || browserSaveAction(action) || action == "item.generate" || action == "item.add" || action == v2AddAction || action == sshGenerateAction || action == sshImportAction) && refusal == nil {
			out.revision = ev.hash()
		}
		return nil
	})
	if e != nil {
		out.browser.clear()
		clear(out.archive)
		clear(out.material)
		clear(out.value)
		clearBundleValues(out.values)
		clear(out.sshSeed)
		if out.otp != nil {
			out.otp.Clear()
		}
		return result{}, e
	}
	if browserSaveAction(action) || option.nativeMutation != nil {
		out.savePersisted = true
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
