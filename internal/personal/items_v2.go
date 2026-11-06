package personal

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/totp"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

const (
	v2ListAction           = "item.list.v2"
	v2DetailViewAction     = "item.desktop.view"
	v2DetailInspectAction  = "item.desktop.inspect"
	v2AddAction            = "item.add.v2"
	v2EditAction           = "item.edit.v2"
	v2FavoriteAction       = "item.edit.favorite"
	v2TagsAction           = "item.edit.tags"
	v2MoveVaultAction      = "item.edit.vault"
	v2HistoryRestoreAction = "item.history.restore"
	v2PurgeAction          = "item.purge"
	v2EmptyTrashAction     = "vault.trash.empty"
	v2AttachmentAddAction  = "item.attachment.add"
	v2AttachmentReadAction = "item.attachment.read"
	v2AttachmentRemoveAct  = "item.attachment.remove"
	v2ListVaultsAction     = "vault.list"
	v2CreateVaultAction    = "vault.sub.create"

	referenceRevealAction = "item.reveal.reference"
	referenceOTPAction    = "item.reveal.reference.otp"
)

const maxHistoryEntries = 20

// ItemSummary extends Row with v2 metadata for list, search, sidebar and
// browser popup views. It never contains secret values.
type ItemSummary struct {
	ID           string             `json:"id"`
	Revision     string             `json:"revision"`
	Kind         string             `json:"kind"`
	Category     vault.ItemCategory `json:"category"`
	VaultID      string             `json:"vault_id"`
	Title        string             `json:"title"`
	Subtitle     string             `json:"subtitle,omitempty"`
	PrimaryURL   string             `json:"primary_url,omitempty"`
	State        string             `json:"state"`
	RestoreState string             `json:"restore_state,omitempty"`
	Favorite     bool               `json:"favorite,omitempty"`
	Tags         []string           `json:"tags,omitempty"`
	HasOTP       bool               `json:"has_otp,omitempty"`
	HasPasskey   bool               `json:"has_passkey,omitempty"`
	Attachments  int                `json:"attachments,omitempty"`
	TrashedAt    *time.Time         `json:"trashed_at,omitempty"`
	UpdatedAt    int64              `json:"updated_at,omitempty"`
}

// ItemDetail is the native-session view of a single item.
type ItemDetail struct {
	ID             string                   `json:"id"`
	Revision       string                   `json:"revision"`
	Kind           string                   `json:"kind"`
	Category       vault.ItemCategory       `json:"category"`
	VaultID        string                   `json:"vault_id"`
	Title          string                   `json:"title"`
	Username       string                   `json:"username,omitempty"`
	Password       string                   `json:"password,omitempty"`
	OTP            string                   `json:"otp,omitempty"`
	URL            string                   `json:"url,omitempty"`
	URLs           []vault.ItemURL          `json:"urls,omitempty"`
	Notes          string                   `json:"notes,omitempty"`
	Favorite       bool                     `json:"favorite,omitempty"`
	AutoSubmit     *bool                    `json:"auto_submit,omitempty"`
	Tags           []string                 `json:"tags,omitempty"`
	State          string                   `json:"state"`
	RestoreState   string                   `json:"restore_state,omitempty"`
	Sections       []vault.ItemSection      `json:"sections,omitempty"`
	CreditCard     *vault.CreditCardDetails `json:"credit_card,omitempty"`
	Identity       *vault.IdentityDetails   `json:"identity,omitempty"`
	History        []vault.ItemHistoryEntry `json:"history,omitempty"`
	Attachments    []vault.AttachmentMeta   `json:"attachments,omitempty"`
	SSHPublicKey   string                   `json:"ssh_public_key,omitempty"`
	SSHFingerprint string                   `json:"ssh_fingerprint,omitempty"`
	HasPasskey     bool                     `json:"has_passkey,omitempty"`
	TrashedAt      *time.Time               `json:"trashed_at,omitempty"`
	CreatedAt      int64                    `json:"created_at,omitempty"`
	UpdatedAt      int64                    `json:"updated_at,omitempty"`
}

// ItemFilter specifies filtering and sorting criteria for Session.ListByFilter.
type ItemFilter struct {
	VaultID  string             `json:"vault_id,omitempty"`
	Category vault.ItemCategory `json:"category,omitempty"`
	Tag      string             `json:"tag,omitempty"`
	Favorite *bool              `json:"favorite,omitempty"`
	State    string             `json:"state,omitempty"`
	Query    string             `json:"query,omitempty"`
	SortBy   string             `json:"sort_by,omitempty"`
}

type v2Request struct {
	filter        ItemFilter
	item          *vault.Item
	favorite      bool
	tags          []string
	historyIndex  int
	attID         string
	fileName      string
	mimeType      string
	content       []byte
	olderThan     *time.Duration
	vaultName     string
	vaultDesc     string
	vaultIcon     string
	targetVaultID string
	copyItem      bool
}

func v2MutationAction(action string) bool {
	switch action {
	case v2AddAction, v2EditAction, v2FavoriteAction, v2TagsAction, v2MoveVaultAction,
		v2HistoryRestoreAction, v2AttachmentAddAction, v2AttachmentRemoveAct,
		v2PurgeAction, v2EmptyTrashAction, v2CreateVaultAction:
		return true
	}
	return false
}

func v2EditLikeAction(action string) bool {
	switch action {
	case v2EditAction, v2FavoriteAction, v2TagsAction, v2MoveVaultAction,
		v2HistoryRestoreAction, v2AttachmentAddAction, v2AttachmentRemoveAct:
		return true
	}
	return false
}

// JournalAction maps an internal v2 action to its stable audit action name.
func (r *v2Request) JournalAction(action string) string {
	switch action {
	case v2ListAction:
		if r != nil && r.filter.Query != "" {
			return searchAction
		}
		return "item.list"
	case v2AddAction:
		return "item.add"
	case v2MoveVaultAction:
		if r != nil && r.copyItem {
			return "item.add"
		}
	}
	return action
}

// ---------- Session v2 APIs ----------

func (s *Session) ListByFilter(filter ItemFilter) ([]ItemSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute(v2ListAction, vault.Item{}, nil, commandOption{v2: &v2Request{filter: filter}})
	return r.summaries, e
}

func (s *Session) GetItemDetail(id, revision string, revealConcealed bool) (ItemDetail, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idOK(id) || !digestOK(revision) {
		return ItemDetail{}, invalid
	}
	action := v2DetailViewAction
	if revealConcealed {
		action = v2DetailInspectAction
	}
	r, e := s.execute(action, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{})
	return r.detail, e
}

func (s *Session) AddItem(item vault.Item, g *MutationGate) (string, string, error) {
	r, e := s.nativeMutation(v2AddAction, item, nil, commandOption{}, g)
	return r.id, r.revision, e
}

func (s *Session) EditItem(id, revision string, updated vault.Item, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	r, e := s.nativeMutation(v2EditAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{item: &updated}}, g)
	return r.revision, e
}

func (s *Session) SetFavorite(id, revision string, favorite bool, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	r, e := s.nativeMutation(v2FavoriteAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{favorite: favorite}}, g)
	return r.revision, e
}

func (s *Session) SetTags(id, revision string, tags []string, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	r, e := s.nativeMutation(v2TagsAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{tags: tags}}, g)
	return r.revision, e
}

func (s *Session) RestoreHistory(id, revision string, historyIndex int, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) || historyIndex < 0 {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	r, e := s.nativeMutation(v2HistoryRestoreAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{historyIndex: historyIndex}}, g)
	return r.revision, e
}

func (s *Session) PurgeTrashed(id, revision string, g *MutationGate) error {
	if !idOK(id) || !digestOK(revision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return ErrMutationRefused
	}
	_, e := s.nativeMutation(v2PurgeAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{}, g)
	return e
}

func (s *Session) EmptyTrash(olderThan *time.Duration, g *MutationGate) (int, error) {
	r, e := s.nativeMutation(v2EmptyTrashAction, vault.Item{}, nil, commandOption{v2: &v2Request{olderThan: olderThan}}, g)
	return r.purged, e
}

func (s *Session) AddAttachment(id, revision, fileName, mimeType string, content []byte, g *MutationGate) (string, string, error) {
	if !idOK(id) || !digestOK(revision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", "", ErrMutationRefused
	}
	body := append([]byte(nil), content...)
	r, e := s.nativeMutation(v2AttachmentAddAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{fileName: fileName, mimeType: mimeType, content: body}}, g)
	if e != nil {
		clear(body)
		return "", "", e
	}
	return r.attachment.ID, r.revision, nil
}

func (s *Session) GetAttachment(id, revision, attID string) (vault.AttachmentMeta, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idOK(id) || !digestOK(revision) || !selectorID(attID) {
		return vault.AttachmentMeta{}, nil, invalid
	}
	r, e := s.execute(v2AttachmentReadAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{attID: attID}})
	if e != nil {
		return vault.AttachmentMeta{}, nil, e
	}
	return r.attachment, r.attachmentBytes, nil
}

func (s *Session) RemoveAttachment(id, revision, attID string, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) || !selectorID(attID) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	r, e := s.nativeMutation(v2AttachmentRemoveAct, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{attID: attID}}, g)
	return r.revision, e
}

func (s *Session) ListVaults() ([]vault.VaultMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute(v2ListVaultsAction, vault.Item{}, nil, commandOption{})
	return r.vaults, e
}

func (s *Session) CreateVault(name, description, icon string, g *MutationGate) (vault.VaultMeta, error) {
	r, e := s.nativeMutation(v2CreateVaultAction, vault.Item{}, nil, commandOption{v2: &v2Request{vaultName: name, vaultDesc: description, vaultIcon: icon}}, g)
	return r.vaultMeta, e
}

func (s *Session) MoveItemVault(id, revision, targetVaultID string, copyItem bool, g *MutationGate) (string, string, error) {
	if !idOK(id) || !digestOK(revision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", "", ErrMutationRefused
	}
	r, e := s.nativeMutation(v2MoveVaultAction, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{v2: &v2Request{targetVaultID: targetVaultID, copyItem: copyItem}}, g)
	return r.id, r.revision, e
}

// ---------- v2 item model helpers ----------

func defaultVaultMeta() vault.VaultMeta {
	return vault.VaultMeta{ID: vault.DefaultVaultID, Name: "Personal"}
}

func listVaultsMeta(vaults []vault.VaultMeta) []vault.VaultMeta {
	out := make([]vault.VaultMeta, 0, len(vaults)+1)
	out = append(out, defaultVaultMeta())
	out = append(out, vaults...)
	return out
}

func vaultExists(vaults []vault.VaultMeta, id string) bool {
	if id == "" || id == vault.DefaultVaultID {
		return true
	}
	for _, v := range vaults {
		if v.ID == id {
			return true
		}
	}
	return false
}

func validVaultMeta(v vault.VaultMeta) bool {
	if v.ID == "" || !selectorID(v.ID) || strings.TrimSpace(v.Name) == "" || len(v.Name) > 256 || !utf8.ValidString(v.Name) || len(v.Description) > 4096 || !utf8.ValidString(v.Description) || len(v.Icon) > 64 || !utf8.ValidString(v.Icon) {
		return false
	}
	for _, s := range []string{v.Name, v.Icon} {
		if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			return false
		}
	}
	return !strings.ContainsRune(v.Description, 0)
}

var vaultsKey = []byte("vaults-v2")
var vaultsLabel = []byte("locklark/personal/vaults/v2\x00")

func loadVaults(b *bolt.Bucket, i identity) ([]vault.VaultMeta, error) {
	raw := b.Get(vaultsKey)
	if raw == nil {
		return nil, nil
	}
	a, e := auditCipher(i)
	if e != nil || len(raw) < a.Overhead() || len(raw) > 64<<10 {
		return nil, invalid
	}
	p, e := a.Open(nil, nil, raw, vaultsLabel)
	if e != nil {
		return nil, invalid
	}
	defer clear(p)
	var vaults []vault.VaultMeta
	if json.Unmarshal(p, &vaults) != nil || len(vaults) > 64 {
		return nil, invalid
	}
	seen := map[string]bool{vault.DefaultVaultID: true}
	for _, v := range vaults {
		if !validVaultMeta(v) || seen[strings.ToLower(v.ID)] {
			return nil, invalid
		}
		seen[strings.ToLower(v.ID)] = true
	}
	return vaults, nil
}

func saveVaults(b *bolt.Bucket, i identity, vaults []vault.VaultMeta) error {
	a, e := auditCipher(i)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(vaults)
	if e != nil {
		return e
	}
	defer clear(raw)
	if len(raw) > 48<<10 {
		return invalid
	}
	return b.Put(vaultsKey, a.Seal(nil, nil, raw, vaultsLabel))
}

func normalizeTags(tags []string) ([]string, error) {
	if tags == nil {
		return nil, nil
	}
	out := make([]string, 0, len(tags))
	seen := map[string]bool{}
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if len(tag) > 256 || !utf8.ValidString(tag) || strings.ContainsFunc(tag, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			return nil, ErrMutationRefused
		}
		if seen[strings.ToLower(tag)] {
			continue
		}
		seen[strings.ToLower(tag)] = true
		out = append(out, tag)
	}
	return out, nil
}

func validAttachmentFileName(name string) bool {
	if name == "" || len(name) > 255 || name == "." || name == ".." || strings.ContainsAny(name, "/\\") || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || r == 0xfffe || r == 0xffff })
}

func selectorID(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func findItemIndex(items []vault.Item, id string) int {
	for i := range items {
		if items[i].ID == id {
			return i
		}
	}
	return -1
}

// normalizeV2Item canonicalizes Kind/Category and derived attachment metadata.
func normalizeV2Item(it vault.Item) (vault.Item, error) {
	cat, ok := vault.CategoryFromKind(it.Kind, it.Category)
	if !ok {
		return vault.Item{}, ErrMutationRefused
	}
	it.Category = cat
	switch cat {
	case vault.CategorySSHKey:
		if len(it.SSHSeed) > 0 || it.Kind == "ssh-key" {
			it.Kind = "ssh-key"
		} else {
			it.Kind = string(vault.CategorySSHKey)
		}
	default:
		it.Kind = string(cat)
	}
	if strings.TrimSpace(it.Title) == "" || len(it.Title) > 1024 || !validBrowserText([]byte(it.Title)) {
		return vault.Item{}, ErrMutationRefused
	}
	it.VaultID = it.EffectiveVaultID()
	for s := range it.Sections {
		for f := range it.Sections[s].Fields {
			field := &it.Sections[s].Fields[f]
			if field.Type == "" {
				field.Type = vault.FieldTypeText
			}
			if field.Type == vault.FieldTypeConcealed || field.Type == vault.FieldTypeOTP || field.Type == vault.FieldTypeTOTP {
				field.Protected = true
			}
		}
	}
	for n := range it.Attachments {
		att := &it.Attachments[n]
		if att.ID == "" {
			id, e := randomID()
			if e != nil {
				return vault.Item{}, e
			}
			att.ID = id
		}
		if att.Content == nil {
			if att.Size != 0 || att.SHA256 != "" {
				return vault.Item{}, ErrMutationRefused
			}
			att.Content = []byte{}
		}
		att.Size = int64(len(att.Content))
		att.SHA256 = vault.AttachmentSHA256(att.Content)
	}
	return it, nil
}

func concealedValues(sections []vault.ItemSection) map[string]string {
	out := map[string]string{}
	for _, s := range sections {
		for _, f := range s.Fields {
			if f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP {
				out[strings.ToLower(s.ID)+"\x00"+strings.ToLower(f.ID)] = f.Value
			}
		}
	}
	return out
}

func concealedChanged(before, after []vault.ItemSection) bool {
	a, b := concealedValues(before), concealedValues(after)
	if len(a) != len(b) {
		return true
	}
	for k, v := range a {
		if b[k] != v {
			return true
		}
	}
	return false
}

func appendHistory(history []vault.ItemHistoryEntry, entry vault.ItemHistoryEntry) []vault.ItemHistoryEntry {
	history = append(history, entry)
	if len(history) > maxHistoryEntries {
		history = append([]vault.ItemHistoryEntry(nil), history[len(history)-maxHistoryEntries:]...)
	}
	return history
}

func autoHistory(prev, next vault.Item) []vault.ItemHistoryEntry {
	history := next.History
	if history == nil {
		history = vault.CloneHistory(prev.History)
	}
	if prev.Password == next.Password && prev.Username == next.Username && prev.Notes == next.Notes && !concealedChanged(prev.Sections, next.Sections) {
		return history
	}
	entry := vault.ItemHistoryEntry{
		Timestamp: time.Now().Unix(),
		Action:    "edit",
		Password:  prev.Password,
		Title:     prev.Title,
		Username:  prev.Username,
		Notes:     prev.Notes,
	}
	if concealedChanged(prev.Sections, next.Sections) {
		entry.Sections = vault.CloneSections(prev.Sections)
	}
	return appendHistory(history, entry)
}

func stateName(it vault.Item) string {
	if it.State == "" {
		return "active"
	}
	return it.State
}

func restoreState(it vault.Item) string {
	if it.State != "trashed" {
		return ""
	}
	if it.PreviousState == "archived" {
		return "archived"
	}
	return "active"
}

func primaryItemURL(it vault.Item) string {
	urls := it.AllURLs()
	for _, u := range urls {
		if u.Primary {
			return u.URL
		}
	}
	if len(urls) > 0 {
		return urls[0].URL
	}
	return ""
}

func sshFingerprint(it vault.Item) (string, string) {
	if len(it.SSHPublicKey) == 0 {
		return "", ""
	}
	pub, err := ssh.ParsePublicKey(it.SSHPublicKey)
	if err != nil {
		return "", ""
	}
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n"), ssh.FingerprintSHA256(pub)
}

func itemSubtitle(it vault.Item) string {
	switch it.EffectiveCategory() {
	case vault.CategoryLogin, vault.CategoryPassword, vault.CategoryDatabase, vault.CategoryServer, vault.CategoryAPICredential, vault.CategoryWirelessRouter:
		return it.Username
	case vault.CategoryCreditCard:
		if cc := it.NormalizedCreditCard(); cc != nil && len(cc.Number) >= 4 {
			return "•••• " + cc.Number[len(cc.Number)-4:]
		}
	case vault.CategoryIdentity:
		if id := it.NormalizedIdentity(); id != nil {
			if name := strings.TrimSpace(id.FirstName + " " + id.LastName); name != "" {
				return name
			}
			return id.Email
		}
	case vault.CategorySSHKey:
		_, fp := sshFingerprint(it)
		return fp
	}
	return ""
}

func hasOTPField(it vault.Item) bool {
	if it.OTP != "" {
		return true
	}
	for _, s := range it.Sections {
		for _, f := range s.Fields {
			if f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP {
				return true
			}
		}
	}
	return false
}

func itemSummary(it vault.Item, revision string) ItemSummary {
	return ItemSummary{
		ID:           it.ID,
		Revision:     revision,
		Kind:         it.Kind,
		Category:     it.EffectiveCategory(),
		VaultID:      it.EffectiveVaultID(),
		Title:        it.Title,
		Subtitle:     itemSubtitle(it),
		PrimaryURL:   primaryItemURL(it),
		State:        stateName(it),
		RestoreState: restoreState(it),
		Favorite:     it.Favorite,
		Tags:         append([]string(nil), it.Tags...),
		HasOTP:       hasOTPField(it),
		HasPasskey:   len(it.Passkey) > 0,
		Attachments:  len(it.Attachments),
		TrashedAt:    it.TrashedAt,
		UpdatedAt:    it.UpdatedAt,
	}
}

func maskSections(in []vault.ItemSection, reveal bool) []vault.ItemSection {
	out := vault.CloneSections(in)
	if reveal {
		return out
	}
	for s := range out {
		for f := range out[s].Fields {
			field := &out[s].Fields[f]
			if field.Protected || field.Type == vault.FieldTypeConcealed || field.Type == vault.FieldTypeOTP || field.Type == vault.FieldTypeTOTP {
				field.Value = ""
			}
		}
	}
	return out
}

func maskHistory(in []vault.ItemHistoryEntry, reveal bool) []vault.ItemHistoryEntry {
	out := vault.CloneHistory(in)
	if reveal {
		return out
	}
	for h := range out {
		out[h].Password = ""
		out[h].Sections = maskSections(out[h].Sections, false)
	}
	return out
}

func itemDetail(it vault.Item, revision string, reveal bool) ItemDetail {
	detail := ItemDetail{
		ID:           it.ID,
		Revision:     revision,
		Kind:         it.Kind,
		Category:     it.EffectiveCategory(),
		VaultID:      it.EffectiveVaultID(),
		Title:        it.Title,
		Username:     it.Username,
		Password:     it.Password,
		OTP:          it.OTP,
		URL:          it.URL,
		URLs:         append([]vault.ItemURL(nil), it.URLs...),
		Notes:        it.Notes,
		Favorite:     it.Favorite,
		AutoSubmit:   it.AutoSubmit,
		Tags:         append([]string(nil), it.Tags...),
		State:        stateName(it),
		RestoreState: restoreState(it),
		Sections:     it.Sections,
		CreditCard:   it.NormalizedCreditCard(),
		Identity:     it.NormalizedIdentity(),
		History:      it.History,
		Attachments:  append([]vault.AttachmentMeta(nil), it.Attachments...),
		HasPasskey:   len(it.Passkey) > 0,
		TrashedAt:    it.TrashedAt,
		CreatedAt:    it.CreatedAt,
		UpdatedAt:    it.UpdatedAt,
	}
	detail.SSHPublicKey, detail.SSHFingerprint = sshFingerprint(it)
	for n := range detail.Attachments {
		detail.Attachments[n].Content = nil
	}
	detail.Sections = maskSections(it.Sections, reveal)
	detail.History = maskHistory(it.History, reveal)
	if !reveal {
		detail.Password = ""
		detail.OTP = ""
		if detail.CreditCard != nil {
			cc := *detail.CreditCard
			cc.Number, cc.Verification, cc.PIN = "", "", ""
			detail.CreditCard = &cc
		}
	}
	return detail
}

func validV2Filter(f ItemFilter) bool {
	if f.State != "" && f.State != "active" && f.State != "archived" && f.State != "trashed" && f.State != "all" {
		return false
	}
	if f.Category != "" && !vault.ValidCategory(f.Category) {
		return false
	}
	if f.Tag != "" && (len(f.Tag) > 256 || !utf8.ValidString(f.Tag)) {
		return false
	}
	if f.Query != "" && !ValidSearchQuery(f.Query) {
		return false
	}
	switch f.SortBy {
	case "", "title", "updated_at", "created_at", "category":
	default:
		return false
	}
	return true
}

func itemMatchesQuery(it vault.Item, query string) bool {
	want := strings.ToLower(query)
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), want) }
	if has(it.Title) || has(it.Username) || has(it.URL) || has(it.Notes) {
		return true
	}
	for _, u := range it.URLs {
		if has(u.URL) || has(u.Label) {
			return true
		}
	}
	for _, tag := range it.Tags {
		if has(tag) {
			return true
		}
	}
	for _, s := range it.Sections {
		if has(s.Title) {
			return true
		}
		for _, f := range s.Fields {
			if f.Protected || f.Type == vault.FieldTypeConcealed || f.Type == vault.FieldTypeOTP || f.Type == vault.FieldTypeTOTP {
				continue
			}
			if has(f.Label) || has(f.Value) {
				return true
			}
		}
	}
	if cc := it.NormalizedCreditCard(); cc != nil && (has(cc.CardholderName) || has(cc.IssuingBank)) {
		return true
	}
	if id := it.NormalizedIdentity(); id != nil {
		if has(id.FirstName) || has(id.LastName) || has(id.Email) || has(id.Company) {
			return true
		}
	}
	return false
}

func listByFilter(items []vault.Item, revisions map[string]string, filter ItemFilter) ([]ItemSummary, error) {
	if !validV2Filter(filter) {
		return nil, invalid
	}
	state := filter.State
	if state == "" {
		state = "active"
	}
	out := make([]ItemSummary, 0, len(items))
	created := map[string]int64{}
	for _, it := range items {
		if state != "all" && stateName(it) != state {
			continue
		}
		if filter.Category != "" && it.EffectiveCategory() != filter.Category {
			continue
		}
		if filter.VaultID != "" && filter.VaultID != "all" && it.EffectiveVaultID() != filter.VaultID {
			continue
		}
		if filter.Favorite != nil && it.Favorite != *filter.Favorite {
			continue
		}
		if filter.Tag != "" {
			found := false
			for _, tag := range it.Tags {
				if strings.EqualFold(tag, filter.Tag) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if filter.Query != "" && !itemMatchesQuery(it, filter.Query) {
			continue
		}
		revision := revisions[it.ID]
		if !digestOK(revision) {
			return nil, invalid
		}
		out = append(out, itemSummary(it, revision))
		created[it.ID] = it.CreatedAt
	}
	sort.SliceStable(out, func(i, j int) bool {
		switch filter.SortBy {
		case "updated_at":
			if out[i].UpdatedAt != out[j].UpdatedAt {
				return out[i].UpdatedAt > out[j].UpdatedAt
			}
		case "created_at":
			if created[out[i].ID] != created[out[j].ID] {
				return created[out[i].ID] > created[out[j].ID]
			}
		case "category":
			if out[i].Category != out[j].Category {
				return out[i].Category < out[j].Category
			}
		}
		return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title) || strings.ToLower(out[i].Title) == strings.ToLower(out[j].Title) && out[i].ID < out[j].ID
	})
	return out, nil
}

// resolveReferenceField reads a value selected by a resolved reference target.
func resolveReferenceField(it vault.Item, sectionID, fieldID string) (string, reference.ValueType, error) {
	if sectionID != "" {
		for _, s := range it.Sections {
			if s.ID != sectionID {
				continue
			}
			for _, f := range s.Fields {
				if f.ID != fieldID {
					continue
				}
				typ := reference.TypeText
				if f.Protected {
					typ = reference.TypePassword
				}
				switch f.Type {
				case vault.FieldTypeConcealed:
					typ = reference.TypePassword
				case vault.FieldTypeOTP, vault.FieldTypeTOTP:
					typ = reference.TypeOTP
				}
				return f.Value, typ, nil
			}
			return "", "", reference.ErrNotFound
		}
		return "", "", reference.ErrNotFound
	}
	switch fieldID {
	case "username":
		return it.Username, reference.TypeText, nil
	case "password":
		return it.Password, reference.TypePassword, nil
	case "otp":
		return it.OTP, reference.TypeOTP, nil
	case "notes":
		return it.Notes, reference.TypeText, nil
	}
	if cc := it.NormalizedCreditCard(); cc != nil {
		switch fieldID {
		case "cc-name":
			return cc.CardholderName, reference.TypeText, nil
		case "cc-type":
			return cc.Type, reference.TypeText, nil
		case "cc-number":
			return cc.Number, reference.TypePassword, nil
		case "cc-csc":
			return cc.Verification, reference.TypePassword, nil
		case "cc-exp":
			return cc.ExpiryDate, reference.TypeText, nil
		case "cc-exp-month":
			if len(cc.ExpiryDate) >= 7 {
				return cc.ExpiryDate[5:7], reference.TypeText, nil
			}
		case "cc-exp-year":
			if len(cc.ExpiryDate) >= 4 {
				return cc.ExpiryDate[:4], reference.TypeText, nil
			}
		case "cc-pin":
			return cc.PIN, reference.TypePassword, nil
		case "cc-bank":
			return cc.IssuingBank, reference.TypeText, nil
		}
	}
	if id := it.NormalizedIdentity(); id != nil {
		switch fieldID {
		case "honorific-prefix":
			return id.Title, reference.TypeText, nil
		case "given-name":
			return id.FirstName, reference.TypeText, nil
		case "additional-name":
			return id.MiddleName, reference.TypeText, nil
		case "family-name":
			return id.LastName, reference.TypeText, nil
		case "bday":
			return id.BirthDate, reference.TypeText, nil
		case "organization":
			return id.Company, reference.TypeText, nil
		case "department":
			return id.Department, reference.TypeText, nil
		case "organization-title":
			return id.JobTitle, reference.TypeText, nil
		case "email":
			return id.Email, reference.TypeText, nil
		case "tel":
			return id.Phone, reference.TypeText, nil
		case "address-line1":
			return id.AddressLine1, reference.TypeText, nil
		case "address-line2":
			return id.AddressLine2, reference.TypeText, nil
		case "address-level2":
			return id.City, reference.TypeText, nil
		case "address-level1":
			return id.State, reference.TypeText, nil
		case "postal-code":
			return id.PostalCode, reference.TypeText, nil
		case "country":
			return id.Country, reference.TypeText, nil
		case "ssn":
			return id.SSN, reference.TypePassword, nil
		case "passport-number":
			return id.PassportNumber, reference.TypeText, nil
		case "license-number":
			return id.LicenseNumber, reference.TypeText, nil
		case "url":
			return id.Website, reference.TypeText, nil
		}
	}
	for _, s := range it.Sections {
		for _, f := range s.Fields {
			if f.ID != fieldID {
				continue
			}
			typ := reference.TypeText
			if f.Protected {
				typ = reference.TypePassword
			}
			return f.Value, typ, nil
		}
	}
	return "", "", reference.ErrNotFound
}

func referenceFieldOTP(value string) (*totp.Config, error) {
	config, err := totp.Parse(value)
	if err != nil {
		return nil, ErrOTPNotConfigured
	}
	return config, nil
}
