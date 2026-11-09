package personal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

var invalid = errors.New("invalid personal vault, unlock factors or journal")

type Event struct {
	ReportDigest string            `json:"report_digest,omitempty"`
	Generation   *password.Profile `json:"generation,omitempty"`
	Link         string            `json:"link,omitempty"`
	BaseRevision string            `json:"base_revision,omitempty"`
	Sequence     uint64            `json:"sequence"`
	UTC          string            `json:"utc"`
	Session      string            `json:"session"`
	Actor        string            `json:"actor"`
	Action       string            `json:"action"`
	Item         string            `json:"item_id,omitempty"`
	Result       string            `json:"result"`
	Previous     string            `json:"previous"`
	Signature    []byte            `json:"signature"`
}
type auditTip struct {
	Count, Epoch   uint64
	Last, Snapshot string
	Origin         string `json:",omitempty"`
}

var eventsKey = []byte("audit-events")
var tipKey = []byte("audit-tip")

func auditCipher(i identity) (cipher.AEAD, error) {
	b, e := aes.NewCipher(i.AuditEncryption)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCMWithRandomNonce(b)
}

func randomID() (string, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}
func idOK(s string) bool {
	v, e := hex.DecodeString(s)
	return e == nil && len(v) == 16 && s == hex.EncodeToString(v)
}
func (e Event) proof() []byte {
	e.Signature = nil
	b, _ := json.Marshal(e)
	return append([]byte("locklark/personal/audit/v1\x00"), b...)
}
func (e Event) hash() string {
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (e Event) verify(pub ed25519.PublicKey, n uint64, prev string) error {
	if _, err := time.Parse(time.RFC3339Nano, e.UTC); err != nil {
		return invalid
	}
	if e.Sequence != n || e.Previous != prev || !idOK(e.Session) || e.Actor != "local-owner" || !ed25519.Verify(pub, e.proof(), e.Signature) {
		return invalid
	}
	// The export intent is an exact fixed known shape checked before the
	// generic Link guards, and it is intentionally not part of
	// passkeyTransferAction because the invitation scanner only sees
	// invite/revoke/consume state.
	if e.Action == passkeyTransferExportAction {
		return verifyPasskeyTransferExportEvent(e, n)
	}
	if e.Action == passkeyTransferItemAction {
		return verifyPasskeyTransferItemEvent(e, n)
	}
	if e.Action != passkeyCreateAction && e.Action != passkeySignalAction && e.Action != "desktop.system.enable" && e.Action != sshSignAction && !browserSaveAction(e.Action) && !editAction(e.Action) && !readValueAction(e.Action) && !otpAction(e.Action) && e.Action != referenceRejectAction && e.Action != inspectionAction && e.Action != exportAction && e.Action != matchAction && !migrationAction(e.Action) && e.Action != v2PurgeAction && e.Action != v2EmptyTrashAction && e.Action != v2CreateVaultAction && e.Action != v2ListVaultsAction && e.Action != v2DetailViewAction && e.Action != v2DetailInspectAction && e.Action != v2AttachmentReadAction && e.Action != watchtowerAction && e.Action != hibpAction && !passkeyTransferAction(e.Action) && !((e.Action == sshGenerateAction || e.Action == sshImportAction || e.Action == "item.add" || e.Action == "item.generate") && e.Result == "native-refused") && (e.Result != "succeeded" || e.BaseRevision != "") {
		return invalid
	}
	if (e.Action == inspectionAction || migrationAction(e.Action) || e.Action == "item.import" || e.Action == healthAction || e.Action == watchtowerAction || e.Action == hibpAction) && e.Result == "succeeded" {
		if !digestOK(e.ReportDigest) {
			return invalid
		}
	} else if e.ReportDigest != "" {
		return invalid
	}
	if e.Action != passkeyCreateAction && e.Action != passkeySignalAction && e.Action != sshSignAction && e.Action != "backup.prepare" && e.Action != "vault.restore" && !browserSaveAction(e.Action) && !boundValueAction(e.Action) && e.Action != searchAction && !passkeyTransferAction(e.Action) && e.Link != "" {
		return invalid
	}
	if e.Action == passkeySignalAction && !digestOK(e.Link) {
		return invalid
	}
	if e.Action == searchAction && !digestOK(e.Link) {
		return invalid
	}
	if boundValueAction(e.Action) && (e.Result == "intent" && !digestOK(e.Link) || e.Result != "intent" && e.Link != "") {
		return invalid
	}
	if generatedAction(e.Action) && e.Result == "succeeded" {
		if e.Generation == nil || !validGenerationProfile(*e.Generation) {
			return invalid
		}
	} else if e.Generation != nil {
		return invalid
	}
	switch e.Action {
	case sshSignAction:
		if n <= 1 {
			return invalid
		}
		if e.Result == "not-found" && e.Item == "" && e.BaseRevision == "" && e.Link == "" {
			break
		}
		if !idOK(e.Item) || !digestOK(e.BaseRevision) {
			return invalid
		}
		if e.Result == "intent" {
			if !digestOK(e.Link) {
				return invalid
			}
		} else if (e.Result != "conflict" && e.Result != "native-refused") || e.Link != "" {
			return invalid
		}
	case passkeyCreateAction:
		if n <= 1 || !idOK(e.Item) || e.Result != "succeeded" || !digestOK(e.Link) || e.BaseRevision != "" && !digestOK(e.BaseRevision) {
			return invalid
		}
	case passkeyRemoveAction:
		if n <= 1 || !idOK(e.Item) || e.Result != "succeeded" || !digestOK(e.BaseRevision) || e.Link != "" {
			return invalid
		}
	case passkeySignalAction:
		// One replayable single-item event per affected login. The keyed link
		// digest binds the hint and the exact reviewed selectors without
		// publishing any of them.
		if n <= 1 || !idOK(e.Item) || e.Result != "succeeded" || !digestOK(e.BaseRevision) || !digestOK(e.Link) {
			return invalid
		}
	case passkeyTransferInviteAction:
		// Invitation creation is independent of item revisions: the 16-byte
		// invitation ID is the audit item, and the keyed link binds the exact
		// canonical signed invitation without persisting it.
		if n <= 1 || !idOK(e.Item) || e.Result != "succeeded" || e.BaseRevision != "" || !digestOK(e.Link) {
			return invalid
		}
	case passkeyTransferRevokeAction, passkeyTransferConsumeAction:
		// Revocation/consumption names the immutable creation event hash as
		// its base and reuses the creation link. Relational uniqueness and
		// ordering are checked against the authenticated current chain.
		if n <= 1 || !idOK(e.Item) || e.Result != "succeeded" || !digestOK(e.BaseRevision) || !digestOK(e.Link) {
			return invalid
		}
	case v2PurgeAction:
		if e.Result == "not-found" {
			if e.Item != "" || e.BaseRevision != "" || n <= 1 {
				return invalid
			}
			break
		}
		if n <= 1 || !idOK(e.Item) || !digestOK(e.BaseRevision) {
			return invalid
		}
		switch e.Result {
		case "succeeded", "conflict", "not-trashed":
		default:
			return invalid
		}
	case v2EmptyTrashAction, v2CreateVaultAction, v2ListVaultsAction:
		if n <= 1 || e.Item != "" || e.BaseRevision != "" || e.Result != "succeeded" {
			return invalid
		}
	case v2DetailViewAction, v2DetailInspectAction:
		if e.Result == "not-found" {
			if e.Item != "" || e.BaseRevision != "" || n <= 1 {
				return invalid
			}
			break
		}
		if n <= 1 || !idOK(e.Item) || !digestOK(e.BaseRevision) {
			return invalid
		}
		want := "succeeded"
		if e.Action == v2DetailInspectAction {
			want = "intent"
		}
		if e.Result != want && e.Result != "conflict" {
			return invalid
		}
	case "item.edit.v2", "item.edit.favorite", "item.edit.tags", "item.edit.vault", "item.history.restore", "item.attachment.add", "item.attachment.remove":
		if e.Result == "not-found" && e.Item == "" && e.BaseRevision == "" && n > 1 {
			break
		}
		if n <= 1 || !idOK(e.Item) || !digestOK(e.BaseRevision) {
			return invalid
		}
		switch e.Result {
		case "succeeded", "conflict", "trashed":
		default:
			return invalid
		}
	case passkeyGetAction:
		if n <= 1 || !idOK(e.Item) || e.Result != "intent" || !digestOK(e.Link) || !digestOK(e.BaseRevision) {
			return invalid
		}
	case browserNewAction, browserUpdateAction:
		if n <= 1 || !digestOK(e.Link) {
			return invalid
		}
		if e.Action == browserNewAction {
			if e.BaseRevision != "" || e.Result != "succeeded" && e.Result != "browser-refused" || e.Result == "succeeded" && !idOK(e.Item) || e.Result != "succeeded" && e.Item != "" {
				return invalid
			}
		} else if e.Result == "not-found" {
			if e.Item != "" || e.BaseRevision != "" {
				return invalid
			}
		} else if !idOK(e.Item) || !digestOK(e.BaseRevision) || e.Result != "succeeded" && e.Result != "conflict" && e.Result != "browser-refused" {
			return invalid
		}
	case importPlanAction, importAction:
		if n <= 1 || e.Item != "" || e.BaseRevision != "" {
			return invalid
		}
		switch e.Result {
		case "succeeded", "invalid", "unsupported", "limit", "source-error", "duplicate":
		case "source-changed":
			if e.Action != importAction {
				return invalid
			}
		default:
			return invalid
		}
	case matchAction:
		if n <= 1 || e.Item != "" || e.BaseRevision != "" || e.Result != "succeeded" && e.Result != "cross-origin" {
			return invalid
		}
	case exportAction:
		if n <= 1 || e.Result != "intent" || e.Item != "" || e.BaseRevision != "" {
			return invalid
		}
	case inspectionAction:
		if n <= 1 || e.Item != "" || e.BaseRevision != "" {
			return invalid
		}
		switch e.Result {
		case "succeeded", "invalid", "unsupported", "limit", "source-error":
		default:
			return invalid
		}
	case referenceRejectAction:
		if n <= 1 || e.Item != "" || e.BaseRevision != "" {
			return invalid
		}
		switch e.Result {
		case "not-found", "ambiguous", "wrong-type", "stale":
		default:
			return invalid
		}
	case "backup.prepare":
		if n <= 1 || !idOK(e.Link) || e.Item != "" {
			return invalid
		}
	case "vault.restore":
		if n != 1 || !digestOK(e.Link) || e.Item != "" {
			return invalid
		}
	case browserOTPAction, browserFillAction, v2AttachmentReadAction, "item.desktop.show.username", "item.desktop.show.password", "item.desktop.copy.username", "item.desktop.copy.password", "item.desktop.show.notes", "item.desktop.copy.notes", "item.desktop.edit.notes", "item.edit.notes", "item.run.username", "item.run.password", runBundleAction, livePullAction, "item.inject.username", "item.inject.password", "item.trash", "item.untrash", "item.archive", "item.unarchive", "item.edit.url", "item.edit.title", "item.edit.username", "item.edit.password", "item.edit.otp", "item.reveal.username", "item.reveal.password", "item.reveal.notes", referenceRevealAction, referenceOTPAction, "item.regenerate.password", otpDisclosureAction, desktopOTPShowAction, desktopOTPCopyAction:
		if e.Result == "not-found" && e.Item == "" && e.BaseRevision == "" && n > 1 {
			break
		}
		accepted := "succeeded"
		if readValueAction(e.Action) || otpAction(e.Action) {
			accepted = "intent"
		}
		already := e.Action == "item.archive" && e.Result == "already-archived" || e.Action == "item.unarchive" && e.Result == "already-active"
		already = already || e.Action == "item.trash" && e.Result == "already-trashed" || e.Action == "item.untrash" && e.Result == "not-trashed"
		blocked := !trashAction(e.Action) && e.Result == "trashed"
		unconfigured := otpAction(e.Action) && e.Result == "not-configured"
		nativeRefused := (e.Action == "item.regenerate.password" || nativeEditAction(e.Action)) && e.Result == "native-refused"
		browserRefused := (e.Action == browserFillAction || e.Action == browserOTPAction) && e.Result == "browser-refused"
		if n <= 1 || !idOK(e.Item) || !digestOK(e.BaseRevision) || (e.Result != accepted && e.Result != "conflict" && !unconfigured && !already && !blocked && !browserRefused && !nativeRefused) {
			return invalid
		}
	case watchtowerAction:
		if n <= 1 || e.Result != "succeeded" || e.Item != "" || e.BaseRevision != "" {
			return invalid
		}
	case hibpAction:
		if n <= 1 || e.Item != "" || e.BaseRevision != "" || (e.Result != "intent" && e.Result != "succeeded") {
			return invalid
		}
	case "vault.create":
		if n != 1 || e.Item != "" {
			return invalid
		}
	case sshGenerateAction, sshImportAction, "item.add", "item.restore", "item.generate", "item.import":
		if (e.Action == sshGenerateAction || e.Action == sshImportAction || e.Action == "item.add" || e.Action == "item.generate") && e.Result == "native-refused" {
			if n <= 1 || e.Item != "" || e.BaseRevision != "" {
				return invalid
			}
			break
		}
		if n <= 1 || !idOK(e.Item) {
			return invalid
		}
	case "desktop.system.enable":
		if n <= 1 || e.Item != "" || e.BaseRevision != "" || e.Result != "intent" {
			return invalid
		}
	case "desktop.unlock", "desktop.system.unlock", searchAction, "item.list", "item.list.archived", "item.list.trashed", "item.list.all", "audit.list", "audit.archived", "reference.list", healthAction:
		if n <= 1 || e.Item != "" {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}
func sealedJSON(a cipher.AEAD, label []byte, v any) ([]byte, error) {
	p, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	defer clear(p)
	return a.Seal(nil, nil, p, label), nil
}
func readSealed(a cipher.AEAD, label, raw []byte, v any) error {
	if len(raw) < a.Overhead() || len(raw) > 8192 {
		return invalid
	}
	p, e := a.Open(nil, nil, raw, label)
	if e != nil {
		return invalid
	}
	defer clear(p)
	if json.Unmarshal(p, v) != nil {
		return invalid
	}
	return nil
}
func eventLabel(seq []byte) []byte { return append([]byte("locklark/personal/event/v1\x00"), seq...) }

// applyAuditRevision is the single revision-replay switch shared by cold
// history verification, warm tail verification and cache extension.
func applyAuditRevision(ev Event, hash string, revisions map[string]string) error {
	if ev.Action == passkeyCreateAction {
		if ev.BaseRevision != revisions[ev.Item] {
			return invalid
		}
		revisions[ev.Item] = hash
	} else if ev.Action == passkeyTransferItemAction {
		// Imported parent revisions use the same strict CAS shape: the base
		// must equal the current revision and a new parent may only be absent
		// before its first event.
		if ev.BaseRevision != revisions[ev.Item] {
			return invalid
		}
		revisions[ev.Item] = hash
	} else if ((ev.Action == sshGenerateAction || ev.Action == sshImportAction || ev.Action == "item.add" || ev.Action == "item.generate") && ev.Result == "succeeded") || ev.Action == "item.restore" || ev.Action == "item.import" || ev.Action == browserNewAction && ev.Result == "succeeded" {
		if revisions[ev.Item] != "" {
			return invalid
		}
		revisions[ev.Item] = hash
	} else if ev.Action == v2PurgeAction {
		if ev.Result == "not-found" {
			if ev.Item != "" || ev.BaseRevision != "" {
				return invalid
			}
		} else {
			if revisions[ev.Item] != ev.BaseRevision {
				return invalid
			}
			if ev.Result == "succeeded" {
				delete(revisions, ev.Item)
			}
		}
	} else if ev.Action == v2DetailViewAction || ev.Action == v2DetailInspectAction {
		found := revisions[ev.Item] != ""
		if (ev.Result == "not-found") == found || ev.BaseRevision != revisions[ev.Item] {
			return invalid
		}
	} else if ev.Action == sshSignAction || ev.Action == passkeySignalAction || editAction(ev.Action) || ev.Action == browserUpdateAction || readValueAction(ev.Action) || otpAction(ev.Action) {
		found := revisions[ev.Item] != ""
		if (ev.Result == "not-found") == found || ev.BaseRevision != revisions[ev.Item] {
			return invalid
		}
		if ev.Result == "succeeded" {
			revisions[ev.Item] = hash
		}
	}
	return nil
}

func replayAuditEvent(ev Event, count uint64, prev, origin string, pub ed25519.PublicKey, revisions map[string]string) (string, error) {
	if ev.verify(pub, count, prev) != nil {
		return "", invalid
	}
	if count == 1 && ((ev.Action == "vault.restore" && ev.Link != origin) || (ev.Action != "vault.restore" && origin != "")) {
		return "", invalid
	}
	hash := ev.hash()
	if applyAuditRevision(ev, hash, revisions) != nil {
		return "", invalid
	}
	return hash, nil
}

func auditTipAfter(ev Event, s vault.Snapshot, prevOrigin string) auditTip {
	origin := prevOrigin
	if ev.Action == "vault.restore" {
		origin = ev.Link
	}
	return auditTip{ev.Sequence, s.Epoch, ev.hash(), hex.EncodeToString(s.Signature), origin}
}

func history(b *bolt.Bucket, i identity, s vault.Snapshot, want bool, revisions map[string]string) (auditTip, []Event, error) {
	var tip auditTip
	var rows []Event
	a, e := auditCipher(i)
	if e != nil {
		return tip, nil, invalid
	}
	if e = readSealed(a, tipKey, b.Get(tipKey), &tip); e != nil || tip.Count == 0 || tip.Epoch != s.Epoch || tip.Snapshot != hex.EncodeToString(s.Signature) {
		return tip, nil, invalid
	}
	events := b.Bucket(eventsKey)
	if events == nil {
		return tip, nil, invalid
	}
	priv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(priv)
	pub := priv.Public().(ed25519.PublicKey)
	var count uint64
	prev := ""
	e = events.ForEach(func(k, raw []byte) error {
		count++
		if len(k) != 8 || binary.BigEndian.Uint64(k) != count || count > tip.Count {
			return invalid
		}
		var ev Event
		if readSealed(a, eventLabel(k), raw, &ev) != nil {
			return invalid
		}
		next, err := replayAuditEvent(ev, count, prev, tip.Origin, pub, revisions)
		if err != nil {
			return err
		}
		prev = next
		if want {
			rows = append(rows, ev)
		}
		return nil
	})
	if e != nil || count != tip.Count || prev != tip.Last {
		return tip, nil, invalid
	}
	return tip, rows, nil
}
func appendEvent(b *bolt.Bucket, i identity, tip auditTip, s vault.Snapshot, action, item, outcome, base string) (Event, error) {
	return appendLinked(b, i, tip, s, action, item, outcome, base, "")
}

type eventDetails struct {
	generation   *password.Profile
	reportDigest string
}

func appendLinked(b *bolt.Bucket, i identity, tip auditTip, s vault.Snapshot, action, item, outcome, base, link string, details ...eventDetails) (Event, error) {
	var ev Event
	if len(details) > 1 {
		return ev, invalid
	}
	session, e := randomID()
	if e != nil {
		return ev, e
	}
	ev = Event{Link: link, Sequence: tip.Count + 1, UTC: time.Now().UTC().Format(time.RFC3339Nano), Session: session, Actor: "local-owner", Action: action, Item: item, BaseRevision: base, Result: outcome, Previous: tip.Last}
	if len(details) == 1 {
		ev.Generation = details[0].generation
		ev.ReportDigest = details[0].reportDigest
	}
	priv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(priv)
	ev.Signature = ed25519.Sign(priv, ev.proof())
	a, e := auditCipher(i)
	if e != nil {
		return ev, e
	}
	k := binary.BigEndian.AppendUint64(nil, ev.Sequence)
	events := b.Bucket(eventsKey)
	if events == nil || events.Get(k) != nil {
		return ev, invalid
	}
	raw, e := sealedJSON(a, eventLabel(k), ev)
	if e != nil {
		return ev, e
	}
	if e = events.Put(bytes.Clone(k), raw); e != nil {
		return ev, e
	}
	tip = auditTipAfter(ev, s, tip.Origin)
	raw, e = sealedJSON(a, tipKey, tip)
	if e != nil {
		return ev, e
	}
	return ev, b.Put(tipKey, raw)
}
