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
	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"time"
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
	if !editAction(e.Action) && !revealAction(e.Action) && e.Action != otpDisclosureAction && e.Action != referenceRejectAction && e.Action != inspectionAction && e.Action != exportAction && e.Action != matchAction && (e.Result != "succeeded" || e.BaseRevision != "") {
		return invalid
	}
	if e.Action == inspectionAction && e.Result == "succeeded" {
		if !digestOK(e.ReportDigest) {
			return invalid
		}
	} else if e.ReportDigest != "" {
		return invalid
	}
	if e.Action != "backup.prepare" && e.Action != "vault.restore" && e.Link != "" {
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
	case "item.trash", "item.untrash", "item.archive", "item.unarchive", "item.edit.url", "item.edit.title", "item.edit.username", "item.edit.password", "item.edit.otp", "item.reveal.username", "item.reveal.password", "item.regenerate.password", otpDisclosureAction:
		if e.Result == "not-found" && e.Item == "" && e.BaseRevision == "" && n > 1 {
			break
		}
		accepted := "succeeded"
		if revealAction(e.Action) || e.Action == otpDisclosureAction {
			accepted = "intent"
		}
		already := e.Action == "item.archive" && e.Result == "already-archived" || e.Action == "item.unarchive" && e.Result == "already-active"
		already = already || e.Action == "item.trash" && e.Result == "already-trashed" || e.Action == "item.untrash" && e.Result == "not-trashed"
		blocked := !trashAction(e.Action) && e.Result == "trashed"
		unconfigured := e.Action == otpDisclosureAction && e.Result == "not-configured"
		if n <= 1 || !idOK(e.Item) || !digestOK(e.BaseRevision) || (e.Result != accepted && e.Result != "conflict" && !unconfigured && !already && !blocked) {
			return invalid
		}
	case "vault.create":
		if n != 1 || e.Item != "" {
			return invalid
		}
	case "item.add", "item.restore", "item.generate":
		if n <= 1 || !idOK(e.Item) {
			return invalid
		}
	case "item.list", "item.list.archived", "item.list.trashed", "item.list.all", "audit.list", "audit.archived", "reference.list":
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
		if readSealed(a, eventLabel(k), raw, &ev) != nil || ev.verify(pub, count, prev) != nil {
			return invalid
		}
		if count == 1 && ((ev.Action == "vault.restore" && ev.Link != tip.Origin) || (ev.Action != "vault.restore" && tip.Origin != "")) {
			return invalid
		}
		prev = ev.hash()
		if ev.Action == "item.add" || ev.Action == "item.restore" || ev.Action == "item.generate" {
			if revisions[ev.Item] != "" {
				return invalid
			}
			revisions[ev.Item] = prev
		} else if editAction(ev.Action) || revealAction(ev.Action) || ev.Action == otpDisclosureAction {
			found := revisions[ev.Item] != ""
			if (ev.Result == "not-found") == found || ev.BaseRevision != revisions[ev.Item] {
				return invalid
			}
			if ev.Result == "succeeded" {
				revisions[ev.Item] = prev
			}
		}
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
	origin := tip.Origin
	if action == "vault.restore" {
		origin = link
	}
	tip = auditTip{ev.Sequence, s.Epoch, ev.hash(), hex.EncodeToString(s.Signature), origin}
	raw, e = sealedJSON(a, tipKey, tip)
	if e != nil {
		return ev, e
	}
	return ev, b.Put(tipKey, raw)
}
