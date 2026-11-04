// Package preview builds a fixed, disposable two-device scenario. It has no
// network paths, accepts no real vault, and grants no access to secret fields.
package preview

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/vault"
)

// Public fixture password. Never use this profile or on-disk fixture secret for a real vault.
const fixturePassword = "locklark synthetic preview only"
const systemSession = "locklark-bootstrap"

var sessionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$`)
var errInput = errors.New("use a new output directory, a non-reserved session ID (1-96 ASCII identifier characters) and a nonempty synthetic reason (max 240 characters, no control characters)")

type Event struct {
	Sequence int    `json:"sequence"`
	Time     string `json:"time"`
	Session  string `json:"session"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
	Result   string `json:"result"`
}
type payload struct {
	pin     string
	Proofs  [][]byte `json:"audit_proofs,omitempty"`
	Archive []byte   `json:"archive"`
	Events  []Event  `json:"events"`
}

func (p *payload) record(session, actor, action, reason, result string) {
	p.Events = append(p.Events, Event{len(p.Events) + 1, time.Now().UTC().Format(time.RFC3339Nano), session, actor, action, reason, result})
}

type manifest struct {
	Epoch     uint64 `json:"epoch"`
	Signature []byte `json:"signature"`
}

func write(dir, name string, b []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func writeJSON(dir, name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return write(dir, name, b)
}
func read(dir, name string, limit int64) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// With an adversarial directory the entry can change between stat and open.
	f, err := root.OpenFile(name, os.O_RDONLY|readFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("invalid fixture file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("invalid fixture size")
	}
	return b, nil
}
func random(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err }
func saveDevice(dir string, id *age.X25519Identity, pub ed25519.PublicKey, secret, accountID []byte) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	slot, err := account.Wrap(fixturePassword, secret, accountID, []byte(id.String()))
	if err != nil {
		return err
	}
	if err = writeJSON(dir, "device.slot", slot); err != nil {
		return err
	}
	if err = write(dir, "fixture.secret", secret); err != nil {
		return err
	}
	return write(dir, "authority.pub", pub)
}
func saveEpoch(dir string, p payload, n uint64, ids []*age.X25519Recipient, signer ed25519.PrivateKey) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer clear(data)
	s, err := vault.Seal(data, n, ids, signer)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err = write(dir, "vault.kdbx", s.Database); err != nil {
		return err
	}
	if err = write(dir, "keys.age", s.Envelope); err != nil {
		return err
	}
	return writeJSON(dir, "manifest.json", manifest{n, s.Signature})
}

func Create(out, session, reason string) error {
	if strings.TrimSpace(out) == "" || !validSession(session) || session == systemSession || !validReason(reason) {
		return errInput
	}
	// Reserve the name exclusively. No overwrite, recursive delete, or replacement
	// on failure. A partial fixture after an I/O failure must be discarded by its owner.
	if err := os.Mkdir(out, 0700); err != nil {
		return err
	}
	clients := filepath.Join(out, "clients")
	share := filepath.Join(out, "share")
	if err := os.Mkdir(clients, 0700); err != nil {
		return err
	}
	if err := os.Mkdir(share, 0700); err != nil {
		return err
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(signer)
	secret, err := random(16)
	if err != nil {
		return err
	}
	defer clear(secret)
	accountID, err := random(16)
	if err != nil {
		return err
	}
	a, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	if err = saveDevice(filepath.Join(clients, "A"), a, pub, secret, accountID); err != nil {
		return err
	}
	if err = saveDevice(filepath.Join(clients, "B"), b, pub, secret, accountID); err != nil {
		return err
	}
	if err = setupInbox(out, secret, accountID); err != nil {
		return err
	}

	auditPub, auditKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(auditKey)
	for _, name := range []string{"A", "B"} {
		if err := write(filepath.Join(clients, name), "audit.pub", auditPub); err != nil {
			return err
		}
	}
	witnessDir := filepath.Join(out, "witness")
	if err := os.Mkdir(witnessDir, 0700); err != nil {
		return err
	}
	saveWitness := func(p payload, name string) error {
		cp, err := makeCheckpoint(p, auditKey)
		if err != nil {
			return err
		}
		return writeJSON(witnessDir, name, cp)
	}
	archive, err := fixtureArchive()
	if err != nil {
		return err
	}
	if _, err = summarize(archive, 1); err != nil {
		return err
	}
	p := payload{Archive: archive}
	p.signedRecord(auditKey, systemSession, "owner", "fixture.import", "load bundled synthetic archive", "imported")
	if err = saveEpoch(filepath.Join(share, "epoch-1"), p, 1, []*age.X25519Recipient{a.Recipient(), b.Recipient()}, signer); err != nil {
		return err
	}
	p.signedRecord(auditKey, systemSession, "owner", "device.remove", "exclude fixture device A", "excluded")
	// All demo requests to disclose a raw value are refused. No field is ever resolved.
	p.signedRecord(auditKey, session, "fixture-agent", "field.read", strings.TrimSpace(reason), "denied")
	if err = saveEpoch(filepath.Join(share, "epoch-2"), p, 2, []*age.X25519Recipient{b.Recipient()}, signer); err != nil {
		return err
	}
	if err = saveWitness(p, "epoch-2.json"); err != nil {
		return err
	}
	p, err = readPayload(filepath.Join(share, "epoch-2"), filepath.Join(clients, "B"), 2)
	if err != nil {
		return err
	}
	p.Archive, err = editedFixture(p.Archive)
	if err != nil {
		return err
	}
	p.signedRecord(auditKey, systemSession, "owner", "fixture.edit", "rename login and rotate synthetic TOTP", "edited")
	if err = saveEpoch(filepath.Join(share, "epoch-3"), p, 3, []*age.X25519Recipient{b.Recipient()}, signer); err != nil {
		return err
	}
	return saveWitness(p, "epoch-3.json")
}

type encryptedSnapshot struct {
	snapshot  vault.Snapshot
	authority ed25519.PublicKey
}

func (c encryptedSnapshot) pin() string { return hex.EncodeToString(c.snapshot.Signature) }
func readEncrypted(bundle, device string, expected uint64) (encryptedSnapshot, error) {
	var p encryptedSnapshot
	mdata, err := read(bundle, "manifest.json", 2048)
	if err != nil {
		return p, err
	}
	var m manifest
	if err = json.Unmarshal(mdata, &m); err != nil || m.Epoch != expected || expected == 0 {
		return p, vault.ErrSnapshot
	}
	pub, err := read(device, "authority.pub", ed25519.PublicKeySize)
	if err != nil {
		return p, err
	}
	s := vault.Snapshot{Epoch: m.Epoch, Signature: m.Signature}
	if s.Database, err = read(bundle, "vault.kdbx", 8<<20); err != nil {
		return p, err
	}
	if s.Envelope, err = read(bundle, "keys.age", 128<<10); err != nil {
		return p, err
	}
	if err = vault.VerifySnapshot(s, pub, expected); err != nil {
		return p, err
	}
	return encryptedSnapshot{s, pub}, nil
}
func readPayload(bundle, device string, expected uint64) (payload, error) {
	c, err := readEncrypted(bundle, device, expected)
	if err != nil {
		return payload{}, err
	}
	return c.unlock(device)
}
func (c encryptedSnapshot) unlock(device string) (payload, error) {
	var p payload
	slotData, err := read(device, "device.slot", 4096)
	if err != nil {
		return p, err
	}
	secret, err := read(device, "fixture.secret", 16)
	if err != nil {
		return p, err
	}
	defer clear(secret)
	var slot account.Slot
	if json.Unmarshal(slotData, &slot) != nil {
		return p, errors.New("invalid local fixture slot")
	}
	raw, err := account.Unwrap(fixturePassword, secret, slot)
	if err != nil {
		return p, err
	}
	defer clear(raw)
	id, err := age.ParseX25519Identity(string(raw))
	if err != nil {
		return p, errors.New("invalid local fixture identity")
	}
	plain, err := vault.Open(c.snapshot, id, c.authority, c.snapshot.Epoch)
	if err != nil {
		return p, fmt.Errorf("cannot unlock this snapshot with the supplied fixture device: %w", err)
	}
	defer clear(plain)
	if json.Unmarshal(plain, &p) != nil {
		return payload{}, errors.New("invalid fixture payload")
	}
	if err = verifyLocalStream(p, device); err != nil {
		return payload{}, err
	}
	p.pin = c.pin()
	return p, nil
}
func Inspect(bundle, device string, expected uint64) (Summary, error) {
	p, err := readPayload(bundle, device, expected)
	if err != nil {
		return Summary{}, err
	}
	return summarize(p.Archive, expected)
}
func Audit(bundle, device string, expected uint64, session string) ([]Event, error) {
	p, err := auditPayload(bundle, device, expected, session)
	if err != nil {
		return nil, err
	}
	return filteredEvents(p, session), nil
}
func auditPayload(bundle, device string, expected uint64, session string) (payload, error) {
	if !validSession(session) {
		return payload{}, errInput
	}
	return readPayload(bundle, device, expected)
}
func filteredEvents(p payload, session string) []Event {
	found := []Event{}
	for _, e := range p.Events {
		if e.Session == session {
			found = append(found, displayedEvent(e))
		}
	}
	return found
}

type WitnessedRow struct {
	Event
	Witnessed bool `json:"witnessed"`
}
type WitnessedQuery struct {
	AuditReport
	Rows []WitnessedRow `json:"rows"`
}

func AuditWithCheckpoint(bundle, device string, expected uint64, session, path string) (WitnessedQuery, error) {
	p, err := auditPayload(bundle, device, expected, session)
	if err != nil {
		return WitnessedQuery{}, err
	}
	report, err := verifyWitness(p, device, path)
	if err != nil {
		return WitnessedQuery{}, err
	}
	q := WitnessedQuery{AuditReport: report, Rows: []WitnessedRow{}}
	for _, e := range filteredEvents(p, session) {
		q.Rows = append(q.Rows, WitnessedRow{e, e.Sequence <= report.Witnessed})
	}
	return q, nil
}
