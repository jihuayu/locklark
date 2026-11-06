package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

const (
	sshGenerateAction = "item.ssh.generate"
	sshImportAction   = "item.ssh.import"
	sshSignAction     = "item.ssh.sign"
	MaxSSHImport      = 16 << 10
	MaxSSHSignData    = 60 << 10
	SSHSignLifetime   = 30 * time.Second
)

var ErrSSHKey = errors.New("SSH key unavailable or unsupported")
var ErrSSHSign = errors.New("SSH signature refused, cancelled or expired")

type SSHKeyTarget struct{ ID, Revision string }
type SSHKeyRow struct{ ID, Revision, Title, State, PublicKey, Fingerprint string }
type SSHSignRequest struct {
	RequestID, ConnectionID, Peer string
	PublicKey, Data               []byte
	Flags                         uint32
}
type SSHSignView struct {
	Key                                      SSHKeyRow
	RequestID, ConnectionID, Peer, Algorithm string
	PayloadDigest                            string
	Flags                                    uint32
	DataBytes                                int
	Deadline                                 time.Time
}
type SSHSignIntent struct{ inner *sshSignState }
type SSHSignatureOutput struct{ inner *sshSignState }
type sshSignState struct {
	mu        sync.Mutex
	status    atomic.Uint32 // pending, output-granted, cancelled
	consuming atomic.Bool
	owner     *Session
	request   SSHSignRequest
	view      SSHSignView
	until     time.Time
	gate      *MutationGate
	timer     *time.Timer
	approving bool
	signature []byte
}

func (SSHSignRequest) String() string                   { return "[SSH signing request]" }
func (SSHSignRequest) GoString() string                 { return "[SSH signing request]" }
func (SSHSignRequest) MarshalJSON() ([]byte, error)     { return nil, ErrSSHSign }
func (SSHSignIntent) String() string                    { return "[SSH signing intent]" }
func (SSHSignIntent) GoString() string                  { return "[SSH signing intent]" }
func (SSHSignIntent) MarshalJSON() ([]byte, error)      { return nil, ErrSSHSign }
func (SSHSignatureOutput) String() string               { return "[SSH signature output]" }
func (SSHSignatureOutput) GoString() string             { return "[SSH signature output]" }
func (SSHSignatureOutput) MarshalJSON() ([]byte, error) { return nil, ErrSSHSign }

func validSSHRequest(r SSHSignRequest) bool {
	if !idOK(r.RequestID) || !idOK(r.ConnectionID) || r.Flags != 0 || len(r.Data) == 0 || len(r.Data) > MaxSSHSignData || len(r.Peer) == 0 || len(r.Peer) > 1024 || !utf8.ValidString(r.Peer) || strings.ContainsRune(r.Peer, 0) {
		return false
	}
	p, e := ssh.ParsePublicKey(r.PublicKey)
	return e == nil && p.Type() == ssh.KeyAlgoED25519 && bytes.Equal(p.Marshal(), r.PublicKey)
}

func sshRow(it vault.Item, revision string) (SSHKeyRow, error) {
	p, e := ssh.ParsePublicKey(it.SSHPublicKey)
	if e != nil || p.Type() != ssh.KeyAlgoED25519 || !idOK(it.ID) || !digestOK(revision) {
		return SSHKeyRow{}, ErrSSHKey
	}
	state := it.State
	if state == "" {
		state = "active"
	}
	return SSHKeyRow{it.ID, revision, it.Title, state, strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(p)), "\n"), ssh.FingerprintSHA256(p)}, nil
}

// ListSSHKeys performs complete read-only authentication on a worker. It neither
// touches idle time nor exposes seeds. Only active keys enter the agent cache.
func (s *Session) ListSSHKeys() (rows []SSHKeyRow, err error) {
	return s.ListSSHKeysState("active")
}

// ListSSHKeysState is native management metadata; network clients use only the
// active-only wrapper above. Cached approvals never include inactive keys.
func (s *Session) ListSSHKeysState(state string) (rows []SSHKeyRow, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidStateFilter(state) {
		return nil, ErrSSHKey
	}
	if err = s.active(false); err != nil {
		return nil, err
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return nil, ErrSSHKey
	}
	err = db.View(func(tx *bolt.Tx) error {
		a, e := authenticateState(tx, "", nil, "desktop.ssh.list", s)
		if e != nil {
			return e
		}
		defer a.clear()
		rows = make([]SSHKeyRow, 0)
		for _, it := range a.items {
			if it.Kind != "ssh-key" || state != "all" && !(state == "active" && it.State == "" || state == it.State) {
				continue
			}
			r, e := sshRow(it, a.revisions[it.ID])
			if e != nil {
				return e
			}
			rows = append(rows, r)
		}
		return nil
	})
	err = s.finishNativeRead(err, db.Close())
	if err != nil {
		return nil, err
	}
	if err = s.active(false); err != nil {
		return nil, err
	}
	s.sshRows = make(map[string]SSHKeyRow, len(rows))
	for _, r := range rows {
		if r.State == "active" {
			s.sshRows[r.ID] = r
		}
	}
	return rows, nil
}

// Caller holds Session.mu. Also used by the existing exact-revision state API.
func (s *Session) cancelSSHTarget(id string) {
	delete(s.sshRows, id)
	s.sshPending.Range(func(key, _ any) bool {
		x := key.(*sshSignState)
		if x.view.Key.ID == id {
			(&SSHSignIntent{x}).Cancel()
		}
		return true
	})
}
func (s *Session) SetSSHKeyState(id, revision, action string, g *MutationGate) (string, error) {
	if !idOK(id) || !digestOK(revision) || !(lifecycleAction(action) || trashAction(action)) {
		g.Cancel()
		s.ReleaseMutation(g)
		return "", ErrSSHKey
	}
	r, e := s.nativeMutation(action, vault.Item{}, &Edit{ID: id, Revision: revision}, commandOption{sshState: true}, g)
	return r.revision, e
}

// PrepareSSHSign is memory-only. The target must come from ListSSHKeys (or this
// session's creation receipt). The cached metadata is not authorization: approval
// reauthenticates the current exact revision in the durable intent transaction.
func (s *Session) PrepareSSHSign(target SSHKeyTarget, r SSHSignRequest, until time.Time) (*SSHSignIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil || !idOK(target.ID) || !digestOK(target.Revision) || !validSSHRequest(r) {
		return nil, ErrSSHSign
	}
	now := time.Now()
	if !now.Before(until) || until.Sub(now) > SSHSignLifetime {
		return nil, ErrSSHSign
	}
	row, ok := s.sshRows[target.ID]
	if !ok || row.Revision != target.Revision || row.State != "active" {
		return nil, ErrSSHSign
	}
	p, _, _, _, e := ssh.ParseAuthorizedKey([]byte(row.PublicKey))
	if e != nil || !bytes.Equal(p.Marshal(), r.PublicKey) {
		return nil, ErrSSHSign
	}
	count := 0
	s.sshPending.Range(func(_, _ any) bool { count++; return true })
	if count >= 8 {
		return nil, ErrSSHSign
	}
	r.Data = bytes.Clone(r.Data)
	r.PublicKey = bytes.Clone(r.PublicKey)
	x := &sshSignState{owner: s, request: r, until: until, gate: NewMutationGate(until), view: SSHSignView{Key: row, RequestID: r.RequestID, ConnectionID: r.ConnectionID, Peer: r.Peer, Algorithm: ssh.KeyAlgoED25519, DataBytes: len(r.Data), Deadline: until}}
	payloadDigest := sha256.Sum256(r.Data)
	x.view.PayloadDigest = hex.EncodeToString(payloadDigest[:])
	x.view.Flags = r.Flags
	x.mu.Lock()
	s.saveMu.Lock()
	if s.lockRequested.Load() {
		s.saveMu.Unlock()
		x.clearLocked()
		x.mu.Unlock()
		return nil, ErrSSHSign
	}
	s.sshPending.Store(x, true)
	x.timer = time.AfterFunc(time.Until(until), func() { (&SSHSignIntent{x}).Cancel() })
	s.saveMu.Unlock()
	x.mu.Unlock()
	return &SSHSignIntent{x}, nil
}
func (i *SSHSignIntent) View() SSHSignView {
	if i == nil || i.inner == nil {
		return SSHSignView{}
	}
	x := i.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.view
}
func (x *sshSignState) clearLocked() {
	clear(x.request.Data)
	clear(x.request.PublicKey)
	clear(x.signature)
	x.request.Data = nil
	x.request.PublicKey = nil
	x.signature = nil
}
func (x *sshSignState) clear() { x.mu.Lock(); defer x.mu.Unlock(); x.clearLocked() }

// Cancel never waits for disk, signing, UI or a socket. A short holder cleanup
// deferred by a concurrent worker remains registered until its buffers are clear.
func (i *SSHSignIntent) Cancel() bool {
	if i == nil || i.inner == nil {
		return false
	}
	x := i.inner
	if !x.status.CompareAndSwap(0, 2) {
		return false
	}
	x.gate.Cancel()
	if x.mu.TryLock() {
		if x.timer != nil {
			x.timer.Stop()
		}
		x.clearLocked()
		x.mu.Unlock()
		x.owner.sshPending.Delete(x)
	} else {
		go func() {
			x.mu.Lock()
			if x.timer != nil {
				x.timer.Stop()
			}
			x.clearLocked()
			x.mu.Unlock()
			x.owner.sshPending.Delete(x)
		}()
	}
	return true
}
func (s *Session) DiscardSSHSign(i *SSHSignIntent) {
	if i != nil && i.inner != nil && i.inner.owner == s {
		i.Cancel()
	}
}
func (s *Session) DiscardSSHSignature(o *SSHSignatureOutput) {
	if o != nil && o.inner != nil && o.inner.owner == s {
		(&SSHSignIntent{o.inner}).Cancel()
	}
}

// ApproveSSHSign is the explicit native action. No seed, private-key object or
// signer escapes this function. Failed commit/close never reaches signing.
func (s *Session) ApproveSSHSign(i *SSHSignIntent) (*SSHSignatureOutput, error) {
	return s.approveSSHSignWith(i, nil)
}
func (s *Session) approveSSHSignWith(i *SSHSignIntent, run func(commandOption) (result, error)) (*SSHSignatureOutput, error) {
	if i == nil || i.inner == nil || i.inner.owner != s {
		return nil, ErrSSHSign
	}
	x := i.inner
	x.mu.Lock()
	if x.status.Load() != 0 || x.approving || !time.Now().Before(x.until) {
		expired := !time.Now().Before(x.until)
		x.mu.Unlock()
		if expired {
			i.Cancel()
		}
		return nil, ErrSSHSign
	}
	x.approving = true
	r := x.request
	r.Data = bytes.Clone(r.Data)
	r.PublicKey = bytes.Clone(r.PublicKey)
	target := x.view.Key
	x.mu.Unlock()
	defer clear(r.Data)
	defer clear(r.PublicKey)
	if e := s.RegisterMutation(x.gate); e != nil {
		i.Cancel()
		return nil, ErrSSHSign
	}
	result, e := s.nativeMutationWithTouch(sshSignAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision}, commandOption{ssh: &sshStoreRequest{sign: &r, target: SSHKeyTarget{target.ID, target.Revision}}}, x.gate, run, false)
	defer clear(result.sshSeed)
	if e != nil {
		i.Cancel()
		return nil, e
	}
	if x.status.Load() != 0 || !time.Now().Before(x.until) || s.lockRequested.Load() || len(result.sshSeed) != ed25519.SeedSize {
		i.Cancel()
		return nil, ErrSSHSign
	}
	private := ed25519.NewKeyFromSeed(result.sshSeed)
	defer clear(private)
	signature := ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: ed25519.Sign(private, r.Data)})
	defer clear(signature)
	x.mu.Lock()
	if x.status.Load() != 0 || !time.Now().Before(x.until) || s.lockRequested.Load() {
		x.mu.Unlock()
		i.Cancel()
		return nil, ErrSSHSign
	}
	x.signature = bytes.Clone(signature)
	x.mu.Unlock()
	return &SSHSignatureOutput{x}, nil
}

// ConsumeSSHSignature grants exactly one bounded output. Acquire the transport
// writer slot first; callers own and must clear returned bytes, then write without
// holding a Session lock. A grant before lock cannot be retracted afterwards.
func (s *Session) ConsumeSSHSignature(o *SSHSignatureOutput) ([]byte, error) {
	if o == nil || o.inner == nil || o.inner.owner != s {
		return nil, ErrSSHSign
	}
	x := o.inner
	if !x.consuming.CompareAndSwap(false, true) {
		return nil, ErrSSHSign
	}
	defer func() {
		if x.status.Load() != 1 {
			(&SSHSignIntent{x}).Cancel()
		}
	}()
	if !s.mu.TryLock() {
		(&SSHSignIntent{x}).Cancel()
		return nil, ErrSSHSign
	}
	defer s.mu.Unlock()
	if s.active(false) != nil {
		return nil, ErrSSHSign
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	s.saveMu.Lock()
	valid := !s.lockRequested.Load() && len(s.material) > 0 && time.Since(s.last) < s.idle && time.Now().Before(x.until) && len(x.signature) > 0
	if !valid || !x.status.CompareAndSwap(0, 1) {
		s.saveMu.Unlock()
		return nil, ErrSSHSign
	}
	output := bytes.Clone(x.signature)
	s.saveMu.Unlock()
	if x.timer != nil {
		x.timer.Stop()
	}
	x.clearLocked()
	s.sshPending.Delete(x)
	return output, nil
}

func (s *Session) GenerateSSHKey(title string, g *MutationGate) (SSHKeyRow, error) {
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, e := rand.Read(seed); e != nil {
		g.Cancel()
		s.ReleaseMutation(g)
		return SSHKeyRow{}, ErrSSHKey
	}
	return s.saveSSHKey(title, seed, sshGenerateAction, g)
}

// ImportSSHKey consumes its input. Encrypted OpenSSH files are rejected by
// header inspection before invoking any parser capable of a password KDF.
func (s *Session) ImportSSHKey(title string, encoded []byte, g *MutationGate) (SSHKeyRow, error) {
	defer clear(encoded)
	seed, e := parseSSHSeed(encoded)
	if e != nil {
		g.Cancel()
		s.ReleaseMutation(g)
		return SSHKeyRow{}, ErrSSHKey
	}
	defer clear(seed)
	return s.saveSSHKey(title, seed, sshImportAction, g)
}
func (s *Session) saveSSHKey(title string, seed []byte, action string, g *MutationGate) (SSHKeyRow, error) {
	if len(seed) != 32 || len(title) > 1024 || strings.TrimSpace(title) == "" || !utf8.ValidString(title) {
		g.Cancel()
		s.ReleaseMutation(g)
		return SSHKeyRow{}, ErrSSHKey
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, e := ssh.NewPublicKey(private.Public())
	if e != nil {
		g.Cancel()
		s.ReleaseMutation(g)
		return SSHKeyRow{}, ErrSSHKey
	}
	item := vault.Item{Kind: "ssh-key", Title: title, SSHSeed: bytes.Clone(seed), SSHPublicKey: public.Marshal()}
	defer clear(item.SSHSeed)
	r, e := s.nativeMutation(action, item, nil, commandOption{ssh: &sshStoreRequest{}}, g)
	if e != nil {
		return SSHKeyRow{}, e
	}
	item.ID = r.id
	row, e := sshRow(item, r.revision)
	if e == nil {
		s.mu.Lock()
		if !s.lockRequested.Load() {
			if s.sshRows == nil {
				s.sshRows = make(map[string]SSHKeyRow)
			}
			s.sshRows[row.ID] = row
		}
		s.mu.Unlock()
	}
	return row, e
}
func parseSSHSeed(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxSSHImport {
		return nil, ErrSSHKey
	}
	if !bytes.HasPrefix(bytes.TrimSpace(encoded), []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		return nil, ErrSSHKey
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrSSHKey
	}
	defer clear(block.Bytes)
	b := block.Bytes
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return nil, ErrSSHKey
	}
	b = b[len(magic):]
	read := func() ([]byte, bool) {
		if len(b) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint64(n) > uint64(len(b)) {
			return nil, false
		}
		v := b[:n]
		b = b[n:]
		return v, true
	}
	cipher, ok := read()
	if !ok || string(cipher) != "none" {
		return nil, ErrSSHKey
	}
	kdf, ok := read()
	if !ok || string(kdf) != "none" {
		return nil, ErrSSHKey
	}
	options, ok := read()
	if !ok || len(options) != 0 {
		return nil, ErrSSHKey
	}
	if len(b) < 4 || binary.BigEndian.Uint32(b) != 1 {
		return nil, ErrSSHKey
	}
	b = b[4:]
	publicWire, ok := read()
	if !ok || len(publicWire) != 51 {
		return nil, ErrSSHKey
	}
	public, e := ssh.ParsePublicKey(publicWire)
	if e != nil || public.Type() != ssh.KeyAlgoED25519 || !bytes.Equal(public.Marshal(), publicWire) {
		return nil, ErrSSHKey
	}
	privateBlock, ok := read()
	if !ok || len(b) != 0 {
		return nil, ErrSSHKey
	}
	var header struct {
		Check1, Check2 uint32
		KeyType        string
		Rest           []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(privateBlock, &header) != nil || header.Check1 != header.Check2 || header.KeyType != ssh.KeyAlgoED25519 {
		return nil, ErrSSHKey
	}
	var parts struct {
		Public, Private []byte
		Comment         string
		Padding         []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(header.Rest, &parts) != nil || len(parts.Public) != ed25519.PublicKeySize || len(parts.Private) != ed25519.PrivateKeySize {
		return nil, ErrSSHKey
	}
	defer clear(parts.Private)
	key, e := ssh.ParseRawPrivateKey(encoded)
	if e != nil {
		return nil, ErrSSHKey
	}
	private, ok := key.(*ed25519.PrivateKey)
	if !ok || len(*private) != ed25519.PrivateKeySize {
		return nil, ErrSSHKey
	}
	defer clear(*private)
	canonical := ed25519.NewKeyFromSeed((*private)[:ed25519.SeedSize])
	defer clear(canonical)
	if !bytes.Equal(canonical, *private) {
		return nil, ErrSSHKey
	}
	derived, e := ssh.NewPublicKey(canonical.Public())
	if e != nil || !bytes.Equal(derived.Marshal(), publicWire) || !bytes.Equal(parts.Public, canonical[ed25519.SeedSize:]) {
		return nil, ErrSSHKey
	}
	return bytes.Clone((*private)[:ed25519.SeedSize]), nil
}

type sshStoreRequest struct {
	sign   *SSHSignRequest
	target SSHKeyTarget
}

func (r *sshStoreRequest) binding(key []byte) (string, error) {
	if r == nil || r.sign == nil || !validSSHRequest(*r.sign) {
		return "", ErrSSHSign
	}
	derived, e := hkdf.Key(sha256.New, key, nil, "locklark/personal/ssh-sign/key/v1", 32)
	if e != nil {
		return "", ErrSSHSign
	}
	defer clear(derived)
	q := r.sign
	raw, e := json.Marshal(struct {
		Profile, RequestID, ConnectionID, Peer string
		Target                                 SSHKeyTarget
		PublicKey, Data                        []byte
		Flags                                  uint32
	}{"ed25519-sign-only-v1", q.RequestID, q.ConnectionID, q.Peer, r.target, q.PublicKey, q.Data, q.Flags})
	if e != nil {
		return "", ErrSSHSign
	}
	defer clear(raw)
	m := hmac.New(sha256.New, derived)
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}
