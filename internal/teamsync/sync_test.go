package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/vault"
)

type syncFixture struct {
	cfg                   *directory.Config
	owner, seq, publisher ed25519.PrivateKey
	keys                  []ed25519.PrivateKey
	ages                  []*age.X25519Identity
	members               []directory.Member
	items                 []vault.Item
	path, root            string
	first                 directory.Receipt
	anchors               *FileAnchorStore
	endpoint              Endpoint
	count                 int
}

func testKey(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func publicKey(k ed25519.PrivateKey) string {
	return hex.EncodeToString(k.Public().(ed25519.PublicKey))
}
func newSyncFixture(t *testing.T, wrap func(http.Handler) http.Handler) *syncFixture {
	t.Helper()
	f := &syncFixture{root: t.TempDir(), owner: testKey(1), seq: testKey(2), publisher: testKey(3), keys: []ed25519.PrivateKey{testKey(10), testKey(11)}, items: []vault.Item{{ID: "login", Kind: "login", Title: "Team", Password: "team-sync-password-canary", Notes: "team-sync-notes-canary\nsecond"}}}
	var e error
	f.cfg, e = directory.NewConfigWithWriterACL(directory.Pins{Team: strings.Repeat("a", 32), Vault: strings.Repeat("b", 32), Owners: []string{publicKey(f.owner)}, Sequencer: publicKey(f.seq), Publisher: publicKey(f.publisher)})
	if e != nil {
		t.Fatal(e)
	}
	var admissions []directory.Admission
	for i, role := range []string{"writer", "reader"} {
		id, e := age.GenerateX25519Identity()
		if e != nil {
			t.Fatal(e)
		}
		f.ages = append(f.ages, id)
		device := directory.Device{ID: fmt.Sprintf("%032x", 20+i), Encryption: id.Recipient().String(), Signing: publicKey(f.keys[i])}
		member := directory.Member{ID: fmt.Sprintf("%032x", 10+i), Role: role, Devices: []directory.Device{device}}
		f.members = append(f.members, member)
		enrollment := directory.Enrollment{Parent: f.cfg.Genesis(), Member: member.ID, Device: device}
		challenge, e := directory.IssueChallenge(f.cfg, f.owner, enrollment)
		if e != nil {
			t.Fatal(e)
		}
		proof, e := directory.AnswerChallenge(f.cfg, enrollment, challenge, id, f.keys[i])
		if e != nil {
			t.Fatal(e)
		}
		admissions = append(admissions, proof)
	}
	p, s, e := directory.Build(f.cfg, f.owner, f.publisher, f.cfg.Genesis(), f.members, f.items, admissions...)
	if e != nil {
		t.Fatal(e)
	}
	f.path = filepath.Join(f.root, "directory.db")
	f.first, e = directory.Create(f.path, f.cfg, f.seq, p, s)
	if e != nil {
		t.Fatal(e)
	}
	f.anchors, e = CreateFileAnchorStore(filepath.Join(f.root, "server.anchor"), f.cfg.Genesis())
	if e != nil {
		t.Fatal(e)
	}
	h, e := NewHandler(f.path, f.cfg, f.seq, f.cfg.Genesis(), f.anchors)
	if e != nil {
		t.Fatal(e)
	}
	if wrap != nil {
		h = wrap(h)
	}
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	f.endpoint = Endpoint{URL: server.URL, Roots: roots}
	return f
}
func (f *syncFixture) anchor(t *testing.T) *FileAnchorStore {
	t.Helper()
	f.count++
	a, e := CreateFileAnchorStore(filepath.Join(f.root, fmt.Sprintf("client-%d.anchor", f.count)), f.cfg.Genesis())
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func (f *syncFixture) client(t *testing.T, index int) *Client {
	t.Helper()
	c, e := NewDeviceClient(f.cfg, f.endpoint, f.members[index].Devices[0], f.keys[index], f.anchor(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}
func (f *syncFixture) ownerClient(t *testing.T) *Client {
	t.Helper()
	c, e := NewOwnerClient(f.cfg, f.endpoint, f.owner, f.anchor(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}
func assertZeroState(t *testing.T, state VerifiedState) {
	t.Helper()
	if state.Checkpoint() != (directory.Checkpoint{}) || !reflect.DeepEqual(state.View(), directory.View{}) || !reflect.DeepEqual(state.History(), directory.History{}) {
		t.Fatal("failed fetch returned nonzero state")
	}
}

func TestHTTPSReadPublishAndConcurrentConflict(t *testing.T) {
	f := newSyncFixture(t, nil)
	writer := f.client(t, 0)
	reader := f.client(t, 1)
	state, e := reader.Fetch(context.Background())
	if e != nil || state.Checkpoint() != f.first.Checkpoint() {
		t.Fatal("authenticated HTTPS read failed", e)
	}
	view := state.View()
	_, items, e := vault.OpenItems(view.Snapshot, f.ages[1], view.SnapshotSigner, view.Receipt.Proposal.Epoch)
	if e != nil || items[0].Notes != f.items[0].Notes {
		t.Fatal("reader did not decrypt verified ciphertext", e)
	}
	// Getter buffers are independent of the retained verified state.
	view.Snapshot.Database[0] ^= 1
	if bytes.Equal(view.Snapshot.Database, state.View().Snapshot.Database) {
		t.Fatal("verified getter lent mutable ciphertext")
	}
	p, s, e := directory.BuildUpdate(f.cfg, f.keys[0], f.first, f.items)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reader.Publish(context.Background(), p, s); !errors.Is(e, ErrDenied) {
		t.Fatal("reader published writer proposal", e)
	}
	other := f.client(t, 0)
	clients := []*Client{writer, other}
	errs := make([]error, 2)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := range clients {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			_, errs[i] = clients[i].Publish(context.Background(), p, s)
		}(i)
	}
	close(start)
	workers.Wait()
	wins, conflicts := 0, 0
	for _, e := range errs {
		if e == nil {
			wins++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected concurrent publish outcome", e)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("CAS had multiple winners")
	}
	state, e = reader.Fetch(context.Background())
	if e != nil || state.Checkpoint().Version != 2 {
		t.Fatal("reader did not observe committed version", e)
	}
}

// Buffer responses while retaining real network deadline control. This permits
// actual TCP lost-response/replay faults without mocking client verification.
type captureWriter struct {
	w      http.ResponseWriter
	header http.Header
	body   bytes.Buffer
	code   int
}

func (w *captureWriter) Header() http.Header         { return w.header }
func (w *captureWriter) WriteHeader(code int)        { w.code = code }
func (w *captureWriter) Write(p []byte) (int, error) { return w.body.Write(p) }
func (w *captureWriter) Unwrap() http.ResponseWriter { return w.w }
func (w *captureWriter) flush() {
	for k, v := range w.header {
		w.w.Header()[k] = v
	}
	if w.code != 0 {
		w.w.WriteHeader(w.code)
	}
	_, _ = w.w.Write(w.body.Bytes())
}

func TestHTTPSReplayTamperTLSAndStrictInput(t *testing.T) {
	var replay atomic.Bool
	var tamper atomic.Bool
	var mu sync.Mutex
	var saved []byte
	f := newSyncFixture(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == ReadPath && replay.Load() {
				mu.Lock()
				body := bytes.Clone(saved)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
				return
			}
			cw := &captureWriter{w: w, header: make(http.Header)}
			next.ServeHTTP(cw, r)
			if r.URL.Path == ReadPath {
				mu.Lock()
				saved = bytes.Clone(cw.body.Bytes())
				mu.Unlock()
				if tamper.Load() {
					var response response
					if json.Unmarshal(cw.body.Bytes(), &response) == nil && response.History != nil {
						response.History.Snapshot.Database[0] ^= 1
						cw.body.Reset()
						cw.body.Write(encode(response))
					}
				}
			}
			cw.flush()
		})
	})
	c := f.client(t, 0)
	if _, e := c.Fetch(context.Background()); e != nil {
		t.Fatal(e)
	}
	replay.Store(true)
	out, e := c.Fetch(context.Background())
	if !errors.Is(e, ErrInvalid) {
		t.Fatal("old signed response matched fresh nonce", e)
	}
	assertZeroState(t, out)
	replay.Store(false)
	tamper.Store(true)
	out, e = c.Fetch(context.Background())
	if !errors.Is(e, ErrInvalid) {
		t.Fatal("tampered snapshot accepted", e)
	}
	assertZeroState(t, out)
	badEndpoint := f.endpoint
	badEndpoint.URL = strings.Replace(badEndpoint.URL, "127.0.0.1", "localhost", 1)
	wrong, e := NewDeviceClient(f.cfg, badEndpoint, f.members[0].Devices[0], f.keys[0], f.anchor(t))
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	out, e = wrong.Fetch(context.Background())
	if !errors.Is(e, ErrTransport) {
		t.Fatal("wrong TLS hostname accepted", e)
	}
	assertZeroState(t, out)
	for _, body := range []string{`{}`, `{"request":{},"request":{}}`, `{"request":{},"unknown":true}`, `{"request":{}} `, `{"request":{}}{}`} {
		r, e := http.NewRequest(http.MethodPost, f.endpoint.URL+ReadPath, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		reply, e := c.http.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, reply.Body)
		reply.Body.Close()
		if reply.StatusCode != 400 {
			t.Fatal("malformed JSON request was accepted")
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		r, _ := http.NewRequest(method, f.endpoint.URL+ReadPath, nil)
		r.Header.Set("Content-Type", "application/json")
		reply, e := c.http.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		reply.Body.Close()
		if reply.StatusCode != 400 || reply.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("unsupported method/CORS accepted")
		}
	}
}

func TestHTTPSLostPublishReconciliationAndServerRollback(t *testing.T) {
	var drop atomic.Int32
	f := newSyncFixture(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == PublishPath && drop.Load() != 0 {
				if drop.Load() == 1 {
					cw := &captureWriter{w: w, header: make(http.Header)}
					next.ServeHTTP(cw, r)
				}
				conn, _, e := http.NewResponseController(w).Hijack()
				if e == nil {
					conn.Close()
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	old, e := os.ReadFile(f.path)
	if e != nil {
		t.Fatal(e)
	}
	c := f.client(t, 0)
	p, s, e := directory.BuildUpdate(f.cfg, f.keys[0], f.first, f.items)
	if e != nil {
		t.Fatal(e)
	}
	drop.Store(2)
	if receipt, e := c.Publish(context.Background(), p, s); !errors.Is(e, ErrUnknown) || receipt.Proposal.Epoch != 0 {
		t.Fatal("lost uncommitted response not unknown", e)
	}
	drop.Store(0)
	status, e := c.Reconcile(context.Background(), p)
	if e != nil || status.State != PublishUnknown {
		t.Fatal("unchanged parent incorrectly proved no commit", e)
	}
	drop.Store(1)
	if _, e = c.Publish(context.Background(), p, s); !errors.Is(e, ErrUnknown) {
		t.Fatal("lost committed response not unknown", e)
	}
	drop.Store(0)
	status, e = c.Reconcile(context.Background(), p)
	if e != nil || status.State != PublishCommitted || status.Receipt.Proposal.Epoch != 2 {
		t.Fatal("lost committed publication failed reconciliation", e)
	}
	if e = os.WriteFile(f.path, old, 0600); e != nil {
		t.Fatal(e)
	}
	fresh := f.client(t, 0)
	out, e := fresh.Fetch(context.Background())
	if !errors.Is(e, ErrInvalid) {
		t.Fatal("server acknowledged rolled-back DB to fresh client", e)
	}
	assertZeroState(t, out)
}

func TestHTTPSOwnerFreezeAndDeviceRevocation(t *testing.T) {
	f := newSyncFixture(t, nil)
	owner := f.ownerClient(t)
	device := f.client(t, 0)
	p, e := directory.Freeze(f.cfg, f.owner, f.first.Checkpoint())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = device.Publish(context.Background(), p, vault.Snapshot{}); !errors.Is(e, ErrDenied) {
		t.Fatal("device envelope relayed owner authority", e)
	}
	receipt, e := owner.Publish(context.Background(), p, vault.Snapshot{})
	if e != nil {
		t.Fatal("owner freeze failed", e)
	}
	state, e := owner.Fetch(context.Background())
	if e != nil || state.Checkpoint() != receipt.Checkpoint() || state.View().SnapshotSigner != nil {
		t.Fatal("owner frozen history unavailable", e)
	}
	out, e := device.Fetch(context.Background())
	if !errors.Is(e, ErrDenied) {
		t.Fatal("revoked/frozen device read allowed", e)
	}
	assertZeroState(t, out)
	status, e := owner.Reconcile(context.Background(), p)
	if e != nil || status.State != PublishCommitted {
		t.Fatal("owner could not reconcile freeze", e)
	}
}
