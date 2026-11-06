package teamsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	bolt "go.etcd.io/bbolt"
)

func lifecycleFixture(t *testing.T) (*syncFixture, *server) {
	t.Helper()
	var managed *server
	f := newSyncFixture(t, func(h http.Handler) http.Handler { managed = h.(*server); return h })
	t.Cleanup(managed.Close)
	return f, managed
}

func lifecycleRequest(f *syncFixture, p *publication) *http.Request {
	action, path := "read", ReadPath
	if p != nil {
		action, path = "publish", PublishPath
	}
	q := request{Publication: p, Proof: requestProof{Protocol: protocol, Scope: f.cfg.Genesis().Scope, Action: action,
		Kind: "owner", ID: publicKey(f.owner), Nonce: strings.Repeat("c", 64), Anchor: f.first.Checkpoint(), BodyDigest: digest("payload", p)}}
	q.Proof.Signature = ed25519.Sign(f.owner, q.Proof.signingBytes())
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encode(q)))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Content-Type", "application/json")
	return r
}

type lifecycleWriter struct {
	header http.Header
	used   atomic.Int32
	wrote  atomic.Int32
	body   bytes.Buffer // Read only after ServeHTTP returns.
	block  chan struct{}
	ready  chan struct{}
}

func newLifecycleWriter() *lifecycleWriter     { return &lifecycleWriter{header: make(http.Header)} }
func (w *lifecycleWriter) Header() http.Header { w.used.Add(1); return w.header }
func (w *lifecycleWriter) WriteHeader(int)     { w.used.Add(1) }
func (w *lifecycleWriter) Write(raw []byte) (int, error) {
	if w.ready != nil {
		close(w.ready)
		<-w.block
	}
	w.wrote.Add(1)
	return w.body.Write(raw)
}
func (*lifecycleWriter) SetReadDeadline(time.Time) error  { return nil }
func (*lifecycleWriter) SetWriteDeadline(time.Time) error { return nil }

func lifecycleWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("owned lifecycle worker did not reach its barrier")
	}
}

func promptClose(t *testing.T, s *server) {
	t.Helper()
	s.keyMu.Lock()
	retained := s.key
	s.keyMu.Unlock()
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close waited for storage, network or an owned worker")
	}
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if !s.closed.Load() || len(s.key) != 0 || s.ctx.Err() == nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("Close did not invalidate and clear retained authority")
	}
}

func TestManagedHandlerCloseDuringBlockedDirectoryRead(t *testing.T) {
	f, s := lifecycleFixture(t)
	db, err := bolt.Open(f.path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal("cannot hold owned directory lock")
	}
	defer db.Close()
	entered := make(chan struct{})
	var signed atomic.Int32
	s.hooks = &serverLifecycleHooks{beforeRead: func() { close(entered) }, afterSign: func() { signed.Add(1) }}
	w, done := newLifecycleWriter(), make(chan struct{})
	go func() { s.ServeHTTP(w, lifecycleRequest(f, nil)); close(done) }()
	lifecycleWait(t, entered)
	select {
	case <-done:
		t.Fatal("directory read did not block on the owned DB lock")
	case <-time.After(30 * time.Millisecond):
	}
	promptClose(t, s)
	select {
	case <-done:
		t.Fatal("blocked directory read unexpectedly finished before DB release")
	default:
	}
	if err := db.Close(); err != nil {
		t.Fatal("cannot release owned directory lock")
	}
	lifecycleWait(t, done)
	if signed.Load() != 0 || w.used.Load() != 0 || w.wrote.Load() != 0 {
		t.Fatal("worker signed or granted output after Close won")
	}
}

func TestManagedHandlerCloseWinsBeforeResponseSignatureOrWriteGrant(t *testing.T) {
	for _, stage := range []string{"signature", "write"} {
		t.Run(stage, func(t *testing.T) {
			f, s := lifecycleFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var signed atomic.Int32
			barrier := func() { close(entered); <-release }
			s.hooks = &serverLifecycleHooks{afterSign: func() { signed.Add(1) }}
			if stage == "signature" {
				s.hooks.beforeSign = barrier
			} else {
				s.hooks.beforeWriteGrant = barrier
			}
			w, done := newLifecycleWriter(), make(chan struct{})
			go func() { s.ServeHTTP(w, lifecycleRequest(f, nil)); close(done) }()
			lifecycleWait(t, entered)
			promptClose(t, s)
			close(release)
			lifecycleWait(t, done)
			if w.used.Load() != 0 || w.wrote.Load() != 0 || stage == "signature" && signed.Load() != 0 || stage == "write" && signed.Load() != 1 {
				t.Fatal("Close did not arbitrate the exact signature/output grant")
			}
		})
	}
}

func TestManagedHandlerCloseDoesNotWaitForAlreadyGrantedNetworkWrite(t *testing.T) {
	f, s := lifecycleFixture(t)
	w := newLifecycleWriter()
	w.ready, w.block = make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() { s.ServeHTTP(w, lifecycleRequest(f, nil)); close(done) }()
	lifecycleWait(t, w.ready)
	promptClose(t, s)
	close(w.block)
	lifecycleWait(t, done)
	var out response
	if decode(w.body.Bytes(), &out) != nil || out.Status != "current" || !ed25519.Verify(f.seq.Public().(ed25519.PublicKey), out.signingBytes(), out.Signature) {
		t.Fatal("already-granted write did not preserve its original signed output")
	}
	late := newLifecycleWriter()
	s.ServeHTTP(late, lifecycleRequest(f, nil))
	if late.used.Load() != 0 || late.wrote.Load() != 0 {
		t.Fatal("closed handler granted a later response")
	}
}

func TestManagedHandlerCommitGrantOwnsKeyAcrossClose(t *testing.T) {
	for _, test := range []struct {
		name    string
		granted bool
		epoch   uint64
	}{{"close-before-grant", false, 1}, {"close-after-grant", true, 2}} {
		t.Run(test.name, func(t *testing.T) {
			f, s := lifecycleFixture(t)
			p, snapshot, err := directory.Build(f.cfg, f.owner, f.publisher, f.first.Checkpoint(), f.members, f.items)
			if err != nil {
				t.Fatal("cannot build owned publication")
			}
			entered, release := make(chan struct{}), make(chan struct{})
			barrier := func() { close(entered); <-release }
			s.hooks = &serverLifecycleHooks{}
			if test.granted {
				s.hooks.afterCommitGrant = barrier
			} else {
				s.hooks.beforeCommitGrant = barrier
			}
			w, done := newLifecycleWriter(), make(chan struct{})
			go func() {
				s.ServeHTTP(w, lifecycleRequest(f, &publication{Proposal: p, Snapshot: snapshot}))
				close(done)
			}()
			lifecycleWait(t, entered)
			promptClose(t, s)
			close(release)
			lifecycleWait(t, done)
			if w.used.Load() != 0 || w.wrote.Load() != 0 {
				t.Fatal("closed publication acknowledged an outcome")
			}
			view, err := directory.Read(f.path, f.cfg, f.first.Checkpoint())
			if err != nil || view.Receipt.Proposal.Epoch != test.epoch {
				t.Fatal("commit grant ordering was not preserved")
			}
			if !validPrivate(f.seq) {
				t.Fatal("handler borrowed or cleared caller-owned key")
			}
		})
	}
}

type lifecycleBody struct {
	readEntered, readRelease, closeEntered, closeRelease chan struct{}
	reads, closes                                        atomic.Int32
}

func (b *lifecycleBody) Read([]byte) (int, error) {
	if b.reads.Add(1) == 1 {
		close(b.readEntered)
	}
	<-b.readRelease
	return 0, io.EOF
}
func (b *lifecycleBody) Close() error {
	if b.closes.Add(1) == 1 {
		close(b.closeEntered)
	}
	<-b.closeRelease
	return nil
}

func TestManagedHandlerCloseDuringBlockedBodyAndLateCalls(t *testing.T) {
	f, s := lifecycleFixture(t)
	body := &lifecycleBody{readEntered: make(chan struct{}), readRelease: make(chan struct{}), closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}
	r := lifecycleRequest(f, nil)
	r.Body = body
	w, done := newLifecycleWriter(), make(chan struct{})
	go func() { s.ServeHTTP(w, r); close(done) }()
	lifecycleWait(t, body.readEntered)
	promptClose(t, s)
	lifecycleWait(t, body.closeEntered)
	close(body.readRelease)
	close(body.closeRelease)
	lifecycleWait(t, done)
	if w.used.Load() != 0 || w.wrote.Load() != 0 {
		t.Fatal("closed body reader produced a new error response")
	}
	late := newLifecycleWriter()
	s.ServeHTTP(late, nil)
	s.ServeHTTP(late, httptest.NewRequest(http.MethodGet, "/invalid", nil))
	if late.used.Load() != 0 || late.wrote.Load() != 0 {
		t.Fatal("late invalid handler wrote a fresh refusal")
	}
}

func TestManagedHandlerCloseConcurrentAndNilConfiguration(t *testing.T) {
	if h, err := NewManagedHandler("", nil, nil, directory.Checkpoint{}, nil); err != ErrInvalid || h != nil {
		t.Fatal("invalid managed constructor did not fail closed")
	}
	_, s := lifecycleFixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
	}
	wg.Wait()
	promptClose(t, s)
	if _, ok := interface{}(s).(ManagedHandler); !ok {
		t.Fatal("legacy constructor lost managed compatibility")
	}
	if key, ok := s.commitKey(context.Background()); ok || len(key) != 0 {
		t.Fatal("closed handler issued a later key grant")
	}
	var out response
	if s.signResponse(context.Background(), &out) || len(out.Signature) != 0 {
		t.Fatal("closed handler signed a later response")
	}
	if s.grantWrite(context.Background()) {
		t.Fatal("closed handler granted a later write")
	}
}
