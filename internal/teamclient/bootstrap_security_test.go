package teamclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamsync"
)

type bootstrapFixture struct {
	path, ownerPath string
	service         SequencerDescriptor
	owner           OwnerDescriptor
	artifact        BootstrapArtifact
	req             ServiceInitRequest
	store           *memoryStore
	before          []byte
	ownerBefore     []byte
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	return prepareBootstrapFixture(t, true)
}
func prepareBootstrapFixture(t *testing.T, build bool) *bootstrapFixture {
	t.Helper()
	// canonicalProfilePath canonicalizes an existing file leaf, so resolve a
	// prospective child and use its canonical parent as the fixture root.
	root, e := canonicalProfilePath(filepath.Join(t.TempDir(), "root"))
	if e != nil {
		t.Fatal("tempdir")
	}
	root = filepath.Dir(root)
	f := &bootstrapFixture{path: filepath.Join(root, "service.profile"), ownerPath: filepath.Join(root, "owner.profile"), store: newMemoryStore()}
	p, e := PrepareSequencer(f.path)
	if e != nil {
		t.Fatal("prepare service")
	}
	defer p.Close()
	f.service, e = p.Protect(context.Background(), f.store)
	if e != nil {
		t.Fatal("protect service")
	}
	f.before, e = os.ReadFile(f.path)
	if e != nil {
		t.Fatal("save original public profile")
	}
	op, e := PrepareOwnerBootstrap(f.ownerPath, f.service, filepath.Join(root, "owner.anchor"))
	if e != nil {
		t.Fatal("prepare owner")
	}
	defer op.Close()
	f.owner, e = op.Protect(context.Background(), f.store)
	if e != nil {
		t.Fatal("protect owner")
	}
	f.ownerBefore, e = os.ReadFile(f.ownerPath)
	if e != nil {
		t.Fatal("save original owner profile")
	}
	if build {
		producer, e := OpenOwnerBootstrap(f.ownerPath)
		if e != nil {
			t.Fatal("open producer")
		}
		defer producer.Close()
		f.artifact, e = producer.BuildInitial(context.Background(), f.store)
		if e != nil {
			t.Fatal("build artifact")
		}
	}
	f.req = ServiceInitRequest{Expected: f.service, TrustedPins: f.owner.Pins, Artifact: f.artifact, Directory: filepath.Join(root, "team.db"), Anchor: filepath.Join(root, "server.anchor")}
	return f
}

func TestBootstrapNewBuildRequiresOriginalUnadvancedAnchor(t *testing.T) {
	for _, mode := range []string{"missing", "advanced"} {
		t.Run(mode, func(t *testing.T) {
			f := newBootstrapFixture(t)
			f.initialize(t)
			restorePublicProfile(t, f.ownerPath, f.ownerBefore)
			if mode == "missing" {
				if os.Remove(f.owner.Anchor) != nil {
					t.Fatal("remove anchor")
				}
			} else {
				a, e := teamsync.OpenFileAnchorStore(f.owner.Anchor)
				if e != nil {
					t.Fatal("anchor")
				}
				c, _ := directory.NewConfigWithWriterACL(f.owner.Pins)
				v, e := directory.Read(f.req.Directory, c, c.Genesis())
				if e != nil || a.Advance(c.Genesis(), v.Receipt.Checkpoint()) != nil {
					t.Fatal("advance anchor")
				}
			}
			o, e := OpenOwnerBootstrap(f.ownerPath)
			if e != nil {
				t.Fatal("open producer")
			}
			defer o.Close()
			var loads atomic.Int32
			s := functionalStore{load: func(id string) ([]byte, error) { loads.Add(1); return f.store.Load(id) }, store: f.store.Store}
			if a, e := o.BuildInitial(context.Background(), s); e == nil || a.Version != 0 || loads.Load() != 0 {
				t.Fatal("old public profile bypassed independent anchor before a new signature")
			}
			if mode == "missing" && !absent(f.owner.Anchor) {
				t.Fatal("new Build recreated anchor")
			}
		})
	}
}
func (f *bootstrapFixture) initialize(t *testing.T) {
	t.Helper()
	r, e := InitializeService(context.Background(), f.path, f.req, f.store)
	if e != nil || r.State != BootstrapActive {
		t.Fatal("initialize fixture")
	}
}
func restorePublicProfile(t *testing.T, path string, b []byte) {
	t.Helper()
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("restore public profile")
	}
}
func mutateProfile(t *testing.T, path string, change func(*profileRecord)) {
	t.Helper()
	l, e := openProfile(path)
	if e != nil {
		t.Fatal("open fixture profile")
	}
	r, e := l.load()
	if e != nil {
		t.Fatal("load fixture profile")
	}
	change(&r)
	e = l.save(&r)
	closed := l.close()
	if e != nil || closed != nil {
		t.Fatal("mutate fixture public profile")
	}
}

func TestBootstrapBoundIdentityRejectsPublicRollbackRebindAndFileRecreation(t *testing.T) {
	for _, lost := range []string{"anchor", "db", "both"} {
		t.Run(lost, func(t *testing.T) {
			f := newBootstrapFixture(t)
			f.initialize(t)
			writes := f.store.writes
			restorePublicProfile(t, f.path, f.before)
			if lost == "anchor" || lost == "both" {
				if os.Remove(f.req.Anchor) != nil {
					t.Fatal("remove anchor")
				}
			}
			if lost == "db" || lost == "both" {
				if os.Remove(f.req.Directory) != nil {
					t.Fatal("remove DB")
				}
			}
			for _, reconcile := range []bool{false, true} {
				var r InitResult
				var e error
				if reconcile {
					r, e = ReconcileServiceInitialization(context.Background(), f.path, f.req, f.store)
				} else {
					r, e = InitializeService(context.Background(), f.path, f.req, f.store)
				}
				if e == nil || r.State == BootstrapActive {
					t.Fatal("restored public profile reset established identity")
				}
			}
			if (lost == "anchor" || lost == "both") && !absent(f.req.Anchor) || (lost == "db" || lost == "both") && !absent(f.req.Directory) || f.store.writes != writes {
				t.Fatal("already-bound entry recreated DB/anchor or rewrote OS identity")
			}
		})
	}
	f := newBootstrapFixture(t)
	f.initialize(t)
	writes := f.store.writes
	restorePublicProfile(t, f.path, f.before)
	secondPath := filepath.Join(filepath.Dir(f.path), "other.owner")
	p, e := PrepareOwnerBootstrap(secondPath, f.service, filepath.Join(filepath.Dir(f.path), "other.client.anchor"))
	if e != nil {
		t.Fatal("second scope prepare")
	}
	defer p.Close()
	d, e := p.Protect(context.Background(), f.store)
	if e != nil {
		t.Fatal("second scope protect")
	}
	producer, e := OpenOwnerBootstrap(secondPath)
	if e != nil {
		t.Fatal("second producer")
	}
	defer producer.Close()
	a, e := producer.BuildInitial(context.Background(), f.store)
	if e != nil {
		t.Fatal("second artifact")
	}
	writes = f.store.writes
	q := ServiceInitRequest{Expected: f.service, TrustedPins: d.Pins, Artifact: a, Directory: filepath.Join(filepath.Dir(f.path), "other.db"), Anchor: filepath.Join(filepath.Dir(f.path), "other.server.anchor")}
	if _, e = InitializeService(context.Background(), f.path, q, f.store); e != ErrBootstrapConflict || !absent(q.Directory) || !absent(q.Anchor) || f.store.writes != writes {
		t.Fatal("bound service adopted another scope after profile rollback")
	}
}

func TestBootstrapBoundPathsAndCopiedProfileCannotRebind(t *testing.T) {
	f := newBootstrapFixture(t)
	f.initialize(t)
	l, e := openProfile(f.path)
	if e != nil {
		t.Fatal("profile")
	}
	r, e := l.load()
	if e != nil {
		t.Fatal("record")
	}
	l.close()
	copied, e := canonicalProfilePath(filepath.Join(filepath.Dir(f.path), "copied.profile"))
	if e != nil {
		t.Fatal("copied profile path")
	}
	r.Path = copied
	if createProfile(copied, r) != nil {
		t.Fatal("copy public profile fixture")
	}
	writes := f.store.writes
	if op, e := OpenService(context.Background(), copied, f.service, f.owner.Pins, f.store); e == nil {
		op.Close()
		t.Fatal("copied profile reused OS identity")
	}
	if _, e = InitializeService(context.Background(), copied, f.req, f.store); e == nil || f.store.writes != writes {
		t.Fatal("copied profile mutated identity")
	}
	newAnchor := filepath.Join(filepath.Dir(f.path), "redirected.anchor")
	c, _ := directory.NewConfigWithWriterACL(f.owner.Pins)
	if _, e = teamsync.CreateFileAnchorStore(newAnchor, c.Genesis()); e != nil {
		t.Fatal("different anchor fixture")
	}
	mutateProfile(t, f.path, func(r *profileRecord) { r.Init.Anchor = newAnchor })
	if op, e := OpenService(context.Background(), f.path, f.service, f.owner.Pins, f.store); e == nil {
		op.Close()
		t.Fatal("public path substitution changed independent server anchor")
	}
	if f.store.writes != writes {
		t.Fatal("path refusal wrote OS state")
	}
}

func TestBootstrapBindingUnknownNeverRetriesStoreOrCreate(t *testing.T) {
	for _, mode := range []string{"before", "after", "lost-record"} {
		t.Run(mode, func(t *testing.T) {
			f := newBootstrapFixture(t)
			var calls atomic.Int32
			fault := functionalStore{load: f.store.Load, store: func(id string, b []byte) error {
				calls.Add(1)
				if mode == "after" {
					_ = f.store.Store(id, b)
				}
				if mode == "lost-record" {
					f.store.mu.Lock()
					delete(f.store.records, id)
					f.store.mu.Unlock()
				}
				return errors.New("private OS diagnostic must not escape")
			}}
			r, e := InitializeService(context.Background(), f.path, f.req, fault)
			if e != ErrBootstrapUnknown || r.State != BootstrapUnknown || !absent(f.req.Directory) || calls.Load() != 1 {
				t.Fatal("uncertain binding had a definite outcome")
			}
			if absent(f.req.Anchor) {
				t.Fatal("bound Store attempt preceded independent Genesis anchor")
			}
			writes := f.store.writes
			for range 2 {
				r, e = ReconcileServiceInitialization(context.Background(), f.path, f.req, f.store)
				if e == nil || r.State == BootstrapActive {
					t.Fatal("unknown binding resumed new Create")
				}
			}
			if !absent(f.req.Directory) || f.store.writes != writes || f.store.deletes != 0 {
				t.Fatal("unknown binding rewrote or deleted identity")
			}
		})
	}
}

func TestBootstrapCreateAmbiguityRecoversOnlyExactExistingDB(t *testing.T) {
	f := newBootstrapFixture(t)
	f.initialize(t)
	// The original record permits completing only the unacknowledged stage.
	mutateProfile(t, f.path, func(r *profileRecord) { r.Phase = BootstrapUnknown; r.Init.Receipt = nil })
	r, e := ReconcileServiceInitialization(context.Background(), f.path, f.req, f.store)
	if e != nil || r.State != BootstrapActive || r.Checkpoint.Version != 1 {
		t.Fatal("exact existing initial DB was not reconciled")
	}
	writes := f.store.writes
	if os.Remove(f.req.Directory) != nil {
		t.Fatal("remove initial DB")
	}
	mutateProfile(t, f.path, func(r *profileRecord) { r.Phase = BootstrapUnknown; r.Init.CreateAttempt = false; r.Init.Receipt = nil })
	if r, e = ReconcileServiceInitialization(context.Background(), f.path, f.req, f.store); e == nil || r.State == BootstrapActive || !absent(f.req.Directory) || f.store.writes != writes {
		t.Fatal("already-bound recovery signed or created missing DB")
	}
}

func TestBootstrapCancellationWhileBoundStoreIsBlocked(t *testing.T) {
	f := newBootstrapFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	store := functionalStore{load: f.store.Load, store: func(id string, b []byte) error { e := f.store.Store(id, b); close(entered); <-release; return e }}
	type result struct {
		r InitResult
		e error
	}
	done := make(chan result, 1)
	go func() { r, e := InitializeService(ctx, f.path, f.req, store); done <- result{r, e} }()
	await(t, entered)
	if absent(f.req.Anchor) || !absent(f.req.Directory) {
		t.Fatal("unsafe binding order")
	}
	// The independent identity lease also excludes another process before OS.
	childCtx, childCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer childCancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestBootstrapIdentityLeaseChild$")
	cmd.Env = append(os.Environ(), "LOCKLARK_TEST_PROFILE_LEASE="+f.path)
	if output, e := cmd.CombinedOutput(); e != nil || string(output) != "PASS\n" {
		t.Fatal("cross-process identity exclusion failed")
	}
	cancel()
	close(release)
	r := await(t, done)
	if r.e != ErrCancelled || r.r.State != BootstrapUnknown || !absent(f.req.Directory) {
		t.Fatal("late binding revived cancelled Create")
	}
	if r, e := ReconcileServiceInitialization(context.Background(), f.path, f.req, f.store); e == nil || r.State == BootstrapActive || !absent(f.req.Directory) {
		t.Fatal("cancelled bound operation created DB on restart")
	}
}
func TestBootstrapIdentityLeaseChild(t *testing.T) {
	if path := os.Getenv("LOCKLARK_TEST_PROFILE_LEASE"); path != "" {
		if _, e := ReadBootstrapStatus(path); e != ErrProfile {
			t.Fatal("identity lease was not exclusive")
		}
	}
}

func TestBootstrapRejectsUntrustedInputsBeforeOS(t *testing.T) {
	f := newBootstrapFixture(t)
	for _, mode := range []string{"pins", "expected", "artifact", "alias", "lease-alias"} {
		t.Run(mode, func(t *testing.T) {
			q := f.req
			q.TrustedPins = clonePins(q.TrustedPins)
			switch mode {
			case "pins":
				q.TrustedPins.Team = strings.Repeat("a", 32)
			case "expected":
				q.Expected.ServiceID = strings.Repeat("b", 32)
			case "artifact":
				q.Artifact.Version = 2
			case "alias":
				q.Anchor = q.Directory
			case "lease-alias":
				q.Anchor = f.path + ".identity-lease"
			}
			var calls atomic.Int32
			s := functionalStore{load: func(string) ([]byte, error) { calls.Add(1); return nil, ErrProtection }, store: func(string, []byte) error { calls.Add(1); return nil }}
			if r, e := InitializeService(context.Background(), f.path, q, s); e == nil || r.State == BootstrapActive || calls.Load() != 0 {
				t.Fatal("untrusted bootstrap reached OS")
			}
		})
	}
	var writes atomic.Int32
	s := functionalStore{load: func(string) ([]byte, error) { return nil, ErrProtection }, store: func(string, []byte) error { writes.Add(1); return nil }}
	if _, e := InitializeService(context.Background(), f.path, f.req, s); e == nil || writes.Load() != 0 {
		t.Fatal("Load failure was treated as absent protected identity")
	}
}

func TestBootstrapArtifactStrictAndDurableOriginal(t *testing.T) {
	f := newBootstrapFixture(t)
	raw, e := EncodeBootstrapArtifact(f.artifact)
	if e != nil {
		t.Fatal("encode")
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), []byte("{}")...), append([]byte(`{"unknown":true,`), raw[1:]...), append([]byte(`{"version":1,`), raw[1:]...), make([]byte, MaxBootstrapArtifactBytes+1)} {
		if _, e := DecodeBootstrapArtifact(bad); e == nil {
			t.Fatal("noncanonical artifact accepted")
		}
	}
	l, e := openProfile(f.ownerPath)
	if e != nil {
		t.Fatal("outbox")
	}
	r, e := l.load()
	l.close()
	if e != nil || !bytes.Equal(r.Artifact, raw) || !r.BuildAttempt {
		t.Fatal("original outbox not durable before export")
	}
	o, e := OpenOwnerBootstrap(f.ownerPath)
	if e != nil {
		t.Fatal("reopen producer")
	}
	defer o.Close()
	var loads atomic.Int32
	readOnlyOS := functionalStore{load: func(id string) ([]byte, error) { loads.Add(1); return f.store.Load(id) }, store: func(string, []byte) error { t.Fatal("public original export rewrote OS"); return nil }}
	a, e := o.BuildInitial(context.Background(), readOnlyOS)
	if e != nil {
		t.Fatal("export original")
	}
	again, _ := EncodeBootstrapArtifact(a)
	if !bytes.Equal(raw, again) || loads.Load() != 1 {
		t.Fatal("original proposal was rebuilt or re-signed")
	}
	for _, b := range f.store.records {
		if len(b) > maxProtectedRoleBytes {
			t.Fatal("OS envelope exceeds Windows minimum capacity")
		}
	}
}

func TestBootstrapFirstFetchNeverResetsOrRedirectsOwnerAnchor(t *testing.T) {
	f := newBootstrapFixture(t)
	f.initialize(t)
	h, e := OpenService(context.Background(), f.path, f.service, f.owner.Pins, f.store)
	if e != nil {
		t.Fatal("service")
	}
	defer h.Close()
	srv := httptest.NewUnstartedServer(h.Handler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	ep := teamsync.Endpoint{URL: srv.URL, Roots: roots}
	before, e := os.ReadFile(f.ownerPath)
	if e != nil {
		t.Fatal("owner backup")
	}
	if r, e := ConfirmInitial(context.Background(), f.ownerPath, f.owner.Pins, f.store, ep); e != nil || r.State != BootstrapActive {
		t.Fatal("first fetch")
	}
	writes := f.store.writes
	exporter, e := OpenOwnerBootstrap(f.ownerPath)
	if e != nil {
		t.Fatal("active export open")
	}
	if _, e = exporter.BuildInitial(context.Background(), f.store); e != nil {
		t.Fatal("active original export")
	}
	exporter.Close()
	status, e := ReconcileProtection(context.Background(), f.ownerPath, f.store)
	if e != nil || status.RecordedState != BootstrapActive || f.store.writes != writes {
		t.Fatal("original export/protection check downgraded active state or rewrote OS record")
	}
	newAnchor := filepath.Join(filepath.Dir(f.path), "substituted.client.anchor")
	c, _ := directory.NewConfigWithWriterACL(f.owner.Pins)
	if _, e = teamsync.CreateFileAnchorStore(newAnchor, c.Genesis()); e != nil {
		t.Fatal("anchor fixture")
	}
	mutateProfile(t, f.ownerPath, func(r *profileRecord) { r.Owner.Anchor = newAnchor })
	if r, e := ConfirmInitial(context.Background(), f.ownerPath, f.owner.Pins, f.store, ep); e == nil || r.State == BootstrapActive {
		t.Fatal("mutable profile redirected protected anchor")
	}
	restorePublicProfile(t, f.ownerPath, before)
	if os.Remove(f.owner.Anchor) != nil {
		t.Fatal("remove owner anchor")
	}
	if r, e := ConfirmInitial(context.Background(), f.ownerPath, f.owner.Pins, f.store, ep); e == nil || r.State == BootstrapActive || !absent(f.owner.Anchor) {
		t.Fatal("old owner profile reset missing independent anchor")
	}
}
