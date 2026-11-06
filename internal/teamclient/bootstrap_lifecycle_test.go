package teamclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestBootstrapRoleProtectionPartialIsNeverAutomaticallyFilled(t *testing.T) {
	root := t.TempDir()
	s := newMemoryStore()
	seq, e := PrepareSequencer(filepath.Join(root, "service"))
	if e != nil {
		t.Fatal("service")
	}
	defer seq.Close()
	d, e := seq.Protect(context.Background(), s)
	if e != nil {
		t.Fatal("service protection")
	}
	p, e := PrepareOwnerBootstrap(filepath.Join(root, "owner"), d, filepath.Join(root, "anchor"))
	if e != nil {
		t.Fatal("owner")
	}
	defer p.Close()
	var calls atomic.Int32
	var borrowed [][]byte
	fault := functionalStore{load: s.Load, store: func(id string, b []byte) error {
		calls.Add(1)
		borrowed = append(borrowed, b)
		if len(b) > 1400 {
			t.Fatal("platform budget exceeded")
		}
		if calls.Load() == 2 {
			return errors.New("private provider detail")
		}
		return s.Store(id, b)
	}}
	original := p.Descriptor()
	result, e := p.Protect(context.Background(), fault)
	if e != ErrBootstrapUnknown || result.State != BootstrapUnknown || result.Device.Device != original.Device.Device || calls.Load() != 2 {
		t.Fatal("partial role protection lost its original identity")
	}
	for _, b := range borrowed {
		if !zeroBytes(b) {
			t.Fatal("worker retained role envelope")
		}
	}
	writes := s.writes
	if _, e = ReconcileProtection(context.Background(), p.inner.path, s); e == nil || s.writes != writes || s.deletes != 0 {
		t.Fatal("recovery filled a missing role or removed a possible write")
	}
	producer, e := OpenOwnerBootstrap(p.inner.path)
	if e != nil {
		t.Fatal("open partial profile")
	}
	defer producer.Close()
	if _, e = producer.BuildInitial(context.Background(), s); e == nil {
		t.Fatal("partially protected owner produced an artifact")
	}
}

func TestBootstrapProtectionRecoveryOnlyLoadsExactOriginal(t *testing.T) {
	p, e := PrepareSequencer(filepath.Join(t.TempDir(), "service"))
	if e != nil {
		t.Fatal("prepare")
	}
	defer p.Close()
	s := newMemoryStore()
	fault := functionalStore{load: s.Load, store: func(id string, b []byte) error { _ = s.Store(id, b); return errors.New("lost OS acknowledgement") }}
	d, e := p.Protect(context.Background(), fault)
	if e != ErrBootstrapUnknown || d.State != BootstrapUnknown {
		t.Fatal("unknown OS result")
	}
	writes := s.writes
	status, e := ReconcileProtection(context.Background(), p.inner.path, s)
	if e != nil || status.RecordedState != BootstrapPending || status.Sequencer.Signing != d.Signing || s.writes != writes || s.deletes != 0 {
		t.Fatal("explicit OS recovery did not retain original identity")
	}
}

func TestBootstrapCloseDuringProtectionClearsOnlyAfterOSReturns(t *testing.T) {
	p, e := PrepareSequencer(filepath.Join(t.TempDir(), "service"))
	if e != nil {
		t.Fatal("prepare")
	}
	defer p.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var borrowed []byte
	s := functionalStore{store: func(_ string, b []byte) error {
		borrowed = b
		close(entered)
		<-release
		if zeroBytes(b) {
			return ErrIdentity
		}
		return nil
	}}
	type result struct {
		d SequencerDescriptor
		e error
	}
	done := make(chan result, 1)
	go func() { d, e := p.Protect(context.Background(), s); done <- result{d, e} }()
	await(t, entered)
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	await(t, closed)
	if p.Descriptor().State != BootstrapUnknown {
		t.Fatal("blocked OS attempt still reported preparing")
	}
	close(release)
	r := await(t, done)
	if r.e != ErrCancelled || r.d.State != BootstrapUnknown || !zeroBytes(borrowed) {
		t.Fatal("closed protection acknowledged or retained borrowed secret buffer")
	}
}

func TestBootstrapOwnerCloseCancelsLateLoadsWithoutFurtherPrompts(t *testing.T) {
	f := prepareBootstrapFixture(t, false)
	o, e := OpenOwnerBootstrap(f.ownerPath)
	if e != nil {
		t.Fatal("producer")
	}
	defer o.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var returned []byte
	s := functionalStore{load: func(id string) ([]byte, error) {
		calls.Add(1)
		close(entered)
		<-release
		raw, e := f.store.Load(id)
		returned = raw
		return raw, e
	}}
	type result struct {
		a BootstrapArtifact
		e error
	}
	done := make(chan result, 1)
	go func() { a, e := o.BuildInitial(context.Background(), s); done <- result{a, e} }()
	await(t, entered)
	o.Close()
	close(release)
	r := await(t, done)
	if r.e == nil || r.a.Version != 0 || calls.Load() != 1 || !zeroBytes(returned) {
		t.Fatal("late role load revived a closed producer or opened another OS prompt")
	}
}

func TestBootstrapPrivateHandlesRedactPointerAndValue(t *testing.T) {
	f := newBootstrapFixture(t)
	p, e := PrepareSequencer(filepath.Join(t.TempDir(), "service"))
	if e != nil {
		t.Fatal("prepare")
	}
	defer p.Close()
	op, e := PrepareOwnerBootstrap(filepath.Join(t.TempDir(), "owner"), f.service, filepath.Join(t.TempDir(), "anchor"))
	if e != nil {
		t.Fatal("owner")
	}
	defer op.Close()
	b, e := OpenOwnerBootstrap(f.ownerPath)
	if e != nil {
		t.Fatal("producer")
	}
	defer b.Close()
	for _, value := range []any{p, *p, op, *op, b, *b, &ServiceOperation{}, ServiceOperation{}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			s := fmt.Sprintf(format, value)
			if s != "[protected sequencer preparation]" && s != "[protected owner bootstrap preparation]" && s != "[protected owner bootstrap operation]" && s != "[protected team service]" {
				t.Fatal("private bootstrap handle formatting leaked structure")
			}
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("private bootstrap handle serialized")
		}
	}
}

func TestBootstrapOwnedTemporaryCleanupPreservesReplacement(t *testing.T) {
	for _, mode := range []string{"owned", "replaced", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "temporary")
			if os.WriteFile(path, []byte("synthetic"), 0600) != nil {
				t.Fatal("temp")
			}
			owned, e := os.Stat(path)
			if e != nil {
				t.Fatal("stat")
			}
			if mode != "owned" {
				if os.Rename(path, path+".original") != nil {
					t.Fatal("move")
				}
				if mode == "replaced" {
					if os.WriteFile(path, []byte("replacement"), 0600) != nil {
						t.Fatal("replace")
					}
				} else if os.Symlink(path+".original", path) != nil {
					t.Skip("symlink creation unavailable")
				}
			}
			removed := removeOwnedProfileTemporary(path, owned)
			if mode == "owned" {
				if !removed || !absent(path) {
					t.Fatal("owned temporary was not removed")
				}
			} else {
				if removed {
					t.Fatal("replacement temporary was removed")
				}
				raw, e := os.ReadFile(path)
				if e != nil || mode == "replaced" && !bytes.Equal(raw, []byte("replacement")) {
					t.Fatal("replacement changed")
				}
			}
		})
	}
}
