package teamclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
)

func TestBootstrapOwnerClaimPreventsGenesisOutboxRollbackRebuild(t *testing.T) {
	f := newBootstrapFixture(t)
	original, e := EncodeBootstrapArtifact(f.artifact)
	if e != nil {
		t.Fatal("original")
	}
	originalProfile := mustPublicProfile(t, f.ownerPath)
	restorePublicProfile(t, f.ownerPath, f.ownerBefore)
	o, e := OpenOwnerBootstrap(f.ownerPath)
	if e != nil {
		t.Fatal("rolled profile")
	}
	defer o.Close()
	var loads, writes atomic.Int32
	readOnly := functionalStore{load: func(id string) ([]byte, error) { loads.Add(1); return f.store.Load(id) }, store: func(string, []byte) error { writes.Add(1); return nil }}
	if a, e := o.BuildInitial(context.Background(), readOnly); e != ErrBootstrapUnknown || a.Version != 0 || loads.Load() != 1 || writes.Load() != 0 {
		t.Fatal("Genesis public rollback generated another original artifact")
	}
	restorePublicProfile(t, f.ownerPath, originalProfile)
	o, e = OpenOwnerBootstrap(f.ownerPath)
	if e != nil {
		t.Fatal("original profile")
	}
	defer o.Close()
	a, e := o.BuildInitial(context.Background(), readOnly)
	encoded, _ := EncodeBootstrapArtifact(a)
	if e != nil || !bytes.Equal(encoded, original) || writes.Load() != 0 {
		t.Fatal("original outbox was not re-exported exactly without OS mutation")
	}
}
func mustPublicProfile(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("public profile backup")
	}
	return b
}

func TestBootstrapOwnerClaimAndFinalizeAmbiguity(t *testing.T) {
	for _, phase := range []string{"claim", "finalize"} {
		for _, timing := range []string{"before", "after"} {
			t.Run(phase+"-"+timing, func(t *testing.T) {
				f := prepareBootstrapFixture(t, false)
				var calls atomic.Int32
				faultAt := int32(1)
				if phase == "finalize" {
					faultAt = 2
				}
				fault := functionalStore{load: f.store.Load, store: func(id string, b []byte) error {
					n := calls.Add(1)
					if n == faultAt && timing == "before" {
						return errors.New("fixed synthetic lost OS result")
					}
					e := f.store.Store(id, b)
					if n == faultAt {
						return errors.New("fixed synthetic lost OS result")
					}
					return e
				}}
				o, e := OpenOwnerBootstrap(f.ownerPath)
				if e != nil {
					t.Fatal("producer")
				}
				a, e := o.BuildInitial(context.Background(), fault)
				o.Close()
				if e != ErrBootstrapUnknown || a.Version != 0 || calls.Load() != faultAt {
					t.Fatal("ambiguous owner transition returned an artifact")
				}
				status, e := ReadBootstrapStatus(f.ownerPath)
				if e != nil || status.RecordedState != BootstrapUnknown || status.BuildID == "" {
					t.Fatal("original BuildID not durable")
				}
				beforeDigest := status.ArtifactDigest
				if phase == "claim" && beforeDigest != "" {
					t.Fatal("claim refusal signed before Store acknowledged")
				}
				if phase == "finalize" && beforeDigest == "" {
					t.Fatal("finalize attempt preceded durable original outbox")
				}
				writes := f.store.writes
				o, e = OpenOwnerBootstrap(f.ownerPath)
				if e != nil {
					t.Fatal("reconcile producer")
				}
				defer o.Close()
				a, e = o.BuildInitial(context.Background(), f.store)
				if phase == "finalize" && timing == "after" {
					if e != nil {
						t.Fatal("built lost-ack did not load/recover original")
					}
					raw, _ := EncodeBootstrapArtifact(a)
					if artifactDigest(raw) != beforeDigest {
						t.Fatal("built recovery changed original artifact")
					}
				} else if e != ErrBootstrapUnknown || a.Version != 0 {
					t.Fatal("ambiguous owner stage retried or exported unfinalized artifact")
				}
				if f.store.writes != writes || f.store.deletes != 0 {
					t.Fatal("owner recovery repeated OS mutation")
				}
			})
		}
	}
}
