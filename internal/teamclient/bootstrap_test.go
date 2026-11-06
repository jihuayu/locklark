package teamclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/teamsync"
)

func TestBootstrapProtectedProducerInitializesAndFetches(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := newMemoryStore()
	servicePath := filepath.Join(root, "service.profile")
	seq, e := PrepareSequencer(servicePath)
	if e != nil {
		t.Fatal("system-protected service bootstrap is missing")
	}
	defer seq.Close()
	service, e := seq.Protect(ctx, store)
	if e != nil || service.State != BootstrapPending {
		t.Fatal("service identity protection")
	}
	ownerPath := filepath.Join(root, "owner.profile")
	op, e := PrepareOwnerBootstrap(ownerPath, service, filepath.Join(root, "owner.anchor"))
	if e != nil {
		t.Fatal("owner preparation")
	}
	defer op.Close()
	owner, e := op.Protect(ctx, store)
	if e != nil || owner.State != BootstrapPending {
		t.Fatal("owner roles protection")
	}
	producer, e := OpenOwnerBootstrap(ownerPath)
	if e != nil {
		t.Fatal("durable producer open")
	}
	defer producer.Close()
	a, e := producer.BuildInitial(ctx, store)
	if e != nil {
		t.Fatal("initial artifact")
	}
	raw, e := EncodeBootstrapArtifact(a)
	if e != nil {
		t.Fatal("artifact encode")
	}
	a, e = DecodeBootstrapArtifact(raw)
	if e != nil {
		t.Fatal("artifact strict decode")
	}
	if bytes.Contains(raw, []byte("AGE-SECRET-KEY")) {
		t.Fatal("artifact exposed private identity")
	}
	req := ServiceInitRequest{Expected: service, TrustedPins: owner.Pins, Artifact: a, Directory: filepath.Join(root, "team.db"), Anchor: filepath.Join(root, "server.anchor")}
	r, e := InitializeService(ctx, servicePath, req, store)
	if e != nil || r.State != BootstrapActive || r.Checkpoint.Version != 1 {
		t.Fatal("service initialization")
	}
	h, e := OpenService(ctx, servicePath, service, owner.Pins, store)
	if e != nil {
		t.Fatal("OS-protected service open")
	}
	defer h.Close()
	srv := httptest.NewUnstartedServer(h.Handler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	first, e := ConfirmInitial(ctx, ownerPath, owner.Pins, store, teamsync.Endpoint{URL: srv.URL, Roots: roots})
	if e != nil || first.State != BootstrapActive || first.ItemCount != 0 || first.Checkpoint != r.Checkpoint || first.DeviceID != owner.Device.Device.ID {
		t.Fatal("first device fetch/decrypt/anchor confirmation")
	}
	if store.deletes != 0 {
		t.Fatal("bootstrap deleted protected identity")
	}
}
