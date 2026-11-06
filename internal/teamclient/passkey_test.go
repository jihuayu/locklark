package teamclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/teamsync"
	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/crypto/ssh"
)

func TestBootstrapPasskeyAndSSHUpdateRoundTrip(t *testing.T) {
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
	req := ServiceInitRequest{Expected: service, TrustedPins: owner.Pins, Artifact: a, Directory: filepath.Join(root, "team.db"), Anchor: filepath.Join(root, "server.anchor")}
	init, e := InitializeService(ctx, servicePath, req, store)
	if e != nil || init.State != BootstrapActive || init.Checkpoint.Version != 1 {
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
	ep := teamsync.Endpoint{URL: srv.URL, Roots: roots}
	first, e := ConfirmInitial(ctx, ownerPath, owner.Pins, store, ep)
	if e != nil || first.State != BootstrapActive || first.ItemCount != 0 || first.Checkpoint != init.Checkpoint || first.DeviceID != owner.Device.Device.ID {
		t.Fatal("first device fetch/decrypt/anchor confirmation")
	}

	lease, e := openProfile(ownerPath)
	if e != nil {
		t.Fatal("owner profile open")
	}
	r, e := lease.load()
	closeErr := lease.close()
	if e != nil {
		t.Fatal("owner profile load")
	}
	if closeErr != nil {
		t.Fatal("owner profile close")
	}
	cfg, e := directory.NewConfigWithWriterACL(r.Owner.Pins)
	if e != nil {
		t.Fatal("owner config")
	}
	id, e := deviceStoreID(r.Owner.Device)
	if e != nil {
		t.Fatal("device store id")
	}
	raw, e := store.Load(id)
	if e != nil {
		t.Fatal("device material load")
	}
	material, e := decodeDevice(r.Owner.Device, raw)
	clear(raw)
	if e != nil {
		t.Fatal("device material decode")
	}
	defer material.clear()
	signing := ed25519.NewKeyFromSeed(material.signingSeed)
	defer clear(signing)
	identity, e := age.ParseX25519Identity(string(material.ageEncoded))
	if e != nil {
		t.Fatal("device encryption identity")
	}

	request, e := passkey.Parse("https://example.test", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"team-passkey-canary","displayName":"Team Passkey"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if e != nil {
		t.Fatal("passkey fixture")
	}
	record, _, e := passkey.Create(request, false)
	if e != nil {
		t.Fatal("passkey record fixture")
	}
	defer clear(record)
	seed := bytes.Repeat([]byte{0x51}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, e := ssh.NewPublicKey(private.Public())
	if e != nil {
		t.Fatal("SSH fixture")
	}
	items := []vault.Item{
		{ID: "passkey-login", Kind: "login", Title: "Team passkey login", Username: "alice", Password: "team-passkey-password", URL: "https://example.test", Passkey: bytes.Clone(record)},
		{ID: "ssh-key", Kind: "ssh-key", Title: "Team SSH key", SSHSeed: bytes.Clone(seed), SSHPublicKey: public.Marshal()},
	}
	anchors, e := teamsync.CreateFileAnchorStore(filepath.Join(root, "publish.anchor"), cfg.Genesis())
	if e != nil {
		t.Fatal("client anchor")
	}
	client, e := teamsync.NewDeviceClient(cfg, ep, r.Owner.Device.Device, signing, anchors)
	if e != nil {
		t.Fatal("device client")
	}
	defer client.Close()
	state, e := client.Fetch(ctx)
	if e != nil || state.Checkpoint() != first.Checkpoint {
		t.Fatal("first device fetch", e)
	}
	proposal, snapshot, e := directory.BuildUpdate(cfg, signing, state.View().Receipt, items)
	if e != nil {
		t.Fatal("team update build")
	}
	if _, e = client.Publish(ctx, proposal, snapshot); e != nil {
		t.Fatal("team update publish", e)
	}
	state, e = client.Fetch(ctx)
	if e != nil || state.Checkpoint().Version != 2 {
		t.Fatal("team update fetch", e)
	}
	view := state.View()
	data, got, e := vault.OpenItems(view.Snapshot, identity, view.SnapshotSigner, view.Receipt.Proposal.Epoch)
	defer clear(data)
	defer func() {
		for n := range got {
			clear(got[n].Attachment)
			clear(got[n].ImportSource)
			clear(got[n].SSHSeed)
			clear(got[n].Passkey)
			got[n] = vault.Item{}
		}
	}()
	if e != nil {
		t.Fatal("team update snapshot did not open", e)
	}
	if string(data) != "locklark/team/items/v1/"+view.Receipt.Proposal.Scope {
		t.Fatal("team update metadata changed")
	}
	if !reflect.DeepEqual(got, items) {
		t.Fatal("passkey or SSH item did not round-trip losslessly")
	}
	if bytes.Contains(view.Snapshot.Database, record) || bytes.Contains(view.Snapshot.Database, seed) {
		t.Fatal("team snapshot exposed passkey or SSH private material")
	}
}
