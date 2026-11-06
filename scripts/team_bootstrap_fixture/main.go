//go:build linux

// The normal workflow runs the product CLIs. This helper independently checks
// public evidence and injects lost results around real native OS calls. It never
// returns a protected team key or replaces the native store with a fake.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/teamclient"
	"github.com/jihuayu/locklark/internal/teamsync"
	"golang.org/x/sys/unix"
)

var refused = errors.New("bootstrap fixture refused")

type request struct {
	Profile, Anchor, Directory, ServiceFile, PinsFile, ArtifactFile string
	Output, State, Fault, Barrier, TLSDirectory                     string
	Version                                                         uint64
	MissingDirectory, MissingAnchor                                 bool
}

func readJSON(path string, out any) error {
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > teamclient.MaxBootstrapArtifactBytes {
		return refused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return refused
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return refused
	}
	return nil
}
func write(path string, raw []byte) error {
	if !filepath.IsAbs(path) {
		return refused
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return refused
	}
	_, e = f.Write(raw)
	sync := f.Sync()
	close := f.Close()
	if e != nil || sync != nil || close != nil {
		return refused
	}
	return nil
}
func public(path string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return refused
	}
	return write(path, raw)
}
func inputs(q request) (teamclient.SequencerDescriptor, directory.Pins, teamclient.BootstrapArtifact, error) {
	var service teamclient.SequencerDescriptor
	var pins directory.Pins
	if readJSON(q.ServiceFile, &service) != nil || readJSON(q.PinsFile, &pins) != nil {
		return service, pins, teamclient.BootstrapArtifact{}, refused
	}
	raw, e := os.ReadFile(q.ArtifactFile)
	if e != nil {
		return service, pins, teamclient.BootstrapArtifact{}, refused
	}
	a, e := teamclient.DecodeBootstrapArtifact(raw)
	if e != nil {
		return service, pins, a, refused
	}
	return service, pins, a, nil
}
func initRequest(q request) (teamclient.ServiceInitRequest, error) {
	s, p, a, e := inputs(q)
	return teamclient.ServiceInitRequest{Expected: s, TrustedPins: p, Artifact: a, Directory: q.Directory, Anchor: q.Anchor}, e
}

type nativeBoundary struct {
	base                    teamclient.SystemStore
	ctx                     context.Context
	request                 request
	stores, deletes, loaded int
}

func (s *nativeBoundary) Load(id string) ([]byte, error) {
	raw, e := s.base.Load(id)
	if e == nil {
		s.loaded++
	}
	return raw, e
}
func (s *nativeBoundary) Delete(id string) error { s.deletes++; return s.base.Delete(id) }
func (s *nativeBoundary) Store(id string, raw []byte) error {
	s.stores++
	if s.request.Fault == "bind-before" || s.request.Fault == "bind-after" {
		var pins directory.Pins
		if readJSON(s.request.PinsFile, &pins) != nil {
			return refused
		}
		c, e := directory.NewConfigWithWriterACL(pins)
		if e != nil {
			return refused
		}
		a, e := teamsync.OpenFileAnchorStore(s.request.Anchor)
		if e != nil {
			return refused
		}
		cp, e := a.Load()
		if e != nil || cp != c.Genesis() {
			return refused
		}
		if s.request.Fault == "bind-before" {
			if write(s.request.Barrier, []byte("before")) != nil {
				return refused
			}
			<-s.ctx.Done()
			return refused
		}
	}
	if e := s.base.Store(id, raw); e != nil {
		return e
	}
	if s.request.Fault == "bind-after" {
		if write(s.request.Barrier, []byte("after")) != nil {
			return refused
		}
		<-s.ctx.Done()
		return refused
	}
	if s.request.Fault == "lost-protection" {
		return refused
	}
	if s.request.Fault == "owner-claim-lost" && s.stores == 1 || s.request.Fault == "owner-built-lost" && s.stores == 2 {
		return refused
	}
	return nil
}

func tlsFiles(dir string, wrongName bool) error {
	if !filepath.IsAbs(dir) {
		return refused
	}
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if e != nil {
			return big.NewInt(0)
		}
		return n
	}
	caPub, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return refused
	}
	defer clear(caKey)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Owned bootstrap acceptance CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if e != nil {
		return refused
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return refused
	}
	defer clear(key)
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Owned bootstrap acceptance service"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if wrongName {
		leaf.DNSNames = []string{"wrong-name.example.test"}
		leaf.IPAddresses = nil
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
	if e != nil {
		return refused
	}
	encoded, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return refused
	}
	defer clear(encoded)
	for name, block := range map[string]*pem.Block{"ca.pem": {Type: "CERTIFICATE", Bytes: caDER}, "server.pem": {Type: "CERTIFICATE", Bytes: der}, "server.key": {Type: "PRIVATE KEY", Bytes: encoded}} {
		raw := pem.EncodeToMemory(block)
		e = write(filepath.Join(dir, name), raw)
		clear(raw)
		if e != nil {
			return e
		}
	}
	return nil
}
func run(mode string, q request) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	store := osunlock.New()
	switch mode {
	case "tls":
		return tlsFiles(q.TLSDirectory, q.Fault == "wrong-name")
	case "owner-public":
		d, e := teamclient.ReadOwnerDescriptor(q.Profile)
		if e != nil {
			return refused
		}
		return public(q.Output, d)
	case "status":
		s, e := teamclient.ReadBootstrapStatus(q.Profile)
		if e != nil || string(s.RecordedState) != q.State {
			return refused
		}
		if q.Output != "" {
			return public(q.Output, s)
		}
		return nil
	case "anchor":
		a, e := teamsync.OpenFileAnchorStore(q.Anchor)
		if e != nil {
			return refused
		}
		cp, e := a.Load()
		if e != nil || cp.Version != q.Version {
			return refused
		}
		if q.Output != "" {
			return public(q.Output, cp)
		}
		return nil
	case "verify-initial":
		s, p, a, e := inputs(q)
		if e != nil || !reflect.DeepEqual(p, a.Pins) || !reflect.DeepEqual(s, a.Service) {
			return refused
		}
		c, e := directory.NewConfigWithWriterACL(p)
		if e != nil || directory.VerifyInitial(c, a.Proposal, a.Snapshot) != nil || len(a.Proposal.Members) != 1 || len(a.Proposal.Members[0].Devices) != 1 || len(a.Proposal.Admissions) != 1 {
			return refused
		}
		o, e := teamclient.ReadOwnerDescriptor(q.Profile)
		if e != nil || !reflect.DeepEqual(o.Pins, p) || o.MemberID != a.Proposal.Members[0].ID || !reflect.DeepEqual(o.Device.Device, a.Proposal.Members[0].Devices[0]) {
			return refused
		}
		keys := map[string]bool{}
		for _, key := range []string{s.Signing, o.Owner.Signing, o.Publisher.Signing, o.Device.Device.Signing} {
			if keys[key] || key == "" {
				return refused
			}
			keys[key] = true
		}
		if o.Device.Device.ID == o.MemberID {
			return refused
		}
		return nil
	case "verify-active":
		var p directory.Pins
		if readJSON(q.PinsFile, &p) != nil {
			return refused
		}
		c, e := directory.NewConfigWithWriterACL(p)
		if e != nil {
			return refused
		}
		a, e := teamsync.OpenFileAnchorStore(q.Anchor)
		if e != nil {
			return refused
		}
		cp, e := a.Load()
		if e != nil || cp.Version != 1 {
			return refused
		}
		v, e := directory.Read(q.Directory, c, cp)
		if e != nil || v.Receipt.Checkpoint() != cp {
			return refused
		}
		if q.Output != "" {
			return public(q.Output, cp)
		}
		return nil
	case "fault-protection":
		plan, e := teamclient.PrepareSequencer(q.Profile)
		if e != nil {
			return refused
		}
		defer plan.Close()
		before := plan.Descriptor()
		b := &nativeBoundary{base: store, ctx: ctx, request: request{Fault: "lost-protection"}}
		d, e := plan.Protect(ctx, b)
		if !errors.Is(e, teamclient.ErrBootstrapUnknown) || d.State != teamclient.BootstrapUnknown || b.stores != 1 || b.deletes != 0 || d.Signing != before.Signing {
			return refused
		}
		return public(q.Output, d)
	case "protection-reconcile":
		b := &nativeBoundary{base: store, ctx: ctx}
		s, e := teamclient.ReconcileProtection(ctx, q.Profile, b)
		if e != nil || s.RecordedState != teamclient.BootstrapPending || b.stores != 0 || b.deletes != 0 {
			return refused
		}
		return nil
	case "owner-no-rebuild":
		o, e := teamclient.OpenOwnerBootstrap(q.Profile)
		if e != nil {
			return refused
		}
		defer o.Close()
		b := &nativeBoundary{base: store, ctx: ctx}
		a, e := o.BuildInitial(ctx, b)
		if e == nil || a.Version != 0 || b.stores != 0 || b.deletes != 0 || q.Fault == "require-native-load" && b.loaded == 0 {
			return refused
		}
		return nil
	case "fault-build":
		o, e := teamclient.OpenOwnerBootstrap(q.Profile)
		if e != nil {
			return refused
		}
		defer o.Close()
		b := &nativeBoundary{base: store, ctx: ctx, request: q}
		a, e := o.BuildInitial(ctx, b)
		want := 1
		if q.Fault == "owner-built-lost" {
			want = 2
		} else if q.Fault != "owner-claim-lost" {
			return refused
		}
		if e == nil || a.Version != 0 || b.stores != want || b.deletes != 0 {
			return refused
		}
		s, e := teamclient.ReadBootstrapStatus(q.Profile)
		if e != nil {
			return refused
		}
		if (s.ArtifactDigest != "") != (want == 2) {
			return refused
		}
		return public(q.Output, s)
	case "owner-export-readonly":
		o, e := teamclient.OpenOwnerBootstrap(q.Profile)
		if e != nil {
			return refused
		}
		defer o.Close()
		b := &nativeBoundary{base: store, ctx: ctx}
		a, e := o.BuildInitial(ctx, b)
		if e != nil || a.Version != 1 || b.stores != 0 || b.deletes != 0 || b.loaded == 0 {
			return refused
		}
		raw, e := teamclient.EncodeBootstrapArtifact(a)
		if e != nil {
			return refused
		}
		return write(q.Output, raw)
	case "fault-bind":
		r, e := initRequest(q)
		if e != nil {
			return refused
		}
		b := &nativeBoundary{base: store, ctx: ctx, request: q}
		_, _ = teamclient.InitializeService(ctx, q.Profile, r, b)
		return refused // controller must terminate the owned, barrier-blocked caller
	case "no-reset":
		r, e := initRequest(q)
		if e != nil {
			return refused
		}
		b := &nativeBoundary{base: store, ctx: ctx}
		if _, e = teamclient.InitializeService(ctx, q.Profile, r, b); e == nil {
			return refused
		}
		if _, e = teamclient.ReconcileServiceInitialization(ctx, q.Profile, r, b); e == nil {
			return refused
		}
		if b.stores != 0 || b.deletes != 0 {
			return refused
		}
		if q.MissingDirectory {
			if _, e = os.Lstat(q.Directory); !os.IsNotExist(e) {
				return refused
			}
		}
		if q.MissingAnchor {
			if _, e = os.Lstat(q.Anchor); !os.IsNotExist(e) {
				return refused
			}
		}
		return nil
	}
	return refused
}
func main() {
	if len(os.Args) >= 4 && os.Args[1] == "console-exec" {
		tty, e := os.OpenFile(os.Args[2], os.O_RDWR, 0)
		if e == nil {
			e = unix.IoctlSetInt(int(tty.Fd()), unix.TIOCSCTTY, 0)
		}
		if e == nil {
			e = syscall.Exec(os.Args[3], os.Args[3:], os.Environ())
		}
		fmt.Println("FAIL: bootstrap fixture")
		os.Exit(1)
	}
	good := false
	if len(os.Args) == 2 {
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, (32<<10)+1))
		if e == nil && len(raw) <= 32<<10 {
			var q request
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&q) == nil {
				var extra any
				if d.Decode(&extra) == io.EOF {
					good = run(os.Args[1], q) == nil
				}
			}
		}
		clear(raw)
	}
	if !good {
		fmt.Println("FAIL: bootstrap fixture")
		os.Exit(1)
	}
	fmt.Println("PASS: bootstrap fixture")
}
