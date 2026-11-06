// Package teambootstrapcli provides the normal native bootstrap command flow.
// It has no private-key arguments, environment overrides or fallback store.
package teambootstrapcli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"strconv"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/teamclient"
	"github.com/jihuayu/locklark/internal/teamconsent"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/teamsync"
)

const OwnerUsage = "locklark team create|export-initial|fetch-initial|status|reconcile-protection (see command flags)\n"
const ServiceUsage = "locklark-team-sync prepare-identity|initialize|reconcile-initialize|serve-profile|status|reconcile-protection\n"

type failure struct {
	code  int
	stage string
}

func (e failure) Error() string {
	switch e.code {
	case 2:
		return "team bootstrap usage refused; see help"
	case 3:
		return "team bootstrap result unknown at " + e.stage + "; retain the original profile and reconcile the same operation"
	case 4:
		return "team bootstrap conflict at " + e.stage + "; original files and identities must not be replaced"
	default:
		return "team bootstrap refused at " + e.stage
	}
}
func ExitCode(err error) int {
	var f failure
	if errors.As(err, &f) {
		return f.code
	}
	return 1
}
func refused(stage string, err error, unknown bool) error {
	if errors.Is(err, teamclient.ErrBootstrapConflict) {
		return failure{4, stage}
	}
	if unknown || errors.Is(err, teamclient.ErrBootstrapUnknown) || errors.Is(err, teamclient.ErrCancelled) || errors.Is(err, teamfiles.ErrPublicationUnknown) {
		return failure{3, stage}
	}
	return failure{1, stage}
}

type runtime struct {
	store   func() teamclient.SystemStore
	confirm func(context.Context, string, string, string, string) error
}

func normalRuntime() runtime {
	return runtime{func() teamclient.SystemStore { return osunlock.New() }, teamconsent.Confirm}
}
func RunOwner(args []string, out io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), bootstrapSignals()...)
	defer stop()
	return run(ctx, args, out, false, normalRuntime())
}
func RunService(args []string, out io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), bootstrapSignals()...)
	defer stop()
	return run(ctx, args, out, true, normalRuntime())
}
func IsServiceCommand(name string) bool {
	switch name {
	case "prepare-identity", "initialize", "reconcile-initialize", "serve-profile", "status", "reconcile-protection":
		return true
	}
	return false
}

type receipt struct {
	Command      string                    `json:"command"`
	State        teamclient.BootstrapPhase `json:"state"`
	Fingerprints map[string]string         `json:"fingerprints,omitempty"`
	Scope        string                    `json:"scope,omitempty"`
	Listen       string                    `json:"listen,omitempty"`
}

func emit(out io.Writer, command string, state teamclient.BootstrapPhase) error {
	return emitReceipt(out, receipt{Command: command, State: state})
}
func emitReceipt(out io.Writer, value receipt) error {
	if json.NewEncoder(out).Encode(value) != nil {
		return failure{1, "output"}
	}
	return nil
}
func fingerprints(seq string, pins *directory.Pins) (map[string]string, string) {
	values := map[string]string{}
	if fp, err := teamconsent.Fingerprint(seq); err == nil {
		values["sequencer"] = fp
	}
	if pins == nil {
		return values, ""
	}
	if len(pins.Owners) == 1 {
		if fp, err := teamconsent.Fingerprint(pins.Owners[0]); err == nil {
			values["owner"] = fp
		}
	}
	if fp, err := teamconsent.Fingerprint(pins.Publisher); err == nil {
		values["publisher"] = fp
	}
	if config, err := directory.NewConfigWithWriterACL(*pins); err == nil {
		return values, config.Genesis().Scope
	}
	return values, ""
}
func readJSON(path string, value any) error {
	raw, err := teamfiles.Read(path, 64<<10, true)
	if err != nil {
		return err
	}
	return teamfiles.JSON(raw, value)
}
func writeJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return teamfiles.ErrFile
	}
	return teamfiles.WriteNew(path, raw)
}
func serviceRecord(path string) (teamclient.SequencerDescriptor, error) {
	var d teamclient.SequencerDescriptor
	if readJSON(path, &d) != nil {
		return d, teamfiles.ErrFile
	}
	if _, err := teamconsent.Fingerprint(d.Signing); err != nil {
		return d, err
	}
	return d, nil
}
func trustedPins(path string) (directory.Pins, *directory.Config, error) {
	var p directory.Pins
	if readJSON(path, &p) != nil || len(p.Owners) != 1 {
		return p, nil, teamfiles.ErrFile
	}
	c, err := directory.NewConfigWithWriterACL(p)
	return p, c, err
}
func run(ctx context.Context, args []string, out io.Writer, service bool, rt runtime) error {
	if len(args) == 0 || len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		usage := OwnerUsage
		if service {
			usage = ServiceUsage
		}
		_, err := io.WriteString(out, usage)
		if err != nil {
			return failure{1, "output"}
		}
		return nil
	}
	if len(args) > 40 {
		return failure{2, "arguments"}
	}
	for _, arg := range args {
		if len(arg) > 4096 {
			return failure{2, "arguments"}
		}
	}
	name := args[0]
	f := flag.NewFlagSet("team-bootstrap", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	specified := map[string]bool{}
	str := func(flagName string) *string {
		value := new(string)
		f.Func(flagName, "absolute reviewed path or bounded public value", func(input string) error {
			if specified[flagName] {
				return errors.New("duplicate bootstrap option")
			}
			specified[flagName] = true
			*value = input
			return nil
		})
		return value
	}
	profile := str("profile")
	var publicOut, pinsOut, anchor, serviceFile, expected, pinsFile, artifact, directoryFile, endpoint, ca, listen, cert, key *string
	switch {
	case service && name == "prepare-identity":
		publicOut = str("public-out")
	case !service && name == "create":
		anchor = str("anchor")
		serviceFile = str("service")
		expected = str("expect-sequencer-fingerprint")
		pinsOut = str("pins-out")
	case !service && name == "export-initial":
		artifact = str("out")
	case !service && name == "fetch-initial":
		endpoint = str("endpoint")
		ca = str("ca")
	case service && (name == "initialize" || name == "reconcile-initialize"):
		serviceFile = str("service")
		pinsFile = str("trusted-pins")
		expected = str("expect-owner-fingerprint")
		artifact = str("artifact")
		directoryFile = str("directory")
		anchor = str("anchor")
	case service && name == "serve-profile":
		serviceFile = str("service")
		pinsFile = str("trusted-pins")
		listen = str("listen")
		cert = str("certificate")
		key = str("tls-key")
	case name == "status":
		if service {
			publicOut = str("public-out")
		} else {
			pinsOut = str("pins-out")
		}
	case name == "reconcile-protection":
	default:
		return failure{2, "arguments"}
	}
	parsed := f.Parse(args[1:])
	if errors.Is(parsed, flag.ErrHelp) {
		f.SetOutput(out)
		f.PrintDefaults()
		return nil
	}
	if parsed != nil || f.NArg() != 0 || !teamfiles.ValidPath(*profile) {
		return failure{2, "arguments"}
	}
	for name, value := range map[string]*string{"public-out": publicOut, "pins-out": pinsOut, "ca": ca} {
		if value != nil && specified[name] && *value == "" {
			return failure{2, "arguments"}
		}
	}
	for _, p := range []*string{publicOut, pinsOut, anchor, serviceFile, pinsFile, artifact, directoryFile, cert, key} {
		if p != nil && !(name == "status" && *p == "") && !teamfiles.ValidPath(*p) {
			return failure{2, "arguments"}
		}
	}
	if name == "status" {
		// Status may omit the optional re-export path.
		return status(ctx, *profile, out, service, publicOut, pinsOut, false, rt)
	}
	if name == "reconcile-protection" {
		return status(ctx, *profile, out, service, nil, nil, true, rt)
	}
	switch name {
	case "prepare-identity":
		if teamfiles.CheckNew(*profile) != nil || teamfiles.CheckNew(*publicOut) != nil || !teamfiles.Distinct(*profile, *profile+".identity-lease", *publicOut) {
			return failure{1, "prepare"}
		}
		if ctx.Err() != nil {
			return failure{1, "prepare"}
		}
		plan, err := teamclient.PrepareSequencer(*profile)
		if err != nil {
			return refused("prepare", err, false)
		}
		defer plan.Close()
		d, err := plan.Protect(ctx, rt.store())
		if err != nil {
			return refused("protect", err, d.State == teamclient.BootstrapUnknown)
		}
		if err = writeJSON(*publicOut, d); err != nil {
			return refused("public-export", err, errors.Is(err, teamfiles.ErrPublicationUnknown))
		}
		fps, scope := fingerprints(d.Signing, nil)
		return emitReceipt(out, receipt{Command: name, State: d.State, Fingerprints: fps, Scope: scope})
	case "create":
		d, err := serviceRecord(*serviceFile)
		if err != nil {
			return failure{1, "service-record"}
		}
		if !teamconsent.ValidFingerprint(*expected) {
			return failure{2, "trust"}
		}
		if !teamfiles.Distinct(*profile, *profile+".identity-lease", *anchor, *serviceFile, *pinsOut) || teamfiles.CheckNew(*profile) != nil || teamfiles.CheckNew(*anchor) != nil || teamfiles.CheckNew(*pinsOut) != nil {
			return failure{1, "prepare"}
		}
		if rt.confirm(ctx, "sequencer", d.Signing, "", *expected) != nil || ctx.Err() != nil {
			return failure{1, "trust"}
		}
		plan, err := teamclient.PrepareOwnerBootstrap(*profile, d, *anchor)
		if err != nil {
			return refused("prepare", err, false)
		}
		defer plan.Close()
		owner, err := plan.Protect(ctx, rt.store())
		if err != nil {
			return refused("protect", err, owner.State == teamclient.BootstrapUnknown)
		}
		if err = writeJSON(*pinsOut, owner.Pins); err != nil {
			return refused("pins-export", err, false)
		}
		fps, scope := fingerprints(owner.Pins.Sequencer, &owner.Pins)
		return emitReceipt(out, receipt{Command: name, State: owner.State, Fingerprints: fps, Scope: scope})
	case "export-initial":
		owner, err := teamclient.OpenOwnerBootstrap(*profile)
		if err != nil {
			return refused("profile", err, false)
		}
		defer owner.Close()
		if teamfiles.CheckNew(*artifact) != nil || !teamfiles.Distinct(*profile, *profile+".identity-lease", owner.Descriptor().Anchor, *artifact) {
			return failure{1, "artifact-export"}
		}
		a, err := owner.BuildInitial(ctx, rt.store())
		if err != nil {
			return refused("build-initial", err, false)
		}
		raw, err := teamclient.EncodeBootstrapArtifact(a)
		if err != nil {
			return refused("artifact", err, false)
		}
		if err = teamfiles.WriteNew(*artifact, raw); err != nil {
			return refused("artifact-export", err, false)
		}
		return emit(out, name, teamclient.BootstrapPending)
	case "initialize", "reconcile-initialize":
		d, err := serviceRecord(*serviceFile)
		if err != nil {
			return failure{1, "service-record"}
		}
		p, c, err := trustedPins(*pinsFile)
		if err != nil || p.Sequencer != d.Signing {
			return failure{1, "pins"}
		}
		if !teamconsent.ValidFingerprint(*expected) {
			return failure{2, "trust"}
		}
		if !teamfiles.Distinct(*profile, *profile+".identity-lease", *serviceFile, *pinsFile, *artifact, *directoryFile, *anchor) {
			return failure{1, "paths"}
		}
		raw, err := teamfiles.Read(*artifact, teamclient.MaxBootstrapArtifactBytes, true)
		if err != nil {
			return failure{1, "artifact"}
		}
		a, err := teamclient.DecodeBootstrapArtifact(raw)
		if err != nil {
			return failure{1, "artifact"}
		}
		if rt.confirm(ctx, "owner", p.Owners[0], c.Genesis().Scope, *expected) != nil || ctx.Err() != nil {
			return failure{1, "trust"}
		}
		q := teamclient.ServiceInitRequest{Expected: d, TrustedPins: p, Artifact: a, Directory: *directoryFile, Anchor: *anchor}
		var result teamclient.InitResult
		if name == "initialize" {
			result, err = teamclient.InitializeService(ctx, *profile, q, rt.store())
		} else {
			result, err = teamclient.ReconcileServiceInitialization(ctx, *profile, q, rt.store())
		}
		if err != nil {
			return refused("initialize", err, result.State == teamclient.BootstrapUnknown)
		}
		if result.State != teamclient.BootstrapActive {
			return failure{3, "initialize"}
		}
		return emit(out, name, result.State)
	case "fetch-initial":
		if endpoint == nil || ca == nil || len(*endpoint) > 2048 {
			return failure{2, "endpoint"}
		}
		u, err := url.Parse(*endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" {
			return failure{2, "endpoint"}
		}
		var roots *x509.CertPool
		if *ca != "" {
			raw, err := teamfiles.Read(*ca, 1<<20, false)
			if err != nil {
				return failure{1, "tls-roots"}
			}
			roots = x509.NewCertPool()
			if !roots.AppendCertsFromPEM(raw) {
				return failure{1, "tls-roots"}
			}
		}
		d, err := teamclient.ReadOwnerDescriptor(*profile)
		if err != nil {
			return refused("profile", err, false)
		}
		result, err := teamclient.ConfirmInitial(ctx, *profile, d.Pins, rt.store(), teamsync.Endpoint{URL: *endpoint, Roots: roots})
		if err != nil {
			return refused("fetch-initial", err, result.State == teamclient.BootstrapUnknown)
		}
		if result.State != teamclient.BootstrapActive {
			return failure{3, "fetch-initial"}
		}
		return emit(out, name, result.State)
	case "serve-profile":
		return serve(ctx, *profile, *serviceFile, *pinsFile, *listen, *cert, *key, out, rt)
	}
	return failure{2, "arguments"}
}

func status(ctx context.Context, path string, out io.Writer, service bool, publicOut, pinsOut *string, reconcile bool, rt runtime) error {
	st, err := teamclient.ReadBootstrapStatus(path)
	if err != nil {
		return refused("status", err, false)
	}
	if service && st.Kind != "sequencer" || !service && st.Kind != "owner" {
		return failure{1, "profile-kind"}
	}
	if reconcile {
		st, err = teamclient.ReconcileProtection(ctx, path, rt.store())
		if err != nil {
			return refused("reconcile-protection", err, true)
		}
	}
	if publicOut != nil && *publicOut != "" {
		paths := []string{path, path + ".identity-lease", *publicOut}
		if st.Initialization != nil {
			paths = append(paths, st.Initialization.Directory, st.Initialization.Anchor)
		}
		if st.Sequencer == nil || !teamfiles.Distinct(paths...) {
			return failure{1, "public-export"}
		}
		if err = writeJSON(*publicOut, *st.Sequencer); err != nil {
			return refused("public-export", err, false)
		}
	}
	if pinsOut != nil && *pinsOut != "" {
		if st.Owner == nil || !teamfiles.Distinct(path, path+".identity-lease", st.Owner.Anchor, *pinsOut) {
			return failure{1, "pins-export"}
		}
		if err = writeJSON(*pinsOut, st.Owner.Pins); err != nil {
			return refused("pins-export", err, false)
		}
	}
	command := "status"
	if reconcile {
		command = "reconcile-protection"
	}
	receipt := struct {
		Command      string                     `json:"command"`
		Verified     bool                       `json:"verified"`
		Record       teamclient.BootstrapStatus `json:"record"`
		Fingerprints map[string]string          `json:"fingerprints"`
		Scope        string                     `json:"scope,omitempty"`
	}{Command: command, Verified: false, Record: st}
	if st.Sequencer != nil {
		receipt.Fingerprints, receipt.Scope = fingerprints(st.Sequencer.Signing, nil)
	}
	if st.Owner != nil {
		receipt.Fingerprints, receipt.Scope = fingerprints(st.Owner.Pins.Sequencer, &st.Owner.Pins)
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return failure{1, "output"}
	}
	return nil
}

func serve(ctx context.Context, profile, serviceFile, pinsFile, listen, certFile, keyFile string, out io.Writer, rt runtime) error {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return failure{2, "listen"}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return failure{2, "listen"}
	}
	if !teamfiles.Distinct(profile, profile+".identity-lease", serviceFile, pinsFile, certFile, keyFile) {
		return failure{1, "paths"}
	}
	d, err := serviceRecord(serviceFile)
	if err != nil {
		return failure{1, "service-record"}
	}
	p, _, err := trustedPins(pinsFile)
	if err != nil || p.Sequencer != d.Signing {
		return failure{1, "pins"}
	}
	cert, err := teamfiles.Read(certFile, 1<<20, false)
	if err != nil {
		return failure{1, "tls-files"}
	}
	key, err := teamfiles.Read(keyFile, 1<<20, true)
	if err != nil {
		return failure{1, "tls-files"}
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return failure{1, "tls-files"}
	}
	op, err := teamclient.OpenService(ctx, profile, d, p, rt.store())
	if err != nil {
		return refused("service-open", err, false)
	}
	defer op.Close()
	if ctx.Err() != nil {
		return failure{1, "service-open"}
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return failure{1, "listen"}
	}
	defer listener.Close()
	bound, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return failure{1, "listen"}
	}
	server := &http.Server{Handler: op.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0), TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	defer server.Close()
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(listener, config)) }()
	if err = emitReceipt(out, receipt{Command: "serve-profile", State: teamclient.BootstrapActive, Listen: bound.String()}); err != nil {
		return err
	}
	select {
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return failure{1, "serve"}
		}
		return nil
	case <-ctx.Done():
		op.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return nil
	}
}
