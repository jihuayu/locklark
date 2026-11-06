package teambootstrapcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/teamclient"
	"github.com/jihuayu/locklark/internal/teamconsent"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type testStore struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (s *testStore) Store(id string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[id] = bytes.Clone(raw)
	return nil
}
func (s *testStore) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.values[id]
	if !ok {
		return nil, errors.New("not available")
	}
	return bytes.Clone(raw), nil
}
func (s *testStore) Delete(string) error { return errors.New("unexpected identity deletion") }
func protectedService(t *testing.T) (string, teamclient.SequencerDescriptor, *testStore) {
	t.Helper()
	root := t.TempDir()
	plan, err := teamclient.PrepareSequencer(filepath.Join(root, "service.profile"))
	if err != nil {
		t.Fatal("service preparation")
	}
	defer plan.Close()
	store := &testStore{values: map[string][]byte{}}
	d, err := plan.Protect(context.Background(), store)
	if err != nil {
		t.Fatal("service protection")
	}
	path := filepath.Join(root, "service-public.json")
	if writeJSON(path, d) != nil {
		t.Fatal("service public record")
	}
	return path, d, store
}
func TestOwnerTrustRefusalPrecedesIdentityAndOSMutation(t *testing.T) {
	service, d, _ := protectedService(t)
	root := t.TempDir()
	profile, anchor, pins := filepath.Join(root, "owner.profile"), filepath.Join(root, "owner.anchor"), filepath.Join(root, "pins.json")
	fp, _ := teamconsent.Fingerprint(d.Signing)
	var out bytes.Buffer
	calls := 0
	rt := runtime{store: func() teamclient.SystemStore { t.Fatal("OS called before explicit trust"); return nil },
		confirm: func(_ context.Context, role, key, scope, expected string) error {
			calls++
			if role != "sequencer" || key != d.Signing || scope != "" || expected != fp {
				t.Fatal("trust review did not bind independently expected public key")
			}
			return teamconsent.ErrTrust
		}}
	err := run(context.Background(), []string{"create", "--profile", profile, "--anchor", anchor, "--service", service, "--expect-sequencer-fingerprint", fp, "--pins-out", pins}, &out, false, rt)
	if ExitCode(err) != 1 || calls != 1 || out.Len() != 0 {
		t.Fatal("trust refusal not fail closed")
	}
	for _, path := range []string{profile, profile + ".identity-lease", anchor, pins} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("identity mutated before trust")
		}
	}
}
func TestBootstrapRejectsSecretFlagsWithoutEchoOrOSAccess(t *testing.T) {
	for _, service := range []bool{false, true} {
		command := "create"
		if service {
			command = "prepare-identity"
		}
		for _, flag := range []string{"--seed", "--private-key", "--password", "--key-file", "--yes"} {
			var out bytes.Buffer
			err := run(context.Background(), []string{command, flag, "private-input-canary"}, &out, service, runtime{store: func() teamclient.SystemStore { t.Fatal("unexpected OS call"); return nil }})
			if err == nil || ExitCode(err) != 2 || strings.Contains(out.String(), "private-input-canary") || strings.Contains(err.Error(), "private-input-canary") {
				t.Fatal("unsupported secret argument accepted or echoed")
			}
		}
	}
}
func TestRecordedStatusAndReexportNeverLoadsOSOrReplacesFiles(t *testing.T) {
	service, d, store := protectedService(t)
	_ = service
	root := t.TempDir()
	path := filepath.Join(root, "owner.profile")
	plan, err := teamclient.PrepareOwnerBootstrap(path, d, filepath.Join(root, "owner.anchor"))
	if err != nil {
		t.Fatal("owner preparation")
	}
	defer plan.Close()
	owner, err := plan.Protect(context.Background(), store)
	if err != nil {
		t.Fatal("owner protection")
	}
	pins := filepath.Join(root, "pins.json")
	rt := runtime{store: func() teamclient.SystemStore { t.Fatal("readonly status called OS"); return nil }}
	var out bytes.Buffer
	if run(context.Background(), []string{"status", "--profile", path, "--pins-out", pins}, &out, false, rt) != nil {
		t.Fatal("recorded status/reexport failed")
	}
	var receipt struct {
		Verified     bool
		Record       teamclient.BootstrapStatus
		Fingerprints map[string]string
		Scope        string
	}
	if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.Verified || receipt.Record.Kind != "owner" {
		t.Fatal("recorded status claimed fresh verification")
	}
	ownerFingerprint, _ := teamconsent.Fingerprint(owner.Pins.Owners[0])
	config, err := directory.NewConfigWithWriterACL(owner.Pins)
	if err != nil || receipt.Fingerprints["owner"] != ownerFingerprint || len(receipt.Fingerprints) != 3 || receipt.Scope != config.Genesis().Scope {
		t.Fatal("recorded public trust fingerprints unavailable")
	}
	raw, err := teamfiles.Read(pins, 64<<10, true)
	var observed any
	want, _ := json.Marshal(owner.Pins)
	if err != nil || !bytes.Equal(raw, want) || json.Unmarshal(raw, &observed) != nil {
		t.Fatal("reexport changed trusted pins")
	}
	if run(context.Background(), []string{"status", "--profile", path, "--pins-out", pins}, &out, false, rt) == nil {
		t.Fatal("readonly export overwrote existing output")
	}
	if run(context.Background(), []string{"status", "--profile", path}, &out, false, rt) != nil {
		t.Fatal("status without optional output failed")
	}
	if os.Remove(owner.Anchor) != nil {
		t.Fatal("missing anchor setup")
	}
	for _, args := range [][]string{
		{"status", "--profile", path, "--pins-out", owner.Anchor},
		{"export-initial", "--profile", path, "--out", owner.Anchor},
	} {
		if run(context.Background(), args, &out, false, rt) == nil {
			t.Fatal("export wrote into missing reserved anchor")
		}
		if _, err := os.Lstat(owner.Anchor); !os.IsNotExist(err) {
			t.Fatal("export recreated missing anchor path")
		}
	}
}
func TestInitialExportReusesOriginalArtifactAndRefusesOverwrite(t *testing.T) {
	_, d, store := protectedService(t)
	root := t.TempDir()
	path := filepath.Join(root, "owner.profile")
	plan, err := teamclient.PrepareOwnerBootstrap(path, d, filepath.Join(root, "owner.anchor"))
	if err != nil {
		t.Fatal("owner preparation")
	}
	defer plan.Close()
	if _, err = plan.Protect(context.Background(), store); err != nil {
		t.Fatal("owner protection")
	}
	rt := runtime{store: func() teamclient.SystemStore { return store }}
	var out bytes.Buffer
	first, second := filepath.Join(root, "one.json"), filepath.Join(root, "two.json")
	for _, target := range []string{first, second} {
		if run(context.Background(), []string{"export-initial", "--profile", path, "--out", target}, &out, false, rt) != nil {
			t.Fatal("original artifact export failed")
		}
	}
	a, _ := os.ReadFile(first)
	b, _ := os.ReadFile(second)
	if !bytes.Equal(a, b) {
		t.Fatal("reexport rebuilt original artifact")
	}
	if _, err = teamclient.DecodeBootstrapArtifact(a); err != nil {
		t.Fatal("exported artifact invalid")
	}
	if run(context.Background(), []string{"export-initial", "--profile", path, "--out", first}, &out, false, rt) == nil {
		t.Fatal("existing artifact overwritten")
	}
}
func TestBootstrapErrorCodesHaveFixedUnknownAndConflictSemantics(t *testing.T) {
	for _, tc := range []struct {
		err     error
		unknown bool
		code    int
	}{{teamclient.ErrBootstrapUnknown, false, 3}, {teamclient.ErrBootstrapConflict, false, 4}, {teamclient.ErrProtection, false, 1}, {teamclient.ErrCancelled, false, 3}, {teamfiles.ErrPublicationUnknown, false, 3}, {errors.New("private-provider-canary"), true, 3}, {errors.New("private-provider-canary"), false, 1}} {
		err := refused("protect", tc.err, tc.unknown)
		if ExitCode(err) != tc.code || strings.Contains(err.Error(), "private-provider-canary") {
			t.Fatal("error classification leaked provider data or weakened uncertainty")
		}
	}
}

func TestExplicitEmptyPolicyAndRepeatedSelectorsAreUsageErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.profile")
	for _, args := range [][]string{
		{"status", "--profile", path, "--pins-out", ""},
		{"fetch-initial", "--profile", path, "--endpoint", "https://localhost:8443", "--ca", ""},
		{"status", "--profile", path, "--profile", path},
	} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, false, runtime{store: func() teamclient.SystemStore { t.Fatal("invalid policy reached OS"); return nil }})
		if err == nil || ExitCode(err) != 2 || out.Len() != 0 {
			t.Fatal("empty explicit policy or repeated selector silently accepted")
		}
	}
}
