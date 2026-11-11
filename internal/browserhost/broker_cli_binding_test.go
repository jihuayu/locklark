//go:build linux || darwin

package browserhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

// cliRunExchangeID numbers every exchange so each one carries a nonce the
// process-wide replay cache has never seen.
var cliRunExchangeID atomic.Uint64

// cliRunBoundReply drives one complete CLI-run exchange over a net.Pipe
// transport: it writes the encoded fixture request frame on the client side,
// serves exactly that frame through serveCLIRun with the test terminal gate,
// and returns the exact reply bytes. Each exchange uses a fresh nonce. Both
// the write and the response read are bounded by a deadline, so a stalled
// protocol fails the test instead of blocking it. Gate and callbacks are
// installed only for this test.
func cliRunBoundReply(t *testing.T, gate func(Peer, string, string, string) error, callbacks BrokerCallbacks) string {
	t.Helper()
	oldGate := cliRunTTYGate
	cliRunTTYGate = gate
	t.Cleanup(func() { cliRunTTYGate = oldGate })
	server, client := net.Pipe()
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	if e := client.SetDeadline(deadline); e != nil {
		t.Fatal(e)
	}
	req := cliRunFixtureRequest()
	req.Scope.Nonce = fmt.Sprintf("%064x", cliRunExchangeID.Add(1))
	frame, e := json.Marshal(req)
	if e != nil {
		t.Fatal(e)
	}
	written := make(chan error, 1)
	go func() {
		e := writeFrame(client, frame)
		clear(frame)
		written <- e
	}()
	b := NewBroker(callbacks)
	replied := make(chan struct{})
	go func() {
		defer close(replied)
		b.serveCLIRun(server, Peer{User: "UID 501"})
	}()
	select {
	case e := <-written:
		if e != nil {
			t.Fatalf("request write: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request frame was not consumed by serveCLIRun")
	}
	raw, e := readFrame(client, MaxOutput)
	if e != nil {
		t.Fatalf("reply read: %v", e)
	}
	defer clear(raw)
	select {
	case <-replied:
	case <-time.After(5 * time.Second):
		t.Fatal("serveCLIRun did not return after the reply")
	}
	return string(raw)
}

func cliRunPassingGate(Peer, string, string, string) error { return nil }

// TestCLIRunCallbackSlotsBoundToRequestedTargets proves the serving callback
// boundary binds PreparedValues to the exact requested slots: an extra slot, a
// missing slot, and a nil buffer are the fixed refusal and never reach the
// wire, and every callback buffer handed over under a slot key is zeroed.
func TestCLIRunCallbackSlotsBoundToRequestedTargets(t *testing.T) {
	receipt := cliRunReceiptFromFixture(t)
	cases := []struct {
		name    string
		prepare func(token, extra []byte) (map[string][]byte, []*[]byte)
	}{
		{"extra-slot", func(token, extra []byte) (map[string][]byte, []*[]byte) {
			return map[string][]byte{"token": token, "other": extra}, []*[]byte{&token, &extra}
		}},
		{"missing-slot", func(_, extra []byte) (map[string][]byte, []*[]byte) {
			// No buffer for the requested "token" slot at all.
			return map[string][]byte{"other": extra}, []*[]byte{&extra}
		}},
		{"nil-value", func(token, _ []byte) (map[string][]byte, []*[]byte) {
			return map[string][]byte{"token": nil}, nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			token := append([]byte(nil), "callback-token-bytes"...)
			extra := append([]byte(nil), "callback-extra-bytes"...)
			var handed []*[]byte
			got := cliRunBoundReply(t, cliRunPassingGate, BrokerCallbacks{
				HandleCLIRun: func(context.Context, Peer, CLIRunBrokerRequest) (BrokerCLIResponse, error) {
					values, buffers := c.prepare(token, extra)
					handed = buffers
					return BrokerCLIResponse{V: 1, PreparedValues: values, Receipt: receipt}, nil
				},
			})
			if got != `{"v":1,"error":"refused"}` {
				t.Fatalf("unbound reply wrote %s", got)
			}
			if bytes.Contains([]byte(got), token) || bytes.Contains([]byte(got), extra) || bytes.Contains([]byte(got), []byte("callback-")) {
				t.Fatal("refused reply carried callback bytes")
			}
			for _, buffer := range handed {
				if !bytes.Equal(*buffer, make([]byte, len(*buffer))) {
					t.Fatalf("callback buffer not zeroed: %q", *buffer)
				}
			}
		})
	}
	// The exact requested set is still the audited success.
	got := cliRunBoundReply(t, cliRunPassingGate, BrokerCallbacks{
		HandleCLIRun: func(context.Context, Peer, CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			return BrokerCLIResponse{V: 1, PreparedValues: map[string][]byte{"token": []byte("exact")}, Receipt: receipt}, nil
		},
	})
	if got != cliRunAuditedReply("token", "ZXhhY3Q=") {
		t.Fatalf("bound reply wrote %s", got)
	}
}

// TestCLIRunMissingHandlerAfterTTYGate proves a nil HandleCLIRun never
// short-circuits the nonce and the peer terminal gate: an unsupported,
// unattested, or mismatching terminal is the fixed refusal even when no
// callback exists.
func TestCLIRunMissingHandlerAfterTTYGate(t *testing.T) {
	gates := map[string]func(Peer, string, string, string) error{
		// The unsupported sentinel errCLIRunUnavailable must not become the
		// fallback-eligible unavailable token.
		"unsupported": func(Peer, string, string, string) error { return errCLIRunUnavailable },
		"unattested":  func(Peer, string, string, string) error { return errCLIRunInvalid },
		"mismatched": func(_ Peer, tty, platform, peerID string) error {
			if tty != cliRunFixtureScope().TTY || platform != testGOOS || peerID != "" {
				t.Error("gate did not receive the declared scope")
			}
			return errCLIRunInvalid
		},
	}
	for name, gate := range gates {
		t.Run(name, func(t *testing.T) {
			got := cliRunBoundReply(t, gate, BrokerCallbacks{})
			if got != `{"v":1,"error":"refused"}` {
				t.Fatalf("no handler, %s gate wrote %s", name, got)
			}
		})
	}
}

// TestCLIRunNoHandlerAfterPassingGateIsUnavailable drives a real serveCLIRun
// exchange with a passing terminal gate and no HandleCLIRun at all, and
// asserts the late missing-handler branch itself returns the exact
// unavailable classification.
func TestCLIRunNoHandlerAfterPassingGateIsUnavailable(t *testing.T) {
	got := cliRunBoundReply(t, cliRunPassingGate, BrokerCallbacks{})
	if got != `{"v":1,"error":"unavailable"}` {
		t.Fatalf("passing gate with nil handler wrote %s", got)
	}
}

// fixtureValidationSpec is a profile spec with every mutable container
// populated, nested deny-argument slices included.
func fixtureValidationSpec() cliprofile.Spec {
	return cliprofile.Spec{
		ID:             "fixture",
		Slots:          []cliprofile.Slot{{Name: "token", Kind: "login", Field: "password"}},
		Env:            map[string]string{"FIXTURE_ONE": "literal:one"},
		Files:          []cliprofile.FileSpec{{RelPath: "config", Format: "fixture", Mode: 0600}},
		Dirs:           []string{"cache"},
		PassthroughEnv: []string{"FIXTURE_HOST"},
		DenyArgs:       [][]string{{"--deny-one", "--deny-two"}, {"--deny-three"}},
		MaxTimeout:     60,
	}
}

// TestCLIRunValidationCopyCleared proves the clearing helper empties every
// mutable container of the canonical request copy, including the nested
// deny-argument slices, and that validCLIRunRequest mutates neither the
// caller's scope and targets nor the shared built-in profile.
func TestCLIRunValidationCopyCleared(t *testing.T) {
	origins := [][]byte{[]byte("--deny-one"), []byte("--deny-two"), []byte("--deny-three")}
	// Keep independent handles on the container tree so in-place zeroing is
	// observable after the request itself has been zeroed, and prove the tree
	// is a fresh copy the helper owns: no container or nested deny slice is
	// shared with the source spec.
	spec := cliprofile.CloneSpec(fixtureValidationSpec())
	tokenSlot, denyOne, denyTwo, envMap, dirs := &spec.Slots[0], spec.DenyArgs[0], spec.DenyArgs[1], spec.Env, spec.Dirs
	request := personal.RunBundleRequest{
		Program:      "/fixture/bin",
		Args:         []string{"--other"},
		Directory:    "/fixture/work",
		HelperPath:   []string{"/fixture/helper"},
		Passthrough:  map[string]string{"FIXTURE_HOST": "keep"},
		TokenEnvName: "FIXTURE_TOKEN",
		Spec:         cliprofile.CloneSpec(spec),
	}
	requestPassthru, requestHelper, requestArgs := request.Passthrough, request.HelperPath, request.Args
	if &request.Spec.Slots[0] == tokenSlot || &request.Spec.DenyArgs[0][0] == &denyOne[0] {
		t.Fatal("fixture request shares containers with the source spec")
	}
	clearCLIRunValidationRequest(&request)
	if !reflect.DeepEqual(request, personal.RunBundleRequest{}) {
		t.Fatalf("request not zeroed: %#v", request)
	}
	// The request's own slices are blanked in place before being dropped.
	if requestHelper[0] != "" || requestArgs[0] != "" {
		t.Fatalf("request slices not cleared in place: %q %q", requestHelper, requestArgs)
	}
	// The source spec is untouched; only the request's own copy is cleared.
	if !reflect.DeepEqual(spec.Slots[0], (cliprofile.Slot{Name: "token", Kind: "login", Field: "password"})) ||
		envMap["FIXTURE_ONE"] != "literal:one" || denyOne[0] != "--deny-one" || denyTwo[0] != "--deny-three" ||
		len(dirs) != 1 || dirs[0] != "cache" {
		t.Fatalf("source spec modified: %#v", spec)
	}
	// Direct helper check: the request's own copy is emptied in place, nested
	// deny-argument slices included, before the request is zeroed.
	own := cliprofile.CloneSpec(fixtureValidationSpec())
	ownDenyOne, ownDenyTwo := own.DenyArgs[0], own.DenyArgs[1]
	scratch := personal.RunBundleRequest{Args: []string{"--a"}, HelperPath: []string{"/h"}, Passthrough: map[string]string{"X": "y"}, Spec: own}
	clearCLIRunValidationRequest(&scratch)
	if len(own.Slots) != 1 || own.Slots[0] != (cliprofile.Slot{}) || own.Env["FIXTURE_ONE"] != "" ||
		len(own.Files) != 1 || own.Files[0] != (cliprofile.FileSpec{}) || len(own.Dirs) != 1 || own.Dirs[0] != "" ||
		len(own.PassthroughEnv) != 1 || own.PassthroughEnv[0] != "" ||
		len(ownDenyOne) != 2 || ownDenyOne[0] != "" || ownDenyOne[1] != "" || len(ownDenyTwo) != 1 || ownDenyTwo[0] != "" {
		t.Fatalf("spec containers not cleared in place: %#v %#v", own, ownDenyOne)
	}
	// Immutable string bytes are documented as unwipable; only the containers
	// holding them are cleared, so a still-referenced string keeps its bytes.
	for _, origin := range origins {
		if len(origin) == 0 {
			t.Fatal("clearing tried to wipe immutable string bytes")
		}
	}
	clearCLIRunValidationRequest(nil)
	// A caller's own request tree is untouched.
	other := personal.RunBundleRequest{Args: []string{"--keep"}, Passthrough: map[string]string{"FIXTURE_HOST": "keep"}, Spec: cliprofile.CloneSpec(fixtureValidationSpec())}
	if requestPassthru["FIXTURE_HOST"] == "keep" || len(other.Args) != 1 || other.Args[0] != "--keep" || other.Passthrough["FIXTURE_HOST"] != "keep" || !reflect.DeepEqual(other.Spec, fixtureValidationSpec()) {
		t.Fatal("clearing touched containers outside the request")
	}
	scope := cliRunFixtureScope()
	targets := cliRunFixtureRequest().Targets
	scopeClone, targetsClone := scope.Clone(), append([]personal.CLIBrokerTarget(nil), targets...)
	if !validCLIRunRequest(1, "/fixture/vault.ll", scope, targets) {
		t.Fatal("fixture request rejected")
	}
	if !reflect.DeepEqual(scope, scopeClone) || !reflect.DeepEqual(targets, targetsClone) {
		t.Fatal("validCLIRunRequest modified its caller's request")
	}
	builtin, ok := cliprofile.Lookup("gh")
	if !ok {
		t.Fatal("gh profile missing")
	}
	shared := builtin.Spec()
	if len(shared.Slots) == 0 {
		t.Fatal("built-in profile has no slots")
	}
	if !validCLIRunRequest(1, "/fixture/vault.ll", scope, targets) {
		t.Fatal("second fixture request rejected")
	}
	if !reflect.DeepEqual(builtin.Spec(), shared) {
		t.Fatal("validation cleared a shared built-in profile")
	}
}

// TestCLIRunErrorTokenWhitelist proves only the exact refused and unavailable
// tokens are ever encoded, while arbitrary nonempty error strings fail.
func TestCLIRunErrorTokenWhitelist(t *testing.T) {
	for _, token := range []string{cliRunErrorRefused, cliRunErrorUnavailable} {
		raw, e := marshalCLIRunResponse(CLIRunBrokerResponse{V: 1, Error: token})
		if e != nil || string(raw) != `{"v":1,"error":"`+token+`"}` {
			t.Fatalf("%q wrote %q %v", token, raw, e)
		}
	}
	for _, token := range []string{"secret-token", "Refused", " refused", "refused ", "unavailable!", "error", "\x00"} {
		raw, e := marshalCLIRunResponse(CLIRunBrokerResponse{V: 1, Error: token})
		if !errors.Is(e, errCLIRunResponse) || raw != nil {
			t.Fatalf("%q serialized %q %v", token, raw, e)
		}
	}
	// A callback that returns an arbitrary error still writes the fixed
	// refusal, never the callback's own text.
	got := cliRunBoundReply(t, cliRunPassingGate, BrokerCallbacks{
		HandleCLIRun: func(context.Context, Peer, CLIRunBrokerRequest) (BrokerCLIResponse, error) {
			return BrokerCLIResponse{}, fmt.Errorf("wrapped: %w", errCLIRunInvalid)
		},
	})
	if got != `{"v":1,"error":"refused"}` {
		t.Fatalf("arbitrary callback error wrote %s", got)
	}
	var decoded map[string]any
	if e := json.Unmarshal([]byte(got), &decoded); e != nil || decoded["error"] != cliRunErrorRefused {
		t.Fatalf("decoded reply %#v %v", decoded, e)
	}
}
