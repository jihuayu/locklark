//go:build linux || darwin

package browserhost

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

// cliRunV2SendRaw opens one fresh v2 connection, reads the challenge, then
// writes exactly the frame build returns. It requires the broker to answer with
// a fixed "refused" reply.
func cliRunV2SendRaw(t *testing.T, endpoint string, build func(CLIRunV2Challenge) []byte) {
	t.Helper()
	conn := cliRunV2Dial(t, endpoint)
	defer conn.Close()
	if e := writeFrame(conn, []byte(`{"v":2,"mode":"cli-run"}`)); e != nil {
		t.Fatal(e)
	}
	ch := cliRunV2ReadChallenge(t, conn)
	raw := build(ch)
	if e := writeFrame(conn, raw); e != nil {
		t.Fatal(e)
	}
	clear(raw)
	out, e := readFrame(conn, MaxOutput)
	if e != nil {
		t.Fatalf("no refusal frame: %v", e)
	}
	defer clear(out)
	var reply CLIRunV2Reply
	if json.Unmarshal(out, &reply) != nil || reply.Error != "refused" {
		t.Fatalf("wire frame was not refused: %s", out)
	}
}

// TestCLIRunV2SpecFingerprintRefusedWithoutCallback is the mixed CLI/desktop
// regression: a client and a broker that resolve the same profile name may hold
// different built-in contents while agreeing on the old versioned spec id. The
// canonical spec digest must separate them before any callback or authority.
func TestCLIRunV2SpecFingerprintRefusedWithoutCallback(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, &calls),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	params := cliRunV2Params(t, s, targets)

	spec, ok := lookupCLIRunV2Profile(params.ProfileID)
	if !ok || spec.ID == "" {
		t.Fatalf("builtin %q missing", params.ProfileID)
	}
	localDigest := cliRunV2SpecDigest(spec)
	changed := cliprofile.CloneSpec(spec)
	changed.MaxTimeout += 60
	changedDigest := cliRunV2SpecDigest(changed)
	if localDigest == "" || changedDigest == localDigest {
		t.Fatal("fixture did not change the canonical spec digest")
	}

	refuse := func(mutate func(*CLIRunV2Request)) {
		cliRunV2SendRaw(t, endpoint, func(ch CLIRunV2Challenge) []byte {
			req := buildCLIRunV2Request(params, ch.Nonce, ch.Epoch)
			mutate(&req)
			raw, e := json.Marshal(req)
			if e != nil {
				t.Fatal(e)
			}
			return raw
		})
	}
	// Same profile name and the same old versioned spec id, different contents.
	refuse(func(r *CLIRunV2Request) { r.SpecDigest = changedDigest })
	refuse(func(r *CLIRunV2Request) { r.SpecID = r.SpecID + "-previous" })
	refuse(func(r *CLIRunV2Request) { r.SpecID = "" })
	refuse(func(r *CLIRunV2Request) { r.SpecDigest = "" })
	refuse(func(r *CLIRunV2Request) { r.SpecDigest = strings.ToUpper(r.SpecDigest) })
	refuse(func(r *CLIRunV2Request) { r.SpecDigest = r.SpecDigest[:62] })
	refuse(func(r *CLIRunV2Request) { r.SpecDigest = strings.Repeat("z", 64) })
	refuse(func(r *CLIRunV2Request) { r.SpecID = "docker-config-v1\u202Eevil" })
	refuse(func(r *CLIRunV2Request) { r.SpecDigest = "docker\u2066config" })
	if got := calls.Load(); got != 0 {
		t.Fatalf("spec fingerprint mismatch reached the approval callback %d times", got)
	}
	if got := cliRunV2RunBundleIntents(t, s); got != 0 {
		t.Fatalf("spec fingerprint mismatch committed %d run bundle intents", got)
	}

	// The matching local built-in still passes end to end.
	conn := cliRunV2Dial(t, endpoint)
	defer conn.Close()
	if e := writeFrame(conn, []byte(`{"v":2,"mode":"cli-run"}`)); e != nil {
		t.Fatal(e)
	}
	ch := cliRunV2ReadChallenge(t, conn)
	raw, e := json.Marshal(buildCLIRunV2Request(params, ch.Nonce, ch.Epoch))
	if e != nil {
		t.Fatal(e)
	}
	if e = writeFrame(conn, raw); e != nil {
		t.Fatal(e)
	}
	clear(raw)
	out, e := readFrame(conn, MaxOutput)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(out)
	var reply CLIRunV2Reply
	if json.Unmarshal(out, &reply) != nil || reply.Error != "" || string(reply.Values["password"]) != "v2-pass" {
		t.Fatalf("matching spec fingerprint refused: %s", out)
	}
	wipeCLIRunV2Values(reply.Values)
	if got := calls.Load(); got != 1 {
		t.Fatalf("matching spec fingerprint callback count %d", got)
	}
}

// TestCLIRunV2StrictJSONRejectsTagAliases proves the scanner refuses any key
// that is not the exact JSON tag spelling, including case-fold duplicates that
// the Go decoder would happily bind to the same struct field.
func TestCLIRunV2StrictJSONRejectsTagAliases(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, &calls),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	params := cliRunV2Params(t, s, targets)

	send := func(mutate func([]byte, CLIRunV2Challenge) []byte) {
		cliRunV2SendRaw(t, endpoint, func(ch CLIRunV2Challenge) []byte {
			return mutate(cliRunV2RequestBytes(t, params, ch), ch)
		})
	}
	replace := func(raw []byte, old, new string) []byte {
		return bytes.Replace(raw, []byte(old), []byte(new), 1)
	}
	noncePair := func(ch CLIRunV2Challenge) (string, string) {
		return `"nonce":"` + ch.Nonce + `"`, ch.Nonce
	}

	for _, mutate := range map[string]func([]byte, CLIRunV2Challenge) []byte{
		"single nonce alias": func(raw []byte, ch CLIRunV2Challenge) []byte {
			old, nonce := noncePair(ch)
			return replace(raw, old, `"Nonce":"`+nonce+`"`)
		},
		"nonce plus alias duplicate": func(raw []byte, ch CLIRunV2Challenge) []byte {
			old, nonce := noncePair(ch)
			return replace(raw, old, old+`,"Nonce":"`+nonce+`"`)
		},
		"version alias": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"v":2`, `"V":2`)
		},
		"epoch alias": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"epoch":`, `"Epoch":`)
		},
		"profile id alias": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"profile_id":`, `"Profile_ID":`)
		},
		"spec digest alias": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"spec_digest":`, `"Spec_Digest":`)
		},
		"nested target id alias": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"id":`, `"ID":`)
		},
		"nested target revision alias": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"revision":`, `"Revision":`)
		},
		"nested target slot alias": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"slot":`, `"Slot":`)
		},
		"nested target case-fold duplicate": func(raw []byte, _ CLIRunV2Challenge) []byte {
			return replace(raw, `"slot":"username"`, `"slot":"username","Slot":"username"`)
		},
	} {
		send(mutate)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("aliased request reached the approval callback %d times", got)
	}
}

// TestCLIRunV2HelloAliasesRefused proves the v2 selector accepts only the exact
// {v,mode} spelling and never falls back to a legacy mode.
func TestCLIRunV2HelloAliasesRefused(t *testing.T) {
	endpoint := brokerTestSocket(t)
	s, targets := cliRunV2Session(t)
	var calls atomic.Int32
	broker := NewBroker(BrokerCallbacks{
		CurrentSession:  func() (*personal.Session, uint64, bool) { return s, 1, s.Unlocked() },
		PrepareCLIRunV2: cliRunV2GrantCallback(s, &calls),
	})
	if e := broker.Start(endpoint); e != nil {
		t.Fatal(e)
	}
	defer broker.Close()
	_ = targets

	for _, hello := range []string{
		`{"V":2,"mode":"cli-run"}`,
		`{"v":2,"Mode":"cli-run"}`,
		`{"v":2,"v":2,"mode":"cli-run"}`,
		`{"v":2,"mode":"cli-run","browser":""}`,
		`{"v":2,"mode":"cli-run","origin":""}`,
	} {
		conn := cliRunV2Dial(t, endpoint)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if e := writeFrame(conn, []byte(hello)); e != nil {
			conn.Close()
			t.Fatal(e)
		}
		raw, e := readFrame(conn, 4096)
		clear(raw)
		conn.Close()
		if e == nil {
			t.Fatalf("aliased hello answered: %s", hello)
		}
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("aliased hello reached the approval callback %d times", got)
	}
}

// TestCLIRunV2DecodeWipesValuesOnMalformedReply keeps the cleanup guarantee for
// a reply the decoder has partially populated: base64 value bytes that were
// already allocated must be zeroed before the zero reply is returned.
func TestCLIRunV2DecodeWipesValuesOnMalformedReply(t *testing.T) {
	nonce := strings.Repeat("a", cliRunV2NonceHexLen)
	receipt := `"receipt":{"session":"` + strings.Repeat("a", 32) + `","intent":"` + strings.Repeat("b", 64) + `","target_digest":"` + strings.Repeat("c", 64) + `"}`
	head := `{"v":2,"nonce":"` + nonce + `","epoch":1,"scope_digest":"` + strings.Repeat("d", 64) + `",` + receipt

	for name, raw := range map[string]string{
		// The scanner passes, the decoder fails on the second value after it has
		// already allocated the first one.
		"type mismatch after values": head + `,"values":{"password":"cGFzcw==","username":123}}`,
	} {
		var retained [][]byte
		sawBytes := false
		cliRunV2ReplyDecodeProbe = func(values map[string][]byte) {
			for _, value := range values {
				retained = append(retained, value)
				for _, b := range value {
					if b != 0 {
						sawBytes = true
					}
				}
			}
		}
		if _, e := decodeCLIRunV2Reply([]byte(raw)); e == nil {
			cliRunV2ReplyDecodeProbe = nil
			t.Fatalf("%s: malformed reply accepted", name)
		}
		cliRunV2ReplyDecodeProbe = nil
		if !sawBytes {
			t.Fatalf("%s: probe did not observe decoder-allocated value bytes", name)
		}
		cliRunV2NeedZeroed(t, retained)
	}

	// Aliased reply keys are refused by the exact schema before any decode, so
	// no value is ever allocated.
	for _, raw := range []string{
		head + `,"values":{"username":"dXNlcg=="},"Nonce":"` + nonce + `"}`,
		`{"v":2,"Nonce":"` + nonce + `","epoch":1,"scope_digest":"` + strings.Repeat("d", 64) + `",` + receipt + `,"values":{"username":"dXNlcg=="}}`,
		`{"v":2,"nonce":"` + nonce + `","epoch":1,"scope_digest":"` + strings.Repeat("d", 64) + `","Receipt":{"session":"` + strings.Repeat("a", 32) + `","intent":"` + strings.Repeat("b", 64) + `","target_digest":"` + strings.Repeat("c", 64) + `"}}`,
	} {
		var retained [][]byte
		cliRunV2ReplyDecodeProbe = func(values map[string][]byte) {
			for _, value := range values {
				retained = append(retained, value)
			}
		}
		if _, e := decodeCLIRunV2Reply([]byte(raw)); e == nil {
			cliRunV2ReplyDecodeProbe = nil
			t.Fatalf("aliased reply accepted: %s", raw)
		}
		cliRunV2ReplyDecodeProbe = nil
		if len(retained) != 0 {
			cliRunV2NeedZeroed(t, retained)
		}
	}

	// A challenge must also reject aliased keys.
	if _, e := decodeCLIRunV2Challenge([]byte(`{"v":2,"Nonce":"` + nonce + `","epoch":1}`)); e == nil {
		t.Fatal("aliased challenge accepted")
	}
	if _, e := decodeCLIRunV2Challenge([]byte(`{"V":2,"nonce":"` + nonce + `","epoch":1}`)); e == nil {
		t.Fatal("aliased challenge version accepted")
	}
}

// TestCLIRunV2ExactSchemaKeepsDynamicMaps proves the exact-tag scanner still
// accepts caller-chosen dynamic keys: upper-case passthrough env names and the
// slot-keyed values map, while a case-fold duplicate inside a dynamic map is
// still refused.
func TestCLIRunV2ExactSchemaKeepsDynamicMaps(t *testing.T) {
	s, targets := cliRunV2Session(t)
	params := cliRunV2Params(t, s, targets)
	params.Passthrough = map[string]string{"DOCKER_HOST": "tcp://127.0.0.1:2375", "DOCKER_CERT_PATH": "/tmp/certs"}
	request := buildCLIRunV2Request(params, strings.Repeat("a", cliRunV2NonceHexLen), 3)
	if !validCLIRunV2Wire(request) {
		t.Fatal("upper-case passthrough env names rejected by the wire gate")
	}
	raw, e := json.Marshal(request)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	var back CLIRunV2Request
	if !strictCLIRunV2Object(raw, &back) || back.Passthrough["DOCKER_HOST"] != "tcp://127.0.0.1:2375" || back.Passthrough["DOCKER_CERT_PATH"] != "/tmp/certs" {
		t.Fatal("exact schema did not preserve the upper-case passthrough map")
	}

	receipt := &CLIRunV2Receipt{Session: strings.Repeat("a", 32), Intent: strings.Repeat("b", 64), TargetDigest: strings.Repeat("c", 64)}
	replyRaw, e := json.Marshal(CLIRunV2Reply{V: cliRunV2Version, Nonce: request.Nonce, Epoch: request.Epoch, ScopeDigest: strings.Repeat("d", 64), Receipt: receipt, Values: map[string][]byte{"USERNAME_SLOT": []byte("u"), "password": []byte("p")}})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(replyRaw)
	var reply CLIRunV2Reply
	if !strictCLIRunV2Object(replyRaw, &reply) || string(reply.Values["USERNAME_SLOT"]) != "u" || string(reply.Values["password"]) != "p" {
		t.Fatal("exact schema did not preserve slot-keyed values")
	}
	wipeCLIRunV2Values(reply.Values)

	folded := bytes.Replace(raw, []byte(`"DOCKER_HOST":"tcp://127.0.0.1:2375"`), []byte(`"DOCKER_HOST":"tcp://127.0.0.1:2375","docker_host":"tcp://127.0.0.1:2375"`), 1)
	if bytes.Equal(folded, raw) {
		t.Fatal("duplicate-key fixture did not apply")
	}
	defer clear(folded)
	var dup CLIRunV2Request
	if strictCLIRunV2Object(folded, &dup) {
		t.Fatal("case-fold duplicate passthrough keys accepted")
	}
}
