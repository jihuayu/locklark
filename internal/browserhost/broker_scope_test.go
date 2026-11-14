//go:build linux || darwin || windows

package browserhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestCLIRunScope_ValidateInvalid proves every ragged scope fails with the one
// fixed error and that no marker value is echoed into the error text.
func TestCLIRunScope_ValidateInvalid(t *testing.T) {
	tooLong := func(prefix string, n int) string { return prefix + strings.Repeat("x", n) }
	eight := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = cliRunFixturePaths.helper
		}
		return out
	}
	cases := map[string]func(s *CLIRunScope){
		"profile-too-long": func(s *CLIRunScope) { s.Profile = tooLong("p", CLIRunMaxProfile+1) },
		"tty-too-long":     func(s *CLIRunScope) { s.TTY = tooLong(cliRunFixturePaths.tty, CLIRunMaxTTYIdentity) },
		"nonce-bad":        func(s *CLIRunScope) { s.Nonce = "zz" + s.Nonce[2:] },
		"nonce-short":      func(s *CLIRunScope) { s.Nonce = s.Nonce[:30] },
		"program-relative": func(s *CLIRunScope) { s.Program = "fixture/bin/gh" },
		"program-dirty":    func(s *CLIRunScope) { s.Program = cliRunFixturePaths.unclean },
		"program-sha-bad":  func(s *CLIRunScope) { s.ProgramSH = strings.Repeat("A", CLIRunMaxProgramSHA256) },
		"args-too-many":    func(s *CLIRunScope) { s.Args = eight(CLIRunMaxArgs + 1) },
		"args-too-long":    func(s *CLIRunScope) { s.Args = []string{tooLong("a", CLIRunMaxArgBytes+1)} },
		// Five individually valid 4095-byte args (the fixture keeps 5 more
		// bytes, so the total is 20480): no per-argument violation, but the
		// total exceeds the aggregate bound.
		"args-bytes-huge": func(s *CLIRunScope) {
			s.Args = make([]string, 5)
			for i := range s.Args {
				s.Args[i] = strings.Repeat("a", CLIRunMaxArgBytes-1)
			}
		},
		"helper-too-many":  func(s *CLIRunScope) { s.Helper = eight(CLIRunMaxHelperPath + 1) },
		"helper-relative":  func(s *CLIRunScope) { s.Helper = []string{"relative-helper"} },
		"helper-uncleaned": func(s *CLIRunScope) { s.Helper = []string{cliRunFixturePaths.joining} },
		"passthru-too-many": func(s *CLIRunScope) {
			s.Passthru = map[string]string{}
			for i := 0; i < CLIRunMaxPassthrough+1; i++ {
				s.Passthru[string(rune('A'+i))] = "v"
			}
		},
		"passthru-oversize": func(s *CLIRunScope) { s.Passthru["GH_HOST"] = tooLong("v", CLIRunMaxPassthroughVal+1) },
		"passthru-name":     func(s *CLIRunScope) { s.Passthru = map[string]string{"BAD-NAME": "v"} },
		"timeout-zero":      func(s *CLIRunScope) { s.Timeout = 0 },
		"timeout-too-long":  func(s *CLIRunScope) { s.Timeout = CLIRunMaxTimeoutSeconds + 1 },
		"temproot-missing":  func(s *CLIRunScope) { s.TempRoot = "" },
		"temproot-relative": func(s *CLIRunScope) { s.TempRoot = "run-root" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			scope := cliRunFixtureScope()
			mutate(&scope)
			err := ValidateCLIRunScope(scope)
			if !errors.Is(err, errCLIRunInvalid) || err.Error() != "desktop browser broker request invalid" {
				t.Fatalf("got %v, want generic error", err)
			}
			for _, marker := range []string{"zz", "relative-helper", "BAD-NAME", "fixture/bin", "run-root", "fixture-passthrough"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("error echoed %q: %q", marker, err)
				}
			}
		})
	}
}

// TestCLIRunScope_DecodeRejects proves the strict decoder refuses duplicate,
// unknown, trailing, null, empty, and ragged scope objects without echoing them.
func TestCLIRunScope_DecodeRejects(t *testing.T) {
	valid, e := json.Marshal(cliRunFixtureScope())
	if e != nil {
		t.Fatal(e)
	}
	dup := `{"profile":"gh","args":[],` + string(valid[1:])
	unknown := string(valid[:len(valid)-1]) + `,"extra_marker":"unk-marker"}`
	cases := map[string]string{
		"duplicate-args":  dup,
		"unknown-field":   unknown,
		"trailing-json":   string(valid) + `{"profile":"gh"}`,
		"null":            "null",
		"empty-object":    `{}`,
		"malformed-nonce": strings.Replace(string(valid), `"nonce":"0`, `"nonce":"g`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeCLIRunScope([]byte(raw))
			if err == nil {
				t.Fatal("accepted malformed scope")
			}
			if got.Profile != "" || got.Args != nil || got.Passthru != nil {
				t.Fatal("returned a scope on error")
			}
			for _, marker := range []string{"unk-marker", "fixture/bin", "fixture-passthrough", "0123456789abcdef"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("error echoed %q: %q", marker, err)
				}
			}
		})
	}
	if _, err := DecodeCLIRunScope(valid); err != nil {
		t.Fatalf("fixture scope rejected: %v", err)
	}
}

// TestCLIRunScope_Clear proves Clear wipes every decoded field in place, which
// is the mechanism DecodeCLIRunScope relies on for its error paths: the decoder
// only ever decodes into one local scope, and every rejection returns the zero
// value plus that same Clear call.
func TestCLIRunScope_Clear(t *testing.T) {
	s := CLIRunScope{
		Profile: "gh", TTY: cliRunFixturePaths.tty, TTYPeerID: "00000001", TTYPlatform: testGOOS,
		Nonce: strings.Repeat("ab", 16), Program: cliRunFixturePaths.program, ProgramSH: strings.Repeat("ab", 32),
		CWD: cliRunFixturePaths.work, TempRoot: cliRunFixturePaths.runRoot, Timeout: 60,
		TokenEnv: "GH_TOKEN",
		Args:     []string{"--version"}, Helper: []string{cliRunFixturePaths.helper},
		Passthru: map[string]string{"GH_HOST": passthruFixture},
	}
	args, helper, passthru := s.Args, s.Helper, s.Passthru
	s.Clear()
	if s.Profile != "" || s.TTY != "" || s.TTYPeerID != "" || s.TTYPlatform != "" ||
		s.Nonce != "" || s.Program != "" || s.ProgramSH != "" ||
		s.CWD != "" || s.TempRoot != "" || s.Timeout != 0 || s.TokenEnv != "" ||
		s.Args != nil || s.Helper != nil || s.Passthru != nil {
		t.Fatalf("Clear left scope fields behind: %+v", s)
	}
	// The cleared copies belong to the scope, so no shared backing array keeps
	// a value reachable through another owner either.
	if args[0] != "" || helper[0] != "" || len(passthru) != 0 {
		t.Fatalf("Clear left values in the decoded collections: %#v %#v %#v", args, helper, passthru)
	}
}

// argsBytesExact is a scope whose args total exactly CLIRunMaxArgsBytes and
// whose every argument is at most CLIRunMaxArgBytes, so it is refused only if
// the aggregate bound regresses.
func argsBytesExact() CLIRunScope {
	s := cliRunFixtureScope()
	s.Args = nil
	for total := 0; total < CLIRunMaxArgsBytes; total += CLIRunMaxArgBytes {
		n := min(CLIRunMaxArgBytes, CLIRunMaxArgsBytes-total)
		s.Args = append(s.Args, strings.Repeat(string(rune('a'+len(s.Args))), n))
	}
	sum := 0
	for _, arg := range s.Args {
		if len(arg) > CLIRunMaxArgBytes {
			panic("argsBytesExact: argument exceeds the per-argument bound")
		}
		sum += len(arg)
	}
	if sum != CLIRunMaxArgsBytes || len(s.Args) != 4 {
		panic("argsBytesExact: total is not exactly the aggregate bound")
	}
	return s
}

// TestCLIRunScope_Valid proves the fixture scope and its boundary variants are
// accepted, including an args total of exactly CLIRunMaxArgsBytes, and a zero
// scope is not.
func TestCLIRunScope_Valid(t *testing.T) {
	if err := ValidateCLIRunScope(cliRunFixtureScope()); err != nil {
		t.Fatalf("fixture scope rejected: %v", err)
	}
	pinned := cliRunFixtureScope()
	pinned.ProgramSH = strings.Repeat("0123456789abcdef", 4)
	pinned.TTYPeerID = "ffffffff"
	cases := map[string]CLIRunScope{
		"program-pinned":      pinned,
		"minimal-collections": func() CLIRunScope { s := cliRunFixtureScope(); s.Args, s.Helper, s.Passthru = nil, nil, nil; return s }(),
		"max-args":            func() CLIRunScope { s := cliRunFixtureScope(); s.Args = make([]string, CLIRunMaxArgs); return s }(),
		// Exactly CLIRunMaxArgsBytes of individually valid 4095/4096-byte args
		// is the last accepted total; each one passes the per-argument bound.
		"args-bytes-exact": argsBytesExact(),
		"max-helper": func() CLIRunScope {
			s := cliRunFixtureScope()
			s.Helper = make([]string, CLIRunMaxHelperPath)
			for i := range s.Helper {
				s.Helper[i] = cliRunFixturePaths.helper
			}
			return s
		}(),
		"timeout-max": func() CLIRunScope { s := cliRunFixtureScope(); s.Timeout = CLIRunMaxTimeoutSeconds; return s }(),
		"timeout-min": func() CLIRunScope { s := cliRunFixtureScope(); s.Timeout = 1; return s }(),
		"token-env":   func() CLIRunScope { s := cliRunFixtureScope(); s.TokenEnv = "GH_TOKEN"; return s }(),
	}
	for name, scope := range cases {
		if err := ValidateCLIRunScope(scope); err != nil {
			t.Errorf("%s: rejected valid scope", name)
		}
	}
	if err := ValidateCLIRunScope(CLIRunScope{}); err == nil {
		t.Fatal("accepted the zero scope")
	}
}

// TestCLIRunScope_Clone proves Clone shares nothing mutable with its source:
// mutating the clone leaves the source intact, mutating the source leaves the
// clone intact, and nil collections stay nil so the clone validates like the
// source.
func TestCLIRunScope_Clone(t *testing.T) {
	src := cliRunFixtureScope()
	clone := src.Clone()
	if err := ValidateCLIRunScope(clone); err != nil {
		t.Fatalf("clone rejected: %v", err)
	}
	clone.Args[0] = "mutated"
	clone.Helper[0] = "/mutated"
	clone.Passthru["GH_HOST"] = "mutated"
	clone.Passthru["EXTRA"] = "mutated"
	if src.Args[0] != "--hostname" || src.Helper[0] != cliRunFixturePaths.helper ||
		src.Passthru["GH_HOST"] != "fixture-passthrough-"+reqID(5) || len(src.Passthru) != 1 {
		t.Fatalf("clone mutation reached the source: %+v", src)
	}
	src.Args[1] = "mutated"
	delete(src.Passthru, "GH_HOST")
	if clone.Args[1] != "fixture" || len(clone.Passthru) != 2 {
		t.Fatalf("source mutation reached the clone: %+v", clone)
	}

	empty := CLIRunScope{}
	got := empty.Clone()
	if got.Args != nil || got.Helper != nil || got.Passthru != nil {
		t.Fatalf("clone of nil collections is not nil: %+v", got)
	}
	if err := ValidateCLIRunScope(got); !errors.Is(err, errCLIRunInvalid) {
		t.Fatalf("zero clone validated differently from its source: %v", err)
	}
}

// TestCLIRunScope_PassthroughNames proves the names come back sorted and that
// no value is ever returned, even when a value sorts before every name.
func TestCLIRunScope_PassthroughNames(t *testing.T) {
	s := cliRunFixtureScope()
	s.Passthru = map[string]string{"ZZ_LAST": "a", "AA_FIRST": "0-aaa", "MM_MID": passthruFixture}
	got := s.PassthroughNames()
	want := []string{"AA_FIRST", "MM_MID", "ZZ_LAST"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names %q, want %q", got, want)
	}
	for _, name := range got {
		if name == "0-aaa" || name == passthruFixture || name == "a" {
			t.Fatalf("PassthroughNames returned a value: %q", got)
		}
	}
	// The result is a fresh slice; writing to it cannot change the scope.
	got[0] = "OVERWRITTEN"
	if len(s.Passthru) != 3 || s.Passthru["AA_FIRST"] != "0-aaa" {
		t.Fatalf("PassthroughNames aliases the scope map: %+v", s.Passthru)
	}
	if names := (CLIRunScope{}).PassthroughNames(); names == nil || len(names) != 0 {
		t.Fatalf("nil passthrough names = %#v, want empty non-nil slice", names)
	}
}

// TestCLIRunScope_ProgramPinned proves only a non-empty digest counts as a pin.
func TestCLIRunScope_ProgramPinned(t *testing.T) {
	s := cliRunFixtureScope()
	if s.ProgramPinned() {
		t.Fatal("unpinned scope reported pinned")
	}
	s.ProgramSH = strings.Repeat("ab", 32)
	if !s.ProgramPinned() {
		t.Fatal("pinned scope reported unpinned")
	}
	s.Clear()
	if s.ProgramPinned() {
		t.Fatal("cleared scope reported pinned")
	}
}

// TestCLIRunScope_DecodeRejectsMore proves the strict decoder refuses a
// truncated object partway through a collection, non-object roots, a duplicate
// key where the first copy would decode as null, a type mismatch, and trailing
// data appended to a complete object, each with no scope returned. Duplicate,
// unknown, and trailing data all fail the strict object scan before any field
// is decoded, so each rejection returns the zero value.
func TestCLIRunScope_DecodeRejectsMore(t *testing.T) {
	valid, e := json.Marshal(cliRunFixtureScope())
	if e != nil {
		t.Fatal(e)
	}
	cases := map[string]string{
		"truncated-mid-args":  strings.Replace(string(valid), `"api"`, `"api",`, 1),
		"non-object-root":     `[]`,
		"string-root":         `"fixture/bin/gh"`,
		"null-args-duplicate": strings.Replace(string(valid), `"args":[`, `"args":null,"args":[`, 1),
		"timeout-string":      strings.Replace(string(valid), `"timeout_seconds":60`, `"timeout_seconds":"60"`, 1),
		"trailing-digit":      string(valid) + `0`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeCLIRunScope([]byte(raw))
			if !errors.Is(err, errCLIRunScopeJSON) {
				t.Fatalf("want scope error, got %v", err)
			}
			if got.Profile != "" || got.Args != nil || got.Helper != nil || got.Passthru != nil {
				t.Fatal("returned a scope on error")
			}
			if strings.Contains(err.Error(), "fixture") {
				t.Fatalf("error echoed a value: %q", err)
			}
		})
	}
	// The duplicate key is rejected before any field decode.
	if _, err := DecodeCLIRunScope([]byte(`{"profile":"gh","profile":"gh"}`)); !errors.Is(err, errCLIRunScopeJSON) {
		t.Fatalf("duplicate key: %v", err)
	}
}

// TestCLIRunScope_DecodeRejectsDuplicatePassthrough proves a duplicate name
// nested inside passthrough_env is refused. Go would otherwise accept it and
// keep the last value. The scope around it is otherwise valid, so only the
// nested scan can reject it; omission and null stay accepted, as Validate
// intends.
func TestCLIRunScope_DecodeRejectsDuplicatePassthrough(t *testing.T) {
	fixture := cliRunFixtureScope()
	const validPassthru = "fixture-passthrough-value"
	fixture.Passthru = map[string]string{"GH_HOST": validPassthru}
	valid, e := json.Marshal(fixture)
	if e != nil {
		t.Fatal(e)
	}
	// withPassthru replaces the whole passthrough_env member; nested keeps it
	// an object and replaces only its body, so a duplicate can be spliced in.
	withPassthru := func(member string) []byte {
		return []byte(strings.Replace(string(valid), `"passthrough_env":{"GH_HOST":"`+validPassthru+`"}`, member, 1))
	}
	nested := func(body string) []byte {
		return withPassthru(`"passthrough_env":{` + body + `}`)
	}
	dup := nested(`"GH_HOST":"first","GH_HOST":"second"`)
	if !bytes.Contains(dup, []byte(`"GH_HOST":"first","GH_HOST":"second"`)) {
		t.Fatalf("fixture splice failed: %s", dup)
	}
	got, err := DecodeCLIRunScope(dup)
	if !errors.Is(err, errCLIRunScopeJSON) {
		t.Fatalf("want generic scope error, got %v", err)
	}
	if got.Profile != "" || got.Nonce != "" || got.Args != nil || got.Helper != nil || got.Passthru != nil {
		t.Fatalf("returned a scope on error: %+v", got)
	}
	for _, sentinel := range []string{"first", "second", validPassthru, passthruFixture} {
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("error echoed %q: %q", sentinel, err)
		}
	}

	omitted := []byte(strings.Replace(string(valid),
		`,"passthrough_env":{"GH_HOST":"`+validPassthru+`"}`, "", 1))
	if bytes.Contains(omitted, []byte("passthrough_env")) {
		t.Fatalf("fixture splice failed: %s", omitted)
	}
	for name, tc := range map[string]struct {
		raw      []byte
		passthru map[string]string
	}{
		"omitted":      {omitted, nil},
		"null":         {withPassthru(`"passthrough_env":null`), nil},
		"empty-object": {withPassthru(`"passthrough_env":{}`), map[string]string{}},
		"single-value": {nested(`"GH_HOST":"` + validPassthru + `"`), map[string]string{"GH_HOST": validPassthru}},
	} {
		scope, err := DecodeCLIRunScope(tc.raw)
		if err != nil {
			t.Fatalf("%s: rejected intended passthrough shape: %v\nraw=%s", name, err, tc.raw)
		}
		if len(scope.Passthru) != len(tc.passthru) {
			scope.Clear()
			t.Fatalf("%s: passthrough %q, want %q", name, scope.PassthroughNames(), tc.passthru)
		}
		scope.Clear()
	}
}

// TestCLIRunScope_DecodeRoundTrip proves a decoded scope owns fresh
// collections and carries every wire field.
func TestCLIRunScope_DecodeRoundTrip(t *testing.T) {
	src := cliRunFixtureScope()
	src.ProgramSH = strings.Repeat("ab", 32)
	src.TokenEnv = "GH_TOKEN"
	raw, e := json.Marshal(src)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeCLIRunScope(raw)
	if e != nil {
		t.Fatalf("decode: %v", e)
	}
	defer got.Clear()
	if got.Profile != src.Profile || got.TTY != src.TTY || got.TTYPlatform != src.TTYPlatform ||
		got.Nonce != src.Nonce || got.Program != src.Program || got.ProgramSH != src.ProgramSH ||
		got.CWD != src.CWD || got.TempRoot != src.TempRoot || got.Timeout != src.Timeout ||
		got.TokenEnv != src.TokenEnv || !got.ProgramPinned() {
		t.Fatalf("decoded %+v, want %+v", got, src)
	}
	if strings.Join(got.Args, " ") != strings.Join(src.Args, " ") ||
		strings.Join(got.Helper, " ") != strings.Join(src.Helper, " ") ||
		len(got.Passthru) != len(src.Passthru) || got.Passthru["GH_HOST"] != src.Passthru["GH_HOST"] {
		t.Fatalf("decoded collections %+v", got)
	}
	got.Args[0] = "mutated"
	if src.Args[0] != "--hostname" {
		t.Fatal("decoded scope aliases the marshaled source")
	}
}

// TestCanonicalCLIRunRequestPreservesProgramPin proves the canonical broker
// conversion carries the optional executable pin from the approved scope into
// the exact RunBundleRequest the desktop prepares and the CLI signs.
func TestCanonicalCLIRunRequestPreservesProgramPin(t *testing.T) {
	scope := cliRunFixtureScope()
	request, err := CanonicalCLIRunRequest(scope, scope.TempRoot)
	if err != nil {
		t.Fatal("unpinned canonical request failed:", err)
	}
	if request.ProgramSHA256 != "" {
		t.Fatalf("unpinned scope became pinned: %q", request.ProgramSHA256)
	}
	pin := strings.Repeat("0123456789abcdef", 4)
	scope.ProgramSH = pin
	request, err = CanonicalCLIRunRequest(scope, scope.TempRoot)
	if err != nil {
		t.Fatal("pinned canonical request failed:", err)
	}
	if request.ProgramSHA256 != pin {
		t.Fatalf("canonical request pin = %q, want %q", request.ProgramSHA256, pin)
	}
}
