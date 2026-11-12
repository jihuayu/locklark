package browserhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

// Bounds for the one-time CLI-run execution scope. They are enforced on the
// client before anything is sent and again on the broker after it is received,
// so oversized or ragged scope data fails closed on both sides.
const (
	CLIRunMaxProfile        = 64
	CLIRunMaxProgramSHA256  = 64
	CLIRunMaxArgs           = 64
	CLIRunMaxArgsBytes      = 16384
	CLIRunMaxArgBytes       = 4096
	CLIRunMaxHelperPath     = 16
	CLIRunMaxPassthrough    = 32
	CLIRunMaxPassthroughVal = 4096
	CLIRunMaxTokenEnvName   = 128
	CLIRunMaxTimeoutSeconds = 86400
)

// CLIRunTarget is one immutable vault slot the CLI-run will disclose: the
// filter slot name, the exact item ID and revision, and the requested field.
type CLIRunTarget = personal.CLIBrokerTarget

// CLIRunScope is the dedicated, bounded on-the-wire execution scope of one
// CLI-run broker request. It is a plain JSON type with explicit snake_case
// names so the desktop never decodes Go internals, and the CLI never sends any
// other field of personal.RunBundleRequest (notably not the profile spec).
//
// The profile is named, not transmitted. The desktop resolves the built-in
// cliprofile spec by name; a profile the desktop does not know is refused.
//
// TTY is the client-derived name of the caller's standard-input terminal
// (CurrentTTYIdentity) and TTYPlatform records the naming rules that produced
// it. They are not authority: the broker reads the peer's controlling terminal
// from the kernel for Peer.PID and the declared name must name that terminal
// before native approval. TTYPeerID is the client-derived unit of its own
// handle; it is an optional display label that the broker ignores and refuses.
// On a platform without peer attestation every brokered CLI-run is unavailable.
//
// Nonce is consumed by the broker's replay cache before native approval and is
// never displayed to the owner.
//
// TempRoot is the client-created private run root the CLI will hand to the
// audited RunBundle path. RunBundle's HMAC binding covers its TemporaryRoot, so
// native approval must name it. Here it is only a path check.
type CLIRunScope struct {
	Profile     string            `json:"profile"`
	TTY         string            `json:"tty_identity"`
	TTYPeerID   string            `json:"tty_peer_id"`
	TTYPlatform string            `json:"tty_platform"`
	Nonce       string            `json:"nonce"`
	Program     string            `json:"program"`
	ProgramSH   string            `json:"program_sha256,omitempty"`
	CWD         string            `json:"cwd"`
	TempRoot    string            `json:"temp_root"`
	Args        []string          `json:"args"`
	Helper      []string          `json:"helper_path"`
	Passthru    map[string]string `json:"passthrough_env"`
	Timeout     int               `json:"timeout_seconds"`
	TokenEnv    string            `json:"token_env_name"`
}

// Clone returns a deep copy so an approved scope can be displayed and later
// bound without sharing mutable slices or maps with the request. A nil
// collection stays nil, so the clone validates exactly like its source.
func (s CLIRunScope) Clone() CLIRunScope {
	s.Args = append([]string(nil), s.Args...)
	s.Helper = append([]string(nil), s.Helper...)
	if s.Passthru != nil {
		passthru := make(map[string]string, len(s.Passthru))
		for name, value := range s.Passthru {
			passthru[name] = value
		}
		s.Passthru = passthru
	}
	return s
}

// PassthroughNames returns the sorted passthrough variable names. Values are
// deliberately never returned: neither the native approval nor a log may show
// an environment value.
func (s CLIRunScope) PassthroughNames() []string {
	names := make([]string, 0, len(s.Passthru))
	for name := range s.Passthru {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ProgramPinned reports whether the scope pins the program by SHA-256.
func (s CLIRunScope) ProgramPinned() bool { return s.ProgramSH != "" }

// Clear zeroes the scope in place. It is exported so the desktop can wipe a
// request after the callback. The scalar strings are replaced with empty
// values and the variable-length collections are emptied in place (each entry
// or value set to "") before their references are dropped; Go strings cannot be
// zeroed more strongly than that, so there is deliberately no custom marshal or
// wrapper type promising more.
func (s *CLIRunScope) Clear() {
	if s == nil {
		return
	}
	s.Profile, s.TTY, s.TTYPeerID, s.TTYPlatform, s.Nonce, s.Program = "", "", "", "", "", ""
	s.ProgramSH = ""
	s.CWD, s.TokenEnv, s.TempRoot, s.Timeout = "", "", "", 0
	for i := range s.Args {
		s.Args[i] = ""
	}
	s.Args = nil
	for i := range s.Helper {
		s.Helper[i] = ""
	}
	s.Helper = nil
	for name := range s.Passthru {
		s.Passthru[name] = ""
		delete(s.Passthru, name)
	}
	s.Passthru = nil
}

// ValidateCLIRunScope is the pure, secret-free scope check. It accepts only
// non-empty, bounded, well-formed values and returns a single generic error
// that never carries the offending value. The desktop applies it on receipt
// and the CLI applies it before transmission.
func ValidateCLIRunScope(scope CLIRunScope) error {
	if !scopeText(scope.Profile, CLIRunMaxProfile) || strings.TrimSpace(scope.Profile) != scope.Profile {
		return errCLIRunInvalid
	}
	if !cliRunTTYNameValid(scope.TTY) || !scopeText(scope.TTYPlatform, 16) {
		return errCLIRunInvalid
	}
	// TTYPeerID is client-derived and never authority, so it may be omitted
	// entirely; when present it must be a well-formed unit. The broker never
	// compares it with anything.
	if scope.TTYPeerID != "" {
		if _, ok := parseTTYPeerID(scope.TTYPeerID); !ok {
			return errCLIRunInvalid
		}
	}
	if !validCLIRunNonce(scope.Nonce) {
		return errCLIRunInvalid
	}
	if !scopeProgramPath(scope.Program) || !scopeAbsPath(scope.CWD) {
		return errCLIRunInvalid
	}
	if scope.ProgramSH != "" && !lowerHex(scope.ProgramSH, CLIRunMaxProgramSHA256) {
		return errCLIRunInvalid
	}
	if len(scope.Args) > CLIRunMaxArgs {
		return errCLIRunInvalid
	}
	total := 0
	for _, arg := range scope.Args {
		total += len(arg)
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) || len(arg) > CLIRunMaxArgBytes || total > CLIRunMaxArgsBytes {
			return errCLIRunInvalid
		}
	}
	if scope.Timeout < 1 || scope.Timeout > CLIRunMaxTimeoutSeconds {
		return errCLIRunInvalid
	}
	if len(scope.Helper) > CLIRunMaxHelperPath {
		return errCLIRunInvalid
	}
	for _, entry := range scope.Helper {
		// Each helper is one directory, exactly as RunBundle later joins them.
		if !scopeAbsPath(entry) || filepath.Clean(entry) != entry || strings.ContainsRune(entry, os.PathListSeparator) {
			return errCLIRunInvalid
		}
	}
	if len(scope.Passthru) > CLIRunMaxPassthrough {
		return errCLIRunInvalid
	}
	for name, value := range scope.Passthru {
		if !validCLIRunEnvName(name, 64) || !utf8.ValidString(value) ||
			strings.ContainsRune(value, 0) || len(value) > CLIRunMaxPassthroughVal {
			return errCLIRunInvalid
		}
	}
	if scope.TokenEnv != "" && !validCLIRunEnvName(scope.TokenEnv, CLIRunMaxTokenEnvName) {
		return errCLIRunInvalid
	}
	// The RunBundle binding covers TempRoot, so it is required and must be one
	// absolute, clean directory path. Creating and owning the private root is
	// the next slice's job; this check is path-only.
	if !scopeProgramPath(scope.TempRoot) || scope.TempRoot == string(filepath.Separator) {
		return errCLIRunInvalid
	}
	return nil
}

func scopeText(value string, max int) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsRune(value, 0) && len(value) <= max
}

func scopeAbsPath(value string) bool {
	return scopeText(value, 4096) && filepath.IsAbs(value)
}

// scopeProgramPath requires one absolute, already-cleaned program path without
// a trailing separator. Whether it is executable is decided later, by the
// RunBundle path itself.
func scopeProgramPath(value string) bool {
	if !scopeAbsPath(value) || filepath.Clean(value) != value {
		return false
	}
	return !strings.HasSuffix(value, "/")
}

func lowerHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// validCLIRunEnvName mirrors the environment-name grammar used by the
// RunBundle path: ASCII letters, digits and underscore, leading letter, bounded
// length. Validation is local so neither side imports personal internals.
func validCLIRunEnvName(name string, max int) bool {
	if len(name) == 0 || len(name) > max {
		return false
	}
	for i, b := range []byte(name) {
		if b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || i > 0 && b >= '0' && b <= '9' {
			continue
		}
		return false
	}
	return true
}

// errCLIRunScopeJSON reports any malformed scope wire object. Its text is
// fixed and never includes the decoded values.
var errCLIRunScopeJSON = errors.New("desktop browser broker scope invalid")

// errCLIRunTrailing reports trailing data after a complete scope object. It is
// only distinguished from errCLIRunScopeJSON so tests can prove that this
// path, which runs after the decoder has already released its fields, still
// returns nothing decoded.
var errCLIRunTrailing = errors.New("desktop browser broker scope has trailing data")

// DecodeCLIRunScope strictly parses the raw scope object of a CLI-run request.
// It rejects duplicate or unknown fields, non-object roots (including null),
// trailing data, and any scope that fails ValidateCLIRunScope. Duplicate names
// nested inside passthrough_env are rejected too: encoding/json would silently
// keep only the last value of a duplicate map key.
//
// The decoder writes the Args, Helper, and Passthru fields from scratch and
// never appends to or merges into an existing collection, so the returned
// scope owns every decoded slice and map; the caller clears it with Clear.
//
// Every raw copy of the object (passthrough values included) is cleared on
// every path, and the local decoded scope is cleared on every error path,
// including a partially decoded json.Decoder.Decode failure, a validation
// rejection, and the trailing-data rejection, which runs after the decoder has
// filled every field. The decoded scope is retained only when it is returned.
func DecodeCLIRunScope(raw []byte) (CLIRunScope, error) {
	keys, copies, ok := strictJSONObject(raw)
	defer clearCLIRunRawMessages(copies) // includes passthrough raw values
	if !ok || !scopeKeysOnly(keys) {
		return CLIRunScope{}, errCLIRunScopeJSON
	}
	if !scopePassthroughStrict(copies["passthrough_env"]) {
		return CLIRunScope{}, errCLIRunScopeJSON
	}
	return decodeCLIRunScopeFields(raw)
}

// scopePassthroughStrict reports whether the raw passthrough_env value is
// absent (no bytes), JSON null, or one object without duplicate names. The
// scan reuses strictJSONObject, so a non-object value is refused here exactly
// as encoding/json would refuse it during the field decode. Any raw copy the
// scan retains is cleared before returning.
func scopePassthroughStrict(raw json.RawMessage) bool {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return true
	}
	_, nested, ok := strictJSONObject(raw)
	defer clearCLIRunRawMessages(nested) // every nested value raw copy
	return ok
}

// decodeCLIRunScopeFields strictly decodes one scope object.
func decodeCLIRunScopeFields(raw []byte) (CLIRunScope, error) {
	var scope CLIRunScope
	retained := false
	defer func() {
		if !retained {
			scope.Clear()
		}
	}()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if dec.Decode(&scope) != nil {
		return CLIRunScope{}, errCLIRunScopeJSON
	}
	if _, e := dec.Token(); e != io.EOF {
		return CLIRunScope{}, errCLIRunTrailing
	}
	if ValidateCLIRunScope(scope) != nil {
		return CLIRunScope{}, errCLIRunScopeJSON
	}
	retained = true
	return scope, nil
}

// scopeKeysOnly reports whether every key is an exact CLIRunScope wire name.
func scopeKeysOnly(keys map[string]struct{}) bool {
	allowed := map[string]struct{}{
		"profile": {}, "tty_identity": {}, "tty_peer_id": {}, "tty_platform": {}, "nonce": {}, "program": {},
		"program_sha256": {}, "args": {}, "cwd": {}, "timeout_seconds": {},
		"helper_path": {}, "passthrough_env": {}, "token_env_name": {}, "temp_root": {},
	}
	for key := range keys {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

// bindProfile resolves the named profile and refuses anything the desktop does
// not recognise. It returns only the immutable built-in spec; the CLI never
// describes its own slots, files, or environment policy over the wire.
func bindProfile(name string) (cliprofile.Spec, error) {
	if profile, ok := cliprofile.Lookup(name); ok {
		return cliprofile.CloneSpec(profile.Spec()), nil
	}
	return cliprofile.Spec{}, errCLIRunInvalid
}
