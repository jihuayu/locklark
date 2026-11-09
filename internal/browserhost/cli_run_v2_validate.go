package browserhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

// validCLIRunV2PublicText accepts bounded UTF-8 text with no NUL and no Unicode
// control rune. Public selectors and paths must never smuggle terminal or
// display control sequences into a native approval view.
func validCLIRunV2PublicText(value string, max int) bool {
	if len(value) > max || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

func validCLIRunV2Path(value string) bool {
	return validCLIRunV2PublicText(value, cliRunV2MaxPathBytes) && filepath.IsAbs(value)
}

func validCLIRunV2Hex(value string, n int) bool {
	if len(value) != n*2 {
		return false
	}
	raw, e := hex.DecodeString(value)
	if e != nil || len(raw) != n {
		return false
	}
	canonical := hex.EncodeToString(raw) == value
	clear(raw)
	return canonical
}

func validCLIRunV2Nonce(value string) bool {
	return validCLIRunV2Hex(value, cliRunV2NonceBytes)
}

// validCLIRunV2Wire enforces every bound that does not need the trusted profile
// registry. Profile-dependent policy is rebuilt separately and validated by
// personal.RunBundleRequest.Validate.
func validCLIRunV2Wire(req CLIRunV2Request) bool {
	if req.V != cliRunV2Version || !validCLIRunV2Nonce(req.Nonce) {
		return false
	}
	if !validCLIRunV2Path(req.VaultPath) || !validCLIRunV2Path(req.Root) {
		return false
	}
	if !validCLIRunV2PublicText(req.ProfileID, cliRunV2MaxProfileID) || req.ProfileID == "" {
		return false
	}
	// The versioned spec id and its canonical 64-hex fingerprint are mandatory.
	// They are always present on a request built from the local built-in, so a
	// missing, aliased, shortened or non-canonical value is a hard wire refusal.
	if !validCLIRunV2PublicText(req.SpecID, cliRunV2MaxProfileID) || req.SpecID == "" {
		return false
	}
	if !validCLIRunV2Hex(req.SpecDigest, sha256.Size) {
		return false
	}
	if !validCLIRunV2Path(req.Program) || !validCLIRunV2Path(req.Directory) {
		return false
	}
	if req.TimeoutSeconds < 1 || req.TimeoutSeconds > 86400 {
		return false
	}
	if len(req.Args) > cliRunV2MaxArgs {
		return false
	}
	total := 0
	for _, arg := range req.Args {
		total += len(arg)
		if total > cliRunV2MaxArgBytes || !validCLIRunV2PublicText(arg, cliRunV2MaxArgBytes) {
			return false
		}
	}
	if len(req.HelperPath) > cliRunV2MaxHelperPath {
		return false
	}
	for _, entry := range req.HelperPath {
		if !validCLIRunV2Path(entry) || strings.ContainsRune(entry, os.PathListSeparator) {
			return false
		}
	}
	if len(req.Passthrough) > cliRunV2MaxPass {
		return false
	}
	for name, value := range req.Passthrough {
		if !cliprofile.ValidEnvName(name) || !validCLIRunV2PublicText(value, cliRunV2MaxPathBytes) {
			return false
		}
	}
	if req.TokenEnvName != "" && !validCLIRunV2PublicText(req.TokenEnvName, 128) {
		return false
	}
	if len(req.Targets) < 1 || len(req.Targets) > cliRunV2MaxTargets {
		return false
	}
	seen := make(map[string]bool, len(req.Targets))
	for _, target := range req.Targets {
		if !validCLIRunV2PublicText(target.Slot, cliRunV2MaxSlotBytes) || target.Slot == "" || seen[target.Slot] {
			return false
		}
		if !validCLIRunV2Hex(target.ID, 16) || !validCLIRunV2Hex(target.Revision, 32) {
			return false
		}
		if !cliRunV2Fields[target.Field] {
			return false
		}
		seen[target.Slot] = true
	}
	return true
}

// lookupCLIRunV2Profile resolves a caller-supplied profile name to the local
// built-in registry entry. The wire never supplies a spec: only the name is
// looked up, and the versioned id plus the canonical spec digest must then match
// this exact local built-in.
func lookupCLIRunV2Profile(id string) (cliprofile.Spec, bool) {
	for _, profile := range cliprofile.List() {
		if profile.Name() == id {
			return profile.Spec(), true
		}
	}
	return cliprofile.Spec{}, false
}

// cliRunV2SpecDigest is the canonical 64-hex fingerprint of one trusted built-in
// profile spec: SHA256(json.Marshal(cliprofile.CloneSpec(spec))). Both peers
// compute it from their own local built-in, so a mixed CLI/desktop pair that
// shares a profile name but renders a changed spec is refused instead of
// agreeing on the name alone.
func cliRunV2SpecDigest(spec cliprofile.Spec) string {
	raw, e := json.Marshal(cliprofile.CloneSpec(spec))
	if e != nil || len(raw) == 0 {
		return ""
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cloneCLIRunV2Targets(targets []CLIRunV2Target) []CLIRunV2Target {
	return append([]CLIRunV2Target(nil), targets...)
}

func cloneCLIRunV2Strings(values []string) []string {
	return append([]string(nil), values...)
}

func cloneCLIRunV2Map(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for name, value := range values {
		out[name] = value
	}
	return out
}

// trustedCLIRunV2Request rebuilds the complete trusted request and target set
// from the public selectors. It clones every slice and map before returning, so
// a caller cannot mutate memory that a signed intent later binds. The candidate
// spec is taken only from the registry, never from the wire, and the wire must
// pin both the versioned spec id and the canonical digest of that same local
// built-in.
func trustedCLIRunV2Request(req CLIRunV2Request) (personal.RunBundleRequest, []personal.BundleTarget, cliprofile.Spec, bool) {
	spec, ok := lookupCLIRunV2Profile(req.ProfileID)
	if !ok || spec.ID == "" {
		return personal.RunBundleRequest{}, nil, cliprofile.Spec{}, false
	}
	if req.SpecID != spec.ID || req.SpecDigest != cliRunV2SpecDigest(spec) {
		return personal.RunBundleRequest{}, nil, cliprofile.Spec{}, false
	}
	request := personal.RunBundleRequest{
		Program:        req.Program,
		Args:           cloneCLIRunV2Strings(req.Args),
		Directory:      req.Directory,
		TimeoutSeconds: req.TimeoutSeconds,
		HelperPath:     cloneCLIRunV2Strings(req.HelperPath),
		Passthrough:    cloneCLIRunV2Map(req.Passthrough),
		TokenEnvName:   req.TokenEnvName,
		Spec:           cliprofile.CloneSpec(spec),
	}
	targets := make([]personal.BundleTarget, len(req.Targets))
	for i, target := range req.Targets {
		targets[i] = personal.BundleTarget{Slot: target.Slot, ID: target.ID, Revision: target.Revision, Field: target.Field}
	}
	if request.Validate(targets) != nil {
		return personal.RunBundleRequest{}, nil, cliprofile.Spec{}, false
	}
	return request, targets, cliprofile.CloneSpec(spec), true
}

// cliRunV2ScopeDigest hashes the entire trusted scope, not just the field
// targets: the profile name, the versioned spec id and the canonical spec
// digest are bound exactly as they appear on the wire. Both peers compute it
// from the same canonical encoding.
func cliRunV2ScopeDigest(req CLIRunV2Request) string {
	targets := cloneCLIRunV2Targets(req.Targets)
	args := cloneCLIRunV2Strings(req.Args)
	helpers := cloneCLIRunV2Strings(req.HelperPath)
	passthrough := cloneCLIRunV2Map(req.Passthrough)
	if len(args) == 0 {
		args = nil
	}
	if len(helpers) == 0 {
		helpers = nil
	}
	if len(passthrough) == 0 {
		passthrough = nil
	}
	payload := struct {
		Version        int               `json:"version"`
		Nonce          string            `json:"nonce"`
		Epoch          uint64            `json:"epoch"`
		VaultPath      string            `json:"vault_path"`
		Root           string            `json:"root"`
		Profile        string            `json:"profile"`
		SpecID         string            `json:"spec_id"`
		SpecDigest     string            `json:"spec_digest"`
		Program        string            `json:"program"`
		Args           []string          `json:"args"`
		Directory      string            `json:"directory"`
		TimeoutSeconds int               `json:"timeout_seconds"`
		HelperPath     []string          `json:"helper_path"`
		Passthrough    map[string]string `json:"passthrough"`
		TokenEnvName   string            `json:"token_env_name"`
		Targets        []CLIRunV2Target  `json:"targets"`
	}{
		Version: cliRunV2Version, Nonce: req.Nonce, Epoch: req.Epoch,
		VaultPath: req.VaultPath, Root: req.Root, Profile: req.ProfileID,
		SpecID: req.SpecID, SpecDigest: req.SpecDigest,
		Program: req.Program, Args: args, Directory: req.Directory,
		TimeoutSeconds: req.TimeoutSeconds, HelperPath: helpers,
		Passthrough: passthrough, TokenEnvName: req.TokenEnvName, Targets: targets,
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return ""
	}
	defer clear(raw)
	sum := sha256.Sum256(append([]byte("locklark/browserhost/cli-run-v2/scope/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

// cliRunV2JSONSchema is the exact wire schema derived from the JSON tags of one
// fixed struct type. Fixed objects accept only their literal tag spelling;
// dynamic maps keep caller-chosen keys (upper-case env names, slot names) but
// still validate every value with the map's element schema.
type cliRunV2JSONSchema struct {
	kind  byte                           // 'o' object, 'a' array, 'l' leaf
	exact map[string]*cliRunV2JSONSchema // fixed field names, case-sensitive; nil for dynamic maps
	elem  *cliRunV2JSONSchema            // array element or dynamic map value
}

var cliRunV2BytesType = reflect.TypeOf([]byte(nil))

func cliRunV2SchemaOf(t reflect.Type) (*cliRunV2JSONSchema, bool) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	// []byte is a base64 JSON string on the wire, never a JSON array.
	if t == cliRunV2BytesType {
		return &cliRunV2JSONSchema{kind: 'l'}, true
	}
	switch t.Kind() {
	case reflect.Struct:
		schema := &cliRunV2JSONSchema{kind: 'o', exact: make(map[string]*cliRunV2JSONSchema, t.NumField())}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if !field.IsExported() || name == "" || name == "-" {
				return nil, false
			}
			sub, ok := cliRunV2SchemaOf(field.Type)
			if !ok {
				return nil, false
			}
			schema.exact[name] = sub
		}
		return schema, true
	case reflect.Slice, reflect.Array:
		sub, ok := cliRunV2SchemaOf(t.Elem())
		if !ok {
			return nil, false
		}
		return &cliRunV2JSONSchema{kind: 'a', elem: sub}, true
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, false
		}
		sub, ok := cliRunV2SchemaOf(t.Elem())
		if !ok {
			return nil, false
		}
		return &cliRunV2JSONSchema{kind: 'o', elem: sub}, true
	default:
		return &cliRunV2JSONSchema{kind: 'l'}, true
	}
}

// scanCLIRunV2JSONValue walks one JSON value and refuses keys that are not the
// exact JSON tag spelling of the target schema, keys that repeat under case
// folding (the Go decoder accepts tag aliases, so "Nonce" would otherwise bind
// the "nonce" field), excessive depth or arity. It is bounded by the already
// size-checked frame.
func scanCLIRunV2JSONValue(dec *json.Decoder, schema *cliRunV2JSONSchema, depth int) bool {
	if depth > 8 || schema == nil {
		return false
	}
	tok, e := dec.Token()
	if e != nil {
		return false
	}
	switch tok {
	case json.Delim('{'):
		if schema.kind != 'o' {
			return false
		}
		seen := make(map[string]bool, 8)
		folded := make(map[string]bool, 8)
		for dec.More() {
			keyTok, e := dec.Token()
			key, ok := keyTok.(string)
			if e != nil || !ok || seen[key] || len(seen) >= 128 {
				return false
			}
			fold := strings.ToLower(key)
			if folded[fold] {
				return false
			}
			folded[fold] = true
			seen[key] = true
			sub := schema.elem
			if schema.exact != nil {
				sub = schema.exact[key]
			}
			if sub == nil || !scanCLIRunV2JSONValue(dec, sub, depth+1) {
				return false
			}
		}
		end, e := dec.Token()
		return e == nil && end == json.Delim('}')
	case json.Delim('['):
		if schema.kind != 'a' || schema.elem == nil {
			return false
		}
		count := 0
		for dec.More() {
			count++
			if count > 1024 || !scanCLIRunV2JSONValue(dec, schema.elem, depth+1) {
				return false
			}
		}
		end, e := dec.Token()
		return e == nil && end == json.Delim(']')
	default:
		return schema.kind == 'l'
	}
}

// strictCLIRunV2Object accepts exactly one bounded JSON value matching the exact
// schema of out, with no aliased, duplicate, unknown or trailing content, then
// decodes it into out.
func strictCLIRunV2Object(raw []byte, out any) bool {
	if len(raw) == 0 || len(raw) > MaxInput || !utf8.Valid(raw) || !strictUnicode(raw) {
		return false
	}
	schema, ok := cliRunV2SchemaOf(reflect.TypeOf(out))
	if !ok || schema.kind != 'o' {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if !scanCLIRunV2JSONValue(dec, schema, 0) {
		return false
	}
	if _, e := dec.Token(); e != io.EOF {
		return false
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil {
		return false
	}
	if _, e := dec.Token(); e != io.EOF {
		return false
	}
	return true
}

func decodeCLIRunV2Request(raw []byte) (CLIRunV2Request, error) {
	var req CLIRunV2Request
	if !strictCLIRunV2Object(raw, &req) || !validCLIRunV2Wire(req) {
		return CLIRunV2Request{}, ErrProtocol
	}
	return req, nil
}

func decodeCLIRunV2Challenge(raw []byte) (CLIRunV2Challenge, error) {
	var ch CLIRunV2Challenge
	if !strictCLIRunV2Object(raw, &ch) || ch.V != cliRunV2Version {
		return CLIRunV2Challenge{}, ErrBrokerUnknown
	}
	if ch.Error == "" && !validCLIRunV2Nonce(ch.Nonce) {
		return CLIRunV2Challenge{}, ErrBrokerUnknown
	}
	return ch, nil
}

// cliRunV2ReplyDecodeProbe is nil in production. A test may install it to
// retain the exact value backing arrays allocated by a failed strict decode,
// proving that decodeCLIRunV2Reply zeroes them before the zero reply is
// returned. It never changes production behaviour.
var cliRunV2ReplyDecodeProbe func(map[string][]byte)

// wipeCLIRunV2Values zeroes every allocated value backing array and then drops
// the map entries. clear(map) alone only drops references; it never erases the
// credential bytes a decoder already allocated.
func wipeCLIRunV2Values(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
	clear(values)
}

func decodeCLIRunV2Reply(raw []byte) (CLIRunV2Reply, error) {
	var reply CLIRunV2Reply
	if !strictCLIRunV2Object(raw, &reply) || reply.V != cliRunV2Version {
		if probe := cliRunV2ReplyDecodeProbe; probe != nil {
			probe(reply.Values)
		}
		wipeCLIRunV2Values(reply.Values)
		return CLIRunV2Reply{}, ErrBrokerUnknown
	}
	return reply, nil
}

// cliRunV2HelloWire is the exact fixed hello shape for the v2 selector. No
// browser, origin, extension or aliased key may be present.
type cliRunV2HelloWire struct {
	V    int    `json:"v"`
	Mode string `json:"mode"`
}

// validCLIRunV2Hello accepts exactly {v:2,mode:"cli-run"} with no duplicate,
// aliased, unknown, browser or origin field. The v2 mode can never be selected
// by a forged browser hello.
func validCLIRunV2Hello(raw []byte) bool {
	var wire cliRunV2HelloWire
	return strictCLIRunV2Object(raw, &wire) && wire.V == cliRunV2Version && wire.Mode == cliRunV2Mode
}
