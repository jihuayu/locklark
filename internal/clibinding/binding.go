// Package clibinding stores the non-secret metadata that binds a local CLI
// tool name to a vault item, a credential profile and one pinned executable.
//
// A binding never contains credential values. It records only vault item IDs,
// immutable revisions and the profile slot each field populates. The SHA-256
// executable pin lets the runner refuse a program that changed since binding.
package clibinding

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

const (
	// DefaultFileName is the owner-only binding file created in the working
	// directory when LOCKLARK_CLI_BINDING is not set.
	DefaultFileName = ".locklark-cli.json"
	// SchemaVersion is the only binding file schema accepted by this build.
	SchemaVersion = 1

	maxBindingFileSize = 64 << 10
	maxBindings        = 64
	maxHelperPaths     = 16
	maxPassthroughEnv  = 32
	maxPathLength      = 4096
)

var (
	// ErrBinding reports malformed, unsafe or untrusted binding metadata.
	ErrBinding = errors.New("invalid or untrusted CLI binding configuration")
	// ErrBindingNotFound reports a tool name that is not in the store.
	ErrBindingNotFound = errors.New("CLI tool binding not found")

	toolNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	targetIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SlotTarget binds one profile slot to one immutable field of a vault item.
type SlotTarget struct {
	Slot     string `json:"slot"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Field    string `json:"field"`
}

// ToolBinding is the complete non-secret description of one wrapped tool.
type ToolBinding struct {
	Profile        string       `json:"profile"`
	VaultPath      string       `json:"vault_path"`
	Program        string       `json:"program"`
	ProgramSHA256  string       `json:"program_sha256,omitempty"`
	Targets        []SlotTarget `json:"targets"`
	HelperPath     []string     `json:"helper_path,omitempty"`
	PassthroughEnv []string     `json:"passthrough_env,omitempty"`
	TimeoutSeconds int          `json:"timeout_seconds,omitempty"`
	TokenEnvName   string       `json:"token_env_name,omitempty"`
}

// Store is the versioned collection persisted in the binding file.
type Store struct {
	Version  int                    `json:"version"`
	Bindings map[string]ToolBinding `json:"bindings"`
}

// NewStore returns an empty store at the current schema version.
func NewStore() Store {
	return Store{Version: SchemaVersion, Bindings: map[string]ToolBinding{}}
}

// DefaultPath resolves the binding file path. LOCKLARK_CLI_BINDING is honored
// only when it is absolute; any other value is ignored rather than interpreted
// relative to an attacker-controlled working directory.
func DefaultPath() (string, error) {
	if env := os.Getenv("LOCKLARK_CLI_BINDING"); env != "" && filepath.IsAbs(env) {
		return filepath.Clean(env), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, DefaultFileName), nil
}

func validPath(value string) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= maxPathLength &&
		!strings.ContainsAny(value, "\x00\r\n") && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func validBindingPath(value string) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsRune(value, 0) &&
		filepath.IsAbs(value) && filepath.Clean(value) == value
}

func validProgramPath(value string) bool {
	return validPath(value)
}

func repeatedName(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

// Validate checks a binding against the immutable built-in profile policy.
func (b ToolBinding) Validate() error {
	prof, ok := cliprofile.Lookup(b.Profile)
	if !ok {
		return ErrBinding
	}
	spec := prof.Spec()
	if !validPath(b.VaultPath) || !validProgramPath(b.Program) {
		return ErrBinding
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(b.Program), ".exe") {
		return ErrBinding
	}
	if b.ProgramSHA256 != "" && !digestPattern.MatchString(b.ProgramSHA256) {
		return ErrBinding
	}
	if err := validateTargets(spec, b.Targets); err != nil {
		return err
	}
	if len(b.HelperPath) > maxHelperPaths {
		return ErrBinding
	}
	for _, directory := range b.HelperPath {
		if !validPath(directory) || strings.ContainsRune(directory, os.PathListSeparator) {
			return ErrBinding
		}
	}
	if len(b.PassthroughEnv) > maxPassthroughEnv || repeatedName(b.PassthroughEnv) {
		return ErrBinding
	}
	for _, name := range b.PassthroughEnv {
		if !cliprofile.ValidPassthroughName(spec, name, "probe") {
			return ErrBinding
		}
	}
	maxTimeout := spec.MaxTimeout
	if maxTimeout <= 0 {
		maxTimeout = 300
	}
	if b.TimeoutSeconds != 0 && (b.TimeoutSeconds < 1 || b.TimeoutSeconds > maxTimeout) {
		return ErrBinding
	}
	if spec.DynamicTokenEnv {
		if !cliprofile.ValidTokenEnvName(b.TokenEnvName) {
			return ErrBinding
		}
	} else if b.TokenEnvName != "" {
		return ErrBinding
	}
	return nil
}

func validateTargets(spec cliprofile.Spec, targets []SlotTarget) error {
	if len(targets) < 1 || len(targets) > len(spec.Slots) {
		return ErrBinding
	}
	slots := make(map[string]cliprofile.Slot, len(spec.Slots))
	for _, slot := range spec.Slots {
		slots[slot.Name] = slot
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		slot, ok := slots[target.Slot]
		if !ok || seen[target.Slot] {
			return ErrBinding
		}
		if !targetIDPattern.MatchString(target.ID) || !digestPattern.MatchString(target.Revision) ||
			target.Field != string(slot.Field) {
			return ErrBinding
		}
		seen[target.Slot] = true
	}
	for _, slot := range spec.Slots {
		if !slot.Optional && !seen[slot.Name] {
			return ErrBinding
		}
	}
	return nil
}

// Validate checks the store version, bounding map size and every binding.
func (s Store) Validate() error {
	if s.Version != SchemaVersion || len(s.Bindings) > maxBindings {
		return ErrBinding
	}
	for tool, binding := range s.Bindings {
		if !toolNamePattern.MatchString(tool) {
			return ErrBinding
		}
		if err := binding.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ComputeProgramSHA256 hashes one absolute regular executable path.
func ComputeProgramSHA256(programPath string) (string, error) {
	if !filepath.IsAbs(programPath) {
		return "", ErrBinding
	}
	file, err := os.Open(programPath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrBinding
	}
	h := sha256.New()
	if _, err = io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyProgram validates the metadata, requires the program to still be a
// regular file and enforces the optional executable pin.
func VerifyProgram(b ToolBinding) error {
	if err := b.Validate(); err != nil {
		return err
	}
	sum, err := ComputeProgramSHA256(b.Program)
	if err != nil {
		return err
	}
	if b.ProgramSHA256 != "" && sum != b.ProgramSHA256 {
		return ErrBinding
	}
	return nil
}

// Load reads and validates one owner-only binding file.
func Load(path string) (Store, error) {
	if !validBindingPath(path) {
		return Store{}, ErrBinding
	}
	raw, err := readPrivateBindingFile(path)
	if err != nil {
		return Store{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var store Store
	if err = decoder.Decode(&store); err != nil {
		return Store{}, ErrBinding
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Store{}, ErrBinding
	}
	if err = store.Validate(); err != nil {
		return Store{}, err
	}
	if store.Bindings == nil {
		store.Bindings = map[string]ToolBinding{}
	}
	return store, nil
}

// Save validates the store and writes canonical owner-only JSON atomically.
func Save(path string, store Store) error {
	if !validBindingPath(path) {
		return ErrBinding
	}
	if store.Version == 0 {
		store.Version = SchemaVersion
	}
	if err := store.Validate(); err != nil {
		return err
	}
	if store.Bindings == nil {
		store.Bindings = map[string]ToolBinding{}
	}
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return ErrBinding
	}
	raw = append(raw, '\n')
	if len(raw) > maxBindingFileSize {
		return ErrBinding
	}
	defer clear(raw)
	return writePrivateBindingFile(path, raw)
}

// randomTempSuffix returns a short unpredictable filename component used by
// both platform-specific atomic writers.
func randomTempSuffix() (string, error) {
	var raw [12]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("clibinding: temporary name unavailable")
	}
	return hex.EncodeToString(raw[:]), nil
}
