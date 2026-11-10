// Package cliprofile defines deterministic, side-effect-free credential
// profiles for local CLI programs. The package renders only the environment
// and files a profile explicitly declares; it never starts a process.
package cliprofile

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValueRef identifies the encrypted vault field a slot is populated from.
type ValueRef string

const (
	FieldUsername   ValueRef = "username"
	FieldPassword   ValueRef = "password"
	FieldURL        ValueRef = "url"
	FieldNotes      ValueRef = "notes"
	FieldAttachment ValueRef = "attachment"
	FieldFilename   ValueRef = "filename"
)

// Slot declares one credential or document value required by a profile.
type Slot struct {
	Name            string   `json:"name"`
	Kind            string   `json:"kind"` // "login" | "document"
	Field           ValueRef `json:"field"`
	Optional        bool     `json:"optional,omitempty"`
	RequireNonBlank bool     `json:"require_non_blank,omitempty"`
}

// FileSpec declares a deterministic file, relative to the isolated run root,
// that must be materialized before the child starts.
type FileSpec struct {
	RelPath string `json:"rel_path"` // relative to run root, e.g. "kube/config", "docker/config.json"
	Format  string `json:"format"`   // deterministic format ID bound into HMAC
	Mode    uint32 `json:"mode"`     // 0600 (or 0700 for the git-askpass-helper-v1 script)
}

// Spec is the complete, serializable policy for one CLI profile.
type Spec struct {
	ID              string            `json:"id"`
	Slots           []Slot            `json:"slots"`
	Env             map[string]string `json:"env,omitempty"` // ENV_NAME -> "slot:<name>" | "file:<relpath>" | "root:<subdir>" | "literal:<val>"
	DynamicTokenEnv bool              `json:"dynamic_token_env,omitempty"`
	Files           []FileSpec        `json:"files,omitempty"`
	Dirs            []string          `json:"dirs,omitempty"`
	PassthroughEnv  []string          `json:"passthrough_env,omitempty"`
	AllowSSHAgent   bool              `json:"allow_ssh_agent,omitempty"`
	MaxTimeout      int               `json:"max_timeout"`
	DenyArgs        [][]string        `json:"deny_args,omitempty"`
	// RequireExplicitProgram refuses automatic PATH lookup. Profiles used for
	// interpreter harnesses must bind one absolute, pinned interpreter instead
	// of silently selecting whichever executable happens to be on PATH.
	RequireExplicitProgram bool `json:"require_explicit_program,omitempty"`
}

// Profile is one named CLI credential policy.
type Profile interface {
	Name() string
	Executables() []string
	Spec() Spec
	NeedsAuth(args []string) bool
}

// CloneSpec returns a deep copy so callers cannot mutate a shared profile or a
// previously bound request through a returned slice or map.
func CloneSpec(s Spec) Spec {
	out := s
	out.Slots = append([]Slot(nil), s.Slots...)
	if s.Env != nil {
		out.Env = make(map[string]string, len(s.Env))
		for k, v := range s.Env {
			out.Env[k] = v
		}
	}
	out.Files = append([]FileSpec(nil), s.Files...)
	out.Dirs = append([]string(nil), s.Dirs...)
	out.PassthroughEnv = append([]string(nil), s.PassthroughEnv...)
	if s.DenyArgs != nil {
		out.DenyArgs = make([][]string, len(s.DenyArgs))
		for i, deny := range s.DenyArgs {
			out.DenyArgs[i] = append([]string(nil), deny...)
		}
	}
	return out
}

// ErrDeniedArgs reports an argument pattern that a profile refuses because it
// would persist authentication or rewrite credential storage outside the
// isolated run root.
var ErrDeniedArgs = errors.New("command arguments are denied by this CLI profile")

// Lookup returns the built-in profile with the supplied name.
func Lookup(name string) (Profile, bool) {
	p, ok := builtinProfiles[name]
	return p, ok
}

// List returns every built-in profile sorted by name.
func List() []Profile {
	out := make([]Profile, 0, len(builtinNames))
	for _, name := range builtinNames {
		out = append(out, builtinProfiles[name])
	}
	return out
}

// DefaultNeedsAuth reports whether an invocation is likely to need
// authentication. Informational and completion subcommands never do.
func DefaultNeedsAuth(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" || arg == "--version" {
			return false
		}
	}
	if len(args) == 1 && args[0] == "-v" {
		return false
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		switch arg {
		case "help", "version", "completion":
			return false
		default:
			return true
		}
	}
	return true
}

// ValidEnvName accepts a bounded ASCII environment variable identifier.
func ValidEnvName(name string) bool {
	if name == "" || len(name) > 128 {
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

// ValidTokenEnvName accepts only uppercase environment names that unambiguously
// denote a bearer credential, never an operating-system or loader setting.
func ValidTokenEnvName(name string) bool {
	if !ValidEnvName(name) || strings.ToUpper(name) != name || strings.EqualFold(name, "SystemRoot") {
		return false
	}
	return name == "TOKEN" || name == "API_KEY" || strings.HasSuffix(name, "_TOKEN") || strings.HasSuffix(name, "_API_KEY") || strings.HasSuffix(name, "_ACCESS_KEY")
}

var deniedPassthroughExact = map[string]bool{
	"PATH": true, "SYSTEMROOT": true, "HOME": true, "USERPROFILE": true,
	"APPDATA": true, "LOCALAPPDATA": true, "TMPDIR": true, "TMP": true,
	"TEMP": true, "BASH_ENV": true, "ENV": true, "CDPATH": true, "IFS": true,
	"NODE_OPTIONS": true, "PYTHONPATH": true, "PYTHONSTARTUP": true,
	"PERL5OPT": true, "RUBYOPT": true, "JAVA_TOOL_OPTIONS": true,
	"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true, "GIT_ASKPASS": true,
	"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_EXEC_PATH": true,
	"GIT_TEMPLATE_DIR": true, "GIT_CONFIG": true, "GIT_CONFIG_GLOBAL": true,
	"GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_COUNT": true, "KUBECONFIG": true,
	"DOCKER_CONFIG": true, "NPM_CONFIG_USERCONFIG": true, "PGPASSFILE": true,
	"PGPASSWORD": true, "NETRC": true,
}

var deniedPassthroughPrefixes = []string{"LD_", "DYLD_", "_", "XDG_", "LOCKLARK_"}

var deniedPassthroughSuffixes = []string{"_PROXY", "_TOKEN", "_API_KEY", "_SECRET", "_PASSWORD", "_ACCESS_KEY", "_PRIVATE_KEY"}

func containsWhitespaceOrControl(value string) bool {
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// ValidPassthroughName accepts one explicitly allow-listed, non-secret
// environment variable. Loader, shell, proxy and credential variables are
// always refused even when a profile accidentally lists them.
func ValidPassthroughName(spec Spec, name, value string) bool {
	if !ValidEnvName(name) || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || len(value) > 4096 {
		return false
	}
	upper := strings.ToUpper(name)
	if deniedPassthroughExact[upper] && !(upper == "SSH_AUTH_SOCK" && spec.AllowSSHAgent) {
		return false
	}
	for _, prefix := range deniedPassthroughPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return false
		}
	}
	for _, suffix := range deniedPassthroughSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return false
		}
	}
	for _, allowed := range spec.PassthroughEnv {
		if allowed == name {
			return true
		}
	}
	return false
}

// ValidateArgs refuses dangerous subcommands and argument sequences. It checks
// both exact contiguous sequences and the leading positional command path,
// ignoring flags (and their likely values) between command words.
func ValidateArgs(spec Spec, args []string) error {
	for _, deny := range spec.DenyArgs {
		if deniedSequence(args, deny) {
			return fmt.Errorf("%w: %s", ErrDeniedArgs, strings.Join(deny, " "))
		}
	}
	return nil
}

func deniedSequence(args, deny []string) bool {
	if len(deny) == 0 || len(args) < len(deny) {
		return false
	}
	for i := 0; i+len(deny) <= len(args); i++ {
		matched := true
		for j := range deny {
			if args[i+j] != deny[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}

	start := firstCommandToken(args)
	if start < 0 {
		return false
	}
	j := 0
	for i := start; i < len(args) && j < len(deny); i++ {
		if args[i] == deny[j] || strings.HasPrefix(deny[j], "-") && strings.HasPrefix(args[i], deny[j]+"=") {
			j++
			continue
		}
		if strings.HasPrefix(deny[j], "-") {
			// The deny pattern names a flag. Keep looking for it after the
			// already matched command path; an unrelated value or flag does
			// not turn this invocation into a different command.
			continue
		}
		if strings.HasPrefix(args[i], "-") {
			// Skip a flag and its immediate value, so a global option cannot
			// hide the next command word. A token that matches the expected
			// command word is never treated as a flag value.
			if !strings.Contains(args[i], "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && args[i+1] != deny[j] {
				i++
			}
			continue
		}
		// A different positional word ends the leading command path.
		return false
	}
	return j == len(deny)
}

// firstCommandToken returns the index of the first positional argument,
// skipping flags and the value that immediately follows a flag.
func firstCommandToken(args []string) int {
	flagValue := false
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flagValue = !strings.Contains(arg, "=")
			continue
		}
		if flagValue {
			flagValue = false
			continue
		}
		return i
	}
	return -1
}
