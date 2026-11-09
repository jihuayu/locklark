package personal

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/vault"
)

const runBundleAction = "item.run.bundle"

// ErrRunProgramPinUnsupported reports that this platform has no implemented
// immutable byte-snapshot execution primitive. A caller that approved one exact
// program image is refused explicitly instead of being executed through a path
// that was verified earlier and may have changed; there is no unverified
// fallback.
var ErrRunProgramPinUnsupported = errors.New("exact program byte pin is unavailable on this platform; refusing to execute an approved pinned program")

// ErrRunProgramScriptPinUnsupported reports that a pinned program is an
// interpreted shebang script. Linux executes a pinned native executable from an
// immutable memfd snapshot reached through /proc/self/fd, and the kernel script
// loader rewrites a script's argv0 to that descriptor path. That changes $0 and
// breaks relative assets and Node-style CLI package context, so a pinned script
// is refused instead of being executed under changed semantics. There is no
// shell or interpreter wrapper and no path-based fallback.
var ErrRunProgramScriptPinUnsupported = errors.New("pinned program is an interpreted script; a sealed snapshot would rewrite the script $0 and break relative assets: bind an explicit trusted interpreter ELF with --program and pass the original script path as an argument, or bind with --pin-sha256 false to run the original script path unpinned (no exact byte guarantee)")

// BundleTarget names one vault field and the profile slot it populates.
type BundleTarget struct {
	Slot     string `json:"slot"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Field    string `json:"field"`
}

// runBundleBeforeStart is an unexported test seam placed after the exact
// program snapshot is sealed but immediately before the child starts.
// Production leaves it as a no-op.
var runBundleBeforeStart = func() {}

// RunBundleRequest describes a one-time, multi-credential disclosure to a
// trusted process. The process still runs as the local user; this is not a
// sandbox or a reusable machine grant.
type RunBundleRequest struct {
	Program string
	// ProgramSHA256, when non-empty, is the canonical SHA-256 of the exact
	// program image the caller approved. Linux execution re-hashes the sealed
	// snapshot and refuses a mismatch, so the executed bytes name the same
	// image the approval saw; a shebang script is refused because the sealed
	// descriptor path would change its $0. Other platforms refuse explicitly
	// rather than execute an image they cannot pin to an immutable snapshot.
	// Empty is the explicit unpinned scope: the original path is executed
	// directly (preserving script $0 and relative assets) and no exact-byte
	// guarantee is made, so the desktop lease path is never used for it.
	ProgramSHA256  string
	Args           []string
	Directory      string
	TimeoutSeconds int
	HelperPath     []string
	Passthrough    map[string]string
	TokenEnvName   string
	Spec           cliprofile.Spec
}

// AddDocument stores one protected document attachment. The file name is
// metadata only; it is never used as a filesystem path.
func AddDocument(path, pw string, key []byte, title, filename string, attachment []byte) (string, error) {
	r, e := command(path, pw, key, "item.add", vault.Item{Kind: "document", Title: title, Filename: filename, Attachment: bytes.Clone(attachment), AttachmentProtected: true}, nil)
	return r.id, e
}

func validRunText(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func (r RunBundleRequest) Validate(targets []BundleTarget) error {
	if !validRunText(r.Program) || !filepath.IsAbs(r.Program) || len(r.Program) > 4096 ||
		!validRunText(r.Directory) || !filepath.IsAbs(r.Directory) || len(r.Directory) > 4096 {
		return ErrRunTarget
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(r.Program), ".exe") {
		return ErrRunTarget
	}
	if r.ProgramSHA256 != "" && !digestOK(r.ProgramSHA256) {
		return ErrRunTarget
	}
	if len(r.Args) > 64 {
		return ErrRunTarget
	}
	total := 0
	for _, arg := range r.Args {
		total += len(arg)
		if !validRunText(arg) || total > 16384 {
			return ErrRunTarget
		}
	}
	if cliprofile.ValidateArgs(r.Spec, r.Args) != nil {
		return ErrRunTarget
	}
	maxTimeout := r.Spec.MaxTimeout
	if maxTimeout <= 0 {
		maxTimeout = 300
	}
	if maxTimeout > 86400 || r.TimeoutSeconds < 1 || r.TimeoutSeconds > maxTimeout {
		return ErrRunTarget
	}
	if len(r.HelperPath) > 16 {
		return ErrRunTarget
	}
	for _, entry := range r.HelperPath {
		if !validRunText(entry) || !filepath.IsAbs(entry) || len(entry) > 4096 || strings.ContainsRune(entry, os.PathListSeparator) {
			return ErrRunTarget
		}
	}
	if r.Spec.ID == "" || len(r.Spec.Slots) < 1 || len(r.Spec.Slots) > 16 || len(r.Spec.Files) > 16 || len(r.Spec.Dirs) > 16 {
		return ErrRunTarget
	}
	if r.Spec.DynamicTokenEnv {
		if !validTokenEnvironment(r.TokenEnvName) {
			return ErrRunTarget
		}
	} else if r.TokenEnvName != "" {
		return ErrRunTarget
	}
	if len(r.Passthrough) > 32 {
		return ErrRunTarget
	}
	for name, value := range r.Passthrough {
		if !cliprofile.ValidPassthroughName(r.Spec, name, value) {
			return ErrRunTarget
		}
	}
	if len(targets) < 1 || len(targets) > len(r.Spec.Slots) {
		return ErrRunTarget
	}
	slots := make(map[string]cliprofile.Slot, len(r.Spec.Slots))
	for _, slot := range r.Spec.Slots {
		slots[slot.Name] = slot
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		slot, ok := slots[target.Slot]
		if !ok || seen[target.Slot] || !idOK(target.ID) || !digestOK(target.Revision) || target.Field != string(slot.Field) {
			return ErrRunTarget
		}
		seen[target.Slot] = true
		switch slot.Kind {
		case "login":
			switch target.Field {
			case "username", "password", "url", "notes":
			default:
				return ErrRunTarget
			}
		case "document":
			switch target.Field {
			case "attachment", "filename":
			default:
				return ErrRunTarget
			}
		default:
			return ErrRunTarget
		}
	}
	for _, slot := range r.Spec.Slots {
		if !slot.Optional && !seen[slot.Name] {
			return ErrRunTarget
		}
	}
	return nil
}

type runBundleStoreRequest struct {
	targets []BundleTarget
	request RunBundleRequest
	root    string
}

func (s *runBundleStoreRequest) validate() error {
	if s == nil || !filepath.IsAbs(s.root) || len(s.root) > 4096 || !utf8.ValidString(s.root) || strings.ContainsRune(s.root, 0) || s.request.Validate(s.targets) != nil {
		return ErrRunTarget
	}
	return nil
}

func clearBundleValues(values map[string][]byte) {
	for name, value := range values {
		clear(value)
		delete(values, name)
	}
}

// extract reads every target field in one authenticated transaction. It never
// discloses a partial set: any stale, missing, trashed or malformed target
// clears the values gathered so far.
func (s *runBundleStoreRequest) extract(items []vault.Item, revisions map[string]string) (string, map[string][]byte, string, error, error) {
	slotKinds := make(map[string]string, len(s.request.Spec.Slots))
	for _, slot := range s.request.Spec.Slots {
		slotKinds[slot.Name] = slot.Kind
	}
	values := make(map[string][]byte, len(s.targets))
	for _, target := range s.targets {
		revision := revisions[target.ID]
		if revision == "" {
			clearBundleValues(values)
			return "", nil, "not-found", ErrNotFound, nil
		}
		if revision != target.Revision {
			clearBundleValues(values)
			return target.ID, nil, "conflict", ErrConflict, nil
		}
		index := -1
		for i := range items {
			if items[i].ID == target.ID {
				index = i
				break
			}
		}
		if index < 0 || items[index].Kind != slotKinds[target.Slot] {
			clearBundleValues(values)
			return "", nil, "", nil, invalid
		}
		item := items[index]
		if item.State == "trashed" {
			clearBundleValues(values)
			return target.ID, nil, "trashed", ErrTrashed, nil
		}
		var value []byte
		switch target.Field {
		case "username":
			value = []byte(item.Username)
		case "password":
			value = []byte(item.Password)
		case "url":
			value = []byte(item.URL)
		case "notes":
			value = []byte(item.Notes)
		case "attachment":
			value = bytes.Clone(item.Attachment)
		case "filename":
			value = []byte(item.Filename)
		default:
			clearBundleValues(values)
			return "", nil, "", nil, invalid
		}
		values[target.Slot] = value
	}
	return s.targets[0].ID, values, "intent", nil, nil
}

func (s *runBundleStoreRequest) binding(secret []byte) (string, error) {
	if s == nil || s.validate() != nil {
		return "", ErrRunTarget
	}
	key, e := hkdf.Key(sha256.New, secret, nil, "locklark/personal/run-bundle/key/v1", 32)
	if e != nil {
		return "", invalid
	}
	defer clear(key)
	raw, e := json.Marshal(struct {
		Profile, Platform, Stdio, Environment, TemporaryRoot string
		HelperPath                                           []string
		Targets                                              []BundleTarget
		Passthrough                                          map[string]string
		TokenEnvName                                         string
		Spec                                                 cliprofile.Spec
		Program                                              string
		ProgramSHA256                                        string
		Args                                                 []string
		Directory                                            string
		TimeoutSeconds                                       int
	}{
		Profile:        "bundle-inherited-stdio-v1",
		Platform:       runtime.GOOS,
		Stdio:          "inherit-os-stdin-stdout-stderr-no-capture",
		Environment:    "os-systemroot-only+bundle-spec+explicit-path+isolated-home-gh-xdg-temp-v1",
		TemporaryRoot:  s.root,
		HelperPath:     s.request.HelperPath,
		Targets:        s.targets,
		Passthrough:    s.request.Passthrough,
		TokenEnvName:   s.request.TokenEnvName,
		Spec:           s.request.Spec,
		Program:        s.request.Program,
		ProgramSHA256:  s.request.ProgramSHA256,
		Args:           s.request.Args,
		Directory:      s.request.Directory,
		TimeoutSeconds: s.request.TimeoutSeconds,
	})
	if e != nil {
		return "", invalid
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// RunBundle commits the authenticated multi-target intent before rendering any
// credential and starting one direct child. It consumes standard streams
// without capture and never returns credential material.
func RunBundle(ctx context.Context, path, pw string, key []byte, targets []BundleTarget, request RunBundleRequest) (RunReceipt, error) {
	return runBundle(ctx, targets, request, createRunCLITemp, func(s *runBundleStoreRequest) (result, error) {
		return command(path, pw, key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: s})
	}, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
		return executeRunBundle(ctx, req, root, rendered, runCLIStreams{os.Stdin, os.Stdout, os.Stderr})
	}, os.RemoveAll)
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for name, value := range values {
		out[name] = value
	}
	return out
}

// cloneRunBundleTargets and cloneRunBundleRequest own every caller slice and
// map so a signed intent cannot be changed afterwards. The session-native grant
// API reuses them before it binds the same all-target intent.
func cloneRunBundleTargets(targets []BundleTarget) []BundleTarget {
	return append([]BundleTarget(nil), targets...)
}

func cloneRunBundleRequest(request RunBundleRequest) RunBundleRequest {
	request.Args = append([]string(nil), request.Args...)
	request.HelperPath = append([]string(nil), request.HelperPath...)
	request.Passthrough = cloneStringMap(request.Passthrough)
	request.Spec = cliprofile.CloneSpec(request.Spec)
	return request
}

func runBundle(ctx context.Context, targets []BundleTarget, request RunBundleRequest, createTemp func() (string, error), prepare func(*runBundleStoreRequest) (result, error), execute func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error), remove func(string) error) (receipt RunReceipt, retErr error) {
	if ctx == nil || request.Validate(targets) != nil {
		return RunReceipt{}, ErrRunTarget
	}
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunCancelled
	}
	// Own every caller slice and map before the signed intent so nothing can
	// change the disclosed set between authorization and execution.
	targets = cloneRunBundleTargets(targets)
	request = cloneRunBundleRequest(request)

	root, e := createTemp()
	if e != nil {
		return RunReceipt{}, ErrRunTemporary
	}
	defer func() {
		if remove(root) != nil {
			receipt, retErr = RunReceipt{}, ErrRunCleanup
		}
	}()
	if e = makeBundleDirs(root, request.Spec.Dirs); e != nil {
		return RunReceipt{}, e
	}
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunCancelled
	}

	storeRequest := &runBundleStoreRequest{targets: targets, request: request, root: root}
	r, e := prepare(storeRequest)
	defer clearBundleValues(r.values)
	if e != nil {
		return RunReceipt{}, e
	}
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunCancelled
	}
	rendered, e := cliprofile.Render(request.Spec, root, request.TokenEnvName, r.values, request.Passthrough)
	defer func() {
		clear(rendered.Env)
		for i := range rendered.Files {
			clear(rendered.Files[i].Content)
		}
	}()
	if e != nil {
		return RunReceipt{}, ErrRunCredential
	}
	code, e := execute(ctx, request, root, rendered)
	if errors.Is(e, ErrRunCancelled) {
		return RunReceipt{}, ErrRunCancelled
	}
	if errors.Is(e, ErrRunCredential) {
		return RunReceipt{}, ErrRunCredential
	}
	if errors.Is(e, ErrRunProgramPinUnsupported) {
		return RunReceipt{}, ErrRunProgramPinUnsupported
	}
	if errors.Is(e, ErrRunProgramScriptPinUnsupported) {
		return RunReceipt{}, ErrRunProgramScriptPinUnsupported
	}
	if e != nil || code < 0 {
		return RunReceipt{}, ErrRunResult
	}
	return RunReceipt{Status: "process-exited", Session: r.session, Intent: r.intent, TargetDigest: r.destinationDigest, ExitCode: code}, nil
}

func makeBundleDirs(root string, extra []string) error {
	names := make([]string, 0, 6+len(extra))
	names = append(names, "home", "gh", "config", "cache", "data", "tmp")
	names = append(names, extra...)
	for _, name := range names {
		target, err := bundleDirectory(root, name)
		if err != nil {
			return ErrRunTarget
		}
		if err = os.MkdirAll(target, 0700); err != nil {
			return ErrRunTemporary
		}
	}
	return nil
}

func bundleDirectory(root, name string) (string, error) {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return "", ErrRunTarget
	}
	rel := filepath.FromSlash(name)
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, string(filepath.Separator)) || filepath.Clean(rel) != rel || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrRunTarget
	}
	target := filepath.Join(root, rel)
	check, err := filepath.Rel(root, target)
	if err != nil || check == "." || strings.HasPrefix(check, "..") {
		return "", ErrRunTarget
	}
	return target, nil
}

func executeRunBundle(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle, streams runCLIStreams) (int, error) {
	if ctx == nil || streams.in == nil || streams.out == nil || streams.err == nil {
		return 0, ErrRunResult
	}
	if ctx.Err() != nil {
		return 0, ErrRunCancelled
	}
	if err := writeRunBundleFiles(root, rendered.Files); err != nil {
		return 0, ErrRunTemporary
	}
	env, e := runBaseEnvironment()
	if e != nil {
		return 0, ErrRunResult
	}
	env = append(env,
		"PATH="+strings.Join(req.HelperPath, string(os.PathListSeparator)),
		"HOME="+filepath.Join(root, "home"),
		"GH_CONFIG_DIR="+filepath.Join(root, "gh"),
		"XDG_CONFIG_HOME="+filepath.Join(root, "config"),
		"XDG_CACHE_HOME="+filepath.Join(root, "cache"),
		"XDG_DATA_HOME="+filepath.Join(root, "data"),
		"TMPDIR="+filepath.Join(root, "tmp"),
		"TMP="+filepath.Join(root, "tmp"),
		"TEMP="+filepath.Join(root, "tmp"),
	)
	if runtime.GOOS == "windows" {
		env = append(env, "USERPROFILE="+filepath.Join(root, "home"), "APPDATA="+filepath.Join(root, "config"), "LOCALAPPDATA="+filepath.Join(root, "data"))
	}
	env = append(env, rendered.Env...)
	defer clear(env)
	limited, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd, closeProgram, e := newRunBundleCommand(limited, req.Program, req.Args, req.ProgramSHA256)
	if e != nil {
		return 0, e
	}
	defer closeProgram()
	cmd.Dir, cmd.Env = req.Directory, env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = streams.in, streams.out, streams.err
	runBundleBeforeStart()
	// CommandContext rechecks cancellation immediately before Start and kills
	// the direct child on cancellation. It cannot revoke a disclosed credential
	// or promise to terminate descendants of an intentionally trusted program.
	e = cmd.Run()
	if limited.Err() != nil {
		if cmd.Process == nil {
			return 0, ErrRunCancelled
		}
		return 0, ErrRunResult
	}
	if e == nil {
		return 0, nil
	}
	var exited *exec.ExitError
	if errors.As(e, &exited) && exited.ExitCode() >= 0 {
		return exited.ExitCode(), nil
	}
	return 0, ErrRunResult
}
