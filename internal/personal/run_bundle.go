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

// BundleTarget names one vault field and the profile slot it populates.
type BundleTarget struct {
	Slot     string `json:"slot"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Field    string `json:"field"`
}

// RunBundleRequest describes a one-time, multi-credential disclosure to a
// trusted process. The process still runs as the local user; this is not a
// sandbox or a reusable machine grant.
type RunBundleRequest struct {
	Program        string
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

func cloneRunBundleRequest(request RunBundleRequest) RunBundleRequest {
	request.Args = append([]string(nil), request.Args...)
	request.HelperPath = append([]string(nil), request.HelperPath...)
	request.Passthrough = cloneStringMap(request.Passthrough)
	request.Spec = cliprofile.CloneSpec(request.Spec)
	return request
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

func runBundle(ctx context.Context, targets []BundleTarget, request RunBundleRequest, createTemp func() (string, error), prepare func(*runBundleStoreRequest) (result, error), execute func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error), remove func(string) error) (receipt RunReceipt, retErr error) {
	if ctx == nil || request.Validate(targets) != nil {
		return RunReceipt{}, ErrRunTarget
	}
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunCancelled
	}
	// Own every caller slice and map before the signed intent so nothing can
	// change the disclosed set between authorization and execution.
	targets = append([]BundleTarget(nil), targets...)
	request.Args = append([]string(nil), request.Args...)
	request.HelperPath = append([]string(nil), request.HelperPath...)
	request.Passthrough = cloneStringMap(request.Passthrough)
	request.Spec = cliprofile.CloneSpec(request.Spec)

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
	if e != nil || code < 0 {
		return RunReceipt{}, ErrRunResult
	}
	return RunReceipt{Status: "process-exited", Session: r.session, Intent: r.intent, TargetDigest: r.destinationDigest, ExitCode: code}, nil
}

// RunBundlePreparationStatus is the explicit lifecycle state of a prepared
// brokered run. "intent-recorded" means the session committed the same signed
// item.run.bundle binding RunBundle would commit before rendering credentials.
const RunBundlePreparationStatus = "intent-recorded"

// RunBundlePreparationReceipt is the non-secret metadata returned with a
// prepared run. It carries no program, directory, helper or credential value.
type RunBundlePreparationReceipt struct {
	Status       string `json:"status"`
	Session      string `json:"session"`
	Intent       string `json:"intent"`
	TargetDigest string `json:"target_digest"`
}

// cloneBundleTargets deep-owns caller target data before any validation or
// transaction so a concurrent caller mutation cannot change what was signed.
func cloneBundleTargets(targets []BundleTarget) []BundleTarget {
	return append([]BundleTarget(nil), targets...)
}

// PrepareBrokeredRun validates the exact request, targets and private temporary
// root, then commits the RunBundle intent through the session transaction so
// session lock/epoch and audit logic apply. It returns the all-or-nothing slot
// values with the receipt; it never starts a child or creates bundle files. A
// cancelled context clears any extracted values and commits no intent.
func (s *Session) PrepareBrokeredRun(ctx context.Context, targets []BundleTarget, request RunBundleRequest, root string) (receipt RunBundlePreparationReceipt, values map[string][]byte, err error) {
	if ctx == nil || s == nil {
		return RunBundlePreparationReceipt{}, nil, ErrRunTarget
	}
	if ctx.Err() != nil {
		return RunBundlePreparationReceipt{}, nil, ErrRunCancelled
	}
	targets = cloneBundleTargets(targets)
	request = cloneRunBundleRequest(request)
	if (&runBundleStoreRequest{targets: targets, request: request, root: root}).validate() != nil {
		return RunBundlePreparationReceipt{}, nil, ErrRunTarget
	}
	if ctx.Err() != nil {
		return RunBundlePreparationReceipt{}, nil, ErrRunCancelled
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.execute(runBundleAction, vault.Item{}, nil, commandOption{runBundle: &runBundleStoreRequest{targets: targets, request: request, root: root}})
	defer func() {
		if err != nil {
			// Never hand back a partial set, and never leave extracted bytes
			// in scope after a failed or cancelled preparation.
			clearBundleValues(r.values)
			clearBundleValues(values)
			values, receipt = nil, RunBundlePreparationReceipt{}
		}
	}()
	// Recheck cancellation after the transaction: the intent may already be
	// committed, but no value may cross the boundary.
	if ctx.Err() != nil {
		return RunBundlePreparationReceipt{}, nil, ErrRunCancelled
	}
	if e != nil {
		return RunBundlePreparationReceipt{}, nil, e
	}
	if r.session == "" || r.intent == "" || r.destinationDigest == "" || len(r.values) != len(targets) {
		return RunBundlePreparationReceipt{}, nil, ErrRunCredential
	}
	values = r.values
	r.values = nil
	return RunBundlePreparationReceipt{
		Status:       RunBundlePreparationStatus,
		Session:      r.session,
		Intent:       r.intent,
		TargetDigest: r.destinationDigest,
	}, values, nil
}

// BrokeredRunPreparer is the desktop-broker preparation step for
// RunBrokeredBundle. It receives the private run root RunBrokeredBundle has
// already created, so it can bind exactly that root in the one-shot scope, and
// returns the preparation receipt plus the exact per-slot values.
//
// On success, ownership of every returned byte slice transfers to
// RunBrokeredBundle: the existing runBundle cleanup zeroes them after the
// profile is rendered and the child has exited. On a callback error, a
// malformed receipt or an invalid value set, the returned buffers are zeroed
// immediately instead. The callback error itself is preserved unchanged so a
// caller of RunBrokeredBundle can fall back only on an exact sentinel (for
// example browserhost.ErrBrokerUnavailable); no error is translated here.
type BrokeredRunPreparer func(ctx context.Context, privateTempRoot string) (RunBundlePreparationReceipt, map[string][]byte, error)

func validBrokeredRunReceipt(receipt RunBundlePreparationReceipt) bool {
	return receipt.Status == RunBundlePreparationStatus && idOK(receipt.Session) &&
		digestOK(receipt.Intent) && digestOK(receipt.TargetDigest)
}

// brokeredRunValuesValid requires exactly one non-nil value per requested slot
// and nothing else. Values are never trimmed or re-keyed here.
func brokeredRunValuesValid(targets []BundleTarget, values map[string][]byte) bool {
	if len(values) != len(targets) {
		return false
	}
	for _, target := range targets {
		value, ok := values[target.Slot]
		if !ok || value == nil {
			return false
		}
	}
	return true
}

// brokeredRunPreparation zeroes every returned buffer, including any partial
// set a failed callback handed back, and releases the map. It also redacts a
// receipt that does not carry canonical metadata, and replaces a refused
// value set with nil before rendering sees it.
func brokeredRunPreparation(targets []BundleTarget, receipt RunBundlePreparationReceipt, values map[string][]byte, err error) (RunBundlePreparationReceipt, map[string][]byte, error) {
	if err != nil {
		// Preserve the callback error exactly; only the partial secrets are
		// dropped so a caller can still fall back on an exact sentinel.
		clearBundleValues(values)
		return RunBundlePreparationReceipt{}, nil, err
	}
	if !validBrokeredRunReceipt(receipt) || !brokeredRunValuesValid(targets, values) {
		clearBundleValues(values)
		return RunBundlePreparationReceipt{}, nil, ErrRunCredential
	}
	return receipt, values, nil
}

// runBrokeredBundle is RunBrokeredBundle with the private-root creator, value
// cleanup and child executor injected so tests stay deterministic.
func runBrokeredBundle(ctx context.Context, targets []BundleTarget, request RunBundleRequest, prepare BrokeredRunPreparer, create func() (string, error), remove func(string) error, execute func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error)) (RunReceipt, error) {
	if prepare == nil {
		return RunReceipt{}, ErrRunTarget
	}
	return runBundle(ctx, targets, request, create, func(s *runBundleStoreRequest) (result, error) {
		return brokeredRunStore(ctx, s, prepare)
	}, execute, remove)
}

// brokeredRunStore adapts the desktop preparation callback to the local
// store boundary. The callback runs only after runBundle created root and the
// profile bundle directories, so it receives the exact private root.
func brokeredRunStore(ctx context.Context, s *runBundleStoreRequest, prepare BrokeredRunPreparer) (result, error) {
	if s == nil || s.validate() != nil {
		// Never let the callback bind or disclose anything for a scope the
		// local RunBundle lifecycle would refuse.
		return result{}, ErrRunTarget
	}
	receipt, values, err := prepare(ctx, s.root)
	receipt, values, err = brokeredRunPreparation(s.targets, receipt, values, err)
	if err != nil {
		return result{}, err
	}
	return result{values: values, session: receipt.Session, intent: receipt.Intent, destinationDigest: receipt.TargetDigest}, nil
}

// RunBrokeredBundle executes values that the desktop broker already prepared
// and audited for exactly targets and request. It shares the local RunBundle
// lifecycle: it validates the request, creates the private run root first,
// passes that root to prepare, accepts only a canonical preparation receipt
// and a value set with exactly one entry per target slot, then renders the
// profile and starts the direct child through executeRunBundle.
//
// A nil prepare, a malformed receipt or an invalid value set fails closed with
// ErrRunTarget or ErrRunCredential before any credential is rendered. A
// preparation error is returned unchanged; values are zeroed and the root is
// removed on every path, on success only after execution. The caller owns
// targets and request and may reuse them; their slices are cloned before use.
func RunBrokeredBundle(ctx context.Context, targets []BundleTarget, request RunBundleRequest, prepare BrokeredRunPreparer) (RunReceipt, error) {
	return runBrokeredBundle(ctx, targets, request, prepare, createRunCLITemp, os.RemoveAll, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
		return executeRunBundle(ctx, req, root, rendered, runCLIStreams{os.Stdin, os.Stdout, os.Stderr})
	})
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
	info, e := os.Stat(req.Program)
	if e != nil || !info.Mode().IsRegular() {
		return 0, ErrRunResult
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
	cmd := exec.CommandContext(limited, req.Program, req.Args...)
	cmd.Dir, cmd.Env = req.Directory, env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = streams.in, streams.out, streams.err
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
