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

	"github.com/jihuayu/locklark/internal/vault"
)

const (
	RunCLIProfileToken = "token"
	RunCLIProfileGH    = "gh"
)

var ErrRunCancelled = errors.New("local process cancelled before start; intent may have been recorded")
var ErrRunCleanup = errors.New("local process temporary state cleanup failed; execution may have occurred")
var ErrRunCredential = errors.New("local process credential refused before start; intent may have been recorded")
var ErrRunTemporary = errors.New("local process trusted temporary directory unavailable; process not started")

// RunCLIRequest describes a one-time disclosure to a trusted process, not a
// sandbox. HelperPath is explicit; no parent environment is inherited.
type RunCLIRequest struct {
	Program        string
	Args           []string
	Directory      string
	Name           string
	TimeoutSeconds int
	Profile        string
	HelperPath     []string
}

type runCLIPolicy struct {
	profile    string
	helperPath []string
	root       string
}

func (r RunCLIRequest) baseRequest() RunRequest {
	return RunRequest{Program: r.Program, Args: r.Args, Directory: r.Directory, Name: r.Name, TimeoutSeconds: r.TimeoutSeconds}
}

func (r RunCLIRequest) runRequest(root string) RunRequest {
	base := r.baseRequest()
	base.Args = append([]string{}, r.Args...)
	base.cli = &runCLIPolicy{profile: r.Profile, helperPath: append([]string{}, r.HelperPath...), root: root}
	return base
}

func validTokenEnvironment(name string) bool {
	if !ValidInjectionName(name) || strings.ToUpper(name) != name {
		return false
	}
	return name == "TOKEN" || name == "API_KEY" || strings.HasSuffix(name, "_TOKEN") || strings.HasSuffix(name, "_API_KEY") || strings.HasSuffix(name, "_ACCESS_KEY")
}

func (r RunCLIRequest) Validate() error {
	if r.baseRequest().Validate() != nil || !validTokenEnvironment(r.Name) || len(r.HelperPath) > 16 {
		return ErrRunTarget
	}
	for _, directory := range r.HelperPath {
		if !filepath.IsAbs(directory) || len(directory) > 4096 || !utf8.ValidString(directory) || strings.ContainsAny(directory, "\x00"+string(os.PathListSeparator)) {
			return ErrRunTarget
		}
	}
	switch r.Profile {
	case RunCLIProfileToken:
	case RunCLIProfileGH:
		if r.Name != "GH_TOKEN" {
			return ErrRunTarget
		}
		// These commands intentionally persist authentication or install global
		// Git credential helpers. This profile only lends an environment token.
		for i, arg := range r.Args {
			if arg == "auth" && i+1 < len(r.Args) && (r.Args[i+1] == "login" || r.Args[i+1] == "setup-git") {
				return ErrRunTarget
			}
		}
	default:
		return ErrRunTarget
	}
	return nil
}

func (p *runCLIPolicy) validate(r RunRequest) error {
	if p == nil || !filepath.IsAbs(p.root) || len(p.root) > 4096 || !utf8.ValidString(p.root) || strings.ContainsRune(p.root, 0) {
		return ErrRunTarget
	}
	return (RunCLIRequest{Program: r.Program, Args: r.Args, Directory: r.Directory, Name: r.Name, TimeoutSeconds: r.TimeoutSeconds, Profile: p.profile, HelperPath: p.helperPath}).Validate()
}

func (p *runCLIPolicy) binding(r RunRequest, secret []byte) (string, error) {
	if p.validate(r) != nil {
		return "", ErrRunTarget
	}
	profile := "single-token-inherited-stdio-v1"
	if p.profile == RunCLIProfileGH {
		profile = "gh-token-inherited-stdio-v1"
	}
	key, e := hkdf.Key(sha256.New, secret, nil, "locklark/personal/run-cli/key/v1", 32)
	if e != nil {
		return "", invalid
	}
	defer clear(key)
	raw, e := json.Marshal(struct {
		Profile, Platform, Stdio, Environment, TemporaryRoot string
		HelperPath                                           []string
		Request                                              RunRequest
	}{profile, runtime.GOOS, "inherit-os-stdin-stdout-stderr-no-capture", "os-systemroot-only+single-token+explicit-path+isolated-home-gh-xdg-temp-v1", p.root, p.helperPath, r})
	if e != nil {
		return "", invalid
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// RunCLI commits the authenticated one-time intent before starting a direct
// child. It connects the real process standard streams without reading or
// recording their bodies. The child and its descendants can retain the value.
func RunCLI(ctx context.Context, path, pw string, key []byte, target RevealTarget, request RunCLIRequest) (RunReceipt, error) {
	return runCLI(ctx, target, request, func(r *RunRequest) (result, error) {
		return command(path, pw, key, "item.run.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{run: r})
	}, func(ctx context.Context, r RunRequest, value []byte) (int, error) {
		return executeRunCLI(ctx, r, value, runCLIStreams{os.Stdin, os.Stdout, os.Stderr})
	}, os.RemoveAll)
}

func runCLI(ctx context.Context, target RevealTarget, request RunCLIRequest, prepare func(*RunRequest) (result, error), execute func(context.Context, RunRequest, []byte) (int, error), remove func(string) error) (receipt RunReceipt, retErr error) {
	if ctx == nil || target.Field != "password" || !ValidRevealTarget(target.ID, target.Revision, target.Field) || request.Validate() != nil {
		return RunReceipt{}, ErrRunTarget
	}
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunCancelled
	}
	// Own all caller slices before intent construction. No caller mutation can
	// change the process target between the signed intent and execution.
	request.Args = append([]string{}, request.Args...)
	request.HelperPath = append([]string{}, request.HelperPath...)
	root, e := createRunCLITemp()
	if e != nil {
		return RunReceipt{}, ErrRunTemporary
	}
	defer func() {
		if remove(root) != nil {
			receipt, retErr = RunReceipt{}, ErrRunCleanup
		}
	}()
	for _, name := range []string{"home", "gh", "config", "cache", "data", "tmp"} {
		if os.Mkdir(filepath.Join(root, name), 0700) != nil {
			return RunReceipt{}, ErrRunTemporary
		}
	}
	run := request.runRequest(root)
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunCancelled
	}
	r, e := prepare(&run)
	defer clear(r.value)
	if e != nil {
		return RunReceipt{}, e
	}
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunCancelled
	}
	if run.cli.profile == RunCLIProfileGH && len(bytes.TrimSpace(r.value)) == 0 {
		// gh treats a blank environment token as absent. Never let this
		// profile silently fall back to another authentication source.
		return RunReceipt{}, ErrRunCredential
	}
	code, e := execute(ctx, run, r.value)
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

type runCLIStreams struct{ in, out, err *os.File }

func executeRunCLI(ctx context.Context, r RunRequest, value []byte, streams runCLIStreams) (int, error) {
	if ctx == nil || r.cli == nil || r.Validate() != nil || !utf8.Valid(value) || strings.ContainsRune(string(value), 0) || streams.in == nil || streams.out == nil || streams.err == nil {
		return 0, ErrRunResult
	}
	if ctx.Err() != nil {
		return 0, ErrRunCancelled
	}
	if r.cli.profile == RunCLIProfileGH && len(bytes.TrimSpace(value)) == 0 {
		return 0, ErrRunCredential
	}
	info, e := os.Stat(r.Program)
	if e != nil || !info.Mode().IsRegular() {
		return 0, ErrRunResult
	}
	env, e := runBaseEnvironment()
	if e != nil {
		return 0, ErrRunResult
	}
	root := r.cli.root
	env = append(env, r.Name+"="+string(value), "PATH="+strings.Join(r.cli.helperPath, string(os.PathListSeparator)), "HOME="+filepath.Join(root, "home"), "GH_CONFIG_DIR="+filepath.Join(root, "gh"), "XDG_CONFIG_HOME="+filepath.Join(root, "config"), "XDG_CACHE_HOME="+filepath.Join(root, "cache"), "XDG_DATA_HOME="+filepath.Join(root, "data"), "TMPDIR="+filepath.Join(root, "tmp"), "TMP="+filepath.Join(root, "tmp"), "TEMP="+filepath.Join(root, "tmp"))
	if runtime.GOOS == "windows" {
		env = append(env, "USERPROFILE="+filepath.Join(root, "home"), "APPDATA="+filepath.Join(root, "config"), "LOCALAPPDATA="+filepath.Join(root, "data"))
	}
	defer clear(env)
	limited, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(limited, r.Program, r.Args...)
	cmd.Dir, cmd.Env = r.Directory, env
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
