package personal

import (
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

const runProfile = "single-env-direct-process-v1"

var ErrRunTarget = errors.New("invalid local process target")
var ErrRunResult = errors.New("local process result unavailable; intent recorded, execution may have occurred")

type RunRequest struct {
	Program        string   `json:"program"`
	Args           []string `json:"args"`
	Directory      string   `json:"directory"`
	Name           string   `json:"name"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	// Only RunCLI constructs this policy. A nil policy retains the original
	// empty-environment/null-stream contract and its original binding.
	cli *runCLIPolicy
}
type RunReceipt struct {
	Status       string `json:"status"`
	Session      string `json:"session"`
	Intent       string `json:"intent"`
	TargetDigest string `json:"target_digest"`
	ExitCode     int    `json:"exit_code"`
}

func runAction(action string) bool {
	return action == "item.run.username" || action == "item.run.password"
}
func (r RunRequest) Validate() error {
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(r.Program), ".exe") {
		return ErrRunTarget
	}
	validText := func(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
	if !filepath.IsAbs(r.Program) || !filepath.IsAbs(r.Directory) || len(r.Program) > 4096 || len(r.Directory) > 4096 || !validText(r.Program) || !validText(r.Directory) || !ValidInjectionName(r.Name) || strings.EqualFold(r.Name, "SystemRoot") || r.TimeoutSeconds < 1 || r.TimeoutSeconds > 300 || len(r.Args) > 64 {
		return ErrRunTarget
	}
	total := 0
	for _, arg := range r.Args {
		total += len(arg)
		if !validText(arg) || total > 16384 {
			return ErrRunTarget
		}
	}
	if r.cli != nil {
		return r.cli.validate(r)
	}
	return nil
}
func (r RunRequest) binding(secret []byte) (string, error) {
	if r.cli != nil {
		return r.cli.binding(r, secret)
	}
	key, e := hkdf.Key(sha256.New, secret, nil, "locklark/personal/run-env/key/v1", 32)
	if e != nil {
		return "", invalid
	}
	defer clear(key)
	raw, e := json.Marshal(struct {
		Profile, Platform, Environment, Stdio string
		Request                               RunRequest
	}{runProfile, runtime.GOOS, "empty-plus-os-systemroot", "null", r})
	if e != nil {
		return "", invalid
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// RunEnv explicitly discloses one field to a trusted local program. It is not
// a sandbox or a machine grant. The caller must obtain local human consent.
// No child output is returned; an exit code is only a locally observed outcome.
func RunEnv(ctx context.Context, path, pw string, key []byte, target RevealTarget, request RunRequest) (RunReceipt, error) {
	if request.cli != nil {
		return RunReceipt{}, ErrRunTarget
	}
	return runEnv(ctx, target, request, func(r *RunRequest) (result, error) {
		return command(path, pw, key, "item.run."+target.Field, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{run: r})
	}, executeRun)
}
func runEnv(ctx context.Context, target RevealTarget, request RunRequest, prepare func(*RunRequest) (result, error), execute func(context.Context, RunRequest, []byte) (int, error)) (RunReceipt, error) {
	// Own the argument slice throughout the intent and execution phases.
	request.Args = append([]string{}, request.Args...)
	if ctx == nil || ctx.Err() != nil || !ValidRevealTarget(target.ID, target.Revision, target.Field) || request.Validate() != nil {
		return RunReceipt{}, ErrRunTarget
	}
	r, e := prepare(&request)
	defer clear(r.value)
	if e != nil {
		return RunReceipt{}, e
	}
	if ctx.Err() != nil {
		return RunReceipt{}, ErrRunResult
	}
	code, e := execute(ctx, request, r.value)
	if e != nil || code < 0 {
		return RunReceipt{}, ErrRunResult
	}
	return RunReceipt{Status: "process-exited", Session: r.session, Intent: r.intent, TargetDigest: r.destinationDigest, ExitCode: code}, nil
}
func executeRun(ctx context.Context, r RunRequest, value []byte) (int, error) {
	if ctx == nil || ctx.Err() != nil || r.cli != nil || r.Validate() != nil || !utf8.Valid(value) || strings.ContainsRune(string(value), 0) {
		return 0, ErrRunResult
	}
	// An existing exact regular path prevents PATHEXT fallback on Windows.
	// The local filesystem and executable are trusted; this is not content pinning.
	info, e := os.Stat(r.Program)
	if e != nil || !info.Mode().IsRegular() {
		return 0, ErrRunResult
	}
	env, e := runBaseEnvironment()
	if e != nil {
		return 0, ErrRunResult
	}
	env = append(env, r.Name+"="+string(value))
	defer clear(env)
	limited, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutSeconds)*time.Second)
	defer cancel()
	// Absolute executable only; never use a shell or resolve through PATH.
	// nil standard streams connect to the null device, with no capture buffers.
	cmd := exec.CommandContext(limited, r.Program, r.Args...)
	cmd.Dir = r.Directory
	cmd.Env = env
	e = cmd.Run()
	if limited.Err() != nil {
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
