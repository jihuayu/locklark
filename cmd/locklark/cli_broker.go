package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/personal"
)

// The brokered CLI run (Darwin only). `locklark cli run` asks the running
// desktop broker for exactly the pinned slot values through the audited
// personal.RunBrokeredBundle lifecycle, so the desktop request is made only
// after the private run root exists and the exact request and targets are
// committed. On every other platform the existing local-factor path runs
// unchanged, and so it does on Darwin after the exact, single
// browserhost.ErrBrokerUnavailable outcome.

// errCLIRunBrokerAbsent reports that the desktop broker is not running. It is
// internal only: the caller turns it into the existing local-factor path.
var errCLIRunBrokerAbsent = errors.New("desktop browser broker is not running")

// cliRunBrokerEnabled reports whether this build attempts the brokered path.
// Only Darwin has the kernel-attested peer terminal the broker requires; every
// other platform keeps the existing local-factor path untouched.
var cliRunBrokerEnabled = func() bool { return runtime.GOOS == "darwin" }

// The seams below are injectable for tests only; production never replaces
// them.
var (
	// cliRunBrokerTTY returns the name of the caller's own controlling
	// terminal. The peer ID is deliberately not sent: it is never authority.
	cliRunBrokerTTY = browserhost.CurrentTTYIdentity
	// cliRunBrokerRequest is the one-shot desktop request.
	cliRunBrokerRequest = browserhost.RequestCLIRun
	// cliRunBrokerRandom fills the per-request nonce buffer.
	cliRunBrokerRandom = rand.Read
	// cliLocalConsoleOpen is the existing local-factor controlling console.
	cliLocalConsoleOpen = openRunCLIConsole
	// cliRunBrokerDescribe shows the exact broker request the owner is asked
	// to approve on the terminal.
	cliRunBrokerDescribe = describeCLIRunBrokerRequest
)

// cliRunBrokerNonces records the nonce of every broker request this process
// actually made. It exists so tests can prove each request drew a fresh one.
var cliRunBrokerNonces []string

// cliRunBrokerCall is one brokered attempt. It carries the same caller-owned
// binding, targets, and request that runCLIRun already derived and validated,
// so the broker request is built from exactly those values.
type cliRunBrokerCall struct {
	Binding clibinding.ToolBinding
	Targets []personal.BundleTarget
	Request personal.RunBundleRequest
}

// run is the audited lifecycle: the private root is created first, then the
// broker is asked with that exact root, request and targets, and the returned
// values are rendered and executed exactly as a local RunBundle run.
func (c cliRunBrokerCall) run(ctx context.Context) (personal.RunReceipt, error) {
	return personal.RunBrokeredBundle(ctx, c.Targets, c.Request, c.prepare)
}

// prepare turns the exact private root and the committed request and targets
// of one personal.RunBrokeredBundle call into the complete broker request.
// Nothing here samples the binding, the environment, or the caller's state
// again: the callback snapshots are the only source of every scope field.
func (c cliRunBrokerCall) prepare(ctx context.Context, root string, request personal.RunBundleRequest, targets []personal.BundleTarget) (personal.RunBundlePreparationReceipt, map[string][]byte, error) {
	scope, e := c.scope(root, request, targets)
	if e != nil {
		return personal.RunBundlePreparationReceipt{}, nil, e
	}
	// Clear blanks Args, Helper, and Passthru in place, so the request gets
	// its own clone: the scope and the request never share those storage
	// arrays, and clearing one never empties the other.
	defer scope.Clear()
	req := browserhost.CLIRunBrokerRequest{V: 1, VaultPath: c.Binding.VaultPath, Scope: scope.Clone(), Targets: make([]personal.CLIBrokerTarget, len(targets))}
	for i, target := range targets {
		req.Targets[i] = personal.CLIBrokerTarget{Slot: target.Slot, ID: target.ID, Revision: target.Revision, Field: target.Field}
	}
	cliRunBrokerNonces = append(cliRunBrokerNonces, scope.Nonce)
	fmt.Fprint(os.Stderr, cliRunBrokerDescribe(req))
	resp, e := cliRunBrokerRequest(ctx, req)
	if e != nil {
		// The error is returned unchanged so the caller can apply the exact
		// fallback gate; it never surfaces to the owner as-is.
		return personal.RunBundlePreparationReceipt{}, nil, e
	}
	if resp.V != 1 || resp.Receipt.Status != personal.RunBundlePreparationStatus || len(resp.PreparedValues) != len(targets) {
		// A reply without the audited receipt and exactly one value per
		// requested slot is never trusted. RunBrokeredBundle zeroes any
		// partial value set it receives with this error.
		clearCLIRunBrokerValues(resp.PreparedValues)
		return personal.RunBundlePreparationReceipt{}, nil, browserhost.ErrCLIRunRefused
	}
	return resp.Receipt, resp.PreparedValues, nil
}

// scope builds the complete CLIRunScope from the callback snapshots and the
// binding, then proves it describes exactly the committed request and targets
// through the same canonical converters the desktop applies.
func (c cliRunBrokerCall) scope(root string, request personal.RunBundleRequest, targets []personal.BundleTarget) (browserhost.CLIRunScope, error) {
	tty, _, e := cliRunBrokerTTY()
	if e != nil || tty == "" {
		return browserhost.CLIRunScope{}, cliRunBrokerTTYError{}
	}
	nonce, e := cliRunBrokerNonce()
	if e != nil {
		return browserhost.CLIRunScope{}, e
	}
	scope := browserhost.CLIRunScope{
		Profile:     c.Binding.Profile,
		TTY:         tty,
		TTYPeerID:   "",
		TTYPlatform: browserhost.CLIRunTTYPlatform(),
		Nonce:       nonce,
		Program:     request.Program,
		ProgramSH:   c.Binding.ProgramSHA256,
		CWD:         request.Directory,
		TempRoot:    root,
		Args:        append([]string(nil), request.Args...),
		Helper:      append([]string(nil), request.HelperPath...),
		Passthru:    make(map[string]string, len(request.Passthrough)),
		Timeout:     request.TimeoutSeconds,
		TokenEnv:    request.TokenEnvName,
	}
	for name, value := range request.Passthrough {
		scope.Passthru[name] = value
	}
	if e = browserhost.ValidateCLIRunScope(scope); e == nil {
		var canonical personal.RunBundleRequest
		if canonical, e = browserhost.CanonicalCLIRunRequest(scope, root); e == nil {
			e = cliRunBrokerRequestDiffers(canonical, request)
		}
	}
	if e != nil {
		scope.Clear()
		return browserhost.CLIRunScope{}, cliRunBrokerScopeError{}
	}
	return scope, nil
}

// cliRunBrokerRequestDiffers reports whether the request the scope would
// resolve to differs from the committed request. It compares the fields that
// decide what is prepared and executed; the spec itself is the one built-in
// profile spec runCLIRun, this scope, and the desktop all resolve by name.
func cliRunBrokerRequestDiffers(canonical, committed personal.RunBundleRequest) error {
	if !sameStrings(canonical.Args, committed.Args) || !sameStrings(canonical.HelperPath, committed.HelperPath) ||
		canonical.Program != committed.Program || canonical.Directory != committed.Directory ||
		canonical.TimeoutSeconds != committed.TimeoutSeconds || canonical.TokenEnvName != committed.TokenEnvName ||
		canonical.Spec.ID != committed.Spec.ID || len(canonical.Passthrough) != len(committed.Passthrough) {
		return browserhost.ErrCLIRunRefused
	}
	for name, value := range canonical.Passthrough {
		if other, ok := committed.Passthrough[name]; !ok || other != value {
			return browserhost.ErrCLIRunRefused
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// cliRunBrokerNonce returns a fresh 32-byte crypto-random nonce, hex encoded.
// Every actual request gets its own.
func cliRunBrokerNonce() (string, error) {
	var b [32]byte
	defer clear(b[:])
	if _, err := cliRunBrokerRandom(b[:]); err != nil {
		return "", cliRunBrokerNonceError{}
	}
	return hex.EncodeToString(b[:]), nil
}

// clearCLIRunBrokerValues zeroes an unusable value set the client rejected.
func clearCLIRunBrokerValues(values map[string][]byte) {
	for slot := range values {
		clear(values[slot])
		delete(values, slot)
	}
}

// Fixed, non-sensitive broker outcomes. They never wrap the broker's own
// error text, so a payload, an endpoint, or a secret never reaches the owner.
type cliRunBrokerTTYError struct{}

func (cliRunBrokerTTYError) Error() string {
	return "desktop broker CLI run requires an identified controlling terminal; no local-factor fallback was used"
}

type cliRunBrokerNonceError struct{}

func (cliRunBrokerNonceError) Error() string {
	return "cannot generate a one-time desktop broker request nonce; no local-factor fallback was used"
}

type cliRunBrokerScopeError struct{}

func (cliRunBrokerScopeError) Error() string {
	return "desktop broker CLI run scope does not match the committed run; no local-factor fallback was used"
}

type cliRunBrokerRefusedError struct{}

func (cliRunBrokerRefusedError) Error() string {
	return "desktop approval refused the CLI run; no local-factor fallback was used"
}

type cliRunBrokerFailedError struct{ cause error }

func (cliRunBrokerFailedError) Error() string {
	return "desktop broker CLI run failed; no local-factor fallback was used"
}

// Is exposes only cancellation and deadline so the exit status stays
// accurate; every other broker failure remains opaque.
func (e cliRunBrokerFailedError) Is(target error) bool {
	return target == context.Canceled && errors.Is(e.cause, context.Canceled) ||
		target == context.DeadlineExceeded && errors.Is(e.cause, context.DeadlineExceeded)
}

// cliRunBrokerFailure is the single fallback gate: only the exact
// browserhost.ErrBrokerUnavailable value, compared with == and never with
// errors.Is, selects the once-only existing local-factor path. Every other
// outcome, including a wrapped copy of the sentinel, is terminal.
func cliRunBrokerFailure(err error) error {
	if err == browserhost.ErrBrokerUnavailable {
		return errCLIRunBrokerAbsent
	}
	if err == browserhost.ErrCLIRunRefused {
		return cliRunBrokerRefusedError{}
	}
	var tty cliRunBrokerTTYError
	if errors.As(err, &tty) {
		return tty
	}
	var nonce cliRunBrokerNonceError
	switch {
	case errors.As(err, &nonce):
		return nonce
	case errors.As(err, &cliRunBrokerScopeError{}):
		return cliRunBrokerScopeError{}
	}
	return cliRunBrokerFailedError{cause: err}
}

// describeCLIRunBrokerRequest is the owner-facing summary of the exact broker
// request that was just sent. It contains no secret: passthrough values are
// listed by name only.
func describeCLIRunBrokerRequest(req browserhost.CLIRunBrokerRequest) string {
	var b strings.Builder
	s := req.Scope
	fmt.Fprintf(&b, "桌面代理 CLI 执行请求（locklark cli run）\r\n")
	fmt.Fprintf(&b, "  密码库  ：%s\r\n", strconv.QuoteToASCII(req.VaultPath))
	fmt.Fprintf(&b, "  Profile ：%s\r\n", strconv.QuoteToASCII(s.Profile))
	fmt.Fprintf(&b, "  终端    ：%s（平台 %s）\r\n", strconv.QuoteToASCII(s.TTY), strconv.QuoteToASCII(s.TTYPlatform))
	fmt.Fprintf(&b, "  执行程序：%s\r\n", strconv.QuoteToASCII(s.Program))
	if s.ProgramPinned() {
		fmt.Fprintf(&b, "  SHA-256 ：%s\r\n", s.ProgramSH)
	}
	fmt.Fprintf(&b, "  工作目录：%s\r\n", strconv.QuoteToASCII(s.CWD))
	fmt.Fprintf(&b, "  临时目录：%s\r\n", strconv.QuoteToASCII(s.TempRoot))
	fmt.Fprintf(&b, "  超时上限：%d 秒\r\n", s.Timeout)
	token := s.TokenEnv
	if token == "" {
		token = "（无）"
	}
	fmt.Fprintf(&b, "  Tokens  ：%s\r\n", strconv.QuoteToASCII(token))
	fmt.Fprintf(&b, "槽位目标（读取不可变修订）：\r\n")
	for _, target := range req.Targets {
		fmt.Fprintf(&b, "  %s = %s @ %s（字段 %s）\r\n", strconv.QuoteToASCII(target.Slot), target.ID, target.Revision, strconv.QuoteToASCII(target.Field))
	}
	fmt.Fprintf(&b, "透传环境变量名（不显示值）：\r\n")
	for _, name := range s.PassthroughNames() {
		fmt.Fprintf(&b, "  %s\r\n", name)
	}
	fmt.Fprintf(&b, "辅助 PATH：\r\n")
	for _, directory := range s.Helper {
		fmt.Fprintf(&b, "  %s\r\n", strconv.QuoteToASCII(directory))
	}
	fmt.Fprintf(&b, "命令参数（会显示在终端与系统进程列表中，请勿在参数内写入秘密）：\r\n")
	for i, arg := range s.Args {
		fmt.Fprintf(&b, "  [%d] %s\r\n", i, strconv.QuoteToASCII(arg))
	}
	return b.String()
}
