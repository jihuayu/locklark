package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/jihuayu/locklark/pkg/onedriveauth"
)

// onedriveHelpText is the single-command help of `locklark personal onedrive`.
// It is also the fixed text printed with a usage refusal, so it names no
// registration value, profile or credential store item.
const onedriveHelpText = `usage: locklark personal onedrive <login|status|logout> --client-id ID --tenant TENANT [flags]

Keep one Microsoft OneDrive OAuth refresh token per local profile in the OS
credential store, service ` + onedriveauth.StoreNamespace + `.
Only the refresh token is stored. It is never printed, and there is no file,
environment variable or other fallback store.

  login   --client-id ID --tenant TENANT --scopes SCOPE_LIST
      Read a local profile label hidden from the controlling terminal, then
      open the system browser for a public-client authorization-code flow with
      PKCE, state and the fixed loopback redirect, and store the refresh token
      the code is redeemed for. SCOPE_LIST is comma- or space-separated and
      must include offline_access before anything else happens. There is no
      client-secret flag.

  status  --client-id ID --tenant TENANT
      Report whether a refresh token is stored for the hidden profile label.
      The token is never read out or shown.

  logout  --client-id ID --tenant TENANT
      Delete the stored refresh token for the hidden profile label.

--client-id and --tenant are the explicit public-client registration values;
they have no default. The store key binds them to the profile label, so one
profile label names a separate store item for each client ID and tenant. The
profile label is a user-chosen local name only: it is not a verified Microsoft
identity, and status reports what this machine stored, not who signed in.
Labels are read only from the controlling terminal with echo disabled and are
never accepted in flags, arguments or the environment. Run
"locklark personal onedrive <command> --help" for one command.
`

// onedriveFlag describes one command flag, once, for parsing and for help.
type onedriveFlag struct {
	name, value, usage string
}

// onedriveRegistrationFlags are the explicit registration values every command
// takes; neither has a default.
var onedriveRegistrationFlags = []onedriveFlag{
	{"client-id", "ID", "public-client application (client) ID; required, no default"},
	{"tenant", "TENANT", "tenant GUID or DNS domain used in the endpoint path; required, no default"},
}

// onedriveScopeFlags are the login-only explicit scopes.
var onedriveScopeFlags = []onedriveFlag{
	{"scopes", "SCOPE_LIST", "explicit scopes, comma- or space-separated; required, must include offline_access"},
}

func onedriveFlags(action string) []onedriveFlag {
	if action == "login" {
		return append(append([]onedriveFlag{}, onedriveRegistrationFlags...), onedriveScopeFlags...)
	}
	return onedriveRegistrationFlags
}

// Fixed, redacted CLI errors. None carries a URL, state, code, client ID,
// tenant, scope, profile label, token, provider response or OS command text.
var (
	errOnedriveTerminal       = errors.New("personal onedrive requires an interactive controlling terminal for hidden input and prompts")
	errOnedriveLogin          = errors.New("the browser sign-in did not complete before the callback listener closed; nothing was saved")
	errOnedriveBrowser        = errors.New("the system browser could not be opened")
	errOnedriveNoRefresh      = errors.New("the token endpoint returned no refresh token; include offline_access in --scopes; nothing was saved")
	errOnedriveExchangePre    = errors.New("the token exchange was cancelled before any request was sent, so the code was not presented")
	errOnedriveExchangeUnsure = errors.New("the token exchange did not finish after a request was sent; the authorization code may have been consumed and must not be retried; nothing was saved")
	errOnedriveExchangeFailed = errors.New("the token endpoint rejected the exchange; the authorization code may have been consumed and must not be retried; nothing was saved")
	errOnedriveStore          = errors.New("the OneDrive refresh token operation on the OS credential store failed; it may not have been saved or deleted; no plaintext fallback exists")
	errOnedriveUnsupported    = errors.New("the OS credential store is not available; no refresh token was saved or deleted; no plaintext fallback exists")
	errOnedriveLabel          = errors.New("invalid profile label; it must be 1-256 printable ASCII bytes")

	// errOnedriveNotEnrolled is the fixed status outcome of a profile with
	// no stored refresh token. It never leaves runPersonalOnedrive.
	errOnedriveNotEnrolled = errors.New("onedrive profile not enrolled")
)

// Printed receipts are fixed lines: none contains a profile label, client ID,
// tenant, token or sign-in detail.
const (
	onedriveStatusEnrolled    = "OneDrive profile (local label): refresh token stored\r\n"
	onedriveStatusNotEnrolled = "OneDrive profile (local label): no refresh token stored\r\n"
	onedriveLogoutDone        = "OneDrive profile (local label): refresh token record deleted\r\n"
	onedriveLoginDone         = "OneDrive sign-in complete. Only the refresh token was stored in the OS credential store.\r\n"
	onedriveLoginNotSaved     = "OneDrive sign-in did not finish. Nothing was saved.\r\n"
)

// onedriveRequest is one parsed command: the action, the explicit public-client
// registration values, and, for login only, the explicit scopes.
type onedriveRequest struct {
	action string
	config onedriveauth.AuthorizeConfig
}

// isOnedriveAction reports whether args is the `locklark personal onedrive`
// command; parseOnedrive decides what its arguments mean.
func isOnedriveAction(args []string) bool { return len(args) > 0 && args[0] == "onedrive" }

// parseOnedrive validates the arguments of one onedrive action without touching
// the terminal, network or credential store. It returns personalUsage unless the
// arguments are exactly what the action accepts:

//   - every command takes --client-id and --tenant exactly once, nonempty;
//   - login also takes --scopes exactly once, and that list includes
//     offline_access;
//   - status and logout take nothing else.
//
// Flags may appear in any order, as "--name VALUE" or "--name=VALUE". An unknown
// command or flag, a repeated or abbreviated flag, a positional argument, a
// missing value, a blank value or any profile-label, client-secret or other
// flag is refused.
func parseOnedrive(args []string) (onedriveRequest, error) {
	var req onedriveRequest
	if len(args) == 0 {
		return req, personalUsage
	}
	req.action = args[0]
	if req.action != "login" && req.action != "status" && req.action != "logout" {
		return onedriveRequest{}, personalUsage
	}
	values, err := parseOnedriveFlags(args[1:], onedriveFlags(req.action))
	if err != nil {
		return onedriveRequest{}, personalUsage
	}
	for _, f := range onedriveFlags(req.action) {
		if values[f.name] == "" {
			return onedriveRequest{}, personalUsage
		}
	}
	req.config = onedriveauth.AuthorizeConfig{ClientID: values["client-id"], Tenant: values["tenant"]}
	if req.action == "login" {
		req.config.Scopes = splitScopes(values["scopes"])
		if len(req.config.Scopes) == 0 || !hasScope(req.config.Scopes, "offline_access") {
			return onedriveRequest{}, personalUsage
		}
	}
	return req, nil
}

// parseOnedriveFlags reads the flags of one command in any order and records
// each accepted flag's value in values. A name is accepted only as exactly
// "--name" or "--name=VALUE"; it must be one of flags, and it may appear once.
// Anything else is refused.
func parseOnedriveFlags(args []string, flags []onedriveFlag) (map[string]string, error) {
	known := map[string]bool{}
	for _, f := range flags {
		known[f.name] = true
	}
	values := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 3 || arg[0] != '-' || arg[1] != '-' {
			return nil, personalUsage
		}
		name, value := arg[2:], ""
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, value = name[:eq], name[eq+1:]
		} else {
			if i+1 >= len(args) {
				return nil, personalUsage
			}
			i++
			value = args[i]
		}
		if !known[name] || value == "" {
			return nil, personalUsage
		}
		if _, seen := values[name]; seen {
			return nil, personalUsage
		}
		values[name] = value
	}
	return values, nil
}

// splitScopes splits an explicit scope list on commas and ASCII white space. It
// neither adds nor reorders a scope.
func splitScopes(list string) []string {
	var scopes []string
	start := -1
	for i := 0; i <= len(list); i++ {
		sep := i == len(list) || isScopeSeparator(list[i])
		if sep && start >= 0 {
			scopes = append(scopes, list[start:i])
			start = -1
			continue
		}
		if !sep && start < 0 {
			start = i
		}
	}
	return scopes
}

func isScopeSeparator(c byte) bool {
	switch c {
	case ',', ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// hasScope reports whether the explicit scope list already grants scope.
func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// onedriveActionHelp renders one command's help from the same flag list and
// error wording the command itself uses.
func onedriveActionHelp(action string) string {
	var b strings.Builder
	b.WriteString("usage: locklark personal onedrive " + action + " --client-id ID --tenant TENANT")
	if action == "login" {
		b.WriteString(" --scopes SCOPE_LIST")
	}
	b.WriteString("\n\n")
	switch action {
	case "login":
		b.WriteString("Read a local profile label hidden from the controlling terminal, then open the system browser for the public-client PKCE authorization flow and store the returned refresh token under that label. The explicit scopes must include offline_access; every flag is required and has no default.\n\n")
		b.WriteString("The authorization URL, state, code, tokens, profile label and provider errors are never printed. The callback listener uses the fixed http://127.0.0.1:PORT" + onedriveauth.CallbackPath + " redirect and is closed on success, cancellation or timeout. A cancellation before the code is sent is reported apart from any failure after a request was sent, which leaves the code possibly consumed and is never retried.\n\n")
	case "status":
		b.WriteString("Report whether a refresh token is stored for the hidden local profile label, without reading it out or showing it. The label is a local name chosen by the user, not a verified Microsoft identity; this reports what this machine stored, not who signed in.\n\n")
	case "logout":
		b.WriteString("Delete the stored refresh token for the hidden local profile label.\n\n")
	}
	b.WriteString("Flags:\n")
	for _, f := range onedriveFlags(action) {
		b.WriteString("  --" + f.name + " " + f.value + "\n  \t" + f.usage + "\n")
	}
	return b.String()
}

// runPersonalOnedrive runs `locklark personal onedrive login|status|logout`. It
// writes its fixed receipt itself, to out, only when it succeeds.
func runPersonalOnedrive(args []string, out io.Writer) error {
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		if args[0] == "login" || args[0] == "status" || args[0] == "logout" {
			_, err := io.WriteString(out, onedriveActionHelp(args[0]))
			return err
		}
		return personalUsage
	}
	req, err := parseOnedrive(args)
	if err != nil {
		_, _ = io.WriteString(os.Stderr, onedriveHelpText)
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The profile label is read only here, from the hidden terminal seam,
	// before any browser, listener or store step, and stays mutable bytes
	// until the store has hashed it; it is cleared on every path.
	label, err := promptProfileLabel(ctx)
	if err != nil {
		return err
	}
	defer clear(label)
	if !onedriveauth.ValidProfileLabel(label) {
		return errOnedriveLabel
	}
	var receipt string
	switch req.action {
	case "login":
		if _, err := fmt.Fprintf(os.Stderr, "OneDrive refresh token store: OS credential store, service %s. Only the refresh token is stored.\r\n", onedriveauth.StoreNamespace); err != nil {
			return err
		}
		// onedriveLogin already returns its own fixed sentinel for every
		// failure, including a store failure from its final save, through
		// onedriveStoreError once. It is returned as is: no second wrap.
		receipt, err = onedriveLogin(ctx, req.config, label)
		if err != nil {
			_, _ = io.WriteString(os.Stderr, onedriveLoginNotSaved)
			return err
		}
	case "logout":
		if err := onedriveDelete(req.config.ClientID, req.config.Tenant, label); err != nil {
			return onedriveStoreError(err)
		}
		receipt = onedriveLogoutDone
	case "status":
		err := onedriveStatus(req.config.ClientID, req.config.Tenant, label)
		if errors.Is(err, errOnedriveNotEnrolled) {
			receipt = onedriveStatusNotEnrolled
			break
		}
		if err != nil {
			return onedriveStoreError(err)
		}
		receipt = onedriveStatusEnrolled
	}
	if _, err := io.WriteString(out, receipt); err != nil {
		return err
	}
	return nil
}

// onedriveStatus reports whether the profile has a stored refresh token without
// reading it out: the owned copy the store returns is cleared at once.
func onedriveStatus(clientID, tenant string, label []byte) error {
	store, err := newOnedriveStore()
	if err != nil {
		return err
	}
	token, ok, err := store.LoadRefreshToken(clientID, tenant, label)
	clear(token)
	if err != nil {
		return err
	}
	if !ok {
		return errOnedriveNotEnrolled
	}
	return nil
}

// onedriveDelete removes the refresh token of the profile.
func onedriveDelete(clientID, tenant string, label []byte) error {
	store, err := newOnedriveStore()
	if err != nil {
		return err
	}
	return store.DeleteRefreshToken(clientID, tenant, label)
}

// onedriveLogin runs one authorization in the system browser, redeems the code,
// and stores the refresh token under the explicit registration values and the
// hidden profile label the caller already read. Every failure is fixed and
// redacted. The callback is closed and every buffer this function owns is cleared
// on every path.
func onedriveLogin(ctx context.Context, cfg onedriveauth.AuthorizeConfig, label []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", errOnedriveLogin
	}
	if !onedriveauth.ValidProfileLabel(label) {
		return "", errOnedriveLabel
	}
	verifier, err := onedriveauth.NewVerifier()
	if err != nil {
		return "", errOnedriveLogin
	}
	defer func() { verifier = "" }()
	state, err := onedriveauth.NewState()
	if err != nil {
		return "", errOnedriveLogin
	}
	defer func() { state = "" }()
	// Start binds the listener and applies its DefaultTimeout; the listener
	// also closes when ctx is done.
	cb, err := onedriveauth.Start(ctx, state, 0)
	if err != nil {
		return "", errOnedriveLogin
	}
	defer func() { _ = cb.Close() }()
	redirectURI, err := cb.RedirectURI()
	if err != nil {
		return "", errOnedriveLogin
	}
	// The URL carries this run's state and PKCE challenge. It goes straight
	// to the opener and is never printed or logged.
	authURL, err := onedriveauth.AuthorizationURL(cb, cfg, verifier)
	if err != nil {
		return "", errOnedriveLogin
	}
	if err := openSystemBrowser(authURL); err != nil {
		_ = cb.Close()
		return "", err
	}
	// Exactly one Wait call: any cancelled Wait aborts the callback, so a
	// wait is never interrupted and retried. The bound is the same
	// DefaultTimeout Start applied.
	res, err := cb.Wait(ctx, onedriveauth.DefaultTimeout)
	if err != nil {
		_ = cb.Close()
		return "", errOnedriveLogin
	}
	code := res.Code()
	defer func() { code = "" }()
	// Wait closed the listener for this code; release the server too.
	_ = cb.Close()
	tok, err := onedriveauth.ExchangeCode(ctx, onedriveauth.TokenExchangeConfig(cfg), redirectURI, code, verifier, 0)
	if err != nil {
		return "", onedriveExchangeError(err)
	}
	// The token result is closed before this function returns on every
	// path, including an exchange cut short by cancellation.
	defer tok.Close()
	refresh := tok.RefreshToken()
	defer clear(refresh)
	if len(refresh) == 0 {
		return "", errOnedriveNoRefresh
	}
	store, err := newOnedriveStore()
	if err != nil {
		return "", onedriveStoreError(err)
	}
	if err := store.SaveRefreshToken(cfg.ClientID, cfg.Tenant, label, refresh); err != nil {
		return "", onedriveStoreError(err)
	}
	// The command owns the receipt: runPersonalOnedrive writes the returned
	// fixed line to its out. This helper prints nothing on success.
	return onedriveLoginDone, nil
}

// onedriveExchangeError keeps the exchange's own classification, exactly and
// without detail: a cancellation before sending is reported as such, because no
// request was made and the code was not presented, while every other failure
// after a possible request says the code may be consumed and must not be retried.
// The package sentinel is joined so errors.Is still classifies it.
func onedriveExchangeError(err error) error {
	switch {
	case errors.Is(err, onedriveauth.ErrCancelled):
		return errors.Join(errOnedriveExchangePre, onedriveauth.ErrCancelled)
	case errors.Is(err, onedriveauth.ErrOutcomeUnknown):
		return errors.Join(errOnedriveExchangeUnsure, onedriveauth.ErrOutcomeUnknown)
	default:
		return errors.Join(errOnedriveExchangeFailed, err)
	}
}

// onedriveStoreError maps a store failure to a fixed CLI error. Underlying
// error text is never kept: it may echo a key, path or OS message. Only the
// package sentinels the command classifies on are preserved, so an absent store
// stays distinguishable from any other failure.
func onedriveStoreError(err error) error {
	switch {
	case errors.Is(err, onedriveauth.ErrStoreUnsupported) && errors.Is(err, errors.ErrUnsupported):
		// An absent store, reported at the platform boundary: keep both
		// sentinels so errors.Is still tells it apart from other failures.
		return errors.Join(errOnedriveUnsupported, onedriveauth.ErrStoreUnsupported, errors.ErrUnsupported)
	case errors.Is(err, onedriveauth.ErrStoreUnsupported):
		// A store the adapter rejected without the platform boundary.
		return errors.Join(errOnedriveStore, onedriveauth.ErrStoreUnsupported)
	default:
		// Arbitrary failures: fixed message only, no cause text.
		return errOnedriveStore
	}
}

// maxProfileLabelByte is the storage bound on a profile label, borrowed from the
// store so the prompt cannot accept a label the store would refuse.
const maxProfileLabelByte = onedriveauth.MaxProfileLabelLen

// onedriveStore is the credential store surface this command uses. Its only
// production implementation is the package adapter, which keeps the fixed
// namespace, composite key derivation and validation; tests inject an in-memory
// fake.
type onedriveStore interface {
	SaveRefreshToken(clientID, tenant string, label, token []byte) error
	LoadRefreshToken(clientID, tenant string, label []byte) ([]byte, bool, error)
	DeleteRefreshToken(clientID, tenant string, label []byte) error
}

// Injectable seams. Production uses the system opener of this OS and the real
// prompt and store; tests replace them so no test opens a browser, the network
// or the real credential store.
var (
	newBrowserCommand  = browserCommandForOS
	promptProfileLabel = func(ctx context.Context) ([]byte, error) {
		return promptControlTerminal(ctx, os.Stdin, os.Stderr, "OneDrive local profile label")
	}
	newOnedriveStore = func() (onedriveStore, error) { return onedriveauth.NewRefreshTokenStore(), nil }
)

// browserCommandForOS names the native opener of this OS. The URL is one
// argument and never passes through a shell. An OS without an opener among the
// build targets fails closed instead of guessing a shell command.
func browserCommandForOS(rawURL string) (program string, args []string, ok bool) {
	return browserCommandFor(rawURL, runtime.GOOS)
}

// browserCommandFor is the pure OS selection behind browserCommandForOS. Linux
// desktops open the system browser through xdg-open; other Unix-like systems
// have no single opener and are refused.
func browserCommandFor(rawURL, goos string) (program string, args []string, ok bool) {
	switch goos {
	case "darwin":
		return "/usr/bin/open", []string{rawURL}, true
	case "windows":
		return `C:\Windows\System32\rundll32.exe`, []string{"url.dll,FileProtocolHandler", rawURL}, true
	case "linux":
		return "xdg-open", []string{rawURL}, true
	}
	return "", nil, false
}

// openSystemBrowser opens rawURL with the platform's own opener, started
// directly without a shell. It never echoes the URL or the opener's output: only
// the fixed opener failure is returned.
func openSystemBrowser(rawURL string) error {
	program, args, ok := newBrowserCommand(rawURL)
	if !ok {
		return errOnedriveBrowser
	}
	return runBrowser(program, args)
}

// runBrowser starts the opener directly, without a shell. It is a variable so
// tests can observe it without starting a process.
var runBrowser = func(program string, args []string) error {
	cmd := exec.Command(program, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Run(); err != nil {
		return errOnedriveBrowser
	}
	return nil
}
