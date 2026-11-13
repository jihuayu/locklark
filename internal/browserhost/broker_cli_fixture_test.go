package browserhost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

// Shared, OS-independent CLI-run fixtures. They live in an untagged file so
// every package test image (linux, darwin and Windows) compiles the same scope
// shape and resolves its paths with the same host filepath rules.

// cliRunFixturePaths are the absolute directory paths a CLI-run fixture names.
// They are built from one host-native absolute base, so they pass
// filepath.IsAbs and filepath.Clean on every platform the tests run on. They
// only give the path checks a well-formed shape; they name no real directory
// and claim no terminal.
//
// unclean is an absolute program path with a ".." element, for the check that
// refuses a program path filepath.Clean would rewrite. joining is a syntactically
// absolute path built with "/" separators only: it is not cleaned (Windows
// filepath.Clean rewrites "/" to "\\"), so it passes the program-path check but
// not the stricter cleaned-helper check.
var cliRunFixturePaths = struct {
	base, tty, program, work, runRoot, helper string
	unclean, joining                          string
}{}

var _ = func() bool {
	p := &cliRunFixturePaths
	p.base = filepath.Join(volumeRoot(), "locklark", "fixture")
	join := func(elem ...string) string { return filepath.Join(append([]string{p.base}, elem...)...) }
	p.tty, p.program, p.work, p.runRoot, p.helper = join("ttys-fixture"), join("bin", "gh"), join("work"), join("run-root"), join("helpers")
	p.unclean = p.base + string(filepath.Separator) + "bin" + string(filepath.Separator) + ".." + string(filepath.Separator) + "bin" + string(filepath.Separator) + "gh"
	p.joining = p.base + "/bin/../gh"
	return true
}()

// cliRunFixtureVault is the absolute, host-native vault path a fixture request
// names.
var cliRunFixtureVault = cliRunFixturePaths.base + string(filepath.Separator) + "vault.ll"

// passthruFixture is the fixture passthrough value that must never be
// returned as a name or echoed into an error.
const passthruFixture = "fixture-passthrough"

// volumeRoot is the root of the host's current volume as filepath reports it:
// "/" on Unix and the current volume's root (with its volume name, if any) on
// Windows. A base under it is absolute, clean, and has no trailing separator
// path element.
func volumeRoot() string {
	return filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
}

// cliRunFixtureScope is the execution scope used by every CLI-run fixture. It
// names the real built-in "gh" profile, so the shared request check resolves
// the canonical spec: slot "token" with password field, "GH_HOST" as an
// allowed passthrough name, and no dynamic token variable (TokenEnv empty).
// The passthrough value is a sentinel that must never reach an error or a
// native approval summary; the token variable stays unset because the
// canonical gh spec does not enable a dynamic token.
//
// The nonce is fixed per fixture and the replay cache is process-wide
// (consumed before the TTY check, too), so a test that must reach the broker
// takes a fresh nonce.
func cliRunFixtureScope() CLIRunScope {
	return CLIRunScope{
		Profile:     "gh",
		TTY:         cliRunFixturePaths.tty,
		TTYPlatform: testGOOS,
		Nonce:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Program:     cliRunFixturePaths.program,
		CWD:         cliRunFixturePaths.work,
		TempRoot:    cliRunFixturePaths.runRoot,
		Args:        []string{"--hostname", "fixture", "api", "user"},
		Helper:      []string{cliRunFixturePaths.helper},
		Passthru:    map[string]string{"GH_HOST": "fixture-passthrough-" + reqID(5)},
		Timeout:     60,
	}
}

// cliRunFixtureRequest is a valid CLI-run request for outcome classification:
// the fixture scope, the fixture vault path, and the profile's single
// token/password target.
func cliRunFixtureRequest() CLIRunBrokerRequest {
	return CLIRunBrokerRequest{
		V:         1,
		VaultPath: cliRunFixtureVault,
		Scope:     cliRunFixtureScope(),
		Targets:   []personal.CLIBrokerTarget{{Slot: "token", ID: reqID(1), Revision: reqRevision(2), Field: "password"}},
	}
}

// cliRunReceiptJSON is the canonical receipt for the fixture request: a 32-hex
// session and two 64-hex digests.
func cliRunReceiptJSON() string {
	return `{"status":"` + personal.RunBundlePreparationStatus + `","session":"` + reqID(16) + `","intent":"` + reqRevision(40) + `","target_digest":"` + reqRevision(41) + `"}`
}

// cliRunReceiptFromFixture decodes cliRunReceiptJSON into the receipt value.
func cliRunReceiptFromFixture(t *testing.T) personal.RunBundlePreparationReceipt {
	t.Helper()
	receipt, ok := decodeCLIRunReceipt(json.RawMessage(cliRunReceiptJSON()))
	if !ok {
		t.Fatal("receipt fixture is not canonical")
	}
	return receipt
}

// cliRunAuditedReply is the exact audited success frame: raw base64 slot
// values plus the canonical receipt.
func cliRunAuditedReply(slot, b64 string) string {
	return `{"v":1,"values_b64":{"` + slot + `":"` + b64 + `"},"receipt":` + cliRunReceiptJSON() + `}`
}

// reqRevision is a canonical 64-character lowercase hex revision digest.
func reqRevision(n int) string { return reqID(n) + reqID(n+16) }

// testGOOS is the host GOOS of the test binary, the value the CLI derives for
// the scope's TTYPlatform. It is read from runtime rather than a build
// constraint so this fixture stays in one untagged file.
var testGOOS = runtime.GOOS
