package browserhost

import "runtime"

// Shared, OS-independent CLI-run fixtures. They live in an untagged file so
// every package test image (linux, darwin and the generic build) compiles the
// same scope shape.

// cliRunFixtureScope is the execution scope used by every CLI-run fixture. It
// names the real built-in "gh" profile, so the shared request check resolves
// the canonical spec: slot "token" with password field, "GH_HOST" as an
// allowed passthrough name, and no dynamic token variable (TokenEnv empty).
// The passthrough value is a sentinel that must never reach an error or a
// native approval summary; the token variable stays unset because the
// canonical gh spec does not enable a dynamic token.
//
// The nonce is fixed per fixture and the replay cache is process-wide, so a
// fixture that must reach the broker takes a fresh nonce.
func cliRunFixtureScope() CLIRunScope {
	return CLIRunScope{
		Profile:     "gh",
		TTY:         "/dev/ttys-fixture",
		TTYPlatform: testGOOS,
		Nonce:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Program:     "/fixture/bin/gh",
		CWD:         "/fixture/work",
		TempRoot:    "/fixture/run-root",
		Args:        []string{"--hostname", "fixture", "api", "user"},
		Helper:      []string{"/fixture/helpers"},
		Passthru:    map[string]string{"GH_HOST": "fixture-passthrough-" + reqID(5)},
		Timeout:     60,
	}
}

// reqRevision is a canonical 64-character lowercase hex revision digest.
func reqRevision(n int) string { return reqID(n) + reqID(n+16) }

// testGOOS is the host GOOS of the test binary, the value the CLI derives for
// the scope's TTYPlatform. It is read from runtime rather than a build
// constraint so this fixture stays in one untagged file.
var testGOOS = runtime.GOOS
