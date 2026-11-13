//go:build linux || darwin || windows

// This file holds the request-level scope test (TestCLIRunScope_Request). It is
// kept as an unstaged draft: validCLIRunRequest and reqID are defined only by
// the dirty broker.go/broker_test.go draft, so the file is not part of the
// independent scope slice.

package browserhost

import (
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

// TestCLIRunScope_Request proves the shared request check resolves the gh
// profile and enforces its single token/password slot and canonical IDs.
func TestCLIRunScope_Request(t *testing.T) {
	vault := cliRunFixtureVault
	scope := cliRunFixtureScope()
	good := []personal.CLIBrokerTarget{{Slot: "token", ID: reqID(1), Revision: reqRevision(2), Field: "password"}}
	if !validCLIRunRequest(1, vault, scope, good) {
		t.Fatal("fixture request rejected")
	}
	bad := map[string]struct {
		scope   CLIRunScope
		targets []personal.CLIBrokerTarget
	}{
		"unknown-profile": {func() CLIRunScope { s := scope; s.Profile = "nope"; return s }(), good},
		"wrong-slot":      {scope, []personal.CLIBrokerTarget{{Slot: "other", ID: reqID(1), Revision: reqRevision(2), Field: "password"}}},
		"wrong-field":     {scope, []personal.CLIBrokerTarget{{Slot: "token", ID: reqID(1), Revision: reqRevision(2), Field: "username"}}},
		"malformed-id":    {scope, []personal.CLIBrokerTarget{{Slot: "token", ID: "not-hex", Revision: reqRevision(2), Field: "password"}}},
		"malformed-rev":   {scope, []personal.CLIBrokerTarget{{Slot: "token", ID: reqID(1), Revision: "rev", Field: "password"}}},
		"duplicate":       {scope, []personal.CLIBrokerTarget{good[0], good[0]}},
		"missing-targets": {scope, nil},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			if validCLIRunRequest(1, vault, c.scope, c.targets) {
				t.Fatal("accepted invalid request")
			}
		})
	}
	if validCLIRunRequest(1, "relative.ll", scope, good) {
		t.Fatal("accepted relative vault path")
	}
}
