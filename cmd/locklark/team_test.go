package main

import (
	"bytes"
	"github.com/jihuayu/locklark/internal/teambootstrapcli"
	"strings"
	"testing"
)

func TestTeamDispatchRejectsSecretArgumentsWithoutEcho(t *testing.T) {
	var out, diag bytes.Buffer
	err := run([]string{"team", "create", "--seed", "private-argument-canary"}, &out, &diag)
	if err == nil || teambootstrapcli.ExitCode(err) != 2 || strings.Contains(out.String()+diag.String()+err.Error(), "private-argument-canary") {
		t.Fatal("team dispatch accepted or echoed private arguments")
	}
}
