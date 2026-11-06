package main

import (
	"bytes"
	"github.com/jihuayu/locklark/internal/teambootstrapcli"
	"strings"
	"testing"
)

func TestBootstrapDispatchRejectsSecretArgumentsWithoutEcho(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"prepare-identity", "--seed", "private-argument-canary"}, &out)
	if err == nil || teambootstrapcli.ExitCode(err) != 2 || strings.Contains(out.String()+err.Error(), "private-argument-canary") {
		t.Fatal("bootstrap dispatch accepted or echoed private arguments")
	}
}
