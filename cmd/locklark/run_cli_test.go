package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

func TestRunCLIBoundary(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal("executable unavailable")
	}
	valid := []string{"run-cli", "--file", "owner.ll", "--id", strings.Repeat("1", 32), "--revision", strings.Repeat("a", 64), "--profile", "token", "--name", "OPENAI_API_KEY", "--cwd", t.TempDir(), "--timeout", "10", "--", exe, "argument", ""}
	for _, tc := range []struct {
		at    int
		value string
	}{{8, "unknown"}, {10, "LD_PRELOAD"}, {12, "relative"}, {14, "01"}, {16, "relative"}} {
		args := append([]string{}, valid...)
		args[tc.at] = tc.value
		if e := runPersonal(args, &bytes.Buffer{}); e != personalUsage {
			t.Fatal("invalid CLI request accepted")
		}
	}
	for _, args := range [][]string{valid[:15], valid[:16], append(append([]string{}, valid[:15]...), "--helper-path", "relative", "--", exe), append(append([]string{}, valid[:15]...), "--field", "password", "--", exe)} {
		if e := runPersonal(args, &bytes.Buffer{}); e != personalUsage {
			t.Fatal("unsupported option accepted")
		}
	}
	gh := append([]string{}, valid...)
	gh[8] = "gh"
	gh[10] = "GH_TOKEN"
	gh = append(gh[:17], "auth", "login")
	if e := runPersonal(gh, &bytes.Buffer{}); e != personalUsage {
		t.Fatal("persistent authentication accepted")
	}
}

func TestRunCLINoControllingConsole(t *testing.T) {
	if os.Getenv("LOCKLARK_TEST_NO_CONSOLE_CHILD") == "1" {
		exe, e := os.Executable()
		if e != nil {
			os.Exit(41)
		}
		args := []string{"run-cli", "--file", "unused.ll", "--id", strings.Repeat("1", 32), "--revision", strings.Repeat("a", 64), "--profile", "token", "--name", "TEST_TOKEN", "--cwd", t.TempDir(), "--timeout", "10", "--", exe}
		var output bytes.Buffer
		if e := runPersonal(args, &output); e != errRunCLIConsole || output.Len() != 0 {
			os.Exit(42)
		}
		os.Exit(0)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal("executable unavailable")
	}
	cmd := exec.Command(exe, "-test.run=^TestRunCLINoControllingConsole$")
	cmd.Env = append(os.Environ(), "LOCKLARK_TEST_NO_CONSOLE_CHILD=1")
	detachRunCLIConsole(cmd)
	if e := cmd.Run(); e != nil {
		t.Fatal("detached command did not refuse before authentication")
	}
}

func TestRunCLIConsoleUsesOnlyExplicitPromptWriter(t *testing.T) {
	var prompt bytes.Buffer
	c := console{reader: bufio.NewReader(strings.NewReader("private-factor-canary\n")), writer: &prompt}
	value, e := c.field("hidden factor")
	defer clear(value)
	if e != nil || string(value) != "private-factor-canary" || prompt.String() != "hidden factor: \r\n" {
		t.Fatal("hidden factor input polluted prompt output")
	}
	prompt.Reset()
	c.reader = bufio.NewReader(strings.NewReader("RUN\n"))
	if e := confirmRunCLI(&c, personal.RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}, personal.RunCLIRequest{Profile: "token", Name: "TEST_TOKEN"}); e != nil {
		t.Fatal("confirmation failed")
	}
	if !strings.Contains(prompt.String(), "输入 RUN 确认本次可信命令披露") || !strings.Contains(prompt.String(), "这不是沙箱") {
		t.Fatal("approval did not use the explicit control-terminal writer")
	}
}
