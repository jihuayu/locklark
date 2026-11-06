package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

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
		fmt.Fprintln(os.Stdout, "LOCKLARK_CONSOLE_PROBE=entered")
		hadConsole, e := prepareRunCLIConsoleProbe()
		if hadConsole {
			fmt.Fprintln(os.Stdout, "LOCKLARK_CONSOLE_PROBE=initial-console-present")
		}
		if e != nil {
			fmt.Fprintln(os.Stdout, "LOCKLARK_CONSOLE_PROBE=detach-failed")
			os.Exit(43)
		}
		fmt.Fprintln(os.Stdout, "LOCKLARK_CONSOLE_PROBE=detached")
		exe, e := os.Executable()
		if e != nil {
			os.Exit(41)
		}
		args := []string{"run-cli", "--file", "unused.ll", "--id", strings.Repeat("1", 32), "--revision", strings.Repeat("a", 64), "--profile", "token", "--name", "TEST_TOKEN", "--cwd", t.TempDir(), "--timeout", "10", "--", exe}
		var output bytes.Buffer
		fmt.Fprintln(os.Stdout, "LOCKLARK_CONSOLE_PROBE=before-command")
		if e := runPersonal(args, &output); e != errRunCLIConsole || output.Len() != 0 {
			fmt.Fprintln(os.Stdout, "LOCKLARK_CONSOLE_PROBE=unexpected-result")
			os.Exit(42)
		}
		fmt.Fprintln(os.Stdout, "LOCKLARK_CONSOLE_PROBE=refused")
		os.Exit(0)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal("executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRunCLINoControllingConsole$", "-test.timeout=10s")
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(), "LOCKLARK_TEST_NO_CONSOLE_CHILD=1")
	var diagnostic, childErrors bytes.Buffer
	cmd.Stdout, cmd.Stderr = &diagnostic, &childErrors
	detachRunCLIConsole(cmd)
	if e := cmd.Run(); e != nil {
		phase, stage := runCLIConsoleProbeDiagnostic(diagnostic.Bytes(), childErrors.Bytes(), ctx.Err() != nil)
		t.Fatalf("detached command did not refuse before authentication; phase=%s stage=%s", phase, stage)
	}
}

// Only fixed test phases and known stack classifications may enter normal test
// output. Child stdout/stderr (including timeout stacks) are never printed.
func runCLIConsoleProbeDiagnostic(output, childErrors []byte, parentTimeout bool) (string, string) {
	phase := "not-entered"
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		switch string(bytes.TrimSuffix(line, []byte{'\r'})) {
		case "LOCKLARK_CONSOLE_PROBE=entered":
			phase = "entered"
		case "LOCKLARK_CONSOLE_PROBE=detached":
			phase = "detached"
		case "LOCKLARK_CONSOLE_PROBE=before-command":
			phase = "before-command"
		case "LOCKLARK_CONSOLE_PROBE=detach-failed":
			phase = "detach-failed"
		case "LOCKLARK_CONSOLE_PROBE=unexpected-result":
			phase = "unexpected-result"
		case "LOCKLARK_CONSOLE_PROBE=refused":
			phase = "refused"
		}
	}
	stage := "child-failed"
	if parentTimeout {
		stage = "parent-deadline"
	} else if bytes.Contains(childErrors, []byte("panic: test timed out")) {
		stage = "child-deadline"
		if bytes.Contains(childErrors, []byte(".openRunCLIConsole")) {
			stage = "console-open"
		} else if bytes.Contains(childErrors, []byte(".(*console).field(")) {
			stage = "factor-input"
		}
	}
	return phase, stage
}

func TestRunCLIConsoleProbeDiagnosticsNeverEchoChildOutput(t *testing.T) {
	canary := "private-console-probe-canary"
	output := []byte("LOCKLARK_CONSOLE_PROBE=before-command\r\nLOCKLARK_CONSOLE_PROBE=" + canary + "\n" + canary)
	childErrors := []byte("panic: test timed out\n" + canary + "\nfixture.openRunCLIConsole.func1")
	phase, stage := runCLIConsoleProbeDiagnostic(output, childErrors, false)
	if phase != "before-command" || stage != "console-open" || strings.Contains(phase+stage, canary) {
		t.Fatal("console probe diagnostic exposed child output")
	}
	phase, stage = runCLIConsoleProbeDiagnostic([]byte(canary), []byte(canary), true)
	if phase != "not-entered" || stage != "parent-deadline" {
		t.Fatal("console probe timeout lacked a fixed diagnosis")
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
