// This separate acceptance executable owns synthetic data and child pipes.
// It calls the normal CLI, never a RunCLI executor or approval replacement.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/term"
)

type fixture struct {
	Master   string `json:"master"`
	Key      string `json:"key"`
	Token    string `json:"token"`
	Username string `json:"username"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

var fixturePhase = "entry"

func check(ok bool) {
	if !ok {
		panic("owned Windows CLI fixture failed")
	}
}
func writeJSON(path string, value any) {
	raw, err := json.Marshal(value)
	check(err == nil)
	defer clear(raw)
	check(os.WriteFile(path, raw, 0600) == nil)
}
func readFixture(root string) fixture {
	fixturePhase = "artifact-security"
	check(privateRoot(root) == nil)
	raw, err := os.ReadFile(filepath.Join(root, "fixture-private.json"))
	check(err == nil)
	defer clear(raw)
	var value fixture
	check(json.Unmarshal(raw, &value) == nil)
	return value
}
func randomValue(prefix string) string {
	var value [24]byte
	_, err := rand.Read(value[:])
	check(err == nil)
	return prefix + hex.EncodeToString(value[:])
}
func setup() {
	fixturePhase = "private-root"
	root, err := newPrivateRoot()
	check(err == nil && privateRoot(root) == nil)
	f := fixture{Master: randomValue("Master"), Token: randomValue("Token"), Username: randomValue("User")}
	key, err := personal.NewSecret()
	check(err == nil)
	defer clear(key)
	f.Key = personal.FormatSecret(key)
	path := filepath.Join(root, "vault.ll")
	fixturePhase = "vault-create"
	check(personal.Create(path, f.Master, key) == nil)
	fixturePhase = "vault-login"
	f.ID, err = personal.AddLogin(path, f.Master, key, "Windows CLI fixture", f.Username, f.Token)
	check(err == nil)
	rows, err := personal.List(path, f.Master, key)
	check(err == nil && len(rows) == 1 && rows[0].ID == f.ID)
	f.Revision = rows[0].Revision
	writeJSON(filepath.Join(root, "fixture-private.json"), f)
	check(privateRoot(root) == nil)
	fmt.Println(root) // Only the owned evidence path, never a factor.
}
func cliArgs(root, executable, label string, f fixture) []string {
	return []string{"personal", "run-cli", "--file", filepath.Join(root, "vault.ll"), "--id", f.ID,
		"--revision", f.Revision, "--profile", "token", "--name", "LOCKLARK_TEST_TOKEN", "--cwd", root,
		"--timeout", "15", "--", executable, "child", root, label}
}
func launch(root, cli, label string) {
	check(label == "approved" || label == "denied" || label == "no-console")
	fixturePhase = "owned-job"
	check(ownProcessTree() == nil)
	f := readFixture(root)
	executable, err := os.Executable()
	check(err == nil && filepath.IsAbs(cli))
	limit := 120 * time.Second
	parentConsoleAbsent := false
	if label == "no-console" {
		fixturePhase = "console-detach"
		check(detachOwnConsole() == nil)
		parentConsoleAbsent = true
		limit = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, cli, cliArgs(root, executable, label, f)...)
	if label == "no-console" {
		detachConsole(cmd)
	}
	fixturePhase = "console-probe"
	var before uint32
	consoleErr := errors.New("fixture is detached")
	if !parentConsoleAbsent {
		before, consoleErr = consoleMode()
		check(consoleErr == nil)
	}
	inR, inW, err := os.Pipe()
	check(err == nil)
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	check(err == nil)
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	check(err == nil)
	defer errR.Close()
	defer errW.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	fixturePhase = "cli-start"
	check(cmd.Start() == nil)
	inR.Close()
	outW.Close()
	errW.Close()
	_, err = inW.Write([]byte("owned Windows stdin marker\n"))
	check(err == nil)
	inW.Close()
	type captured struct {
		raw []byte
		err error
	}
	read := func(file *os.File) <-chan captured {
		done := make(chan captured, 1)
		go func() {
			raw, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
			done <- captured{raw, err}
		}()
		return done
	}
	out, stderr := read(outR), read(errR)
	fixturePhase = "cli-wait"
	err = cmd.Wait()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		check(errors.As(err, &exit))
		code = exit.ExitCode()
	}
	take := func(done <-chan captured, file *os.File, name string) {
		select {
		case value := <-done:
			defer clear(value.raw)
			check(value.err == nil && len(value.raw) <= 64<<10)
			check(os.WriteFile(filepath.Join(root, name), value.raw, 0600) == nil)
		case <-time.After(2 * time.Second):
			file.Close()
			panic("owned child pipe did not close")
		}
	}
	fixturePhase = "pipe-capture"
	take(out, outR, label+"-stdout.log")
	take(stderr, errR, label+"-stderr.log")
	var after uint32
	afterErr := consoleErr
	if !parentConsoleAbsent {
		after, afterErr = consoleMode()
	} else {
		check(ownConsoleAbsent())
	}
	writeJSON(filepath.Join(root, label+"-result.json"), map[string]any{
		"exit_code": code, "timed_out": ctx.Err() != nil,
		"console_available":   consoleErr == nil && afterErr == nil,
		"console_mode_before": before, "console_mode_after": after,
		"parent_console_absent": parentConsoleAbsent,
	})
	check(privateRoot(root) == nil)
	fmt.Println("OWNED_WINDOWS_CLI_DONE")
}
func child(root, label string) {
	f := readFixture(root)
	fixturePhase = "child-console"
	mode, err := consoleMode()
	check(err == nil)
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
	check(err == nil)
	allowed := map[string]bool{}
	for _, name := range []string{"LOCKLARK_TEST_TOKEN", "SYSTEMROOT", "PATH", "HOME", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR", "TMP", "TEMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		allowed[name] = true
	}
	environment := len(os.Environ()) == len(allowed)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !allowed[strings.ToUpper(name)] {
			environment = false
		}
	}
	writeJSON(filepath.Join(root, label+"-child.json"), map[string]any{
		"token_matches":            os.Getenv("LOCKLARK_TEST_TOKEN") == f.Token,
		"stdin_matches":            string(data) == "owned Windows stdin marker\n",
		"stdio_are_pipes":          !term.IsTerminal(int(os.Stdin.Fd())) && !term.IsTerminal(int(os.Stdout.Fd())) && !term.IsTerminal(int(os.Stderr.Fd())),
		"only_allowed_environment": environment, "console_mode": mode,
		"temporary_root": filepath.Dir(os.Getenv("HOME")),
	})
	clear(data)
	fmt.Fprint(os.Stdout, "owned Windows child stdout\n")
	fmt.Fprint(os.Stderr, "owned Windows child stderr\n")
	os.Exit(23)
}
func audit(root string) {
	f := readFixture(root)
	fixturePhase = "signed-audit"
	key, err := personal.ParseSecret(f.Key)
	check(err == nil)
	defer clear(key)
	events, err := personal.Audit(filepath.Join(root, "vault.ll"), f.Master, key)
	check(err == nil)
	count := 0
	for _, event := range events {
		if event.Action == "item.run.password" {
			check(event.Item == f.ID && event.BaseRevision == f.Revision && event.Result == "intent")
			count++
		}
	}
	writeJSON(filepath.Join(root, "audit-result.json"), map[string]any{"run_intents": count, "exact_target": true})
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "owned Windows CLI fixture failed at "+fixturePhase)
			os.Exit(95)
		}
	}()
	check(len(os.Args) >= 2)
	switch os.Args[1] {
	case "setup":
		check(len(os.Args) == 2)
		setup()
	case "launch":
		check(len(os.Args) == 5)
		launch(os.Args[2], os.Args[3], os.Args[4])
	case "child":
		check(len(os.Args) == 4)
		child(os.Args[2], os.Args[3])
	case "audit":
		check(len(os.Args) == 3)
		audit(os.Args[2])
	case "verify-private":
		check(len(os.Args) == 3 && privateRoot(os.Args[2]) == nil)
	default:
		panic("unsupported acceptance operation")
	}
}
