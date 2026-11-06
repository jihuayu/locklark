package personal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

func cliRequest(t *testing.T) RunCLIRequest {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal("executable unavailable")
	}
	return RunCLIRequest{Program: exe, Args: []string{"-test.run=^TestRunCLIChild$", "--", "probe", "", "two words", "a;b"}, Directory: t.TempDir(), Name: "LOCKLARK_TEST_TOKEN", TimeoutSeconds: 10, Profile: RunCLIProfileToken, HelperPath: []string{filepath.Dir(exe)}}
}

func TestRunCLIChild(t *testing.T) {
	value, present := os.LookupEnv("LOCKLARK_TEST_TOKEN")
	if !present {
		return
	}
	allowed := map[string]bool{"LOCKLARK_TEST_TOKEN": true, "PATH": true, "HOME": true, "XDG_CONFIG_HOME": true, "XDG_CACHE_HOME": true, "XDG_DATA_HOME": true, "GH_CONFIG_DIR": true, "TMPDIR": true, "TMP": true, "TEMP": true}
	if runtime.GOOS == "windows" {
		allowed["SystemRoot"] = true
		allowed["USERPROFILE"], allowed["APPDATA"], allowed["LOCALAPPDATA"] = true, true, true
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !allowed[name] {
			os.Exit(31)
		}
	}
	if value != "private-cli-value" || !reflect.DeepEqual(os.Args[len(os.Args)-3:], []string{"", "two words", "a;b"}) {
		os.Exit(32)
	}
	if os.Getenv("HOME") == "" || os.Getenv("GH_CONFIG_DIR") == "" || os.Getenv("PATH") == "" {
		os.Exit(33)
	}
	for _, name := range []string{"HOME", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR", "TMP", "TEMP"} {
		info, e := os.Stat(os.Getenv(name))
		if e != nil || !info.IsDir() {
			os.Exit(34)
		}
	}
	mode := os.Args[len(os.Args)-4]
	if mode == "sleep" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	if mode == "exit" {
		os.Exit(7)
	}
	if mode == "block" {
		fmt.Fprint(os.Stdout, "ready")
		io.ReadAll(os.Stdin)
		os.Exit(37)
	}
	raw, e := io.ReadAll(os.Stdin)
	if e != nil || string(raw) != "input is usable" {
		os.Exit(35)
	}
	fmt.Fprint(os.Stdout, value)
	fmt.Fprint(os.Stderr, value)
	if os.WriteFile("child-proof", []byte(os.Getenv("HOME")), 0600) != nil {
		os.Exit(36)
	}
	os.Exit(0)
}

func TestRunCLIIntentStdioAndCleanup(t *testing.T) {
	path, key, target := revealFixture(t)
	request := cliRequest(t)
	if _, e := EditLogin(path, "fixture", key, Edit{ID: target.ID, Revision: target.Revision, Field: "password", Value: "private-cli-value"}); e != nil {
		t.Fatal("fixture edit failed")
	}
	rows, e := List(path, "fixture", key)
	if e != nil {
		t.Fatal("fixture list failed")
	}
	target.Revision = rows[0].Revision
	input, e := os.CreateTemp(t.TempDir(), "input")
	if e != nil {
		t.Fatal("input fixture failed")
	}
	defer input.Close()
	if _, e = input.WriteString("input is usable"); e != nil {
		t.Fatal("input fixture failed")
	}
	input.Seek(0, 0)
	output, e := os.CreateTemp(t.TempDir(), "output")
	if e != nil {
		t.Fatal("output fixture failed")
	}
	defer output.Close()
	errout, e := os.CreateTemp(t.TempDir(), "error")
	if e != nil {
		t.Fatal("error fixture failed")
	}
	defer errout.Close()
	t.Setenv("HTTPS_PROXY", "private-parent-proxy")
	t.Setenv("GH_DEBUG", "api")
	t.Setenv("GITHUB_TOKEN", "private-parent-token")
	t.Setenv("SSH_AUTH_SOCK", "private-parent-agent")
	t.Setenv("GH_HOST", "private-parent-host")
	t.Setenv("GH_CONFIG_DIR", "private-parent-config")
	called := 0
	r, e := runCLI(context.Background(), target, request, func(r *RunRequest) (result, error) {
		return command(path, "fixture", key, "item.run.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{run: r})
	}, func(ctx context.Context, r RunRequest, value []byte) (int, error) {
		called++
		events, e := Audit(path, "fixture", key)
		if e != nil {
			t.Fatal("intent transaction not closed")
		}
		if events[len(events)-2].Action != "item.run.password" || events[len(events)-2].Result != "intent" {
			t.Fatal("process preceded committed intent")
		}
		return executeRunCLI(ctx, r, value, runCLIStreams{input, output, errout})
	}, os.RemoveAll)
	if e != nil || called != 1 || r.ExitCode != 0 {
		t.Fatal("CLI execution failed")
	}
	home, e := os.ReadFile(filepath.Join(request.Directory, "child-proof"))
	if e != nil {
		t.Fatal("child did not complete")
	}
	if _, e = os.Stat(filepath.Dir(string(home))); !os.IsNotExist(e) {
		t.Fatal("private temporary state survived")
	}
	for _, file := range []*os.File{output, errout} {
		file.Seek(0, 0)
		raw, e := io.ReadAll(file)
		if e != nil || string(raw) != "private-cli-value" {
			t.Fatal("child stream not connected")
		}
		clear(raw)
	}
	if os.Getenv("GITHUB_TOKEN") != "private-parent-token" {
		t.Fatal("parent environment changed")
	}
	if os.Getenv("SSH_AUTH_SOCK") != "private-parent-agent" {
		t.Fatal("parent agent configuration changed")
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal("audit unavailable")
	}
	encoded, _ := json.Marshal([]any{r, events})
	for _, text := range []string{"private-cli-value", request.Program, request.Directory, request.Name, string(home)} {
		if bytes.Contains(encoded, []byte(text)) {
			t.Fatal("private target or value in receipt/audit")
		}
	}
}

func TestRunCLIValidationAndBinding(t *testing.T) {
	request := cliRequest(t)
	for _, name := range []string{"TOKEN", "API_KEY", "OPENAI_API_KEY", "GITLAB_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
		r := request
		r.Name = name
		if r.Validate() != nil {
			t.Fatal("common token name refused")
		}
	}
	for _, name := range []string{"PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PYTHONPATH", "GH_DEBUG", "HTTPS_PROXY", "SystemRoot", "GIT_CONFIG_COUNT", "BASH_ENV", "bad_TOKEN"} {
		r := request
		r.Name = name
		if r.Validate() == nil {
			t.Fatal("control environment accepted")
		}
	}
	for _, change := range []func(*RunCLIRequest){func(r *RunCLIRequest) { r.Program = "relative" }, func(r *RunCLIRequest) { r.Directory = "relative" }, func(r *RunCLIRequest) { r.HelperPath = []string{"relative"} }, func(r *RunCLIRequest) { r.HelperPath = []string{""} }, func(r *RunCLIRequest) { r.TimeoutSeconds = 0 }, func(r *RunCLIRequest) { r.Profile = "unknown" }} {
		r := request
		change(&r)
		if r.Validate() == nil {
			t.Fatal("invalid CLI request accepted")
		}
	}
	gh := request
	gh.Profile = RunCLIProfileGH
	gh.Name = "GH_TOKEN"
	gh.Args = []string{"api", "user"}
	if gh.Validate() != nil {
		t.Fatal("gh request refused")
	}
	for _, args := range [][]string{{"auth", "login"}, {"auth", "setup-git"}} {
		gh.Args = args
		if gh.Validate() == nil {
			t.Fatal("persistent auth command accepted")
		}
	}
	key := bytes.Repeat([]byte{7}, 32)
	r := request.runRequest(filepath.Join(t.TempDir(), "private"))
	base, e := r.binding(key)
	if e != nil {
		t.Fatal("binding failed")
	}
	old := r
	old.cli = nil
	oldDigest, _ := old.binding(key)
	if oldDigest == base {
		t.Fatal("null stdio binding reused")
	}
	if _, e := RunEnv(context.Background(), "unused", "unused", nil, RevealTarget{}, r); e != ErrRunTarget {
		t.Fatal("CLI policy admitted to null-stdio entry")
	}
	for _, change := range []func(*RunRequest){func(r *RunRequest) { r.cli.root += "different" }, func(r *RunRequest) { r.cli.helperPath = []string{t.TempDir()} }, func(r *RunRequest) { r.Args = []string{"different"} }, func(r *RunRequest) { r.TimeoutSeconds++ }, func(r *RunRequest) { r.Name = "OTHER_TOKEN" }} {
		other := r
		policy := *r.cli
		other.cli = &policy
		change(&other)
		digest, e := other.binding(key)
		if e != nil || digest == base {
			t.Fatal("CLI policy target not bound")
		}
	}
}

func TestRunCLIActualExitTimeoutAndCancellation(t *testing.T) {
	request := cliRequest(t)
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}
	for _, mode := range []string{"exit", "sleep", "block"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := request
			request.Args = append([]string{}, request.Args...)
			request.Args[len(request.Args)-4] = mode
			if mode == "sleep" {
				request.TimeoutSeconds = 1
			}
			input, inputWriter, e := os.Pipe()
			if e != nil {
				t.Fatal("input pipe unavailable")
			}
			defer input.Close()
			defer inputWriter.Close()
			output, outputWriter, e := os.Pipe()
			if e != nil {
				t.Fatal("output pipe unavailable")
			}
			defer output.Close()
			defer outputWriter.Close()
			null, e := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if e != nil {
				t.Fatal("null device unavailable")
			}
			defer null.Close()
			finished := make(chan struct{})
			var receipt RunReceipt
			var outcome error
			root := ""
			go func() {
				receipt, outcome = runCLI(ctx, target, request, func(r *RunRequest) (result, error) {
					root = r.cli.root
					return result{value: []byte("private-cli-value")}, nil
				}, func(ctx context.Context, r RunRequest, value []byte) (int, error) {
					return executeRunCLI(ctx, r, value, runCLIStreams{input, outputWriter, null})
				}, os.RemoveAll)
				close(finished)
			}()
			if mode == "block" {
				readyResult := make(chan bool, 1)
				go func() {
					var ready [5]byte
					_, err := io.ReadFull(output, ready[:])
					readyResult <- err == nil && string(ready[:]) == "ready"
				}()
				select {
				case ready := <-readyResult:
					if !ready {
						cancel()
						<-finished
						t.Fatal("child start barrier failed")
					}
				case <-time.After(15 * time.Second):
					cancel()
					output.Close()
					<-finished
					t.Fatal("child start barrier timed out")
				}
				cancel()
			}
			<-finished
			if mode == "exit" {
				if outcome != nil || receipt.ExitCode != 7 {
					t.Fatal("normal nonzero child status lost")
				}
			} else if outcome != ErrRunResult {
				t.Fatal("timeout or cancellation claimed success")
			}
			if _, e = os.Stat(root); !os.IsNotExist(e) {
				t.Fatal("temporary state survived child cancellation")
			}
		})
	}
}

func TestRunCLIFailureCancellationAndCleanup(t *testing.T) {
	request := cliRequest(t)
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}
	for _, kind := range []string{"prepare", "cancel", "execute", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value := []byte("private-cli-value")
			called := 0
			root := ""
			_, e := runCLI(ctx, target, request, func(r *RunRequest) (result, error) {
				root = r.cli.root
				if kind == "prepare" {
					return result{value: value}, errors.New("private-prepare-error")
				}
				if kind == "cancel" {
					cancel()
				}
				return result{value: value}, nil
			}, func(context.Context, RunRequest, []byte) (int, error) {
				called++
				if kind == "execute" {
					return 0, errors.New("private-execute-error")
				}
				return 0, nil
			}, func(path string) error {
				if kind == "cleanup" {
					defer os.RemoveAll(path)
					return errors.New("private-cleanup-error")
				}
				return os.RemoveAll(path)
			})
			if e == nil || strings.Contains(e.Error(), "private-execute-error") || strings.Contains(e.Error(), "private-cleanup-error") {
				t.Fatal("failure status missing or private error exposed")
			}
			if kind == "cancel" && e != ErrRunCancelled {
				t.Fatal("known cancellation before start was not distinguished")
			}
			if (kind == "prepare" || kind == "cancel") && called != 0 {
				t.Fatal("failed authorization executed")
			}
			if !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("disclosed buffer not cleared")
			}
			if _, e = os.Stat(root); !os.IsNotExist(e) {
				t.Fatal("temporary state survived failure")
			}
		})
	}
}

func TestRunCLICancelledEntryAndPasswordOnly(t *testing.T) {
	request := cliRequest(t)
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := RunCLI(ctx, "unused", "unused", nil, target, request); e != ErrRunCancelled {
		t.Fatal("cancelled entry did not stop before authentication")
	}
	target.Field = "username"
	if _, e := RunCLI(context.Background(), "unused", "unused", nil, target, request); e != ErrRunTarget {
		t.Fatal("non-password CLI disclosure accepted")
	}
	run := request.runRequest(t.TempDir())
	null, e := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if e != nil {
		t.Fatal("null device unavailable")
	}
	defer null.Close()
	if _, e := executeRunCLI(ctx, run, []byte("private-cli-value"), runCLIStreams{null, null, null}); e != ErrRunCancelled {
		t.Fatal("cancelled executor entered process creation")
	}
}

func TestRunCLIGHBlankCredentialNeverStarts(t *testing.T) {
	target := RevealTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), Field: "password"}
	request := cliRequest(t)
	request.Name, request.Profile = "GH_TOKEN", RunCLIProfileGH
	for _, content := range []string{"", " \t\r\n", "\u2003\u00a0"} {
		value := []byte(content)
		started := 0
		root := ""
		_, e := runCLI(context.Background(), target, request, func(r *RunRequest) (result, error) {
			root = r.cli.root
			return result{value: value}, nil
		}, func(context.Context, RunRequest, []byte) (int, error) {
			started++
			return 0, nil
		}, os.RemoveAll)
		if e != ErrRunCredential || started != 0 || root == "" {
			t.Fatal("blank GH credential reached process execution")
		}
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("refused credential not cleared")
		}
		if _, e = os.Stat(root); !os.IsNotExist(e) {
			t.Fatal("temporary state survived GH refusal")
		}
	}
	null, e := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if e != nil {
		t.Fatal("null device unavailable")
	}
	defer null.Close()
	if _, e := executeRunCLI(context.Background(), request.runRequest(t.TempDir()), []byte(" \t"), runCLIStreams{null, null, null}); e != ErrRunCredential {
		t.Fatal("direct executor allowed a blank GH credential")
	}
	// The generic disclosure contract continues to pass the original bytes.
	request.Name, request.Profile = "TEST_TOKEN", RunCLIProfileToken
	started := 0
	if _, e := runCLI(context.Background(), target, request, func(*RunRequest) (result, error) {
		return result{value: []byte(" \t")}, nil
	}, func(_ context.Context, _ RunRequest, value []byte) (int, error) {
		started++
		if string(value) != " \t" {
			t.Fatal("generic token was normalized")
		}
		return 0, nil
	}, os.RemoveAll); e != nil || started != 1 {
		t.Fatal("generic empty-value semantics changed")
	}
}
