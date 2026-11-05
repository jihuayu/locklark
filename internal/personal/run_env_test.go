package personal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func runRequest(t *testing.T) RunRequest {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return RunRequest{Program: exe, Args: []string{"-test.run=^TestRunEnvChild$", "--", "", "two words", "$(echo hidden)", "a;b", "probe"}, Directory: t.TempDir(), Name: "LOCKLARK_TEST_VALUE", TimeoutSeconds: 10}
}

func TestRunEnvChild(t *testing.T) {
	value, ok := os.LookupEnv("LOCKLARK_TEST_VALUE")
	if !ok {
		return
	}
	// Deliberately emit the credential: neither stream may reach the parent output.
	fmt.Fprint(os.Stdout, value)
	fmt.Fprint(os.Stderr, value)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name != "LOCKLARK_TEST_VALUE" && !(runtime.GOOS == "windows" && strings.EqualFold(name, "SystemRoot")) {
			os.Exit(23)
		}
	}
	if !reflect.DeepEqual(os.Args[len(os.Args)-5:len(os.Args)-1], []string{"", "two words", "$(echo hidden)", "a;b"}) {
		os.Exit(24)
	}
	var input [1]byte
	n, _ := os.Stdin.Read(input[:])
	if n != 0 {
		os.Exit(25)
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "sleep" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	if mode == "exit" {
		os.Exit(7)
	}
	if os.Getenv("LOCKLARK_PARENT_ONLY") != "" {
		os.Exit(20)
	}
	if value != "private-value\t\"quoted\"\n" {
		os.Exit(21)
	}
	if e := os.WriteFile("child-proof", []byte("matched"), 0600); e != nil {
		os.Exit(22)
	}
	os.Exit(0)
}

func TestRunEnvIntentPrecedesProcess(t *testing.T) {
	path, key, target := revealFixture(t)
	request := runRequest(t)
	prepare := func(r *RunRequest) (result, error) {
		return command(path, "fixture", key, "item.run.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{run: r})
	}
	called := 0
	receipt, e := runEnv(context.Background(), target, request, prepare, func(ctx context.Context, r RunRequest, value []byte) (int, error) {
		called++
		events, e := Audit(path, "fixture", key)
		if e != nil {
			t.Fatal("process before close", e)
		}
		ev := events[len(events)-2]
		if ev.Action != "item.run.password" || ev.Result != "intent" || ev.BaseRevision != target.Revision {
			t.Fatal("no committed intent")
		}
		return executeRun(ctx, r, value)
	})
	if e != nil || called != 1 || receipt.Status != "process-exited" || receipt.ExitCode != 0 {
		t.Fatal("run", e, receipt)
	}
	raw, e := os.ReadFile(filepath.Join(request.Directory, "child-proof"))
	if e != nil || string(raw) != "matched" {
		t.Fatal("no child proof", e)
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ev := range events {
		if ev.hash() == receipt.Intent {
			found = true
			if ev.Link != receipt.TargetDigest {
				t.Fatal("wrong binding")
			}
		}
	}
	if !found {
		t.Fatal("missing intent")
	}
	encoded, _ := json.Marshal([]any{receipt, events})
	for _, s := range []string{"private-value", request.Program, request.Directory, "LOCKLARK_TEST_VALUE"} {
		if bytes.Contains(encoded, []byte(s)) {
			t.Fatal("private value/target exposed")
		}
	}
	rows, e := List(path, "fixture", key)
	if e != nil || rows[0].Revision != target.Revision {
		t.Fatal("run changed revision", e)
	}
	backup := filepath.Join(t.TempDir(), "backup.llb")
	kit, e := Backup(path, backup, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := NewSecret()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(fresh)
	restored := filepath.Join(t.TempDir(), "restored.ll")
	if e = Restore(backup, restored, "fixture", key, kit, fresh); e != nil {
		t.Fatal("restore run history", e)
	}
}

func TestRunEnvFailuresAndBinding(t *testing.T) {
	path, key, target := revealFixture(t)
	request := runRequest(t)
	called := 0
	execute := func(context.Context, RunRequest, []byte) (int, error) {
		called++
		return 0, errors.New("private child value")
	}
	prepare := func(r *RunRequest) (result, error) {
		return command(path, "fixture", key, "item.run.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{run: r})
	}
	original := target.Revision
	target.Revision = strings.Repeat("0", 64)
	if _, e := runEnv(context.Background(), target, request, prepare, execute); e != ErrConflict || called != 0 {
		t.Fatal("stale ran", e)
	}
	target.Revision = original
	if r, e := RunEnv(context.Background(), path, "wrong", key, target, request); e == nil || !reflect.DeepEqual(r, RunReceipt{}) {
		t.Fatal("wrong password ran")
	}
	db, e := existing(path)
	if e != nil {
		t.Fatal(e)
	}
	injected := errors.New("rollback")
	_, e = runEnv(context.Background(), target, request, func(r *RunRequest) (result, error) {
		return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
			return db.Update(func(tx *bolt.Tx) error {
				if e := fn(tx); e != nil {
					return e
				}
				return injected
			})
		}, "fixture", key, "item.run.password", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{run: r})
	}, execute)
	db.Close()
	if e != injected || called != 0 {
		t.Fatal("rollback ran", e)
	}
	r, e := runEnv(context.Background(), target, request, prepare, execute)
	if e != ErrRunResult || called != 1 || !reflect.DeepEqual(r, RunReceipt{}) {
		t.Fatal("raw process error", e)
	}
	target.Revision, e = SetTrashed(path, "fixture", key, target.ID, target.Revision, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runEnv(context.Background(), target, request, prepare, execute); e != ErrTrashed || called != 1 {
		t.Fatal("trash ran", e)
	}
	for _, kind := range []string{"close", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value := []byte("private")
			_, e := runEnv(ctx, target, request, func(*RunRequest) (result, error) {
				if kind == "cancel" {
					cancel()
					return result{value: value}, nil
				}
				return commandWithClose(func() (result, error) { return result{value: value}, nil }, func() error { return errors.New("close") })
			}, execute)
			if e == nil || called != 1 || !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("failed boundary ran", e)
			}
		})
	}
	base, _ := request.binding(bytes.Repeat([]byte{1}, 32))
	for _, change := range []func(*RunRequest){func(r *RunRequest) { r.Program += "x" }, func(r *RunRequest) { r.Directory += "x" }, func(r *RunRequest) { r.Name = "OTHER" }, func(r *RunRequest) { r.Args = []string{"different"} }, func(r *RunRequest) { r.TimeoutSeconds++ }} {
		other := request
		change(&other)
		got, e := other.binding(bytes.Repeat([]byte{1}, 32))
		if e != nil || got == base {
			t.Fatal("target not bound")
		}
	}
	for _, args := range [][]string{{"a b"}, {"a", "b"}, {"a", "b", ""}} {
		r := request
		r.Args = args
		one, _ := r.binding(bytes.Repeat([]byte{1}, 32))
		if one == base {
			t.Fatal("argv boundary binding")
		}
		base = one
	}
	other, _ := request.binding(bytes.Repeat([]byte{2}, 32))
	if other == base || !digestOK(base) {
		t.Fatal("cross vault binding")
	}
}

func TestRunEnvProcessAndValidation(t *testing.T) {
	request := runRequest(t)
	t.Setenv("LOCKLARK_PARENT_ONLY", "must-not-inherit")
	t.Setenv("PATHEXT", ".POISON")
	for _, mode := range []string{"probe", "exit", "sleep"} {
		r := request
		r.Args = append([]string(nil), request.Args...)
		r.Args[len(r.Args)-1] = mode
		// Race-instrumented helper binaries pause during normal exit.
		if mode == "sleep" {
			r.TimeoutSeconds = 1
		}
		code, e := executeRun(context.Background(), r, []byte("private-value\t\"quoted\"\n"))
		switch mode {
		case "probe":
			if e != nil || code != 0 {
				t.Fatal("probe", e, code)
			}
		case "exit":
			if e != nil || code != 7 {
				t.Fatal("exit", e, code)
			}
		case "sleep":
			if e == nil {
				t.Fatal("timeout ignored")
			}
		}
	}
	for _, change := range []func(*RunRequest){func(r *RunRequest) { r.Program = "relative" }, func(r *RunRequest) { r.Directory = "relative" }, func(r *RunRequest) { r.Name = "SystemRoot" }, func(r *RunRequest) { r.Name = "a=b" }, func(r *RunRequest) { r.TimeoutSeconds = 0 }, func(r *RunRequest) { r.TimeoutSeconds = 301 }, func(r *RunRequest) { r.Args = []string{"nul\x00"} }, func(r *RunRequest) { r.Args = make([]string, 65) }} {
		r := request
		change(&r)
		if r.Validate() == nil {
			t.Fatal("invalid request accepted", r)
		}
	}
	if _, e := executeRun(context.Background(), request, []byte("nul\x00")); e == nil {
		t.Fatal("NUL env accepted")
	}
	missing := request
	missing.Program = filepath.Join(t.TempDir(), "absent")
	if _, e := executeRun(context.Background(), missing, []byte("value")); e == nil {
		t.Fatal("missing executable accepted")
	}
}

func TestRunEnvUsernameIntent(t *testing.T) {
	path, key, target := revealFixture(t)
	target.Field = "username"
	request := runRequest(t)
	receipt, e := runEnv(context.Background(), target, request, func(r *RunRequest) (result, error) {
		return command(path, "fixture", key, "item.run.username", vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{run: r})
	}, func(_ context.Context, _ RunRequest, value []byte) (int, error) {
		if string(value) != "fixture-user" {
			t.Fatal("wrong field disclosed")
		}
		return 0, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	events, e := Audit(path, "fixture", key)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ev := range events {
		if ev.hash() == receipt.Intent {
			found = true
			if ev.Action != "item.run.username" || ev.BaseRevision != target.Revision || ev.Link != receipt.TargetDigest {
				t.Fatal("field binding absent")
			}
		}
	}
	if !found {
		t.Fatal("intent absent")
	}
}
