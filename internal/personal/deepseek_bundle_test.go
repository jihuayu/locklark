package personal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/vault"
)

func TestDeepSeekCredentialChild(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "deepseek-credential-probe" {
		return
	}
	if os.Getenv("DEEPSEEK_API_KEY") != bundleTestPassword || os.Getenv("GH_TOKEN") != "" {
		os.Exit(71)
	}
	if os.Getenv("DEEPSEEK_MODEL") != "synthetic-worker" {
		os.Exit(72)
	}
	// Report only directory metadata, never the credential or a credential hash.
	if json.NewEncoder(os.Stdout).Encode(filepath.Dir(os.Getenv("HOME"))) != nil {
		os.Exit(73)
	}
	os.Exit(0)
}

func TestDeepSeekVaultCredentialReachesOnlyChild(t *testing.T) {
	f := newBundleTestFixture(t)
	t.Setenv("GH_TOKEN", "ambient-secret-must-not-be-inherited")
	t.Setenv("DEEPSEEK_API_KEY", "ambient-key-must-not-win")
	profile, _ := cliprofile.Lookup("deepseek")
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := RunBundleRequest{
		Program: program, Directory: t.TempDir(), TimeoutSeconds: 10,
		Args:       []string{"-test.run=^TestDeepSeekCredentialChild$", "--", "deepseek-credential-probe"},
		HelperPath: []string{filepath.Dir(program)}, Spec: profile.Spec(),
		Passthrough: map[string]string{"DEEPSEEK_MODEL": "synthetic-worker"},
	}
	targets := []BundleTarget{{Slot: "token", ID: f.loginID, Revision: f.loginRevision, Field: "password"}}
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.CreateTemp(t.TempDir(), "child-output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	receipt, err := runBundle(context.Background(), targets, request, createRunCLITemp, func(r *runBundleStoreRequest) (result, error) {
		return command(f.path, "fixture", f.key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: r})
	}, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
		return executeRunBundle(ctx, req, root, rendered, runCLIStreams{input, output, output})
	}, os.RemoveAll)
	if err != nil || receipt.ExitCode != 0 || receipt.Intent == "" {
		t.Fatalf("vault credential execution failed: code=%d error=%v", receipt.ExitCode, err)
	}
	if _, err = output.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var root string
	if json.NewDecoder(output).Decode(&root) != nil || root == "" {
		t.Fatal("credential child did not complete")
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("credential run directory survived cleanup")
	}
	events, err := Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(events)
	if err != nil || strings.Contains(string(raw), bundleTestPassword) {
		t.Fatal("audit contained credential data")
	}
	found := false
	for _, event := range events {
		if event.Action == runBundleAction && event.Result == "intent" {
			found = true
		}
	}
	if !found {
		t.Fatal("execution intent missing from authenticated audit")
	}
}
