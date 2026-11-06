package personal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/cliprofile"
)

func TestInformationalCLIChild(t *testing.T) {
	if os.Getenv("LOCKLARK_CLI_ACTIVE") != "informational-test" {
		return
	}
	for _, name := range []string{"GH_TOKEN", "DEEPSEEK_API_KEY", "HTTPS_PROXY", "PYTHONPATH", "LD_PRELOAD"} {
		if _, exists := os.LookupEnv(name); exists {
			os.Exit(61)
		}
	}
	root := filepath.Dir(os.Getenv("HOME"))
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "GH_CONFIG_DIR", "TMPDIR"} {
		path := os.Getenv(name)
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() || filepath.Dir(path) != root {
			os.Exit(62)
		}
	}
	if os.Getenv("NO_COLOR") != "1" {
		os.Exit(63)
	}
	if json.NewEncoder(os.Stdout).Encode(root) != nil {
		os.Exit(64)
	}
	os.Exit(17)
}

func TestInformationalCLIIsolationAndCleanup(t *testing.T) {
	t.Setenv("GH_TOKEN", "ambient-gh-canary")
	t.Setenv("DEEPSEEK_API_KEY", "ambient-deepseek-canary")
	t.Setenv("HTTPS_PROXY", "ambient-proxy-canary")
	t.Setenv("PYTHONPATH", "ambient-python-canary")
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := cliprofile.Lookup("gh")
	request := RunBundleRequest{
		Program: program, Directory: t.TempDir(), TimeoutSeconds: 10,
		Args:       []string{"-test.run=^TestInformationalCLIChild$", "--", "--help"},
		HelperPath: []string{filepath.Dir(program)}, Spec: profile.Spec(),
		Passthrough: map[string]string{"NO_COLOR": "1"},
	}
	targets := []BundleTarget{{Slot: "token", Field: "password", ID: strings.Repeat("a", 32), Revision: strings.Repeat("b", 64)}}
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	code, err := runCLIInformational(context.Background(), request, targets, "informational-test", runCLIStreams{input, output, output})
	if err != nil || code != 17 {
		t.Fatalf("isolated child failed: code=%d error=%v", code, err)
	}
	if _, err = output.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var root string
	if err = json.NewDecoder(output).Decode(&root); err != nil || root == "" {
		t.Fatal("child directory evidence missing")
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("isolated directory survived execution")
	}
	request.Passthrough["GH_TOKEN"] = "refused-canary"
	if _, err = runCLIInformational(context.Background(), request, targets, "informational-test", runCLIStreams{input, output, output}); err != ErrRunTarget {
		t.Fatal("credential passthrough accepted")
	}
}
