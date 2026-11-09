package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/personal"
)

const (
	cliTestID        = "0123456789abcdef0123456789abcdef"
	cliTestRevision  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cliTestID2       = "fedcba9876543210fedcba9876543210"
	cliTestRevision2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func cliTestDir(t *testing.T) string {
	t.Helper()
	dir := newPrivateCLITestDir(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private directory unavailable")
	}
	return dir
}

func cliTestExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	return exe
}

func runCLIForTest(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := runCLICommand(args, &out)
	return out.Bytes(), err
}

func decodeCLIJSON(t *testing.T, raw []byte, value any) {
	t.Helper()
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
}

func TestCLIProfilesAndStoreLifecycle(t *testing.T) {
	raw, err := runCLIForTest(t, "profiles")
	if err != nil {
		t.Fatal("profiles failed:", err)
	}
	var profiles []cliProfileDescription
	decodeCLIJSON(t, raw, &profiles)
	wantNames := []string{"anthropic", "aws", "deepseek", "docker", "flyctl", "gh", "git", "kubectl", "netrc", "npm", "openai", "psql", "stripe", "terraform", "token", "vercel"}
	if len(profiles) != len(wantNames) {
		t.Fatalf("profile count = %d, want %d", len(profiles), len(wantNames))
	}
	for i, want := range wantNames {
		if profiles[i].Name != want || profiles[i].ID == "" || profiles[i].MaxTimeout <= 0 || profiles[i].Slots == nil {
			t.Fatalf("profile %d is incomplete: %+v", i, profiles[i])
		}
	}
	for _, profile := range profiles {
		if (profile.Name == "token" || profile.Name == "deepseek") && (profile.Executables == nil || len(profile.Executables) != 0) {
			t.Fatalf("%s profile executables must be an empty array", profile.Name)
		}
	}

	dir := cliTestDir(t)
	bindingPath := filepath.Join(dir, clibinding.DefaultFileName)
	vaultPath := filepath.Join(dir, "owner.ll")
	program := cliTestExecutable(t)
	args := []string{
		"init", "gh", "--file", vaultPath, "--program", program, "--binding", bindingPath,
		"--id", cliTestID, "--revision", cliTestRevision, "--passthrough", "GH_HOST,NO_COLOR",
		"--timeout", "60",
	}
	raw, err = runCLIForTest(t, args...)
	if err != nil {
		t.Fatal("init failed:", err)
	}
	var receipt struct {
		Status        string `json:"status"`
		Tool          string `json:"tool"`
		Profile       string `json:"profile"`
		Program       string `json:"program"`
		ProgramSHA256 string `json:"program_sha256"`
		BindingFile   string `json:"binding_file"`
	}
	decodeCLIJSON(t, raw, &receipt)
	wantSHA, hashErr := clibinding.ComputeProgramSHA256(program)
	if hashErr != nil || receipt.Status != "bound" || receipt.Tool != "gh" || receipt.Profile != "gh" ||
		receipt.Program != program || receipt.ProgramSHA256 != wantSHA || receipt.BindingFile != bindingPath {
		t.Fatalf("unexpected init receipt: %+v", receipt)
	}
	info, err := os.Stat(bindingPath)
	if err != nil {
		t.Fatal("binding file missing")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("binding file mode is %04o, want 0600", info.Mode().Perm())
	}

	raw, err = runCLIForTest(t, "list", "--binding", bindingPath)
	if err != nil {
		t.Fatal("list failed:", err)
	}
	var store clibinding.Store
	decodeCLIJSON(t, raw, &store)
	if store.Version != clibinding.SchemaVersion || len(store.Bindings) != 1 {
		t.Fatalf("unexpected store: %+v", store)
	}
	if len(store.Bindings["gh"].Targets) != 1 || store.Bindings["gh"].Targets[0].Field != "password" {
		t.Fatal("listed target is incomplete")
	}
	raw, err = runCLIForTest(t, "list", "--config", bindingPath)
	if err != nil {
		t.Fatal("config alias list failed:", err)
	}

	raw, err = runCLIForTest(t, "show", "gh", "--binding", bindingPath)
	if err != nil {
		t.Fatal("show failed:", err)
	}
	var shown clibinding.ToolBinding
	decodeCLIJSON(t, raw, &shown)
	if !reflect.DeepEqual(shown, store.Bindings["gh"]) {
		t.Fatal("show output differs from the stored binding")
	}

	for _, shell := range []string{"bash", "zsh", "fish", "powershell", "pwsh"} {
		raw, err = runCLIForTest(t, "shell-init", shell, "--binding", bindingPath)
		if err != nil {
			t.Fatalf("shell-init %s failed: %v", shell, err)
		}
		script := string(raw)
		switch shell {
		case "bash", "zsh":
			if !strings.Contains(script, "gh() {") || !strings.Contains(script, "command locklark cli run gh") ||
				!strings.Contains(script, "--binding '"+bindingPath+"'") || !strings.Contains(script, `-- "$@"`) ||
				strings.Contains(script, "alias gh=") {
				t.Fatalf("unsafe bash/zsh wrapper: %s", script)
			}
		case "fish":
			if !strings.Contains(script, "function gh --wraps=gh") || !strings.Contains(script, " -- $argv") {
				t.Fatalf("unsafe fish wrapper: %s", script)
			}
		default:
			if !strings.Contains(script, "function Invoke-LocklarkCli_gh") ||
				!strings.Contains(script, "Set-Alias -Name gh -Value Invoke-LocklarkCli_gh") ||
				!strings.Contains(script, " -- @args") {
				t.Fatalf("unsafe powershell wrapper: %s", script)
			}
		}
	}

	missing := filepath.Join(dir, "missing.json")
	raw, err = runCLIForTest(t, "shell-init", "bash", "--binding", missing)
	if err != nil {
		t.Fatal("shell-init default tools failed:", err)
	}
	if !strings.Contains(string(raw), "aws() {") || !strings.Contains(string(raw), "terraform() {") {
		t.Fatal("default wrapper list is incomplete")
	}

	raw, err = runCLIForTest(t, "remove", "gh", "--binding", bindingPath)
	if err != nil {
		t.Fatal("remove failed:", err)
	}
	var removed struct {
		Status string `json:"status"`
		Tool   string `json:"tool"`
	}
	decodeCLIJSON(t, raw, &removed)
	if removed.Status != "removed" || removed.Tool != "gh" {
		t.Fatalf("unexpected removal receipt: %+v", removed)
	}
	if _, err = runCLIForTest(t, "show", "gh", "--binding", bindingPath); !errors.Is(err, clibinding.ErrBindingNotFound) {
		t.Fatal("removed tool still shown")
	}
	raw, err = runCLIForTest(t, "list", "--binding", bindingPath)
	if err != nil {
		t.Fatal("empty list failed:", err)
	}
	store = clibinding.Store{}
	decodeCLIJSON(t, raw, &store)
	if store.Version != 1 || len(store.Bindings) != 0 {
		t.Fatal("removal did not persist an empty store")
	}

	var routed bytes.Buffer
	if err = run([]string{"cli", "profiles"}, &routed, &bytes.Buffer{}); err != nil || !bytes.Contains(routed.Bytes(), []byte(`"token"`)) {
		t.Fatal("main did not route cli profiles")
	}
	if !strings.Contains(usage, "cli run <tool>") || !strings.Contains(usage, "cli shell-init") {
		t.Fatal("usage omits cli commands")
	}
}

func findTarget(binding clibinding.ToolBinding, slot string) (clibinding.SlotTarget, bool) {
	for _, target := range binding.Targets {
		if target.Slot == slot {
			return target, true
		}
	}
	return clibinding.SlotTarget{}, false
}

func TestCLIInitTargetErgonomics(t *testing.T) {
	dir := cliTestDir(t)
	bindingPath := filepath.Join(dir, "bindings.json")
	vaultPath := filepath.Join(dir, "owner.ll")
	program := cliTestExecutable(t)
	base := []string{"--file", vaultPath, "--program", program, "--binding", bindingPath}

	if _, err := runCLIForTest(t, append([]string{"init", "aws"}, append(base, "--id", cliTestID, "--revision", cliTestRevision)...)...); err != nil {
		t.Fatal("aws convenience init failed:", err)
	}
	raw, err := runCLIForTest(t, "show", "aws", "--binding", bindingPath)
	if err != nil {
		t.Fatal("aws show failed:", err)
	}
	var aws clibinding.ToolBinding
	decodeCLIJSON(t, raw, &aws)
	if len(aws.Targets) != 2 {
		t.Fatalf("aws target count = %d, want 2", len(aws.Targets))
	}
	access, ok := findTarget(aws, "access_key_id")
	if !ok || access.Field != "username" {
		t.Fatal("aws access key target missing")
	}
	secret, ok := findTarget(aws, "secret_access_key")
	if !ok || secret.Field != "password" {
		t.Fatal("aws secret key target missing")
	}
	if _, ok = findTarget(aws, "session_token"); ok {
		t.Fatal("optional session token was populated without being requested")
	}

	if _, err = runCLIForTest(t, append([]string{"bind", "mydocker", "--profile", "docker"}, append(base, "--id", cliTestID, "--revision", cliTestRevision, "--slot-username", cliTestID2+":"+cliTestRevision2)...)...); err != nil {
		t.Fatal("docker override init failed:", err)
	}
	raw, err = runCLIForTest(t, "show", "mydocker", "--binding", bindingPath)
	if err != nil {
		t.Fatal("docker show failed:", err)
	}
	var docker clibinding.ToolBinding
	decodeCLIJSON(t, raw, &docker)
	username, ok := findTarget(docker, "username")
	if !ok || username.ID != cliTestID2 || username.Revision != cliTestRevision2 {
		t.Fatal("explicit slot target did not override the convenience pair")
	}
	password, ok := findTarget(docker, "password")
	if !ok || password.ID != cliTestID || password.Field != "password" {
		t.Fatal("convenience password target missing")
	}

	if _, err = runCLIForTest(t, append([]string{"init", "kube"}, append(base, "--profile", "kubectl", "--login", cliTestID+":"+cliTestRevision)...)...); !errors.Is(err, cliUsage) {
		t.Fatal("login pair accepted for a document-only profile")
	}
	if _, err = runCLIForTest(t, append([]string{"init", "kube"}, append(base, "--profile", "kubectl", "--id", cliTestID, "--revision", cliTestRevision)...)...); err != nil {
		t.Fatal("single-slot document convenience init failed:", err)
	}
	raw, err = runCLIForTest(t, "show", "kube", "--binding", bindingPath)
	if err != nil {
		t.Fatal("kubectl show failed:", err)
	}
	var kubectl clibinding.ToolBinding
	decodeCLIJSON(t, raw, &kubectl)
	if target, ok := findTarget(kubectl, "kubeconfig"); !ok || target.Field != "attachment" {
		t.Fatal("document target field is wrong")
	}

	if _, err = runCLIForTest(t, append([]string{"init", "myapi"}, append(base, "--profile", "token", "--name", "MY_API_TOKEN", "--id", cliTestID, "--revision", cliTestRevision)...)...); err != nil {
		t.Fatal("token init failed:", err)
	}
	raw, err = runCLIForTest(t, "show", "myapi", "--binding", bindingPath)
	if err != nil {
		t.Fatal("token show failed:", err)
	}
	var token clibinding.ToolBinding
	decodeCLIJSON(t, raw, &token)
	if token.TokenEnvName != "MY_API_TOKEN" || token.Profile != "token" {
		t.Fatalf("token binding metadata wrong: %+v", token)
	}

	if _, err = runCLIForTest(t, append([]string{"init", "session"}, append(base, "--profile", "aws", "--id", cliTestID, "--revision", cliTestRevision, "--session-token", cliTestID2+":"+cliTestRevision2)...)...); err != nil {
		t.Fatal("session token init failed:", err)
	}
	raw, err = runCLIForTest(t, "show", "session", "--binding", bindingPath)
	if err != nil {
		t.Fatal("session show failed:", err)
	}
	var session clibinding.ToolBinding
	decodeCLIJSON(t, raw, &session)
	if target, ok := findTarget(session, "session_token"); !ok || target.ID != cliTestID2 || target.Field != "password" {
		t.Fatal("explicit session token target missing")
	}

	errorCases := [][]string{
		append([]string{"init", "bad", "--id", cliTestID}, base...),
		append([]string{"init", "bad"}, append(base, "--revision", cliTestRevision)...),
		append([]string{"init", "bad", "--profile", "aws", "--id", cliTestID, "--revision", cliTestRevision, "--slot-unknown", cliTestID + ":" + cliTestRevision}, base...),
		append([]string{"init", "bad"}, append(base, "--slot-token", "short")...),
		append([]string{"init", "bad", "--profile", "terraform"}, append(base, "--id", cliTestID, "--revision", cliTestRevision)...),
		append([]string{"init", "bad", "--profile", "token", "--id", cliTestID, "--revision", cliTestRevision}, base...),
		{"init", "bad", "--file", vaultPath, "--program", "relative", "--binding", bindingPath, "--id", cliTestID, "--revision", cliTestRevision},
		{"init", "bad", "--file", vaultPath, "--program", dir, "--binding", bindingPath, "--id", cliTestID, "--revision", cliTestRevision},
		{"init", "bad", "--tool=", "--file", vaultPath, "--program", program, "--binding", bindingPath, "--id", cliTestID, "--revision", cliTestRevision},
		{"init", "bad", "--profile=", "--file", vaultPath, "--program", program, "--binding", bindingPath, "--id", cliTestID, "--revision", cliTestRevision},
		{"init", "bad", "--program=", "--file", vaultPath, "--binding", bindingPath, "--id", cliTestID, "--revision", cliTestRevision},
		append([]string{"init", "bad"}, append(base, "--id", cliTestID, "--revision", cliTestRevision, "--pin-sha256", "yes")...),
		append([]string{"init", "bad"}, append(base, "--id", cliTestID, "--revision", cliTestRevision, "--timeout", "0")...),
		append([]string{"init", "bad"}, append(base, "--id", cliTestID, "--revision", cliTestRevision, "--timeout", "301")...),
		append([]string{"init", "bad"}, append(base, "--id", cliTestID, "--revision", cliTestRevision, "--name", "MY_TOKEN")...),
		append([]string{"init", "bad"}, append(base, "--id", cliTestID, "--revision", cliTestRevision, "--passthrough", "PATH")...),
		append([]string{"init", "bad", "second"}, base...),
		append([]string{"init", "bad", "--tool", "bad"}, base...),
		append([]string{"init"}, base...),
	}
	for i, args := range errorCases {
		if _, err := runCLIForTest(t, args...); err == nil {
			t.Errorf("invalid init %d accepted: %v", i, args)
		}
	}

	unpinned := append([]string{"init", "unpinned", "--profile", "gh"}, append(base, "--id", cliTestID, "--revision", cliTestRevision, "--pin-sha256", "false")...)
	if _, err := runCLIForTest(t, unpinned...); err != nil {
		t.Fatal("unpinned init failed:", err)
	}
	raw, err = runCLIForTest(t, "show", "unpinned", "--binding", bindingPath)
	if err != nil {
		t.Fatal("unpinned show failed:", err)
	}
	var unpinnedBinding clibinding.ToolBinding
	decodeCLIJSON(t, raw, &unpinnedBinding)
	if unpinnedBinding.ProgramSHA256 != "" {
		t.Fatal("pin flag false still stored a digest")
	}
}

func TestCLIProgramLookupDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("script executable fixture uses a POSIX path")
	}
	dir := cliTestDir(t)
	toolDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(toolDir, 0700); err != nil {
		t.Fatal("tool directory unavailable")
	}
	tool := filepath.Join(toolDir, "mytool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal("tool fixture unavailable")
	}
	t.Setenv("PATH", toolDir)
	bindingPath := filepath.Join(dir, "bindings.json")
	raw, err := runCLIForTest(t, "init", "mytool", "--profile", "token", "--name", "MY_TOKEN",
		"--file", filepath.Join(dir, "owner.ll"), "--binding", bindingPath,
		"--id", cliTestID, "--revision", cliTestRevision)
	if err != nil {
		t.Fatal("lookup init failed:", err)
	}
	var receipt struct {
		Program string `json:"program"`
	}
	decodeCLIJSON(t, raw, &receipt)
	if receipt.Program != tool {
		t.Fatalf("resolved program = %q, want %q", receipt.Program, tool)
	}
	raw, err = runCLIForTest(t, "show", "mytool", "--binding", bindingPath)
	if err != nil {
		t.Fatal("lookup show failed:", err)
	}
	var binding clibinding.ToolBinding
	decodeCLIJSON(t, raw, &binding)
	if len(binding.HelperPath) != 1 || binding.HelperPath[0] != toolDir {
		t.Fatal("default helper path is not the program directory")
	}
}

func TestCLIDeepSeekProfileBinding(t *testing.T) {
	dir := cliTestDir(t)
	bindingPath := filepath.Join(dir, "bindings.json")
	vaultPath := filepath.Join(dir, "owner.ll")
	program := cliTestExecutable(t)
	canary := "DeepSeekCanary" + strings.Repeat("x", 32)
	t.Setenv("DEEPSEEK_API_KEY", canary)
	base := []string{"init", "deepseek-worker", "--profile", "deepseek", "--file", vaultPath, "--binding", bindingPath,
		"--id", cliTestID, "--revision", cliTestRevision}
	if _, err := runCLIForTest(t, base...); !errors.Is(err, cliUsage) {
		t.Fatal("deepseek accepted automatic program lookup")
	}
	if _, err := runCLIForTest(t, append(base, "--program", program, "--passthrough", "DEEPSEEK_API_KEY")...); err == nil {
		t.Fatal("deepseek accepted secret passthrough")
	}
	args := append(base, "--program", program, "--timeout", "3600",
		"--passthrough", "DEEPSEEK_BASE_URL,DEEPSEEK_MODEL,DEEPSEEK_STATE_DIR")
	if _, err := runCLIForTest(t, args...); err != nil {
		t.Fatal("deepseek init failed:", err)
	}
	raw, err := runCLIForTest(t, "show", "deepseek-worker", "--binding", bindingPath)
	if err != nil {
		t.Fatal("deepseek show failed:", err)
	}
	var binding clibinding.ToolBinding
	decodeCLIJSON(t, raw, &binding)
	if binding.Profile != "deepseek" || binding.Program != program || binding.TimeoutSeconds != 3600 ||
		len(binding.Targets) != 1 || binding.Targets[0].Slot != "token" || binding.Targets[0].Field != "password" ||
		reflect.DeepEqual(binding.PassthroughEnv, []string{"DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL", "DEEPSEEK_STATE_DIR"}) == false {
		t.Fatalf("deepseek binding metadata wrong: %+v", binding)
	}
	if binding.ProgramSHA256 == "" {
		t.Fatal("deepseek interpreter was not pinned")
	}
	stored, err := os.ReadFile(bindingPath)
	if err != nil || bytes.Contains(stored, []byte(canary)) {
		t.Fatal("deepseek binding persisted a credential value")
	}
	for _, denied := range [][]string{{"configure"}, {"spawn"}, {"--background"}} {
		if _, err := runCLIForTest(t, append([]string{"run", "deepseek-worker", "--binding", bindingPath, "--"}, denied...)...); !errors.Is(err, cliUsage) {
			t.Fatalf("deepseek accepted denied args %v: %v", denied, err)
		}
	}
}

func TestCLIListShowMissingAndCorrupt(t *testing.T) {
	dir := cliTestDir(t)
	missing := filepath.Join(dir, "missing.json")
	t.Setenv("LOCKLARK_CLI_BINDING", missing)
	raw, err := runCLIForTest(t, "list")
	if err != nil {
		t.Fatal("missing default list failed:", err)
	}
	var store clibinding.Store
	decodeCLIJSON(t, raw, &store)
	if store.Version != 1 || store.Bindings == nil || len(store.Bindings) != 0 {
		t.Fatal("missing binding list is not an empty store")
	}
	if _, err = runCLIForTest(t, "show", "gh"); !errors.Is(err, clibinding.ErrBindingNotFound) {
		t.Fatal("show on a missing store did not report not found")
	}
	if _, err = runCLIForTest(t, "remove", "gh"); !errors.Is(err, clibinding.ErrBindingNotFound) {
		t.Fatal("remove on a missing store did not report not found")
	}

	corrupt := filepath.Join(dir, "corrupt.json")
	if err = os.WriteFile(corrupt, []byte(`{"version":1,"bindings":{`), 0600); err != nil {
		t.Fatal("corrupt fixture unavailable")
	}
	if _, err = runCLIForTest(t, "list", "--binding", corrupt); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("corrupt explicit binding accepted")
	}
	if _, err = runCLIForTest(t, "show", "gh", "--binding", corrupt); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("show on corrupt binding accepted")
	}

	if runtime.GOOS == "windows" {
		return
	}
	wide := filepath.Join(dir, "wide.json")
	if err = os.WriteFile(wide, []byte(`{"version":1,"bindings":{}}`), 0600); err != nil {
		t.Fatal("wide fixture unavailable")
	}
	if err = os.Chmod(wide, 0644); err != nil {
		t.Fatal("chmod unavailable")
	}
	if _, err = runCLIForTest(t, "list", "--binding", wide); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("group-readable binding accepted")
	}
}

func TestCLIUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"profiles", "extra"},
		{"list", "extra"},
		{"init"},
		{"init", "gh", "--unknown", "x"},
		{"show"},
		{"remove", "gh", "extra"},
		{"shell-init"},
		{"shell-init", "unknown"},
		{"run"},
	} {
		if _, err := runCLIForTest(t, args...); !errors.Is(err, cliUsage) {
			t.Errorf("args %v returned %v, want cliUsage", args, err)
		}
	}
}

func TestCLISubcommandHelpAndShellDiagnostics(t *testing.T) {
	dir := cliTestDir(t)
	missing := filepath.Join(dir, "never-created.json")
	t.Setenv("LOCKLARK_CLI_BINDING", missing)
	top, err := runCLIForTest(t, "--help")
	if err != nil || !strings.Contains(string(top), "usage: locklark cli") || !strings.Contains(string(top), "cli init|bind") {
		t.Fatalf("top-level cli help failed: %v %q", err, top)
	}
	for _, command := range []string{"profiles", "list", "init", "bind", "show", "remove", "shell-init", "run"} {
		raw, err := runCLIForTest(t, command, "--help")
		helpName := command
		if command == "bind" {
			helpName = "init|bind"
		}
		if err != nil || !strings.Contains(string(raw), "usage: locklark cli "+helpName) {
			t.Fatalf("%s help failed: %v %q", command, err, raw)
		}
		raw, err = runCLIForTest(t, command, "-h")
		if err != nil || !strings.Contains(string(raw), "usage: locklark cli "+helpName) {
			t.Fatalf("%s -h failed: %v %q", command, err, raw)
		}
	}
	if _, err = os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("subcommand help touched the binding path")
	}
	for _, args := range [][]string{{"unknown", "--help"}, {"init", "--help", "extra"}, {"--help", "extra"}} {
		if _, err := runCLIForTest(t, args...); !errors.Is(err, cliUsage) {
			t.Fatalf("invalid help invocation %v returned %v", args, err)
		}
	}
	_, err = runCLIForTest(t, "shell-init", "tcsh")
	if !errors.Is(err, cliUsage) || !strings.Contains(err.Error(), "bash, zsh, fish, powershell, pwsh") {
		t.Fatalf("unsupported shell diagnostic = %v", err)
	}
}

func writeCLIStoredBinding(t *testing.T, path, tool string, binding clibinding.ToolBinding) {
	t.Helper()
	store := clibinding.NewStore()
	store.Bindings[tool] = binding
	if err := clibinding.Save(path, store); err != nil {
		t.Fatal("store fixture unavailable:", err)
	}
}

func cliRunBinding(t *testing.T, tool, program, profile string, field string, slot string) (string, clibinding.ToolBinding) {
	t.Helper()
	path := filepath.Join(cliTestDir(t), "bindings.json")
	binding := clibinding.ToolBinding{
		Profile:        profile,
		VaultPath:      filepath.Join(cliTestDir(t), "owner.ll"),
		Program:        program,
		Targets:        []clibinding.SlotTarget{{Slot: slot, ID: cliTestID, Revision: cliTestRevision, Field: field}},
		HelperPath:     []string{filepath.Dir(program)},
		PassthroughEnv: []string{},
		TimeoutSeconds: 10,
	}
	if profile == "token" {
		binding.TokenEnvName = "LOCKLARK_TEST_TOKEN"
	}
	sum, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		t.Fatal("program digest unavailable")
	}
	binding.ProgramSHA256 = sum
	if err = binding.Validate(); err != nil {
		t.Fatal("binding fixture invalid:", err)
	}
	writeCLIStoredBinding(t, path, tool, binding)
	return path, binding
}

func TestCLIRunRecursionDenyAndTamper(t *testing.T) {
	original := cliTestExecutable(t)
	tamperedProgram := filepath.Join(cliTestDir(t), "tampered-tool")
	if runtime.GOOS == "windows" {
		tamperedProgram += ".exe"
	}
	rawProgram, err := os.ReadFile(original)
	if err != nil {
		t.Fatal("test executable unreadable")
	}
	if err = os.WriteFile(tamperedProgram, rawProgram, 0700); err != nil {
		t.Fatal("tampered program fixture unavailable")
	}
	bindingPath, _ := cliRunBinding(t, "gh", tamperedProgram, "gh", "password", "token")

	t.Setenv("LOCKLARK_CLI_ACTIVE", "outer")
	if _, err := runCLIForTest(t, "run", "gh", "--binding", bindingPath, "--", "--help"); !errors.Is(err, errCLIRecursion) {
		t.Fatal("recursive run was not refused first")
	}
	t.Setenv("LOCKLARK_CLI_ACTIVE", "")

	if _, err := runCLIForTest(t, "run", "gh", "--binding", bindingPath, "--", "auth", "login"); !errors.Is(err, cliUsage) {
		t.Fatal("denied arguments were not refused")
	}
	if _, err := runCLIForTest(t, "run", "missing", "--binding", bindingPath, "--", "--help"); !errors.Is(err, clibinding.ErrBindingNotFound) {
		t.Fatal("unknown tool was not reported")
	}
	if _, err := runCLIForTest(t, "run", "gh", "--binding", bindingPath, "--cwd", "/definitely/not/a/directory", "--", "--help"); !errors.Is(err, cliUsage) {
		t.Fatal("invalid cwd was accepted")
	}

	if err := os.WriteFile(tamperedProgram, []byte("tampered"), 0700); err != nil {
		t.Fatal("tamper fixture failed")
	}
	if _, err := runCLIForTest(t, "run", "gh", "--binding", bindingPath, "--", "--help"); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("tampered pinned program was accepted")
	}
}

func TestCLIRunFastPathAndExitStatus(t *testing.T) {
	program := cliTestExecutable(t)
	bindingPath, _ := cliRunBinding(t, "fasttool", program, "token", "password", "token")
	dir := cliTestDir(t)
	marker := filepath.Join(dir, "marker")
	parentHome := t.TempDir()
	parentConfig := filepath.Join(parentHome, ".deepseek")
	parentTmp := filepath.Join(parentHome, "tmp")
	for _, directory := range []string{parentConfig, parentTmp} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal("parent fixture unavailable")
		}
	}
	canary := "AmbientCanary" + strings.Repeat("z", 32)
	t.Setenv("HOME", parentHome)
	t.Setenv("XDG_CONFIG_HOME", parentConfig)
	t.Setenv("TMPDIR", parentTmp)
	t.Setenv("GH_TOKEN", canary)
	t.Setenv("DEEPSEEK_API_KEY", canary)
	t.Setenv("DEEPSEEK_STATE_DIR", filepath.Join(parentHome, "state"))
	t.Setenv("LOCKLARK_TEST_CLI_MARKER", marker)
	t.Setenv("LOCKLARK_TEST_CLI_EXIT", "")
	t.Setenv("LOCKLARK_CLI_ACTIVE", "")

	args := []string{"run", "fasttool", "--binding", bindingPath, "--",
		"-test.run=^TestCLIRunFastPathChild$", "help", marker, "", parentHome, parentConfig, parentTmp}
	if out, err := runCLIForTest(t, args...); err != nil || len(out) != 0 {
		t.Fatalf("fast path failed: %v %q", err, out)
	}
	raw, err := os.ReadFile(marker)
	if err != nil || string(raw) != "isolated" {
		t.Fatal("fast-path child did not receive an isolated credential-free environment")
	}

	if err = os.Remove(marker); err != nil {
		t.Fatal("marker cleanup failed")
	}
	exitArgs := append([]string(nil), args...)
	exitArgs[len(exitArgs)-4] = "7"
	if _, err = runCLIForTest(t, exitArgs...); err == nil {
		t.Fatal("fast-path child error was not propagated")
	} else {
		var child *childExitStatus
		if !errors.As(err, &child) || child.code != 7 {
			t.Fatalf("fast-path exit = %v, want status 7", err)
		}
	}
	if raw, err = os.ReadFile(marker); err != nil || string(raw) != "isolated" {
		t.Fatal("fast-path child did not run before propagating its exit status")
	}
}

func TestCLIRunFastPathChild(t *testing.T) {
	helpIndex := -1
	for i, arg := range os.Args {
		if arg == "help" {
			helpIndex = i
			break
		}
	}
	if helpIndex < 0 || len(os.Args) < helpIndex+6 {
		return
	}
	marker := os.Args[helpIndex+1]
	exitRaw := os.Args[helpIndex+2]
	parentHome := os.Args[helpIndex+3]
	parentConfig := os.Args[helpIndex+4]
	parentTmp := os.Args[helpIndex+5]
	if os.Getenv("LOCKLARK_CLI_ACTIVE") != "fasttool" {
		os.Exit(41)
	}
	for _, name := range []string{
		"GH_TOKEN", "DEEPSEEK_API_KEY", "DEEPSEEK_STATE_DIR",
		"LOCKLARK_TEST_CLI_MARKER", "LOCKLARK_TEST_CLI_EXIT", "AWS_SECRET_ACCESS_KEY",
	} {
		if os.Getenv(name) != "" {
			os.Exit(42)
		}
	}
	home := os.Getenv("HOME")
	if home == "" || home == parentHome {
		os.Exit(43)
	}
	for name, parent := range map[string]string{"HOME": parentHome, "XDG_CONFIG_HOME": parentConfig, "TMPDIR": parentTmp} {
		value := os.Getenv(name)
		if value == "" || value == parent {
			os.Exit(44)
		}
	}
	if filepath.Dir(home) != filepath.Dir(os.Getenv("XDG_CONFIG_HOME")) || filepath.Dir(home) != filepath.Dir(os.Getenv("TMPDIR")) {
		os.Exit(45)
	}
	if err := os.WriteFile(marker, []byte("isolated"), 0600); err != nil {
		os.Exit(46)
	}
	if exitRaw != "" {
		code, err := strconv.Atoi(exitRaw)
		if err != nil {
			os.Exit(47)
		}
		os.Exit(code)
	}
	os.Exit(0)
}

type failingCLIWriter struct{}

func (failingCLIWriter) Write([]byte) (int, error) {
	return 0, errors.New("untrusted output failure")
}

func TestConfirmRunBundleDisclosure(t *testing.T) {
	dir := cliTestDir(t)
	program := cliTestExecutable(t)
	spec := cliprofile.Spec{
		ID:             "disclosure-v1",
		Slots:          []cliprofile.Slot{{Name: "kubeconfig", Kind: "document", Field: cliprofile.FieldAttachment}},
		Env:            map[string]string{"KUBECONFIG": "file:kube/config"},
		Files:          []cliprofile.FileSpec{{RelPath: "kube/config", Format: "raw-slot:kubeconfig", Mode: 0600}},
		PassthroughEnv: []string{"NO_COLOR"},
		MaxTimeout:     60,
	}
	binding := clibinding.ToolBinding{
		Profile:       "kubectl",
		VaultPath:     filepath.Join(dir, "owner.ll"),
		Program:       program,
		ProgramSHA256: strings.Repeat("a", 64),
		Targets:       []clibinding.SlotTarget{{Slot: "kubeconfig", ID: cliTestID, Revision: cliTestRevision, Field: "attachment"}},
		HelperPath:    []string{filepath.Dir(program)},
	}
	targets := []personal.BundleTarget{{Slot: "kubeconfig", ID: cliTestID, Revision: cliTestRevision, Field: "attachment"}}
	request := personal.RunBundleRequest{
		Program: program, Args: []string{"--help", "$(touch /tmp/pwned)", "\x1b[31mred"},
		Directory: dir, TimeoutSeconds: 30, HelperPath: binding.HelperPath,
		Passthrough: map[string]string{"NO_COLOR": "1"}, Spec: spec,
	}
	var prompt bytes.Buffer
	c := console{reader: bufio.NewReader(strings.NewReader("RUN\n")), writer: &prompt}
	if err := confirmRunBundle(&c, "kube", binding, targets, request); err != nil {
		t.Fatal("confirmation failed:", err)
	}
	text := prompt.String()
	for _, needle := range []string{
		"kube", "kubectl", binding.VaultPath, program, binding.ProgramSHA256, dir, "30 秒",
		"kubeconfig", cliTestID, cliTestRevision, "attachment", "KUBECONFIG",
		"kube/config", "NO_COLOR", filepath.Dir(program), "$(touch /tmp/pwned)",
		"输入 RUN 确认本次可信命令披露",
	} {
		quoted := strings.Trim(strconv.Quote(needle), `"`)
		if !strings.Contains(text, quoted) {
			t.Fatalf("disclosure omits %q: %s", needle, text)
		}
	}
	if strings.ContainsRune(text, '\x1b') {
		t.Fatal("disclosure emitted a raw terminal escape")
	}
	if !strings.Contains(text, `\x1b[31mred`) {
		t.Fatal("argument was not rendered as an escaped literal")
	}

	refuse := console{reader: bufio.NewReader(strings.NewReader("NO\n")), writer: &bytes.Buffer{}}
	if err := confirmRunBundle(&refuse, "kube", binding, targets, request); err == nil {
		t.Fatal("non-RUN consent accepted")
	}
	broken := console{reader: bufio.NewReader(strings.NewReader("RUN\n")), writer: failingCLIWriter{}}
	if err := confirmRunBundle(&broken, "kube", binding, targets, request); err == nil {
		t.Fatal("disclosure write failure ignored")
	}
}

func TestShellInitQuotesBindingPaths(t *testing.T) {
	dir := cliTestDir(t)
	path := filepath.Join(dir, "bind'quote.json")
	for shell, want := range map[string]string{
		"bash": strings.ReplaceAll(path, "'", "'\\''"),
		"fish": strings.ReplaceAll(path, "'", "\\'"),
		"pwsh": strings.ReplaceAll(path, "'", "''"),
	} {
		raw, err := runCLIForTest(t, "shell-init", "--shell", shell, "--binding", path, "--tools", "gh")
		if err != nil {
			t.Fatalf("shell-init %s failed: %v", shell, err)
		}
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%s quoting did not preserve %q: %s", shell, path, raw)
		}
	}
}

func TestResolveCLIRunToolProfileFlag(t *testing.T) {
	values := map[string]string{"profile": "gh"}
	tool, profile, child, err := resolveCLIRunTool(values, []string{"pr", "list"}, false)
	if err != nil || tool != "gh" || profile != "gh" || !reflect.DeepEqual(child, []string{"pr", "list"}) {
		t.Fatalf("profile-only run resolution = %q %q %v %v", tool, profile, child, err)
	}
	if _, _, _, err = resolveCLIRunTool(values, []string{"pr"}, true); !errors.Is(err, cliUsage) {
		t.Fatal("positional child before -- accepted with profile flag")
	}
	values = map[string]string{"tool": "gh", "profile": "docker"}
	if _, _, _, err = resolveCLIRunTool(values, nil, true); !errors.Is(err, cliUsage) {
		t.Fatal("conflicting tool/profile accepted")
	}
	values = map[string]string{"tool": "gh"}
	tool, profile, child, err = resolveCLIRunTool(values, []string{"pr"}, false)
	if err != nil || tool != "gh" || profile != "gh" || !reflect.DeepEqual(child, []string{"pr"}) {
		t.Fatalf("tool flag run resolution = %q %q %v %v", tool, profile, child, err)
	}
}
