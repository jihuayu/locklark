package clibinding_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/clibinding"
)

const (
	testID       = "0123456789abcdef0123456789abcdef"
	testRevision = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func testProgram(t *testing.T) string {
	t.Helper()
	name := "tool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal("program fixture unavailable")
	}
	return path
}

func testVaultPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "owner.ll")
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private directory unavailable")
	}
	return dir
}

func validGHBinding(t *testing.T) clibinding.ToolBinding {
	t.Helper()
	program := testProgram(t)
	sum, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		t.Fatal("program digest unavailable")
	}
	return clibinding.ToolBinding{
		Profile:        "gh",
		VaultPath:      testVaultPath(t),
		Program:        program,
		ProgramSHA256:  sum,
		Targets:        []clibinding.SlotTarget{{Slot: "token", ID: testID, Revision: testRevision, Field: "password"}},
		HelperPath:     []string{filepath.Dir(program)},
		PassthroughEnv: []string{"GH_HOST"},
		TimeoutSeconds: 60,
	}
}

func validTokenBinding(t *testing.T) clibinding.ToolBinding {
	t.Helper()
	binding := validGHBinding(t)
	binding.Profile = "token"
	binding.PassthroughEnv = nil
	binding.TokenEnvName = "MY_ACCESS_TOKEN"
	return binding
}

func cloneBinding(binding clibinding.ToolBinding) clibinding.ToolBinding {
	out := binding
	out.Targets = append([]clibinding.SlotTarget(nil), binding.Targets...)
	out.HelperPath = append([]string(nil), binding.HelperPath...)
	out.PassthroughEnv = append([]string(nil), binding.PassthroughEnv...)
	return out
}

func TestNewStoreAndDefaultPath(t *testing.T) {
	store := clibinding.NewStore()
	if store.Version != clibinding.SchemaVersion || store.Bindings == nil || len(store.Bindings) != 0 {
		t.Fatal("new store is not empty at the current schema version")
	}
	absolute := filepath.Join(t.TempDir(), "absolute.json")
	t.Setenv("LOCKLARK_CLI_BINDING", absolute+string(filepath.Separator)+"."+string(filepath.Separator))
	path, err := clibinding.DefaultPath()
	if err != nil || path != filepath.Clean(absolute) {
		t.Fatalf("absolute environment binding not honored: %q %v", path, err)
	}
	t.Setenv("LOCKLARK_CLI_BINDING", "relative.json")
	path, err = clibinding.DefaultPath()
	if err != nil {
		t.Fatal("default path unavailable")
	}
	wd, err := os.Getwd()
	if err != nil || path != filepath.Join(wd, clibinding.DefaultFileName) {
		t.Fatalf("relative environment binding must be ignored: %q", path)
	}
	t.Setenv("LOCKLARK_CLI_BINDING", "")
	path, err = clibinding.DefaultPath()
	if err != nil || path != filepath.Join(wd, clibinding.DefaultFileName) {
		t.Fatalf("working-directory binding path wrong: %q", path)
	}
}

func TestToolBindingValidate(t *testing.T) {
	valid := []clibinding.ToolBinding{validGHBinding(t), validTokenBinding(t)}
	aws := validGHBinding(t)
	aws.Profile = "aws"
	aws.Targets = []clibinding.SlotTarget{
		{Slot: "access_key_id", ID: testID, Revision: testRevision, Field: "username"},
		{Slot: "secret_access_key", ID: testID, Revision: testRevision, Field: "password"},
	}
	aws.PassthroughEnv = []string{"AWS_REGION"}
	aws.TimeoutSeconds = 3600
	valid = append(valid, aws)
	kubectl := validGHBinding(t)
	kubectl.Profile = "kubectl"
	kubectl.Targets = []clibinding.SlotTarget{{Slot: "kubeconfig", ID: testID, Revision: testRevision, Field: "attachment"}}
	kubectl.PassthroughEnv = nil
	kubectl.TimeoutSeconds = 28800
	valid = append(valid, kubectl)
	for i, binding := range valid {
		if err := binding.Validate(); err != nil {
			t.Fatalf("valid binding %d refused: %v", i, err)
		}
	}

	base := validGHBinding(t)
	dir := filepath.Dir(base.Program)
	longPath := "/" + strings.Repeat("a", 4096)
	cases := map[string]func(*clibinding.ToolBinding){
		"unknown profile":       func(b *clibinding.ToolBinding) { b.Profile = "unknown" },
		"empty vault":           func(b *clibinding.ToolBinding) { b.VaultPath = "" },
		"relative vault":        func(b *clibinding.ToolBinding) { b.VaultPath = "owner.ll" },
		"unclean vault":         func(b *clibinding.ToolBinding) { b.VaultPath = dir + "/x/../vault.ll" },
		"nul vault":             func(b *clibinding.ToolBinding) { b.VaultPath = dir + "/vault\x00.ll" },
		"newline vault":         func(b *clibinding.ToolBinding) { b.VaultPath = dir + "/vault\n.ll" },
		"invalid utf8 vault":    func(b *clibinding.ToolBinding) { b.VaultPath = dir + "/vault\xff.ll" },
		"long vault":            func(b *clibinding.ToolBinding) { b.VaultPath = longPath },
		"empty program":         func(b *clibinding.ToolBinding) { b.Program = "" },
		"relative program":      func(b *clibinding.ToolBinding) { b.Program = "tool" },
		"unclean program":       func(b *clibinding.ToolBinding) { b.Program = dir + "/x/../tool" },
		"uppercase digest":      func(b *clibinding.ToolBinding) { b.ProgramSHA256 = strings.Repeat("A", 64) },
		"short digest":          func(b *clibinding.ToolBinding) { b.ProgramSHA256 = strings.Repeat("a", 63) },
		"nil targets":           func(b *clibinding.ToolBinding) { b.Targets = nil },
		"too many targets":      func(b *clibinding.ToolBinding) { b.Targets = append(b.Targets, b.Targets[0]) },
		"unknown slot":          func(b *clibinding.ToolBinding) { b.Targets[0].Slot = "unknown" },
		"duplicate slot":        func(b *clibinding.ToolBinding) { b.Targets = append(b.Targets, b.Targets[0]) },
		"missing required slot": func(b *clibinding.ToolBinding) { b.Targets = nil },
		"uppercase target id":   func(b *clibinding.ToolBinding) { b.Targets[0].ID = strings.Repeat("A", 32) },
		"short target id":       func(b *clibinding.ToolBinding) { b.Targets[0].ID = strings.Repeat("1", 31) },
		"uppercase revision":    func(b *clibinding.ToolBinding) { b.Targets[0].Revision = strings.Repeat("A", 64) },
		"short revision":        func(b *clibinding.ToolBinding) { b.Targets[0].Revision = strings.Repeat("a", 63) },
		"wrong target field":    func(b *clibinding.ToolBinding) { b.Targets[0].Field = "username" },
		"too many helper paths": func(b *clibinding.ToolBinding) { b.HelperPath = make([]string, 17) },
		"empty helper path":     func(b *clibinding.ToolBinding) { b.HelperPath = []string{""} },
		"relative helper path":  func(b *clibinding.ToolBinding) { b.HelperPath = []string{"relative"} },
		"unclean helper path":   func(b *clibinding.ToolBinding) { b.HelperPath = []string{dir + "/x/.."} },
		"nul helper path":       func(b *clibinding.ToolBinding) { b.HelperPath = []string{dir + "/x\x00"} },
		"newline helper path":   func(b *clibinding.ToolBinding) { b.HelperPath = []string{dir + "/x\n"} },
		"separator helper path": func(b *clibinding.ToolBinding) {
			b.HelperPath = []string{dir + "/x" + string(os.PathListSeparator) + "y"}
		},
		"too many passthrough":   func(b *clibinding.ToolBinding) { b.PassthroughEnv = make([]string, 33) },
		"duplicate passthrough":  func(b *clibinding.ToolBinding) { b.PassthroughEnv = []string{"GH_HOST", "GH_HOST"} },
		"disallowed passthrough": func(b *clibinding.ToolBinding) { b.PassthroughEnv = []string{"AWS_REGION"} },
		"dangerous passthrough":  func(b *clibinding.ToolBinding) { b.PassthroughEnv = []string{"PATH"} },
		"negative timeout":       func(b *clibinding.ToolBinding) { b.TimeoutSeconds = -1 },
		"timeout over profile":   func(b *clibinding.ToolBinding) { b.TimeoutSeconds = 301 },
		"token env on static":    func(b *clibinding.ToolBinding) { b.TokenEnvName = "MY_TOKEN" },
	}
	for name, mutate := range cases {
		binding := cloneBinding(base)
		mutate(&binding)
		if err := binding.Validate(); !errors.Is(err, clibinding.ErrBinding) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	for name, binding := range map[string]clibinding.ToolBinding{
		"token env empty":       func() clibinding.ToolBinding { b := validTokenBinding(t); b.TokenEnvName = ""; return b }(),
		"token env lowercase":   func() clibinding.ToolBinding { b := validTokenBinding(t); b.TokenEnvName = "my_token"; return b }(),
		"token env not bearer":  func() clibinding.ToolBinding { b := validTokenBinding(t); b.TokenEnvName = "MY_SECRET"; return b }(),
		"token env system root": func() clibinding.ToolBinding { b := validTokenBinding(t); b.TokenEnvName = "SYSTEMROOT"; return b }(),
	} {
		if err := binding.Validate(); !errors.Is(err, clibinding.ErrBinding) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	zeroTimeout := cloneBinding(base)
	zeroTimeout.TimeoutSeconds = 0
	if err := zeroTimeout.Validate(); err != nil {
		t.Fatal("an omitted timeout must be accepted")
	}
	noPin := cloneBinding(base)
	noPin.ProgramSHA256 = ""
	if err := noPin.Validate(); err != nil {
		t.Fatal("an omitted executable pin must be accepted")
	}
}

func TestStoreValidate(t *testing.T) {
	if err := clibinding.NewStore().Validate(); err != nil {
		t.Fatal("empty store refused")
	}
	base := clibinding.NewStore()
	base.Bindings["gh"] = validGHBinding(t)
	if err := base.Validate(); err != nil {
		t.Fatal("valid store refused")
	}
	for name, store := range map[string]clibinding.Store{
		"zero version": {Version: 0, Bindings: map[string]clibinding.ToolBinding{}},
		"future":       {Version: 2, Bindings: map[string]clibinding.ToolBinding{}},
	} {
		if err := store.Validate(); !errors.Is(err, clibinding.ErrBinding) {
			t.Errorf("%s store accepted", name)
		}
	}
	bad := clibinding.NewStore()
	bad.Bindings["Gh"] = validGHBinding(t)
	if err := bad.Validate(); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("invalid tool name accepted")
	}
	for _, tool := range []string{"", "-gh", "gh.tool", strings.Repeat("a", 65)} {
		store := clibinding.NewStore()
		store.Bindings[tool] = validGHBinding(t)
		if err := store.Validate(); !errors.Is(err, clibinding.ErrBinding) {
			t.Errorf("tool name %q accepted", tool)
		}
	}
	tooMany := clibinding.NewStore()
	for i := 0; i < 65; i++ {
		tooMany.Bindings["tool"+string(rune('a'+i))] = validGHBinding(t)
	}
	if err := tooMany.Validate(); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("store over the binding limit accepted")
	}
	if err := base.Validate(); err != nil {
		t.Fatal("valid store changed by a separate validation")
	}
}

func TestComputeAndVerifyProgram(t *testing.T) {
	binding := validGHBinding(t)
	program := binding.Program
	raw, err := os.ReadFile(program)
	if err != nil {
		t.Fatal("program unreadable")
	}
	want := sha256.Sum256(raw)
	sum, err := clibinding.ComputeProgramSHA256(program)
	if err != nil || sum != hex.EncodeToString(want[:]) {
		t.Fatalf("program digest mismatch: %q %v", sum, err)
	}
	if _, err = clibinding.ComputeProgramSHA256("relative"); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("relative program hash accepted")
	}
	if _, err = clibinding.ComputeProgramSHA256(t.TempDir()); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("directory program hash accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err = clibinding.ComputeProgramSHA256(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing program hash did not report not-exist")
	}

	if err = clibinding.VerifyProgram(binding); err != nil {
		t.Fatal("pinned program refused")
	}
	if err = os.WriteFile(program, []byte("different"), 0700); err != nil {
		t.Fatal("program fixture update failed")
	}
	if err = clibinding.VerifyProgram(binding); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("tampered pinned program accepted")
	}
	unpinned := cloneBinding(binding)
	unpinned.ProgramSHA256 = ""
	if err = clibinding.VerifyProgram(unpinned); err != nil {
		t.Fatal("unpinned regular program refused")
	}
	unpinned.Program = "relative"
	if err = clibinding.VerifyProgram(unpinned); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("invalid unpinned binding accepted")
	}
}

func saveTestStore(t *testing.T, path string) clibinding.Store {
	t.Helper()
	store := clibinding.NewStore()
	store.Bindings["gh"] = validGHBinding(t)
	if err := clibinding.Save(path, store); err != nil {
		t.Fatal("save fixture failed:", err)
	}
	return store
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(privateDir(t), clibinding.DefaultFileName)
	store := saveTestStore(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("binding file missing")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("binding file mode is %04o, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("binding file unreadable")
	}
	if !bytes.Contains(raw, []byte("  \"version\": 1,")) || !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("binding file is not canonical indented JSON")
	}
	loaded, err := clibinding.Load(path)
	if err != nil {
		t.Fatal("load failed:", err)
	}
	if !reflect.DeepEqual(loaded, store) {
		t.Fatal("binding round trip changed the store")
	}
	for _, secret := range []string{"password-value", "hunter2"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("binding file contains a secret value")
		}
	}

	// A version-zero in-memory store is written at the current version.
	freshPath := filepath.Join(privateDir(t), "fresh.json")
	zero := clibinding.NewStore()
	zero.Version = 0
	if err = clibinding.Save(freshPath, zero); err != nil {
		t.Fatal("version-zero save failed:", err)
	}
	loaded, err = clibinding.Load(freshPath)
	if err != nil || loaded.Version != clibinding.SchemaVersion || loaded.Bindings == nil {
		t.Fatal("version-zero store did not load as a current empty store")
	}

	nullPath := filepath.Join(privateDir(t), "null.json")
	if err = os.WriteFile(nullPath, []byte(`{"version":1,"bindings":null}`+"\n"), 0600); err != nil {
		t.Fatal("null fixture unavailable")
	}
	loaded, err = clibinding.Load(nullPath)
	if err != nil || loaded.Bindings == nil {
		t.Fatal("null bindings were not normalized")
	}
}

func TestSaveLoadRejectUnsafeInput(t *testing.T) {
	dir := privateDir(t)
	unclean := dir + string(filepath.Separator) + "sub" + string(filepath.Separator) + ".." + string(filepath.Separator) + "x.json"
	invalidPaths := []string{"relative.json", unclean, filepath.Join(dir, "x\x00.json"), ""}
	for _, path := range invalidPaths {
		if _, err := clibinding.Load(path); !errors.Is(err, clibinding.ErrBinding) {
			t.Errorf("load path %q accepted", path)
		}
		if err := clibinding.Save(path, clibinding.NewStore()); !errors.Is(err, clibinding.ErrBinding) {
			t.Errorf("save path %q accepted", path)
		}
	}
	missing := filepath.Join(dir, "missing.json")
	if _, err := clibinding.Load(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing binding did not report not-exist")
	}

	path := filepath.Join(dir, "binding.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"bindings":{},"extra":true}`), 0600); err != nil {
		t.Fatal("fixture unavailable")
	}
	if _, err := clibinding.Load(path); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("unknown JSON field accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"bindings":{}}{"version":1,"bindings":{}}`), 0600); err != nil {
		t.Fatal("fixture unavailable")
	}
	if _, err := clibinding.Load(path); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("trailing JSON document accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"bindings":{}}`), 0600); err != nil {
		t.Fatal("fixture unavailable")
	}
	if _, err := clibinding.Load(path); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("future schema accepted")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), (64<<10)+1), 0600); err != nil {
		t.Fatal("fixture unavailable")
	}
	if _, err := clibinding.Load(path); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("oversized binding accepted")
	}
	if err := clibinding.Save(path, clibinding.NewStore()); err != nil {
		t.Fatalf("overwriting an oversized binding failed: %v", err)
	}
	if _, err := clibinding.Load(path); err != nil {
		t.Fatal("overwritten binding unreadable:", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"bindings":{}}`), 0600); err != nil {
		t.Fatal("fixture unavailable")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal("chmod unavailable")
	}
	if _, err := clibinding.Load(path); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("group-readable binding accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal("chmod unavailable")
	}

	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := clibinding.Load(link); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("symlinked binding accepted")
	}
	if err := clibinding.Save(link, clibinding.NewStore()); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("symlinked binding overwritten")
	}

	writeDir := filepath.Join(dir, "writable")
	if err := os.Mkdir(writeDir, 0700); err != nil {
		t.Fatal("directory unavailable")
	}
	if err := os.Chmod(writeDir, 0777); err != nil {
		t.Fatal("chmod unavailable")
	}
	if err := clibinding.Save(filepath.Join(writeDir, "binding.json"), clibinding.NewStore()); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("writable parent accepted")
	}
}

func TestSaveLimits(t *testing.T) {
	dir := privateDir(t)
	store := clibinding.NewStore()
	for i := 0; i < 65; i++ {
		store.Bindings["tool"+string(rune('a'+i))] = validGHBinding(t)
	}
	if err := clibinding.Save(filepath.Join(dir, "too-many.json"), store); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("store over the binding limit saved")
	}
	tooBig := clibinding.NewStore()
	binding := validGHBinding(t)
	binding.HelperPath = make([]string, 16)
	for i := range binding.HelperPath {
		binding.HelperPath[i] = filepath.Join("/", strings.Repeat(string(rune('a'+i)), 4094))
	}
	tooBig.Bindings["gh"] = binding
	if err := clibinding.Save(filepath.Join(dir, "too-big.json"), tooBig); !errors.Is(err, clibinding.ErrBinding) {
		t.Fatal("oversized binding saved")
	}
}

func TestLoadRejectsCorruptJSON(t *testing.T) {
	path := filepath.Join(privateDir(t), "binding.json")
	for _, raw := range []string{`{`, `[]`, `null`, `{"version":1,"bindings":[]}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal("fixture unavailable")
		}
		if _, err := clibinding.Load(path); !errors.Is(err, clibinding.ErrBinding) {
			t.Errorf("corrupt JSON %q accepted", raw)
		}
	}
}

func TestStoreJSONShape(t *testing.T) {
	raw, err := json.Marshal(clibinding.NewStore())
	if err != nil {
		t.Fatal("store encoding failed")
	}
	if string(raw) != `{"version":1,"bindings":{}}` {
		t.Fatalf("unexpected empty store JSON: %s", raw)
	}
}
