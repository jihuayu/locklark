package personal

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/clibinding"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/vault"
)

// TestRunBundlePinChild is the owned synthetic child used by the real
// execution-pin test. It is this test binary, copied to a private temporary
// path, and only acts when invoked with the pin-child marker arguments.
func TestRunBundlePinChild(t *testing.T) {
	marker, code := "", 0
	for i, arg := range os.Args {
		if arg == "pin-child" && i+2 < len(os.Args) {
			marker = os.Args[i+1]
			code, _ = strconv.Atoi(os.Args[i+2])
			break
		}
	}
	if marker == "" {
		return
	}
	if os.Getenv("GH_TOKEN") != bundleTestPassword {
		os.Exit(70)
	}
	if os.Getenv("LOCKLARK_CLI_ACTIVE") != "" {
		os.Exit(71)
	}
	if err := os.WriteFile(marker, []byte("started"), 0600); err != nil {
		os.Exit(72)
	}
	if _, err := os.Stdout.WriteString("pin-child-ok\n"); err != nil {
		os.Exit(73)
	}
	os.Exit(code)
}

func pinTestSpec() cliprofile.Spec {
	return cliprofile.Spec{
		ID: "run-bundle-pin-test-v1",
		Slots: []cliprofile.Slot{
			{Name: "token", Kind: "login", Field: cliprofile.FieldPassword, RequireNonBlank: true},
		},
		Env:        map[string]string{"GH_TOKEN": "slot:token"},
		Files:      []cliprofile.FileSpec{{RelPath: "token/secret", Format: "raw-slot:token", Mode: 0600}},
		MaxTimeout: 60,
	}
}

func copyPinChildProgram(t *testing.T) (string, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal("test executable unreadable")
	}
	name := "pin-child"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	program := filepath.Join(t.TempDir(), name)
	if err = os.WriteFile(program, raw, 0700); err != nil {
		t.Fatal("synthetic child unavailable")
	}
	if err = os.Chmod(program, 0700); err != nil {
		t.Fatal("synthetic child mode unavailable")
	}
	sum, err := clibinding.ComputeProgramSHA256(program)
	if err != nil {
		t.Fatal("synthetic child digest unavailable")
	}
	return program, sum
}

func appendPinProgramBytes(t *testing.T, program string) {
	t.Helper()
	file, err := os.OpenFile(program, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal("synthetic child not writable")
	}
	if _, err = file.Write([]byte("\nprogram-bytes-changed-during-preparation\n")); err != nil {
		file.Close()
		t.Fatal("synthetic child bytes unchanged")
	}
	if err = file.Close(); err != nil {
		t.Fatal("synthetic child close failed")
	}
	changed, err := clibinding.ComputeProgramSHA256(program)
	if err != nil || changed == "" {
		t.Fatal("changed synthetic child digest unavailable")
	}
}

// TestRunBundlePinRealChild is the minimum real execution test: this test
// binary is copied to an owned private path and run through the production
// RunBundle lifecycle. Preparation changes the copied program bytes after the
// signed intent and before executeRunBundle. A pinned mismatch must refuse
// before any credential file is written and before the child starts; an
// unchanged matching pin must preserve normal stdout, exit status and cleanup.
func TestRunBundlePinRealChild(t *testing.T) {
	for _, test := range []struct {
		name     string
		mutate   bool
		wantCode int
	}{
		{name: "mismatch-refused-before-write-or-start", mutate: true},
		{name: "matching-pin-runs-normal-child", mutate: false, wantCode: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newBundleTestFixture(t)
			program, sum := copyPinChildProgram(t)
			targets := []BundleTarget{{Slot: "token", ID: f.loginID, Revision: f.loginRevision, Field: "password"}}
			marker := filepath.Join(t.TempDir(), "child-started")
			request := RunBundleRequest{
				Program:        program,
				ProgramSHA256:  sum,
				Args:           []string{"-test.run=^TestRunBundlePinChild$", "--", "pin-child", marker, strconv.Itoa(test.wantCode)},
				Directory:      t.TempDir(),
				TimeoutSeconds: 15,
				HelperPath:     []string{filepath.Dir(program)},
				Spec:           pinTestSpec(),
			}
			if err := request.Validate(targets); err != nil {
				t.Fatal("pin request fixture invalid:", err)
			}
			create, roots := testBundleTempCreatorTracked(t)
			input, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal("stdin unavailable")
			}
			defer input.Close()
			output, err := os.OpenFile(filepath.Join(t.TempDir(), "stdout"), os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				t.Fatal("stdout unavailable")
			}
			defer output.Close()
			root := ""
			receipt, runErr := runBundle(context.Background(), targets, request, create, func(s *runBundleStoreRequest) (result, error) {
				root = s.root
				prepared, err := command(f.path, "fixture", f.key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: s})
				if err == nil && test.mutate {
					// Exactly the replacement window this checkpoint closes:
					// after the signed intent, during preparation, before the
					// late pin recheck at executeRunBundle.
					appendPinProgramBytes(t, program)
				}
				return prepared, err
			}, func(ctx context.Context, req RunBundleRequest, gotRoot string, rendered cliprofile.RenderedBundle) (int, error) {
				if gotRoot != root {
					t.Error("execution root changed")
				}
				code, executeErr := executeRunBundle(ctx, req, gotRoot, rendered, runCLIStreams{input, output, output})
				credentialPath := filepath.Join(gotRoot, "token", "secret")
				if test.mutate {
					if _, statErr := os.Stat(credentialPath); !os.IsNotExist(statErr) {
						t.Fatalf("mismatch wrote a rendered credential file: %v", statErr)
					}
					if executeErr == nil {
						t.Fatal("mismatch was not refused")
					}
					if err := filepath.WalkDir(gotRoot, func(path string, entry os.DirEntry, walkErr error) error {
						if walkErr != nil {
							return walkErr
						}
						if !entry.IsDir() {
							t.Errorf("mismatch left a file before refusal: %s", path)
						}
						return nil
					}); err != nil {
						t.Fatalf("refused run root unreadable: %v", err)
					}
				} else {
					raw, readErr := os.ReadFile(credentialPath)
					if readErr != nil || string(raw) != bundleTestPassword {
						t.Fatalf("matching pin did not preserve rendered credential: %v", readErr)
					}
					if executeErr != nil || code != test.wantCode {
						t.Fatalf("matching pin execution: code=%d error=%v", code, executeErr)
					}
				}
				return code, executeErr
			}, os.RemoveAll)
			if test.mutate {
				if !errors.Is(runErr, ErrRunCredential) {
					t.Fatalf("mismatch refusal = %v, want fixed ErrRunCredential", runErr)
				}
				if receipt != (RunReceipt{}) {
					t.Fatalf("mismatch returned a receipt: %#v", receipt)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("mismatch started the child")
				}
				if outputInfo, err := output.Stat(); err != nil || outputInfo.Size() != 0 {
					t.Fatalf("mismatch produced child output: %v size=%d", err, outputInfo.Size())
				}
			} else {
				if runErr != nil {
					t.Fatalf("matching pin run failed: %v", runErr)
				}
				if receipt.ExitCode != test.wantCode || receipt.Status != "process-exited" || receipt.Intent == "" {
					t.Fatalf("matching pin receipt changed: %#v", receipt)
				}
				if _, err := os.Stat(marker); err != nil {
					t.Fatal("matching pin did not start the child")
				}
				raw, err := os.ReadFile(output.Name())
				if err != nil || !strings.Contains(string(raw), "pin-child-ok") {
					t.Fatalf("matching pin stdout changed: %q %v", raw, err)
				}
			}
			for _, created := range roots() {
				if _, err := os.Stat(created); !os.IsNotExist(err) {
					t.Fatalf("run root survived cleanup: %s", created)
				}
			}
		})
	}
}

func TestRunBundleRequestPinShape(t *testing.T) {
	f := newBundleTestFixture(t)
	targets := []BundleTarget{{Slot: "token", ID: f.loginID, Revision: f.loginRevision, Field: "password"}}
	program := filepath.Join(t.TempDir(), "pin-shape-program")
	if runtime.GOOS == "windows" {
		program += ".exe"
	}
	request := RunBundleRequest{
		Program:        program,
		Args:           []string{"--version"},
		Directory:      t.TempDir(),
		TimeoutSeconds: 10,
		HelperPath:     []string{t.TempDir()},
		Spec:           pinTestSpec(),
	}
	for _, pin := range []string{"", strings.Repeat("0", 64), strings.Repeat("abcdef01", 8)} {
		copy := request
		copy.ProgramSHA256 = pin
		if err := copy.Validate(targets); err != nil {
			t.Fatalf("valid pin %q refused: %v", pin, err)
		}
	}
	for _, pin := range []string{
		strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("g", 64), "0x" + strings.Repeat("a", 62), " " + strings.Repeat("a", 63),
	} {
		copy := request
		copy.ProgramSHA256 = pin
		if err := copy.Validate(targets); !errors.Is(err, ErrRunTarget) {
			t.Fatalf("invalid pin %q accepted: %v", pin, err)
		}
	}
}

func TestRunBundlePinBinding(t *testing.T) {
	f := newBundleTestFixture(t)
	program, sum := copyPinChildProgram(t)
	targets := []BundleTarget{{Slot: "token", ID: f.loginID, Revision: f.loginRevision, Field: "password"}}
	root := t.TempDir()
	request := RunBundleRequest{
		Program:        program,
		Args:           []string{"--version"},
		Directory:      root,
		TimeoutSeconds: 10,
		HelperPath:     []string{filepath.Dir(program)},
		Spec:           pinTestSpec(),
	}
	store := &runBundleStoreRequest{targets: targets, request: request, root: root}
	secret := []byte("pin-binding-secret")
	unpinned, err := store.binding(secret)
	if err != nil {
		t.Fatal("unpinned binding failed")
	}

	// The pre-pin canonical object, byte for byte. The empty pin must omit its
	// field so existing unpinned signed bytes and digests do not change.
	key, err := hkdf.Key(sha256.New, secret, nil, "locklark/personal/run-bundle/key/v1", 32)
	if err != nil {
		t.Fatal("binding key unavailable")
	}
	defer clear(key)
	raw, err := json.Marshal(struct {
		Profile, Platform, Stdio, Environment, TemporaryRoot string
		HelperPath                                           []string
		Targets                                              []BundleTarget
		Passthrough                                          map[string]string
		TokenEnvName                                         string
		Spec                                                 cliprofile.Spec
		Program                                              string
		Args                                                 []string
		Directory                                            string
		TimeoutSeconds                                       int
	}{
		Profile: "bundle-inherited-stdio-v1", Platform: runtime.GOOS, Stdio: "inherit-os-stdin-stdout-stderr-no-capture",
		Environment: "os-systemroot-only+bundle-spec+explicit-path+isolated-home-gh-xdg-temp-v1", TemporaryRoot: root,
		HelperPath: request.HelperPath, Targets: targets, Passthrough: request.Passthrough,
		TokenEnvName: request.TokenEnvName, Spec: request.Spec, Program: request.Program,
		Args: request.Args, Directory: request.Directory, TimeoutSeconds: request.TimeoutSeconds,
	})
	if err != nil {
		t.Fatal("canonical unpinned bytes unavailable")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	wantUnpinned := hex.EncodeToString(mac.Sum(nil))
	if unpinned != wantUnpinned {
		t.Fatal("empty program pin changed the existing unpinned signed bytes")
	}

	pinnedStore := &runBundleStoreRequest{targets: targets, request: cloneBundleRequest(request), root: root}
	pinnedStore.request.ProgramSHA256 = sum
	pinned, err := pinnedStore.binding(secret)
	if err != nil || pinned == unpinned {
		t.Fatalf("program pin not bound: %v", err)
	}
	otherStore := &runBundleStoreRequest{targets: targets, request: cloneBundleRequest(request), root: root}
	otherStore.request.ProgramSHA256 = strings.Repeat("a", 64)
	other, err := otherStore.binding(secret)
	if err != nil || other == pinned || other == unpinned {
		t.Fatalf("distinct program pin not bound: %v", err)
	}
}
