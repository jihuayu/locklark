package personal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/vault"
)

const (
	bundleTestUsername   = "deploy-user"
	bundleTestPassword   = "s3cret"
	bundleTestAttachment = "apiVersion: v1\nkind: Config\nclusters: []\n"
	bundleAskpassScript  = "#!/bin/sh\ncase \"$1\" in\n*Username*|*username*) sed -n '1p' \"$LOCKLARK_GIT_SECRET_FILE\" ;;\n*) sed -n '2p' \"$LOCKLARK_GIT_SECRET_FILE\" ;;\nesac\n"
)

type bundleTestFixture struct {
	path             string
	key              []byte
	loginID          string
	loginRevision    string
	documentID       string
	documentRevision string
}

func newBundleTestFixture(t *testing.T) *bundleTestFixture {
	t.Helper()
	f := &bundleTestFixture{path: filepath.Join(t.TempDir(), "owner.ll"), key: bytes.Repeat([]byte{5}, 16)}
	if err := Create(f.path, "fixture", f.key); err != nil {
		t.Fatal("create vault", err)
	}
	if _, err := AddLogin(f.path, "fixture", f.key, "bundle login", bundleTestUsername, bundleTestPassword); err != nil {
		t.Fatal("add login", err)
	}
	if _, err := AddDocument(f.path, "fixture", f.key, "bundle document", "kubeconfig.yaml", []byte(bundleTestAttachment)); err != nil {
		t.Fatal("add document", err)
	}
	f.refresh(t)
	return f
}

func (f *bundleTestFixture) refresh(t *testing.T) {
	t.Helper()
	rows, err := ListState(f.path, "fixture", f.key, "all")
	if err != nil {
		t.Fatal("list vault", err)
	}
	for _, row := range rows {
		switch row.Kind {
		case "login":
			f.loginID, f.loginRevision = row.ID, row.Revision
		case "document":
			f.documentID, f.documentRevision = row.ID, row.Revision
		}
	}
	if f.loginID == "" || f.documentID == "" {
		t.Fatal("fixture items missing")
	}
}

func (f *bundleTestFixture) refreshTargets(t *testing.T, targets []BundleTarget) []BundleTarget {
	t.Helper()
	f.refresh(t)
	out := append([]BundleTarget(nil), targets...)
	for i := range out {
		switch out[i].ID {
		case f.loginID:
			out[i].Revision = f.loginRevision
		case f.documentID:
			out[i].Revision = f.documentRevision
		}
	}
	return out
}

func bundleTestSpec() cliprofile.Spec {
	return cliprofile.Spec{
		ID: "run-bundle-test-v1",
		Slots: []cliprofile.Slot{
			{Name: "token", Kind: "login", Field: cliprofile.FieldPassword, RequireNonBlank: true},
			{Name: "username", Kind: "login", Field: cliprofile.FieldUsername, RequireNonBlank: true},
			{Name: "password", Kind: "login", Field: cliprofile.FieldPassword, RequireNonBlank: true},
			{Name: "kubeconfig", Kind: "document", Field: cliprofile.FieldAttachment, RequireNonBlank: true},
		},
		Env: map[string]string{
			"GH_TOKEN":                 "slot:token",
			"DOCKER_CONFIG":            "root:docker",
			"NPM_CONFIG_USERCONFIG":    "file:npm/npmrc",
			"PGPASSFILE":               "file:pg/pgpass",
			"GIT_ASKPASS":              "file:git/askpass.sh",
			"LOCKLARK_GIT_SECRET_FILE": "file:git/askpass_secret",
			"NETRC":                    "file:git/netrc",
		},
		Files: []cliprofile.FileSpec{
			{RelPath: "kube/config", Format: "raw-slot:kubeconfig", Mode: 0600},
			{RelPath: "docker/config.json", Format: "docker-auths-v1", Mode: 0600},
			{RelPath: "npm/npmrc", Format: "npmrc-v1", Mode: 0600},
			{RelPath: "pg/pgpass", Format: "pgpass-v1", Mode: 0600},
			{RelPath: "git/netrc", Format: "netrc-v1", Mode: 0600},
			{RelPath: "git/askpass_secret", Format: "git-askpass-secret-v1", Mode: 0600},
			{RelPath: "git/askpass.sh", Format: "git-askpass-helper-v1", Mode: 0700},
			{RelPath: "git/credentials", Format: "git-credentials-v1", Mode: 0600},
			{RelPath: "git/gitconfig", Format: "git-config-store-v1", Mode: 0600},
		},
		Dirs:           []string{"kube", "docker", "npm", "pg", "git"},
		PassthroughEnv: []string{"BUNDLE_TEST_REGION", "NO_COLOR"},
		MaxTimeout:     60,
	}
}

func bundleTestTargets(f *bundleTestFixture) []BundleTarget {
	return []BundleTarget{
		{Slot: "token", ID: f.loginID, Revision: f.loginRevision, Field: "password"},
		{Slot: "username", ID: f.loginID, Revision: f.loginRevision, Field: "username"},
		{Slot: "password", ID: f.loginID, Revision: f.loginRevision, Field: "password"},
		{Slot: "kubeconfig", ID: f.documentID, Revision: f.documentRevision, Field: "attachment"},
	}
}

func bundleChildArgs(mode string) []string {
	return []string{"-test.run=^TestRunCLIBundleChild$", "--", "bundle-child", mode}
}

func bundleTestRequest(t *testing.T, f *bundleTestFixture) RunBundleRequest {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	return RunBundleRequest{
		Program:        exe,
		Args:           bundleChildArgs("probe"),
		Directory:      t.TempDir(),
		TimeoutSeconds: 15,
		HelperPath:     []string{filepath.Dir(exe)},
		Passthrough:    map[string]string{"BUNDLE_TEST_REGION": "test-region", "NO_COLOR": "1"},
		Spec:           bundleTestSpec(),
	}
}

func bundleTestValues() map[string][]byte {
	return map[string][]byte{
		"token":      []byte(bundleTestPassword),
		"username":   []byte(bundleTestUsername),
		"password":   []byte(bundleTestPassword),
		"kubeconfig": []byte(bundleTestAttachment),
	}
}

func cloneBundleRequest(r RunBundleRequest) RunBundleRequest {
	r.Args = append([]string(nil), r.Args...)
	r.HelperPath = append([]string(nil), r.HelperPath...)
	r.Passthrough = cloneStringMap(r.Passthrough)
	r.Spec = cliprofile.CloneSpec(r.Spec)
	return r
}

// testBundleTempCreator provides a private 0700 root below t.TempDir. The
// container VM's /home and /tmp ancestors are not owned by the current user, so
// the production localpath policy correctly refuses them; end-to-end tests still
// exercise the real runBundle implementation with a trusted private parent.
func testBundleTempCreator(t *testing.T) func() (string, error) {
	t.Helper()
	create, _ := testBundleTempCreatorTracked(t)
	return create
}

func testBundleTempCreatorTracked(t *testing.T) (func() (string, error), func() []string) {
	t.Helper()
	base, err := os.MkdirTemp(t.TempDir(), "bundle-base-")
	if err != nil {
		t.Fatal("temporary base unavailable")
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal("temporary base permissions unavailable")
	}
	var roots []string
	return func() (string, error) {
		root, err := os.MkdirTemp(base, "run-")
		if err != nil {
			return "", err
		}
		if err = os.Chmod(root, 0700); err != nil {
			os.RemoveAll(root)
			return "", err
		}
		roots = append(roots, root)
		return root, nil
	}, func() []string { return append([]string(nil), roots...) }
}

func bundleEnvValue(rendered cliprofile.RenderedBundle, name string) (string, bool) {
	for _, entry := range rendered.Env {
		gotName, gotValue, _ := strings.Cut(entry, "=")
		if gotName == name {
			return gotValue, true
		}
	}
	return "", false
}

func bundleRenderedFile(rendered cliprofile.RenderedBundle, rel string) (cliprofile.RenderedFile, bool) {
	for _, file := range rendered.Files {
		if file.RelPath == rel {
			return file, true
		}
	}
	return cliprofile.RenderedFile{}, false
}

func TestRunCLIBundleChild(t *testing.T) {
	mode := ""
	found := false
	for i, arg := range os.Args {
		if arg == "bundle-child" && i+1 < len(os.Args) {
			mode, found = os.Args[i+1], true
			break
		}
	}
	if !found {
		return
	}
	allowed := map[string]bool{
		"GH_TOKEN": true, "DOCKER_CONFIG": true, "NPM_CONFIG_USERCONFIG": true,
		"PGPASSFILE": true, "GIT_ASKPASS": true, "LOCKLARK_GIT_SECRET_FILE": true,
		"NETRC": true, "BUNDLE_TEST_REGION": true, "NO_COLOR": true,
		"PATH": true, "HOME": true, "GH_CONFIG_DIR": true,
		"XDG_CONFIG_HOME": true, "XDG_CACHE_HOME": true, "XDG_DATA_HOME": true,
		"TMPDIR": true, "TMP": true, "TEMP": true,
	}
	if runtime.GOOS == "windows" {
		allowed["SystemRoot"] = true
		allowed["USERPROFILE"], allowed["APPDATA"], allowed["LOCALAPPDATA"] = true, true, true
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !allowed[name] {
			os.Exit(41)
		}
	}
	if os.Getenv("GH_TOKEN") != bundleTestPassword || os.Getenv("PATH") == "" {
		os.Exit(42)
	}
	if mode == "sleep" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	if mode == "exit" {
		os.Exit(7)
	}
	root := filepath.Dir(os.Getenv("HOME"))
	if root == "." || root == string(filepath.Separator) {
		os.Exit(43)
	}
	for _, name := range []string{"HOME", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR", "TMP", "TEMP", "DOCKER_CONFIG"} {
		info, err := os.Stat(os.Getenv(name))
		if err != nil || !info.IsDir() {
			os.Exit(44)
		}
	}
	expected := map[string]struct {
		mode    os.FileMode
		content []byte
	}{
		"kube/config":        {0600, []byte(bundleTestAttachment)},
		"docker/config.json": {0600, nil},
		"npm/npmrc":          {0600, []byte("//registry.npmjs.org/:_authToken=" + bundleTestPassword + "\n")},
		"pg/pgpass":          {0600, []byte("*:*:*:" + bundleTestUsername + ":" + bundleTestPassword + "\n")},
		"git/netrc":          {0600, []byte("machine github.com login " + bundleTestUsername + " password " + bundleTestPassword + "\n")},
		"git/askpass_secret": {0600, []byte(bundleTestUsername + "\n" + bundleTestPassword + "\n")},
		"git/askpass.sh":     {0700, []byte(bundleAskpassScript)},
		"git/credentials":    {0600, []byte("https://" + bundleTestUsername + ":" + bundleTestPassword + "@github.com\n")},
	}
	dockerAuth := base64.StdEncoding.EncodeToString([]byte(bundleTestUsername + ":" + bundleTestPassword))
	var dockerDocument struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	dockerRaw, err := os.ReadFile(filepath.Join(root, "docker", "config.json"))
	if err != nil || json.Unmarshal(dockerRaw, &dockerDocument) != nil || len(dockerDocument.Auths) != 1 {
		os.Exit(45)
	}
	for registry, auth := range dockerDocument.Auths {
		if registry != "https://index.docker.io/v1/" || auth.Auth != dockerAuth {
			os.Exit(46)
		}
	}
	for rel, want := range expected {
		path := filepath.Join(root, filepath.FromSlash(rel))
		raw, err := os.ReadFile(path)
		if err != nil {
			os.Exit(47)
		}
		if want.content != nil && string(raw) != string(want.content) {
			os.Exit(48)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != want.mode {
				os.Exit(49)
			}
		}
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil || string(input) != "bundle input" {
		os.Exit(50)
	}
	gitconfig, err := os.ReadFile(filepath.Join(root, "git", "gitconfig"))
	if err != nil || !strings.Contains(string(gitconfig), "helper = store --file=") || !strings.HasSuffix(string(gitconfig), "/git/credentials\n") {
		os.Exit(51)
	}
	if mode != "probe" {
		os.Exit(52)
	}
	os.Stdout.WriteString(bundleTestPassword)
	os.Stderr.WriteString(bundleTestPassword)
	if err = os.WriteFile("child-proof", []byte(root), 0600); err != nil {
		os.Exit(53)
	}
	os.Exit(0)
}

func testBundleEndToEnd(t *testing.T) {
	f := newBundleTestFixture(t)
	targets := bundleTestTargets(f)
	request := bundleTestRequest(t, f)
	create, roots := testBundleTempCreatorTracked(t)
	inputPath := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(inputPath, []byte("bundle input"), 0600); err != nil {
		t.Fatal("stdin fixture unavailable")
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal("stdin unavailable")
	}
	defer input.Close()
	output, err := os.OpenFile(filepath.Join(t.TempDir(), "stdout"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal("stdout unavailable")
	}
	defer output.Close()
	errout, err := os.OpenFile(filepath.Join(t.TempDir(), "stderr"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal("stderr unavailable")
	}
	defer errout.Close()
	called, intentSeen := 0, false
	root := ""
	receipt, err := runBundle(context.Background(), targets, request, create, func(s *runBundleStoreRequest) (result, error) {
		root = s.root
		return command(f.path, "fixture", f.key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: s})
	}, func(ctx context.Context, req RunBundleRequest, gotRoot string, rendered cliprofile.RenderedBundle) (int, error) {
		called++
		if gotRoot != root {
			t.Errorf("execution root changed")
		}
		for name, want := range map[string]string{
			"GH_TOKEN": bundleTestPassword, "DOCKER_CONFIG": filepath.Join(root, "docker"),
			"NPM_CONFIG_USERCONFIG": filepath.Join(root, "npm", "npmrc"),
			"PGPASSFILE":            filepath.Join(root, "pg", "pgpass"),
			"GIT_ASKPASS":           filepath.Join(root, "git", "askpass.sh"),
			"NETRC":                 filepath.Join(root, "git", "netrc"),
			"BUNDLE_TEST_REGION":    "test-region",
		} {
			if got, ok := bundleEnvValue(rendered, name); !ok || got != want {
				t.Errorf("rendered environment %s missing or wrong", name)
			}
		}
		if file, ok := bundleRenderedFile(rendered, "kube/config"); !ok || string(file.Content) != bundleTestAttachment {
			t.Errorf("rendered kubeconfig missing")
		}
		events, auditErr := Audit(f.path, "fixture", f.key)
		if auditErr != nil || len(events) < 2 {
			t.Errorf("intent transaction not closed before execution")
		} else {
			event := events[len(events)-2]
			if event.Action != runBundleAction || event.Result != "intent" || event.Item != targets[0].ID || event.BaseRevision != targets[0].Revision || !digestOK(event.Link) {
				t.Errorf("intent was not committed before execution")
			}
			intentSeen = true
		}
		return executeRunBundle(ctx, req, gotRoot, rendered, runCLIStreams{input, output, errout})
	}, os.RemoveAll)
	if err != nil || called != 1 || !intentSeen || receipt.Status != "process-exited" || receipt.ExitCode != 0 {
		t.Fatalf("bundle run failed: %v %+v", err, receipt)
	}
	if !digestOK(receipt.Intent) || !digestOK(receipt.TargetDigest) || !idOK(receipt.Session) {
		t.Fatal("receipt digests invalid")
	}
	proof, err := os.ReadFile(filepath.Join(request.Directory, "child-proof"))
	if err != nil || string(proof) != root {
		t.Fatalf("child proof %q %v", proof, err)
	}
	for _, file := range []*os.File{output, errout} {
		if _, err = file.Seek(0, 0); err != nil {
			t.Fatal("stream seek failed")
		}
		raw, readErr := io.ReadAll(file)
		if readErr != nil || string(raw) != bundleTestPassword {
			t.Fatal("child stream not inherited")
		}
		clear(raw)
	}
	for _, got := range roots() {
		if _, err = os.Stat(got); !os.IsNotExist(err) {
			t.Fatal("temporary bundle root survived execution")
		}
	}
	events, err := Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal("audit unavailable")
	}
	foundIntent := false
	for _, event := range events {
		if event.hash() == receipt.Intent {
			foundIntent = true
			if event.Action != runBundleAction || event.Result != "intent" || event.BaseRevision != targets[0].Revision || event.Link != receipt.TargetDigest {
				t.Fatal("intent binding mismatch")
			}
		}
	}
	if !foundIntent {
		t.Fatal("intent event missing")
	}
	encoded, _ := json.Marshal([]any{receipt, events})
	for _, secret := range []string{bundleTestPassword, bundleTestAttachment, request.Program, request.Directory, root} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("private target or credential exposed in receipt/audit")
		}
	}
}

func TestRunCLIBundleEndToEnd(t *testing.T) { testBundleEndToEnd(t) }
func TestRunBundleEndToEnd(t *testing.T)    { testBundleEndToEnd(t) }

func testBundleRefusesReplaceableTemporaryParents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("production temporary selection uses KnownFolderPath rather than TMPDIR on Windows")
	}
	f := newBundleTestFixture(t)
	targets := bundleTestTargets(f)
	request := bundleTestRequest(t, f)
	request.Program = filepath.Join(f.path, "absent-program")
	unsafeParent := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(unsafeParent, 0700); err != nil {
		t.Fatal("unsafe parent fixture unavailable")
	}
	if err := os.Chmod(unsafeParent, 0777); err != nil {
		t.Fatal("unsafe parent permissions unavailable")
	}
	before, err := Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal("audit unavailable")
	}
	t.Setenv("TMPDIR", unsafeParent)
	receipt, err := RunBundle(context.Background(), f.path, "fixture", f.key, targets, request)
	if err != ErrRunTemporary || !reflect.DeepEqual(receipt, RunReceipt{}) {
		t.Fatalf("untrusted temporary parent accepted: %v %+v", err, receipt)
	}
	after, err := Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal("audit unavailable")
	}
	for _, event := range append(before, after[len(before):]...) {
		if event.Action == runBundleAction {
			t.Fatal("untrusted temporary parent prepared an intent")
		}
	}
}

func TestRunCLIBundleRefusesReplaceableTemporaryParents(t *testing.T) {
	testBundleRefusesReplaceableTemporaryParents(t)
}
func TestRunBundleRefusesReplaceableTemporaryParents(t *testing.T) {
	testBundleRefusesReplaceableTemporaryParents(t)
}

func testBundleAttempt(t *testing.T, f *bundleTestFixture, targets []BundleTarget, request RunBundleRequest, execute func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error)) (RunReceipt, error, int, string) {
	t.Helper()
	create := testBundleTempCreator(t)
	called := 0
	root := ""
	receipt, err := runBundle(context.Background(), targets, request, create, func(s *runBundleStoreRequest) (result, error) {
		root = s.root
		return command(f.path, "fixture", f.key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: s})
	}, func(ctx context.Context, req RunBundleRequest, gotRoot string, rendered cliprofile.RenderedBundle) (int, error) {
		called++
		if execute != nil {
			return execute(ctx, req, gotRoot, rendered)
		}
		return 0, nil
	}, os.RemoveAll)
	return receipt, err, called, root
}

func testBundleJournalAndExtraction(t *testing.T) {
	f := newBundleTestFixture(t)
	request := bundleTestRequest(t, f)
	targets := bundleTestTargets(f)

	receipt, err, called, root := testBundleAttempt(t, f, targets, request, nil)
	if err != nil || called != 1 || receipt.ExitCode != 0 {
		t.Fatalf("baseline bundle failed: %v", err)
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("baseline temporary root survived")
	}

	stale := append([]BundleTarget(nil), targets...)
	stale[0].Revision = strings.Repeat("0", 64)
	if _, err, called, _ = testBundleAttempt(t, f, stale, request, nil); err != ErrConflict || called != 0 {
		t.Fatalf("stale revision accepted: %v", err)
	}

	missing := append([]BundleTarget(nil), targets...)
	missing[0].ID = strings.Repeat("2", 32)
	if _, err, called, _ = testBundleAttempt(t, f, missing, request, nil); err != ErrNotFound || called != 0 {
		t.Fatalf("missing target accepted: %v", err)
	}

	wrongKind := append([]BundleTarget(nil), targets...)
	wrongKind[3].ID = f.loginID
	wrongKind[3].Revision = f.loginRevision
	if _, err, called, _ = testBundleAttempt(t, f, wrongKind, request, nil); err != invalid || called != 0 {
		t.Fatalf("kind mismatch accepted: %v", err)
	}

	if _, err = SetTrashed(f.path, "fixture", f.key, f.documentID, f.documentRevision, true); err != nil {
		t.Fatal("trash document", err)
	}
	targets = f.refreshTargets(t, targets)
	if _, err, called, _ = testBundleAttempt(t, f, targets, request, nil); err != ErrTrashed || called != 0 {
		t.Fatalf("trashed document accepted: %v", err)
	}
	events, err := Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal("audit unavailable")
	}
	if len(events) < 2 {
		t.Fatal("journal missing")
	}
	last := events[len(events)-2]
	if last.Action != runBundleAction || last.Result != "trashed" || last.Item != f.documentID || last.BaseRevision != f.documentRevision {
		t.Fatal("trashed outcome not journaled canonically")
	}
	if _, err = SetTrashed(f.path, "fixture", f.key, f.documentID, f.documentRevision, false); err != nil {
		t.Fatal("untrash document", err)
	}
	targets = f.refreshTargets(t, targets)

	if _, err = EditLogin(f.path, "fixture", f.key, Edit{ID: f.loginID, Revision: f.loginRevision, Field: "password", Value: "   "}); err != nil {
		t.Fatal("blank credential fixture unavailable")
	}
	targets = f.refreshTargets(t, targets)
	if _, err, called, _ = testBundleAttempt(t, f, targets, request, nil); err != ErrRunCredential || called != 0 {
		t.Fatalf("blank credential reached execution: %v", err)
	}

	events, err = Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal("audit after blank credential unavailable")
	}
	last = events[len(events)-2]
	if last.Action != runBundleAction || last.Result != "intent" || !digestOK(last.Link) {
		t.Fatal("blank credential intent not journaled")
	}

	if _, err = EditLogin(f.path, "fixture", f.key, Edit{ID: f.loginID, Revision: f.loginRevision, Field: "password", Value: bundleTestPassword}); err != nil {
		t.Fatal("restore credential failed")
	}
	f.refresh(t)
}

func TestRunCLIBundleJournalAndExtraction(t *testing.T) { testBundleJournalAndExtraction(t) }
func TestRunBundleJournalAndExtraction(t *testing.T)    { testBundleJournalAndExtraction(t) }

func testBundleValidationAndBinding(t *testing.T) {
	f := newBundleTestFixture(t)
	targets := bundleTestTargets(f)
	request := bundleTestRequest(t, f)
	if err := request.Validate(targets); err != nil {
		t.Fatal("valid base request refused")
	}
	mutations := []func(*RunBundleRequest){
		func(r *RunBundleRequest) { r.Program = "" },
		func(r *RunBundleRequest) { r.Program = "relative" },
		func(r *RunBundleRequest) { r.Program += "\x00" },
		func(r *RunBundleRequest) { r.Directory = "relative" },
		func(r *RunBundleRequest) { r.Directory = "" },
		func(r *RunBundleRequest) { r.Args = make([]string, 65) },
		func(r *RunBundleRequest) { r.Args = []string{strings.Repeat("x", 16385)} },
		func(r *RunBundleRequest) { r.Args = []string{"bad\x00"} },
		func(r *RunBundleRequest) { r.Args = []string{string([]byte{0xff})} },
		func(r *RunBundleRequest) {
			r.Spec.DenyArgs = [][]string{{"auth", "login"}}
			r.Args = []string{"auth", "login"}
		},
		func(r *RunBundleRequest) { r.TimeoutSeconds = 0 },
		func(r *RunBundleRequest) { r.TimeoutSeconds = 61 },
		func(r *RunBundleRequest) { r.Spec.MaxTimeout = 0; r.TimeoutSeconds = 301 },
		func(r *RunBundleRequest) { r.Spec.MaxTimeout = 90000 },
		func(r *RunBundleRequest) { r.HelperPath = []string{"relative"} },
		func(r *RunBundleRequest) { r.HelperPath = []string{r.Program + string(os.PathListSeparator)} },
		func(r *RunBundleRequest) { r.HelperPath = make([]string, 17) },
		func(r *RunBundleRequest) { r.Spec.ID = "" },
		func(r *RunBundleRequest) { r.Spec.Slots = nil },
		func(r *RunBundleRequest) { r.Spec.Slots = make([]cliprofile.Slot, 17) },
		func(r *RunBundleRequest) { r.Spec.Files = make([]cliprofile.FileSpec, 17) },
		func(r *RunBundleRequest) { r.Spec.Dirs = make([]string, 17) },
		func(r *RunBundleRequest) { r.TokenEnvName = "TOKEN" },
		func(r *RunBundleRequest) { r.Spec.DynamicTokenEnv = true; r.TokenEnvName = "" },
		func(r *RunBundleRequest) { r.Spec.DynamicTokenEnv = true; r.TokenEnvName = "SystemRoot" },
		func(r *RunBundleRequest) { r.Passthrough["LD_PRELOAD"] = "x" },
		func(r *RunBundleRequest) {
			r.Passthrough = make(map[string]string, 33)
			for i := 0; i < 33; i++ {
				r.Passthrough["PASSTHROUGH_"+strings.Repeat("X", i)] = "x"
			}
		},
	}
	for i, mutate := range mutations {
		r := cloneBundleRequest(request)
		mutate(&r)
		if r.Validate(targets) == nil {
			t.Fatalf("invalid request mutation %d accepted", i)
		}
	}
	invalidTargets := [][]BundleTarget{
		nil,
		{},
		append(append([]BundleTarget(nil), targets...), BundleTarget{Slot: "extra", ID: f.loginID, Revision: f.loginRevision, Field: "password"}),
		func() []BundleTarget { x := append([]BundleTarget(nil), targets...); x[0].Slot = "unknown"; return x }(),
		func() []BundleTarget { x := append([]BundleTarget(nil), targets...); x[1].Slot = x[0].Slot; return x }(),
		targets[1:],
		func() []BundleTarget { x := append([]BundleTarget(nil), targets...); x[0].ID = "bad"; return x }(),
		func() []BundleTarget {
			x := append([]BundleTarget(nil), targets...)
			x[0].Revision = strings.Repeat("z", 64)
			return x
		}(),
		func() []BundleTarget { x := append([]BundleTarget(nil), targets...); x[0].Field = "username"; return x }(),
	}
	for i, bad := range invalidTargets {
		if request.Validate(bad) == nil {
			t.Fatalf("invalid targets %d accepted", i)
		}
	}
	unknownKind := cloneBundleRequest(request)
	for i := range unknownKind.Spec.Slots {
		if unknownKind.Spec.Slots[i].Name == "username" {
			unknownKind.Spec.Slots[i].Kind = "other"
		}
	}
	if unknownKind.Validate(targets) == nil {
		t.Fatal("unknown slot kind accepted")
	}
	documentField := cloneBundleRequest(request)
	for i := range documentField.Spec.Slots {
		if documentField.Spec.Slots[i].Name == "username" {
			documentField.Spec.Slots[i].Kind = "login"
			documentField.Spec.Slots[i].Field = cliprofile.FieldAttachment
		}
	}
	badFieldTargets := append([]BundleTarget(nil), targets...)
	badFieldTargets[1].Field = "attachment"
	if documentField.Validate(badFieldTargets) == nil {
		t.Fatal("login attachment field accepted")
	}

	if (*runBundleStoreRequest)(nil).validate() == nil {
		t.Fatal("nil store request accepted")
	}
	root := t.TempDir()
	store := &runBundleStoreRequest{targets: targets, request: request, root: root}
	if err := store.validate(); err != nil {
		t.Fatal("valid store request refused")
	}
	for _, badRoot := range []string{"", "relative", root + "\x00"} {
		copy := *store
		copy.root = badRoot
		if copy.validate() == nil {
			t.Fatalf("invalid store root %q accepted", badRoot)
		}
	}

	secret := bytes.Repeat([]byte{9}, 32)
	base, err := store.binding(secret)
	if err != nil || !digestOK(base) {
		t.Fatalf("binding failed: %v", err)
	}
	if again, err := store.binding(secret); err != nil || again != base {
		t.Fatal("binding is not deterministic")
	}
	if other, err := store.binding(bytes.Repeat([]byte{8}, 32)); err != nil || other == base {
		t.Fatal("binding does not depend on the vault secret")
	}
	variations := []func(*runBundleStoreRequest){
		func(s *runBundleStoreRequest) { s.root = filepath.Join(root, "other") },
		func(s *runBundleStoreRequest) { s.targets[0], s.targets[1] = s.targets[1], s.targets[0] },
		func(s *runBundleStoreRequest) { s.targets[0].Revision = strings.Repeat("0", 64) },
		func(s *runBundleStoreRequest) { s.request.Passthrough["NO_COLOR"] = "0" },
		func(s *runBundleStoreRequest) { s.request.HelperPath = append(s.request.HelperPath, root) },
		func(s *runBundleStoreRequest) { s.request.Args = append(s.request.Args, "extra") },
		func(s *runBundleStoreRequest) { s.request.TimeoutSeconds++ },
		func(s *runBundleStoreRequest) { s.request.Spec.ID = "changed-spec" },
		func(s *runBundleStoreRequest) {
			s.request.Program = filepath.Join(filepath.Dir(s.request.Program), "other"+filepath.Ext(s.request.Program))
		},
		func(s *runBundleStoreRequest) { s.request.Directory += "-other" },
	}
	for i, change := range variations {
		copy := &runBundleStoreRequest{targets: append([]BundleTarget(nil), store.targets...), request: cloneBundleRequest(store.request), root: store.root}
		change(copy)
		if err := copy.validate(); err != nil {
			t.Fatalf("binding variation %d invalid: %v", i, err)
		}
		if digest, err := copy.binding(secret); err != nil || digest == base {
			t.Fatalf("binding variation %d not bound", i)
		}
	}
	tokenRequest := cloneBundleRequest(store.request)
	tokenRequest.Spec.DynamicTokenEnv = true
	tokenRequest.TokenEnvName = "BUNDLE_TOKEN"
	first := &runBundleStoreRequest{targets: append([]BundleTarget(nil), store.targets...), request: tokenRequest, root: store.root}
	digestOne, err := first.binding(secret)
	if err != nil {
		t.Fatal("dynamic token binding failed")
	}
	second := &runBundleStoreRequest{targets: append([]BundleTarget(nil), store.targets...), request: cloneBundleRequest(tokenRequest), root: store.root}
	second.request.TokenEnvName = "OTHER_TOKEN"
	digestTwo, err := second.binding(secret)
	if err != nil || digestTwo == digestOne {
		t.Fatal("token environment name not bound")
	}
}

func TestRunCLIBundleValidationAndBinding(t *testing.T) { testBundleValidationAndBinding(t) }
func TestRunBundleValidationAndBinding(t *testing.T)    { testBundleValidationAndBinding(t) }

func testBundleFilesSafety(t *testing.T) {
	newRoot := func() string {
		root := filepath.Join(t.TempDir(), "run")
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal("root fixture unavailable")
		}
		return root
	}
	root := newRoot()
	files := []cliprofile.RenderedFile{{RelPath: "nested/deep/secret", Mode: 0600, Content: []byte("private")}}
	if err := writeRunBundleFiles(root, files); err != nil {
		t.Fatalf("valid file refused: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(root, "nested", "deep", "secret")); err != nil || string(raw) != "private" {
		t.Fatal("valid file content wrong")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(root, "nested", "deep")); err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("nested parent not owner-only")
		}
		if info, err := os.Stat(filepath.Join(root, "nested", "deep", "secret")); err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("file not owner-only")
		}
	}
	if err := writeRunBundleFiles(root, files); err == nil {
		t.Fatal("existing file overwritten")
	}
	invalid := []struct {
		name string
		root string
		file cliprofile.RenderedFile
	}{
		{"empty-root", "", cliprofile.RenderedFile{RelPath: "x", Mode: 0600}},
		{"relative-root", "relative", cliprofile.RenderedFile{RelPath: "x", Mode: 0600}},
		{"nul-root", newRoot() + "\x00", cliprofile.RenderedFile{RelPath: "x", Mode: 0600}},
		{"empty-path", newRoot(), cliprofile.RenderedFile{RelPath: "", Mode: 0600}},
		{"absolute-path", newRoot(), cliprofile.RenderedFile{RelPath: "/absolute", Mode: 0600}},
		{"nul-path", newRoot(), cliprofile.RenderedFile{RelPath: "x\x00y", Mode: 0600}},
		{"mode", newRoot(), cliprofile.RenderedFile{RelPath: "x", Mode: 0644}},
		{"dotdot", newRoot(), cliprofile.RenderedFile{RelPath: "../escape", Mode: 0600}},
		{"dotdot-clean", newRoot(), cliprofile.RenderedFile{RelPath: "a/../b", Mode: 0600}},
		{"dotdot-prefix", newRoot(), cliprofile.RenderedFile{RelPath: "..evil", Mode: 0600}},
		{"dot", newRoot(), cliprofile.RenderedFile{RelPath: ".", Mode: 0600}},
	}
	for _, test := range invalid {
		if err := writeRunBundleFiles(test.root, []cliprofile.RenderedFile{test.file}); err == nil {
			t.Fatalf("%s accepted", test.name)
		}
	}
	rootFile := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(rootFile, []byte("x"), 0600); err != nil {
		t.Fatal("root file fixture unavailable")
	}
	if err := writeRunBundleFiles(rootFile, []cliprofile.RenderedFile{{RelPath: "x", Mode: 0600}}); err == nil {
		t.Fatal("file used as root")
	}
	realRoot := newRoot()
	rootLink := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(realRoot, rootLink); err != nil {
		t.Skip("symlink unavailable")
	}
	if err := writeRunBundleFiles(rootLink, []cliprofile.RenderedFile{{RelPath: "x", Mode: 0600}}); err == nil {
		t.Fatal("symlink root accepted")
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal("outside fixture unavailable")
	}
	root = newRoot()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal("parent symlink unavailable")
	}
	if err := writeRunBundleFiles(root, []cliprofile.RenderedFile{{RelPath: "link/escape", Mode: 0600, Content: []byte("x")}}); err == nil {
		t.Fatal("symlink parent accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(err) {
		t.Fatal("symlink parent wrote outside root")
	}

	if runtime.GOOS != "windows" {
		root = newRoot()
		if err := os.Mkdir(filepath.Join(root, "public"), 0700); err != nil {
			t.Fatal("public parent fixture unavailable")
		}
		if err := os.Chmod(filepath.Join(root, "public"), 0777); err != nil {
			t.Fatal("public parent permissions unavailable")
		}
		if err := writeRunBundleFiles(root, []cliprofile.RenderedFile{{RelPath: "public/x", Mode: 0600}}); err == nil {
			t.Fatal("public parent accepted")
		}
	}

	root = newRoot()
	if err := os.WriteFile(filepath.Join(root, "plain"), []byte("x"), 0600); err != nil {
		t.Fatal("plain parent fixture unavailable")
	}
	if err := writeRunBundleFiles(root, []cliprofile.RenderedFile{{RelPath: "plain/child", Mode: 0600}}); err == nil {
		t.Fatal("file parent accepted")
	}

	outsideFile := filepath.Join(outside, "victim")
	if err := os.WriteFile(outsideFile, []byte("original"), 0600); err != nil {
		t.Fatal("victim fixture unavailable")
	}
	root = newRoot()
	if err := os.Symlink(outsideFile, filepath.Join(root, "victim")); err != nil {
		t.Fatal("target symlink unavailable")
	}
	if err := writeRunBundleFiles(root, []cliprofile.RenderedFile{{RelPath: "victim", Mode: 0600, Content: []byte("changed")}}); err == nil {
		t.Fatal("target symlink overwritten")
	}
	if raw, err := os.ReadFile(outsideFile); err != nil || string(raw) != "original" {
		t.Fatal("target symlink changed outside file")
	}
}

func TestRunCLIBundleFilesSafety(t *testing.T) { testBundleFilesSafety(t) }
func TestRunBundleFilesSafety(t *testing.T)    { testBundleFilesSafety(t) }

func TestAddDocumentLifecycleAndBundle(t *testing.T) {
	f := newBundleTestFixture(t)
	rows, err := List(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal("list failed")
	}
	var document Row
	for _, row := range rows {
		if row.Kind == "document" {
			document = row
		}
	}
	if document.ID == "" || document.State != "active" {
		t.Fatal("document fixture missing")
	}
	revision, err := SetArchived(f.path, "fixture", f.key, document.ID, document.Revision, true)
	if err != nil {
		t.Fatal("archive document", err)
	}
	archived, err := ListState(f.path, "fixture", f.key, "archived")
	if err != nil || len(archived) != 1 || archived[0].ID != document.ID {
		t.Fatal("document not archived")
	}
	revision, err = SetTrashed(f.path, "fixture", f.key, document.ID, revision, true)
	if err != nil {
		t.Fatal("trash document", err)
	}
	trashed, err := ListState(f.path, "fixture", f.key, "trashed")
	if err != nil || len(trashed) != 1 || trashed[0].RestoreState != "archived" {
		t.Fatal("document trash state wrong")
	}
	revision, err = SetTrashed(f.path, "fixture", f.key, document.ID, revision, false)
	if err != nil {
		t.Fatal("untrash document", err)
	}
	if _, err = SetArchived(f.path, "fixture", f.key, document.ID, revision, false); err != nil {
		t.Fatal("unarchive document", err)
	}
	active, err := ListState(f.path, "fixture", f.key, "active")
	if err != nil || len(active) != 2 {
		t.Fatal("document not restored")
	}

	if _, err = AddDocument(f.path, "fixture", f.key, "second", "second.bin", []byte("second")); err != nil {
		t.Fatal("second document add failed")
	}
	rows, err = List(f.path, "fixture", f.key)
	if err != nil || len(rows) != 3 {
		t.Fatal("second document missing")
	}
	for _, bad := range []struct {
		title, filename string
		attachment      []byte
	}{
		{"", "file", []byte("x")},
		{" ", "file", []byte("x")},
		{"title", "", []byte("x")},
		{"title", " ", []byte("x")},
		{"title", "../escape", []byte("x")},
		{"title", ".", []byte("x")},
		{"title", "file", nil},
		{"title", "file", []byte{}},
	} {
		if _, err = AddDocument(f.path, "fixture", f.key, bad.title, bad.filename, bad.attachment); err == nil {
			t.Fatalf("invalid document accepted: %+v", bad)
		}
	}

	events, err := Audit(f.path, "fixture", f.key)
	if err != nil {
		t.Fatal("audit unavailable")
	}
	added := 0
	for _, event := range events {
		if event.Action == "item.add" && event.Result == "succeeded" {
			added++
		}
	}
	if added < 3 {
		t.Fatal("document add events missing")
	}
}

func testBundleCancellationTimeoutAndCleanup(t *testing.T) {
	f := newBundleTestFixture(t)
	request := bundleTestRequest(t, f)

	t.Run("cancelled-entry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		created, prepared, executed := 0, 0, 0
		_, err := runBundle(ctx, bundleTestTargets(f), request, func() (string, error) {
			created++
			return "", errors.New("must not create")
		}, func(*runBundleStoreRequest) (result, error) {
			prepared++
			return result{}, nil
		}, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
			executed++
			return 0, nil
		}, os.RemoveAll)
		if err != ErrRunCancelled || created != 0 || prepared != 0 || executed != 0 {
			t.Fatal("cancelled entry did not stop before temporary creation")
		}
	})

	t.Run("cancelled-prepare", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		create, roots := testBundleTempCreatorTracked(t)
		executed := 0
		_, err := runBundle(ctx, bundleTestTargets(f), request, create, func(*runBundleStoreRequest) (result, error) {
			cancel()
			return result{}, nil
		}, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
			executed++
			return 0, nil
		}, os.RemoveAll)
		if err != ErrRunCancelled || executed != 0 {
			t.Fatal("cancelled preparation reached execution")
		}
		for _, root := range roots() {
			if _, err = os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("cancelled preparation left temporary state")
			}
		}
	})

	t.Run("create-failure", func(t *testing.T) {
		prepared, executed := 0, 0
		_, err := runBundle(context.Background(), bundleTestTargets(f), request, func() (string, error) {
			return "", errors.New("private temporary failure")
		}, func(*runBundleStoreRequest) (result, error) {
			prepared++
			return result{}, nil
		}, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
			executed++
			return 0, nil
		}, os.RemoveAll)
		if err != ErrRunTemporary || prepared != 0 || executed != 0 {
			t.Fatal("temporary failure reached intent or execution")
		}
	})

	t.Run("cleanup-failure", func(t *testing.T) {
		create := testBundleTempCreator(t)
		receipt, err := runBundle(context.Background(), bundleTestTargets(f), request, create, func(*runBundleStoreRequest) (result, error) {
			return result{values: bundleTestValues()}, nil
		}, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
			return 0, nil
		}, func(path string) error {
			os.RemoveAll(path)
			return errors.New("private cleanup failure")
		})
		if err != ErrRunCleanup || !reflect.DeepEqual(receipt, RunReceipt{}) {
			t.Fatal("cleanup failure not distinguished")
		}
	})

	t.Run("render-refusal", func(t *testing.T) {
		if _, err := EditLogin(f.path, "fixture", f.key, Edit{ID: f.loginID, Revision: f.loginRevision, Field: "password", Value: "   "}); err != nil {
			t.Fatal("blank credential fixture unavailable")
		}
		targets := f.refreshTargets(t, bundleTestTargets(f))
		create, roots := testBundleTempCreatorTracked(t)
		called := 0
		_, err := runBundle(context.Background(), targets, request, create, func(s *runBundleStoreRequest) (result, error) {
			return command(f.path, "fixture", f.key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: s})
		}, func(context.Context, RunBundleRequest, string, cliprofile.RenderedBundle) (int, error) {
			called++
			return 0, nil
		}, os.RemoveAll)
		if err != ErrRunCredential || called != 0 {
			t.Fatal("blank credential reached process execution")
		}
		for _, root := range roots() {
			if _, err = os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("refused credential left temporary state")
			}
		}
		if _, err = EditLogin(f.path, "fixture", f.key, Edit{ID: f.loginID, Revision: f.loginRevision, Field: "password", Value: bundleTestPassword}); err != nil {
			t.Fatal("restore credential failed")
		}
		f.refresh(t)
	})

	t.Run("timeout", func(t *testing.T) {
		null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			t.Fatal("null device unavailable")
		}
		defer null.Close()
		request := request
		request.Args = bundleChildArgs("sleep")
		request.TimeoutSeconds = 1
		create, roots := testBundleTempCreatorTracked(t)
		called := 0
		_, err = runBundle(context.Background(), bundleTestTargets(f), request, create, func(s *runBundleStoreRequest) (result, error) {
			return command(f.path, "fixture", f.key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: s})
		}, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
			called++
			return executeRunBundle(ctx, req, root, rendered, runCLIStreams{null, null, null})
		}, os.RemoveAll)
		if err != ErrRunResult || called != 1 {
			t.Fatalf("timeout not enforced: %v", err)
		}
		for _, root := range roots() {
			if _, err = os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("timed-out process left temporary state")
			}
		}
	})

	t.Run("exit-code", func(t *testing.T) {
		null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			t.Fatal("null device unavailable")
		}
		defer null.Close()
		request := request
		request.Args = bundleChildArgs("exit")
		create, roots := testBundleTempCreatorTracked(t)
		receipt, err := runBundle(context.Background(), bundleTestTargets(f), request, create, func(s *runBundleStoreRequest) (result, error) {
			return command(f.path, "fixture", f.key, runBundleAction, vault.Item{}, nil, commandOption{runBundle: s})
		}, func(ctx context.Context, req RunBundleRequest, root string, rendered cliprofile.RenderedBundle) (int, error) {
			return executeRunBundle(ctx, req, root, rendered, runCLIStreams{null, null, null})
		}, os.RemoveAll)
		if err != nil || receipt.ExitCode != 7 {
			t.Fatalf("nonzero child status lost: %v %+v", err, receipt)
		}
		for _, root := range roots() {
			if _, err = os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("child exit left temporary state")
			}
		}
	})
}

func TestRunCLIBundleCancellationTimeoutAndCleanup(t *testing.T) {
	testBundleCancellationTimeoutAndCleanup(t)
}
func TestRunBundleCancellationTimeoutAndCleanup(t *testing.T) {
	testBundleCancellationTimeoutAndCleanup(t)
}
