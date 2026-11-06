package cliprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func envLookup(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, entry := range env {
		name, value, _ := strings.Cut(entry, "=")
		out[name] = value
	}
	return out
}

func findRenderedFile(t *testing.T, files []RenderedFile, rel string) RenderedFile {
	t.Helper()
	for _, file := range files {
		if file.RelPath == rel {
			return file
		}
	}
	t.Fatalf("rendered file %q missing", rel)
	return RenderedFile{}
}

func renderBuiltin(t *testing.T, name, tokenEnv string, slots map[string][]byte, passthrough map[string]string) RenderedBundle {
	t.Helper()
	profile, ok := Lookup(name)
	if !ok {
		t.Fatalf("profile %q missing", name)
	}
	rendered, err := Render(profile.Spec(), t.TempDir(), tokenEnv, slots, passthrough)
	if err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return rendered
}

var expectedProfiles = []string{
	"anthropic", "aws", "docker", "flyctl", "gh", "git", "kubectl", "netrc",
	"npm", "openai", "psql", "stripe", "terraform", "token", "vercel",
}

func TestListLookupAndCloneSpec(t *testing.T) {
	profiles := List()
	if len(profiles) != len(expectedProfiles) {
		t.Fatalf("got %d profiles", len(profiles))
	}
	for i, profile := range profiles {
		if profile.Name() != expectedProfiles[i] {
			t.Fatalf("profile order %q at %d", profile.Name(), i)
		}
		if _, ok := Lookup(profile.Name()); !ok {
			t.Fatalf("lookup failed for %q", profile.Name())
		}
	}
	if _, ok := Lookup("unknown"); ok {
		t.Fatal("unknown profile found")
	}
	if len(Lookup0(t, "token").Executables()) != 0 {
		t.Fatal("token profile has executables")
	}
	executables := map[string][]string{
		"gh":        {"gh"},
		"aws":       {"aws"},
		"kubectl":   {"kubectl", "helm"},
		"docker":    {"docker"},
		"npm":       {"npm", "pnpm", "yarn"},
		"terraform": {"terraform", "tofu"},
		"git":       {"git"},
		"netrc":     {"curl"},
		"psql":      {"psql", "pg_dump", "pg_restore"},
		"openai":    {"openai"},
		"anthropic": {"anthropic", "claude"},
		"stripe":    {"stripe"},
		"flyctl":    {"flyctl", "fly"},
		"vercel":    {"vercel", "vc"},
	}
	for name, want := range executables {
		if got := Lookup0(t, name).Executables(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s executables %v", name, got)
		}
	}
	original := Lookup0(t, "git").Spec()
	clone := CloneSpec(original)
	clone.Slots[0].Name = "changed"
	clone.Env["GIT_ASKPASS"] = "changed"
	clone.Files[0].RelPath = "changed"
	clone.Dirs[0] = "changed"
	clone.PassthroughEnv[0] = "changed"
	clone.DenyArgs[0][0] = "changed"
	again := Lookup0(t, "git").Spec()
	if again.Slots[0].Name != "username" || again.Files[0].RelPath != "git/askpass_secret" || again.Dirs[0] != "git" || again.PassthroughEnv[0] != "GIT_AUTHOR_NAME" || again.DenyArgs[0][0] != "config" {
		t.Fatal("CloneSpec aliased the shared profile")
	}
}

func Lookup0(t *testing.T, name string) Profile {
	t.Helper()
	profile, ok := Lookup(name)
	if !ok {
		t.Fatalf("profile %q missing", name)
	}
	return profile
}

func TestRenderTerraform(t *testing.T) {
	rendered := renderBuiltin(t, "terraform", "", map[string][]byte{"token": []byte("tf-token")}, nil)
	env := envLookup(rendered.Env)
	if env["TF_TOKEN_app_terraform_io"] != "tf-token" || env["TF_CLI_CONFIG_FILE"] == "" {
		t.Fatalf("terraform environment %v", env)
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		if _, present := env[name]; present {
			t.Fatalf("empty optional credential %s emitted", name)
		}
	}
	file := findRenderedFile(t, rendered.Files, "terraform/terraform.rc")
	if file.Mode.Perm() != 0600 || len(file.Content) != 0 {
		t.Fatalf("terraform config file %v %d", file.Mode, len(file.Content))
	}
	rendered = renderBuiltin(t, "terraform", "", map[string][]byte{
		"aws_access_key_id": []byte("AKIATEST"), "aws_secret_access_key": []byte("secret"),
	}, nil)
	env = envLookup(rendered.Env)
	if env["AWS_ACCESS_KEY_ID"] != "AKIATEST" || env["AWS_SECRET_ACCESS_KEY"] != "secret" {
		t.Fatalf("terraform AWS environment %v", env)
	}
	if _, present := env["TF_TOKEN_app_terraform_io"]; present {
		t.Fatal("empty optional terraform token emitted")
	}
}

func TestRenderTokenProfiles(t *testing.T) {
	cases := []struct {
		profile string
		slot    string
		env     string
		token   string
		extra   map[string]string
	}{
		{"gh", "token", "GH_TOKEN", "gh-secret", nil},
		{"openai", "token", "OPENAI_API_KEY", "sk-test", nil},
		{"anthropic", "token", "ANTHROPIC_API_KEY", "sk-ant", nil},
		{"stripe", "token", "STRIPE_API_KEY", "sk_live_test", nil},
		{"flyctl", "token", "FLY_API_TOKEN", "FlyV1 test", nil},
		{"vercel", "token", "VERCEL_TOKEN", "vercel-secret", nil},
		{"token", "token", "DEPLOY_TOKEN", "generic-secret", nil},
	}
	for _, test := range cases {
		t.Run(test.profile, func(t *testing.T) {
			tokenEnv := ""
			if test.profile == "token" {
				tokenEnv = test.env
			}
			rendered := renderBuiltin(t, test.profile, tokenEnv, map[string][]byte{test.slot: []byte(test.token)}, test.extra)
			got := envLookup(rendered.Env)
			if got[test.env] != test.token || len(got) != 1 {
				t.Fatalf("environment %v", got)
			}
			names := make([]string, 0, len(rendered.Env))
			for _, entry := range rendered.Env {
				names = append(names, entry[:strings.IndexByte(entry, '=')])
			}
			if !sort.StringsAreSorted(names) {
				t.Fatal("environment is not sorted")
			}
		})
	}
	if rendered := renderBuiltin(t, "gh", "", map[string][]byte{"token": []byte("x")}, map[string]string{"GH_HOST": "github.example.com"}); envLookup(rendered.Env)["GH_HOST"] != "github.example.com" {
		t.Fatal("passthrough missing")
	}
}

func TestRenderAWS(t *testing.T) {
	slots := map[string][]byte{"access_key_id": []byte("AKIATEST"), "secret_access_key": []byte("secret")}
	rendered := renderBuiltin(t, "aws", "", slots, nil)
	env := envLookup(rendered.Env)
	if env["AWS_ACCESS_KEY_ID"] != "AKIATEST" || env["AWS_SECRET_ACCESS_KEY"] != "secret" {
		t.Fatalf("aws environment %v", env)
	}
	if _, present := env["AWS_SESSION_TOKEN"]; present {
		t.Fatal("empty optional session token emitted")
	}
	if env["AWS_CONFIG_FILE"] != filepath.Join(filepath.Dir(filepath.Dir(env["AWS_CONFIG_FILE"])), "aws", "config") || env["AWS_SHARED_CREDENTIALS_FILE"] != filepath.Join(filepath.Dir(env["AWS_CONFIG_FILE"]), "credentials") {
		t.Fatalf("aws file paths %v", env)
	}
	if env["AWS_PAGER"] != "" {
		t.Fatal("literal empty value not preserved")
	}
	if len(rendered.Files) != 2 {
		t.Fatalf("aws files %d", len(rendered.Files))
	}
	for _, rel := range []string{"aws/config", "aws/credentials"} {
		file := findRenderedFile(t, rendered.Files, rel)
		if file.Mode.Perm() != 0600 || len(file.Content) != 0 {
			t.Fatalf("aws file %s mode=%v len=%d", rel, file.Mode, len(file.Content))
		}
	}
	slots["session_token"] = []byte("session")
	if envLookup(renderBuiltin(t, "aws", "", slots, nil).Env)["AWS_SESSION_TOKEN"] != "session" {
		t.Fatal("optional session token not emitted")
	}
}

func TestRenderKubectl(t *testing.T) {
	config := []byte("apiVersion: v1\nkind: Config\nclusters: []\n")
	rendered := renderBuiltin(t, "kubectl", "", map[string][]byte{"kubeconfig": config}, nil)
	file := findRenderedFile(t, rendered.Files, "kube/config")
	if file.Mode.Perm() != 0600 || !bytes.Equal(file.Content, config) {
		t.Fatalf("kubeconfig file %v %q", file.Mode, file.Content)
	}
	env := envLookup(rendered.Env)
	if env["KUBECONFIG"] != filepath.Join(filepath.Dir(filepath.Dir(env["KUBECONFIG"])), "kube", "config") {
		t.Fatalf("kubeconfig env %q", env["KUBECONFIG"])
	}
	if !filepath.IsAbs(env["KUBECACHEDIR"]) || filepath.Base(env["KUBECACHEDIR"]) != "cache" {
		t.Fatalf("cache env %q", env["KUBECACHEDIR"])
	}
}

func dockerAuth(t *testing.T, rendered RenderedBundle) (string, string) {
	t.Helper()
	file := findRenderedFile(t, rendered.Files, "docker/config.json")
	if file.Mode.Perm() != 0600 || !bytes.HasSuffix(file.Content, []byte("\n")) {
		t.Fatalf("docker config mode/content %v %q", file.Mode, file.Content)
	}
	var document struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(file.Content, &document); err != nil || len(document.Auths) != 1 {
		t.Fatalf("docker config JSON %v %v", err, document)
	}
	for registry, auth := range document.Auths {
		return registry, auth.Auth
	}
	return "", ""
}

func TestRenderDocker(t *testing.T) {
	rendered := renderBuiltin(t, "docker", "", map[string][]byte{"username": []byte("deploy-user"), "password": []byte("s3cret")}, nil)
	registry, auth := dockerAuth(t, rendered)
	if registry != "https://index.docker.io/v1/" {
		t.Fatalf("default registry %q", registry)
	}
	if auth != base64.StdEncoding.EncodeToString([]byte("deploy-user:s3cret")) {
		t.Fatalf("auth %q", auth)
	}
	if envLookup(rendered.Env)["DOCKER_CONFIG"] == "" {
		t.Fatal("DOCKER_CONFIG missing")
	}
	rendered = renderBuiltin(t, "docker", "", map[string][]byte{
		"username": []byte("deploy-user"), "password": []byte("s3cret"), "registry": []byte("registry.example.com:5000/team"),
	}, nil)
	if registry, _ := dockerAuth(t, rendered); registry != "registry.example.com:5000/team" {
		t.Fatalf("custom registry %q", registry)
	}
	for _, slots := range []map[string][]byte{
		{"username": []byte("user:name"), "password": []byte("secret")},
		{"username": []byte("user"), "password": []byte("sec\nret")},
		{"username": []byte("user"), "password": []byte("sec\x00ret")},
		{"username": []byte("user"), "password": []byte("secret"), "registry": []byte("host name")},
		{"username": []byte("user"), "password": []byte("secret"), "registry": []byte("host\nname")},
		{"username": []byte("user"), "password": []byte("   ")},
	} {
		if _, err := Render(Lookup0(t, "docker").Spec(), t.TempDir(), "", slots, nil); err == nil {
			t.Fatalf("docker accepted unsafe slots %v", slots)
		}
	}
}

func TestRenderNPM(t *testing.T) {
	rendered := renderBuiltin(t, "npm", "", map[string][]byte{"token": []byte("npm-secret")}, nil)
	file := findRenderedFile(t, rendered.Files, "npm/npmrc")
	if file.Mode.Perm() != 0600 || string(file.Content) != "//registry.npmjs.org/:_authToken=npm-secret\n" {
		t.Fatalf("npmrc %q", file.Content)
	}
	if envLookup(rendered.Env)["NPM_CONFIG_USERCONFIG"] == "" {
		t.Fatal("NPM_CONFIG_USERCONFIG missing")
	}
	cases := []struct {
		registry string
		want     string
	}{
		{"https://registry.example.com", "//registry.example.com/"},
		{"http://registry.example.com/path", "//registry.example.com/path/"},
		{"registry.example.com:8080", "//registry.example.com:8080/"},
		{"//registry.example.com/scope/", "//registry.example.com/scope/"},
	}
	for _, test := range cases {
		rendered := renderBuiltin(t, "npm", "", map[string][]byte{"token": []byte("secret"), "registry": []byte(test.registry)}, nil)
		want := test.want + ":_authToken=secret\n"
		if got := string(findRenderedFile(t, rendered.Files, "npm/npmrc").Content); got != want {
			t.Fatalf("registry %q rendered %q", test.registry, got)
		}
	}
	for _, slots := range []map[string][]byte{
		{"token": []byte("bad\ntoken")},
		{"token": []byte("bad token")},
		{"token": []byte("bad\rtoken")},
		{"token": []byte("ok"), "registry": []byte("registry example.com")},
		{"token": []byte("ok"), "registry": []byte("registry\n.example.com")},
		{"token": []byte("ok"), "registry": []byte("ftp://registry.example.com")},
		{"token": []byte("bad\u00a0token")},
	} {
		if _, err := Render(Lookup0(t, "npm").Spec(), t.TempDir(), "", slots, nil); err == nil {
			t.Fatalf("npm accepted unsafe slots %v", slots)
		}
	}
}

func TestRenderPSQL(t *testing.T) {
	rendered := renderBuiltin(t, "psql", "", map[string][]byte{
		"username": []byte("dbuser"),
		"password": []byte("dbpass"),
		"url":      []byte("postgres://dbuser@db.example.com:5433/prod"),
	}, nil)
	file := findRenderedFile(t, rendered.Files, "pg/pgpass")
	if file.Mode.Perm() != 0600 || string(file.Content) != "db.example.com:5433:prod:dbuser:dbpass\n" {
		t.Fatalf("pgpass %q", file.Content)
	}
	if envLookup(rendered.Env)["PGPASSFILE"] == "" {
		t.Fatal("PGPASSFILE missing")
	}
	rendered = renderBuiltin(t, "psql", "", map[string][]byte{
		"username": []byte("us:er"),
		"password": []byte(`pa\ss:word`),
		"url":      []byte("host:5433/db"),
	}, nil)
	if got, want := string(findRenderedFile(t, rendered.Files, "pg/pgpass").Content), "host:5433:db:us\\:er:pa\\\\ss\\:word\n"; got != want {
		t.Fatalf("pgpass escaping got %q want %q", got, want)
	}
	rendered = renderBuiltin(t, "psql", "", map[string][]byte{"username": []byte("u"), "password": []byte("p")}, nil)
	if got := string(findRenderedFile(t, rendered.Files, "pg/pgpass").Content); got != "*:*:*:u:p\n" {
		t.Fatalf("pgpass defaults %q", got)
	}
	if _, err := Render(Lookup0(t, "psql").Spec(), t.TempDir(), "", map[string][]byte{"username": []byte("u"), "password": []byte("p\n")}, nil); err == nil {
		t.Fatal("newline in pgpass field accepted")
	}
}

const expectedAskpassScript = "#!/bin/sh\ncase \"$1\" in\n*Username*|*username*) sed -n '1p' \"$LOCKLARK_GIT_SECRET_FILE\" ;;\n*) sed -n '2p' \"$LOCKLARK_GIT_SECRET_FILE\" ;;\nesac\n"

func TestRenderGitAndNetrc(t *testing.T) {
	rendered := renderBuiltin(t, "git", "", map[string][]byte{
		"username": []byte("deploy-user"),
		"password": []byte("s3cret"),
		"url":      []byte("https://github.com"),
	}, nil)
	want := map[string]struct {
		mode    os.FileMode
		content string
	}{
		"git/askpass_secret": {0600, "deploy-user\ns3cret\n"},
		"git/askpass.sh":     {0700, expectedAskpassScript},
		"git/netrc":          {0600, "machine github.com login deploy-user password s3cret\n"},
		"git/credentials":    {0600, "https://deploy-user:s3cret@github.com\n"},
	}
	for rel, expect := range want {
		file := findRenderedFile(t, rendered.Files, rel)
		if file.Mode.Perm() != expect.mode || string(file.Content) != expect.content {
			t.Fatalf("%s mode=%v content=%q", rel, file.Mode, file.Content)
		}
	}
	gitconfig := findRenderedFile(t, rendered.Files, "git/gitconfig")
	if gitconfig.Mode.Perm() != 0600 || !strings.HasPrefix(string(gitconfig.Content), "[credential]\n\thelper = store --file=") || !strings.HasSuffix(string(gitconfig.Content), "/git/credentials\n") {
		t.Fatalf("gitconfig %q", gitconfig.Content)
	}
	env := envLookup(rendered.Env)
	if env["GIT_TERMINAL_PROMPT"] != "0" || env["GIT_ASKPASS"] == "" || env["LOCKLARK_GIT_SECRET_FILE"] == "" || env["GIT_CONFIG_GLOBAL"] == "" || env["NETRC"] == "" {
		t.Fatalf("git environment %v", env)
	}

	rendered = renderBuiltin(t, "git", "", map[string][]byte{
		"username": []byte("deploy:user"),
		"password": []byte("p@ss"),
		"url":      []byte("https://github.com"),
	}, nil)
	if got := string(findRenderedFile(t, rendered.Files, "git/credentials").Content); got != "https://deploy%3Auser:p%40ss@github.com\n" {
		t.Fatalf("escaped credentials %q", got)
	}

	rendered = renderBuiltin(t, "netrc", "", map[string][]byte{
		"username": []byte("netrc-user"),
		"password": []byte("netrc-pass"),
		"url":      []byte("https://example.com"),
	}, nil)
	netrc := findRenderedFile(t, rendered.Files, "home/.netrc")
	if netrc.Mode.Perm() != 0600 || string(netrc.Content) != "machine example.com login netrc-user password netrc-pass\n" {
		t.Fatalf("netrc %q", netrc.Content)
	}
	if envLookup(rendered.Env)["NETRC"] == "" {
		t.Fatal("NETRC missing")
	}
	rendered = renderBuiltin(t, "netrc", "", map[string][]byte{"username": []byte("u"), "password": []byte("p")}, nil)
	if string(findRenderedFile(t, rendered.Files, "home/.netrc").Content) != "machine github.com login u password p\n" {
		t.Fatal("netrc default host missing")
	}
	for _, slots := range []map[string][]byte{
		{"username": []byte("user name"), "password": []byte("p")},
		{"username": []byte("u"), "password": []byte("pass\tword")},
		{"username": []byte("u"), "password": []byte("pass\nword")},
	} {
		if _, err := Render(Lookup0(t, "netrc").Spec(), t.TempDir(), "", slots, nil); err == nil {
			t.Fatalf("netrc accepted %v", slots)
		}
	}
}

func TestRenderValidation(t *testing.T) {
	spec := Lookup0(t, "gh").Spec()
	slots := map[string][]byte{"token": []byte("secret")}
	for _, root := range []string{"", "relative", "/tmp/nul\x00root"} {
		if _, err := Render(spec, root, "", slots, nil); err == nil {
			t.Fatalf("root %q accepted", root)
		}
	}
	for _, bad := range []map[string][]byte{
		{},
		{"token": []byte("   ")},
		{"token": []byte("bad\x00value")},
		{"token": []byte{0xff}},
		{"token": make([]byte, maxSlotBytes+1)},
		{"unknown": []byte("value"), "token": []byte("secret")},
	} {
		if _, err := Render(spec, t.TempDir(), "", bad, nil); err == nil {
			t.Fatalf("slots accepted: %v", bad)
		}
	}
	tokenProfile := Lookup0(t, "token").Spec()
	if _, err := Render(tokenProfile, t.TempDir(), "", map[string][]byte{"token": []byte("x")}, nil); err == nil {
		t.Fatal("dynamic profile without token name accepted")
	}
	if _, err := Render(tokenProfile, t.TempDir(), "bad-token-name", map[string][]byte{"token": []byte("x")}, nil); err == nil {
		t.Fatal("invalid dynamic token name accepted")
	}
	terraform := Lookup0(t, "terraform").Spec()
	if _, err := Render(terraform, t.TempDir(), "", map[string][]byte{}, nil); err == nil {
		t.Fatal("all-optional profile accepted no values")
	}
	if _, err := Render(terraform, t.TempDir(), "", map[string][]byte{"aws_access_key_id": []byte("key")}, nil); err == nil {
		t.Fatal("incomplete AWS pair accepted")
	}
	if _, err := Render(terraform, t.TempDir(), "", map[string][]byte{"token": []byte("token")}, nil); err != nil {
		t.Fatalf("terraform token refused: %v", err)
	}
	if _, err := Render(terraform, t.TempDir(), "", map[string][]byte{"aws_access_key_id": []byte("key"), "aws_secret_access_key": []byte("secret")}, nil); err != nil {
		t.Fatalf("complete AWS pair refused: %v", err)
	}
	if _, err := Render(spec, t.TempDir(), "", slots, map[string]string{"GITHUB_TOKEN": "x"}); err == nil {
		t.Fatal("unlisted passthrough accepted")
	}
	if _, err := Render(spec, t.TempDir(), "", slots, map[string]string{"GH_HOST": "bad\x00host"}); err == nil {
		t.Fatal("NUL passthrough accepted")
	}
	custom := CloneSpec(spec)
	custom.Files = []FileSpec{{RelPath: "x", Format: "unknown", Mode: 0600}}
	if _, err := Render(custom, t.TempDir(), "", slots, nil); err == nil {
		t.Fatal("unknown file format accepted")
	}
	custom = CloneSpec(spec)
	custom.Files = []FileSpec{{RelPath: "x", Format: "raw-slot:missing", Mode: 0600}}
	if _, err := Render(custom, t.TempDir(), "", slots, nil); err == nil {
		t.Fatal("unknown raw slot accepted")
	}
	custom = CloneSpec(spec)
	custom.Env = map[string]string{"BAD": "file:../escape"}
	if _, err := Render(custom, t.TempDir(), "", slots, nil); err == nil {
		t.Fatal("escaping file env accepted")
	}
	custom = CloneSpec(spec)
	custom.Slots = append(custom.Slots, custom.Slots[0])
	if _, err := Render(custom, t.TempDir(), "", slots, nil); err == nil {
		t.Fatal("duplicate slot accepted")
	}
}

func TestNeedsAuth(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"--version"}, {"-v"}, {"help"}, {"version"}, {"completion"}, {"--profile=prod", "help"}, {"auth", "--help"}} {
		if DefaultNeedsAuth(args) {
			t.Fatalf("%v should not need auth", args)
		}
	}
	for _, args := range [][]string{{"api", "user"}, {"config", "--global"}, {"-v", "extra"}, {"help-me"}, {"auth", "login"}, {"--profile", "x", "help"}} {
		if !DefaultNeedsAuth(args) {
			t.Fatalf("%v should need auth", args)
		}
	}
	for _, profile := range List() {
		if profile.NeedsAuth([]string{"--help"}) || !profile.NeedsAuth([]string{"run"}) {
			t.Fatalf("%s NeedsAuth mismatch", profile.Name())
		}
	}
}

func TestValidateArgs(t *testing.T) {
	cases := []struct {
		profile string
		denied  [][]string
		allowed [][]string
	}{
		{"gh", [][]string{{"auth", "login"}, {"auth", "setup-git"}, {"auth", "token"}, {"auth", "refresh"}, {"--hostname", "h", "auth", "login"}}, [][]string{{"api", "user"}, {"pr", "list"}, {"--help"}}},
		{"aws", [][]string{{"configure"}, {"--region", "us-east-1", "configure"}, {"s3", "ls", "configure"}}, [][]string{{"s3", "ls"}, {"ec2", "describe-instances"}}},
		{"kubectl", [][]string{{"config", "set-credentials", "x"}, {"config", "set-cluster", "x"}, {"config", "set-context", "x"}, {"--kubeconfig", "k", "config", "set-credentials", "x"}, {"config", "--kubeconfig=k", "set-context", "x"}}, [][]string{{"get", "pods"}, {"config", "view"}, {"config", "--local", "view"}}},
		{"docker", [][]string{{"login"}, {"logout"}, {"build", "--tag", "login"}}, [][]string{{"run", "alpine"}, {"ps"}}},
		{"npm", [][]string{{"login"}, {"adduser"}, {"logout"}}, [][]string{{"install", "express"}, {"run", "build"}}},
		{"terraform", [][]string{{"login"}, {"logout"}}, [][]string{{"plan"}, {"apply", "-auto-approve"}}},
		{"git", [][]string{{"config", "--global", "user.name", "x"}, {"-c", "x=y", "config", "--system", "user.name", "x"}, {"credential", "approve"}, {"credential", "reject"}, {"config", "--kubeconfig=x", "--global"}}, [][]string{{"config", "--local", "user.name", "x"}, {"push", "origin", "main"}, {"status"}}},
		{"stripe", [][]string{{"login"}, {"logout"}}, [][]string{{"payment-links", "create"}}},
		{"flyctl", [][]string{{"auth", "login"}, {"auth", "logout"}, {"auth", "token"}}, [][]string{{"deploy"}, {"status"}}},
		{"vercel", [][]string{{"login"}, {"logout"}}, [][]string{{"deploy"}, {"ls"}}},
	}
	for _, test := range cases {
		spec := Lookup0(t, test.profile).Spec()
		for _, args := range test.denied {
			if err := ValidateArgs(spec, args); !errors.Is(err, ErrDeniedArgs) || err == nil || !strings.Contains(err.Error(), "denied") {
				t.Fatalf("%s denied args %v accepted: %v", test.profile, args, err)
			}
		}
		for _, args := range test.allowed {
			if err := ValidateArgs(spec, args); err != nil {
				t.Fatalf("%s allowed args %v refused: %v", test.profile, args, err)
			}
		}
	}
	if err := ValidateArgs(Spec{}, []string{"anything"}); err != nil {
		t.Fatal("empty deny list refused")
	}
}

func TestValidEnvironmentNames(t *testing.T) {
	for _, name := range []string{"TOKEN", "API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY"} {
		if !ValidEnvName(name) || !ValidTokenEnvName(name) {
			t.Fatalf("valid token name %q refused", name)
		}
	}
	if !ValidEnvName("A_1") {
		t.Fatal("valid environment name refused")
	}
	for _, name := range []string{"", "1TOKEN", "bad-name", "bad name", strings.Repeat("A", 129), "SystemRoot", "gh_token"} {
		if ValidTokenEnvName(name) {
			t.Fatalf("invalid token name %q accepted", name)
		}
	}
	if !ValidEnvName("Mixed_Case_9") {
		t.Fatal("valid mixed-case environment name refused")
	}
}

func TestValidPassthroughName(t *testing.T) {
	aws := Lookup0(t, "aws").Spec()
	docker := Lookup0(t, "docker").Spec()
	psql := Lookup0(t, "psql").Spec()
	for name, value := range map[string]string{"AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "eu-west-1", "AWS_DEFAULT_OUTPUT": "json", "AWS_CA_BUNDLE": "/tmp/ca.pem", "NO_COLOR": "1", "TERM": "xterm"} {
		if !ValidPassthroughName(aws, name, value) {
			t.Fatalf("aws passthrough %q refused", name)
		}
	}
	if !ValidPassthroughName(docker, "DOCKER_HOST", "unix:///run/docker.sock") {
		t.Fatal("DOCKER_HOST refused")
	}
	if !ValidPassthroughName(psql, "PGHOST", "db.example.com") {
		t.Fatal("PGHOST refused")
	}
	for _, name := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "HTTPS_PROXY", "NODE_OPTIONS", "PATH", "SystemRoot", "GIT_ASKPASS", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "PGPASSWORD", "XDG_CONFIG_HOME", "LOCKLARK_SECRET", "_PRIVATE"} {
		if ValidPassthroughName(aws, name, "value") {
			t.Fatalf("denied passthrough %q accepted", name)
		}
	}
	if ValidPassthroughName(aws, "AWS_REGION", "bad\x00value") {
		t.Fatal("NUL passthrough value accepted")
	}
	if ValidPassthroughName(aws, "AWS_REGION", strings.Repeat("x", 4097)) {
		t.Fatal("oversized passthrough value accepted")
	}
	if ValidPassthroughName(aws, "GH_HOST", "github.com") {
		t.Fatal("unlisted passthrough accepted")
	}
}
