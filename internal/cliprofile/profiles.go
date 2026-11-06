package cliprofile

import "sort"

type staticProfile struct {
	name        string
	executables []string
	spec        Spec
}

func (p staticProfile) Name() string { return p.name }

func (p staticProfile) Executables() []string { return append([]string(nil), p.executables...) }

func (p staticProfile) Spec() Spec { return CloneSpec(p.spec) }

func (p staticProfile) NeedsAuth(args []string) bool { return DefaultNeedsAuth(args) }

var builtinProfiles = map[string]Profile{
	"gh": staticProfile{
		name:        "gh",
		executables: []string{"gh"},
		spec: Spec{
			ID: "gh-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
			},
			Env:            map[string]string{"GH_TOKEN": "slot:token"},
			PassthroughEnv: []string{"GH_HOST", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "TERM"},
			MaxTimeout:     300,
			DenyArgs:       [][]string{{"auth", "login"}, {"auth", "setup-git"}, {"auth", "token"}, {"auth", "refresh"}},
		},
	},
	"aws": staticProfile{
		name:        "aws",
		executables: []string{"aws"},
		spec: Spec{
			ID: "aws-env-v1",
			Slots: []Slot{
				{Name: "access_key_id", Kind: "login", Field: FieldUsername, RequireNonBlank: true},
				{Name: "secret_access_key", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
				{Name: "session_token", Kind: "login", Field: FieldPassword, Optional: true},
			},
			Dirs: []string{"aws"},
			Files: []FileSpec{
				{RelPath: "aws/config", Format: "empty-v1", Mode: 0600},
				{RelPath: "aws/credentials", Format: "empty-v1", Mode: 0600},
			},
			Env: map[string]string{
				"AWS_ACCESS_KEY_ID":           "slot:access_key_id",
				"AWS_SECRET_ACCESS_KEY":       "slot:secret_access_key",
				"AWS_SESSION_TOKEN":           "slot:session_token",
				"AWS_CONFIG_FILE":             "file:aws/config",
				"AWS_SHARED_CREDENTIALS_FILE": "file:aws/credentials",
				"AWS_PAGER":                   "literal:",
			},
			PassthroughEnv: []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_DEFAULT_OUTPUT", "AWS_CA_BUNDLE", "NO_COLOR", "TERM"},
			MaxTimeout:     3600,
			DenyArgs:       [][]string{{"configure"}},
		},
	},
	"kubectl": staticProfile{
		name:        "kubectl",
		executables: []string{"kubectl", "helm"},
		spec: Spec{
			ID: "kubectl-kubeconfig-v1",
			Slots: []Slot{
				{Name: "kubeconfig", Kind: "document", Field: FieldAttachment, RequireNonBlank: true},
			},
			Dirs: []string{"kube"},
			Files: []FileSpec{
				{RelPath: "kube/config", Format: "raw-slot:kubeconfig", Mode: 0600},
			},
			Env:            map[string]string{"KUBECONFIG": "file:kube/config", "KUBECACHEDIR": "root:cache"},
			PassthroughEnv: []string{"TERM", "NO_COLOR", "KUBE_EDITOR"},
			MaxTimeout:     28800,
			DenyArgs:       [][]string{{"config", "set-credentials"}, {"config", "set-cluster"}, {"config", "set-context"}},
		},
	},
	"docker": staticProfile{
		name:        "docker",
		executables: []string{"docker"},
		spec: Spec{
			ID: "docker-config-v1",
			Slots: []Slot{
				{Name: "username", Kind: "login", Field: FieldUsername, RequireNonBlank: true},
				{Name: "password", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
				{Name: "registry", Kind: "login", Field: FieldURL, Optional: true},
			},
			Dirs: []string{"docker"},
			Files: []FileSpec{
				{RelPath: "docker/config.json", Format: "docker-auths-v1", Mode: 0600},
			},
			Env:            map[string]string{"DOCKER_CONFIG": "root:docker"},
			PassthroughEnv: []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_BUILDKIT", "TERM", "NO_COLOR"},
			MaxTimeout:     28800,
			DenyArgs:       [][]string{{"login"}, {"logout"}},
		},
	},
	"npm": staticProfile{
		name:        "npm",
		executables: []string{"npm", "pnpm", "yarn"},
		spec: Spec{
			ID: "npm-npmrc-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
				{Name: "registry", Kind: "login", Field: FieldURL, Optional: true},
			},
			Dirs: []string{"npm"},
			Files: []FileSpec{
				{RelPath: "npm/npmrc", Format: "npmrc-v1", Mode: 0600},
			},
			Env:            map[string]string{"NPM_CONFIG_USERCONFIG": "file:npm/npmrc", "NPM_CONFIG_CACHE": "root:cache"},
			PassthroughEnv: []string{"TERM", "NO_COLOR"},
			MaxTimeout:     1800,
			DenyArgs:       [][]string{{"login"}, {"adduser"}, {"logout"}},
		},
	},
	"terraform": staticProfile{
		name:        "terraform",
		executables: []string{"terraform", "tofu"},
		spec: Spec{
			ID: "terraform-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, Optional: true},
				{Name: "aws_access_key_id", Kind: "login", Field: FieldUsername, Optional: true},
				{Name: "aws_secret_access_key", Kind: "login", Field: FieldPassword, Optional: true},
			},
			Dirs: []string{"terraform"},
			Files: []FileSpec{
				{RelPath: "terraform/terraform.rc", Format: "empty-v1", Mode: 0600},
			},
			Env: map[string]string{
				"TF_TOKEN_app_terraform_io": "slot:token",
				"AWS_ACCESS_KEY_ID":         "slot:aws_access_key_id",
				"AWS_SECRET_ACCESS_KEY":     "slot:aws_secret_access_key",
				"TF_CLI_CONFIG_FILE":        "file:terraform/terraform.rc",
			},
			PassthroughEnv: []string{"TF_PLUGIN_CACHE_DIR", "AWS_REGION", "AWS_DEFAULT_REGION", "TF_LOG", "TERM", "NO_COLOR"},
			MaxTimeout:     7200,
			DenyArgs:       [][]string{{"login"}, {"logout"}},
		},
	},
	"git": staticProfile{
		name:        "git",
		executables: []string{"git"},
		spec: Spec{
			ID: "git-askpass-v1",
			Slots: []Slot{
				{Name: "username", Kind: "login", Field: FieldUsername, RequireNonBlank: true},
				{Name: "password", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
				{Name: "url", Kind: "login", Field: FieldURL, Optional: true},
			},
			Dirs: []string{"git"},
			Files: []FileSpec{
				{RelPath: "git/askpass_secret", Format: "git-askpass-secret-v1", Mode: 0600},
				{RelPath: "git/askpass.sh", Format: "git-askpass-helper-v1", Mode: 0700},
				{RelPath: "git/netrc", Format: "netrc-v1", Mode: 0600},
				{RelPath: "git/credentials", Format: "git-credentials-v1", Mode: 0600},
				{RelPath: "git/gitconfig", Format: "git-config-store-v1", Mode: 0600},
			},
			Env: map[string]string{
				"GIT_ASKPASS":              "file:git/askpass.sh",
				"LOCKLARK_GIT_SECRET_FILE": "file:git/askpass_secret",
				"GIT_CONFIG_GLOBAL":        "file:git/gitconfig",
				"NETRC":                    "file:git/netrc",
				"GIT_TERMINAL_PROMPT":      "literal:0",
			},
			PassthroughEnv: []string{"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "TERM", "NO_COLOR"},
			MaxTimeout:     1800,
			DenyArgs:       [][]string{{"config", "--global"}, {"config", "--system"}, {"credential", "approve"}, {"credential", "reject"}},
		},
	},
	"netrc": staticProfile{
		name:        "netrc",
		executables: []string{"curl"},
		spec: Spec{
			ID: "netrc-v1",
			Slots: []Slot{
				{Name: "username", Kind: "login", Field: FieldUsername, RequireNonBlank: true},
				{Name: "password", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
				{Name: "url", Kind: "login", Field: FieldURL, Optional: true},
			},
			Files: []FileSpec{
				{RelPath: "home/.netrc", Format: "netrc-v1", Mode: 0600},
			},
			Env:            map[string]string{"NETRC": "file:home/.netrc"},
			PassthroughEnv: []string{"TERM", "NO_COLOR"},
			MaxTimeout:     600,
		},
	},
	"psql": staticProfile{
		name:        "psql",
		executables: []string{"psql", "pg_dump", "pg_restore"},
		spec: Spec{
			ID: "psql-pgpass-v1",
			Slots: []Slot{
				{Name: "username", Kind: "login", Field: FieldUsername, RequireNonBlank: true},
				{Name: "password", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
				{Name: "url", Kind: "login", Field: FieldURL, Optional: true},
			},
			Dirs: []string{"pg"},
			Files: []FileSpec{
				{RelPath: "pg/pgpass", Format: "pgpass-v1", Mode: 0600},
			},
			Env:            map[string]string{"PGPASSFILE": "file:pg/pgpass"},
			PassthroughEnv: []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSSLMODE", "TERM", "NO_COLOR"},
			MaxTimeout:     28800,
		},
	},
	"openai": staticProfile{
		name:        "openai",
		executables: []string{"openai"},
		spec: Spec{
			ID: "openai-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
			},
			Env:            map[string]string{"OPENAI_API_KEY": "slot:token"},
			PassthroughEnv: []string{"OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "OPENAI_BASE_URL", "TERM", "NO_COLOR"},
			MaxTimeout:     600,
		},
	},
	"anthropic": staticProfile{
		name:        "anthropic",
		executables: []string{"anthropic", "claude"},
		spec: Spec{
			ID: "anthropic-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
			},
			Env:            map[string]string{"ANTHROPIC_API_KEY": "slot:token"},
			PassthroughEnv: []string{"TERM", "NO_COLOR"},
			MaxTimeout:     600,
		},
	},
	"stripe": staticProfile{
		name:        "stripe",
		executables: []string{"stripe"},
		spec: Spec{
			ID: "stripe-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
			},
			Env:            map[string]string{"STRIPE_API_KEY": "slot:token"},
			PassthroughEnv: []string{"TERM", "NO_COLOR"},
			MaxTimeout:     600,
			DenyArgs:       [][]string{{"login"}, {"logout"}},
		},
	},
	"flyctl": staticProfile{
		name:        "flyctl",
		executables: []string{"flyctl", "fly"},
		spec: Spec{
			ID: "flyctl-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
			},
			Env:            map[string]string{"FLY_API_TOKEN": "slot:token"},
			PassthroughEnv: []string{"FLY_APP", "FLY_REGION", "TERM", "NO_COLOR"},
			MaxTimeout:     1800,
			DenyArgs:       [][]string{{"auth", "login"}, {"auth", "logout"}, {"auth", "token"}},
		},
	},
	"vercel": staticProfile{
		name:        "vercel",
		executables: []string{"vercel", "vc"},
		spec: Spec{
			ID: "vercel-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
			},
			Env:            map[string]string{"VERCEL_TOKEN": "slot:token"},
			PassthroughEnv: []string{"VERCEL_ORG_ID", "VERCEL_PROJECT_ID", "TERM", "NO_COLOR"},
			MaxTimeout:     1800,
			DenyArgs:       [][]string{{"login"}, {"logout"}},
		},
	},
	"token": staticProfile{
		name:        "token",
		executables: []string{},
		spec: Spec{
			ID: "token-v1",
			Slots: []Slot{
				{Name: "token", Kind: "login", Field: FieldPassword, RequireNonBlank: true},
			},
			DynamicTokenEnv: true,
			PassthroughEnv:  []string{"TERM", "NO_COLOR"},
			MaxTimeout:      300,
		},
	},
}

var builtinNames []string

func init() {
	builtinNames = make([]string, 0, len(builtinProfiles))
	for name := range builtinProfiles {
		builtinNames = append(builtinNames, name)
	}
	sort.Strings(builtinNames)
}
