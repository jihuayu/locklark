# CLI wrappers (`locklark cli`)

Stage 2 / Feature F16 of Milestone M4 adds first-class wrappers around local
command-line tools. A wrapper binds a tool name such as `gh`, `aws` or
`kubectl` to:

- one built-in credential profile,
- one owner-only vault path,
- one pinned executable,
- immutable vault-item targets for every profile slot.

Credentials are read only when the wrapped command is executed. The binding
file contains IDs, revisions, paths and policy metadata, never usernames,
passwords, tokens, attachments or notes.

> `locklark plugin` remains reserved for the signed plugin catalog. CLI
> wrappers are always managed with `locklark cli`.

## Contents

1. [Architecture and security invariants](#architecture-and-security-invariants)
2. [Built-in profiles](#built-in-profiles)
3. [The `.locklark-cli.json` schema](#the-locklark-clijson-schema)
4. [Usage](#usage)
5. [Troubleshooting](#troubleshooting)
6. [Limits and threat model](#limits-and-threat-model)

## Architecture and security invariants

The feature is split into three layers:

| Layer | Location | Responsibility |
| --- | --- | --- |
| Profile registry | `internal/cliprofile` | Declarative slots, environment bindings, isolated files, denied arguments and timeouts. No side effects, no process execution. |
| Binding store | `internal/clibinding` | Owner-only JSON binding file, path/profile/target validation, executable SHA-256 pinning, trusted-parent and no-symlink checks. |
| Command integration | `cmd/locklark/cli.go` | Argument parsing, interactive disclosure, controlling-console factors, `personal.RunBundle` invocation and exit-status propagation. |

The authenticated path builds on the isolated multi-credential runner added in
PR #41. Historically `personal.RunCLI` supported one token (`gh` or a dynamic
token environment); `personal.RunBundle` generalizes that contract to multiple
vault items and profile slots while preserving the same safety rules.

### Execution paths

`locklark cli run <tool>` first loads the binding store, finds the tool and
calls `clibinding.VerifyProgram`. Validation and the executable SHA-256 pin are
checked before any prompt or child start.

1. **Metadata and policy checks**
   - profile lookup,
   - absolute, clean, bounded paths,
   - target IDs/revisions and slot fields,
   - helper-directory and passthrough allow-lists,
   - timeout bounds and dynamic token environment name,
   - regular-file check and SHA-256 pin match.
2. **Denied-argument check** via `cliprofile.ValidateArgs`. This happens
   before a controlling terminal is opened, before a password is requested and
   before the child is started.
3. **Fast path** when `Profile.NeedsAuth(args)` is false (`--help`,
   `-h`, `--version`, `help`, `version`, `completion`, and similar
   informational invocations).
   - The pinned executable is started directly.
   - It inherits the real standard streams and the original child exit status.
   - `personal.RunCLIInformational` creates the same trusted owner-only
     temporary root as authenticated runs. The child receives isolated
     `HOME`/`GH_CONFIG_DIR`/`XDG_*`/`TMPDIR` paths, the explicit helper `PATH`,
     the recursion guard `LOCKLARK_CLI_ACTIVE=<tool>`, and only the profile's
     explicitly bound non-secret passthrough variables. It receives no
     ambient `GH_TOKEN`, `DEEPSEEK_API_KEY`, `DEEPSEEK_STATE_DIR`, proxy,
     loader or user config environment, and no slot is rendered.
   - No vault is unlocked, no authentication prompt is shown and no credential
     material is rendered or written.
4. **Authenticated path**
   - `personal.RunBundleRequest.Validate` runs before the controlling console
     is opened.
   - Locklark opens `/dev/tty` (Unix) or `CONIN$`/`CONOUT$` (Windows), disables
     echo with `term.MakeRaw`, and reads `主密码` and `Secret Key` from that
     console, never from a pipe.
   - A disclosure summary lists the tool, profile, vault, executable,
     executable digest, working directory, timeout, every slot target, the
     environment variable **names**, the ephemeral files and their modes, the
     allow-listed passthrough names, the helper `PATH`, and the full argv.
   - The operator must type `RUN`. Anything else cancels before the vault is
     queried.
   - `personal.RunBundle` commits a journal intent with action
     `item.run.bundle` before rendering credentials, derives a one-time key
     with HKDF domain `locklark/personal/run-bundle/key/v1`, creates an
     isolated `0700` run root, wires the explicit helper `PATH`, and starts one
     direct child with inherited standard streams.
   - Credential files are materialized with `0600` (`0700` for the git askpass
     helper), under the isolated run root, and removed after the process ends.

### Security invariants inherited from PR #41

- **No ambient environment.** On Unix the child base environment is empty; on
  Windows it contains only the OS `SystemRoot`. The runner adds explicit
  `HOME`, `GH_CONFIG_DIR`, XDG directories, temporary directories, `PATH` and
  the profile's declared variables. Proxy, debug, loader and unrelated token
  variables are not inherited.
- **Isolated root.** The run root is created below the OS user temporary
  location, is owner-only, and contains `home/`, `gh/`, `config/`, `cache/`,
  `data/`, `tmp/` and profile-specific directories. It is removed after the
  process, including on ordinary errors.
- **One authenticated transaction.** Every target is read in one vault
  transaction and checked against its expected immutable revision. A stale,
  missing, trashed or kind-mismatched item fails the whole bundle; no partial
  credential set is disclosed.
- **Journaled intent.** The `item.run.bundle` intent is committed before any
  credential file or environment value exists. Receipts contain a session,
  intent digest, target digest and exit code; they never contain credential
  values, executable paths or working directories.
- **Credential files are short-lived.** Files live only under the one-time
  `0700` root. They are written with explicit owner-only modes, never by
  following a final-component symlink.
- **Controlling-terminal factors.** The master password and Secret Key are read
  from a newly opened controlling terminal with echo disabled. Pipe input
  cannot supply them, and prompt text is written only to the control terminal.
- **Explicit consent.** The disclosure is rendered before startup, and the
  literal `RUN` is required. The child's standard streams are inherited, not
  captured or recorded by Locklark.
- **No persistent authentication.** The bundled profiles refuse commands that
  would log in, persist credentials, rewrite global tool configuration or
  install global credential helpers.
- **Recursion guard for the fast path.** A fast-path child receives
  `LOCKLARK_CLI_ACTIVE=<tool>`. Any nested `locklark cli run` refuses
  immediately. Authenticated execution intentionally starts from the isolated
  base environment described above, so unrelated parent guard variables are
  not inherited by that child.
- **Pinned executable.** Binding records a SHA-256 digest of the executable by
  default. `clibinding.VerifyProgram` re-hashes the regular file on every run,
  so replacing or modifying the program after binding is refused.

## Built-in profiles

The current build contains 24 deterministic, side-effect-free profiles. A slot is one encrypted vault
field:

- `login` slots can target `username`, `password`, `url` or `notes`.
- `document` slots can target `attachment` or `filename`.
- Required slots must have a target. Optional slots may be omitted.
- A target stores the vault item `id`, the expected item `revision`, and the
  exact field name. Revisions are immutable snapshots: an updated item must be
  rebound before it can be used again.

### Profile matrix A: executables, slots, environment, timeout, denied arguments

| Profile | Executable(s) | Slots | Environment injected | Max timeout | Denied arguments |
| --- | --- | --- | --- | --- | --- |
| `gh` | `gh` | `token` = password (required) | `GH_TOKEN=slot:token` | 300 s | `auth login`, `auth setup-git`, `auth token`, `auth refresh` |
| `glab` | `glab` | `token` = password (required) | `GITLAB_TOKEN=slot:token` | 600 s | `auth login`, `auth logout`, `auth switch` |
| `aws` | `aws` | `access_key_id` = username (required)<br>`secret_access_key` = password (required)<br>`session_token` = password (optional) | `AWS_ACCESS_KEY_ID`<br>`AWS_SECRET_ACCESS_KEY`<br>`AWS_SESSION_TOKEN`<br>`AWS_CONFIG_FILE=file:aws/config`<br>`AWS_SHARED_CREDENTIALS_FILE=file:aws/credentials`<br>`AWS_PAGER=` (empty literal) | 3600 s | `configure` |
| `deepseek` | — (absolute Python interpreter must be supplied with `--program`) | `token` = password (required) | `DEEPSEEK_API_KEY=slot:token` | 3600 s | `configure`, `spawn`, `--background` |
| `kubectl` | `kubectl`, `helm` | `kubeconfig` = attachment (required document) | `KUBECONFIG=file:kube/config`<br>`KUBECACHEDIR=root:cache` | 28800 s | `config set-credentials`, `config set-cluster`, `config set-context` |
| `docker` | `docker` | `username` = username (required)<br>`password` = password (required)<br>`registry` = url (optional) | `DOCKER_CONFIG=root:docker` | 28800 s | `login`, `logout` |
| `npm` | `npm`, `pnpm`, `yarn` | `token` = password (required)<br>`registry` = url (optional) | `NPM_CONFIG_USERCONFIG=file:npm/npmrc`<br>`NPM_CONFIG_CACHE=root:cache` | 1800 s | `login`, `adduser`, `logout` |
| `terraform` | `terraform`, `tofu` | `token` = password (optional)<br>`aws_access_key_id` = username (optional)<br>`aws_secret_access_key` = password (optional) | `TF_TOKEN_app_terraform_io`<br>`AWS_ACCESS_KEY_ID`<br>`AWS_SECRET_ACCESS_KEY`<br>`TF_CLI_CONFIG_FILE=file:terraform/terraform.rc` | 7200 s | `login`, `logout` |
| `git` | `git` | `username` = username (required)<br>`password` = password (required)<br>`url` = url (optional) | `GIT_ASKPASS=file:git/askpass.sh`<br>`LOCKLARK_GIT_SECRET_FILE=file:git/askpass_secret`<br>`GIT_CONFIG_GLOBAL=file:git/gitconfig`<br>`NETRC=file:git/netrc`<br>`GIT_TERMINAL_PROMPT=0` | 1800 s | `config --global`, `config --system`, `credential approve`, `credential reject` |
| `netrc` | `curl` | `username` = username (required)<br>`password` = password (required)<br>`url` = url (optional) | `NETRC=file:home/.netrc` | 600 s | — |
| `psql` | `psql`, `pg_dump`, `pg_restore` | `username` = username (required)<br>`password` = password (required)<br>`url` = url (optional) | `PGPASSFILE=file:pg/pgpass` | 28800 s | — |
| `openai` | `openai` | `token` = password (required) | `OPENAI_API_KEY=slot:token` | 600 s | — |
| `codex` | `codex` | `token` = password (required) | `CODEX_HOME=root:codex`; API key in `codex/auth.json` | 600 s | `login`, `logout` |
| `anthropic` | `anthropic`, `claude` | `token` = password (required) | `ANTHROPIC_API_KEY=slot:token` | 600 s | — |
| `stripe` | `stripe` | `token` = password (required) | `STRIPE_API_KEY=slot:token` | 600 s | `login`, `logout` |
| `flyctl` | `flyctl`, `fly` | `token` = password (required) | `FLY_API_TOKEN=slot:token` | 1800 s | `auth login`, `auth logout`, `auth token` |
| `vercel` | `vercel`, `vc` | `token` = password (required) | `VERCEL_TOKEN=slot:token` | 1800 s | `login`, `logout` |
| `wrangler` | `wrangler` | `token` = password (required) | `CLOUDFLARE_API_TOKEN=slot:token` | 1800 s | `login`, `logout`, `auth token` |
| `supabase` | `supabase` | `token` = password (required) | `SUPABASE_ACCESS_TOKEN=slot:token` | 1800 s | `login`, `logout` |
| `railway` | `railway` | `token` = password (required, project token) | `RAILWAY_TOKEN=slot:token` | 1800 s | `login`, `logout` |
| `railway-account` | `railway` | `token` = password (required, account token) | `RAILWAY_API_TOKEN=slot:token` | 1800 s | `login`, `logout` |
| `huggingface` | `hf`, `huggingface-cli` | `token` = password (required) | `HF_TOKEN=slot:token` | 600 s | `login`, `logout`, `auth login`, `auth logout` |
| `gemini` | `gemini` | `token` = password (required) | `GEMINI_API_KEY=slot:token` | 600 s | — |
| `token` | — (program must be supplied) | `token` = password (required) | Dynamic name via `--name`, e.g. `MY_API_TOKEN=slot:token` | 300 s | — |

### Profile matrix B: ephemeral files and passthrough allow-lists

All paths are relative to the isolated `0700` run root. Files are `0600`
unless a different mode is shown.

| Profile | Ephemeral credential files | Passthrough allow-list |
| --- | --- | --- |
| `gh` | — | `GH_HOST`, `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`, `TERM` |
| `aws` | `aws/config` (`0600`, empty)<br>`aws/credentials` (`0600`, empty) | `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_DEFAULT_OUTPUT`, `AWS_CA_BUNDLE`, `NO_COLOR`, `TERM` |
| `deepseek` | — (the token is environment-only; no credential file is ever created) | `DEEPSEEK_BASE_URL`, `DEEPSEEK_MODEL`, `DEEPSEEK_STATE_DIR`, `TERM`, `NO_COLOR` |
| `kubectl` | `kube/config` (`0600`, raw attachment) | `TERM`, `NO_COLOR`, `KUBE_EDITOR` |
| `docker` | `docker/config.json` (`0600`, `auths` document) | `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`, `DOCKER_BUILDKIT`, `TERM`, `NO_COLOR` |
| `npm` | `npm/npmrc` (`0600`, `_authToken`) | `TERM`, `NO_COLOR` |
| `terraform` | `terraform/terraform.rc` (`0600`, empty) | `TF_PLUGIN_CACHE_DIR`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `TF_LOG`, `TERM`, `NO_COLOR` |
| `git` | `git/askpass_secret` (`0600`)<br>`git/askpass.sh` (`0700`)<br>`git/netrc` (`0600`)<br>`git/credentials` (`0600`)<br>`git/gitconfig` (`0600`) | `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `SSH_AUTH_SOCK`, `TERM`, `NO_COLOR` |
| `netrc` | `home/.netrc` (`0600`) | `TERM`, `NO_COLOR` |
| `psql` | `pg/pgpass` (`0600`) | `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGSSLMODE`, `TERM`, `NO_COLOR` |
| `openai` | — | `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID`, `OPENAI_BASE_URL`, `TERM`, `NO_COLOR` |
| `codex` | `codex/auth.json` (`0600`, API-key auth document) | `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID`, `OPENAI_BASE_URL`, `TERM`, `NO_COLOR` |
| `anthropic` | — | `TERM`, `NO_COLOR` |
| `stripe` | — | `TERM`, `NO_COLOR` |
| `flyctl` | — | `FLY_APP`, `FLY_REGION`, `TERM`, `NO_COLOR` |
| `vercel` | — | `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID`, `TERM`, `NO_COLOR` |
| `wrangler` | — | `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_BASE_URL`, `TERM`, `NO_COLOR` |
| `supabase` | — | `TERM`, `NO_COLOR` |
| `railway` | — | `RAILWAY_ENVIRONMENT`, `TERM`, `NO_COLOR` |
| `railway-account` | — | `RAILWAY_ENVIRONMENT`, `TERM`, `NO_COLOR` |
| `huggingface` | — | `HF_ENDPOINT`, `TERM`, `NO_COLOR` |
| `gemini` | — | `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `TERM`, `NO_COLOR` |
| `token` | — | `TERM`, `NO_COLOR` |

`codex` supports API-key authentication only. It writes a short-lived
`codex/auth.json` under the isolated `CODEX_HOME`; ChatGPT OAuth credentials
are not imported or copied. `railway` uses the project token
(`RAILWAY_TOKEN`), while `railway-account` uses the account token
(`RAILWAY_API_TOKEN`) so the two credential kinds cannot be silently mixed.

The passthrough implementation additionally refuses `PATH`, `HOME`, `TMPDIR`,
loader variables, proxy variables, credential variables and every name with a
`LOCKLARK_`, `LD_`, `DYLD_`, `_`, `XDG_` prefix or a `_TOKEN`, `_API_KEY`,
`_SECRET`, `_PASSWORD`, `_ACCESS_KEY` or `_PRIVATE_KEY` suffix. A profile
allow-list is necessary but not sufficient: these hard denials always win.

`SSH_AUTH_SOCK` is the one deliberate exception: only the `git` profile may
list it, and only when the binding explicitly selects it with
`--passthrough SSH_AUTH_SOCK`. This lets a signed Git operation use the
Locklark SSH agent without inheriting an unrelated ambient agent endpoint.

### Ergonomic target selection

`locklark cli init` can build targets in several ways:

- `--id ID --revision REV` fills the single slot of one-slot profiles
  (`gh`, `glab`, `deepseek`, `kubectl`, `openai`, `codex`, `anthropic`,
  `stripe`, `flyctl`, `vercel`, `wrangler`, `supabase`, `railway`,
  `railway-account`, `huggingface`, `gemini`, `token`). `deepseek`
  additionally requires an explicit absolute `--program`; it never
  auto-discovers a Python interpreter.
- For multi-slot login profiles (`aws`, `docker`, `npm`, `git`, `netrc`,
  `psql`), the same pair fills every **required** `login` slot with the shared
  item ID/revision and each slot's own field (`username` or `password`).
  Optional slots such as `session_token`, `registry` and `url` are not
  populated automatically.
- `--login ID:REV` is an alternative convenience pair for required login
  slots. It may not disagree with `--id`/`--revision` when both are supplied.
- `--document ID:REV` fills required document slots (for example
  `kubectl`'s `kubeconfig`).
- `--slot-<name> ID:REV` sets one exact target and overrides a convenience
  pair. For example `--slot-username ID:REV`.
- `--session-token ID:REV` is shorthand for `--slot-session_token ID:REV`.

`--id` and `--revision` are indivisible: supplying only one is an argument
error. Every ID must be 32 lowercase hex characters and every revision 64
lowercase hex characters.

### Git SSH commit signing

The `git` profile keeps HTTP credentials isolated, but it can also use the
Locklark SSH agent for signed commits. Bind the endpoint name explicitly:

```sh
locklark cli init git \
  --program /absolute/path/to/git \
  --file /absolute/path/to/owner.ll \
  --id ID --revision REV \
  --passthrough SSH_AUTH_SOCK \
  --helper-path /absolute/path/to/ssh-keygen-directory
```

Then configure signing in the repository, not in the user's global Git
configuration:

```powershell
git config --local gpg.format ssh
git config --local user.signingkey C:/secure/locklark-signing.pub
git config --local gpg.ssh.program C:/Windows/System32/OpenSSH/ssh-keygen.exe
git config --local commit.gpgsign true
git config --local tag.gpgsign true
```

Set `SSH_AUTH_SOCK` to the private endpoint displayed by the desktop SSH
agent before running the wrapped command. The public key file must match the
key enabled in the agent; the private key is never written to the Git
configuration or the run root. The helper directory is required so the child
can resolve `ssh-keygen` even though Locklark starts it with an isolated
`PATH`. The `config --global` and `config --system` mutations remain refused.

### DeepSeek worker harness workflow

The `deepseek` profile is a foreground-only, single-token wrapper for a
locally trusted Python harness. It injects the vault password field as
`DEEPSEEK_API_KEY`, permits only `DEEPSEEK_BASE_URL`, `DEEPSEEK_MODEL`,
`DEEPSEEK_STATE_DIR`, `TERM` and `NO_COLOR` as passthrough, and denies
`configure`, `spawn` and `--background`. No credential file is created.

Store the DeepSeek key with the existing hidden-input personal command. The
key is typed at the controlling terminal, never on the command line:

```sh
locklark personal add-login --file "$VAULT"
# 登录标题: DeepSeek worker key
# 用户名（可留空）: (empty)
# 登录密码: <paste the DeepSeek API key at the hidden prompt>

# Read the returned id, then list to obtain the current immutable revision.
locklark personal list --file "$VAULT" --state active
# Use the row's "id" and "revision" below. Do not copy the secret value.
```

Bind the absolute Python interpreter and the single vault field. The default
pin hashes the **Python binary**; the harness script itself is trusted
separately and must be reviewed and pinned/checked by your own deployment:

```sh
VAULT=/home/alice/vaults/personal.ll
ID=0123456789abcdef0123456789abcdef
REV=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
ABS_PYTHON=/usr/bin/python3
ABS_HARNESS=/opt/deepseek-worker/harness.py
PROJECT=/home/alice/project
TASK=/home/alice/tasks/task.md
STATE=/home/alice/.local/state/deepseek-worker

locklark cli init deepseek-worker \
  --profile deepseek \
  --program "$ABS_PYTHON" \
  --file "$VAULT" \
  --id "$ID" --revision "$REV" \
  --passthrough DEEPSEEK_BASE_URL,DEEPSEEK_MODEL,DEEPSEEK_STATE_DIR \
  --timeout 3600
```

Run the harness in the foreground under Locklark's supervision. The vault key
is delivered only through the child environment; it never appears in argv,
the binding file or a persistent config file:

```sh
DEEPSEEK_STATE_DIR="$STATE" \
  locklark cli run deepseek-worker -- "$ABS_HARNESS" run --root "$PROJECT" --task-file "$TASK"
```

`DEEPSEEK_STATE_DIR` is an explicit, non-secret allow-listed path and is the
only place harness state should persist. If it is omitted, the isolated
`HOME`/`TMPDIR` is deleted after the run. `DEEPSEEK_CONFIG_FILE` is not
injected and cannot be passed through; the harness's embedded config fallback
remains, but the injected `DEEPSEEK_API_KEY` takes priority over any file
value. Do not use `--background`, `spawn` or `configure`; run the foreground
command under a separate master supervision process if background execution is
required by the caller. The child exit status is preserved.

## The `.locklark-cli.json` schema

By default the binding store is `.locklark-cli.json` in the current working
directory. If `LOCKLARK_CLI_BINDING` is set to an **absolute** path, that path
is used instead. A relative environment value is ignored rather than resolved
against the working directory. Every command accepts `--binding PATH`; `list`
also accepts `--config PATH` as an alias.

```json
{
  "version": 1,
  "bindings": {
    "gh": {
      "profile": "gh",
      "vault_path": "/home/alice/vaults/personal.ll",
      "program": "/usr/bin/gh",
      "program_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "targets": [
        {
          "slot": "token",
          "id": "0123456789abcdef0123456789abcdef",
          "revision": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          "field": "password"
        }
      ],
      "helper_path": ["/usr/bin"],
      "passthrough_env": ["GH_HOST", "NO_COLOR"],
      "timeout_seconds": 300
    },
    "my-api": {
      "profile": "token",
      "vault_path": "/home/alice/vaults/personal.ll",
      "program": "/opt/tools/my-api",
      "program_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "targets": [
        {
          "slot": "token",
          "id": "fedcba9876543210fedcba9876543210",
          "revision": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "field": "password"
        }
      ],
      "helper_path": ["/opt/tools"],
      "timeout_seconds": 300,
      "token_env_name": "MY_API_TOKEN"
    }
  }
}
```

### Schema rules

- `version` must be exactly `1`.
- `bindings` may contain at most 64 entries.
- A tool name must match `^[a-z0-9][a-z0-9_-]{0,63}$`.
- `profile` must name a built-in profile.
- `vault_path` and `program` must be absolute, clean paths no longer than 4096
  bytes, valid UTF-8, and must not contain NUL, CR or LF. On Windows the
  program must end in `.exe`.
- `program_sha256` is optional but, when present, must be 64 lowercase hex
  characters.
- `targets` must contain between 1 and the number of profile slots. Every
  slot name must exist and be unique, every required slot must be present, and
  each `field` must equal the slot's declared field.
- `helper_path` may contain at most 16 absolute, clean directories. Entries
  cannot contain the platform path-list separator. The resulting explicit
  `PATH` is the only path used for child program lookup.
- `passthrough_env` may contain at most 32 unique names, each admitted by the
  profile's allow-list and the global hard denials.
- `timeout_seconds` may be omitted (`0`); otherwise it must be from 1 through
  the profile's `max_timeout` (300 seconds if a profile declares no maximum).
- `token_env_name` is required only for the dynamic `token` profile and must be
  a valid uppercase bearer-credential name (`*_TOKEN`, `*_API_KEY`,
  `*_ACCESS_KEY`, `TOKEN` or `API_KEY`). It must be empty for all other
  profiles.

### File security

The binding file contains non-secret metadata, but it is protected as sensitive
metadata:

- The file is `0600` on Unix. On Windows it is created with a protected DACL
  granting access only to the current user.
- The parent directory must already exist, must be a real directory (not a
  symlink/reparse point), must be owned by the current user or root/trusted
  Windows principals, and must not be group- or other-writable on Unix. A
  root-owned sticky directory such as `/tmp` is accepted; a mode `0777`
  working directory is not.
- The final path component is opened with `O_NOFOLLOW` on Unix and revalidated
  after `Lstat`; Windows rejects reparse points and non-private DACLs.
- Saves use a same-directory temporary file, explicit `0600` (or a protected
  DACL on Windows), `fsync`, an atomic rename/replace, and a best-effort
  directory sync. Temporary files are removed on failure.
- `Load` rejects unknown JSON fields, trailing documents, oversized files
  (over 64 KiB), future schema versions, unsafe paths, unsafe permissions and
  every target/profile validation failure.

The binding file **never stores a credential value**. A stolen binding file
discloses tool names, vault paths, executable paths, item IDs and revisions,
but it cannot be used to read a vault field without the master password and
Secret Key.

## Usage

### Inspect profiles

```sh
locklark cli profiles
```

The output is a JSON array. Each entry contains `name`, `id`, `executables`,
`slots`, `passthrough_env` and `max_timeout`. Profile data is compiled into the
binary and is deterministic across runs.

### Create a binding

```sh
locklark cli init gh \
  --file /home/alice/vaults/personal.ll \
  --program /usr/bin/gh \
  --id 0123456789abcdef0123456789abcdef \
  --revision abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

`init` and `bind` are synonyms. The tool name can be positional, as above, or
supplied with `--tool`; `--profile` selects the underlying profile when the
wrapper name differs from a built-in profile:

```sh
locklark cli bind my-gh --profile gh \
  --file /home/alice/vaults/personal.ll \
  --program /usr/bin/gh \
  --id 0123456789abcdef0123456789abcdef \
  --revision abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

If `--program` is omitted, the tool name is resolved with `exec.LookPath`; if
that fails, each executable declared by the profile is tried. The wrapper
requires a clean absolute regular file. If `--helper-path` is omitted it
defaults to the program's directory, which becomes the child's entire explicit
`PATH`.

A successful binding prints:

```json
{
  "status": "bound",
  "tool": "gh",
  "profile": "gh",
  "program": "/usr/bin/gh",
  "program_sha256": "…64 lowercase hex…",
  "binding_file": "/home/alice/project/.locklark-cli.json"
}
```

The default is to pin the program. Disable it explicitly only when the
executable is updated in place by its own installer:

```sh
locklark cli init flyctl ... --pin-sha256 false
```

#### Multi-slot examples

AWS automatically uses one login item for both required keys:

```sh
locklark cli init aws \
  --file ~/vaults/personal.ll --program /usr/local/bin/aws \
  --id 0123456789abcdef0123456789abcdef \
  --revision abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

Docker's optional registry can be added, and any explicit slot overrides the
shared convenience pair:

```sh
locklark cli init docker \
  --file ~/vaults/personal.ll --program /usr/bin/docker \
  --id 0123456789abcdef0123456789abcdef \
  --revision abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
  --slot-registry fedcba9876543210fedcba9876543210:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

A Kubernetes document slot takes an attachment ID/revision:

```sh
locklark cli init kube --profile kubectl \
  --file ~/vaults/personal.ll --program /usr/bin/kubectl \
  --id 0123456789abcdef0123456789abcdef \
  --revision abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

A dynamic token wrapper names the environment variable explicitly:

```sh
locklark cli init my-api --profile token \
  --file ~/vaults/personal.ll --program /opt/tools/my-api \
  --name MY_API_TOKEN \
  --id 0123456789abcdef0123456789abcdef \
  --revision abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

Optional runtime policy flags:

```sh
--helper-path /opt/tools:/usr/local/bin   # explicit PATH directories
--passthrough NO_COLOR,TERM               # only names in the profile allow-list
--timeout 120                             # seconds, bounded by the profile maximum
```

### List, show and remove

```sh
locklark cli list
locklark cli list --binding /secure/path/.locklark-cli.json
locklark cli show gh
locklark cli show --tool gh --binding /secure/path/.locklark-cli.json
locklark cli remove gh
```

- `list` prints the full store as JSON. A missing default binding file prints
  the empty version-1 store. A corrupt, untrusted or unsafe existing file is
  an error.
- `show` prints one `ToolBinding` object. A missing file or tool returns
  `CLI tool binding not found`.
- `remove` deletes one tool and atomically rewrites the store, then prints
  `{"status":"removed","tool":"gh"}`.

### Generate shell functions

```sh
# bash
eval "$(locklark cli shell-init bash)"

# zsh
eval "$(locklark cli shell-init zsh)"

# fish
locklark cli shell-init fish | source

# PowerShell / pwsh
locklark cli shell-init pwsh | Out-String | Invoke-Expression
```

`--shell <name>` is equivalent to the positional shell name. The shell name
must be one of `bash`, `zsh`, `fish`, `powershell` or `pwsh`.

```sh
locklark cli shell-init bash
# Locklark CLI wrappers (bash/zsh)
gh() {
  command locklark cli run gh -- "$@"
}
```

```fish
locklark cli shell-init fish
# Locklark CLI wrappers (fish)
function gh --wraps=gh
  command locklark cli run gh -- $argv
end
```

```powershell
locklark cli shell-init pwsh
# Locklark CLI wrappers (pwsh)
function Invoke-LocklarkCli_gh {
  & locklark cli run gh -- @args
}
Set-Alias -Name gh -Value Invoke-LocklarkCli_gh
```

The emitted objects are functions (with a PowerShell alias pointing at a
function), never bare aliases. This keeps shell completion and positional
arguments working, and `command locklark` bypasses the wrapper itself.

Tool selection for `shell-init`:

- `--tools gh,docker` (or positional tool names after the shell) wraps exactly
  those names and validates each as a safe tool identifier.
- Otherwise, if the binding file exists and loads, its sorted key set is used.
- Otherwise, the default core set is wrapped: `aws`, `docker`, `gh`, `git`,
  `kubectl`, `npm`, `psql`, `terraform`.

If `--binding` was explicitly supplied, the generated function includes that
quoted path, for example:

```sh
gh() {
  command locklark cli run gh --binding '/secure/my bindings.json' -- "$@"
}
```

### Run a wrapped tool

Informational invocations use the fast path and do not prompt:

```sh
locklark cli run gh -- --help
locklark cli run kubectl -- version
locklark cli run gh -- completion bash
```

These execute the pinned program with the original standard streams and no
vault access. `--help`, `-h`, `--version`, `help`, `version` and `completion`
are treated as non-authenticating.

Authenticated invocations prompt for the master password and Secret Key, print
the disclosure summary, require `RUN`, and then run the child:

```sh
locklark cli run aws -- sts get-caller-identity
locklark cli run kubectl -- get pods -A
locklark cli run gh -- pr list
```

Wrapper options must appear before `--`:

```sh
locklark cli run gh \
  --binding /secure/path/.locklark-cli.json \
  --cwd /home/alice/project \
  --timeout 120 \
  -- pr list --limit 20
```

`--` separates wrapper arguments from child arguments. Everything after it is
passed verbatim, including options beginning with `--` and an empty string. If
`--` is omitted, the first positional argument is the tool and remaining
positional arguments become child arguments; any unknown flag before them is
an argument error, so use `--` for child flags. A missing working directory
defaults to the current directory and must be an absolute existing directory
when supplied.

The wrapper does not print a receipt on success; the child's stdout and stderr
are the command output. A non-zero child exit status is propagated as
locklark's exit status. Denied arguments and invalid metadata return a fixed
error before the interactive console is opened.

### Exit status

| Situation | Behavior |
| --- | --- |
| Child exits 0 | `locklark` exits 0 |
| Child exits N | `locklark` exits N |
| Invalid CLI arguments | Error, exit 1 |
| Binding missing | `CLI tool binding not found`, exit 1 |
| Pin mismatch, unsafe file, stale metadata | Validation error, exit 1 |
| Vault, intent or cleanup error | Fixed `personal` package error, exit 1 |
| Recursive fast-path run | `recursive locklark cli run is not allowed`, exit 1 |

## Troubleshooting

### `invalid or untrusted CLI binding configuration`

A binding file, parent directory or target failed validation, or the executable
no longer matches its pin. Check:

```sh
locklark cli list
locklark cli show gh
ls -ld "$(dirname "$BINDING_PATH")" "$BINDING_PATH"
```

The immediate parent must not be group/other writable. The file must be `0600`
on Unix. Symlinks and Windows reparse points are refused. If the program was
updated intentionally, rerun `locklark cli init` for that tool to record the new
SHA-256.

On Windows, `%TEMP%` is commonly not a trusted binding parent because its ACLs
allow more than the current user. Put the binding file in a directory whose
whole ancestor chain is trusted. The executable itself must be an absolute
`.exe`; npm `.cmd` shims are refused. For Node-based tools, bind `node.exe`
explicitly and pass the package entry point in the child argv.

### `CLI tool binding not found`

The tool name is not a key in the selected store. Confirm the store path:

```sh
locklark cli list --binding /secure/path/.locklark-cli.json
```

### `personal run-cli requires an interactive terminal...`

Authenticated `run` requires a controlling terminal, not just a pipe. This is
intentional: factors and the `RUN` confirmation cannot be supplied through
stdin. Run the command from an interactive terminal. Fast-path commands such
as `--help` do not require one.

### The command was refused even though it is not in the table

Profiles deny both exact contiguous sequences and the leading command path
while ignoring flags and likely flag values. Check the profile's denied list
and run a non-persistent alternative, for example `gh api user` instead of
`gh auth login`. Locklark never falls back to a global tool login.

### The wrapped command cannot find a helper executable

The child receives only `helper_path` as its `PATH`; it does not inherit the
parent `PATH`. Add the required absolute directories when binding:

```sh
locklark cli init my-tool ... --helper-path /opt/tools:/usr/local/bin
```

### The child needs a non-secret environment variable

Add it to `--passthrough` only if the profile allow-list includes the name.
Secrets, proxy variables, loaders and path-location variables are always
refused. Array values are not supported; each environment entry is one string.

## Limits and threat model

- **Not a sandbox.** The child runs as the local user with the user's
  permissions. It can read other files, use the network, write files, inspect
  its own environment, and retain or forward disclosed credentials.
- **No revocation.** Once a credential is rendered into the child environment
  or a file under the run root, Locklark cannot take it back. Removing the
  wrapper or revoking the vault item does not revoke values already disclosed.
- **Timeout is best effort.** The runner kills the direct child on timeout or
  cancellation. Descendants can survive, and an interrupted operation's result
  may be unknown. The intent journal records that execution may have occurred.
- **Arguments are public.** Child argv appears in the terminal disclosure and
  in the operating system process list. Never put a secret in an argument.
- **Binding metadata is sensitive.** The store is owner-only, but item IDs and
  revisions are still metadata. Keep it on a local, trusted filesystem.
- **No shell interpretation.** The runner calls `exec.Command` directly; it
  does not invoke a shell. Shell wrappers only forward `"$@"`/`$argv`/`@args`.
- **Windows.** Binding directories and files use owner/DACL validation rather
  than Unix mode bits. Reparse points are refused. The executable must be a
  regular `.exe` file.
- **No signed plugin execution.** `locklark plugin` is a separate, signed
  catalog surface. CLI wrappers are local, user-owned bindings and never load
  a plugin.
