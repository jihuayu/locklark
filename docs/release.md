# Desktop release

Desktop releases are requested by the repository owner with a
`repository_dispatch` event of type `desktop-release` and payload
`{"tag":"v0.2.0"}`. The tag must already exist. The
[Desktop Release workflow](../.github/workflows/desktop-release.yml) is
triggered only by that dispatch; pushing a tag does not start it. It:

1. authorizes the default-branch dispatch, current run, repository owner, and
   exact real tag candidate before any write or production credential is used;
2. checks the production environment secrets and the matching `CHANGELOG.md`
   section;
3. creates or refreshes a draft GitHub release with notes from that section;
4. builds the Windows x64 package on `windows-latest`;
5. builds a Developer ID-signed and notarized macOS universal app on
   `macos-latest`;
6. downloads the draft assets, verifies every signed update manifest and
   archive from the trusted workflow commit, and rebuilds a complete
   `SHA256SUMS`.

The release remains a draft for review. Installed applications cannot see it
through GitHub's `releases/latest/download` endpoint until the draft is
published.

## Required release environment secrets

### Release metadata reader

The separate `release-metadata` environment must be pre-created and protected
to an exact `main`-only deployment policy before it is referenced, because a
GitHub environment reference can otherwise auto-create an empty environment.
Store the blank environment secret `RELEASE_METADATA_READ_TOKEN` only after
that protection exists; filling its value is an owner step outside this task.

The token is a repository-scoped fine-grained read-only token covering
Administration, Secrets, Environments, Actions, and Metadata for the metadata
API. No write scope is recommended. The workflow checkout uses the separate
builtin read-only token. The authorize job never receives production signing
keys, and it never falls back to the builtin token for metadata API reads.

A ruleset's `bypass_actors` may be redacted depending on the repository
user/write role and token scope. Absent or redacted bypass metadata is refused;
do not treat it as empty. Live positive policy and read-only scope verification
remain external acceptance work.

### Update signing key

`MYGO_UPDATER_PRIVATE_KEY` is the Ed25519 private key that signs update
archives and manifests. The matching public key is committed in
`updates.publicKey` in `mygo.config.ts`.

Generate a key pair when setting up a new repository:

```sh
go run github.com/egoist/mygo/cmd/mygo@v0.7.4 keygen
```

On Windows the default location is
`%APPDATA%\mygo\update-keys\mygo-update.key`; the adjacent
`mygo-update.pub` contains the public key. Store the account secret without
printing it (PowerShell on Windows):

```powershell
Get-Content -Raw "$env:APPDATA\mygo\update-keys\mygo-update.key" |
  gh secret set MYGO_UPDATER_PRIVATE_KEY --env production --repo jihuayu/locklark
```

Keep an offline backup in a password manager. Losing the key prevents every
existing installation from accepting future updates; exposing it lets an
attacker sign code that those installations will accept. Do not rotate this
key without an explicit migration plan.

### macOS production signing and notarization

All of these production environment secrets are required. The workflow fails
before creating the draft when one is missing:

- `MACOS_CERTIFICATE`: base64-encoded Developer ID Application `.p12`;
- `MACOS_CERTIFICATE_PASSWORD`: its password;
- `MACOS_SIGNING_IDENTITY`: the full Developer ID identity;
- `MACOS_PROVISIONING_PROFILE`: base64-encoded provisioning profile for
  `app.locklark.desktop` and its `keychain-access-groups`;
- `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`: notarization
  credentials.

The provisioning profile is required for Touch ID quick unlock and passkey
user verification. Building without it would produce an app with no
`keychain-access-groups`, so the release gate does not allow an ad-hoc
fallback.

### Windows Authenticode signing

These optional production environment secrets sign the executable,
installer, uninstaller, and unsigned executables shipped as resources:

- `WINDOWS_CERTIFICATE`: base64-encoded `.pfx` code-signing certificate;
- `WINDOWS_CERTIFICATE_PASSWORD`: its password.

When they are absent the release still builds and updates correctly, but
Windows SmartScreen will warn users. A fully production-signed Windows
release requires both secrets and a certificate trusted by the target
machines.

## Cutover prerequisites

Before dispatching any real release tag, verify externally that production
credentials are isolated to the `production` environment, `main` protection
and the required reviews/immutable-tag rules are enforced, and every legacy
tag-triggered workflow or script in historical tag trees is disabled or made
inert. Committing the new workflow cannot retroactively stop workflows embedded
in old tags.

The builtin workflow token may lack the administrative or secret-metadata
scopes needed to prove some policy inputs. The authorizer then refuses with a
fixed enum. Do not widen the token or weaken the policy gate to make it pass.

## Creating a release

1. Add a `## <version>` or `## [<version>] - <date>` section to
   `CHANGELOG.md`. MyGo puts its text into every signed update manifest and
   the workflow uses it as the draft release notes.
2. Commit and merge the change after the normal checks pass.
3. Create and push the tag, then ask the repository owner to dispatch the
   release workflow:

   ```sh
   git tag -s v0.2.0 -m "Locklark v0.2.0"
   git push origin v0.2.0
   gh api --method POST "/repos/jihuayu/locklark/dispatches" \
     -f event_type=desktop-release \
     -f 'client_payload[tag]=v0.2.0'
   ```

4. Wait for `authorize`, Windows, macOS, and `verify-release` to pass.
5. Review every asset and the platform signatures, then publish the draft.

The tag and `CHANGELOG.md` heading must use the same version. Re-running a
failed job reuses the existing draft; the workflow refuses to overwrite an
already published release.

## Windows packages

MyGo builds Windows x64 with the per-user NSIS installer:

- `locklark-setup-<version>-amd64.exe`;
- `Locklark.exe` inside the installer and update archive;
- `locklark-<version>-windows-<arch>.tar.gz`, the update archive;
- `update-windows-<arch>.json`, the signed update manifest;
- `install.ps1`, the MyGo one-line installer.

The NSIS installer requests no administrator rights. It installs under
`%LOCALAPPDATA%\Programs\Locklark`, writes the uninstall entry under `HKCU`,
adds Start menu and optional desktop shortcuts, and includes an uninstaller
listed in Windows Settings. Upgrading replaces the files in the existing
per-user install folder; vault data and settings stay outside that folder
and are not removed by an update.

`SHA256SUMS` covers the installer, disk image, update archives/deltas, and
install scripts; the update manifests carry their own Ed25519 signatures.
`install.ps1` downloads the x64 installer from the latest published release,
checks it against `SHA256SUMS`, and runs it silently.

## Automatic updates

`updates.github` points to the public `jihuayu/locklark` repository.
Applications built with this configuration read:

- `update-windows-amd64.json` on Windows;
- `update-darwin-universal.json` on macOS.

Each manifest contains the version, release notes, archive URL, size, and
Ed25519 signature. The updater downloads the archive or a matching delta,
checks its size, SHA-256 digest, and signature against the public key built
into the app, then replaces the per-user installation. A delta is used only
when the running version has one; otherwise the full archive is downloaded.

The installed app checks automatically after launch and every 24 hours by
default. The tray menu and Security settings also expose "Check for
Updates…". Development builds, read-only installs, and package-manager
installs cannot self-update and report that instead of attempting a write.

The first published release has no deltas. Later releases get up to three
delta updates from the currently published version and the earlier versions
listed in its manifest.

## Release authorization

The active workflow uses the read-only
`scripts/desktop_release_routing.py` entry. It binds the default-branch
`repository_dispatch` to the canonical current run and exact real tag
candidate, then reuses the C1 policy gates for main protection, reviews,
immutable tags, environment branch restriction, and environment-only
credentials. The historical `scripts/authorize_desktop_release.py`
`workflow_run` CLI remains unwired.

The validator is fail-closed. Generic illustrative fixtures that omit `main`
protection, active immutable `v*` tag rules, a default-branch-only production
environment policy, or environment-only production credential scope are
refused. This checkpoint makes no statement about the current external settings
of any repository and does not claim that external policy has been fixed. See
[release-trust.md](release-trust.md) and
[release-routing.md](release-routing.md) for the prerequisites and test
caveats.
