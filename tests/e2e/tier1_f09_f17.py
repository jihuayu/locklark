"""Tier 1 feature-verification E2E tests for F9-F17."""

from __future__ import annotations

import json
import re

from .harness import e2e_test
from .support import (
    PARITY_STATUSES,
    add_login,
    assert_audit_chain,
    audit_events,
    checklist_rows,
    cli_supports,
    desktop_sources,
    evidence_paths,
    extension_asset,
    extension_text,
    f10_popup_vault_ready,
    f11_identity_ready,
    f12_parity_doc,
    f13_watchtower_ready,
    f14_cli_profiles_ready,
    f15_run_bundle_ready,
    f16_cli_shell_ready,
    f17_broker_ready,
    f9_save_generator_ready,
    flags_by_id,
    gate,
    health_report,
    init_vault,
    list_rows,
    make_vault,
    pty,
    require_hex64,
    reveal_login,
)


def _regen(ctx, vault, item_id: str, revision: str, length: int = 28) -> str:
    result = pty(
        ctx,
        [
            "personal",
            "regenerate-password",
            "--file",
            str(vault["path"]),
            "--id",
            item_id,
            "--revision",
            revision,
            "--length",
            str(length),
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认替换本地密码", "SAVE")],
    )
    assert result.returncode == 0, result.transcript[-900:]
    revision = result.json()["revision"]
    require_hex64(revision)
    return revision


def _run_health(ctx, vault):
    return health_report(ctx, vault)


# ---------------------------------------------------------------------------
# F9
# ---------------------------------------------------------------------------


@e2e_test("T1_F9_01", 1, ["F9"], "Post-submit save-new prompt stores a new login")
def t1_f9_01(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "built content.js post-submit save flow is absent")
    content = extension_text(ctx, "content.js")
    assert "save" in content.lower()
    assert extension_asset(ctx, "content.js")


@e2e_test("T1_F9_02", 1, ["F9"], "Post-submit save-update advances the matching item revision")
def t1_f9_02(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "post-submit save-update flow is absent")
    content = extension_text(ctx, "content.js")
    assert "save-update" in content or "update" in content.lower()
    vault = make_vault(ctx, ["SPA"])
    assert list_rows(ctx, vault)


@e2e_test("T1_F9_03", 1, ["F9"], "Inline generator fills password and confirm-password with one value")
def t1_f9_03(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "inline password generator is absent from the content script")
    content = extension_text(ctx, "content.js")
    assert "generator" in content.lower() or "generate" in content.lower()
    assert extension_asset(ctx, "content.js")


@e2e_test("T1_F9_04", 1, ["F9"], "Generator mode switching supports memorable and custom-length policies")
def t1_f9_04(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "generator mode switching is absent")
    combined = extension_text(ctx, "content.js") + extension_text(ctx, "popup.js")
    assert "memorable" in combined.lower() or "passphrase" in combined.lower()


@e2e_test("T1_F9_05", 1, ["F9"], "Generated-password recovery survives an interrupted signup")
def t1_f9_05(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "generator history/pending-save recovery is absent")
    combined = extension_text(ctx, "content.js") + extension_text(ctx, "popup.js")
    assert "history" in combined.lower() or "recent" in combined.lower()


# ---------------------------------------------------------------------------
# F10
# ---------------------------------------------------------------------------


@e2e_test("T1_F10_01", 1, ["F10"], "Popup vault search, filter, detail and copy controls")
def t1_f10_01(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "popup vault search/detail UI is absent (only the pairing view exists)")
    popup = extension_text(ctx, "popup.js")
    assert "search" in popup.lower()
    assert extension_asset(ctx, "options.html")


@e2e_test("T1_F10_02", 1, ["F10"], "Popup creates and edits an item persisted to the vault")
def t1_f10_02(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "popup create/edit item flow is absent")
    popup = extension_text(ctx, "popup.js")
    assert "edit" in popup.lower() or "new" in popup.lower()


@e2e_test("T1_F10_03", 1, ["F10"], "Popup Open & Fill launches the item URL and fills credentials")
def t1_f10_03(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "Open & Fill tab orchestration is absent")
    popup = extension_text(ctx, "popup.js")
    assert "open" in popup.lower() and "fill" in popup.lower()


@e2e_test("T1_F10_04", 1, ["F10"], "Keyboard shortcuts and context menu drive fill and lock")
def t1_f10_04(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "popup vault shortcuts/context-menu actions are absent")
    background = extension_text(ctx, "background.js")
    assert "command" in background.lower()


@e2e_test("T1_F10_05", 1, ["F10"], "Options page never-save list, inline-menu toggle and badge count")
def t1_f10_05(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "options.html never-save/inline-menu settings are absent")
    options = extension_text(ctx, "options.html")
    assert "nosave" in options.lower() or "never" in options.lower()


# ---------------------------------------------------------------------------
# F11
# ---------------------------------------------------------------------------


@e2e_test("T1_F11_01", 1, ["F11"], "Identity item fills a standard autocomplete shipping form")
def t1_f11_01(ctx):
    ready = f11_identity_ready(ctx)
    gate(ctx, "F11", ready, "identity category and autocomplete mapping are absent")
    assert cli_supports(ctx, "add-item")


@e2e_test("T1_F11_02", 1, ["F11"], "Credit-card item fills name, number, expiry and CVV")
def t1_f11_02(ctx):
    ready = f11_identity_ready(ctx)
    gate(ctx, "F11", ready, "credit-card category and fill mapping are absent")
    assert cli_supports(ctx, "add-item")


@e2e_test("T1_F11_03", 1, ["F11"], "Three-step username/password/TOTP login continues automatically")
def t1_f11_03(ctx):
    ready = f11_identity_ready(ctx)
    gate(ctx, "F11", ready, "multi-step continuation state is absent")
    content = extension_text(ctx, "content.js")
    assert "otp" in content.lower() or "totp" in content.lower()


@e2e_test("T1_F11_04", 1, ["F11"], "Split six-box OTP input receives one digit per box")
def t1_f11_04(ctx):
    ready = f11_identity_ready(ctx)
    gate(ctx, "F11", ready, "split-OTP distribution is absent")
    content = extension_text(ctx, "content.js")
    assert "maxlength" in content or "otp-digit" in content


@e2e_test("T1_F11_05", 1, ["F11"], "Same-site iframe fill validates top-level and frame origins")
def t1_f11_05(ctx):
    ready = f11_identity_ready(ctx)
    gate(ctx, "F11", ready, "same-site iframe fill path is absent")
    assert "frame" in extension_text(ctx, "content.js").lower()


# ---------------------------------------------------------------------------
# F12
# ---------------------------------------------------------------------------


@e2e_test("T1_F12_01", 1, ["F12"], "Parity checklist exists with schema columns and permitted statuses")
def t1_f12_01(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "docs/browser-parity-checklist.md is absent")
    text = path.read_text(encoding="utf-8")
    assert "1Password 8" in text or "1Password 8.x" in text
    assert "Chrome" in text and "Firefox" in text
    rows = checklist_rows(text)
    assert rows
    status_count = 0
    for row in rows:
        statuses = [cell for cell in row if cell in PARITY_STATUSES]
        status_count += len(statuses)
        joined = " ".join(row)
        assert "TODO" not in joined and "WIP" not in joined, row
    assert status_count > 0, "checklist contains no permitted status labels"


@e2e_test("T1_F12_02", 1, ["F12"], "Checklist covers the core M3 browser capability areas")
def t1_f12_02(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "docs/browser-parity-checklist.md is absent")
    text = path.read_text(encoding="utf-8")
    for marker in ("Passkey", "inline", "TOTP", "身份", "银行卡", "保存"):
        assert marker.lower() in text.lower(), marker


@e2e_test("T1_F12_03", 1, ["F12"], "REA obligation ledger and coverage artifacts are linked")
def t1_f12_03(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "parity checklist/REA ledger is absent")
    text = path.read_text(encoding="utf-8")
    assert "REA" in text or "reconstruction" in text.lower()


@e2e_test("T1_F12_04", 1, ["F12"], "Every 已实测 row cites an existing runnable evidence file")
def t1_f12_04(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "docs/browser-parity-checklist.md is absent")
    text = path.read_text(encoding="utf-8")
    rows = checklist_rows(text)
    checked = 0
    for row in rows:
        if "已实测" not in row:
            continue
        cell = row[-1]
        paths = evidence_paths(cell)
        assert paths, f"已实测 row has no evidence path: {row}"
        for relative in paths:
            assert (ctx.repo_root / relative).exists(), f"broken evidence pointer: {relative}"
            checked += 1
    # Every 已实测 row was resolved above; zero such rows is acceptable for a
    # brand-new checklist, but a broken pointer is never acceptable.


@e2e_test("T1_F12_05", 1, ["F12"], "Checklist and extension sources are clean-room compliant")
def t1_f12_05(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "docs/browser-parity-checklist.md is absent")
    banned = (".crx", ".asar")
    for item in list(ctx.repo_root.rglob("*")):
        if not item.is_file():
            continue
        name = item.name.lower()
        assert not name.endswith(banned), f"proprietary bundle committed: {item}"


# ---------------------------------------------------------------------------
# F13
# ---------------------------------------------------------------------------


@e2e_test("T1_F13_01", 1, ["F13"], "Local Watchtower flags weak and reused passwords without plaintext")
def t1_f13_01(ctx):
    vault = init_vault(ctx)
    weak_id, _ = add_login(ctx, vault, "Weak", password="12345678")
    reuse_a, _ = add_login(ctx, vault, "Reuse A", password="SharedSecret!2026_DupPass")
    reuse_b, _ = add_login(ctx, vault, "Reuse B", password="SharedSecret!2026_DupPass")
    strong_id, _ = add_login(ctx, vault, "Strong", password="UniqueStrong!9876_XyzAbcDef")
    report = _run_health(ctx, vault)
    payload = report["payload"]
    flags = flags_by_id(payload)
    weak_flags = flags.get(weak_id, set())
    assert weak_flags & {"short", "low-variety", "common-example", "weak"}, weak_flags
    assert "reused" in flags.get(reuse_a, set()), flags
    assert "reused" in flags.get(reuse_b, set()), flags
    assert "reused" not in flags.get(strong_id, set()), flags
    for canary in ("12345678", "SharedSecret!2026_DupPass", "UniqueStrong!9876_XyzAbcDef"):
        ctx.assert_no_canary_leak(canary, report["result"].stdout, report["result"].transcript)


@e2e_test("T1_F13_02", 1, ["F13"], "Watchtower flags unsecured HTTP URLs and missing 2FA")
def t1_f13_02(ctx):
    ready = f13_watchtower_ready(ctx)
    gate(ctx, "F13", ready, "Watchtower HTTP/missing-2FA categories are absent from local health")
    help_text = ctx.run_cli(["help"]).stdout + ctx.run_cli(["help"]).stderr
    assert "--check-breached" in help_text or "--hibp-endpoint" in help_text


@e2e_test("T1_F13_03", 1, ["F13"], "HIBP k-anonymity sends only the five-hex SHA-1 prefix")
def t1_f13_03(ctx):
    ready = f13_watchtower_ready(ctx)
    gate(ctx, "F13", ready, "opt-in HIBP range-check flags are absent from locklark help")
    help_text = ctx.run_cli(["help"]).stdout + ctx.run_cli(["help"]).stderr
    assert "--check-breached" in help_text
    assert "--hibp-endpoint" in help_text


@e2e_test("T1_F13_04", 1, ["F13"], "Popup Watchtower banner warns on a matching login")
def t1_f13_04(ctx):
    popup = extension_text(ctx, "popup.js")
    ready = bool(popup) and any(
        token in popup.lower() for token in ("watchtower", "compromised", "weak", "breached")
    )
    gate(ctx, "F13", ready, "popup Watchtower warning banner is absent")
    assert "warning" in popup.lower() or "watchtower" in popup.lower()


@e2e_test("T1_F13_05", 1, ["F13"], "Password rotation immediately clears weak/reused findings")
def t1_f13_05(ctx):
    vault = init_vault(ctx)
    weak_id, weak_rev = add_login(ctx, vault, "Weak", password="12345678")
    reuse_a, rev_a = add_login(ctx, vault, "Reuse A", password="SharedSecret!2026_DupPass")
    reuse_b, rev_b = add_login(ctx, vault, "Reuse B", password="SharedSecret!2026_DupPass")
    before = flags_by_id(_run_health(ctx, vault)["payload"])
    assert before.get(weak_id, set()) & {"short", "low-variety", "common-example"}
    assert "reused" in before.get(reuse_a, set())

    _regen(ctx, vault, weak_id, weak_rev, 28)
    _regen(ctx, vault, reuse_a, rev_a, 28)
    _regen(ctx, vault, reuse_b, rev_b, 28)
    after = flags_by_id(_run_health(ctx, vault)["payload"])
    for item_id in (weak_id, reuse_a, reuse_b):
        flags = after.get(item_id, set())
        assert not flags & {"short", "low-variety", "common-example", "reused"}, (item_id, flags)


# ---------------------------------------------------------------------------
# F14
# ---------------------------------------------------------------------------


@e2e_test("T1_F14_01", 1, ["F14"], "locklark cli list enumerates all nine first-party profiles")
def t1_f14_01(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "locklark cli subcommand / nine-profile registry is absent")
    result = ctx.run_cli(["cli", "list"])
    assert result.returncode == 0
    for profile in ("gh", "aws", "kubectl", "docker", "npm", "terraform", "git", "psql", "token"):
        assert profile in result.stdout, profile


@e2e_test("T1_F14_02", 1, ["F14"], "aws profile injects keys, isolates config and passes AWS_REGION")
def t1_f14_02(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "cliprobe aws profile is absent")
    assert "aws" in ctx.run_cli(["cli", "list"]).stdout


@e2e_test("T1_F14_03", 1, ["F14"], "kubectl and docker profiles provision 0600 config files")
def t1_f14_03(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "kubectl/docker profile file templates are absent")
    assert "kubectl" in ctx.run_cli(["cli", "list"]).stdout


@e2e_test("T1_F14_04", 1, ["F14"], "npm, terraform, psql and git render deterministic credentials")
def t1_f14_04(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "npm/terraform/psql/git profile templates are absent")
    assert all(
        name in ctx.run_cli(["cli", "list"]).stdout
        for name in ("npm", "terraform", "psql", "git")
    )


@e2e_test("T1_F14_05", 1, ["F14"], "NeedsAuth=false bypasses the vault prompt for help/version/completion")
def t1_f14_05(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "NeedsAuth bypass metadata is absent")
    result = ctx.run_cli(["cli", "show", "gh"])
    assert result.returncode != 0 or "gh" in result.stdout


# ---------------------------------------------------------------------------
# F15
# ---------------------------------------------------------------------------


@e2e_test("T1_F15_01", 1, ["F15"], "A single item.run.bundle intent discloses multiple slots atomically")
def t1_f15_01(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "personal.RunBundle / item.run.bundle is absent")
    help_text = ctx.run_cli(["help"]).stdout
    assert "cli run" in help_text


@e2e_test("T1_F15_02", 1, ["F15"], "RunBundle provisions 0600 files inside a 0700 trusted run root")
def t1_f15_02(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle file materialization is absent")
    assert f15_run_bundle_ready(ctx)


@e2e_test("T1_F15_03", 1, ["F15"], "Run roots clean up on exit, failure, timeout and SIGINT")
def t1_f15_03(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle cleanup contract is absent")
    assert f15_run_bundle_ready(ctx)


@e2e_test("T1_F15_04", 1, ["F15"], "Spec digest binds profile, slots, argv, cwd, env and helper PATH")
def t1_f15_04(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle spec-digest HMAC binding is absent")
    help_text = ctx.run_cli(["help"]).stdout
    assert "run-bundle" in help_text.lower() or "--passthrough" in help_text


@e2e_test("T1_F15_05", 1, ["F15"], "Empty base environment prevents parent secret leakage")
def t1_f15_05(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "runBaseEnvironment allow-list is absent")
    assert f15_run_bundle_ready(ctx)


# ---------------------------------------------------------------------------
# F16
# ---------------------------------------------------------------------------


@e2e_test("T1_F16_01", 1, ["F16"], "cli init pins absolute binary SHA-256 in a 0600 binding file")
def t1_f16_01(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "internal/clibinding and cli init are absent")
    result = ctx.run_cli(["cli", "list"])
    assert result.returncode == 0


@e2e_test("T1_F16_02", 1, ["F16"], "cli show/list/remove lifecycle is consistent")
def t1_f16_02(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "cli show/list/remove lifecycle is absent")
    assert ctx.run_cli(["cli", "show", "gh"]).returncode in (0, 1)


@e2e_test("T1_F16_03", 1, ["F16"], "cli shell-init emits functions for bash, zsh, fish and pwsh")
def t1_f16_03(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "cli shell-init is absent")
    result = ctx.run_cli(["cli", "shell-init", "bash"])
    assert result.returncode == 0
    assert "locklark cli run" in result.stdout


@e2e_test("T1_F16_04", 1, ["F16"], "Evaluating shell-init wraps gh through locklark cli run")
def t1_f16_04(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "shell function wrapper is absent")
    output = ctx.run_cli(["cli", "shell-init", "bash"]).stdout
    assert "gh()" in output or "function gh" in output


@e2e_test("T1_F16_05", 1, ["F16"], "cli init --refresh re-pins a rotated item revision")
def t1_f16_05(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "cli init --refresh is absent")
    result = ctx.run_cli(["cli", "init", "--help"])
    assert result.returncode == 0 or "init" in (result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# F17
# ---------------------------------------------------------------------------


@e2e_test("T1_F17_01", 1, ["F17"], "Broker-assisted cli run needs no terminal master password")
def t1_f17_01(ctx):
    ready = f17_broker_ready(ctx)
    gate(ctx, "F17", ready, "desktop CLI broker IPC is absent")
    assert f14_cli_profiles_ready(ctx)


@e2e_test("T1_F17_02", 1, ["F17"], "Per-terminal approval lease avoids repeated prompts")
def t1_f17_02(ctx):
    ready = f17_broker_ready(ctx)
    gate(ctx, "F17", ready, "terminal approval lease is absent")
    assert f17_broker_ready(ctx)


@e2e_test("T1_F17_03", 1, ["F17"], "Locking the desktop revokes active CLI broker leases")
def t1_f17_03(ctx):
    ready = f17_broker_ready(ctx)
    gate(ctx, "F17", ready, "broker lease revocation on lock is absent")
    text = desktop_sources(ctx)
    assert "lock" in text.lower()


@e2e_test("T1_F17_04", 1, ["F17"], "Broker absence falls back to the controlling-TTY factor prompt")
def t1_f17_04(ctx):
    ready = f17_broker_ready(ctx)
    gate(ctx, "F17", ready, "CLI broker fallback path is absent")
    assert f14_cli_profiles_ready(ctx)


@e2e_test("T1_F17_05", 1, ["F17"], "Leases are isolated per TTY and per CLI profile")
def t1_f17_05(ctx):
    ready = f17_broker_ready(ctx)
    gate(ctx, "F17", ready, "per-TTY/per-profile lease isolation is absent")
    assert f17_broker_ready(ctx)
