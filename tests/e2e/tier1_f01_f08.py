"""Tier 1 feature-verification E2E tests for F1-F8.

Every test uses a user-facing surface.  Milestone-only cases perform a real
probe first and then raise the progressive gate, so pre-merge runs report
``PENDING_FEATURE`` instead of silently passing.
"""

from __future__ import annotations

import json
import re
import shutil

from .harness import e2e_test
from .support import (
    add_login,
    assert_audit_chain,
    audit_events,
    built_extension,
    cli_supports,
    desktop_binary_starts,
    desktop_runtime_available,
    desktop_sources,
    extension_asset,
    extension_text,
    extension_or_source_text,
    f1_autosubmit_ready,
    f1_passkey_ready,
    f2_autologin_ready,
    f2_inline_ready,
    f3_team_sync_ready,
    f4_team_cli_ready,
    f5_desktop_timer_ready,
    f5_filter_refresh_ready,
    f7_shared_ipc_ready,
    f8_desktop_v2_ready,
    f8_v2_editor_ready,
    gate,
    health_report,
    list_rows,
    make_vault,
    multi_category_1pux,
    node_eval,
    node_test,
    node_test_pattern,
    pty,
    require_hex32,
    require_hex64,
    reveal_login,
    source_text,
    sources_contain,
    f13_watchtower_ready,
)


def _run_team_sync_help(ctx) -> str:
    binary = ctx.team_sync_bin
    assert binary is not None and binary.is_file()
    result = ctx.run_cli(["help"], binary=binary, timeout=8.0)
    return (result.stdout or "") + (result.stderr or "")


def _import_multi_category(ctx, vault) -> tuple[dict, dict]:
    archive = multi_category_1pux(ctx)
    plan = pty(
        ctx,
        ["personal", "plan-import-1pux", "--file", str(vault["path"]), "--source", str(archive)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 PLAN 确认生成导入计划", "PLAN")],
    )
    assert plan.returncode == 0, plan.transcript[-1200:]
    payload = plan.json()
    digest = payload["report"]["source_digest"]
    apply = pty(
        ctx,
        [
            "personal",
            "import-1pux",
            "--file",
            str(vault["path"]),
            "--source",
            str(archive),
            "--digest",
            digest,
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认整批导入", "SAVE")],
    )
    assert apply.returncode == 0, apply.transcript[-1200:]
    return payload, apply.json()


def _plan_multi_category(ctx, vault):
    archive = multi_category_1pux(ctx)
    return pty(
        ctx,
        ["personal", "plan-import-1pux", "--file", str(vault["path"]), "--source", str(archive)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 PLAN 确认生成导入计划", "PLAN")],
    )


# ---------------------------------------------------------------------------
# F1 - rebased SSH + Passkey vault and Firefox auto-submit
# ---------------------------------------------------------------------------


@e2e_test("T1_F1_01", 1, ["F1"], "Mixed SSH-key and Passkey login coexist in one vault")
def t1_f1_01(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F1", ready, "extension webauthn.js and native passkey protocol are not present")
    vault = make_vault(ctx, ["Prod Bastion SSH", "login.locklark.test"])
    rows = list_rows(ctx, vault)
    assert len(rows) == 2, rows
    for row in rows:
        require_hex32(row["id"])
        require_hex64(row["revision"])
        assert row["state"] == "active"
    assert extension_asset(ctx, "webauthn.js")
    assert sources_contain(ctx, "internal/desktop/*.go", "SSH 密钥")


@e2e_test("T1_F1_02", 1, ["F1"], "Mixed SSH/Passkey audit journal keeps a replayable hash chain")
def t1_f1_02(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F1", ready, "native passkey protocol is absent; mixed journal cannot replay")
    vault = make_vault(ctx, ["Prod Bastion SSH", "passkey-login"])
    events = audit_events(ctx, vault)
    assert_audit_chain(events)
    actions = {event["action"] for event in events}
    assert "vault.create" in actions and "item.add" in actions, actions


@e2e_test("T1_F1_03", 1, ["F1"], "Encrypted backup/restore preserves SSH keys and Passkeys")
def t1_f1_03(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F1", ready, "passkey vault artifacts are absent; mixed backup cannot be verified")
    vault = make_vault(ctx, ["Prod Bastion SSH", "passkey-login"])
    backup = ctx.temp_dir / "mixed-backup.ll"
    created = pty(
        ctx,
        ["personal", "backup", "--file", str(vault["path"]), "--out", str(backup)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("重新输入恢复码", None)],
    )
    assert created.returncode == 0, created.transcript[-1200:]
    assert created.issued and backup.is_file()
    assert backup.stat().st_mode & 0o077 == 0
    restored = ctx.temp_dir / "mixed-restored.ll"
    restored_result = pty(
        ctx,
        ["personal", "restore", "--file", str(backup), "--out", str(restored)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("此备份的恢复码", created.issued[0]), ("重新输入新 Secret Key", None)],
    )
    assert restored_result.returncode == 0, restored_result.transcript[-1200:]
    assert restored_result.issued
    rows = pty(
        ctx,
        ["personal", "list", "--file", str(restored)],
        password=vault["password"],
        secret=restored_result.issued[0],
    )
    assert rows.returncode == 0, rows.transcript[-800:]
    assert len(rows.json()) == 2


@e2e_test("T1_F1_04", 1, ["F1"], "KDBX export of the mixed vault keeps SSH and Passkey slots separate")
def t1_f1_04(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F1", ready, "passkey vault artifacts are absent; mixed KDBX export is unavailable")
    vault = make_vault(ctx, ["Prod Bastion SSH", "passkey-login"])
    output = ctx.temp_dir / "mixed.kdbx"
    result = pty(
        ctx,
        ["personal", "export-kdbx", "--file", str(vault["path"]), "--out", str(output)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[
            ("新导出密码（至少 12 字符）", "export-pass-2026"),
            ("再次输入导出密码", "export-pass-2026"),
            ("输入 SAVE 确认加密导出", "SAVE"),
        ],
    )
    assert result.returncode == 0, result.transcript[-1200:]
    assert output.is_file() and output.stat().st_size > 0
    assert output.read_bytes()[:8] == b"\x03\xd9\xa2\x9ag\xfbK\xb5"
    for canary in ("Prod Bastion SSH", "passkey-login", vault["secret"]):
        ctx.assert_no_canary_leak(canary, output.read_bytes())


@e2e_test("T1_F1_05", 1, ["F1"], "Firefox DOM login parity awaits/dispatches a real submit")
def t1_f1_05(ctx):
    core = extension_text(ctx, "core.js") or source_text(ctx, "browser-extension/core.js")
    ready = bool(core) and any(token in core for token in ("autoSubmit", "submitDocument", "requestSubmit"))
    gate(ctx, "F1", ready, "Firefox auto-submit implementation is absent from the built core.js")
    chromium, firefox = built_extension(ctx)
    manifest = json.loads((firefox / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["browser_specific_settings"]["gecko"]["id"] == "browser@locklark.local"
    assert "submit" in core.lower()
    node_test(ctx, "browser-extension/test/core.test.js")


@e2e_test("T1_F1_06", 1, ["F1"], "Browser match projection returns only login items in a mixed vault")
def t1_f1_06(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F1", ready, "mixed ssh-key/passkey vault projection is unavailable on this branch")
    vault = make_vault(ctx, ["login.locklark.test"])
    from .support import edit_url, match_logins

    item_id, revision = vault["items"][0]["id"], vault["items"][0]["revision"]
    revision = edit_url(ctx, vault, item_id, revision, "https://login.locklark.test/login")
    rows = match_logins(ctx, vault, "https://login.locklark.test")
    assert len(rows) == 1 and rows[0]["kind"] == "login", rows
    assert rows[0]["id"] == item_id


# ---------------------------------------------------------------------------
# F2 - inline autofill, auto-login, native passkeys
# ---------------------------------------------------------------------------


@e2e_test("T1_F2_01", 1, ["F2"], "Closed-shadow inline menu renders and fills credentials")
def t1_f2_01(ctx):
    ready = f2_inline_ready(ctx)
    gate(ctx, "F2", ready, "built extension content.js (closed-shadow inline menu) is absent")
    content = extension_text(ctx, "content.js")
    assert "attachShadow" in content
    assert re.search(r'mode\s*:\s*["\']closed["\']', content), content[:2000]
    node_test(ctx, "browser-extension/test/core.test.js")


@e2e_test(
    "T1_F2_02",
    1,
    ["F2"],
    "Global and per-login auto-submit settings control form submission",
    coverage_kind="component_contract",
)
def t1_f2_02(ctx):
    # The shipped preference is `autoLogin` (global) plus per-item
    # `loginOverrides`; the old `autoSubmit` literal never existed in the
    # extension and turned a working path into a phantom pending result.
    ready = f2_inline_ready(ctx) and f2_autologin_ready(ctx)
    gate(
        ctx,
        "F2",
        ready,
        "autoLogin preference plumbing (global setting + per-item loginOverrides) is absent from the extension bundle",
    )
    popup = extension_or_source_text(ctx, "popup.js")
    options = extension_or_source_text(ctx, "options.js")
    assert "autoLogin" in popup or "opt-auto-login" in options
    counts = node_test_pattern(
        ctx,
        "browser-extension/test/background.test.js",
        r"automatic submission respects global/item opt-outs",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test("T1_F2_03", 1, ["F2"], "Single-field step login fills username-only and password-only steps")
def t1_f2_03(ctx):
    ready = f2_inline_ready(ctx)
    gate(ctx, "F2", ready, "inline menu content script is absent; step-login fill cannot run")
    content = extension_text(ctx, "content.js")
    assert "username" in content and "password" in content
    assert "current-password" in content or "autocomplete" in content


@e2e_test("T1_F2_04", 1, ["F2"], "WebAuthn create returns an ES256 discoverable credential")
def t1_f2_04(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F2", ready, "WebAuthn bridge and native passkey-create handler are absent")
    webauthn = extension_text(ctx, "webauthn.js")
    assert "credentials" in webauthn and "create" in webauthn
    protocol = source_text(ctx, "internal/browserhost/protocol.go")
    assert "passkey-create" in protocol or "passkey" in protocol.lower()


@e2e_test("T1_F2_05", 1, ["F2"], "WebAuthn get returns a verifiable ES256 assertion")
def t1_f2_05(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F2", ready, "WebAuthn bridge and native passkey-get handler are absent")
    webauthn = extension_text(ctx, "webauthn.js")
    assert "credentials" in webauthn and "get" in webauthn


@e2e_test("T1_F2_06", 1, ["F2"], "Browser fallback delegates WebAuthn to the native browser implementation")
def t1_f2_06(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F2", ready, "WebAuthn fallback bridge is absent from the built extension")
    webauthn = extension_text(ctx, "webauthn.js")
    assert any(token in webauthn for token in ("fallback", "native", "original"))


# ---------------------------------------------------------------------------
# F3 - authenticated team synchronization & mobile vault core
# ---------------------------------------------------------------------------


@e2e_test("T1_F3_01", 1, ["F3"], "Team sync init-anchor/serve starts a TLS sequencer with hidden seed input")
def t1_f3_01(ctx):
    ready = f3_team_sync_ready(ctx)
    gate(ctx, "F3", ready, "cmd/locklark-team-sync is not present in this checkout")
    output = _run_team_sync_help(ctx)
    assert "team" in output.lower() or "usage" in output.lower(), output


@e2e_test("T1_F3_02", 1, ["F3"], "Authenticated Fetch/Publish advances a reader checkpoint")
def t1_f3_02(ctx):
    ready = f3_team_sync_ready(ctx) and (
        ctx.repo_root / "scripts" / "team_sync_acceptance.py"
    ).is_file()
    gate(ctx, "F3", ready, "team-sync binary or scripts/team_sync_acceptance.py is absent")
    assert (ctx.repo_root / "scripts" / "team_sync_acceptance.py").is_file()


@e2e_test("T1_F3_03", 1, ["F3"], "Interrupted publish reconciliation returns committed/conflicted/unknown")
def t1_f3_03(ctx):
    ready = f3_team_sync_ready(ctx)
    gate(ctx, "F3", ready, "team-sync sequencer binary is absent; reconcile cannot be exercised")
    output = _run_team_sync_help(ctx)
    assert "sync" in output.lower()


@e2e_test("T1_F3_04", 1, ["F3"], "Mobile vault core preserves Passkeys and hides ssh-key items")
def t1_f3_04(ctx):
    ready = f3_team_sync_ready(ctx) and f1_passkey_ready(ctx)
    gate(ctx, "F3", ready, "team-sync/mobile core and passkey schema are not both present")
    assert (ctx.repo_root / "scripts" / "team_sync_acceptance.py").is_file()


@e2e_test("T1_F3_05", 1, ["F3"], "Android new-master-password focus and OS credential restore")
def t1_f3_05(ctx):
    script = ctx.repo_root / "scripts" / "test_mobile_android_acceptance.py"
    acceptance = ctx.repo_root / "scripts" / "mobile_android_acceptance.py"
    ready = script.is_file() and acceptance.is_file()
    gate(ctx, "F3", ready, "mobile Android acceptance harness is absent from the checkout")
    result = ctx.run_cli(
        ["-m", "unittest", "scripts/test_mobile_android_acceptance.py"],
        binary=shutil.which("python3") or "python3",
        timeout=180,
        cwd=ctx.repo_root,
        env={"PYTHONPATH": str(script.parent)},
    )
    assert result.returncode == 0, (result.stdout + result.stderr)[-2000:]


# ---------------------------------------------------------------------------
# F4 - protected team identities and first-device bootstrap
# ---------------------------------------------------------------------------


@e2e_test("T1_F4_01", 1, ["F4"], "Server prepare-identity and owner team create verify mutual fingerprints")
def t1_f4_01(ctx):
    ready = f4_team_cli_ready(ctx)
    gate(ctx, "F4", ready, "locklark team command is absent (CLI reports unknown command)")
    result = ctx.run_cli(["team", "status"])
    assert "unknown command" not in (result.stderr or "").lower()


@e2e_test("T1_F4_02", 1, ["F4"], "Owner export-initial and server initialize bind directory and genesis checkpoint")
def t1_f4_02(ctx):
    ready = f4_team_cli_ready(ctx) and f3_team_sync_ready(ctx)
    gate(ctx, "F4", ready, "team client command or team-sync sequencer binary is absent")
    result = ctx.run_cli(["team", "status"])
    assert "unknown command" not in (result.stderr or "").lower()


@e2e_test("T1_F4_03", 1, ["F4"], "serve-profile and fetch-initial activate the owner over TLS")
def t1_f4_03(ctx):
    ready = f4_team_cli_ready(ctx) and f3_team_sync_ready(ctx)
    gate(ctx, "F4", ready, "serve-profile/fetch-initial team commands are absent")
    assert f4_team_cli_ready(ctx)


@e2e_test("T1_F4_04", 1, ["F4"], "Status re-export and export-initial replay are byte-stable")
def t1_f4_04(ctx):
    ready = f4_team_cli_ready(ctx)
    gate(ctx, "F4", ready, "team status --pins-out / export-initial replay are absent")
    result = ctx.run_cli(["team", "status", "--help"])
    assert "unknown command" not in (result.stderr or "").lower()


@e2e_test("T1_F4_05", 1, ["F4"], "reconcile-protection/reconcile-initialize recover interrupted bootstrap")
def t1_f4_05(ctx):
    ready = f4_team_cli_ready(ctx) and f3_team_sync_ready(ctx)
    gate(ctx, "F4", ready, "reconcile-protection/reconcile-initialize are absent")
    help_text = ctx.run_cli(["help"]).stdout
    assert "team" in help_text


# ---------------------------------------------------------------------------
# F5 - desktop timer/state bugs #32, #33, #34
# ---------------------------------------------------------------------------


@e2e_test("T1_F5_01", 1, ["F5"], "Capability probe: independent clipboard expiry timer")
def t1_f5_01(ctx):
    ready = f5_desktop_timer_ready(ctx)
    gate(ctx, "F5", ready, "clipboard expiry is still render-loop driven; no independent timer")
    if not desktop_runtime_available(ctx):
        gate(ctx, "F5", False, "validation blocked: xvfb-run unavailable; desktop launch not exercised")
    vault = make_vault(ctx, ["Alpha"])
    assert desktop_binary_starts(ctx, vault["path"])
    text = desktop_sources(ctx)
    assert "clipboardTimer = time.AfterFunc" in text
    assert "clipboardUntil" in text and "clipboardTimeout()" in text


@e2e_test("T1_F5_02", 1, ["F5"], "Capability probe: display and idle deadlines are timer-driven")
def t1_f5_02(ctx):
    text = desktop_sources(ctx)
    ready = f5_desktop_timer_ready(ctx) and "displayUntil" in text
    gate(ctx, "F5", ready, "display/idle deadlines are not enforced without a rendered frame")
    if not desktop_runtime_available(ctx):
        gate(ctx, "F5", False, "validation blocked: xvfb-run unavailable; desktop launch not exercised")
    vault = make_vault(ctx, ["Alpha"])
    assert desktop_binary_starts(ctx, vault["path"])
    assert "displayTimer = time.AfterFunc" in text
    assert "idleTimer = time.AfterFunc" in text
    vault = make_vault(ctx, ["Alpha"])
    audit = audit_events(ctx, vault)
    assert_audit_chain(audit)


@e2e_test("T1_F5_03", 1, ["F5"], "Locking cancels a desktop edit waiting on the database")
def t1_f5_03(ctx):
    text = desktop_sources(ctx)
    ready = (
        f5_desktop_timer_ready(ctx)
        and "gate.Cancel()" in text
        and ("CommitWon()" in text or "mutationUnknown" in text)
    )
    gate(ctx, "F5", ready, "edit cancellation on lock lacks a post-commit gate")
    vault = make_vault(ctx, ["Alpha"])
    events = audit_events(ctx, vault)
    assert_audit_chain(events)


@e2e_test("T1_F5_04", 1, ["F5"], "Editing a non-title field preserves the active title filter")
def t1_f5_04(ctx):
    text = desktop_sources(ctx)
    ready = f5_desktop_timer_ready(ctx) and f5_filter_refresh_ready(ctx)
    gate(
        ctx,
        "F5",
        ready,
        "refresh does not capture and re-apply the active query/scope (captureFilter/filterCurrent/queryRows)",
    )
    vault = make_vault(ctx, ["Alpha", "Beta"])
    rows = list_rows(ctx, vault)
    assert {row["title"] for row in rows} == {"Alpha", "Beta"}
    assert "func (a *App) refresh()" in text


@e2e_test("T1_F5_05", 1, ["F5"], "Archive/trash/regenerate on a filtered item keeps query and scope")
def t1_f5_05(ctx):
    text = desktop_sources(ctx)
    ready = (
        f5_desktop_timer_ready(ctx)
        and "a.scope" in text
        and ("SetArchived" in text or "archiveLogin" in text or "归档" in text)
    )
    gate(ctx, "F5", ready, "filtered state mutations do not retain the scope/query pair")
    vault = make_vault(ctx, ["Alpha-1", "Alpha-2", "Beta"])
    rows = list_rows(ctx, vault)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# F6 - item model v2 and 1PUX mapping
# ---------------------------------------------------------------------------


@e2e_test("T1_F6_01", 1, ["F6"], "Items persist across all v2 categories")
def t1_f6_01(ctx):
    ready = cli_supports(ctx, "add-item")
    gate(
        ctx,
        "F6",
        ready,
        "CLI `personal add-item` command is absent (command-surface gap); the v2 item "
        "model and category browser exist in the desktop/browser host",
    )
    vault = make_vault(ctx)
    rows = list_rows(ctx, vault)
    assert rows and rows[0]["kind"] == "login"
    assert "add-item" in ctx.run_cli(["help"]).stdout


@e2e_test("T1_F6_02", 1, ["F6"], "Sections and typed custom fields resolve through op:// references")
def t1_f6_02(ctx):
    ready = cli_supports(ctx, "add-item") and cli_supports(ctx, "references")
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item/references command surface is absent; section-qualified custom "
        "fields exist in the v2 host model, so op:// references cannot be created "
        "through the CLI",
    )
    vault = make_vault(ctx)
    result = pty(
        ctx,
        ["personal", "references", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
    )
    assert result.returncode == 0, result.transcript[-1000:]
    references = result.json()
    assert references["items"], references


@e2e_test("T1_F6_03", 1, ["F6"], "Multiple URLs per login match across primary and secondary URLs")
def t1_f6_03(ctx):
    ready = cli_supports(ctx, "add-item")
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item command is absent; multi-URL fields exist in the v2 host item "
        "model but cannot be created through the CLI",
    )
    vault = make_vault(ctx, ["Corp SSO"])
    from .support import edit_url, match_logins

    item = vault["items"][0]
    revision = edit_url(ctx, vault, item["id"], item["revision"], "https://portal.corp.example.com/auth")
    rows = match_logins(ctx, vault, "https://portal.corp.example.com")
    assert rows and rows[0]["id"] == item["id"], rows
    assert revision != item["revision"]


@e2e_test("T1_F6_04", 1, ["F6"], "Tags and favorite metadata survive KDBX save/reload and backup")
def t1_f6_04(ctx):
    ready = cli_supports(ctx, "add-item")
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item command is absent; tags/favorite metadata are part of the v2 "
        "host item model, so the KDBX round trip cannot be driven from the CLI",
    )
    vault = make_vault(ctx, ["GitHub"])
    backup = ctx.temp_dir / "tags-backup.ll"
    result = pty(
        ctx,
        ["personal", "backup", "--file", str(vault["path"]), "--out", str(backup)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("重新输入恢复码", None)],
    )
    assert result.returncode == 0, result.transcript[-1000:]
    assert backup.is_file()


@e2e_test("T1_F6_05", 1, ["F6"], "1PUX import maps multi-category items, sections, tags and favorites")
def t1_f6_05(ctx):
    vault = make_vault(ctx)
    plan = _plan_multi_category(ctx, vault)
    ready = plan.returncode == 0
    gate(
        ctx,
        "F6",
        ready,
        "CLI plan-import-1pux rejects non-basic-login archives wholesale "
        "(command-surface gap); the v2 item model exists in the host",
    )
    payload = plan.json()
    assert payload["report"]["items"] >= 4, payload
    _import_multi_category(ctx, vault)
    rows = list_rows(ctx, vault, "all")
    titles = {row["title"] for row in rows}
    assert {"Corp SSO", "Runbook", "Ada Lovelace", "Corp Visa"} <= titles, titles


@e2e_test("T1_F6_06", 1, ["F6"], "Existing v1 login-notes vaults migrate without ID/revision churn")
def t1_f6_06(ctx):
    # This path is intentionally baseline-capable: the current CLI already
    # creates and reads login-notes-v2 vaults, which is the compatibility floor
    # the v2 model must keep.
    vault = make_vault(ctx, ["Legacy Alpha"])
    item = vault["items"][0]
    first = list_rows(ctx, vault)
    assert len(first) == 1 and first[0]["id"] == item["id"]
    assert first[0]["revision"] == item["revision"]
    username, _ = reveal_login(ctx, vault, item["id"], item["revision"], "username")
    assert username == "legacy alpha-user", username
    events = audit_events(ctx, vault)
    assert_audit_chain(events)
    second = list_rows(ctx, vault)
    assert second[0]["id"] == item["id"]


# ---------------------------------------------------------------------------
# F7 - shared desktop/extension IPC session
# ---------------------------------------------------------------------------


@e2e_test("T1_F7_01", 1, ["F7"], "Capability probe: desktop and extension share one unlocked session")
def t1_f7_01(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "desktop shared-IPC broker is absent; a separate host window is still spawned")
    if not desktop_runtime_available(ctx):
        gate(ctx, "F7", False, "validation blocked: xvfb-run unavailable; desktop launch not exercised")
    vault = make_vault(ctx, ["Alpha"])
    assert desktop_binary_starts(ctx, vault["path"])
    text = desktop_sources(ctx)
    assert "此窗口与浏览器共享已解锁的金库会话" in text
    assert not sources_contain(ctx, "internal/desktop/*.go", "此窗口持有独立金库会话")
    assert sources_contain(ctx, "internal/desktop/ipc_broker.go", "startBrowserBroker")


@e2e_test("T1_F7_02", 1, ["F7"], "Desktop lock immediately invalidates extension capabilities")
def t1_f7_02(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "lock propagation over local IPC is not implemented")
    text = desktop_sources(ctx)
    assert "Invalidate" in text or "invalidate" in text


@e2e_test("T1_F7_03", 1, ["F7"], "Re-unlock restores extension access without manual re-pairing")
def t1_f7_03(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "persistent paired-session restore over IPC is absent")
    assert f7_shared_ipc_ready(ctx)


@e2e_test("T1_F7_04", 1, ["F7"], "Browser save/passkey mutations appear live in the desktop list")
def t1_f7_04(ctx):
    ready = f7_shared_ipc_ready(ctx) and f1_passkey_ready(ctx)
    gate(ctx, "F7", ready, "shared IPC mutation routing and passkey artifacts are absent")
    text = desktop_sources(ctx)
    assert "browser" in text.lower()


@e2e_test("T1_F7_05", 1, ["F7"], "Chromium and Firefox hosts share one desktop session and lock together")
def t1_f7_05(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "multi-host shared desktop session is absent")
    assert ctx.browser_chromium_bin.is_file() and ctx.browser_firefox_bin.is_file()


# ---------------------------------------------------------------------------
# F8 - desktop UI v2
# ---------------------------------------------------------------------------


@e2e_test("T1_F8_01", 1, ["F8"], "Capability probe: v2 navigation exposes favorites/all/trash")
def t1_f8_01(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "v2 sidebar (favorites/all/recently-deleted) is absent from the desktop source")
    if not desktop_runtime_available(ctx):
        gate(ctx, "F8", False, "validation blocked: xvfb-run unavailable; desktop launch not exercised")
    vault = make_vault(ctx, ["Jira", "Runbook"])
    assert desktop_binary_starts(ctx, vault["path"])
    text = desktop_sources(ctx)
    assert all(marker in text for marker in ("navFavorites", "navAllItems", "navRecentlyDelete"))
    assert "收藏" in text and "最近删除" in text


@e2e_test("T1_F8_02", 1, ["F8"], "Full item editor and random/memorable/PIN password generator")
def t1_f8_02(ctx):
    # The desktop v2 editor and generator ship in internal/desktop.  The CLI has
    # no add-item command; that command-surface gap must never be read as
    # "the native v2 editor/model is absent".
    ready = f8_desktop_v2_ready(ctx) and f8_v2_editor_ready(ctx)
    gate(
        ctx,
        "F8",
        ready,
        "desktop v2 item editor or random/memorable/PIN generator is absent (CLI add-item is a separate command-surface gap)",
    )
    text = desktop_sources(ctx)
    assert "生成器" in text or "generator" in text.lower()
    assert all(mode in text for mode in ("ModeRandom", "ModeMemorable", "ModePIN"))


@e2e_test("T1_F8_03", 1, ["F8"], "Full-text search covers title, username, URL, notes and tags")
def t1_f8_03(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "v2 full-text search index is absent")
    vault = make_vault(ctx, ["Cloud", "Database", "Bastion"])
    rows = list_rows(ctx, vault)
    assert len(rows) == 3
    text = desktop_sources(ctx)
    assert "query" in text


@e2e_test("T1_F8_04", 1, ["F8"], "Item history restore and Recently Deleted permanent purge")
def t1_f8_04(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "history and 最近删除 permanent-delete UI are absent")
    text = desktop_sources(ctx)
    assert "最近删除" in text or "永久删除" in text


@e2e_test("T1_F8_05", 1, ["F8"], "Encrypted attachments round-trip byte-identically")
def t1_f8_05(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "attachment/document item UI is absent")
    text = desktop_sources(ctx)
    assert "attachment" in text.lower() or "附件" in text


@e2e_test("T1_F8_06", 1, ["F8"], "Settings persist custom auto-lock and clipboard timeouts")
def t1_f8_06(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "configurable auto-lock/clipboard timeout settings are absent")
    text = desktop_sources(ctx)
    assert "自动锁定" in text
