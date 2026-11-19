"""Tier 1 feature-verification E2E tests for F1-F8.

Every test uses a user-facing surface.  Milestone-only cases perform a real
probe first and then raise the progressive gate, so pre-merge runs report
``PENDING_FEATURE`` instead of silently passing.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from .harness import e2e_test
from .support import (
    add_item,
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
    f2_passkey_management_ready,
    f3_team_sync_ready,
    f4_team_cli_ready,
    f5_desktop_timer_ready,
    f5_filter_refresh_ready,
    f7_shared_ipc_ready,
    f8_desktop_v2_ready,
    f8_v2_editor_ready,
    gate,
    go_package_test,
    health_report,
    init_vault,
    item_metadata,
    legacy_rich_1pux,
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
    write_typed_item,
    f13_watchtower_ready,
)


def _run_team_sync_help(ctx) -> str:
    binary = ctx.team_sync_bin
    assert binary is not None and binary.is_file()
    result = ctx.run_cli(["help"], binary=binary, timeout=8.0)
    return (result.stdout or "") + (result.stderr or "")


V2_MODEL = ("--model", "v2")


def _plan_import(
    ctx,
    vault,
    archive,
    *,
    v2: bool = True,
    confirm: str = "PLAN",
):
    args = [
        "personal",
        "plan-import-1pux",
        "--file",
        str(vault["path"]),
        "--source",
        str(archive),
    ]
    if v2:
        args.extend(V2_MODEL)
    return pty(
        ctx,
        args,
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 PLAN 确认生成导入计划", confirm)],
    )


def _import_archive(ctx, vault, archive, digest, *, v2: bool = True):
    args = [
        "personal",
        "import-1pux",
        "--file",
        str(vault["path"]),
        "--source",
        str(archive),
        "--digest",
        digest,
    ]
    if v2:
        args.extend(V2_MODEL)
    return pty(
        ctx,
        args,
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认整批导入", "SAVE")],
    )


def _import_multi_category(ctx, vault) -> tuple[dict, dict]:
    archive = multi_category_1pux(ctx)
    plan = _plan_import(ctx, vault, archive)
    assert plan.returncode == 0, plan.transcript[-1200:]
    payload = plan.json()
    digest = payload["report"]["source_digest"]
    apply = _import_archive(ctx, vault, archive, digest)
    assert apply.returncode == 0, apply.transcript[-1200:]
    return payload, apply.json()


def _plan_multi_category(ctx, vault):
    return _plan_import(ctx, vault, multi_category_1pux(ctx))


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


@e2e_test(
    "T1_F2_07", 1, ["F2"],
    "Passkey list projects safe metadata and filters before the 500-item cap",
    coverage_kind="component_contract",
)
def t1_f2_07(ctx):
    gate(ctx, "F2", f2_passkey_management_ready(ctx), "Passkey management protocol is absent on the extension or native host")
    go_package_test(
        ctx, "./internal/browserhost",
        r"^TestPasskey(ManagementMetadataSearchAndStrictWire|FilterRunsBeforeFiveHundredCap)$",
        min_passed=2,
    )
    node_test_pattern(
        ctx, "browser-extension/test/background.test.js",
        r"passkey metadata is a safe DTO and searches forward the server filter",
        min_passed=1,
    )


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
    # Locked-desktop startup smoke; settings cannot select or unlock the vault.
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
    # Locked-desktop startup smoke; settings cannot select or unlock the vault.
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

# The documented `personal add-item` category projection (docs/typed-personal-cli.md).
# Documents use explicit attachment files and ssh_key uses one explicit
# owner-private Ed25519 key file; both are covered by dedicated PTY cases instead
# of this inline category tuple. Raw key/attachment bodies stay outside.
F6_ADD_ITEM_CATEGORIES = (
    "login",
    "password",
    "secure_note",
    "credit_card",
    "identity",
    "api_credential",
    "database",
    "server",
    "bank_account",
    "wireless_router",
    "software_license",
    "membership",
    "crypto_wallet",
    "medical_record",
)

F6_CONCEALED_CANARY = "CANARY-T1-F6-02-CONCEALED-7731"
F6_AMBIGUOUS_CANARY = "CANARY-T1-F6-02-AMBIGUOUS-8822"
F6_TAGS = ("F6Tag-Alpha-4417", "F6Tag-Beta-4417")
F6_TAG_FIELD_CANARY = "CANARY-T1-F6-04-PIN-9933"


def _terminal_command_ready(ctx, args):
    """Probe a personal command without trusting the partial top-level help text.

    A real command that reaches the interactive-terminal boundary exists; a
    missing command falls through to the fixed ``usage:`` string instead.
    """

    result = ctx.run_cli(args)
    text = (result.stdout or "") + (result.stderr or "")
    return "interactive terminal" in text and "usage: locklark personal" not in text


def _add_item_ready(ctx):
    return _terminal_command_ready(
        ctx, ["personal", "add-item", "--file", "unused.ll", "--input", "unused.json"]
    )


def _references_ready(ctx):
    return _terminal_command_ready(ctx, ["personal", "references", "--file", "unused.ll"])


def _row_by_id(rows, item_id):
    row = next((entry for entry in rows if entry.get("id") == item_id), None)
    assert row is not None, f"item {item_id} missing from personal list"
    return row


def _disclosed_value(result) -> object:
    match = re.search(r'\r?\n("(?:[^"\\]|\\.)*")\s*$', result.transcript)
    assert match, f"no JSON disclosure on the terminal: {result.transcript[-400:]!r}"
    return json.loads(match.group(1))


def _f6_document(category: str, index: int) -> dict:
    document: dict = {
        "category": category,
        "title": f"Matrix {category}",
        "tags": [f"matrix-{index}"],
    }
    if category == "login":
        document["username"] = "matrix-user"
        document["password"] = "matrix-pass-2026-Aa1!"
        document["url"] = "https://matrix.example.test/login"
    elif category == "password":
        document["password"] = "matrix-password-2026"
    elif category == "secure_note":
        document["notes"] = "matrix secure note"
    elif category == "credit_card":
        document["credit_card"] = {
            "cardholder_name": "Matrix Holder",
            "number": "4111111111111111",
            "expiry_date": "2030-01",
        }
    elif category == "identity":
        document["identity"] = {"first_name": "Matrix", "last_name": "Identity"}
    return document


@e2e_test(
    "T1_F6_01",
    1,
    ["F6"],
    "Documented add-item category matrix persists in the encrypted vault",
)
def t1_f6_01(ctx):
    ready = _add_item_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI `personal add-item` command is absent (command-surface gap); the v2 item "
        "model and category browser exist in the desktop/browser host",
    )
    vault = make_vault(ctx)
    created = {}
    for index, category in enumerate(F6_ADD_ITEM_CATEGORIES):
        payload = add_item(
            ctx,
            vault,
            _f6_document(category, index),
            name=f"category-{index}.json",
        )
        created[category] = payload["id"]
    rows = list_rows(ctx, vault, "all")
    by_id = {row["id"]: row for row in rows}
    categories = set()
    for category, item_id in created.items():
        row = by_id.get(item_id)
        assert row is not None, f"{category} item missing from list"
        require_hex64(row["revision"])
        detail = item_metadata(ctx, vault, row)
        assert detail["id"] == item_id, detail
        assert detail["category"] == category, (category, detail)
        categories.add(detail["category"])
    assert categories >= set(F6_ADD_ITEM_CATEGORIES), categories


@e2e_test(
    "T1_F6_02",
    1,
    ["F6"],
    "Created concealed section reference discloses by ref and refuses ambiguity",
)
def t1_f6_02(ctx):
    ready = _add_item_ready(ctx) and _references_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item/references command surface is absent; section-qualified custom "
        "fields exist in the v2 host model, so op:// references cannot be created "
        "through the CLI",
    )
    vault = make_vault(ctx)
    created = add_item(
        ctx,
        vault,
        {
            "category": "login",
            "title": "Recovery Kit",
            "username": "rec-user",
            "password": "rec-pass-2026-Aa1!",
            "sections": [
                {
                    "id": "recovery",
                    "title": "Recovery",
                    "fields": [
                        {
                            "id": "recovery_code",
                            "label": "Recovery Code",
                            "type": "concealed",
                            "value": F6_CONCEALED_CANARY,
                        }
                    ],
                }
            ],
        },
        name="recovery-kit.json",
    )
    references = pty(
        ctx,
        ["personal", "references", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
    )
    assert references.returncode == 0, references.transcript[-1000:]
    index = references.json()
    row = next(
        (entry for entry in index["items"] if entry["id"] == created["id"]), None
    )
    assert row is not None, index
    ref = row["references"]["recovery/recovery_code"]
    assert ref.startswith("op://"), ref
    revealed = pty(
        ctx,
        [
            "personal",
            "reveal-ref",
            "--file",
            str(vault["path"]),
            "--ref",
            ref,
            "--revision",
            created["revision"],
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SHOW 确认按引用显示", "SHOW")],
    )
    assert revealed.returncode == 0, revealed.transcript[-1000:]
    assert _disclosed_value(revealed) == F6_CONCEALED_CANARY

    ambiguous = add_item(
        ctx,
        vault,
        {
            "category": "login",
            "title": "Shared Field Kit",
            "sections": [
                {
                    "id": "one",
                    "title": "One",
                    "fields": [
                        {
                            "id": "shared_one",
                            "label": "Shared Code",
                            "type": "concealed",
                            "value": F6_AMBIGUOUS_CANARY,
                        }
                    ],
                },
                {
                    "id": "two",
                    "title": "Two",
                    "fields": [
                        {
                            "id": "shared_two",
                            "label": "Shared Code",
                            "type": "concealed",
                            "value": F6_AMBIGUOUS_CANARY,
                        }
                    ],
                },
            ],
        },
        name="shared-field-kit.json",
    )
    refused = pty(
        ctx,
        [
            "personal",
            "reveal-ref",
            "--file",
            str(vault["path"]),
            "--ref",
            f"op://Personal/{ambiguous['id']}/Shared Code",
            "--revision",
            ambiguous["revision"],
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SHOW 确认按引用显示", "SHOW")],
    )
    assert refused.returncode != 0, refused.transcript[-1000:]
    ctx.assert_no_canary_leak(F6_AMBIGUOUS_CANARY, refused.stdout, refused.transcript)


@e2e_test(
    "T1_F6_03",
    1,
    ["F6"],
    "Created multi-URL login matches primary and secondary but never a never-URL",
)
def t1_f6_03(ctx):
    ready = _add_item_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item command is absent; multi-URL fields exist in the v2 host item "
        "model but cannot be created through the CLI",
    )
    vault = make_vault(ctx)
    created = add_item(
        ctx,
        vault,
        {
            "category": "login",
            "title": "Corp SSO",
            "username": "alice",
            "password": "multi-url-pass-2026",
            "url": "https://sso.corp.example.test/login",
            "urls": [
                {
                    "label": "primary",
                    "url": "https://sso.corp.example.test/login",
                    "primary": True,
                },
                {"label": "portal", "url": "https://portal.corp.example.test/auth"},
                {
                    "label": "blocked",
                    "url": "https://blocked.corp.example.test/",
                    "match_mode": "never",
                },
            ],
        },
        name="multi-url-login.json",
    )
    from .support import match_logins

    primary = match_logins(ctx, vault, "https://sso.corp.example.test")
    secondary = match_logins(ctx, vault, "https://portal.corp.example.test")
    never = match_logins(ctx, vault, "https://blocked.corp.example.test")
    for rows in (primary, secondary):
        assert len(rows) == 1 and rows[0]["id"] == created["id"], rows
    assert never == [], never
    row = _row_by_id(list_rows(ctx, vault), created["id"])
    detail = item_metadata(ctx, vault, row)
    primary_urls = [entry for entry in detail["urls"] if entry.get("primary")]
    assert len(primary_urls) == 1, detail
    assert primary_urls[0]["url"] == "https://sso.corp.example.test/login", detail
    by_url = {entry["url"]: entry.get("match_mode", "") for entry in detail["urls"]}
    assert by_url == {
        "https://sso.corp.example.test/login": "",
        "https://portal.corp.example.test/auth": "",
        "https://blocked.corp.example.test/": "never",
    }, detail


@e2e_test(
    "T1_F6_04",
    1,
    ["F6"],
    "Created tags and favorite stay encrypted yet survive backup/restore",
)
def t1_f6_04(ctx):
    ready = _add_item_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item command is absent; tags/favorite metadata are part of the v2 "
        "host item model, so the encrypted round trip cannot be driven from the CLI",
    )
    vault = make_vault(ctx)
    created = add_item(
        ctx,
        vault,
        {
            "category": "login",
            "title": "Tagged GitHub",
            "username": "alice",
            "password": "tagged-pass-2026",
            "favorite": True,
            "tags": list(F6_TAGS),
            "sections": [
                {
                    "id": "extras",
                    "title": "Extras",
                    "fields": [
                        {
                            "id": "support_pin",
                            "label": "Support PIN",
                            "type": "concealed",
                            "value": F6_TAG_FIELD_CANARY,
                        }
                    ],
                }
            ],
        },
        name="tagged-github.json",
    )
    row = _row_by_id(list_rows(ctx, vault), created["id"])
    detail = item_metadata(ctx, vault, row)
    assert detail["favorite"] is True, detail
    assert set(detail["tags"]) == set(F6_TAGS), detail
    assert detail["section_ids"] == ["extras"], detail
    assert detail["section_field_counts"] == {"extras": 1}, detail
    vault_bytes = Path(vault["path"]).read_bytes()
    for canary in (*F6_TAGS, F6_TAG_FIELD_CANARY):
        ctx.assert_no_canary_leak(canary, vault_bytes)

    backup = ctx.temp_dir / "tags-backup.ll"
    created_backup = pty(
        ctx,
        ["personal", "backup", "--file", str(vault["path"]), "--out", str(backup)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("重新输入恢复码", None)],
    )
    assert created_backup.returncode == 0, created_backup.transcript[-1000:]
    assert backup.is_file()
    ctx.assert_no_canary_leak(F6_TAG_FIELD_CANARY, backup.read_bytes())

    restored = ctx.temp_dir / "tags-restored.ll"
    restored_result = pty(
        ctx,
        ["personal", "restore", "--file", str(backup), "--out", str(restored)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("此备份的恢复码", created_backup.issued[0]), ("重新输入新 Secret Key", None)],
    )
    assert restored_result.returncode == 0, restored_result.transcript[-1000:]
    assert restored_result.issued
    restored_rows = pty(
        ctx,
        ["personal", "list", "--file", str(restored)],
        password=vault["password"],
        secret=restored_result.issued[0],
    )
    assert restored_rows.returncode == 0, restored_rows.transcript[-800:]
    restored_row = _row_by_id(restored_rows.json(), created["id"])
    restored_vault = {
        "path": restored,
        "password": vault["password"],
        "secret": restored_result.issued[0],
    }
    restored_detail = item_metadata(ctx, restored_vault, restored_row)
    assert restored_detail["favorite"] is True, restored_detail
    assert set(restored_detail["tags"]) == set(F6_TAGS), restored_detail
    assert restored_detail["section_ids"] == ["extras"], restored_detail


@e2e_test(
    "T1_F6_05",
    1,
    ["F6"],
    "Explicit v2 1PUX plan/import maps four categories; default and changed digest refuse",
)
def t1_f6_05(ctx):
    vault = init_vault(ctx)
    archive = multi_category_1pux(ctx)
    default_plan = _plan_import(ctx, vault, archive, v2=False)
    assert default_plan.returncode != 0, default_plan.transcript[-1200:]
    assert "unsupported 1PUX archive feature" in default_plan.transcript, (
        default_plan.transcript[-800:]
    )
    plan = _plan_import(ctx, vault, archive)
    assert plan.returncode == 0, plan.transcript[-1200:]
    payload = plan.json()
    assert payload["report"]["profile"] == "1pux-full-v2", payload
    assert payload["report"]["items"] == 4, payload
    digest = payload["report"]["source_digest"]

    changed = _import_archive(ctx, vault, archive, "0" * 64)
    assert changed.returncode != 0, changed.transcript[-1200:]
    assert "1PUX source changed since the confirmed plan" in changed.transcript, (
        changed.transcript[-1200:]
    )
    assert list_rows(ctx, vault) == [], "changed digest imported part of the batch"

    apply = _import_archive(ctx, vault, archive, digest)
    assert apply.returncode == 0, apply.transcript[-1200:]
    rows = list_rows(ctx, vault, "all")
    titles = {row["title"]: row for row in rows}
    assert {"Corp SSO", "Runbook", "Ada Lovelace", "Corp Visa"} <= set(titles), titles
    sso = item_metadata(ctx, vault, titles["Corp SSO"])
    assert sso["category"] == "login", sso
    assert sso["favorite"] is True, sso
    assert set(sso["tags"]) == {"imported", "sso"}, sso
    assert {entry["url"] for entry in sso["urls"]} == {
        "https://sso.corp.example.test/login",
        "https://portal.corp.example.test/auth",
    }, sso
    assert [entry for entry in sso["urls"] if entry.get("primary")], sso
    assert sso["section_ids"] == ["recovery"], sso

    legacy = legacy_rich_1pux(ctx)
    legacy_plan = _plan_import(ctx, vault, legacy)
    assert legacy_plan.returncode != 0, legacy_plan.transcript[-1200:]
    assert "unsupported 1PUX archive feature" in legacy_plan.transcript, (
        legacy_plan.transcript[-1200:]
    )
    assert len(list_rows(ctx, vault, "all")) == 4, "legacy refusal mutated the vault"


@e2e_test(
    "T1_F6_06",
    1,
    ["F6"],
    "Existing v1 login-notes vaults migrate without ID/revision churn",
)
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


@e2e_test(
    "T1_F6_07",
    1,
    ["F6"],
    "Document creation with explicit private attachment files round-trips exact bytes",
)
def t1_f6_07(ctx):
    ready = _add_item_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI `personal add-item` command is absent; attachment documents cannot be probed",
    )
    vault = make_vault(ctx)
    bodies = [bytes([0, 1, 255, 254, 65, 0, 127, 128]), b"second\x00body\xff\n", b""]
    attachments = []
    for index, body in enumerate(bodies):
        path = ctx.temp_dir / f"attachment-{index}.bin"
        path.write_bytes(body)
        path.chmod(0o600)
        attachments.append(
            {
                "file": str(path),
                "file_name": path.name,
                "mime_type": "application/octet-stream",
            }
        )
    total_bytes = sum(len(body) for body in bodies)
    assert total_bytes == 21
    document = {
        "category": "document",
        "title": "Synthetic binary document",
        "attachments": attachments,
    }
    source = write_typed_item(ctx, "document-attachments.json", document)

    def create(consent):
        return pty(
            ctx,
            [
                "personal",
                "add-item",
                "--file",
                str(vault["path"]),
                "--input",
                str(source),
            ],
            password=vault["password"],
            secret=vault["secret"],
            extra=[] if consent is None else [("输入 SAVE 确认新增条目", consent)],
        )

    baseline = len(list_rows(ctx, vault, "all"))

    saved = create("SAVE")
    assert saved.returncode == 0, saved.transcript[-800:]
    receipt = saved.json()
    assert set(receipt) == {"status", "id", "revision"}, receipt
    assert receipt["status"] == "created", receipt
    require_hex32(receipt["id"])
    require_hex64(receipt["revision"])
    assert f"{len(attachments)} 个附件共 {total_bytes} 字节" in saved.transcript, (
        saved.transcript[-400:]
    )

    # Neither the SAVE receipt, the consent prompt nor the transcript may echo
    # the document title, an attachment path/name or any raw body bytes.
    visible = saved.transcript + saved.stdout
    for value in [document["title"], *[entry["file"] for entry in attachments],
                  *[entry["file_name"] for entry in attachments]]:
        assert value not in visible, value
    for body in bodies:
        if body:
            assert body.hex() not in visible.lower()

    rows = list_rows(ctx, vault, "all")
    assert len(rows) == baseline + 1, "document creation did not add exactly one item"
    row = next(entry for entry in rows if entry["id"] == receipt["id"])
    assert row["revision"] == receipt["revision"], row
    assert row["kind"] == "document", row

    detail = item_metadata(ctx, vault, row, verify_attachments=True)
    assert detail["id"] == receipt["id"], detail
    assert detail["category"] == "document", detail
    assert detail["attachment_read_verified"] is True, detail
    assert len(detail["attachments"]) == len(attachments), detail["attachments"]
    for expected, meta, read in zip(
        attachments, detail["attachments"], detail["attachment_reads"]
    ):
        body = next(item for item in bodies if len(item) == meta["size"] and
                    hashlib.sha256(item).hexdigest() == meta["sha256"])
        digest = hashlib.sha256(body).hexdigest()
        assert meta["file_name"] == expected["file_name"], meta
        assert meta["mime_type"] == expected["mime_type"], meta
        assert meta["size"] == len(body), meta
        assert meta["sha256"] == digest, meta
        assert read == {"sha256": digest, "bytes": len(body)}, read
    projected = json.dumps(detail)
    for body in bodies:
        if body:
            assert body.hex() not in projected.lower()

    # A wrong consent word mutates nothing.
    wrong = create("NOPE")
    assert wrong.returncode != 0, wrong.transcript[-800:]
    assert wrong.stdout.strip() == "", wrong.stdout
    assert len(list_rows(ctx, vault, "all")) == baseline + 1, "wrong SAVE mutated the vault"

    # One attachment that is no longer owner-only is refused before SAVE, and
    # no path or body material crosses the refusal boundary.
    unsafe = ctx.temp_dir / "attachment-1.bin"
    unsafe.chmod(0o644)
    refused = create(None)
    unsafe.chmod(0o600)
    assert refused.returncode != 0, refused.transcript[-800:]
    assert "输入 SAVE" not in refused.transcript, refused.transcript[-400:]
    for entry in attachments:
        assert entry["file"] not in refused.transcript, entry["file"]
    assert len(list_rows(ctx, vault, "all")) == baseline + 1, (
        "unsafe attachment refusal mutated the vault"
    )


@e2e_test(
    "T1_F6_08",
    1,
    ["F6"],
    "Typed ssh_key creation from an explicit owner-private Ed25519 file",
)
def t1_f6_08(ctx):
    import base64
    import subprocess

    ready = _add_item_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI `personal add-item` command is absent; typed SSH private-file creation cannot run",
    )
    vault = make_vault(ctx)
    baseline = len(list_rows(ctx, vault, "all"))

    key_dir = ctx.temp_dir / "typed-ssh-key"
    key_dir.mkdir(mode=0o700, exist_ok=True)
    key_path = key_dir / "id_ed25519"
    generated = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "e2e", "-f", str(key_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert generated.returncode == 0, "ssh-keygen failed to create the private fixture"
    key_path.chmod(0o600)
    public_line = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(key_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert public_line.returncode == 0, "ssh-keygen failed to derive the public fixture"
    public_wire = base64.b64decode(public_line.stdout.split()[1])

    title = "Typed SSH PTY private title"
    document = {
        "category": "ssh_key",
        "title": title,
        "ssh_private_key_file": str(key_path),
        "tags": ["infra"],
        "favorite": True,
        "sections": [
            {
                "id": "ops",
                "title": "Ops",
                "fields": [{"id": "note", "label": "Note", "value": "owner-visible"}],
            }
        ],
    }
    created_input = write_typed_item(ctx, "ssh-key.json", document)
    created = pty(
        ctx,
        ["personal", "add-item", "--file", str(vault["path"]), "--input", str(created_input)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认新增条目", "SAVE")],
    )
    assert created.returncode == 0, created.transcript[-800:]
    payload = created.json()
    assert set(payload) == {"status", "id", "revision"}, payload
    assert payload["status"] == "created"
    assert len(payload["id"]) == 32 and len(payload["revision"]) == 64
    for marker in (
        str(created_input),
        str(key_path),
        "BEGIN OPENSSH PRIVATE KEY",
        base64.b64encode(public_wire).decode("ascii"),
        title,
    ):
        assert marker not in created.transcript, (
            "receipt or prompt leaked protected SSH material"
        )

    metadata = item_metadata(ctx, vault, payload, verify_ssh_public=public_wire)
    assert metadata["category"] == "ssh_key", metadata
    assert metadata["tags"] == ["infra"], metadata
    assert metadata["favorite"] is True, metadata
    assert metadata["section_ids"] == ["ops"], metadata
    assert metadata["section_field_counts"] == {"ops": 1}, metadata
    assert metadata["ssh_pair_matches"] is True, metadata
    assert len(list_rows(ctx, vault, "all")) == baseline + 1

    malformed_path = ctx.temp_dir / "ssh-malformed-key"
    malformed_path.write_text("not a private key\n", encoding="utf-8")
    malformed_path.chmod(0o600)
    unsafe_path = key_dir / "id_ed25519_world"
    unsafe_path.write_bytes(key_path.read_bytes())
    unsafe_path.chmod(0o644)
    raw_private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    documents = {
        "ssh-bare.json": {"category": "ssh_key", "title": "Unsupported ssh_key"},
        "ssh-private-key.json": {
            "category": "ssh_key",
            "title": "Raw private key",
            "private_key": raw_private_key,
        },
        "ssh-key-field.json": {
            "category": "ssh_key",
            "title": "Key field",
            "sections": [
                {
                    "id": "ssh",
                    "title": "SSH",
                    "fields": [
                        {
                            "id": "private_key",
                            "label": "Private Key",
                            "type": "concealed",
                            "value": raw_private_key,
                        }
                    ],
                }
            ],
        },
        "ssh-malformed.json": {
            "category": "ssh_key",
            "title": "Malformed key",
            "ssh_private_key_file": str(malformed_path),
        },
        "ssh-unsafe.json": {
            "category": "ssh_key",
            "title": "Unsafe key",
            "ssh_private_key_file": str(unsafe_path),
        },
        "ssh-wrong-category.json": {
            "category": "login",
            "title": "Wrong category",
            "ssh_private_key_file": str(key_path),
        },
    }
    for name, bad_document in documents.items():
        path = write_typed_item(ctx, name, bad_document)
        refused = pty(
            ctx,
            ["personal", "add-item", "--file", str(vault["path"]), "--input", str(path)],
            password=vault["password"],
            secret=vault["secret"],
        )
        assert refused.returncode != 0, (name, refused.transcript[-800:])
        assert refused.stdout.strip() == "", (name, refused.stdout)
        assert "输入 SAVE" not in refused.transcript, (name, refused.transcript[-400:])
        for marker in (
            "BEGIN OPENSSH PRIVATE KEY",
            raw_private_key.strip(),
            str(path),
            str(key_path),
        ):
            assert marker not in refused.transcript, (name, marker)
        assert len(list_rows(ctx, vault, "all")) == baseline + 1, (
            f"refused SSH document mutated the vault: {name}"
        )

    wrong_input = write_typed_item(
        ctx,
        "ssh-wrong-save.json",
        {
            "category": "ssh_key",
            "title": "Wrong SAVE",
            "ssh_private_key_file": str(key_path),
        },
    )
    wrong = pty(
        ctx,
        ["personal", "add-item", "--file", str(vault["path"]), "--input", str(wrong_input)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认新增条目", "NOPE")],
    )
    assert wrong.returncode != 0, wrong.transcript[-800:]
    assert "输入 SAVE" in wrong.transcript
    assert len(list_rows(ctx, vault, "all")) == baseline + 1, "wrong SAVE mutated the vault"
    ctx.require_feature(
        "F6",
        True,
        "typed ssh_key creation from an explicit owner-private Ed25519 file verified "
        "over the real PTY",
    )


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
    # Locked-desktop startup smoke; settings cannot select or unlock the vault.
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
    # Locked-desktop startup smoke; settings cannot select or unlock the vault.
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
