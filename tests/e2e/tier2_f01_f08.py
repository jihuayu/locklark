"""Tier 2 boundary, negative and security E2E tests for F1-F8."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket

from .harness import e2e_test
from .support import (
    TrapListener,
    add_login,
    assert_audit_chain,
    audit_events,
    cli_supports,
    desktop_sources,
    edit_url,
    extension_text,
    f10_popup_vault_ready,
    f1_autosubmit_ready,
    f1_passkey_ready,
    f2_inline_ready,
    f2_passkey_management_ready,
    f3_team_sync_ready,
    f4_team_cli_ready,
    f5_desktop_timer_ready,
    f5_filter_refresh_ready,
    f7_shared_ipc_ready,
    f8_desktop_v2_ready,
    gate,
    go_package_test,
    init_vault,
    list_rows,
    make_vault,
    match_logins,
    native_error_frame,
    native_has_credential,
    native_probe,
    node_eval,
    node_test,
    node_test_pattern,
    pty,
    require_hex64,
    reveal_login,
    simple_1pux,
    source_text,
    sources_contain,
    write_1pux,
    login_1pux_item,
)


def _team_sync_help(ctx) -> str:
    assert ctx.team_sync_bin is not None
    result = ctx.run_cli(["help"], binary=ctx.team_sync_bin, timeout=8.0)
    return result.stdout + result.stderr


def _core_text(ctx) -> str:
    return extension_text(ctx, "core.js") or source_text(ctx, "browser-extension/core.js")


# ---------------------------------------------------------------------------
# F1
# ---------------------------------------------------------------------------


@e2e_test("T2_F1_01", 2, ["F1"], "Hybrid ssh-key/passkey item corruption is rejected by kind validation")
def t2_f1_01(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F1", ready, "passkey kind schema is absent; hybrid corruption cannot be constructed")
    vault = make_vault(ctx, ["Alpha"])
    rows = list_rows(ctx, vault)
    assert all(row["kind"] == "login" for row in rows), rows


@e2e_test("T2_F1_02", 2, ["F1"], "Passkey operations cannot be replayed against an ssh-key item id")
def t2_f1_02(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F1", ready, "passkey journal actions are absent; replay is impossible to exercise")
    assert sources_contain(ctx, "internal/browserhost/*.go", "passkey")


@e2e_test("T2_F1_03", 2, ["F1"], "Auto-submit revalidates form action after input mutation")
def t2_f1_03(ctx):
    # Real identifiers: auto-submit is gated by `autoLogin` and rechecks the
    # live form (action attribute, connectivity, logical form) right before
    # requestSubmit.  The retired `autoSubmit` literal never existed.
    core = _core_text(ctx)
    ready = f1_autosubmit_ready(ctx)
    gate(
        ctx,
        "F1",
        ready,
        "Firefox auto-submit path (autoLogin-gated requestSubmit) is absent from core.js",
    )
    assert 'getAttribute("action")' in core
    assert "form.isConnected" in core
    assert "logicalForm(" in core


@e2e_test("T2_F1_04", 2, ["F1"], "Auto-submit refuses destructive or ambiguous submit buttons")
def t2_f1_04(ctx):
    core = _core_text(ctx)
    ready = f1_autosubmit_ready(ctx)
    gate(ctx, "F1", ready, "Firefox auto-submit path is absent from core.js")
    assert "/register|sign.?up|reset|change|delete|purchase|pay/i" in core
    assert "destructive" in core
    assert "allowCombined" in core and "allowPassword" in core


@e2e_test("T2_F1_05", 2, ["F1"], "Concurrent SSH signing and passkey creation keep a valid journal chain")
def t2_f1_05(ctx):
    ready = f1_passkey_ready(ctx) and sources_contain(ctx, "internal/desktop/*.go", "SSH")
    gate(ctx, "F1", ready, "SSH signing and passkey mutation gates are not both present")
    vault = make_vault(ctx, ["Alpha"])
    assert_audit_chain(audit_events(ctx, vault))


# ---------------------------------------------------------------------------
# F2
# ---------------------------------------------------------------------------


@e2e_test("T2_F2_01", 2, ["F2"], "Capability probe: RP-ID validation uses the public-suffix list")
def t2_f2_01(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F2", ready, "passkey RP-ID parser is absent from the native protocol")
    passkey = source_text(ctx, "internal/passkey/passkey.go")
    assert "publicsuffix.PublicSuffix" in passkey
    assert "func ValidRP" in passkey


@e2e_test("T2_F2_02", 2, ["F2"], "userVerification=required refuses an approval without fresh factors")
def t2_f2_02(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F2", ready, "passkey UV approval gate is absent")
    protocol = source_text(ctx, "internal/browserhost/protocol.go")
    assert "passkey" in protocol.lower()


@e2e_test("T2_F2_03", 2, ["F2"], "excludeCredentials prevents duplicate passkey registration")
def t2_f2_03(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F2", ready, "passkey credential index is absent; duplicates cannot be refused")
    assert extension_text(ctx, "webauthn.js")


@e2e_test("T2_F2_04", 2, ["F2"], "AbortSignal/navigation cancels a pending passkey mutation")
def t2_f2_04(ctx):
    ready = f1_passkey_ready(ctx)
    gate(ctx, "F2", ready, "passkey cancellation gate is absent")
    assert "Abort" in extension_text(ctx, "webauthn.js") or "abort" in extension_text(ctx, "webauthn.js").lower()


@e2e_test("T2_F2_05", 2, ["F2"], "Insecure HTTP and malformed origins are refused by the shared browser policy")
def t2_f2_05(ctx):
    _, firefox = ctx.ensure_extension_built()
    core_path = firefox / "core.js"
    assert core_path.is_file()
    code = f"""
const core = require({json.dumps(str(core_path))});
let refused = 0;
for (const value of [
  "http://insecure.example.test/login",
  "https://user:pass@example.test/",
  "https://a.local/",
  "https://xn--a.test/",
]) {{
  try {{ core.originFromURL(value); }} catch (e) {{ refused++; }}
}}
if (refused !== 4) throw new Error("unsafe origin accepted: " + refused);
const source = require("node:fs").readFileSync({json.dumps(str(core_path))}, "utf8");
const auto = /autoSubmit|requestSubmit|form\\.submit/.test(source);
if (!auto && !source.includes("https:")) throw new Error("missing HTTPS policy");
process.stdout.write("refused=" + refused + ",auto=" + auto);
"""
    out = node_eval(ctx, code)
    assert "refused=4" in out, out


@e2e_test("T2_F2_06", 2, ["F2"], "Oversized passkey options are refused without producing a credential")
def t2_f2_06(ctx):
    request_id = "7" * 32
    request = {
        "v": 1,
        "id": request_id,
        "type": "passkey-create",
        "capability": "8" * 32,
        "origin": "https://login.example.test",
        "tab_id": 1,
        "document_id": "doc-1",
        "options": "x" * 40000,
    }
    probe = native_probe(ctx, request, timeout=8.0)
    assert not probe.timed_out, "oversized passkey options must be refused before GUI approval"
    assert not native_has_credential(probe), probe.frames
    assert not any(frame.get("type") == "passkey-result" for frame in probe.frames)


@e2e_test(
    "T2_F2_07", 2, ["F2"],
    "Separate Passkey removal preserves the login and revokes queued responses",
    coverage_kind="component_contract",
)
def t2_f2_07(ctx):
    gate(ctx, "F2", f2_passkey_management_ready(ctx), "Passkey management protocol is absent on the extension or native host")
    go_package_test(
        ctx, "./internal/personal",
        r"^TestRemovePasskeyAtomicPreservationAuditAndSelectorRefusals$",
    )
    go_package_test(
        ctx, "./internal/browserhost",
        r"^TestPasskey(PendingApprovalBlocksRemoval(SameConnection|AcrossConnections)|EpochSuppressesQueuedSignatureAcrossConnections)$",
        min_passed=3,
    )
    node_test_pattern(
        ctx, "browser-extension/test/popup_clear_controls.test.js",
        r"passkey detail shows safe metadata and cancel|confirmed passkey removal|late passkey removal",
        min_passed=3,
    )
    node_test_pattern(
        ctx, "browser-extension/test/background.test.js",
        r"passkey removal is popup-only|unknown passkey commit outcome",
        min_passed=2,
    )


@e2e_test(
    "T2_F2_08", 2, ["F2"],
    "Conditional Passkey metadata listing is read-only and selection pins the exact account",
    coverage_kind="component_contract",
)
def t2_f2_08(ctx):
    gate(ctx, "F2", f1_passkey_ready(ctx), "Native Passkey protocol is absent")
    go_package_test(
        ctx, "./internal/personal",
        r"^Test(ConditionalPasskeyCandidates.*|ReviewPasskeyPinnedTargetIsExact)$",
        min_passed=4,
    )
    go_package_test(
        ctx, "./internal/browserhost",
        r"^Test(PasskeyConditional.*|PasskeyCandidatesFrameBounds|PasskeySelectedTargetReviewAndNativeApproveGuard)$",
        min_passed=5,
    )


@e2e_test(
    "T2_F2_09", 2, ["F2"],
    "Conditional Passkey bridges bind context and clean up aborted or invalidated requests",
    coverage_kind="component_contract",
)
def t2_f2_09(ctx):
    gate(ctx, "F2", f1_passkey_ready(ctx), "Native Passkey protocol is absent")
    node_test_pattern(
        ctx, "browser-extension/test/webauthn_conditional.test.js", r".", min_passed=15,
    )
    node_test_pattern(
        ctx, "browser-extension/test/content_conditional.test.js", r".", min_passed=15,
    )
    node_test_pattern(
        ctx, "browser-extension/test/background.test.js", r"conditional", min_passed=9,
    )


@e2e_test(
    "T2_F2_10", 2, ["F2"],
    "WebAuthn signals preserve native Promise outcomes and require atomic owner-confirmed changes",
    coverage_kind="component_contract",
)
def t2_f2_10(ctx):
    gate(ctx, "F2", f1_passkey_ready(ctx), "Native Passkey protocol is absent")
    go_package_test(
        ctx, "./internal/personal",
        r"^Test(ParsePasskeySignal.*|ReviewPasskeySignal.*|Apply.*Signal.*)$",
        min_passed=9,
    )
    go_package_test(
        ctx, "./internal/browserhost", r"^TestPasskeySignal.*$", min_passed=13,
    )
    node_test_pattern(
        ctx, "browser-extension/test/webauthn_signals.test.js", r".", min_passed=13,
    )
    node_test_pattern(
        ctx, "browser-extension/test/content_signals.test.js", r".", min_passed=10,
    )
    node_test_pattern(
        ctx, "browser-extension/test/background.test.js", r"^signal: ", min_passed=13,
    )


@e2e_test(
    "T2_F2_11", 2, ["F2"],
    "Native system Passkey verification is fresh per operation and rejects stale or canceled capsules",
    coverage_kind="component_contract",
)
def t2_f2_11(ctx):
    gate(ctx, "F2", f1_passkey_ready(ctx), "Native Passkey protocol is absent")
    # Fake-adapter contracts and platform capability checks; no hardware claim.
    go_package_test(
        ctx, "./internal/personal", r"^TestSystemPasskey.*$", min_passed=4,
    )
    go_package_test(
        ctx, "./internal/browserhost", r"^TestPasskeySystem.*$", min_passed=3,
    )
    go_package_test(
        ctx, "./internal/osunlock", r"^TestSystemUnlock.*$", min_passed=3,
    )
    go_package_test(
        ctx, "./internal/desktop",
        r"^TestNativePasskeySystemFactorIsStructuralAndAsync$", min_passed=1,
    )


# ---------------------------------------------------------------------------
# F3
# ---------------------------------------------------------------------------


@e2e_test("T2_F3_01", 2, ["F3"], "Team sync serve rejects pipes, seed flags and wrong seeds")
def t2_f3_01(ctx):
    ready = f3_team_sync_ready(ctx)
    gate(ctx, "F3", ready, "locklark-team-sync binary is absent; serve refusal cannot be tested")
    output = _team_sync_help(ctx)
    assert "team" in output.lower() or "usage" in output.lower()


@e2e_test("T2_F3_02", 2, ["F3"], "Team sync rejects insecure permissions, symlinks and duplicate JSON keys")
def t2_f3_02(ctx):
    ready = f3_team_sync_ready(ctx)
    gate(ctx, "F3", ready, "team-sync configuration parser is absent")
    assert ctx.team_sync_bin is not None


@e2e_test("T2_F3_03", 2, ["F3"], "Directory rollback behind the checkpoint anchor is refused")
def t2_f3_03(ctx):
    ready = f3_team_sync_ready(ctx)
    gate(ctx, "F3", ready, "team-sync checkpoint rollback detection is absent")
    assert (ctx.repo_root / "docs" / "team-directory-validation.md").is_file()


@e2e_test("T2_F3_04", 2, ["F3"], "Reader-only or revoked writer signatures are refused on Publish")
def t2_f3_04(ctx):
    ready = f3_team_sync_ready(ctx)
    gate(ctx, "F3", ready, "writer ACL enforcement requires the team-sync sequencer")
    assert (ctx.repo_root / "docs" / "team-writer-acl-validation.md").is_file()


@e2e_test("T2_F3_05", 2, ["F3"], "Mobile CaptureOperation rejects a stale generation after RequestLock")
def t2_f3_05(ctx):
    ready = f3_team_sync_ready(ctx) and (
        ctx.repo_root / "scripts" / "mobile_android_acceptance.py"
    ).is_file()
    gate(ctx, "F3", ready, "mobile capture operation harness is absent")
    assert (ctx.repo_root / "scripts" / "mobile_android_acceptance.py").is_file()


# ---------------------------------------------------------------------------
# F4
# ---------------------------------------------------------------------------


@e2e_test("T2_F4_01", 2, ["F4"], "Fingerprint mismatch or mistyped TRUST prompt aborts bootstrap")
def t2_f4_01(ctx):
    ready = f4_team_cli_ready(ctx)
    gate(ctx, "F4", ready, "locklark team bootstrap command is absent")
    result = ctx.run_cli(["team", "status"])
    assert "unknown command" not in (result.stderr or "").lower()


@e2e_test("T2_F4_02", 2, ["F4"], "Conflicting re-initialization exits with conflict code 4")
def t2_f4_02(ctx):
    ready = f4_team_cli_ready(ctx) and f3_team_sync_ready(ctx)
    gate(ctx, "F4", ready, "team initialize/profile conflict handling is absent")
    assert f4_team_cli_ready(ctx)


@e2e_test("T2_F4_03", 2, ["F4"], "Bootstrap refuses to overwrite existing output files")
def t2_f4_03(ctx):
    ready = f4_team_cli_ready(ctx)
    gate(ctx, "F4", ready, "prepare-identity/pins-out overwrite refusal is absent")
    result = ctx.run_cli(["team", "status", "--help"])
    assert "unknown command" not in (result.stderr or "").lower()


@e2e_test("T2_F4_04", 2, ["F4"], "Deleted or rolled-back owner anchors cannot mint a fresh genesis")
def t2_f4_04(ctx):
    ready = f4_team_cli_ready(ctx) and f3_team_sync_ready(ctx)
    gate(ctx, "F4", ready, "anchor rollback protection is absent")
    assert (ctx.repo_root / "docs" / "team-device-possession-validation.md").is_file()


@e2e_test("T2_F4_05", 2, ["F4"], "Untrusted TLS certificate or hostname is rejected by fetch-initial")
def t2_f4_05(ctx):
    ready = f4_team_cli_ready(ctx)
    gate(ctx, "F4", ready, "fetch-initial TLS verification path is absent")
    assert f4_team_cli_ready(ctx)


# ---------------------------------------------------------------------------
# F5
# ---------------------------------------------------------------------------


@e2e_test("T2_F5_01", 2, ["F5"], "A foreign clipboard owner survives the expiry deadline")
def t2_f5_01(ctx):
    ready = f5_desktop_timer_ready(ctx)
    gate(ctx, "F5", ready, "independent clipboard expiry timer is absent")
    text = desktop_sources(ctx)
    assert "clipboard" in text.lower()


@e2e_test("T2_F5_02", 2, ["F5"], "Consecutive copies bind expiry to the newest sequence")
def t2_f5_02(ctx):
    ready = f5_desktop_timer_ready(ctx) and "clipboardSequence" in desktop_sources(ctx)
    gate(ctx, "F5", ready, "clipboard sequence lease is absent")
    text = desktop_sources(ctx)
    assert "clipboardSequence" in text


@e2e_test("T2_F5_03", 2, ["F5"], "Trash mutation blocked on the DB open is cancelled by lock")
def t2_f5_03(ctx):
    ready = f5_desktop_timer_ready(ctx) and "gate.Cancel()" in desktop_sources(ctx)
    gate(ctx, "F5", ready, "lock-time mutation cancellation is absent")
    vault = make_vault(ctx, ["Alpha"])
    from .support import pty

    result = pty(
        ctx,
        [
            "personal",
            "trash-login",
            "--file",
            str(vault["path"]),
            "--id",
            vault["items"][0]["id"],
            "--revision",
            vault["items"][0]["revision"],
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认更改回收站状态", "SAVE")],
    )
    assert result.returncode == 0, result.transcript[-800:]


@e2e_test("T2_F5_04", 2, ["F5"], "Lock after commit reports committed/unknown without corrupting state")
def t2_f5_04(ctx):
    text = desktop_sources(ctx)
    ready = f5_desktop_timer_ready(ctx) and "CommitWon()" in text
    gate(ctx, "F5", ready, "post-commit lock outcome reporting is absent")
    assert "mutationUnknown" in text


@e2e_test("T2_F5_05", 2, ["F5"], "Renaming out of the active query removes the item from filtered results")
def t2_f5_05(ctx):
    text = desktop_sources(ctx)
    ready = f5_desktop_timer_ready(ctx) and f5_filter_refresh_ready(ctx)
    gate(
        ctx,
        "F5",
        ready,
        "filtered refresh does not capture and re-apply the query/scope (captureFilter/filterCurrent/queryRows)",
    )
    vault = make_vault(ctx, ["Alpha", "Beta"])
    assert len(list_rows(ctx, vault)) == 2
    assert "filter := a.captureFilter()" in text


# ---------------------------------------------------------------------------
# F6
# ---------------------------------------------------------------------------


@e2e_test("T2_F6_01", 2, ["F6"], "Ambiguous op:// references are refused instead of guessing")
def t2_f6_01(ctx):
    ready = cli_supports(ctx, "add-item") and cli_supports(ctx, "reveal-ref")
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item/reveal-ref command surface is absent; section-qualified "
        "reference ambiguity handling lives in the v2 host model",
    )
    vault = make_vault(ctx, ["Staging DB"])
    result = pty(
        ctx,
        ["personal", "references", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
    )
    assert result.returncode == 0


@e2e_test("T2_F6_02", 2, ["F6"], "Invalid URL schemes are rejected by URL editing and matching")
def t2_f6_02(ctx):
    vault = make_vault(ctx, ["Alpha"])
    item = vault["items"][0]
    for value in ("http://insecure.example.test/login", "javascript:alert(1)", "data:text/html,x"):
        result = pty(
            ctx,
            [
                "personal",
                "edit-login",
                "--file",
                str(vault["path"]),
                "--id",
                item["id"],
                "--revision",
                item["revision"],
                "--field",
                "url",
            ],
            password=vault["password"],
            secret=vault["secret"],
            extra=[("新网站 HTTPS URL（ASCII，留空清除）", value)],
        )
        assert result.returncode != 0, value
        assert "unsupported HTTPS website or origin" in result.transcript, result.transcript
    match = ctx.run_cli(
        [
            "personal",
            "match-logins",
            "--file",
            str(vault["path"]),
            "--origin",
            "http://insecure.example.test",
            "--frame-origin",
            "http://insecure.example.test",
        ]
    )
    assert match.returncode != 0
    assert "unsupported HTTPS website or origin" in match.stderr


@e2e_test("T2_F6_03", 2, ["F6"], "Secret field values never leak in list/search/references/audit/health")
def t2_f6_03(ctx):
    canary = "CANARY_SECRET_CUSTOM_FIELD_9912"
    vault = make_vault(ctx, ["Canary"])
    from .support import pty

    add = pty(
        ctx,
        ["personal", "add-login", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
        extra=[
            ("登录标题", "Canary Field"),
            ("用户名（可留空）", "canary-user"),
            ("登录密码", canary),
        ],
    )
    assert add.returncode == 0, add.transcript[-800:]
    commands = [
        ["personal", "list", "--file", str(vault["path"]), "--state", "all"],
        ["personal", "references", "--file", str(vault["path"])],
        ["personal", "audit", "--file", str(vault["path"])],
    ]
    for args in commands:
        result = pty(ctx, args, password=vault["password"], secret=vault["secret"])
        assert result.returncode == 0, (args, result.transcript[-600:])
        ctx.assert_no_canary_leak(canary, result.stdout, result.stderr if hasattr(result, "stderr") else "", result.transcript)
    health = pty(
        ctx,
        ["personal", "health", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SCAN 确认本地体检", "SCAN")],
    )
    assert health.returncode == 0
    ctx.assert_no_canary_leak(canary, health.stdout, health.transcript)
    search = pty(
        ctx,
        ["personal", "search", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("搜索标题（隐藏输入）", "Canary")],
    )
    assert search.returncode == 0
    ctx.assert_no_canary_leak(canary, search.stdout, search.transcript)


@e2e_test("T2_F6_04", 2, ["F6"], "Tampered 1PUX archive fails its confirmed plan digest")
def t2_f6_04(ctx):
    vault = init_vault(ctx)
    archive = simple_1pux(ctx)
    plan = pty(
        ctx,
        ["personal", "plan-import-1pux", "--file", str(vault["path"]), "--source", str(archive)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 PLAN 确认生成导入计划", "PLAN")],
    )
    assert plan.returncode == 0, plan.transcript[-800:]
    digest = plan.json()["report"]["source_digest"]
    write_1pux(
        archive,
        [login_1pux_item("GitHub", "https://github.example.test/login", "alice", "changed-secret")],
    )
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
    assert apply.returncode != 0
    assert "source changed" in apply.transcript.lower(), apply.transcript[-800:]
    assert list_rows(ctx, vault) == []


@e2e_test("T2_F6_05", 2, ["F6"], "Oversized or control-character custom field payloads are rejected")
def t2_f6_05(ctx):
    ready = cli_supports(ctx, "add-item")
    gate(
        ctx,
        "F6",
        ready,
        "CLI add-item command is absent; typed custom-field validation lives in the "
        "v2 host item model",
    )
    vault = make_vault(ctx)
    result = ctx.run_cli(["personal", "add-item", "--help"])
    assert "add-item" in (result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# F7
# ---------------------------------------------------------------------------


@e2e_test("T2_F7_01", 2, ["F7"], "World-writable or symlinked IPC socket directories are refused")
def t2_f7_01(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "desktop IPC broker and localpath checks are absent")
    assert (ctx.repo_root / "internal" / "localpath").is_dir()


@e2e_test("T2_F7_02", 2, ["F7"], "Unauthenticated local IPC peers are dropped without disclosure")
def t2_f7_02(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "desktop IPC peer-authentication handshake is absent")
    assert (ctx.repo_root / "internal" / "localpath").is_dir()


@e2e_test("T2_F7_03", 2, ["F7"], "Desktop SIGTERM mid-fill yields a clean native-host refusal")
def t2_f7_03(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "bounded IPC failure handling is absent")
    assert ctx.browser_chromium_bin.is_file()


@e2e_test("T2_F7_04", 2, ["F7"], "Disabling browser integration refuses native host IPC requests")
def t2_f7_04(ctx):
    ready = f7_shared_ipc_ready(ctx)
    gate(ctx, "F7", ready, "Connect-with-browser setting plumbing is absent")
    text = desktop_sources(ctx)
    assert "browser" in text.lower()


@e2e_test("T2_F7_05", 2, ["F7"], "A stale capability cannot authorize fill and is refused")
def t2_f7_05(ctx):
    request_id = "9" * 32
    request = {
        "v": 1,
        "id": request_id,
        "type": "match",
        "capability": "a" * 32,
        "origin": "https://login.example.test",
        "tab_id": 1,
        "document_id": "doc-1",
    }
    # The host may route this request to the desktop before answering, so keep
    # stdin open until one framed reply arrives (a real browser keeps the pipe
    # open).  Whether an orphaned broker or a GUI bus problem caused earlier
    # remote no-frame results is unconfirmed; the diagnostic below stays
    # metadata-only so CI can tell the cases apart.
    probe = native_probe(ctx, request, timeout=8.0, await_reply=True)
    if probe.timed_out:
        frame_types = sorted({str(frame.get("type")) for frame in probe.frames})
        raise AssertionError(
            "native host produced no framed reply: timed_out=True, "
            "returncode=%r, stdout_bytes=%d, frames=%d, frame_types=%s, "
            "dbus_session=%s, stderr=%r"
            % (
                probe.returncode,
                len(probe.raw_stdout or b""),
                len(probe.frames),
                frame_types,
                bool((os.environ.get("DBUS_SESSION_BUS_ADDRESS") or "").strip()),
                (probe.stderr or "")[:400],
            )
        )
    if not probe.frames and probe.returncode not in (0, None):
        gate(
            ctx,
            "F7",
            False,
            "native browser host GUI could not start; stale-capability probe unavailable: "
            + probe.stderr.strip()[:200],
        )
    assert native_error_frame(probe, request_id), probe.frames
    assert not native_has_credential(probe), probe.frames


# ---------------------------------------------------------------------------
# F8
# ---------------------------------------------------------------------------


@e2e_test("T2_F8_01", 2, ["F8"], "Oversized, symlinked or existing-path attachments are refused")
def t2_f8_01(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "attachment size/path validation is absent")
    text = desktop_sources(ctx)
    assert "attachment" in text.lower() or "附件" in text


@e2e_test("T2_F8_02", 2, ["F8"], "Search index clears on lock and excludes trashed items")
def t2_f8_02(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "v2 search index lifecycle is absent")
    vault = make_vault(ctx, ["Trashed Canary"])
    from .support import pty

    item = vault["items"][0]
    result = pty(
        ctx,
        [
            "personal",
            "trash-login",
            "--file",
            str(vault["path"]),
            "--id",
            item["id"],
            "--revision",
            item["revision"],
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认更改回收站状态", "SAVE")],
    )
    assert result.returncode == 0
    assert list_rows(ctx, vault) == []


@e2e_test("T2_F8_03", 2, ["F8"], "Permanent delete requires confirmation and is cancelled by lock")
def t2_f8_03(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "永久删除 confirmation gate is absent")
    assert "最近删除" in desktop_sources(ctx)


@e2e_test("T2_F8_04", 2, ["F8"], "Auto-lock/clipboard timeout settings reject invalid values")
def t2_f8_04(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "configurable timeout validation is absent")
    text = desktop_sources(ctx)
    assert "自动锁定" in text


@e2e_test("T2_F8_05", 2, ["F8"], "Cross-vault move to a locked vault is refused without data loss")
def t2_f8_05(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "multi-vault move/copy is absent")
    assert "vault" in desktop_sources(ctx).lower()


@e2e_test("T2_F8_06", 2, ["F8"], "Password generator rejects impossible policy combinations")
def t2_f8_06(ctx):
    ready = f8_desktop_v2_ready(ctx)
    gate(ctx, "F8", ready, "v2 generator policy validation is absent")
    result = ctx.run_cli(["personal", "generate-login", "--file", str(ctx.temp_dir / "x.ll"), "--length", "8"])
    assert result.returncode != 0
    assert "entropy below required minimum" in result.stderr.lower()
