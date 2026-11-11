"""Tier 2 boundary, negative and security E2E tests for F9-F17."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket

from .harness import e2e_test
from .support import (
    PARITY_STATUSES,
    TrapListener,
    add_login,
    assert_audit_chain,
    audit_events,
    card_fill_explicit_authorization_component,
    checkout_native_acceptance,
    checklist_rows,
    cli_profiles,
    cli_supports,
    desktop_sources,
    evidence_paths,
    extension_text,
    extension_or_source_text,
    f10_popup_vault_ready,
    f11_fill_contract_ready,
    f12_parity_doc,
    f13_hibp_client_ready,
    f13_watchtower_ready,
    go_package_test,
    go_tool,
    node_test_pattern,
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
    make_script,
    make_vault,
    native_has_credential,
    native_probe,
    node_test,
    pty,
    simple_1pux,
    write_1pux,
    login_1pux_item,
)


# ---------------------------------------------------------------------------
# F9
# ---------------------------------------------------------------------------


@e2e_test("T2_F9_01", 2, ["F9"], "A failed login submit does not offer save or overwrite the vault")
def t2_f9_01(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "post-submit result classification is absent")
    content = extension_text(ctx, "content.js")
    assert "submit" in content.lower()


@e2e_test("T2_F9_02", 2, ["F9"], "Oversized save payload is refused by the native protocol")
def t2_f9_02(ctx):
    request_id = "1" * 32
    request = {
        "v": 1,
        "id": request_id,
        "type": "save-new",
        "capability": "2" * 32,
        "origin": "https://app.example.test",
        "tab_id": 1,
        "document_id": "doc-1",
        "window_id": 0,
        "username": "alice",
        "password": "P" * 20000,
    }
    probe = native_probe(ctx, request, timeout=8.0)
    assert not probe.timed_out, probe.stderr
    assert not native_has_credential(probe), probe.frames
    assert not any(frame.get("type") == "saved" for frame in probe.frames), probe.frames


@e2e_test("T2_F9_03", 2, ["F9"], "Cross-origin submit redirect cannot attribute credentials to the attacker")
def t2_f9_03(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "origin-bound pending-save attribution is absent")
    content = extension_text(ctx, "content.js")
    assert "origin" in content.lower()


@e2e_test("T2_F9_04", 2, ["F9"], "MAIN-world scripts cannot read the closed-shadow generator DOM")
def t2_f9_04(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "closed-shadow inline generator is absent")
    content = extension_text(ctx, "content.js")
    assert "attachShadow" in content
    assert "closed" in content


@e2e_test("T2_F9_05", 2, ["F9"], "Generator rejects out-of-bounds lengths and locked sessions")
def t2_f9_05(ctx):
    ready = f9_save_generator_ready(ctx)
    gate(ctx, "F9", ready, "inline generator bounds validation is absent")
    core = extension_text(ctx, "core.js")
    assert "generate" in core.lower() or "length" in core.lower()


# ---------------------------------------------------------------------------
# F10
# ---------------------------------------------------------------------------


@e2e_test("T2_F10_01", 2, ["F10"], "Lock clears popup search results, details and cached secrets")
def t2_f10_01(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "popup vault state cache is absent")
    popup = extension_text(ctx, "popup.js")
    assert "lock" in popup.lower()


@e2e_test("T2_F10_02", 2, ["F10"], "Popup renders item titles and usernames as inert text")
def t2_f10_02(ctx):
    popup = extension_text(ctx, "popup.js") or (ctx.repo_root / "browser-extension" / "popup.js").read_text(
        encoding="utf-8"
    )
    assert "textContent" in popup
    assert "innerHTML" not in popup
    node_test(ctx, "browser-extension/test/popup.test.js")


@e2e_test("T2_F10_03", 2, ["F10"], "Open & Fill refuses javascript:, data:, file:// and http:// URLs")
def t2_f10_03(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "Open & Fill URL validation is absent")
    popup = extension_text(ctx, "popup.js")
    assert "open" in popup.lower()


@e2e_test("T2_F10_04", 2, ["F10"], "Stale revision edits from the popup are rejected")
def t2_f10_04(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "popup edit revision conflict handling is absent")
    assert "revision" in extension_text(ctx, "popup.js").lower()


@e2e_test("T2_F10_05", 2, ["F10"], "Shortcuts and context menu are inert on privileged browser pages")
def t2_f10_05(ctx):
    ready = f10_popup_vault_ready(ctx)
    gate(ctx, "F10", ready, "privileged-page shortcut guard is absent")
    background = extension_text(ctx, "background.js")
    assert "chrome://" in background or "about:" in background or "tab" in background


# ---------------------------------------------------------------------------
# F11
# ---------------------------------------------------------------------------


@e2e_test("T2_F11_01", 2, ["F11"], "A cross-origin iframe is refused by origin matching")
def t2_f11_01(ctx):
    vault = make_vault(ctx, ["Shop"])
    result = pty(
        ctx,
        [
            "personal",
            "match-logins",
            "--file",
            str(vault["path"]),
            "--origin",
            "https://shop.example.test",
            "--frame-origin",
            "https://evil.attacker.test",
        ],
        password=vault["password"],
        secret=vault["secret"],
    )
    assert result.returncode != 0, result.stdout
    assert "cross-origin frame matching refused" in result.transcript, result.transcript
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 same-origin iframe fill carries frameId and allowSubframe; cross-origin is refused",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


M3_FILL = "browser-extension/test/m3_fill_v2.test.js"


@e2e_test(
    "T2_F11_02",
    2,
    ["F11"],
    "Hidden/off-screen honeypot inputs are skipped during identity fill",
    coverage_kind="component_contract",
)
def t2_f11_02(ctx):
    # The visibility filter is the eligible-classification contract enforced by
    # inspectAutofillFields; the M3 suite exercises hidden/disabled controls.
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "identity fill entrypoints are absent from the shipped extension; honeypot filtering cannot run",
    )
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 identity inspectAutofillFields returns only eligible classified controls",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test(
    "T2_F11_03",
    2,
    ["F11"],
    "Multi-step continuation aborts on a cross-origin navigation",
    coverage_kind="component_contract",
)
def t2_f11_03(ctx):
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "multi-step continuation state (username/password/OTP across navigation) is absent from the shipped extension",
    )
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 multi-step login is cleared by cross-site navigation",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test(
    "T2_F11_04",
    2,
    ["F11"],
    "Split OTP fill refuses a mismatched or unrelated input group",
    coverage_kind="component_contract",
)
def t2_f11_04(ctx):
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "split-OTP group validation is absent from the shipped extension",
    )
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 split OTP rejects mismatched box counts and invalid codes",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test(
    "T2_F11_05",
    2,
    ["F11"],
    "Card fill component explicit-authorization contract",
    coverage_kind="component_contract",
)
def t2_f11_05(ctx):
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "credit-card fill explicit-authorization entrypoints are absent from the shipped extension",
    )
    # Component contract only: this executes the built bundle's
    # `core.fillCardDocument` directly.  It does not exercise `content.js` or
    # any background page-load wiring, and it does not perform a real browser
    # gesture.  The explicit authorization it verifies is the shipped
    # short-lived (origin, expiresAt, category) intent; without one, the
    # component must refuse and leave every control untouched.
    observed = card_fill_explicit_authorization_component(ctx)
    gate(
        ctx,
        "F11",
        observed is not None,
        "the built extension bundle carries no fillCardDocument entrypoint",
    )
    assert observed["beforeAuthorization"] == ["", "", "", ""], observed[
        "beforeAuthorization"
    ]
    for name, refused in observed["rejects"].items():
        assert refused is False, (name, refused)
        # A refused invocation must not touch any control.
        assert observed["afterRejects"][name] == ["", "", "", ""], (
            name,
            observed["afterRejects"][name],
        )
    # Only a valid explicit authorization may write, and it writes exactly the
    # card controls once.
    assert observed["authorized"] is True, observed
    assert sorted(observed["written"]) == ["csc", "exp", "holder", "number"], observed["written"]
    assert observed["afterAuthorization"] == [
        "Ada Lovelace",
        "4242424242424242",
        "12/29",
        "123",
    ], observed["afterAuthorization"]
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 fillCardDocument fills number, expiry variants, selects and csc|M3 same-origin iframe fill",
        min_passed=2,
    )
    assert counts["pass"] >= 2, counts


@e2e_test(
    "T2_F11_06",
    2,
    ["F11"],
    "Real Chromium checkout approval, deny, cancel, navigation and lock journey",
    coverage_kind="functional",
)
def t2_f11_06(ctx):
    # One row for the existing multi-case native journey.  It consumes a
    # previously produced sanitized manifest when explicitly pointed at one,
    # otherwise it runs the real journey once with LOCKLARK_E2E_CHECKOUT_NATIVE=1
    # and reuses the cached result for any later F11 row in this process.
    evidence = checkout_native_acceptance(ctx)
    ctx.record_evidence(evidence)


# ---------------------------------------------------------------------------
# F12
# ---------------------------------------------------------------------------


def _parity_or_gate(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "docs/browser-parity-checklist.md is absent")
    return path.read_text(encoding="utf-8")


@e2e_test("T2_F12_01", 2, ["F12"], "Checklist validator rejects unapproved status labels")
def t2_f12_01(ctx):
    text = _parity_or_gate(ctx)
    for row in checklist_rows(text):
        joined = " ".join(row)
        assert "WIP" not in joined and "TODO" not in joined, row
        statuses = [cell for cell in row if cell in PARITY_STATUSES]
        if statuses:
            assert len(statuses) == 1, row


@e2e_test("T2_F12_02", 2, ["F12"], "Safari/biometric rows are not marked 已实测 from a Linux run")
def t2_f12_02(ctx):
    text = _parity_or_gate(ctx)
    for row in checklist_rows(text):
        joined = " ".join(row)
        if "Safari" in joined or "Touch ID" in joined or "Windows Hello" in joined:
            assert "已实测" not in row, row


@e2e_test("T2_F12_03", 2, ["F12"], "Checklist reference-analysis links resolve to real files")
def t2_f12_03(ctx):
    text = _parity_or_gate(ctx)
    relative = "history/browser-parity-m3-baseline-2026-11-06.md"
    assert relative in text, "checklist has no reference-analysis link"
    assert (ctx.repo_root / "docs" / relative).is_file()


@e2e_test("T2_F12_04", 2, ["F12"], "Checklist evidence verifier rejects broken 已实测 pointers")
def t2_f12_04(ctx):
    text = _parity_or_gate(ctx)
    for row in checklist_rows(text):
        if "已实测" not in row:
            continue
        paths = evidence_paths(" ".join(row))
        assert paths, f"已实测 row has no evidence: {row}"
        for relative in paths:
            assert (ctx.repo_root / relative).exists(), relative


@e2e_test("T2_F12_05", 2, ["F12"], "Repository tree has no .crx/.asar/1Password reference bundles")
def t2_f12_05(ctx):
    _parity_or_gate(ctx)
    for item in ctx.repo_root.rglob("*"):
        if item.is_file():
            assert not item.name.lower().endswith((".crx", ".asar")), item


# ---------------------------------------------------------------------------
# F13
# ---------------------------------------------------------------------------


@e2e_test("T2_F13_01", 2, ["F13"], "Default local health check makes zero outbound connections")
def t2_f13_01(ctx):
    vault = make_vault(ctx, ["Alpha", "Beta"])
    with TrapListener() as trap:
        # Prove the trap really observes a loopback connection first.
        sanity = socket.create_connection(("127.0.0.1", trap.port), timeout=2)
        sanity.close()
        assert trap.poll(0.5) >= 1
        trap.connections = 0
        result = pty(
            ctx,
            ["personal", "health", "--file", str(vault["path"])],
            password=vault["password"],
            secret=vault["secret"],
            extra=[("输入 SCAN 确认本地体检", "SCAN")],
            env={
                "HIBP_ENDPOINT": trap.url,
                "LOCKLARK_HIBP_ENDPOINT": trap.url,
                "LOCKLARK_CHECK_BREACHED": "false",
            },
        )
        assert result.returncode == 0, result.transcript[-800:]
        assert trap.poll(0.5) == 0, "default local health check connected to the network"


@e2e_test("T2_F13_02", 2, ["F13"], "Trashed and archived items are excluded from active Watchtower alarms")
def t2_f13_02(ctx):
    vault = init_vault(ctx)
    active_id, _ = add_login(ctx, vault, "Active", password="SharedSecret!2026_DupPass")
    trashed_id, trashed_rev = add_login(ctx, vault, "Trashed", password="SharedSecret!2026_DupPass")
    trash = pty(
        ctx,
        [
            "personal",
            "trash-login",
            "--file",
            str(vault["path"]),
            "--id",
            trashed_id,
            "--revision",
            trashed_rev,
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认更改回收站状态", "SAVE")],
    )
    assert trash.returncode == 0, trash.transcript[-800:]
    payload = health_report(ctx, vault)["payload"]
    report = payload["report"]
    assert report["scope"] == "active-logins"
    assert report["checked"] == 1, report
    ids = set(flags_by_id(payload))
    assert active_id in ids
    assert trashed_id not in ids


@e2e_test(
    "T2_F13_03",
    2,
    ["F13"],
    "HIBP client rejects http:// endpoints and oversized responses",
    coverage_kind="component_contract",
)
def t2_f13_03(ctx):
    ready = f13_hibp_client_ready(ctx)
    gate(
        ctx,
        "F13",
        ready,
        "host HIBP range client validation (https-only endpoint, bounded responses) is absent; live-network validation blocked",
    )
    if go_tool() is None:
        gate(
            ctx,
            "F13",
            False,
            "validation blocked: go toolchain unavailable; HIBP client component test not executed",
        )
    counts = go_package_test(
        ctx,
        "./internal/watchtower",
        "TestHIBPClientFixedRefusals",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test(
    "T2_F13_04",
    2,
    ["F13"],
    "Duplicate SHA-1 prefixes are queried at most once",
    coverage_kind="component_contract",
)
def t2_f13_04(ctx):
    ready = f13_hibp_client_ready(ctx)
    gate(
        ctx,
        "F13",
        ready,
        "host HIBP prefix deduplication (LookupCandidates grouping) is absent; live-network validation blocked",
    )
    if go_tool() is None:
        gate(
            ctx,
            "F13",
            False,
            "validation blocked: go toolchain unavailable; HIBP dedup component test not executed",
        )
    counts = go_package_test(
        ctx,
        "./internal/watchtower",
        "TestLookupCandidatesGroupsPrefixes",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test("T2_F13_05", 2, ["F13"], "Watchtower output never contains plaintext or full SHA-1 hashes")
def t2_f13_05(ctx):
    canary = "CanaryWeakPass_123"
    vault = init_vault(ctx)
    add_login(ctx, vault, "Canary", password=canary)
    report = health_report(ctx, vault)
    payload = report["payload"]
    result = report["result"]
    digest = hashlib.sha1(canary.encode("utf-8")).hexdigest()
    ctx.assert_no_canary_leak(canary, result.stdout, result.transcript, json.dumps(payload))
    ctx.assert_no_canary_leak(digest, result.stdout, result.transcript, json.dumps(payload))
    events = audit_events(ctx, vault)
    ctx.assert_no_canary_leak(canary, json.dumps(events))
    ctx.assert_no_canary_leak(digest, json.dumps(events))


# ---------------------------------------------------------------------------
# F14
# ---------------------------------------------------------------------------


@e2e_test("T2_F14_01", 2, ["F14"], "gh DenyArgs blocks auth login/setup-git before child execution")
def t2_f14_01(ctx):
    vault = make_vault(ctx, ["GH Token"])
    marker = ctx.temp_dir / "gh-started"
    program = make_script(
        ctx,
        "fake-gh.sh",
        f"#!/bin/sh\n: > {marker}\nexit 0\n",
    )
    result = ctx.run_cli(
        [
            "personal",
            "run-cli",
            "--file",
            str(vault["path"]),
            "--id",
            vault["items"][0]["id"],
            "--revision",
            vault["items"][0]["revision"],
            "--profile",
            "gh",
            "--name",
            "GH_TOKEN",
            "--cwd",
            str(ctx.temp_dir),
            "--timeout",
            "5",
            "--",
            str(program),
            "auth",
            "login",
        ]
    )
    assert result.returncode != 0, result.stdout
    assert not marker.exists(), "denied gh auth login executed the child"


@e2e_test("T2_F14_02", 2, ["F14"], "Passthrough environment rejects LD_PRELOAD, NODE_OPTIONS and proxies")
def t2_f14_02(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "--passthrough environment validation is absent")
    assert "--passthrough" in ctx.run_cli(["help"]).stdout


@e2e_test("T2_F14_03", 2, ["F14"], "Template renderer rejects newline/NUL credential injection")
def t2_f14_03(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "cliprobe config-template injection checks are absent")
    assert f14_cli_profiles_ready(ctx)


@e2e_test("T2_F14_04", 2, ["F14"], "kubectl rejects corrupt/oversized kubeconfig attachments")
def t2_f14_04(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "kubectl attachment validation is absent")
    kubectl = {entry["name"]: entry for entry in cli_profiles(ctx)}["kubectl"]
    assert kubectl["slots"][0]["kind"] == "document"
    assert kubectl["slots"][0]["field"] == "attachment"


@e2e_test("T2_F14_05", 2, ["F14"], "Profile timeout rejects zero and above-ceiling values")
def t2_f14_05(ctx):
    vault = make_vault(ctx, ["GH Token"])
    base = [
        "personal",
        "run-cli",
        "--file",
        str(vault["path"]),
        "--id",
        vault["items"][0]["id"],
        "--revision",
        vault["items"][0]["revision"],
        "--profile",
        "gh",
        "--name",
        "GH_TOKEN",
        "--cwd",
        str(ctx.temp_dir),
    ]
    for timeout in ("0", "999999"):
        result = ctx.run_cli([*base, "--timeout", timeout, "--", "/bin/true", "pr", "list"])
        assert result.returncode != 0, timeout


# ---------------------------------------------------------------------------
# F15
# ---------------------------------------------------------------------------


@e2e_test("T2_F15_01", 2, ["F15"], "A stale BundleTarget revision aborts the whole bundle")
def t2_f15_01(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle revision authentication is absent")
    assert f15_run_bundle_ready(ctx)


@e2e_test("T2_F15_02", 2, ["F15"], "A blank required credential slot returns ErrRunCredential")
def t2_f15_02(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle blank-slot validation is absent")
    assert f15_run_bundle_ready(ctx)


@e2e_test("T2_F15_03", 2, ["F15"], "Pre-existing/symlinked run-root files are rejected with O_EXCL")
def t2_f15_03(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle O_CREATE|O_EXCL|O_NOFOLLOW materialization is absent")
    assert f15_run_bundle_ready(ctx)


@e2e_test("T2_F15_04", 2, ["F15"], "Untrusted world-writable TMPDIR is refused before execution")
def t2_f15_04(ctx):
    vault = make_vault(ctx, ["Alpha"])
    marker = ctx.temp_dir / "child-started"
    program = make_script(ctx, "child.sh", f"#!/bin/sh\n: > {marker}\nexit 0\n")
    bad = ctx.temp_dir / "world-writable"
    bad.mkdir(mode=0o777, exist_ok=True)
    os.chmod(bad, 0o777)
    result = pty(
        ctx,
        [
            "personal",
            "run-cli",
            "--file",
            str(vault["path"]),
            "--id",
            vault["items"][0]["id"],
            "--revision",
            vault["items"][0]["revision"],
            "--profile",
            "gh",
            "--name",
            "GH_TOKEN",
            "--cwd",
            str(ctx.temp_dir),
            "--timeout",
            "5",
            "--",
            str(program),
            "pr",
            "list",
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 RUN 确认本次可信命令披露", "RUN")],
        env={"TMPDIR": str(bad)},
        controlling_tty=True,
    )
    assert result.returncode != 0
    assert "trusted temporary directory" in result.transcript, result.transcript[-1200:]
    assert not marker.exists()
    assert list(bad.iterdir()) == []


@e2e_test("T2_F15_05", 2, ["F15"], "Typing anything except exact RUN cancels without execution")
def t2_f15_05(ctx):
    vault = make_vault(ctx, ["Alpha"])
    marker = ctx.temp_dir / "child-started"
    program = make_script(ctx, "child.sh", f"#!/bin/sh\n: > {marker}\nexit 0\n")
    result = pty(
        ctx,
        [
            "personal",
            "run-env",
            "--file",
            str(vault["path"]),
            "--id",
            vault["items"][0]["id"],
            "--revision",
            vault["items"][0]["revision"],
            "--field",
            "password",
            "--name",
            "LL_TEST",
            "--cwd",
            str(ctx.temp_dir),
            "--timeout",
            "5",
            "--",
            str(program),
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 RUN 确认向本地程序披露字段", "run")],
        controlling_tty=True,
    )
    assert result.returncode != 0
    assert "cancelled" in result.transcript.lower(), result.transcript[-800:]
    assert not marker.exists()


# ---------------------------------------------------------------------------
# F16
# ---------------------------------------------------------------------------


@e2e_test("T2_F16_01", 2, ["F16"], "A tampered pinned binary fails its SHA-256 check")
def t2_f16_01(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "clibinding pinned-digest verification is absent")
    assert f16_cli_shell_ready(ctx)


@e2e_test("T2_F16_02", 2, ["F16"], "LOCKLARK_CLI_ACTIVE recursion guard blocks wrapper loops")
def t2_f16_02(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "recursion guard is absent")
    assert f16_cli_shell_ready(ctx)


@e2e_test("T2_F16_03", 2, ["F16"], "A 0644/0666 binding file is refused")
def t2_f16_03(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "binding-file mode enforcement is absent")
    assert f16_cli_shell_ready(ctx)


@e2e_test("T2_F16_04", 2, ["F16"], "cli init rejects relative, directory, symlink and non-executable programs")
def t2_f16_04(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "cli init program-path validation is absent")
    assert f16_cli_shell_ready(ctx)


@e2e_test("T2_F16_05", 2, ["F16"], "shell-init rejects unsupported shells and injected names")
def t2_f16_05(ctx):
    ready = f16_cli_shell_ready(ctx)
    gate(ctx, "F16", ready, "shell-init argument validation is absent")
    result = ctx.run_cli(["cli", "shell-init", "cmd.exe"])
    assert result.returncode != 0
    assert "bash" in (result.stdout + result.stderr).lower()


# ---------------------------------------------------------------------------
# F17
# ---------------------------------------------------------------------------


@e2e_test("T2_F17_01", 2, ["F17"], "Deny/close/timeout of the broker modal aborts cli run")
def t2_f17_01(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "CLI broker client is absent, so the desktop approval request path cannot be "
        "exercised end-to-end (the desktop broker server exists)",
    )
    assert f17_broker_ready(ctx)


@e2e_test("T2_F17_02", 2, ["F17"], "Mismatched UID or untrusted socket path is dropped by the broker")
def t2_f17_02(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "CLI broker client is absent; terminal-side SO_PEERCRED/path trust cannot be "
        "exercised (browser IPC trust checks exist)",
    )
    assert (ctx.repo_root / "internal" / "localpath").is_dir()


@e2e_test("T2_F17_03", 2, ["F17"], "Changing argv/cwd/passthrough invalidates a terminal lease")
def t2_f17_03(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "lease scope binding is absent because no CLI broker client holds leases",
    )
    assert f17_broker_ready(ctx)


@e2e_test("T2_F17_04", 2, ["F17"], "An expired terminal lease requires fresh approval")
def t2_f17_04(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "lease TTL handling is absent because no CLI broker client holds leases",
    )
    assert f17_broker_ready(ctx)


@e2e_test("T2_F17_05", 2, ["F17"], "Replayed broker nonces/request ids are rejected")
def t2_f17_05(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "single-use broker nonce store is absent from the missing CLI broker client",
    )
    assert f17_broker_ready(ctx)
