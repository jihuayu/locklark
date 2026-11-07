"""Tier 4 real-world end-to-end scenario tests (T4_01..T4_10).

Each scenario models a multi-step user or developer journey and gates on the
milestone capability that prevents the journey from completing on the current
branch.  Baseline steps (vault creation, CLI metadata, health, native protocol)
always execute for real.
"""

from __future__ import annotations

import json

from .harness import e2e_test
from .support import (
    add_login,
    audit_events,
    cli_supports,
    desktop_sources,
    extension_asset,
    f10_popup_vault_ready,
    f11_identity_ready,
    f12_parity_doc,
    f13_cli_health_flags,
    f13_watchtower_ready,
    f14_cli_profiles_ready,
    f15_run_bundle_ready,
    f16_cli_shell_ready,
    f17_broker_ready,
    f1_passkey_ready,
    f2_inline_ready,
    f3_team_sync_ready,
    f4_team_cli_ready,
    f5_desktop_timer_ready,
    f7_shared_ipc_ready,
    f8_desktop_v2_ready,
    f9_save_generator_ready,
    gate,
    health_report,
    init_vault,
    list_rows,
    make_vault,
    multi_category_1pux,
    pty,
)


@e2e_test(
    "T4_01",
    4,
    ["F2", "F6", "F8", "F10", "F13", "F14", "F15", "F16"],
    "Full 1Password migration: 1PUX import -> health -> browser fill -> CLI wrappers",
)
def t4_01(ctx):
    vault = make_vault(ctx, ["GitHub", "AWS"])
    archive = multi_category_1pux(ctx)
    plan = pty(
        ctx,
        ["personal", "plan-import-1pux", "--file", str(vault["path"]), "--source", str(archive)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 PLAN 确认生成导入计划", "PLAN")],
    )
    health_report(ctx, vault)
    ready = plan.returncode == 0 and cli_supports(ctx, "add-item")
    gate(
        ctx,
        "F6",
        ready,
        "CLI plan-import-1pux rejects non-basic-login archives and the CLI has no "
        "add-item surface; the v2 item model exists in the desktop/browser host, "
        "so the whole migration journey is blocked on the CLI command surface",
    )
    assert plan.json()["report"]["items"] >= 4
    _import_multi(ctx, vault, archive, plan.json()["report"]["source_digest"])
    assert f14_cli_profiles_ready(ctx)


def _import_multi(ctx, vault, archive, digest):
    result = pty(
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
    assert result.returncode == 0, result.transcript[-1200:]


@e2e_test(
    "T4_02",
    4,
    ["F5", "F7", "F8", "F10", "F14", "F15", "F16", "F17"],
    "Zero-friction developer day: one desktop unlock -> browser -> gh/aws -> instant lock",
)
def t4_02(ctx):
    vault = make_vault(ctx, ["Console", "GitHub"])
    ready = (
        f7_shared_ipc_ready(ctx)
        and f8_desktop_v2_ready(ctx)
        and f17_broker_ready(ctx)
    )
    gate(
        ctx,
        "F7",
        ready,
        "shared desktop IPC and the v2 shell exist; the CLI broker client is absent",
    )
    assert list_rows(ctx, vault)


@e2e_test(
    "T4_03",
    4,
    ["F1", "F2", "F7", "F9", "F10", "F11"],
    "New-account onboarding: generated signup -> save -> TOTP -> passkey upgrade",
)
def t4_03(ctx):
    vault = make_vault(ctx, ["cloud.example.test"])
    ready = (
        f9_save_generator_ready(ctx)
        and f11_identity_ready(ctx)
        and f1_passkey_ready(ctx)
    )
    gate(
        ctx,
        "F9",
        ready,
        "inline generator, multi-step login and passkey upgrade components exist, "
        "but the onboarding journey cannot be driven end-to-end while the CLI "
        "item-creation surface is absent",
    )
    assert list_rows(ctx, vault)


@e2e_test(
    "T4_04",
    4,
    ["F6", "F7", "F10", "F11"],
    "E-commerce checkout: identity -> same-site card iframe -> 3DS split OTP",
)
def t4_04(ctx):
    vault = make_vault(ctx, ["Store"])
    ready = f11_identity_ready(ctx) and f10_popup_vault_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "identity/card fill and split OTP exist (M3 component contracts) and only "
        "same-origin subframes are supported, so same-site cross-origin card iframe "
        "fill is genuinely unsupported and the checkout journey is additionally "
        "blocked on the CLI item-creation surface",
    )
    assert list_rows(ctx, vault)


@e2e_test(
    "T4_05",
    4,
    ["F6", "F14", "F15", "F16", "F17"],
    "Multi-cloud DevOps pipeline through locklark cli with zero plaintext files left",
)
def t4_05(ctx):
    vault = make_vault(ctx, ["AWS", "Terraform", "Kubernetes", "Docker", "Postgres"])
    ready = f14_cli_profiles_ready(ctx) and f15_run_bundle_ready(ctx)
    gate(ctx, "F14", ready, "nine-profile CLI registry / RunBundle is absent")
    assert len(list_rows(ctx, vault)) == 5


@e2e_test(
    "T4_06",
    4,
    ["F9", "F10", "F13", "F14", "F15", "F16"],
    "Security incident response: breach -> browser rotation -> stale CLI refusal -> refresh",
)
def t4_06(ctx):
    vault = make_vault(ctx, ["GitHub"])
    ready = f13_watchtower_ready(ctx) and f9_save_generator_ready(ctx)
    gate(
        ctx,
        "F13",
        ready,
        "host Watchtower service or inline generator remediation is absent",
    )
    # The breach-to-rotation journey needs an opt-in HIBP run.  The host range
    # client exists, but CLI health exposes no opt-in HIBP flags and no live
    # api.pwnedpasswords.com round trip is exercised offline, so this end-to-end
    # validation stays blocked instead of claiming breach detection is absent.
    gate(
        ctx,
        "F13",
        f13_cli_health_flags(ctx),
        "breach-to-rotation journey blocked: no opt-in HIBP flags on CLI health "
        "and no live HIBP egress exercised offline (host HIBP client exists)",
    )
    health_report(ctx, vault)


@e2e_test(
    "T4_07",
    4,
    ["F1", "F3", "F4", "F6", "F8"],
    "Team workspace bootstrap, multi-device sync and personal/team isolation",
)
def t4_07(ctx):
    vault = make_vault(ctx, ["Personal"])
    ready = f3_team_sync_ready(ctx) and f4_team_cli_ready(ctx)
    gate(ctx, "F3", ready, "authenticated team sync / protected bootstrap is absent")
    assert list_rows(ctx, vault)


@e2e_test(
    "T4_08",
    4,
    ["F2", "F9", "F10", "F11", "F14", "F15", "F16"],
    "Malicious website and supply-chain defense in one session",
)
def t4_08(ctx):
    vault = make_vault(ctx, ["Defense"])
    ready = f2_inline_ready(ctx) and f11_identity_ready(ctx)
    gate(
        ctx,
        "F2",
        ready,
        "inline autofill, identity/card fill and cross-origin iframe refusal "
        "components exist (M3 component contracts); the malicious-site journey is "
        "blocked on the absent CLI item-creation surface, not on those capabilities",
    )
    assert audit_events(ctx, vault)


@e2e_test(
    "T4_09",
    4,
    ["F5", "F7", "F8", "F10", "F17"],
    "Unattended idle lock: clipboard + editor draft + popup + CLI lease all revoked",
)
def t4_09(ctx):
    vault = make_vault(ctx, ["Alpha"])
    ready = (
        f5_desktop_timer_ready(ctx)
        and f7_shared_ipc_ready(ctx)
        and f8_desktop_v2_ready(ctx)
        and f17_broker_ready(ctx)
    )
    gate(
        ctx,
        "F5",
        ready,
        "desktop timers and shared IPC exist; the CLI broker client (and its lease "
        "revocation) is absent",
    )
    assert desktop_sources(ctx)


@e2e_test(
    "T4_10",
    4,
    ["F1", "F2", "F9", "F10", "F11", "F12", "F13"],
    "Clean-room browser parity release gate across Chromium and Firefox",
)
def t4_10(ctx):
    ready = (
        f12_parity_doc(ctx) is not None
        and f2_inline_ready(ctx)
        and f1_passkey_ready(ctx)
        and f9_save_generator_ready(ctx)
    )
    gate(ctx, "F12", ready, "docs/browser-parity-checklist.md and browser parity assets are absent")
    assert extension_asset(ctx, "content.js")
    assert (ctx.repo_root / "docs" / "browser-parity-checklist.md").is_file()
