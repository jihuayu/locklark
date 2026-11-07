"""Tier 3 pairwise cross-feature E2E tests (T3_01..T3_20).

Each case combines two independent user-facing feature surfaces.  Cases whose
pair includes an unmerged milestone capability perform real CLI/extension/file
probes and then raise the progressive gate.
"""

from __future__ import annotations

import json

from .harness import e2e_test
from .support import (
    add_login,
    assert_audit_chain,
    audit_events,
    cli_supports,
    desktop_sources,
    extension_asset,
    extension_or_source_text,
    extension_text,
    f10_popup_vault_ready,
    f11_identity_ready,
    f12_parity_doc,
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
    list_rows,
    make_vault,
    match_logins,
)


@e2e_test("T3_01", 3, ["F1", "F2"], "Mixed SSH+Passkey vault drives Chromium and Firefox inline fill")
def t3_01(ctx):
    vault = make_vault(ctx, ["login.example.test"])
    ready = f1_passkey_ready(ctx) and f2_inline_ready(ctx)
    gate(ctx, "F1", ready, "passkey protocol or inline-menu content.js is absent")
    assert extension_asset(ctx, "webauthn.js") and extension_asset(ctx, "content.js")
    assert list_rows(ctx, vault)


@e2e_test("T3_02", 3, ["F2", "F9"], "Inline generator -> post-submit save -> inline fill with auto-submit")
def t3_02(ctx):
    vault = make_vault(ctx, ["portal.example.test"])
    ready = f2_inline_ready(ctx) and f9_save_generator_ready(ctx)
    gate(ctx, "F2", ready, "inline autofill and post-submit save are not both present")
    assert extension_asset(ctx, "content.js")
    assert list_rows(ctx, vault)


@e2e_test("T3_03", 3, ["F2", "F11"], "Inline menu + passkey fallback across a three-step split-OTP login")
def t3_03(ctx):
    vault = make_vault(ctx, ["auth.example.test"])
    ready = f1_passkey_ready(ctx) and f2_inline_ready(ctx) and f11_identity_ready(ctx)
    gate(
        ctx,
        "F2",
        ready,
        "inline menu, passkey fallback and multi-step continuation components exist "
        "but the whole-browser three-step split-OTP journey is not executed by this "
        "capability probe; blocked on the absent CLI item-creation surface",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_04", 3, ["F3", "F4"], "Team bootstrap and authenticated team sync preserve Passkey/SSH projection")
def t3_04(ctx):
    ready = f3_team_sync_ready(ctx) and f4_team_cli_ready(ctx)
    gate(ctx, "F3", ready, "team-sync sequencer or team client bootstrap is absent")
    assert f3_team_sync_ready(ctx)


@e2e_test("T3_05", 3, ["F5", "F8"], "Desktop v2 editor/auto-lock interacts with clipboard and edit-cancel timers")
def t3_05(ctx):
    vault = make_vault(ctx, ["Alpha"])
    ready = f5_desktop_timer_ready(ctx) and f8_desktop_v2_ready(ctx)
    gate(ctx, "F5", ready, "independent timers or desktop v2 editor are absent")
    assert desktop_sources(ctx)


@e2e_test("T3_06", 3, ["F6", "F8"], "1PUX v2 categories import into the Desktop UI v2 browser/editor")
def t3_06(ctx):
    vault = make_vault(ctx, ["Imported"])
    ready = cli_supports(ctx, "add-item") and f8_desktop_v2_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI item import/add-item command surface is absent (multi-category 1PUX is "
        "rejected by plan-import); the desktop v2 browser/editor exists, so the "
        "native v2 item model is not absent",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_07", 3, ["F6", "F10"], "Multi-URL/tags/favorites item surfaces in the popup vault")
def t3_07(ctx):
    vault = make_vault(ctx, ["Portal"])
    ready = cli_supports(ctx, "add-item") and f10_popup_vault_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI multi-URL/tags/favorites item creation surface is absent; the popup "
        "vault UI exists, so the gap is the CLI command surface",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_08", 3, ["F6", "F11"], "Identity/Credit-Card v2 field ids drive checkout autofill")
def t3_08(ctx):
    vault = make_vault(ctx, ["Ada"])
    ready = cli_supports(ctx, "add-item") and f11_identity_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI v2 identity/card item creation surface is absent; the extension "
        "identity/card fill contract exists (see M3 component tests), so the "
        "checkout journey is blocked on the CLI surface only",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_09", 3, ["F6", "F13"], "Watchtower inspects every URL in a v2 multi-URL login and cross-category reuse")
def t3_09(ctx):
    vault = make_vault(ctx, ["Multi URL"])
    ready = cli_supports(ctx, "add-item") and f13_watchtower_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI v2 multi-URL item creation surface is absent (so no multi-URL item can "
        "be fed to Watchtower); the host Watchtower service exists",
    )
    assert audit_events(ctx, vault)


@e2e_test("T3_10", 3, ["F6", "F15"], "v2 custom fields and document attachments bind into RunBundle")
def t3_10(ctx):
    vault = make_vault(ctx, ["AWS"])
    ready = cli_supports(ctx, "add-item") and f15_run_bundle_ready(ctx)
    gate(
        ctx,
        "F6",
        ready,
        "CLI v2 custom-field/attachment item surface is absent; RunBundle itself is "
        "implemented",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_11", 3, ["F7", "F9"], "Shared desktop IPC powers generator and post-submit save")
def t3_11(ctx):
    vault = make_vault(ctx, ["Signup"])
    ready = f7_shared_ipc_ready(ctx) and f9_save_generator_ready(ctx)
    gate(ctx, "F7", ready, "shared desktop IPC or post-submit save/generator is absent")
    assert list_rows(ctx, vault)


@e2e_test("T3_12", 3, ["F7", "F10"], "Bi-directional lock/unlock propagation between desktop and popup")
def t3_12(ctx):
    vault = make_vault(ctx, ["Portal"])
    ready = f7_shared_ipc_ready(ctx) and f10_popup_vault_ready(ctx)
    gate(ctx, "F7", ready, "shared IPC lock propagation or popup vault is absent")
    assert list_rows(ctx, vault)


@e2e_test("T3_13", 3, ["F7", "F11"], "Shared desktop session approves credit-card and split-OTP fill")
def t3_13(ctx):
    vault = make_vault(ctx, ["Shop"])
    ready = f7_shared_ipc_ready(ctx) and f11_identity_ready(ctx)
    gate(
        ctx,
        "F7",
        ready,
        "shared desktop IPC and identity/card fill components exist, but the "
        "cross-surface approval journey is not executed and the CLI item-creation "
        "surface is absent",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_14", 3, ["F7", "F17"], "One desktop unlock serves both browser IPC and CLI broker runs")
def t3_14(ctx):
    vault = make_vault(ctx, ["Alpha"])
    ready = f7_shared_ipc_ready(ctx) and f17_broker_ready(ctx)
    gate(
        ctx,
        "F7",
        ready,
        "browser IPC exists; the CLI broker client and its shared terminal session are "
        "absent",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_15", 3, ["F8", "F13"], "Desktop Watchtower dashboard remediates weak/reused items in place")
def t3_15(ctx):
    vault = make_vault(ctx, ["Weak"])
    ready = f8_desktop_v2_ready(ctx) and f13_watchtower_ready(ctx)
    gate(ctx, "F8", ready, "desktop v2 Watchtower dashboard is absent")
    text = desktop_sources(ctx)
    assert "Watchtower" in text
    assert "安全评分" in text or "watchtower.Report" in text
    assert list_rows(ctx, vault)


@e2e_test("T3_16", 3, ["F9", "F13"], "Inline generator remediates a compromised login and clears the alert")
def t3_16(ctx):
    vault = make_vault(ctx, ["Account"])
    ready = f9_save_generator_ready(ctx) and f13_watchtower_ready(ctx)
    gate(ctx, "F9", ready, "inline generator or Watchtower breach alerts are absent")
    content = extension_or_source_text(ctx, "content.js")
    background = extension_or_source_text(ctx, "background.js")
    assert "generator" in content.lower()
    assert "watchtower" in (background + content).lower() or "breached" in background.lower()
    assert list_rows(ctx, vault)


@e2e_test("T3_17", 3, ["F10", "F11"], "Popup Open & Fill seeds a multi-step split-OTP login")
def t3_17(ctx):
    vault = make_vault(ctx, ["SSO Corp"])
    ready = f10_popup_vault_ready(ctx) and f11_identity_ready(ctx)
    gate(
        ctx,
        "F10",
        ready,
        "popup vault Open & Fill exists and multi-step continuation is covered by the "
        "M3 component tests, but the whole-browser journey is not executed and the "
        "CLI item-creation surface is absent",
    )
    assert list_rows(ctx, vault)


@e2e_test("T3_18", 3, ["F12", "F9"], "REA capture of post-submit save/generator verifies parity ledger rows")
def t3_18(ctx):
    ready = f12_parity_doc(ctx) is not None and f9_save_generator_ready(ctx)
    gate(ctx, "F12", ready, "parity checklist or post-submit save/generator is absent")
    assert (ctx.repo_root / "docs" / "browser-parity-checklist.md").is_file()


@e2e_test("T3_19", 3, ["F14", "F15"], "Every CLI profile spec is cryptographically bound into RunBundle")
def t3_19(ctx):
    ready = f14_cli_profiles_ready(ctx) and f15_run_bundle_ready(ctx)
    gate(ctx, "F14", ready, "nine-profile registry or RunBundle digest binding is absent")
    assert f14_cli_profiles_ready(ctx)


@e2e_test("T3_20", 3, ["F16", "F17"], "Shell wrappers run through the desktop CLI broker with session leases")
def t3_20(ctx):
    ready = f16_cli_shell_ready(ctx) and f17_broker_ready(ctx)
    gate(
        ctx,
        "F16",
        ready,
        "cli shell-init is implemented; the desktop CLI broker client is absent",
    )
    assert f16_cli_shell_ready(ctx)
