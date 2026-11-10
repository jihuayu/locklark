"""Tier 4 real-world end-to-end scenario tests (T4_01..T4_10).

Each scenario models a multi-step user or developer journey and gates on the
milestone capability that prevents the journey from completing on the current
branch.  Baseline steps (vault creation, CLI metadata, health, native protocol)
always execute for real.
"""

from __future__ import annotations

import hashlib
import json

from .harness import e2e_test
from .support import (
    HIBP_FIXED_HOST,
    HIBP_HTTPS_PORT,
    HIBP_NETWORK_PROMPT,
    add_login,
    audit_events,
    cli_supports,
    desktop_sources,
    extension_asset,
    f10_popup_vault_ready,
    f11_identity_ready,
    f12_parity_doc,
    f13_cli_hibp_opt_in,
    f13_cli_hibp_range_lookups,
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
    match_logins,
    multi_category_1pux,
    pykeepass_peer,
    pty,
    read_kdbx_entries,
    reveal_login,
)


@e2e_test(
    "T4_01",
    4,
    ["F2", "F6", "F8", "F10", "F13", "F14", "F15", "F16"],
    "Capability probe (CLI segment only): 1PUX v2 import -> search -> reveal -> export",
)
def t4_01(ctx):
    import_ready = cli_supports(ctx, "plan-import-1pux") and cli_supports(
        ctx, "import-1pux"
    )
    gate(
        ctx,
        "F6",
        import_ready,
        "`personal plan-import-1pux`/`import-1pux` are not advertised by the CLI",
    )
    # The export must be reopened by an independent KDBX reader, not by the
    # product that wrote it.  A missing peer blocks the assertion instead of
    # silently downgrading it to a signature check.
    peer = pykeepass_peer()
    if peer is None:
        ctx.require_feature(
            "F6",
            False,
            "validation blocked: an independent PyKeePass reader is unavailable; "
            "install pykeepass==4.2.0 or point LOCKLARK_TEST_PYKEEPASS at a peer interpreter",
        )
    vault = make_vault(ctx, ["GitHub", "AWS"])
    archive = multi_category_1pux(ctx)
    plan = pty(
        ctx,
        [
            "personal",
            "plan-import-1pux",
            "--file",
            str(vault["path"]),
            "--source",
            str(archive),
            "--model",
            "v2",
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 PLAN 确认生成导入计划", "PLAN")],
    )
    assert plan.returncode == 0, plan.transcript[-1200:]
    report = plan.json()["report"]
    assert report["items"] >= 4, report
    assert report["profile"] == "1pux-full-v2", report
    digest = report["source_digest"]
    _import_multi(ctx, vault, archive, digest)

    # Search reaches the imported login by title only.
    found = pty(
        ctx,
        ["personal", "search", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("搜索标题（隐藏输入）", "Corp SSO")],
    )
    assert found.returncode == 0, found.transcript[-800:]
    rows = found.json()["rows"]
    assert [row["title"] for row in rows] == ["Corp SSO"], rows
    imported_id = rows[0]["id"]
    imported_revision = rows[0]["revision"]

    # The native origin match surfaces the same item for its imported URL.
    matched = match_logins(ctx, vault, "https://sso.corp.example.test")
    matched_ids = [row["id"] for row in matched]
    assert imported_id in matched_ids, matched

    # Controlled disclosure: the imported password leaves only through the
    # explicit SHOW consent.  The transcript must carry the actual value, while
    # stdout, search rows and match rows must never do so.
    revealed_value, revealed_transcript = reveal_login(
        ctx, vault, imported_id, imported_revision, "password"
    )
    assert revealed_value == "P@ssw0rd-2026", revealed_value
    assert json.dumps(revealed_value) in revealed_transcript, revealed_transcript[-400:]
    for canary in ("P@ssw0rd-2026", vault["secret"]):
        ctx.assert_no_canary_leak(
            canary, found.stdout, matched, json.dumps(plan.json())
        )

    # Export: an authenticated KDBX of the migrated vault.
    exported = ctx.temp_dir / "migrated.kdbx"
    export = pty(
        ctx,
        ["personal", "export-kdbx", "--file", str(vault["path"]), "--out", str(exported)],
        password=vault["password"],
        secret=vault["secret"],
        extra=[
            ("新导出密码（至少 12 字符）", "export-pass-2026"),
            ("再次输入导出密码", "export-pass-2026"),
            ("输入 SAVE 确认加密导出", "SAVE"),
        ],
    )
    assert export.returncode == 0, export.transcript[-1200:]
    assert exported.is_file() and exported.stat().st_size > 0
    assert exported.read_bytes()[:8] == b"\x03\xd9\xa2\x9ag\xfbK\xb5", (
        "unexpected KDBX signature"
    )
    # Reopen the export with PyKeePass, independently of the writer.  This
    # asserts the real imported content and not just the KDBX magic.
    entries = read_kdbx_entries(exported, "export-pass-2026", peer=peer)
    by_title = {entry["title"]: entry for entry in entries}
    assert {"Corp SSO", "Runbook", "Ada Lovelace", "Corp Visa"} <= set(by_title), (
        sorted(by_title)
    )
    sso = by_title["Corp SSO"]
    assert sso["username"] == "alice", sso
    assert sso["password"] == "P@ssw0rd-2026", sso
    assert sso["url"] == "https://sso.corp.example.test/login", sso
    for canary in ("Corp SSO", "P@ssw0rd-2026", vault["secret"]):
        ctx.assert_no_canary_leak(canary, exported.read_bytes())


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
            "--model",
            "v2",
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认整批导入", "SAVE")],
    )
    assert result.returncode == 0, result.transcript[-1200:]
    assert result.json().get("status") == "imported-1pux-full-v2", result.stdout[:400]


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
    # The declined-consent and strict-option checks below run against a
    # genuinely empty vault.  The two synthetic canaries that the mocked HIBP
    # run may query (and nothing else) are added later, so only their two
    # prefixes can reach the mock.
    vault = init_vault(ctx)
    assert list_rows(ctx, vault) == [], "the consent fixture vault must start empty"
    ready = f13_watchtower_ready(ctx) and f9_save_generator_ready(ctx)
    gate(
        ctx,
        "F13",
        ready,
        "host Watchtower service or inline generator remediation is absent",
    )
    # The breach-to-rotation journey needs the opt-in HIBP run on the CLI.
    # Observe the real CLI contract: the strict `--hibp true` pair is refused
    # for any other spelling, and the local (offline) report still executes.
    opt_in = f13_cli_hibp_opt_in(ctx, vault)
    gate(
        ctx,
        "F13",
        opt_in["flags"],
        "`personal health` does not advertise the `--hibp true` opt-in",
    )
    assert opt_in["bad_pair_refused"], (
        "a non-literal --hibp option pair was accepted by `personal health`"
    )
    # The refusal itself was asserted inside f13_cli_hibp_opt_in (fixed
    # cancellation error, no receipt, no unlock and no vault.health.hibp
    # intent appended).
    assert opt_in["audit_delta"] == [], opt_in
    health_report(ctx, vault)
    _t4_06_consented_mock_hibp(ctx, vault)
    # The consent-gated CLI HIBP lookup above ran for real against the local
    # CONNECT/TLS mock (never the live service), but this scenario still does
    # not execute the browser rotation or the CLI lease refresh.  This stays an
    # explicit not-verified result and is never reported as a pass.
    raise AssertionError(
        "UNVERIFIED (not a pass): breach-to-rotation journey not exercised - "
        "the CLI HIBP opt-in contract (strict pair, consent refusal, no intent) "
        "was validated and the real consented `personal health --hibp true` "
        "substep was exercised against the local CONNECT/TLS HIBP mock (two "
        "synthetic prefixes, breached suffix matched, route and audit checked), "
        "but T4_06 does not execute the browser rotation or the CLI lease "
        "refresh, so the whole breach -> rotation -> stale CLI refusal -> "
        "refresh path remains unvalidated"
    )


def _t4_06_consented_mock_hibp(ctx, vault):
    """Consented ``personal health --hibp true`` through the local HIBP mock.

    Uses the existing, already-tested ``f13_cli_hibp_range_lookups`` helper: the
    fixed endpoint and the shipped client are untouched, and a private child
    environment routes ``api.pwnedpasswords.com:443`` to a loopback CONNECT
    proxy/TLS range server.  Only the two synthetic canaries below are added,
    so the mock must see exactly their two prefixes and nothing else.
    """

    breached = "T4-Synthetic-Breached-Pass!2026"
    clean = "T4-Synthetic-Clean-Pass!2026-Xy9"
    breached_id, _ = add_login(ctx, vault, "T4 Breached Canary", password=breached)
    clean_id, _ = add_login(ctx, vault, "T4 Clean Canary", password=clean)
    breached_hash = hashlib.sha1(breached.encode("utf-8")).hexdigest().upper()
    clean_hash = hashlib.sha1(clean.encode("utf-8")).hexdigest().upper()
    breached_prefix = breached_hash[:5]
    clean_prefix = clean_hash[:5]
    assert breached_prefix != clean_prefix, "the synthetic passwords share a prefix"
    # Each prefix receives only its own answer lines: the breached password's
    # real 35-hex suffix with count 2, and an empty (padding-only) clean range.
    # No suffix, hash or password is ever sent by the test or the SUT.
    responses = {
        breached_prefix: ((breached_hash[5:], 2),),
        clean_prefix: (),
    }
    before = audit_events(ctx, vault)
    observed = f13_cli_hibp_range_lookups(ctx, vault, responses)
    after = audit_events(ctx, vault)
    # A missing route is never a pass: pending gates the scenario.
    if observed["status"] != "ran":
        gate(
            ctx,
            "F13",
            False,
            "local HIBP route not established (loopback CONNECT proxy or synthetic "
            f"CA unavailable): {observed.get('reason', 'no proxy connection')}; the "
            "real service is never contacted and the consented breach match stays "
            "unvalidated",
        )
    assert observed["returncode"] == 0, (
        observed["returncode"],
        observed["transcript"][-1200:],
    )
    # Only the fixed destination was attempted and nothing was refused.
    assert observed["connections"], observed
    assert all(
        host == f"{HIBP_FIXED_HOST}:{HIBP_HTTPS_PORT}" for host in observed["connections"]
    ), observed["connections"]
    assert observed["refused"] == [], observed["refused"]
    # Split forbidden material by surface.  The expected five-hex prefixes are
    # the only hash material allowed to leave the process (in the request
    # path), so they are deliberately not treated as secret.  The breached
    # suffix is the correct mock answer, so it is expected in that prefix's
    # response body.  Passwords, full hashes, suffixes and the Secret Key must
    # never appear in any request header or forwarded request.
    forbidden_secrets = (
        breached,
        clean,
        breached_hash,
        clean_hash,
        breached_hash[5:],
        clean_hash[5:],
        vault["secret"],
    )
    header_dumps: list[str] = []
    by_prefix: dict[str, list[dict]] = {}
    for record in observed["requests"]:
        assert not record.get("refused"), record
        path = record["path"]
        prefix = path[len("/range/") :] if path.startswith("/range/") else ""
        # The request path is exactly the fixed segment plus this prefix's
        # exact uppercase five-hex hash.
        assert prefix in (breached_prefix, clean_prefix), path
        assert path == f"/range/{prefix}", path
        assert record["headers"].get("Add-Padding", "").lower() == "true", record["headers"]
        headers_dump = json.dumps(record["headers"])
        # The proxy only forwards a CONNECT target plus the GET line and
        # headers; none of them may carry a password, full hash, suffix or key.
        for canary in forbidden_secrets:
            ctx.assert_no_canary_leak(canary, path, headers_dump)
        forwarded = f"CONNECT {HIBP_FIXED_HOST}:{HIBP_HTTPS_PORT}\nGET {path}\n{headers_dump}"
        for canary in forbidden_secrets:
            ctx.assert_no_canary_leak(canary, forwarded)
        header_dumps.append(headers_dump)
        by_prefix.setdefault(prefix, []).append(record)
    # Exactly one request per expected prefix, no unknown prefix, and each got
    # its own independent answer including the zero-count padding line.
    assert set(by_prefix) == set(responses), (set(by_prefix), set(responses))
    for prefix, expected_lines in responses.items():
        records = by_prefix[prefix]
        assert len(records) == 1, (prefix, records)
        record = records[0]
        assert record["unknown_prefix"] is False, record
        served = tuple((line["suffix"], line["count"]) for line in record["suffixes"])
        assert served == expected_lines, (prefix, served, expected_lines)
        assert record["body"] == "".join(
            f"{suffix}:{count}\r\n" for suffix, count in expected_lines
        ) + "0" * 35 + ":0\r\n", record["body"]
    assert len({record["body"] for record in observed["requests"]}) == 2, (
        "the two prefixes did not receive independent responses"
    )
    # The receipt is the reviewed non-secret projection of the provider answer.
    payload = observed["payload"]
    assert isinstance(payload, dict), payload
    assert payload["hibp_checked"] is True, payload
    assert payload["status"] == "checked-hibp", payload
    assert payload["checked"] == 2, payload
    assert payload["skipped"] == 0, payload
    breach_counts = {
        finding["id"]: finding["breach_count"] for finding in payload["findings"]
    }
    assert breach_counts.get(breached_id) == 2, (payload, responses)
    assert breach_counts.get(clean_id) == 0, payload
    # No password, full hash, hash suffix or Secret Key in the CLI receipt,
    # stdout or terminal transcript.
    transcript = observed["transcript"]
    for canary in forbidden_secrets:
        ctx.assert_no_canary_leak(canary, payload, observed["stdout"], transcript)
    # The consent prompt was presented before the (mocked) network phase.
    assert HIBP_NETWORK_PROMPT in transcript, transcript[-1200:]
    assert "Add-Padding: true" in transcript, transcript[-1200:]
    # The successful run unlocked the authenticated session, recorded one
    # succeeded local Watchtower pass, then the ``vault.health.hibp`` intent
    # followed by its succeeded result.
    delta = [
        event
        for event in after[len(before) :]
        if event.get("action") != "audit.list"
    ]
    assert len(after) >= len(before), (len(before), len(after))
    actions = [event.get("action") for event in delta]
    expected_actions = [
        "desktop.unlock",
        "vault.health.watchtower",
        "vault.health.hibp",
        "vault.health.hibp",
    ]
    assert actions == expected_actions, actions
    unlock_event, watchtower_event, intent_event, result_event = delta
    assert unlock_event.get("result") == "succeeded", unlock_event
    assert watchtower_event.get("result") == "succeeded", watchtower_event
    assert intent_event.get("result") == "intent", intent_event
    assert result_event.get("result") == "succeeded", result_event
    audit_dump = json.dumps(delta)
    for canary in forbidden_secrets:
        ctx.assert_no_canary_leak(canary, audit_dump)


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
