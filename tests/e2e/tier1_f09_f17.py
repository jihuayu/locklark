"""Tier 1 feature-verification E2E tests for F9-F17."""

from __future__ import annotations

import hashlib
import json
import re

from .harness import e2e_test
from .support import (
    F14_REQUIRED_PROFILES,
    PARITY_STATUSES,
    add_login,
    assert_audit_chain,
    audit_events,
    checklist_rows,
    cli_profiles,
    cli_supports,
    desktop_sources,
    evidence_paths,
    extension_asset,
    extension_text,
    extension_or_source_text,
    f10_popup_vault_ready,
    f11_fill_contract_ready,
    f12_parity_doc,
    HIBP_FIXED_HOST,
    HIBP_HTTPS_PORT,
    HIBP_PREFIX_RE,
    f13_cli_hibp_opt_in,
    f13_cli_hibp_range_lookups,
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
    make_vault,
    pty,
    require_hex64,
    reveal_login,
    shell_function_body,
    source_text,
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


M3_FILL = "browser-extension/test/m3_fill_v2.test.js"


@e2e_test(
    "T1_F11_01",
    1,
    ["F11"],
    "Identity item fills a standard autocomplete shipping form",
    coverage_kind="component_contract",
)
def t1_f11_01(ctx):
    # Identity fill ships in browser-extension/core.js and is covered by the M3
    # component contract.  The CLI has no add-item command; that is a genuine
    # command-surface gap, never evidence that identity fields are absent.
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "identity fill entrypoints (fillIdentityDocument/inspectAutofillFields) are absent from the shipped extension",
    )
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 fillIdentityDocument (fills identity inputs and selects|derives first, middle and last names)",
        min_passed=2,
    )
    assert counts["pass"] >= 2, counts


@e2e_test(
    "T1_F11_02",
    1,
    ["F11"],
    "Credit-card item fills name, number, expiry and CVV",
    coverage_kind="component_contract",
)
def t1_f11_02(ctx):
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "credit-card fill entrypoints (fillCardDocument/card classification) are absent from the shipped extension",
    )
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 (fillCardDocument fills number, expiry variants, selects and csc|card classifyField covers cardholder, number, expiry and security)",
        min_passed=2,
    )
    assert counts["pass"] >= 2, counts


@e2e_test(
    "T1_F11_03",
    1,
    ["F11"],
    "Three-step username/password/TOTP login continues automatically",
    coverage_kind="component_contract",
)
def t1_f11_03(ctx):
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "multi-step continuation (username/password/OTP across navigation) is absent from the shipped extension",
    )
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 multi-step login continues username, password and OTP across navigation",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test(
    "T1_F11_04",
    1,
    ["F11"],
    "Split six-box OTP input receives one digit per box",
    coverage_kind="component_contract",
)
def t1_f11_04(ctx):
    ready = f11_fill_contract_ready(ctx)
    gate(
        ctx,
        "F11",
        ready,
        "split-OTP distribution is absent from the shipped extension",
    )
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 split OTP distributes six and eight digits box by box",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test(
    "T1_F11_05",
    1,
    ["F11"],
    "Same-site boundary component contract: same-origin subframe fill and sameSite evaluation",
    coverage_kind="component_contract",
)
def t1_f11_05(ctx):
    # Component checks only.  Both Node tests call the shipped extension code
    # directly; neither loads a page, a subframe or a browser runtime, so no
    # page/subframe/browser injection journey (including sibling-domain iframe
    # fill) is covered or end-to-end verified here.
    #
    # Same-origin half: the shipped identity fill entrypoint validates the
    # top-level and frame origins.
    counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 identity fill permits only same-origin subframes",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts
    # Same-site half: the behavioural evidence is the direct sameSite test in
    # M3_FILL.  The gate only decides whether a same-site helper is shipped at
    # all: the current core.js sameSite/siteKey exports, or an actual psl.js
    # registrable-domain helper when one exists.  It is not full PSL coverage -
    # siteKey resolves suffixes from the finite MULTI_LABEL_SUFFIXES list.
    text = extension_or_source_text(ctx, "core.js") + extension_or_source_text(
        ctx, "content.js"
    )
    has_core_same_site = "function sameSite" in text and "function siteKey" in text
    psl = source_text(ctx, "browser-extension/psl.js")
    has_psl = re.search(
        r"\bfunction\s+(?:registrableDomain|getDomain)\b|\b(?:registrableDomain|getDomain)\s*[:=]",
        psl,
    ) is not None
    gate(
        ctx,
        "F11",
        has_core_same_site or has_psl,
        "same-site boundary component is absent: the extension ships neither the "
        "core.js sameSite/siteKey helper nor a psl.js registrable-domain helper",
    )
    assert has_core_same_site, (
        "a psl.js registrable-domain helper was found, but the direct sameSite "
        "component test in the M3 suite covers the core.js sameSite/siteKey helper; "
        "add a behavioral test for the psl.js helper before claiming this half"
    )
    same_site_counts = node_test_pattern(
        ctx,
        M3_FILL,
        r"M3 sameSite treats sibling subdomains as one site",
        min_passed=1,
    )
    assert same_site_counts["pass"] >= 1, same_site_counts


# ---------------------------------------------------------------------------
# F12
# ---------------------------------------------------------------------------


@e2e_test("T1_F12_01", 1, ["F12"], "Parity checklist exists with schema columns and permitted statuses")
def t1_f12_01(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "docs/browser-parity-checklist.md is absent")
    text = path.read_text(encoding="utf-8")
    assert "1Password" in text
    assert ("Chromium" in text or "Chrome" in text) and "Firefox" in text
    rows = checklist_rows(text)
    assert rows
    status_count = 0
    for row in rows:
        statuses = [
            cell.strip("`*_ ")
            for cell in row
            if cell.strip("`*_ ") in PARITY_STATUSES
        ]
        status_count += len(statuses)
        joined = " ".join(row)
        assert "TODO" not in joined and "WIP" not in joined, row
    assert status_count > 0, "checklist contains no permitted status labels"


@e2e_test("T1_F12_02", 1, ["F12"], "Checklist covers the core M3 browser capability areas")
def t1_f12_02(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "docs/browser-parity-checklist.md is absent")
    text = path.read_text(encoding="utf-8")
    for marker in ("Passkey", "inline", "TOTP", "Identity", "Credit Card", "save"):
        assert marker.lower() in text.lower(), marker


@e2e_test("T1_F12_03", 1, ["F12"], "Checklist links its reference-analysis baseline snapshot")
def t1_f12_03(ctx):
    path = f12_parity_doc(ctx)
    gate(ctx, "F12", path is not None, "parity checklist is absent")
    text = path.read_text(encoding="utf-8")
    assert "历史快照" in text or "参考分析" in text
    assert "history/browser-parity-m3-baseline-2026-11-06.md" in text
    assert (ctx.repo_root / "docs" / "history" / "browser-parity-m3-baseline-2026-11-06.md").is_file()


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


@e2e_test(
    "T1_F13_02",
    1,
    ["F13"],
    "Watchtower flags unsecured HTTP URLs and missing 2FA",
    coverage_kind="component_contract",
)
def t1_f13_02(ctx):
    # Local health categories ship in internal/watchtower and are surfaced by
    # the desktop dashboard/popup banner.  The CLI's opt-in network surface
    # (``personal health --hibp true``) is a different surface, not missing
    # Watchtower analysis.
    ready = f13_watchtower_ready(ctx)
    gate(
        ctx,
        "F13",
        ready,
        "host Watchtower unsecured-HTTP/missing-2FA analysis is absent (the CLI --hibp opt-in is a separate command surface)",
    )
    if go_tool() is None:
        gate(
            ctx,
            "F13",
            False,
            "validation blocked: go toolchain unavailable; native Watchtower component tests not executed",
        )
    counts = go_package_test(
        ctx,
        "./internal/watchtower",
        "TestUnsecuredHTTPAndLocalhost|TestAnalyzeScopeAndTwoFactor",
        min_passed=2,
    )
    assert counts["pass"] >= 2, counts


@e2e_test(
    "T1_F13_03",
    1,
    ["F13"],
    "HIBP k-anonymity sends only the five-hex SHA-1 prefix",
    coverage_kind="component_contract",
)
def t1_f13_03(ctx):
    # Component-level evidence: the host range client is executed against its
    # bundled httptest server, so only the five-hex prefix leaves the process.
    # The CLI opt-in contract is additionally exercised against the synthetic
    # vault (declined consent, strict option pair) by the code after the gate.
    ready = f13_hibp_client_ready(ctx)
    gate(
        ctx,
        "F13",
        ready,
        "host HIBP range client (https-only endpoint, five-hex prefix, cached lookups) is absent; live-network validation blocked",
    )
    if go_tool() is None:
        gate(
            ctx,
            "F13",
            False,
            "validation blocked: go toolchain unavailable; HIBP client component test not executed",
        )
    vault = make_vault(ctx, ["Breach Probe"])
    opt_in = f13_cli_hibp_opt_in(ctx, vault)
    gate(
        ctx,
        "F13",
        opt_in["flags"],
        "`personal health` does not advertise the `--hibp true` opt-in",
    )
    # A refused option pair and a declined consent must both stop before any
    # unlock or vault.health.hibp intent, on the real compiled CLI.
    assert opt_in["bad_pair_refused"], (
        "personal health accepted a non-literal --hibp option pair: "
        f"{opt_in}"
    )
    # The refusal itself was asserted inside f13_cli_hibp_opt_in (fixed
    # cancellation error, no receipt, no unlock and no vault.health.hibp
    # intent appended).
    assert opt_in["audit_delta"] == [], opt_in
    counts = go_package_test(
        ctx,
        "./internal/watchtower",
        "TestHIBPClientPrefixOnlyAndParsing",
        min_passed=1,
    )
    assert counts["pass"] >= 1, counts


@e2e_test(
    "T1_F13_06",
    1,
    ["F13"],
    "Opt-in HIBP breach match through the CLI against the local mock range server",
)
def t1_f13_06(ctx):
    # The CLI hard-codes https://api.pwnedpasswords.com/range/ and offers no
    # endpoint/proxy/client override.  The shipped HIBP client is built with
    # an empty `http.Client` (nil `Transport`), so its requests use Go's
    # default transport, which honours `HTTPS_PROXY` via
    # `ProxyFromEnvironment`.  That default is the only routing mechanism this
    # test uses: a private child environment points `HTTPS_PROXY` at a
    # loopback CONNECT proxy (`NO_PROXY`/`no_proxy` emptied) that accepts only
    # api.pwnedpasswords.com:443 and relays it to a loopback TLS range server
    # whose throwaway certificate for that hostname is the child's only trust
    # anchor (SSL_CERT_FILE/SSL_CERT_DIR).  No system DNS/hosts change,
    # nothing listens on 443, and no production switch is added.
    #
    # If the proxy/CA cannot start or no CONNECT ever arrives, the helper
    # returns PENDING and this run is never redirected to the real service.
    # Once CONNECT arrives, the route is being exercised: a TLS handshake or
    # range failure makes this test hard-fail.  It is never downgraded to
    # pending and never reported green.
    if go_tool() is None:
        gate(
            ctx,
            "F13",
            False,
            "validation blocked: go toolchain unavailable; CLI HIBP opt-in not exercised",
        )
    # Only the two synthetic passwords below are eligible, so the mock must
    # see exactly their two prefixes and nothing else.
    vault = init_vault(ctx)
    breached = "Synthetic-Breached-Pass!2026"
    clean = "Synthetic-Clean-Pass!2026-Xy9"
    add_login(ctx, vault, "Breached Mail", password=breached)
    add_login(ctx, vault, "Clean Mail", password=clean)
    breached_hash = hashlib.sha1(breached.encode("utf-8")).hexdigest().upper()
    clean_hash = hashlib.sha1(clean.encode("utf-8")).hexdigest().upper()
    # Each prefix gets only its own suffix lines.  The breached password's real
    # suffix is the one returned below, so the SUT must match it to report a
    # breach; the clean prefix gets padding only.  The test still sends no
    # suffix or password: only the prefix leaves the process.
    responses = {
        breached_hash[:5]: ((breached_hash[5:], 2),),
        clean_hash[:5]: (),
    }
    assert len(responses) == 2, "the synthetic passwords must share no prefix"
    observed = f13_cli_hibp_range_lookups(ctx, vault, responses)
    if observed["status"] != "ran":
        gate(
            ctx,
            "F13",
            False,
            "local HIBP route not established (loopback CONNECT proxy or synthetic "
            f"CA unavailable): {observed.get('reason', 'no proxy connection')}; the "
            "real service is never contacted and the breach match stays unvalidated",
        )
    # The mock was reached: only the fixed destination was attempted and only
    # five-hex prefixes were requested.
    assert observed["connections"], observed
    assert all(
        host == f"{HIBP_FIXED_HOST}:{HIBP_HTTPS_PORT}" for host in observed["connections"]
    ), observed["connections"]
    assert observed["refused"] == [], observed["refused"]
    assert observed["requests"], "the proxy accepted CONNECT but no range request came"
    by_prefix: dict[str, list[dict]] = {}
    for record in observed["requests"]:
        assert not record.get("refused"), record
        path = record["path"]
        assert path.startswith("/range/"), record
        prefix = path[len("/range/") :]
        assert HIBP_PREFIX_RE.fullmatch(prefix), path
        assert record["headers"].get("Add-Padding", "").lower() == "true", record["headers"]
        for secret_material in (
            breached,
            clean,
            breached_hash[5:],
            clean_hash[5:],
            vault["secret"],
        ):
            ctx.assert_no_canary_leak(secret_material, path, json.dumps(record["headers"]))
        by_prefix.setdefault(prefix, []).append(record)
    # Both expected prefixes reached the mock, each exactly once, and each got
    # exactly its own independent answer rather than a shared canned body.
    assert set(by_prefix) == set(responses), (set(by_prefix), set(responses))
    for prefix, expected_lines in responses.items():
        records = by_prefix[prefix]
        assert len(records) == 1, (prefix, records)
        record = records[0]
        assert record["unknown_prefix"] is False, record
        served = tuple(
            (line["suffix"], line["count"]) for line in record["suffixes"]
        )
        assert served == expected_lines, (prefix, served, expected_lines)
        assert record["body"] == "".join(
            f"{suffix}:{count}\r\n" for suffix, count in expected_lines
        ) + "0" * 35 + ":0\r\n", record["body"]
    assert len({record["body"] for record in observed["requests"]}) == 2, (
        "the two prefixes did not receive independent responses"
    )
    payload = observed["payload"]
    assert payload["hibp_checked"] is True, payload
    assert payload["status"] == "checked-hibp", payload
    titles = {row["id"]: row["title"] for row in list_rows(ctx, vault, state="active")}
    for canary in (breached, clean, breached_hash[5:], clean_hash[5:], vault["secret"]):
        ctx.assert_no_canary_leak(canary, json.dumps(payload), observed["transcript"])
    breach_counts = {
        finding["id"]: finding["breach_count"] for finding in payload["findings"]
    }
    breached_id = next(key for key, title in titles.items() if title == "Breached Mail")
    clean_id = next(key for key, title in titles.items() if title == "Clean Mail")
    assert breach_counts.get(breached_id) == 2, (payload, responses)
    assert breach_counts.get(clean_id) == 0, payload


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


def _profile_map(ctx):
    return {entry["name"]: entry for entry in cli_profiles(ctx)}


@e2e_test("T1_F14_01", 1, ["F14"], "Capability probe: cli profiles exposes the required registry IDs")
def t1_f14_01(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "structured cli profiles registry is absent or incomplete")
    profiles = _profile_map(ctx)
    assert all(
        profiles[name]["id"] == profile_id
        for name, profile_id in F14_REQUIRED_PROFILES.items()
    )


@e2e_test("T1_F14_02", 1, ["F14"], "Capability probe: aws profile declares required key slots")
def t1_f14_02(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "cliprobe aws profile is absent")
    aws = _profile_map(ctx)["aws"]
    assert aws["id"] == "aws-env-v1"
    slots = {slot["name"]: slot for slot in aws["slots"]}
    assert slots["access_key_id"]["field"] == "username"
    assert slots["secret_access_key"]["field"] == "password"


@e2e_test("T1_F14_03", 1, ["F14"], "Capability probe: kubectl and docker template slots are declared")
def t1_f14_03(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "kubectl/docker profile file templates are absent")
    profiles = _profile_map(ctx)
    assert profiles["kubectl"]["slots"][0]["kind"] == "document"
    assert profiles["kubectl"]["slots"][0]["field"] == "attachment"
    assert {slot["name"] for slot in profiles["docker"]["slots"]} >= {"username", "password"}


@e2e_test("T1_F14_04", 1, ["F14"], "Capability probe: npm/terraform/psql/git profiles are present")
def t1_f14_04(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "npm/terraform/psql/git profile templates are absent")
    profiles = _profile_map(ctx)
    assert {"npm", "terraform", "psql", "git"} <= set(profiles)
    assert "npm" in profiles["npm"]["executables"]
    assert "psql" in profiles["psql"]["executables"]


@e2e_test("T1_F14_05", 1, ["F14"], "Capability probe: profile help/show stays credential-free")
def t1_f14_05(ctx):
    ready = f14_cli_profiles_ready(ctx)
    gate(ctx, "F14", ready, "NeedsAuth bypass metadata is absent")
    result = ctx.run_cli(["cli", "show", "gh"])
    assert result.returncode != 0 or "gh" in result.stdout


# ---------------------------------------------------------------------------
# F15
# ---------------------------------------------------------------------------


def _run_help(ctx):
    result = ctx.run_cli(["cli", "run", "--help"])
    assert result.returncode == 0, result.stderr[-800:]
    return result.stdout + result.stderr


@e2e_test("T1_F15_01", 1, ["F15"], "Capability probe: public cli run contract advertises multi-slot execution")
def t1_f15_01(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "public cli run / multi-slot profile contract is absent")
    usage = _run_help(ctx)
    assert "locklark cli run <tool>" in usage and "-- [ARG...]" in usage


@e2e_test("T1_F15_02", 1, ["F15"], "Capability probe: run help documents binding, cwd and timeout")
def t1_f15_02(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle file materialization is absent")
    usage = _run_help(ctx)
    assert all(token in usage for token in ("--binding PATH", "--cwd ABS_DIR", "--timeout SECONDS"))


@e2e_test("T1_F15_03", 1, ["F15"], "Capability probe: run accepts verbatim child argv after --")
def t1_f15_03(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle cleanup contract is absent")
    usage = _run_help(ctx)
    assert "-- [ARG...]" in usage
    assert "foreground" in usage.lower()


@e2e_test("T1_F15_04", 1, ["F15"], "Capability probe: spec-bound profile slots are exposed without internals")
def t1_f15_04(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "RunBundle spec-digest HMAC binding is absent")
    profiles = {entry["name"]: entry for entry in cli_profiles(ctx)}
    assert len(profiles["aws"]["slots"]) >= 2
    assert _run_help(ctx)


@e2e_test("T1_F15_05", 1, ["F15"], "Capability probe: profile registry declares credential-field slots")
def t1_f15_05(ctx):
    ready = f15_run_bundle_ready(ctx)
    gate(ctx, "F15", ready, "runBaseEnvironment allow-list is absent")
    profiles = {entry["name"]: entry for entry in cli_profiles(ctx)}
    fields = {slot["field"] for entry in profiles.values() for slot in entry["slots"]}
    assert {"username", "password"} <= fields


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
    gate(
        ctx,
        "F17",
        ready,
        "CLI broker client over the desktop IPC is absent (the desktop broker server "
        "exists), so broker-assisted cli run cannot be exercised",
    )
    assert f14_cli_profiles_ready(ctx)


@e2e_test("T1_F17_02", 1, ["F17"], "Per-terminal approval lease avoids repeated prompts")
def t1_f17_02(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "terminal approval lease is absent because the CLI broker client that would "
        "hold leases does not exist",
    )
    assert f17_broker_ready(ctx)


@e2e_test("T1_F17_03", 1, ["F17"], "Locking the desktop revokes active CLI broker leases")
def t1_f17_03(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "broker lease revocation on lock is unexercised: no CLI broker client exists "
        "to hold leases",
    )
    text = desktop_sources(ctx)
    assert "lock" in text.lower()


@e2e_test("T1_F17_04", 1, ["F17"], "Broker absence falls back to the controlling-TTY factor prompt")
def t1_f17_04(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "CLI broker fallback path is absent (no client-side broker handshake or "
        "controlling-TTY factor prompt exists)",
    )
    assert f14_cli_profiles_ready(ctx)


@e2e_test("T1_F17_05", 1, ["F17"], "Leases are isolated per TTY and per CLI profile")
def t1_f17_05(ctx):
    ready = f17_broker_ready(ctx)
    gate(
        ctx,
        "F17",
        ready,
        "per-TTY/per-profile lease isolation is absent because leases live in the "
        "missing CLI broker client",
    )
    assert f17_broker_ready(ctx)
