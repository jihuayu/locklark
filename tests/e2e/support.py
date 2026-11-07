"""Shared opaque-box helpers for the M5 four-tier E2E suite.

Everything in this module talks to the product through the same user-facing
surfaces the harness exposes: compiled binaries, native-messaging frames,
built extension bundles, and repository files.  It never imports a Locklark Go
package or inspects private in-memory state.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Iterable, Sequence

from .harness import CLIResult, E2EContext, PTYResult, terminate_process_group

HEX32_RE = re.compile(r"^[a-f0-9]{32}$")
HEX64_RE = re.compile(r"^[a-f0-9]{64}$")

# The five checklist statuses permitted by docs/design.md.
PARITY_STATUSES = (
    "未实现",
    "已实现未对照",
    "已实测",
    "平台不适用",
    "经用户确认的差异",
)


# ---------------------------------------------------------------------------
# Progressive gate
# ---------------------------------------------------------------------------


def gate(ctx: E2EContext, feature: str, condition: Any, detail: str) -> None:
    """Gate a milestone assertion on a *real* observation.

    ``detail`` must explain precisely which user-facing artifact or protocol
    capability was probed.  The duplicate marker is deliberate: release tooling
    greps for ``FEATURE_NOT_YET_LANDED`` while the harness prefixes the
    structured ``PROGRESSIVE_UNIMPLEMENTED`` marker.
    """

    ctx.require_feature(
        feature,
        bool(condition),
        f"FEATURE_NOT_YET_LANDED: {feature} - {detail}",
    )


def require_hex32(value: str, label: str = "id") -> str:
    if not HEX32_RE.fullmatch(value or ""):
        raise AssertionError(f"{label} is not a 32-hex identifier: {value!r}")
    return value


def require_hex64(value: str, label: str = "revision") -> str:
    if not HEX64_RE.fullmatch(value or ""):
        raise AssertionError(f"{label} is not a 64-hex revision: {value!r}")
    return value


# ---------------------------------------------------------------------------
# CLI / PTY helpers
# ---------------------------------------------------------------------------


def pty(
    ctx: E2EContext,
    args: Sequence[Any],
    *,
    password: str | None = None,
    secret: str | None = None,
    extra: Sequence[tuple[str, str | None]] = (),
    **kwargs: Any,
) -> PTYResult:
    prompts: list[tuple[str, str | None]] = []
    if password is not None:
        prompts.append(("主密码", password))
    if secret is not None:
        prompts.append(("Secret Key", secret))
    prompts.extend(extra)
    return ctx.run_pty_cli(args, prompts=prompts, **kwargs)


def init_vault(ctx: E2EContext) -> dict[str, Any]:
    path, password, secret = ctx.init_vault()
    return {"path": path, "password": password, "secret": secret, "items": []}


def add_login(
    ctx: E2EContext,
    vault: dict[str, Any],
    title: str,
    username: str | None = None,
    password: str | None = None,
    *,
    index: int = 0,
) -> tuple[str, str]:
    item_id, revision = ctx.add_login(
        vault["path"],
        vault["password"],
        vault["secret"],
        title,
        username if username is not None else f"{title.lower()}-user",
        password
        if password is not None
        else f"pw-{title.lower()}-{index}-2026-Aa1!",
    )
    require_hex32(item_id)
    require_hex64(revision)
    vault["items"].append(
        {"id": item_id, "revision": revision, "title": title, "username": username}
    )
    return item_id, revision


def make_vault(
    ctx: E2EContext, titles: Sequence[str] = ("Alpha",)
) -> dict[str, Any]:
    vault = init_vault(ctx)
    for index, title in enumerate(titles):
        add_login(ctx, vault, title, index=index)
    return vault


def list_rows(
    ctx: E2EContext, vault: dict[str, Any], state: str | None = None
) -> list[dict[str, Any]]:
    args = ["personal", "list", "--file", str(vault["path"])]
    if state:
        args.extend(["--state", state])
    result = pty(ctx, args, password=vault["password"], secret=vault["secret"])
    if result.returncode != 0:
        raise AssertionError(
            f"personal list failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    rows = result.json()
    if not isinstance(rows, list):
        raise AssertionError(f"personal list did not return a list: {rows!r}")
    return rows


def audit_events(ctx: E2EContext, vault: dict[str, Any]) -> list[dict[str, Any]]:
    result = pty(
        ctx,
        ["personal", "audit", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
    )
    if result.returncode != 0:
        raise AssertionError(
            f"personal audit failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    events = result.json()
    if not isinstance(events, list) or not events:
        raise AssertionError(f"personal audit did not return events: {events!r}")
    return events


def assert_audit_chain(events: Sequence[dict[str, Any]]) -> None:
    """Assert the externally visible shape of the authenticated hash chain."""

    last_sequence = 0
    previous: set[str] = set()
    for event in events:
        sequence = event.get("sequence")
        if not isinstance(sequence, int) or sequence <= last_sequence:
            raise AssertionError(f"audit sequence is not strictly increasing: {event!r}")
        last_sequence = sequence
        link = event.get("previous", "")
        if sequence == 1:
            if link != "":
                raise AssertionError(f"first audit event has a previous link: {event!r}")
        else:
            if not HEX64_RE.fullmatch(link or ""):
                raise AssertionError(f"audit previous link is not 64-hex: {event!r}")
            if link in previous:
                raise AssertionError(f"audit chain reuses a previous link: {event!r}")
        signature = event.get("signature", "")
        if not signature or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", signature):
            raise AssertionError(f"audit event is not signed: {event!r}")
        if not event.get("action") or not event.get("session"):
            raise AssertionError(f"audit event lacks action/session: {event!r}")
        previous.add(link)


def reveal_login(
    ctx: E2EContext,
    vault: dict[str, Any],
    item_id: str,
    revision: str,
    field: str,
) -> tuple[Any, str]:
    result = pty(
        ctx,
        [
            "personal",
            "reveal-login",
            "--file",
            str(vault["path"]),
            "--id",
            item_id,
            "--revision",
            revision,
            "--field",
            field,
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SHOW 确认显示", "SHOW")],
    )
    if result.returncode != 0:
        raise AssertionError(
            f"reveal-login failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    # The disclosed JSON string is written to the terminal, not stdout.
    match = re.search(r'\r?\n("(?:[^"\\]|\\.)*")\s*$', result.transcript)
    if not match:
        raise AssertionError(f"reveal-login did not disclose JSON: {result.transcript[-400:]!r}")
    return json.loads(match.group(1)), result.transcript


def edit_url(
    ctx: E2EContext, vault: dict[str, Any], item_id: str, revision: str, url: str
) -> str:
    result = pty(
        ctx,
        [
            "personal",
            "edit-login",
            "--file",
            str(vault["path"]),
            "--id",
            item_id,
            "--revision",
            revision,
            "--field",
            "url",
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("新网站 HTTPS URL（ASCII，留空清除）", url)],
    )
    if result.returncode != 0:
        raise AssertionError(
            f"edit-login url failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    payload = result.json()
    require_hex64(payload.get("revision", ""))
    return payload["revision"]


def match_logins(
    ctx: E2EContext, vault: dict[str, Any], origin: str, frame_origin: str | None = None
) -> list[dict[str, Any]]:
    result = pty(
        ctx,
        [
            "personal",
            "match-logins",
            "--file",
            str(vault["path"]),
            "--origin",
            origin,
            "--frame-origin",
            frame_origin or origin,
        ],
        password=vault["password"],
        secret=vault["secret"],
    )
    if result.returncode != 0:
        raise AssertionError(
            f"match-logins failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    rows = result.json()
    if not isinstance(rows, list):
        raise AssertionError(f"match-logins did not return a list: {rows!r}")
    return rows


def health_report(ctx: E2EContext, vault: dict[str, Any], *, check: bool = True) -> dict[str, Any]:
    result = pty(
        ctx,
        ["personal", "health", "--file", str(vault["path"])],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SCAN 确认本地体检", "SCAN")],
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"personal health failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    return {"result": result, "payload": result.json() if result.returncode == 0 else {}}


def flags_by_id(payload: dict[str, Any]) -> dict[str, set[str]]:
    report = payload.get("report") or {}
    findings = report.get("findings") or []
    return {
        finding.get("id", ""): set(finding.get("flags") or [])
        for finding in findings
        if isinstance(finding, dict)
    }


def make_script(ctx: E2EContext, name: str, body: str) -> Path:
    path = ctx.temp_dir / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o700)
    return path


def assert_private(ctx: E2EContext, canary: str, *texts: Any) -> None:
    ctx.assert_no_canary_leak(canary, *texts)


# ---------------------------------------------------------------------------
# 1PUX fixtures
# ---------------------------------------------------------------------------


def login_1pux_item(
    title: str, url: str, username: str, password: str, *, uuid: str | None = None
) -> dict[str, Any]:
    return {
        "uuid": uuid or title.lower().replace(" ", "-"),
        "categoryUuid": "001",
        "state": "active",
        "createdAt": 123,
        "overview": {"title": title, "url": url},
        "details": {
            "loginFields": [
                {"designation": "username", "type": "T", "value": username},
                {"designation": "password", "type": "P", "value": password},
            ]
        },
    }


def write_1pux(path: Path, items: Sequence[dict[str, Any]]) -> Path:
    data = {
        "accounts": [
            {
                "attrs": {"uuid": "account-e2e"},
                "vaults": [
                    {"attrs": {"uuid": "vault-e2e"}, "items": list(items)}
                ],
            }
        ]
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "export.attributes",
            json.dumps(
                {
                    "version": 3,
                    "description": "1Password Unencrypted Export",
                    "createdAt": 0,
                }
            ),
        )
        archive.writestr("export.data", json.dumps(data))
    return path


def multi_category_1pux(ctx: E2EContext) -> Path:
    """A rich archive that baseline locklark intentionally rejects wholesale."""

    login = login_1pux_item(
        "Corp SSO", "https://sso.corp.example.test/login", "alice", "P@ssw0rd-2026"
    )
    login["overview"]["urls"] = [
        {"label": "primary", "url": "https://sso.corp.example.test/login"},
        {"label": "portal", "url": "https://portal.corp.example.test/auth"},
    ]
    login["details"]["sections"] = [
        {
            "title": "Recovery",
            "fields": [
                {
                    "designation": "recovery_code",
                    "type": "C",
                    "value": "CANARY-1PUX-RECOVERY-9912",
                }
            ],
        }
    ]
    login["tags"] = ["imported"]
    login["favIndex"] = 1
    note = {
        "uuid": "secure-note-1",
        "categoryUuid": "003",
        "state": "active",
        "overview": {"title": "Runbook"},
        "details": {"notesPlain": "restart the service"},
    }
    identity = {
        "uuid": "identity-1",
        "categoryUuid": "004",
        "state": "active",
        "overview": {"title": "Ada Lovelace"},
        "details": {
            "sections": [
                {
                    "title": "Personal",
                    "fields": [
                        {"designation": "firstname", "type": "T", "value": "Ada"},
                        {"designation": "lastname", "type": "T", "value": "Lovelace"},
                    ],
                }
            ]
        },
    }
    card = {
        "uuid": "card-1",
        "categoryUuid": "002",
        "state": "active",
        "overview": {"title": "Corp Visa"},
        "details": {
            "sections": [
                {
                    "title": "Card",
                    "fields": [
                        {"designation": "cardnumber", "type": "T", "value": "4111222233334444"},
                        {"designation": "cvv", "type": "C", "value": "842"},
                    ],
                }
            ]
        },
    }
    return write_1pux(ctx.temp_dir / "multi-category.1pux", [login, note, identity, card])


def simple_1pux(ctx: E2EContext) -> Path:
    return write_1pux(
        ctx.temp_dir / "simple.1pux",
        [
            login_1pux_item(
                "GitHub",
                "https://github.example.test/login",
                "alice",
                "simple-secret-2026",
            )
        ],
    )


# ---------------------------------------------------------------------------
# Extension / repository probes
# ---------------------------------------------------------------------------


def built_extension(ctx: E2EContext) -> tuple[Path, Path]:
    return ctx.ensure_extension_built()


def extension_asset(ctx: E2EContext, name: str) -> bool:
    for directory in built_extension(ctx):
        if (directory / name).is_file():
            return True
    return False


def extension_text(ctx: E2EContext, name: str) -> str:
    for directory in built_extension(ctx):
        path = directory / name
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
    return ""


def source_text(ctx: E2EContext, relative: str) -> str:
    path = ctx.repo_root / relative
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def extension_or_source_text(ctx: E2EContext, name: str) -> str:
    """Return a shipped bundle asset, falling back to its checked-in source.

    Component contracts are asserted against the same code the browser runs
    (``browser-extension/build.js`` output) but must not turn a not-yet-built
    dist directory into a phantom feature absence.
    """

    return extension_text(ctx, name) or source_text(ctx, f"browser-extension/{name}")


def sources_contain(ctx: E2EContext, relative_glob: str, needle: str) -> bool:
    for path in (ctx.repo_root).glob(relative_glob):
        if not path.is_file():
            continue
        try:
            if needle in path.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def source_files(ctx: E2EContext, relative_glob: str) -> list[Path]:
    return [path for path in ctx.repo_root.glob(relative_glob) if path.is_file()]


def cli_help(ctx: E2EContext) -> str:
    result = ctx.run_cli(["help"])
    if result.returncode != 0:
        raise AssertionError(f"locklark help failed (rc={result.returncode}): {result.stderr}")
    return result.stdout + "\n" + result.stderr


def cli_supports(ctx: E2EContext, token: str) -> bool:
    return token in cli_help(ctx)


def cli_command(ctx: E2EContext, args: Sequence[Any], **kwargs: Any) -> CLIResult:
    return ctx.run_cli(args, **kwargs)


def command_known(ctx: E2EContext, args: Sequence[Any]) -> tuple[bool, CLIResult]:
    result = ctx.run_cli(args)
    known = not (
        result.returncode != 0
        and "unknown command; see locklark help" in (result.stderr or "")
    )
    return known, result


def node_test(ctx: E2EContext, relative: str, timeout: float = 90.0) -> subprocess.CompletedProcess:
    node = shutil.which("node")
    if node is None:
        raise AssertionError("node is required for extension E2E checks")
    result = ctx.run_cli(
        ["--test", str(ctx.repo_root / relative)],
        binary=node,
        timeout=timeout,
        cwd=ctx.repo_root,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"node --test {relative} failed (rc={result.returncode}):\n"
            f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
    combined = result.stdout + result.stderr
    if re.search(r"^# fail [1-9]", combined, re.MULTILINE):
        raise AssertionError(f"node --test {relative} reported failures:\n{combined[-3000:]}")
    return subprocess.CompletedProcess(
        args=["node", "--test", relative],
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


NODE_SUMMARY_RE = re.compile(
    r"(?:^|\s)(?:ℹ|#)\s+(tests|pass|fail|skipped)\s+(\d+)", re.MULTILINE
)


def _node_summary_counts(text: str) -> dict[str, int]:
    counts = {"tests": 0, "pass": 0, "fail": 0, "skipped": 0}
    for name, value in NODE_SUMMARY_RE.findall(text or ""):
        counts[name] = max(counts[name], int(value))
    return counts


def node_test_pattern(
    ctx: E2EContext,
    relative: str,
    pattern: str,
    *,
    min_passed: int = 1,
    timeout: float = 120.0,
) -> dict[str, int]:
    """Run one existing component test file, selected by test-name pattern.

    The pattern *is* the contract: a pattern that selects zero executed tests
    is a stale adapter and raises AssertionError (a real failure), never a
    ``FEATURE_NOT_YET_LANDED`` pending result.  ``min_passed`` guards against a
    silently renamed test shrinking the selected set.
    """

    node = shutil.which("node")
    if node is None:
        raise AssertionError("node is required for extension component contracts")
    args = [
        "--test",
        f"--test-name-pattern={pattern}",
        str((ctx.repo_root / relative).resolve()),
    ]
    result = ctx.run_cli(args, binary=node, timeout=timeout, cwd=ctx.repo_root)
    combined = (result.stdout or "") + (result.stderr or "")
    counts = _node_summary_counts(combined)
    label = f"node --test {relative} --test-name-pattern={pattern!r}"
    if result.returncode != 0:
        raise AssertionError(f"{label} failed (rc={result.returncode}):\n{combined[-2000:]}")
    if counts["fail"]:
        raise AssertionError(
            f"{label} reported {counts['fail']} failing component tests:\n{combined[-2500:]}"
        )
    if counts["pass"] < min_passed:
        raise AssertionError(
            f"{label} selected {counts['pass']} passing tests, expected at least "
            f"{min_passed}; the pattern no longer matches the component contract"
            f" (stale adapter, not an absent feature):\n{combined[-2000:]}"
        )
    return counts


def go_tool() -> str | None:
    found = shutil.which("go")
    if found:
        return found
    for candidate in (
        os.environ.get("LOCKLARK_GO", ""),
        "/workspace/toolchains/go/bin/go",
    ):
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def go_package_test(
    ctx: E2EContext,
    package: str,
    run: str,
    *,
    min_passed: int = 1,
    timeout: float = 180.0,
) -> dict[str, int]:
    """Execute existing Go package tests for a native service contract.

    This is component-level evidence: it runs the shipped implementation with
    its own tests, but never claims a live network round trip.  A package test
    that fails is an implementation failure, not an absent feature.
    """

    go = go_tool()
    if go is None:
        raise AssertionError(
            "validation blocked: go toolchain unavailable; native component tests not executed"
        )
    args = ["test", package, "-run", run, "-count=1", "-v"]
    result = ctx.run_cli(args, binary=go, timeout=timeout, cwd=ctx.repo_root)
    combined = (result.stdout or "") + (result.stderr or "")
    passed = len(re.findall(r"^--- PASS: ", combined, re.MULTILINE))
    if result.returncode != 0:
        raise AssertionError(
            f"go test {package} -run {run!r} failed (rc={result.returncode}):\n{combined[-2500:]}"
        )
    if passed < min_passed:
        raise AssertionError(
            f"go test {package} -run {run!r} executed {passed} tests, expected at least "
            f"{min_passed}; the native contract is no longer covered"
            f" (stale adapter, not an absent feature):\n{combined[-2000:]}"
        )
    return {"pass": passed}


def node_eval(ctx: E2EContext, code: str, timeout: float = 30.0) -> str:
    result = ctx.run_node(code, timeout=timeout)
    if result.returncode != 0:
        raise AssertionError(
            f"node evaluation failed (rc={result.returncode}):\n"
            f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# Native-messaging probes
# ---------------------------------------------------------------------------


def native_probe(
    ctx: E2EContext,
    frame: Any,
    *,
    browser: str = "chromium",
    timeout: float = 8.0,
    launch_args: Sequence[Any] | None = None,
    await_reply: bool = False,
) -> Any:
    """Speak the native-messaging protocol to the real browser host.

    ``await_reply=True`` is only for probes whose answer is produced by the
    desktop broker round trip: it keeps the relay stdin open until one complete
    framed reply arrives, mirroring a real browser.  Malformed/truncated-EOF
    probes keep the default immediate-close behaviour.
    """

    return ctx.probe_native_host_frame(
        frame,
        browser=browser,
        timeout=timeout,
        launch_args=launch_args,
        await_reply=await_reply,
    )


def native_error_frame(probe: Any, request_id: str | None = None) -> bool:
    for frame in probe.frames:
        if frame.get("type") != "error" or frame.get("error") != "refused":
            continue
        if request_id is None or frame.get("id") == request_id:
            return True
    return False


def native_has_credential(probe: Any) -> bool:
    for frame in probe.frames:
        if frame.get("type") in ("passkey-result", "fill", "saved", "otp-fill"):
            return True
        if "password" in frame or "credential" in frame:
            return True
    return False


# ---------------------------------------------------------------------------
# Feature-readiness probes (all real, all cheap)
# ---------------------------------------------------------------------------


def f1_passkey_ready(ctx: E2EContext) -> bool:
    return extension_asset(ctx, "webauthn.js") and (
        bool(source_files(ctx, "internal/browserhost/passkey*.go"))
        or "passkey-create" in source_text(ctx, "internal/browserhost/protocol.go")
    )


def f1_autosubmit_ready(ctx: E2EContext) -> bool:
    """Firefox form auto-submit rides on the shipped ``autoLogin`` preference.

    The extension never used an ``autoSubmit`` identifier; probing that literal
    described a nonexistent artifact and turned a working path into a phantom
    feature gap.
    """

    core = extension_or_source_text(ctx, "core.js")
    return "autoLogin" in core and "requestSubmit" in core


def f2_inline_ready(ctx: E2EContext) -> bool:
    content = extension_text(ctx, "content.js")
    return bool(content) and (
        "attachShadow" in content or "autoSubmit" in content or "autofill" in content
    )


def f2_autologin_ready(ctx: E2EContext) -> bool:
    """Global/per-login auto-login plumbing in the shipped extension bundle."""

    names = ("background.js", "content.js", "core.js", "popup.js", "options.js")
    text = "".join(extension_or_source_text(ctx, name) for name in names)
    return "autoLogin" in text and "loginOverrides" in text


def f3_team_sync_ready(ctx: E2EContext) -> bool:
    return ctx.team_sync_bin is not None


def f4_team_cli_ready(ctx: E2EContext) -> bool:
    known, result = command_known(ctx, ["team", "status"])
    return known and "unknown command" not in (result.stderr or "").lower()


def desktop_sources(ctx: E2EContext) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in source_files(ctx, "internal/desktop/*.go")
        if not path.name.endswith("_test.go")
    )


def f5_desktop_timer_ready(ctx: E2EContext) -> bool:
    text = desktop_sources(ctx)
    # The #32 fix must clear the clipboard from a timer that does not depend on
    # a rendered frame.  Accept the common shapes an implementation may use.
    return bool(
        re.search(r"AfterFunc\([^\n]*clipboardUntil", text)
        or "clipboardExpiry" in text
        or "scheduleClipboard" in text
        or "clipboardTimer" in text
    )


def f5_filter_refresh_ready(ctx: E2EContext) -> bool:
    """The desktop refresh path captures and re-applies query/scope.

    The real contract is the ``captureFilter``/``filterCurrent``/``queryRows``
    trio used by ``refresh()``; a regex over the shape of the function body only
    matched an older spelling of the code.
    """

    text = desktop_sources(ctx)
    return (
        re.search(r"func \(a \*App\) refresh\(\)", text) is not None
        and "filter := a.captureFilter()" in text
        and "a.filterCurrent(filter)" in text
        and "queryRows(s, filter)" in text
    )


def f7_shared_ipc_ready(ctx: E2EContext) -> bool:
    if source_files(ctx, "internal/desktop/ipc*.go"):
        return True
    text = desktop_sources(ctx)
    return "shared session" in text.lower() or "desktopipc" in text.lower()


def f8_desktop_v2_ready(ctx: E2EContext) -> bool:
    text = desktop_sources(ctx)
    return any(
        marker in text
        for marker in ("收藏夹", "所有条目", "最近删除", "生成器", "item_editor")
    )


def f8_v2_editor_ready(ctx: E2EContext) -> bool:
    """Desktop v2 item editor plus the random/memorable/PIN generator."""

    text = desktop_sources(ctx)
    editor = any(
        marker in text
        for marker in ("item_editor", "editItem", "openEditor", "v2.editor")
    )
    generator = "generatorState" in text and all(
        mode in text for mode in ("ModeRandom", "ModeMemorable", "ModePIN")
    )
    return editor and generator


def f9_save_generator_ready(ctx: E2EContext) -> bool:
    content = extension_text(ctx, "content.js")
    core = extension_text(ctx, "core.js") or source_text(ctx, "browser-extension/core.js")
    return bool(content) and (
        "postSubmit" in content or "save" in content.lower() or "generator" in content.lower()
    ) and ("generator" in core.lower() or "generate" in core.lower())


def f10_popup_vault_ready(ctx: E2EContext) -> bool:
    popup = extension_text(ctx, "popup.js") or source_text(ctx, "browser-extension/popup.js")
    return extension_asset(ctx, "options.html") and any(
        marker in popup.lower()
        for marker in ("search", "open-and-fill", "openfill", "edit")
    )


def f11_identity_ready(ctx: E2EContext) -> bool:
    """CLI item-creation command surface (NOT identity/card fill existence).

    ``personal add-item`` is a genuine command-surface gap; the identity and
    credit-card fill contracts live in the browser extension and must be probed
    with :func:`f11_fill_contract_ready`, never through this CLI probe.
    """

    return cli_supports(ctx, "add-item") or cli_supports(ctx, "edit-item")


def f11_fill_contract_ready(ctx: E2EContext) -> bool:
    """Identity/credit-card fill entrypoints shipped by the extension."""

    text = extension_or_source_text(ctx, "core.js") + extension_or_source_text(
        ctx, "content.js"
    )
    test_file = ctx.repo_root / "browser-extension" / "test" / "m3_fill_v2.test.js"
    return (
        test_file.is_file()
        and "fillIdentityDocument" in text
        and "fillCardDocument" in text
        and "credit_card" in text
    )


def f12_parity_doc(ctx: E2EContext) -> Path | None:
    path = ctx.repo_root / "docs" / "browser-parity-checklist.md"
    if path.is_file() and path.stat().st_size > 0:
        return path
    return None


def f13_cli_health_flags(ctx: E2EContext) -> bool:
    """Opt-in HIBP flags on the CLI ``health`` command (a separate surface)."""

    help_text = cli_help(ctx)
    return "--check-breached" in help_text or "--hibp-endpoint" in help_text


def f13_hibp_client_ready(ctx: E2EContext) -> bool:
    """Host HIBP range client: https-only, five-hex prefix, cached lookups."""

    hibp = source_text(ctx, "internal/watchtower/hibp.go")
    host = source_text(ctx, "internal/browserhost/protocol.go")
    return bool(
        hibp
        and "https://" in hibp
        and "hibpPrefix" in hibp
        and "LookupCandidates" in hibp
        and "include_hibp" in host
    )


def f13_watchtower_ready(ctx: E2EContext) -> bool:
    """Host/browser Watchtower service, independent of CLI health flags.

    Local health categories (weak/reused, unsecured HTTP, missing 2FA) ship in
    ``internal/watchtower`` and are surfaced by the desktop dashboard and the
    popup banner; the CLI ``health`` command has no opt-in HIBP flags.  Those
    two facts must never be conflated into "Watchtower is absent".
    """

    watchtower = source_text(ctx, "internal/watchtower/watchtower.go")
    host = bool(watchtower) and (
        "UnsecuredHTTP" in watchtower or "unsecured-http" in watchtower
    )
    desktop = "watchtower" in desktop_sources(ctx).lower()
    browser = any(
        "watchtower" in extension_or_source_text(ctx, name).lower()
        for name in ("background.js", "popup.js")
    )
    return bool(host or desktop or browser)


F14_REQUIRED_PROFILES = {
    "gh": "gh-v1",
    "aws": "aws-env-v1",
    "kubectl": "kubectl-kubeconfig-v1",
    "docker": "docker-config-v1",
    "npm": "npm-npmrc-v1",
    "terraform": "terraform-v1",
    "git": "git-askpass-v1",
    "psql": "psql-pgpass-v1",
    "token": "token-v1",
}


def cli_profiles(ctx: E2EContext) -> list[dict[str, Any]]:
    """Return the validated structured profile registry, or [] if absent.

    ``cli list`` shows bindings, not built-in profiles, so it must never be
    used as a capability probe here.  A command that advertises profiles but
    fails or emits a malformed contract is an implementation failure, not an
    absent feature: those cases raise AssertionError.
    """

    help_result = ctx.run_cli(["help"])
    if help_result.returncode != 0:
        raise AssertionError(
            f"locklark help probe failed (rc={help_result.returncode}): "
            f"{help_result.stderr[-800:]}"
        )
    if "cli profiles" not in (help_result.stdout + help_result.stderr):
        return []
    result = ctx.run_cli(["cli", "profiles"])
    if result.returncode != 0:
        raise AssertionError(
            f"advertised `cli profiles` failed (rc={result.returncode}): "
            f"{result.stderr[-800:]}"
        )
    try:
        payload = result.json()
    except (TypeError, ValueError) as exc:
        raise AssertionError(f"cli profiles returned invalid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise AssertionError(f"cli profiles did not return a JSON list: {payload!r}")
    seen: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            raise AssertionError(f"cli profiles entry is not an object: {entry!r}")
        name = entry.get("name")
        profile_id = entry.get("id")
        if not isinstance(name, str) or not name:
            raise AssertionError(f"cli profiles entry lacks a name: {entry!r}")
        if not isinstance(profile_id, str) or not profile_id:
            raise AssertionError(f"cli profile {name!r} lacks an id: {entry!r}")
        if name in seen:
            raise AssertionError(f"cli profiles repeats {name!r}")
        seen.add(name)
        if not isinstance(entry.get("slots"), list) or not entry["slots"]:
            raise AssertionError(f"cli profile {name!r} lacks slots: {entry!r}")
        if not isinstance(entry.get("max_timeout"), int) or entry["max_timeout"] <= 0:
            raise AssertionError(f"cli profile {name!r} has an invalid timeout: {entry!r}")
    return payload


def f14_cli_profiles_ready(ctx: E2EContext) -> bool:
    payload = cli_profiles(ctx)
    if not payload:
        return False
    by_name = {entry["name"]: entry["id"] for entry in payload}
    return all(by_name.get(name) == profile_id for name, profile_id in F14_REQUIRED_PROFILES.items())


def f15_run_bundle_ready(ctx: E2EContext) -> bool:
    """Probe the public multi-credential CLI runner contract.

    Internal Go identifiers are deliberately ignored.  The current public
    contract is ``cli run`` plus a multi-slot built-in profile; an advertised
    command that fails or emits a malformed usage string is a failure.
    """

    top = ctx.run_cli(["help"])
    if top.returncode != 0:
        raise AssertionError(
            f"locklark help probe failed (rc={top.returncode}): {top.stderr[-800:]}"
        )
    if "cli run" not in (top.stdout + top.stderr):
        return False
    profiles = cli_profiles(ctx)
    if not profiles:
        return False
    run_help = ctx.run_cli(["cli", "run", "--help"])
    if run_help.returncode != 0:
        raise AssertionError(
            f"advertised `cli run --help` failed (rc={run_help.returncode}): "
            f"{run_help.stderr[-800:]}"
        )
    usage = run_help.stdout + run_help.stderr
    required = (
        "locklark cli run <tool>",
        "--binding PATH",
        "--cwd ABS_DIR",
        "--timeout SECONDS",
        "-- [ARG...]",
    )
    missing = [token for token in required if token not in usage]
    if missing:
        raise AssertionError(f"cli run help is missing public options: {missing}")
    return any(
        len(entry["slots"]) > 1
        and any(not slot.get("optional", False) for slot in entry["slots"])
        for entry in profiles
    )


def shell_function_body(script: str, tool: str) -> str:
    """Return a POSIX shell function body declared for *tool*, or ""."""

    patterns = (
        rf"(?ms)^{re.escape(tool)}\s*\(\)\s*\{{(.*?)^\}}",
        rf"(?ms)^function\s+{re.escape(tool)}\b[^\n]*\{{(.*?)^\}}",
    )
    for pattern in patterns:
        match = re.search(pattern, script)
        if match:
            return match.group(1)
    return ""


def f16_cli_shell_ready(ctx: E2EContext) -> bool:
    """Probe shell-init for a real function that forwards to ``cli run``."""

    top = ctx.run_cli(["help"])
    if top.returncode != 0:
        raise AssertionError(
            f"locklark help probe failed (rc={top.returncode}): {top.stderr[-800:]}"
        )
    if "cli shell-init" not in (top.stdout + top.stderr):
        return False
    result = ctx.run_cli(["cli", "shell-init", "bash"])
    if result.returncode != 0:
        raise AssertionError(
            f"advertised `cli shell-init bash` failed (rc={result.returncode}): "
            f"{result.stderr[-800:]}"
        )
    body = shell_function_body(result.stdout, "gh")
    if not body:
        raise AssertionError("cli shell-init did not emit a gh function")
    if not re.search(r"\bcli\s+run\s+gh\b", body):
        raise AssertionError(f"gh wrapper does not call cli run: {body!r}")
    if not re.search(r"(?:command|&)\s+\S*locklark\b", body):
        raise AssertionError(f"gh wrapper does not invoke a locklark executable: {body!r}")
    if '"$@"' not in body:
        raise AssertionError(f"gh wrapper does not forward arguments: {body!r}")
    return True


def desktop_broker_implemented(ctx: E2EContext) -> bool:
    source = source_text(ctx, "internal/desktop/ipc_broker.go")
    return "startBrowserBroker" in source and "handleCLIRun" in source


def cli_broker_client_implemented(ctx: E2EContext) -> bool:
    return sources_contain(ctx, "cmd/locklark/*.go", "RequestCLIRun") or sources_contain(
        ctx, "cmd/locklark/*.go", "BrokerCLI"
    )


def f17_broker_ready(ctx: E2EContext) -> bool:
    """F17 needs both the desktop broker and a CLI-side client path."""

    return (
        f14_cli_profiles_ready(ctx)
        and desktop_broker_implemented(ctx)
        and cli_broker_client_implemented(ctx)
    )


# ---------------------------------------------------------------------------
# Desktop / repository checks used by full assertions
# ---------------------------------------------------------------------------


def desktop_runtime_available(ctx: E2EContext) -> bool:
    """Whether this checkout can launch the desktop under Xvfb."""

    return shutil.which("xvfb-run") is not None


def desktop_binary_starts(ctx: E2EContext, vault: Path, seconds: float = 2.0) -> bool:
    xvfb = shutil.which("xvfb-run")
    if xvfb is None:
        return False
    env = dict(os.environ)
    env["TMPDIR"] = str(ctx.temp_dir)
    command = [
        xvfb,
        "-a",
        "-s",
        "-screen 0 1280x900x24",
        str(ctx.desktop_bin),
        "--file",
        str(vault),
    ]
    process = subprocess.Popen(
        command,
        cwd=str(ctx.temp_dir),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # xvfb-run, the GUI and any broker child share a private session so a
        # bounded SIGTERM/SIGKILL of the group reaps all of them; terminating
        # only the wrapper used to leave the desktop (and its broker socket)
        # alive for later tests on slower/remote runners.
        start_new_session=True,
    )
    try:
        time.sleep(seconds)
        return process.poll() is None
    finally:
        terminate_process_group(process, grace=3.0, owned_group=process.pid)


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checklist_rows(text: str) -> list[list[str]]:
    """Parse simple markdown table rows (header separators excluded)."""

    rows: list[list[str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or all(set(cell) <= set("-: ") for cell in cells):
            continue
        rows.append(cells)
    return rows


def evidence_paths(cell: str) -> list[str]:
    return re.findall(r"(?:scripts|browser-extension/test|tests/e2e)/[A-Za-z0-9_./-]+", cell)


# ---------------------------------------------------------------------------
# Local-network trap used by the Watchtower privacy tests
# ---------------------------------------------------------------------------


class TrapListener:
    """A loopback TCP listener that records whether anything connected."""

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(0.05)
        self.connections = 0
        self.port = self.socket.getsockname()[1]

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}/range/"

    def poll(self, seconds: float) -> int:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            connection.close()
        return self.connections

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass

    def __enter__(self) -> "TrapListener":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.close()
        return False


__all__ = [
    "HEX32_RE",
    "F14_REQUIRED_PROFILES",
    "HEX32_RE",
    "HEX64_RE",
    "PARITY_STATUSES",
    "TrapListener",
    "add_login",
    "assert_audit_chain",
    "assert_private",
    "audit_events",
    "built_extension",
    "checklist_rows",
    "cli_broker_client_implemented",
    "cli_command",
    "cli_help",
    "cli_profiles",
    "cli_supports",
    "command_known",
    "desktop_binary_starts",
    "desktop_runtime_available",
    "desktop_broker_implemented",
    "desktop_sources",
    "edit_url",
    "evidence_paths",
    "extension_asset",
    "extension_text",
    "f1_passkey_ready",
    "f1_autosubmit_ready",
    "f2_inline_ready",
    "f2_autologin_ready",
    "f3_team_sync_ready",
    "f4_team_cli_ready",
    "f5_desktop_timer_ready",
    "f5_filter_refresh_ready",
    "f7_shared_ipc_ready",
    "f8_desktop_v2_ready",
    "f8_v2_editor_ready",
    "f9_save_generator_ready",
    "f10_popup_vault_ready",
    "f11_identity_ready",
    "f11_fill_contract_ready",
    "f12_parity_doc",
    "f13_watchtower_ready",
    "f13_cli_health_flags",
    "f13_hibp_client_ready",
    "f14_cli_profiles_ready",
    "f15_run_bundle_ready",
    "f16_cli_shell_ready",
    "f17_broker_ready",
    "extension_or_source_text",
    "go_package_test",
    "go_tool",
    "node_test_pattern",
    "file_mode",
    "flags_by_id",
    "gate",
    "health_report",
    "init_vault",
    "list_rows",
    "login_1pux_item",
    "make_script",
    "make_vault",
    "match_logins",
    "multi_category_1pux",
    "native_error_frame",
    "native_has_credential",
    "native_probe",
    "node_eval",
    "node_test",
    "pty",
    "require_hex32",
    "require_hex64",
    "reveal_login",
    "sha256_file",
    "shell_function_body",
    "simple_1pux",
    "source_files",
    "source_text",
    "sources_contain",
    "write_1pux",
]
