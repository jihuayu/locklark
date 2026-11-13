"""Shared opaque-box helpers for the M5 four-tier E2E suite.

Everything in this module talks to the product through the same user-facing
surfaces the harness exposes: compiled binaries, native-messaging frames,
built extension bundles, and repository files.  It never imports a Locklark Go
package or inspects private in-memory state.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import select
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .harness import (
    CLIResult,
    E2EContext,
    FeatureNotImplementedError,
    PTYResult,
    owned_gui_command,
    terminate_process_group,
)

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


def write_typed_item(
    ctx: E2EContext, name: str, document: dict[str, Any]
) -> Path:
    """Write an owner-only ``0600`` typed add-item document under the fixture root."""

    path = ctx.temp_dir / name
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)
    if file_mode(path) != 0o600:
        raise AssertionError(f"typed input is not owner-only: mode {file_mode(path):o}")
    return path


def add_item(
    ctx: E2EContext,
    vault: dict[str, Any],
    document: dict[str, Any],
    *,
    name: str = "item.json",
    confirm: str = "SAVE",
) -> dict[str, Any]:
    """Create one typed item through the real PTY ``personal add-item`` flow."""

    path = write_typed_item(ctx, name, document)
    result = pty(
        ctx,
        [
            "personal",
            "add-item",
            "--file",
            str(vault["path"]),
            "--input",
            str(path),
        ],
        password=vault["password"],
        secret=vault["secret"],
        extra=[("输入 SAVE 确认新增条目", confirm)],
    )
    if result.returncode != 0:
        raise AssertionError(
            f"personal add-item failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    payload = result.json()
    require_hex32(payload.get("id", ""))
    require_hex64(payload.get("revision", ""))
    vault["items"].append(
        {
            "id": payload["id"],
            "revision": payload["revision"],
            "title": document.get("title"),
        }
    )
    return payload


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


ITEM_METADATA_FIELDS = frozenset(
    {
        "id",
        "revision",
        "category",
        "tags",
        "favorite",
        "urls",
        "section_ids",
        "section_field_counts",
        "attachments",
        "attachment_read_verified",
        "attachment_reads",
        "ssh_pair_matches",
    }
)

ITEM_METADATA_URL_FIELDS = frozenset({"label", "url", "primary", "match_mode"})

# Attachment projections carry public metadata only; a verified read carries
# just the digest and byte count of the decrypted body.
ITEM_METADATA_ATTACHMENT_FIELDS = frozenset(
    {"id", "file_name", "mime_type", "size", "sha256"}
)

ITEM_METADATA_READ_FIELDS = frozenset({"sha256", "bytes"})


def _item_metadata_bin(ctx: E2EContext) -> Path:
    """Compile the private metadata probe once per test context.

    The helper lives under the repository so it may import ``internal/``; it is
    built into this context's own private bin directory (removed with the
    temporary root) and is never installed, shipped or exposed as a product
    command.
    """

    cached = getattr(ctx, "_item_metadata_bin", None)
    if cached is not None and Path(cached).is_file():
        return Path(cached)
    go = go_tool()
    if go is None:
        raise AssertionError(
            "validation blocked: go toolchain unavailable; metadata probe not built"
        )
    bin_dir = ctx.temp_dir / "probe-bin"
    bin_dir.mkdir(mode=0o700, exist_ok=True)
    binary = bin_dir / "item-metadata"
    build = ctx.run_cli(
        ["build", "-o", str(binary), "./tests/e2e/helpers"],
        binary=go,
        cwd=ctx.repo_root,
        timeout=180.0,
    )
    if build.returncode != 0 or not binary.is_file():
        raise AssertionError(
            "metadata probe build failed (rc=%d): %s"
            % (build.returncode, (build.stderr or build.stdout)[-1200:])
        )
    binary.chmod(0o700)
    ctx._item_metadata_bin = binary
    return binary


def _check_metadata_payload(payload: Any) -> dict[str, Any]:
    """Accept only the safe projection and refuse anything else."""

    if not isinstance(payload, dict):
        raise AssertionError(f"metadata probe did not return an object: {payload!r}")
    extra = set(payload) - ITEM_METADATA_FIELDS
    if extra:
        raise AssertionError(f"metadata probe leaked unexpected fields: {sorted(extra)}")
    missing = ITEM_METADATA_FIELDS - set(payload)
    if missing:
        raise AssertionError(f"metadata probe is missing fields: {sorted(missing)}")
    require_hex32(payload["id"])
    require_hex64(payload["revision"])
    if not isinstance(payload["category"], str) or not payload["category"]:
        raise AssertionError(f"metadata probe category is not a string: {payload!r}")
    if not isinstance(payload["favorite"], bool):
        raise AssertionError(f"metadata probe favorite is not a bool: {payload!r}")
    if not isinstance(payload["tags"], list) or not all(
        isinstance(tag, str) for tag in payload["tags"]
    ):
        raise AssertionError(f"metadata probe tags are not strings: {payload!r}")
    if not isinstance(payload["urls"], list):
        raise AssertionError(f"metadata probe urls are not a list: {payload!r}")
    for entry in payload["urls"]:
        if not isinstance(entry, dict) or set(entry) - ITEM_METADATA_URL_FIELDS:
            raise AssertionError(f"metadata probe url entry is not safe: {entry!r}")
        if not isinstance(entry.get("url"), str):
            raise AssertionError(f"metadata probe url is not a string: {entry!r}")
    if not isinstance(payload["section_ids"], list) or not all(
        isinstance(section, str) for section in payload["section_ids"]
    ):
        raise AssertionError(f"metadata probe section ids are not strings: {payload!r}")
    counts = payload["section_field_counts"]
    if not isinstance(counts, dict) or not all(
        isinstance(key, str) and isinstance(value, int) for key, value in counts.items()
    ):
        raise AssertionError(f"metadata probe field counts are invalid: {payload!r}")
    attachments = payload["attachments"]
    if not isinstance(attachments, list):
        raise AssertionError(f"metadata probe attachments are not a list: {payload!r}")
    for entry in attachments:
        if not isinstance(entry, dict) or set(entry) != ITEM_METADATA_ATTACHMENT_FIELDS:
            raise AssertionError(
                f"metadata probe attachment entry is not safe metadata: {entry!r}"
            )
        if not isinstance(entry["id"], str) or not entry["id"]:
            raise AssertionError(f"metadata probe attachment id is invalid: {entry!r}")
        if not isinstance(entry["file_name"], str) or not entry["file_name"]:
            raise AssertionError(f"metadata probe attachment name is invalid: {entry!r}")
        if not isinstance(entry["mime_type"], str):
            raise AssertionError(f"metadata probe attachment mime type is invalid: {entry!r}")
        if not isinstance(entry["size"], int) or isinstance(entry["size"], bool):
            raise AssertionError(f"metadata probe attachment size is invalid: {entry!r}")
        if not HEX64_RE.fullmatch(entry["sha256"] or ""):
            raise AssertionError(f"metadata probe attachment digest is invalid: {entry!r}")
    verified = payload["attachment_read_verified"]
    if not isinstance(verified, bool):
        raise AssertionError(f"metadata probe verified flag is not a bool: {payload!r}")
    if not isinstance(payload["ssh_pair_matches"], bool):
        raise AssertionError(f"metadata probe ssh pair flag is not a bool: {payload!r}")
    reads = payload["attachment_reads"]
    if not isinstance(reads, list):
        raise AssertionError(f"metadata probe attachment reads are not a list: {payload!r}")
    if not verified and reads:
        raise AssertionError(f"metadata probe reported unrequested attachment reads: {payload!r}")
    if verified and len(reads) != len(attachments):
        raise AssertionError(f"metadata probe verified reads do not match attachments: {payload!r}")
    for entry in reads:
        if not isinstance(entry, dict) or set(entry) != ITEM_METADATA_READ_FIELDS:
            raise AssertionError(f"metadata probe attachment read is unsafe: {entry!r}")
        if not HEX64_RE.fullmatch(entry["sha256"] or ""):
            raise AssertionError(f"metadata probe attachment read digest is invalid: {entry!r}")
        if not isinstance(entry["bytes"], int) or isinstance(entry["bytes"], bool):
            raise AssertionError(f"metadata probe attachment read size is invalid: {entry!r}")
    return payload


def item_metadata(
    ctx: E2EContext,
    vault: dict[str, Any],
    row: dict[str, Any],
    *,
    verify_attachments: bool = False,
    verify_ssh_public: bytes | None = None,
) -> dict[str, Any]:
    """Read one item's category/tags/favorite/URLs/section/attachment shape.

    The request travels as bounded JSON on the probe's stdin and the reply is
    restricted to the safe metadata projection; no credential, title, notes,
    attachment body/path or key material crosses the boundary.  With
    ``verify_attachments`` the probe additionally reads each attachment body
    through the native session, hashes the exact bytes and reports only the
    digest and byte count.  The probe binary is built into this context's
    private temp root, so the fixture is cleared with the context.
    """

    binary = _item_metadata_bin(ctx)
    request = {
        "path": str(vault["path"]),
        "password": vault["password"],
        "secret_key": vault["secret"],
        "id": row["id"],
        "revision": row["revision"],
        "verify_attachments": verify_attachments,
        "verify_ssh_public": (
            base64.b64encode(verify_ssh_public).decode("ascii")
            if verify_ssh_public is not None
            else ""
        ),
    }
    proc = subprocess.run(
        [str(binary)],
        input=json.dumps(request).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(ctx.temp_dir),
        timeout=60.0,
    )
    if proc.returncode != 0:
        raise AssertionError(
            "metadata probe failed (rc=%d): %s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace")[-600:])
        )
    try:
        payload = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AssertionError(f"metadata probe returned invalid JSON: {exc}") from exc
    return _check_metadata_payload(payload)


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
        timeout=180,
        # The disclosed JSON is the last terminal write; keep a bounded drain
        # window so a loaded runner does not assert on a truncated transcript.
        drain_after_exit=2.0,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"reveal-login failed (rc={result.returncode}): {result.transcript[-800:]}"
        )
    receipt = result.json()
    if receipt.get("status") != "written-to-terminal":
        raise AssertionError(f"reveal-login did not write to the terminal: {receipt!r}")
    # The disclosed JSON string is written to the terminal, not stdout.
    match = re.search(r'\r?\n("(?:[^"\\]|\\.)*")\s*$', result.transcript)
    if not match:
        raise AssertionError(f"reveal-login did not disclose JSON: {result.transcript[-400:]!r}")
    value = json.loads(match.group(1))
    if value:
        # The receipt and stdout must never carry the disclosed value.
        ctx.assert_no_canary_leak(value, result.stdout, json.dumps(receipt))
    return value, result.transcript


PYKEEPASS_ENV = "LOCKLARK_TEST_PYKEEPASS"

_PYKEEPASS_READER = r"""
import json
import sys
from pykeepass import PyKeePass

request = json.load(sys.stdin)
db = PyKeePass(sys.argv[1], password=request["password"])
print(json.dumps([
    {
        "title": entry.title or "",
        "username": entry.username or "",
        "password": entry.password or "",
        "url": entry.url or "",
        "notes": entry.notes or "",
    }
    for entry in db.entries
], ensure_ascii=False))
"""


def pykeepass_peer() -> str | None:
    """Return an interpreter that can import PyKeePass, if one is installed.

    CI installs ``pykeepass==4.2.0`` into a peer virtualenv and points
    ``LOCKLARK_TEST_PYKEEPASS`` at it.  The current interpreter is probed as a
    local fallback; when neither works the export content cannot be read
    independently and the caller must report a blocked assertion, never pass.
    """

    configured = os.environ.get(PYKEEPASS_ENV)
    candidates = [configured, sys.executable]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import pykeepass"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:
            return candidate
    return None


def read_kdbx_entries(
    path: Path,
    password: str,
    *,
    peer: str | None = None,
) -> list[dict[str, str]]:
    """Read an exported KDBX with PyKeePass, independently of the product.

    The export password travels over stdin, never argv.  Only the projection
    used for content assertions is returned; no vault credential is read.
    """

    interpreter = peer or pykeepass_peer()
    if interpreter is None:
        raise AssertionError(
            "validation blocked: an independent PyKeePass reader is unavailable; "
            f"install pykeepass==4.2.0 or point {PYKEEPASS_ENV} at a peer interpreter"
        )
    proc = subprocess.run(
        [interpreter, "-c", _PYKEEPASS_READER, str(path)],
        input=json.dumps({"password": password}).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    if proc.returncode != 0:
        raise AssertionError(
            "PyKeePass could not open the exported KDBX (rc=%d): %s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace")[-600:])
        )
    try:
        entries = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AssertionError(f"PyKeePass returned invalid JSON: {exc}") from exc
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict)
        and set(entry) == {"title", "username", "password", "url", "notes"}
        and all(isinstance(value, str) for value in entry.values())
        for entry in entries
    ):
        raise AssertionError(f"PyKeePass returned an unexpected projection: {entries!r}")
    return entries


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


def typed_field(field_id: str, title: str, value: Any) -> dict[str, Any]:
    """One 1PUX v3 field: only ``id``/``title``/``value``.

    ``value`` is a typed object such as ``{"concealed": ...}`` or
    ``{"string": ...}``; the legacy ``designation``/``type``/``value`` spelling
    is not part of the v3 schema and is refused by the real importer.
    """

    return {"id": field_id, "title": title, "value": value}


def typed_section(name: str, title: str, *fields: dict[str, Any]) -> dict[str, Any]:
    """One 1PUX v3 section: only ``name``/``title``/``fields``."""

    return {"name": name, "title": title, "fields": list(fields)}


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
    """A real 1PUX v3 archive with four categories and rich metadata.

    It only carries the v3 shape the importer documents: tags live on
    ``overview``, sections are ``{name,title,fields}`` and every field is
    ``{id,title,value:{string|concealed|...}}``.
    """

    login = login_1pux_item(
        "Corp SSO", "https://sso.corp.example.test/login", "alice", "P@ssw0rd-2026"
    )
    login["overview"]["urls"] = [
        {"label": "primary", "url": "https://sso.corp.example.test/login"},
        {"label": "portal", "url": "https://portal.corp.example.test/auth"},
    ]
    login["overview"]["tags"] = ["imported", "sso"]
    login["details"]["sections"] = [
        typed_section(
            "recovery",
            "Recovery",
            typed_field(
                "recovery_code",
                "Recovery Code",
                {"concealed": "CANARY-1PUX-RECOVERY-9912"},
            ),
        )
    ]
    login["favIndex"] = 1
    note = {
        "uuid": "secure-note-1",
        "categoryUuid": "003",
        "state": "active",
        "overview": {"title": "Runbook"},
        "details": {
            "sections": [
                typed_section(
                    "notes",
                    "Notes",
                    typed_field("body", "Body", {"string": "restart the service"}),
                )
            ]
        },
    }
    identity = {
        "uuid": "identity-1",
        "categoryUuid": "004",
        "state": "active",
        "overview": {"title": "Ada Lovelace"},
        "details": {
            "sections": [
                typed_section(
                    "identity",
                    "Personal",
                    typed_field("firstname", "First", {"string": "Ada"}),
                    typed_field("lastname", "Last", {"string": "Lovelace"}),
                )
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
                typed_section(
                    "card",
                    "Card",
                    typed_field(
                        "cardholder", "Cardholder", {"string": "Ada Lovelace"}
                    ),
                    typed_field(
                        "ccnum", "Number", {"creditCardNumber": "4111222233334444"}
                    ),
                    typed_field("cvv", "CVV", {"concealed": "842"}),
                    typed_field("expiry", "Expiry", {"monthYear": 203001}),
                )
            ]
        },
    }
    return write_1pux(ctx.temp_dir / "multi-category.1pux", [login, note, identity, card])


def legacy_rich_1pux(ctx: E2EContext) -> Path:
    """The pre-v3 shape (root ``tags`` and legacy section fields).

    This is a negative fixture only: both import profiles must keep refusing it
    wholesale, so the production parser is never relaxed to accept it.
    """

    login = login_1pux_item(
        "Legacy Rich", "https://legacy.corp.example.test/login", "alice", "legacy-secret-2026"
    )
    login["tags"] = ["imported"]
    login["details"]["sections"] = [
        {
            "title": "Recovery",
            "fields": [
                {
                    "designation": "recovery_code",
                    "type": "C",
                    "value": "CANARY-LEGACY-1PUX-3311",
                }
            ],
        }
    ]
    return write_1pux(ctx.temp_dir / "legacy-rich.1pux", [login])


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


def cli_help(ctx: E2EContext, args: Sequence[Any] = ("help",)) -> str:
    """Run the real CLI help surface (``locklark help`` by default)."""

    result = ctx.run_cli(list(args))
    if result.returncode != 0:
        raise AssertionError(
            f"locklark {' '.join(str(arg) for arg in args)} failed "
            f"(rc={result.returncode}): {result.stderr}"
        )
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
    """Return a *working* go toolchain, verifying it answers ``go version``.

    A stale or shadowed ``go`` on PATH that cannot run subcommands must not be
    accepted: the previous check returned the first executable named ``go`` and
    every build/test probe then failed with a toolchain error that looked like a
    product failure.
    """

    candidates = [
        shutil.which("go") or "",
        os.environ.get("LOCKLARK_GO", ""),
        "/workspace/toolchains/go/bin/go",
    ]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        if not os.access(candidate, os.X_OK):
            continue
        try:
            probe = subprocess.run(
                [candidate, "version"], capture_output=True, text=True, timeout=20
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and "go version" in (probe.stdout or ""):
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


def f2_passkey_management_ready(ctx: E2EContext) -> bool:
    """Both sides of the shipped management protocol must exist before testing it."""
    return (
        "passkey-management-v1" in extension_or_source_text(ctx, "core.js")
        and "passkey-management-v1" in source_text(ctx, "internal/browserhost/types_v2.go")
        and '"passkey-remove"' in source_text(ctx, "internal/browserhost/protocol.go")
    )


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
    """Opt-in HIBP surface on ``personal health`` (a separate CLI surface).

    The landed contract is the strict literal pair ``--hibp true`` (``--hibp
    false``, ``--check-breached`` and ``--hibp-endpoint`` are all refused).
    This only looks for the advertised option; whether the opted-in run really
    reaches the range client is decided by :func:`f13_cli_hibp_opt_in`
    against the real binary.
    """

    # Read every help surface and match the literal option pair.  `personal
    # help` and `personal health --help` are read as text without requiring
    # exit 0: this probe only locates the advertised pair, while behaviour is
    # asserted by :func:`f13_cli_hibp_opt_in` on the real binary.
    help_text = [cli_help(ctx)]
    for surface in (
        ["personal", "help"],
        ["personal", "health", "--help"],
        ["personal", "health"],
    ):
        result = ctx.run_cli(surface)
        help_text.append(result.stdout + "\n" + result.stderr)
    return any("--hibp true" in chunk for chunk in help_text)


def f13_cli_hibp_opt_in(ctx: E2EContext, vault: dict[str, Any]) -> dict[str, Any]:
    """Exercise the real ``personal health --hibp true`` opt-in contract.

    Everything happens on the synthetic vault through the compiled CLI and the
    hidden NETWORK consent; no endpoint is contacted.  A declined consent is a
    real failure (never a clean result), so the strict checks raise here:

    - the CLI exits non-zero and the terminal shows the fixed cancellation
      error verbatim, with no stdio receipt;
    - the audit chain gains no event at all, i.e. no unlock and no
      ``vault.health.hibp`` intent.

    Returns the option-surface observations for the caller:

    - ``flags``: ``--hibp true`` is advertised by the ``personal`` help
      surfaces;
    - ``bad_pair_refused``: free-form spellings (``--hibp false``,
      ``--hibp endpoint``) are rejected with the fixed usage refusal;
    - ``audit_delta``: audit actions appended across the refusal, excluding the
      observation's own ``audit.list`` disclosure event (always empty here,
      re-checked even on a failure path).
    """

    path = str(vault["path"])
    flags = f13_cli_health_flags(ctx)
    bad_pairs = [
        ctx.run_cli(["personal", "health", "--file", path, "--hibp", value])
        for value in ("false", "endpoint")
    ]
    before = audit_events(ctx, vault)
    # Interactive commands default to a 20s PTY timeout; a full vault unlock on
    # a slower machine must not turn a real refusal into a timeout error.
    declined = pty(
        ctx,
        ["personal", "health", "--file", path, "--hibp", "true"],
        password=vault["password"],
        secret=vault["secret"],
        extra=[(HIBP_NETWORK_PROMPT, "DECLINE")],
        timeout=180,
    )
    after = audit_events(ctx, vault)
    # ``personal audit`` appends one ``audit.list`` disclosure event of its own.
    # Drop only that observation noise so the delta still proves the declined
    # run wrote no unlock, no local health report and no HIBP intent.
    delta = [
        event.get("action")
        for event in after[len(before) :]
        if event.get("action") != "audit.list"
    ]
    # The fixed refusal is what the cancellation error maps to on the CLI
    # (cmd/locklark prints it as its error line); an accepted decline would
    # instead finish rc=0 with a JSON receipt.
    cancelled_error = "HIBP network check cancelled"
    observations = {
        "flags": flags,
        "bad_pair_refused": all(
            result.returncode != 0
            and "usage: locklark personal" in result.stderr
            for result in bad_pairs
        ),
        "declined_rc": declined.returncode,
        "declined_error": (
            cancelled_error
            if cancelled_error in declined.stdout + declined.transcript
            else "missing"
        ),
        "audit_delta": delta,
    }
    ctx.require_feature(
        "F13",
        declined.returncode != 0
        and cancelled_error in declined.stdout + declined.transcript
        and not declined.stdout.strip(),
        "FEATURE_NOT_YET_LANDED: F13 - a declined NETWORK consent did not stop "
        "with the fixed cancellation error before any network access "
        f"(rc={declined.returncode}, stdout={declined.stdout[:120]!r})",
    )
    assert delta == [], (
        "a declined NETWORK consent wrote audit events (no unlock / no "
        f"vault.health.hibp intent allowed): {delta}"
    )
    return observations


# The hidden consent prompt emitted by ``personal health --hibp true`` before
# any unlock or network access (cmd/locklark/personal_health_hibp.go).
HIBP_NETWORK_PROMPT = "输入 NETWORK 确认联网查询泄露前缀"


HIBP_RANGE_SEGMENT = "/range/"
HIBP_FIXED_HOST = "api.pwnedpasswords.com"
HIBP_HTTPS_PORT = 443
HIBP_PREFIX_RE = re.compile(r"^[0-9A-F]{5}$")


def local_hibp_range_proxy(
    ctx: E2EContext,
    responses: Mapping[str, Sequence[tuple[str, int]]],
) -> "LocalHIBPRangeProxy":
    """Start a loopback HTTPS CONNECT proxy in front of a local range server.

    The shipped HIBP client is built with an empty ``http.Client`` (nil
    ``Transport``), so its requests use Go's default transport and honour
    ``HTTPS_PROXY`` through ``ProxyFromEnvironment``.  The product endpoint
    stays the fixed ``https://api.pwnedpasswords.com/range/`` and there is no
    endpoint/proxy/client override; this proxy is reached only because a
    child process with a private environment supplies ``HTTPS_PROXY``.  It
    accepts exactly that one CONNECT target, ``api.pwnedpasswords.com:443``,
    and relays it to a local TLS server with a throwaway certificate for that
    hostname (installed as the child's only trust anchor through
    ``SSL_CERT_FILE``/``SSL_CERT_DIR``).  Every other target is refused;
    system DNS and hosts files are untouched and nothing listens on port 443.

    ``responses`` maps each expected five-hex prefix to its own independent
    ``(suffix, count)`` lines.  The caller owns the synthetic passwords, so it
    can supply the one suffix that really belongs to each prefix; the SUT only
    ever sends the prefix.  A zero-count padding line is appended to every
    response, exactly like the real provider.
    """

    return LocalHIBPRangeProxy(ctx, responses)


def _normalise_hibp_responses(
    responses: Mapping[str, Sequence[tuple[str, int]]],
) -> dict[str, tuple[tuple[str, int], ...]]:
    """Validate the synthetic per-prefix range answers before serving them."""

    normalised: dict[str, tuple[tuple[str, int], ...]] = {}
    for raw_prefix, raw_lines in responses.items():
        prefix = str(raw_prefix).upper()
        if not HIBP_PREFIX_RE.fullmatch(prefix):
            raise AssertionError(f"synthetic HIBP prefix is not five hex: {raw_prefix!r}")
        if prefix in normalised:
            raise AssertionError(f"duplicate synthetic HIBP prefix: {prefix}")
        lines: list[tuple[str, int]] = []
        for raw_suffix, raw_count in raw_lines:
            suffix = str(raw_suffix).upper()
            if not re.fullmatch(r"[0-9A-F]{35}", suffix):
                raise AssertionError(
                    f"synthetic HIBP suffix is not 35 hex: {raw_suffix!r}"
                )
            if not isinstance(raw_count, int) or isinstance(raw_count, bool) or raw_count <= 0:
                raise AssertionError(f"synthetic HIBP count is not positive: {raw_count!r}")
            lines.append((suffix, raw_count))
        normalised[prefix] = tuple(lines)
    return normalised


class LocalHIBPRangeProxy:
    """Loopback CONNECT proxy with a mock range server behind it.

    Each requested five-hex prefix receives only the lines the caller supplied
    for that prefix (plus zero-count padding).  The answers are therefore
    independent: the test asserts what each prefix received and that the SUT
    matched its own full-hash suffix rather than a shared canned response.
    """

    def __init__(
        self,
        ctx: E2EContext,
        responses: Mapping[str, Sequence[tuple[str, int]]],
    ) -> None:
        self.responses = _normalise_hibp_responses(responses)
        work = ctx.temp_dir / "hibp-proxy"
        work.mkdir(mode=0o700, exist_ok=True)
        self.cert = work / "range.pem"
        key = work / "range.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                f"/CN={HIBP_FIXED_HOST}",
                "-addext",
                f"subjectAltName=DNS:{HIBP_FIXED_HOST}",
                "-keyout",
                str(key),
                "-out",
                str(self.cert),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        os.chmod(key, 0o600)
        os.chmod(self.cert, 0o600)
        self._trust = work / "trust"
        self._trust.mkdir(mode=0o700, exist_ok=True)

        self.requests: list[dict[str, Any]] = []
        self.refused: list[str] = []
        self.connections: list[str] = []

        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_CONNECT(self) -> None:  # noqa: N802 - http.server API
                target = self.path or ""
                proxy.connections.append(target)
                if target != f"{HIBP_FIXED_HOST}:{HIBP_HTTPS_PORT}":
                    proxy.refused.append(target)
                    self.send_error(403, "refused target")
                    return
                # The only upstream is the local range server; no DNS lookup
                # and no other destination is ever opened.
                upstream = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                try:
                    self.send_response(200, "Connection Established")
                    self.end_headers()
                    self._relay(self.connection, upstream)
                finally:
                    for stream in (upstream, self.connection):
                        try:
                            stream.close()
                        except OSError:
                            pass
                    self.close_connection = True

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                proxy.refused.append(self.path or "")
                self.send_error(403, "refused")

            def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
                # Forward bytes both ways.  A TLS close_notify is relayed as a
                # half-close so the peer still sees the EOF, while the other
                # direction keeps draining until it ends too.
                sockets = [client, upstream]

                def peer(stream: socket.socket) -> socket.socket:
                    return upstream if stream is client else client

                try:
                    while sockets:
                        ready, _, _ = select.select(sockets, [], [], 15)
                        if not ready:
                            return
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                sockets.remove(source)
                                try:
                                    peer(source).shutdown(socket.SHUT_WR)
                                except OSError:
                                    return
                                continue
                            peer(source).sendall(data)
                except OSError:
                    return

            def log_message(self, *_: Any) -> None:
                return

        class RangeHandler(BaseHTTPRequestHandler):
            # HTTP/1.1 with an explicit length; the answer stays plain text
            # even when the client advertises gzip (which it does by default).
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                record: dict[str, Any] = {
                    "path": self.path,
                    "headers": dict(self.headers),
                }
                proxy.requests.append(record)
                prefix = (
                    self.path[len(HIBP_RANGE_SEGMENT) :]
                    if self.path.startswith(HIBP_RANGE_SEGMENT)
                    else ""
                )
                record["prefix"] = prefix
                if not HIBP_PREFIX_RE.fullmatch(prefix):
                    # Never answer an unexpected path: it would prove that
                    # something other than a five-hex prefix left the process.
                    record["refused"] = True
                    self.send_response(400)
                    self.end_headers()
                    self.close_connection = True
                    return
                lines = proxy.responses.get(prefix)
                record["unknown_prefix"] = lines is None
                lines = lines or ()
                record["suffixes"] = [
                    {"suffix": suffix, "count": count} for suffix, count in lines
                ]
                body = "".join(
                    f"{suffix}:{count}\r\n" for suffix, count in lines
                ) + "0" * 35 + ":0\r\n"
                record["body"] = body
                payload = body.encode("ascii")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()
                self.close_connection = True

            def log_message(self, *_: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), RangeHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.cert), str(key))
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()
        self.port = self._server.server_address[1]

        self._proxy = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._proxy_thread = threading.Thread(target=self._proxy.serve_forever, daemon=True)
        self._proxy_thread.start()
        self.proxy_port = self._proxy.server_address[1]

    @property
    def env(self) -> dict[str, str]:
        """Private child environment: loopback proxy + synthetic trust only."""

        proxy = f"http://127.0.0.1:{self.proxy_port}"
        return {
            "HTTPS_PROXY": proxy,
            "https_proxy": proxy,
            "NO_PROXY": "",
            "no_proxy": "",
            "SSL_CERT_FILE": str(self.cert),
            "SSL_CERT_DIR": str(self._trust),
        }

    def close(self) -> None:
        for server, thread in (
            (self._proxy, self._proxy_thread),
            (self._server, self._server_thread),
        ):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def f13_cli_hibp_range_lookups(
    ctx: E2EContext,
    vault: dict[str, Any],
    responses: Mapping[str, Sequence[tuple[str, int]]],
) -> dict[str, Any]:
    """Run one consented ``--hibp true`` check routed to the local mock.

    ``responses`` maps the five-hex SHA-1 prefixes the test expects the CLI to
    derive from the synthetic passwords to that prefix's own answer lines.
    Outcomes:

    - ``"ran"``: the proxy accepted the CLI's CONNECT.  This only establishes
      the route; the caller still asserts requests, range bodies, payload and
      audit.  A TLS handshake failure after CONNECT returns ``"ran"`` with no
      requests and usually a non-zero CLI result, so the caller hard-fails.
      It is never downgraded to pending and never treated as green;
    - ``"pending"``: no CONNECT ever arrived (local proxy/CA startup failed,
      or the CLI never used the proxy), so nothing was validated.  This is a
      PENDING_FEATURE outcome, never PASS.
    """

    try:
        proxy = local_hibp_range_proxy(ctx, responses)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "pending", "reason": f"local proxy/CA unavailable: {exc}"}
    try:
        result = ctx.run_pty_cli(
            ["personal", "health", "--file", str(vault["path"]), "--hibp", "true"],
            prompts=[
                ("主密码", vault["password"]),
                ("Secret Key", vault["secret"]),
                (HIBP_NETWORK_PROMPT, "NETWORK"),
            ],
            env=proxy.env,
            timeout=180,
        )
        connections = list(proxy.connections)
        requests = list(proxy.requests)
        refused = list(proxy.refused)
    finally:
        proxy.close()
    if not connections:
        return {
            "status": "pending",
            "reason": "the CLI never reached the loopback proxy (route not established)",
            "connections": connections,
            "requests": requests,
            "refused": refused,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "transcript": result.transcript,
        }
    payload: Any = None
    if result.returncode == 0:
        try:
            payload = result.json()
        except ValueError as exc:
            raise AssertionError(f"personal health --hibp true printed invalid JSON: {exc}")
    return {
        "status": "ran",
        "returncode": result.returncode,
        "payload": payload,
        "expected_prefixes": set(proxy.responses),
        "connections": connections,
        "requests": requests,
        "refused": refused,
        "stdout": result.stdout,
        "transcript": result.transcript,
    }


def card_fill_explicit_authorization_component(
    ctx: E2EContext, core_path: Path | None = None
) -> dict[str, Any] | None:
    """Execute the shipped card fill under explicit-authorization inputs.

    T2_F11_05 is a **component contract**, not a page-load wiring test.  The
    shipped artifact has two layers: ``content.js`` runs on HTTPS pages and
    decides when to inject the sandboxed fill, while ``core.fillCardDocument``
    is the function that may write only for a short-lived explicit
    ``(expectedOrigin, expiresAt, category)`` intent.

    This runs the *built* bundle's ``core.js`` in a W3C-shaped synthetic
    checkout page (one card form, no extension runtime) and calls the
    component directly.  It does not exercise ``content.js``/background
    injection, a real browser gesture, or native approval.  It reports that
    no values exist before authorization, that expired/stale intents, a wrong
    origin and a wrong category are refused without touching a control, and
    that one valid intent writes the card controls once.  Returns ``None``
    when no built bundle carries the entrypoint.

    The component's sixth argument is the worker's already-consumed
    ``userAuthorized`` boolean, so the harness passes ``true`` exactly where
    the shipped ``cardSandbox`` adapter would.  This harness receives that
    flag as input; it does not mint or validate the worker's v2 nonce proof
    and does not exercise real gesture/background wiring.  The background
    tests own the v2 one-time proof behavior.  Missing/``false`` auth is
    covered only as a component-level negative control.
    """

    node = shutil.which("node")
    if node is None:
        raise AssertionError("node is required for extension E2E checks")
    candidates = (
        [Path(core_path)]
        if core_path is not None
        else [directory / "core.js" for directory in built_extension(ctx)]
    )
    for candidate in candidates:
        if not candidate.is_file():
            continue
        script = ctx.temp_dir / "card_fill_explicit_authorization.cjs"
        script.write_text(_CARD_FILL_AUTHORIZATION_HARNESS, encoding="utf-8")
        result = ctx.run_cli(
            [str(script), str(candidate)],
            binary=node,
            cwd=ctx.repo_root,
            timeout=120,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"gesture-only card fill harness failed (rc={result.returncode}):\n"
                f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
            )
        return json.loads(result.stdout)
    return None


_CARD_FILL_AUTHORIZATION_HARNESS = r"""
"use strict";
// Synthetic W3C-shaped checkout page: one card form, no extension runtime.
const vm = require("node:vm");
const core = require(process.argv[2]);
const events = [];
class Target {
  constructor() { this.listeners = {}; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatchEvent(event) {
    for (const fn of this.listeners[event.type] || []) fn(event);
    return true;
  }
}
class Element extends Target {
  constructor(tag, attrs) {
    super();
    this.tagName = tag;
    this.attrs = attrs;
    this.isConnected = true;
    this.disabled = false;
    this.readOnly = false;
    this.hidden = false;
    this._value = "";
  }
  getAttribute(name) {
    return Object.hasOwn(this.attrs, name) ? this.attrs[name] : null;
  }
  hasAttribute(name) { return Object.hasOwn(this.attrs, name); }
  matches() { return false; }
  closest() { return null; }
  getRootNode() { return this.ownerDocument; }
  getBoundingClientRect() { return { width: 240, height: 28 }; }
  getClientRects() { return [{}]; }
  focus() {}
  get labels() { return []; }
}
class HtmlInput extends Element {
  constructor(attrs) {
    super("INPUT", attrs);
    this.type = attrs.type || "text";
    this.name = attrs.name || "";
    this.id = attrs.id || "";
    this.placeholder = attrs.placeholder || "";
    this.autocomplete = attrs.autocomplete || "";
    this.maxLength = Number(attrs.maxlength || -1);
  }
}
Object.defineProperty(HtmlInput.prototype, "value", {
  get() { return this._value; },
  set(value) {
    this._value = String(value);
    if (this._touched) events.push(this.id);
  },
});
const form = new Target();
const controls = [
  new HtmlInput({ id: "holder", autocomplete: "cc-name", "aria-label": "Cardholder" }),
  new HtmlInput({ id: "number", autocomplete: "cc-number", type: "tel", placeholder: "1234 5678 9012 3456" }),
  new HtmlInput({ id: "exp", autocomplete: "cc-exp", maxlength: "5", placeholder: "MM/YY" }),
  new HtmlInput({ id: "csc", autocomplete: "cc-csc", "aria-label": "Security code" }),
];
for (const control of controls) control.form = form;
form.querySelectorAll = (selector) =>
  selector === 'input[type="password"]' ? [] : controls.slice();
const documentElement = new Target();
const document = new Target();
Object.assign(document, {
  documentElement,
  baseURI: "https://shop.example.test/pay",
  querySelectorAll: () => controls.slice(),
  querySelector: () => controls[0],
  getElementById: (id) => controls.find((c) => c.id === id) || null,
});
for (const control of controls) control.ownerDocument = document;
const location = {
  origin: "https://shop.example.test",
  protocol: "https:",
  href: "https://shop.example.test/pay",
};
const clock = 1_700_000_000_000;
const context = {
  document, location, Event, URL,
  getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
  CSS: { escape: (value) => String(value) },
  Element, HTMLInputElement: HtmlInput,
  Date: { now: () => clock },
  performance: { timeOrigin: 1, now: () => 50 },
  console: {},
};
context.window = context;
context.top = context;
const fill = vm.runInNewContext(
  "(" + core.fillCardDocument.toString() + ")",
  context,
);
const values = () => controls.map((control) => control.value);
// Record every write from here on.  No document-load event is dispatched:
// this harness calls the fill component directly and proves only the
// explicit-authorization contract, not page-load wiring.
for (const control of controls) control._touched = true;
const data = {
  cardholder_name: "Ada Lovelace",
  number: "4242424242424242",
  exp: "12/29",
  cvv: "123",
};
const beforeAuthorization = values();
const rejected = {};
const afterRejects = {};
// Each scoped negative control carries `true` for the sixth `userAuthorized`
// argument (what the `cardSandbox` adapter passes after the worker consumed a
// gesture), so it must be refused for its named condition alone.  This harness
// only receives that already-consumed flag; it does not mint or validate the
// worker's v2 nonce proof — the background tests own that behavior.
const rejects = {
  missing_auth: () => [location.origin, data, clock + 1500, false, "credit_card"],
  unauthorized: () => [location.origin, data, clock + 1500, false, "credit_card", false],
  expired: () => [location.origin, data, clock - 1, false, "credit_card", true],
  stale_window: () => [location.origin, data, clock + 60000, false, "credit_card", true],
  wrong_origin: () => ["https://evil.example.test", data, clock + 1500, false, "credit_card", true],
  wrong_category: () => [location.origin, data, clock + 1500, false, "identity", true],
};
for (const [name, args] of Object.entries(rejects)) {
  rejected[name] = fill(...args());
  afterRejects[name] = values();
}
const authorized = fill(location.origin, data, clock + 1500, false, "credit_card", true);
process.stdout.write(JSON.stringify({
  beforeAuthorization,
  afterRejects,
  rejects: rejected,
  authorized,
  written: events.slice(),
  afterAuthorization: values(),
}));
"""


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
    if shutil.which("xvfb-run") is None:
        return False
    env = dict(os.environ)
    env["TMPDIR"] = str(ctx.temp_dir)
    # Own a complete Linux GUI session: private D-Bus (unless the caller already
    # supplied a usable bus) plus Xvfb, matching the native acceptance scripts.
    command = owned_gui_command(
        [str(ctx.desktop_bin), "--file", str(vault)], env=env, use_xvfb=True
    )
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


# ---------------------------------------------------------------------------
# Native Chromium checkout journey (F11)
# ---------------------------------------------------------------------------

CHECKOUT_EVIDENCE_SCHEMA = "locklark.e2e.checkout-native"
CHECKOUT_EVIDENCE_VERSION = 1
CHECKOUT_JOURNEY_ID = "chromium-native-checkout"
# Report key attached only when a native journey run exits nonzero.
CHECKOUT_FAILURE_EVIDENCE_KEY = "checkoutNativeFailure"

# Each stable case ID maps to the fixed stage labels the existing native script
# emits for that case.  The script remains the source of truth; this allowlist
# only lets the E2E runner prove that every case actually ran without copying
# any captured output into the report.
CHECKOUT_CASES = (
    (
        "checkout-approve",
        (
            "checkout-approve:blank",
            "checkout-approve:native-review",
            "checkout-approve:approve",
        ),
    ),
    (
        "checkout-deny",
        (
            "checkout-deny:navigation",
            "checkout-deny:native-review",
            "checkout-deny:refuse",
        ),
    ),
    (
        "checkout-cross-site",
        (
            "checkout-cross-site:navigation",
            "checkout-cross-site:picker",
            "checkout-cross-site:refused",
        ),
    ),
    (
        "checkout-sandbox",
        ("checkout-sandbox:navigation", "checkout-sandbox:picker"),
    ),
    (
        "checkout-stale",
        (
            "checkout-stale:navigation",
            "checkout-stale:native-review",
            "checkout-stale:child-navigation",
            "checkout-stale:old-approval",
        ),
    ),
    (
        "checkout-deny-navigation",
        (
            "checkout-deny-navigation:navigation",
            "checkout-deny-navigation:native-review",
            "checkout-deny-navigation:top-navigation",
            "checkout-deny-navigation:status",
        ),
    ),
    (
        "checkout-same-origin",
        (
            "checkout-same-origin:navigation",
            "checkout-same-origin:blank",
            "checkout-same-origin:native-review",
            "checkout-same-origin:approve",
        ),
    ),
    (
        "checkout-picker-cancel",
        (
            "checkout-picker-cancel:navigation",
            "checkout-picker-cancel:programmatic-refused",
            "checkout-picker-cancel:picker",
        ),
    ),
    (
        "checkout-lock-review",
        (
            "checkout-lock-review:navigation",
            "checkout-lock-review:native-review",
            "checkout-lock-review:lock",
            "checkout-lock-review:status",
        ),
    ),
)
CHECKOUT_CASE_IDS = tuple(case_id for case_id, _ in CHECKOUT_CASES)
# The cross-site case has two mutually exclusive outcomes.  Both branch markers
# are allowlisted, but a run executes exactly one of them: the native review
# for a listed cross-site child, or its exclusion from the picker.  Both wait
# for the same `checkout-cross-site:refused` completion, so only that common
# stage may be required by every run.
CHECKOUT_BRANCH_CASE_ID = "checkout-cross-site"
_CHECKOUT_BRANCH_STAGES = {
    "checkout-cross-site": (
        "checkout-cross-site:excluded",
        "checkout-cross-site:native-review",
    ),
}
# A branch marker belongs, as an optional stage, only to the case that owns
# it; evidence never records one case's marker under another case.
CHECKOUT_OPTIONAL_STAGES = tuple(
    stage for markers in _CHECKOUT_BRANCH_STAGES.values() for stage in markers
)
CHECKOUT_REQUIRED_STAGES = tuple(
    stage
    for _, stages in CHECKOUT_CASES
    for stage in stages
    if stage not in CHECKOUT_OPTIONAL_STAGES
)
# Every fixed stage the native script may emit for a case, branch markers
# included.  The parser allowlists these and nothing else.
_CHECKOUT_STAGE_LABELS = CHECKOUT_REQUIRED_STAGES + CHECKOUT_OPTIONAL_STAGES
_CHECKOUT_STAGE_PREFIX = "Native browser stage: "
# The one sanitized line the native script already prints on a failed journey.
# A nonzero checkout run copies only its fixed stage, kind and helper error
# into the report; the rest of the captured output never leaves memory.
_CHECKOUT_DIAGNOSTIC_PREFIX = "Native browser diagnostic: "
_CHECKOUT_DIAGNOSTIC_MAX_BYTES = 64 * 1024
_CHECKOUT_DIAGNOSTIC_MAX_LINE = 8 * 1024
# Opt-in normal-checkout startup markers printed on stdout; only these and the
# fixed stderr wrapper signatures below are matched, never copied.
_CHECKOUT_STARTUP_PREFIX = "Native checkout startup: "
_CHECKOUT_STARTUP_PHASES = (
    "module-ready",
    "state-ready",
    "tls-ready",
    "https-ready",
    "journey-entered",
)
_CHECKOUT_WRAPPER_SIGNATURES = (
    ("dbus", ("Autolaunch error", "Unable to autolaunch", "dbus-launch:")),
    ("xvfb", ("xvfb-run: error:", "xauth:  file", "_XSERVTransmkdir")),
    ("node-loader", ("SyntaxError: Cannot use import statement",
                     "ERR_MODULE_NOT_FOUND", "ERR_REQUIRE_ESM")),
)
# The five journey modules whose basenames the script's own stack-frame regex
# keeps; one frame is "<basename>:line:column", nothing else is ever accepted.
_CHECKOUT_SOURCE_FILES = (
    "browser_native_acceptance.mjs",
    "browser_checkout_acceptance.mjs",
    "browser_passkey_management_acceptance.mjs",
    "browser_conditional_passkey_acceptance.mjs",
    "browser_passkey_acceptance.mjs",
)
_CHECKOUT_SOURCE_FRAMES_MAX = 16
# The picker's fixed bounded public statuses, as the module's enum values. A
# value outside this set rejects the whole record; an absent one keeps the
# existing projection.
CHECKOUT_PICKER_STATUSES = (
    "no-gesture",
    "unavailable",
    "unsupported",
    "list-failed",
    "selected",
    "cancelled",
    "other",
)
_CHECKOUT_SOURCE_FRAME = re.compile(
    r"(" + "|".join(re.escape(name) for name in _CHECKOUT_SOURCE_FILES) + r")"
    r":[0-9]{1,6}:[0-9]{1,5}"
)
_CHECKOUT_FAILED_STAGES = frozenset(_CHECKOUT_STAGE_LABELS) | {
    "approved-fill:approve",
    "driver-arguments-failure",
    "fixture",
    "native-connect",
    "native-disconnect",
    "native-pair",
    "native-reconnect",
    "native-unlock",
    "post-repair:route-attached",
    "post-repair:route-click",
    "post-repair:route-close",
    "post-repair:route-match",
    "post-repair:route-native",
    "post-repair:route-observe",
    "post-repair:route-open",
    "post-repair:route-popup-closed",
    "post-repair:route-refetched",
    "post-repair:route-refused",
    "post-repair:route-reject",
    "save-new:control",
} | {
    f"{case_id}:{step}"
    for case_id in CHECKOUT_CASE_IDS
    for step in ("popup", "native-confirmation")
}
_CHECKOUT_FAILED_CODES = frozenset(
    {
        "a11y-query",
        "a11y-unavailable",
        "chooser-owner",
        "chooser-owner-ambiguous",
        "control-missing",
        "control-ready-timeout",
        "inspection-request",
        "label-not-allowed",
        "shortcut-mapping",
        "unexpected",
        "window-ambiguous",
        "window-close-timeout",
        "window-timeout",
        "window-viewable-timeout",
        "x-input",
        "x-query",
        "x-target",
    }
)
# The native helper's fixed FAILURE_CONTEXT action enum (browser_native_x11.py).
_CHECKOUT_HELPER_ACTIONS = frozenset(
    {
        "chooser-navigate",
        "chooser-open",
        "key",
        "label-click",
        "label-wait",
        "pointer",
        "setup",
        "snapshot",
        "text-entry",
    }
)
CHECKOUT_PASS_SUMMARY = (
    "PASS: real Chromium checkout same-origin child approval (profile review) "
    "and picker cancellation, cross-origin approval/refusal, cross-site, "
    "opaque sandbox, changed-document and top-navigation rejection, and lock "
    "while cross-origin card review is pending"
)

# Relevant source bytes that must still match consumed evidence.  The git
# revision is bound as well when this checkout has one.
CHECKOUT_SOURCE_FILES = (
    "scripts/browser_native_acceptance.mjs",
    "scripts/browser_checkout_acceptance.mjs",
    "scripts/browser_save_acceptance.mjs",
    "scripts/browser_native_x11.py",
    "browser-extension/build.js",
    # Current chromium build inputs (build.js ``files`` plus release version).
    "browser-extension/core.js",
    "browser-extension/content.js",
    "browser-extension/webauthn.js",
    "browser-extension/background.js",
    "browser-extension/popup.html",
    "browser-extension/popup.css",
    "browser-extension/popup.js",
    "browser-extension/options.html",
    "browser-extension/options.css",
    "browser-extension/options.js",
    "browser-extension/release-version.json",
    # Every direct and transitive local ES module imported by the journey.
    "scripts/browser_passkey_acceptance.mjs",
    "scripts/browser_passkey_management_acceptance.mjs",
    "scripts/browser_conditional_passkey_acceptance.mjs",
    "scripts/browser_other_provider_acceptance.mjs",
    "scripts/browser_firefox_passkey_acceptance.mjs",
    "scripts/browser_passkey_signal_acceptance.mjs",
    "scripts/browser_otp_acceptance.mjs",
    "scripts/browser_popup_vault_acceptance.mjs",
    "scripts/browser_popup_completion_acceptance.mjs",
    "scripts/browser_shared_clipboard_acceptance.mjs",
    "scripts/browser_edge_install.mjs",
    "scripts/e2e_runner.py",
    "tests/e2e/harness.py",
    "tests/e2e/support.py",
    "tests/e2e/tier2_f09_f17.py",
)

CHECKOUT_BINARY_ROLES = (
    "chromium_host",
    "browser_register",
    "fixture",
    "chromium",
)
_CHECKOUT_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_CHECKOUT_GIT_REVISION_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
_CHECKOUT_TOOL_VERSIONS = {
    "node": re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$"),
    "playwright": re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$"),
    "chromium": re.compile(r"^(?:Chromium|Chrome) [0-9]+(?:\.[0-9]+){1,3}$"),
}

_CHECKOUT_TIMEOUT = 900.0
_CHECKOUT_EVIDENCE_MAX_BYTES = 1_000_000
_CHECKOUT_JOURNEY_CACHE: dict[tuple[str, str, str, str], dict[str, Any]] = {}


def _checkout_pending(detail: str) -> FeatureNotImplementedError:
    return FeatureNotImplementedError(
        f"[PROGRESSIVE_UNIMPLEMENTED: F11] {detail}"
    )


def _executable_path(path: Path | str | None) -> Path | None:
    if not path:
        return None
    candidate = Path(path)
    try:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    except OSError:
        return None
    return None


def _checkout_source_identity(repo_root: Path) -> dict[str, Any]:
    repo_root = Path(repo_root)
    digest = hashlib.sha256()
    for relative in CHECKOUT_SOURCE_FILES:
        source = repo_root / relative
        try:
            data = source.read_bytes()
        except OSError:
            raise AssertionError(
                "checkout evidence source is unavailable"
            ) from None
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
    revision: str | None = None
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        proc = None
    if proc is not None and proc.returncode == 0:
        value = (proc.stdout or "").strip()
        if _CHECKOUT_GIT_REVISION_RE.fullmatch(value):
            revision = value
    return {"git_revision": revision, "source_sha256": digest.hexdigest()}


def _checkout_playwright_path(ctx: E2EContext) -> Path | None:
    raw = (os.environ.get("LOCKLARK_TEST_PLAYWRIGHT") or "").strip()
    candidates: list[Path] = []
    if raw:
        candidates.append(Path(raw))
    candidates.append(Path(ctx.repo_root) / "web" / "node_modules" / "playwright")
    for candidate in candidates:
        try:
            if candidate.is_dir():
                if (candidate / "package.json").is_file():
                    return candidate.resolve()
            elif candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def _checkout_chromium_executable(playwright: Path | None) -> Path | None:
    explicit = _executable_path(
        os.environ.get("LOCKLARK_TEST_BROWSER_EXECUTABLE")
    )
    if explicit is not None:
        return explicit
    node = shutil.which("node")
    if node is None or playwright is None:
        return None
    script = (
        "const p=require(process.argv[1]);"
        "const e=p.chromium.executablePath();"
        "if(!e)process.exit(2);"
        "process.stdout.write(e);"
    )
    try:
        proc = subprocess.run(
            [node, "-e", script, str(playwright)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    value = (proc.stdout or "").strip()
    if not value or "\n" in value:
        return None
    return _executable_path(value)


def _resolve_checkout_artifacts(ctx: E2EContext) -> dict[str, Any]:
    """Resolve the real host/register/fixture/Chromium binaries for a journey."""

    host = _executable_path(getattr(ctx, "browser_chromium_bin", None))
    register = _executable_path(getattr(ctx, "browser_register_bin", None))
    fixture = _executable_path(
        os.environ.get("LOCKLARK_BROWSER_FIXTURE")
    ) or _executable_path(Path(ctx.bin_dir) / "browser-acceptance-fixture")
    playwright = _checkout_playwright_path(ctx)
    chromium = _checkout_chromium_executable(playwright)
    if host is None:
        raise _checkout_pending(
            "native checkout prerequisites are absent: Chromium native host"
        )
    if register is None:
        raise _checkout_pending(
            "native checkout prerequisites are absent: native host register"
        )
    if fixture is None:
        raise _checkout_pending(
            "native checkout prerequisites are absent: acceptance fixture"
        )
    if chromium is None:
        raise _checkout_pending(
            "native checkout prerequisites are absent: Chromium executable"
        )
    return {
        "chromium_host": host,
        "browser_register": register,
        "fixture": fixture,
        "chromium": chromium,
        "playwright": playwright,
        "node": _executable_path(shutil.which("node")),
    }


def _checkout_artifact_hashes(artifacts: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for role in CHECKOUT_BINARY_ROLES:
        path = _executable_path(artifacts.get(role))
        if path is None:
            raise AssertionError(
                "checkout evidence binary is unavailable"
            ) from None
        hashes[role] = sha256_file(path)
    return hashes


def _checkout_execution_environment(artifacts: dict[str, Any]) -> None:
    if not sys.platform.startswith("linux"):
        raise _checkout_pending(
            "native checkout acceptance requires a Linux X11/dbus runtime"
        )
    for tool in ("dbus-run-session", "xvfb-run", "node", "python3", "openssl"):
        if shutil.which(tool) is None:
            raise _checkout_pending(
                f"native checkout acceptance requires {tool}"
            )
    if artifacts.get("node") is None:
        raise _checkout_pending(
            "native checkout prerequisites are absent: node runtime"
        )
    if artifacts.get("playwright") is None:
        raise _checkout_pending(
            "native checkout prerequisites are absent: Playwright module"
        )


def _checkout_version(
    command: list[str], pattern: re.Pattern[str], env: dict[str, str] | None = None
) -> str | None:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    value = (proc.stdout or "").strip()
    match = pattern.search(value)
    return match.group(0) if match else None


def _checkout_tool_metadata(
    artifacts: dict[str, Any], env: dict[str, str] | None = None
) -> dict[str, str | None]:
    node = artifacts.get("node")
    playwright = artifacts.get("playwright")
    chromium = artifacts.get("chromium")
    node_version = (
        _checkout_version([str(node), "--version"], re.compile(r"^v[0-9.]+$"), env)
        if node is not None
        else None
    )
    playwright_version: str | None = None
    if playwright is not None:
        package = Path(playwright)
        if package.is_file():
            package = package.parent
        try:
            payload = json.loads(
                (package / "package.json").read_text(encoding="utf-8")
            )
            version = payload.get("version")
            if isinstance(version, str) and _CHECKOUT_TOOL_VERSIONS[
                "playwright"
            ].fullmatch(version):
                playwright_version = version
        except (OSError, ValueError, TypeError):
            playwright_version = None
    chromium_version = (
        _checkout_version(
            [str(chromium), "--version"],
            re.compile(r"^(?:Chromium|Chrome) [0-9]+(?:\.[0-9]+){1,3}$"),
            env,
        )
        if chromium is not None
        else None
    )
    return {
        "node": node_version,
        "playwright": playwright_version,
        "chromium": chromium_version,
    }


def _checkout_branch_stage(case_id: str, stages: set[str]) -> str | None:
    """Return the one branch marker observed for ``case_id``, if any.

    The branch markers are mutually exclusive: a case that reports both is
    malformed evidence, never resolved by picking one.
    """

    markers = _CHECKOUT_BRANCH_STAGES.get(case_id, ())
    observed = [stage for stage in markers if stage in stages]
    if len(observed) > 1:
        raise AssertionError("checkout evidence is malformed")
    return observed[0] if observed else None


def _checkout_allowed_stages(case_id: str) -> frozenset[str]:
    """Stages ``case_id`` may record: its own fixed stages and branch markers.

    The allowlist is per case, so one case can never borrow another case's
    stage to satisfy its required set.
    """

    required = next(stages for case, stages in CHECKOUT_CASES if case == case_id)
    return frozenset(required) | frozenset(_CHECKOUT_BRANCH_STAGES.get(case_id, ()))


def _checkout_case_stages(
    case_id: str, observed: set[str] | None = None
) -> list[str]:
    """Stages recorded for one case: its required stages plus its branch.

    Without ``observed`` output the branch is unknown and no marker is
    claimed.  Otherwise only markers seen in that output are included, so
    evidence never names a branch that did not run.
    """

    required = next(stages for case, stages in CHECKOUT_CASES if case == case_id)
    stages = list(required)
    branch = _checkout_branch_stage(case_id, observed or set())
    if branch is not None:
        stages.append(branch)
    return stages


def _checkout_cases_evidence(
    observed_stages: set[str] | None = None,
) -> list[dict[str, Any]]:
    return [
        {"case_id": case_id, "stages": _checkout_case_stages(case_id, observed_stages)}
        for case_id in CHECKOUT_CASE_IDS
    ]


def _checkout_evidence_is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _checkout_evidence_structure(evidence: Any) -> list[dict[str, Any]]:
    """Validate the fixed schema without consulting current binaries/source."""

    if not _checkout_evidence_is_mapping(evidence):
        raise AssertionError("checkout evidence is malformed")
    if set(evidence) != {
        "schema",
        "schema_version",
        "journey",
        "status",
        "cases",
        "source",
        "artifacts",
        "tools",
    }:
        raise AssertionError("checkout evidence is malformed")
    if evidence.get("schema") != CHECKOUT_EVIDENCE_SCHEMA:
        raise AssertionError("checkout evidence is malformed")
    if (
        type(evidence.get("schema_version")) is not int
        or evidence.get("schema_version") != CHECKOUT_EVIDENCE_VERSION
    ):
        raise AssertionError("checkout evidence is malformed")
    if evidence.get("journey") != CHECKOUT_JOURNEY_ID:
        raise AssertionError("checkout evidence is malformed")
    if evidence.get("status") != "PASS":
        raise AssertionError("checkout evidence is not PASS")

    cases = evidence.get("cases")
    if not isinstance(cases, list):
        raise AssertionError("checkout evidence is malformed")
    seen: set[str] = set()
    by_id: dict[str, dict[str, Any]] = {}
    for entry in cases:
        if not isinstance(entry, dict) or set(entry) != {"case_id", "stages"}:
            raise AssertionError("checkout evidence is malformed")
        case_id = entry.get("case_id")
        stages = entry.get("stages")
        if not isinstance(case_id, str) or case_id not in CHECKOUT_CASE_IDS:
            raise AssertionError("checkout evidence is malformed")
        if case_id in seen:
            raise AssertionError("checkout evidence is malformed")
        if not isinstance(stages, list) or not all(
            isinstance(stage, str) for stage in stages
        ):
            raise AssertionError("checkout evidence is malformed")
        seen.add(case_id)
        by_id[case_id] = entry
    if seen != set(CHECKOUT_CASE_IDS):
        raise AssertionError(
            "checkout evidence is missing an expected checkout case"
        )
    for case_id, expected_stages in CHECKOUT_CASES:
        stages = by_id[case_id]["stages"]
        observed = set(stages)
        # A case may record only its own fixed stages plus its own optional
        # branch markers.  The global allowlist alone would let, say, a
        # cross-site exclusion stand in for a missing approve stage.
        allowed = _checkout_allowed_stages(case_id)
        # Unknown, duplicated or foreign stages are never part of the contract.
        if len(observed) != len(stages) or not observed <= allowed:
            raise AssertionError("checkout evidence is malformed")
        # The mutually exclusive branches cannot both have run.
        _checkout_branch_stage(case_id, observed)
        if not set(expected_stages) <= observed:
            raise AssertionError(
                "checkout evidence is missing an expected checkout stage"
            )

    source = evidence.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"git_revision", "source_sha256"}
    ):
        raise AssertionError("checkout evidence is malformed")
    if "git_revision" in source:
        revision = source["git_revision"]
        if revision is not None and (
            not isinstance(revision, str)
            or _CHECKOUT_GIT_REVISION_RE.fullmatch(revision) is None
        ):
            raise AssertionError("checkout evidence is malformed")
    if "source_sha256" in source:
        source_hash = source["source_sha256"]
        if not isinstance(
            source_hash, str
        ) or not _CHECKOUT_HEX64_RE.fullmatch(source_hash):
            raise AssertionError("checkout evidence is malformed")

    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(
        CHECKOUT_BINARY_ROLES
    ):
        raise AssertionError("checkout evidence is malformed")
    for role in CHECKOUT_BINARY_ROLES:
        value = artifacts.get(role)
        if not isinstance(value, str) or not _CHECKOUT_HEX64_RE.fullmatch(value):
            raise AssertionError("checkout evidence is malformed")

    tools = evidence.get("tools")
    if not isinstance(tools, dict) or set(tools) != set(
        _CHECKOUT_TOOL_VERSIONS
    ):
        raise AssertionError("checkout evidence is malformed")
    for name, pattern in _CHECKOUT_TOOL_VERSIONS.items():
        value = tools.get(name)
        if value is None:
            continue
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise AssertionError("checkout evidence is malformed")
    return cases


def _checkout_evidence_matches(
    evidence: dict[str, Any],
    source_identity: dict[str, Any],
    artifact_hashes: dict[str, str],
) -> None:
    source = evidence.get("source")
    if not isinstance(source, dict) or any(
        source_identity.get(key) != value for key, value in source.items()
    ):
        raise AssertionError(
            "checkout evidence is stale for the current source"
        )
    if evidence.get("artifacts") != artifact_hashes:
        raise AssertionError(
            "checkout evidence does not match the current binaries"
        )


def _parse_checkout_stdout(stdout: str) -> tuple[set[str], bool]:
    """Extract only the fixed stage allowlist and the fixed PASS summary."""

    allowed = set(_CHECKOUT_STAGE_LABELS)
    stages: set[str] = set()
    summary = False
    for raw in str(stdout or "").splitlines():
        line = raw.rstrip("\r")
        if line.startswith(_CHECKOUT_STAGE_PREFIX):
            label = line[len(_CHECKOUT_STAGE_PREFIX) :]
            if label in allowed:
                stages.add(label)
        elif line == CHECKOUT_PASS_SUMMARY:
            summary = True
    return stages, summary


def _checkout_bounded(value: Any, low: int, high: int) -> int | None:
    if type(value) is not int or not low <= value <= high:
        return None
    return value


def _checkout_failed_native(value: Any) -> dict[str, Any] | None:
    """The helper error, only when every copied field passes its allowlist."""

    if not isinstance(value, dict):
        return None
    code, action = value.get("code"), value.get("action")
    if (
        not isinstance(code, str)
        or code not in _CHECKOUT_FAILED_CODES
        or not isinstance(action, str)
        or action not in _CHECKOUT_HELPER_ACTIONS
    ):
        return None
    native: dict[str, Any] = {"code": code, "action": action}
    # ``index`` is part of every helper failure line; a missing one is
    # malformed like any other refused field.
    index = _checkout_bounded(value.get("index"), -1, 255)
    if index is None:
        return None
    native["index"] = index
    codes = value.get("x_codes", [])
    if not isinstance(codes, list) or len(codes) > 8:
        return None
    checked = [_checkout_bounded(entry, 1, 255) for entry in codes]
    if None in checked or len(set(checked)) != len(checked):
        return None
    native["x_codes"] = checked
    return native


def _parse_checkout_startup(stdout: str, stderr: str) -> dict[str, str]:
    """Project the fixed startup fields only, never any raw captured text."""

    # Exact bounded prefix lines; one bad value rejects the whole block.
    phases = [
        "" if len(line) > 128 else
        line.rstrip("\r")[len(_CHECKOUT_STARTUP_PREFIX) :]
        for line in str(stdout or "").splitlines()
        if line.startswith(_CHECKOUT_STARTUP_PREFIX)
    ]
    valid = bool(phases) and all(p in _CHECKOUT_STARTUP_PHASES for p in phases)
    # Independent of the markers: no prefix is absent, a present but unusable
    # one is rejected, and only the existing fixed projection is accepted.
    # The script may emit its fixed line on either captured stream, so both
    # are read as one sequence under the same single-diagnostic rule.
    streams = _checkout_diagnostic_streams(stdout, stderr)
    lines = [line for stream in streams for line in stream.splitlines()]
    # Presence is any line (not only the first) with the exact prefix.
    present = any(line.startswith(_CHECKOUT_DIAGNOSTIC_PREFIX) for line in lines)
    diagnostic = _parse_checkout_diagnostic(streams)
    usable = diagnostic is not None and (
        diagnostic["stage"] in _CHECKOUT_FAILED_STAGES
    )
    state = "absent" if not present else "accepted" if usable else "rejected"
    families = [
        family
        for family, signatures in _CHECKOUT_WRAPPER_SIGNATURES
        if any(
            signature in line
            for line in lines
            if not line.startswith(_CHECKOUT_DIAGNOSTIC_PREFIX)
            for signature in signatures
        )
    ]
    return {
        "startupPhase": phases[-1] if valid else "unknown",
        "failureRecordState": state,
        "wrapperFamily": families[0] if len(families) == 1 else "unknown",
    }


def _checkout_source_frames(value: Any) -> list[dict[str, Any]] | None:
    """The optional fixed source frames, or ``None`` if malformed/oversized.

    Missing, null and empty means no frames and never rejects; anything else
    must be a bounded list of exact known-basename frames so no path, raw
    text or arbitrary value is ever copied.
    """

    if value is None or value == []:
        return None
    if not isinstance(value, list) or len(value) > _CHECKOUT_SOURCE_FRAMES_MAX:
        return None
    frames: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, str):
            return None
        match = _CHECKOUT_SOURCE_FRAME.fullmatch(entry)
        if match is None:
            return None
        line, column = _checkout_bounded(
            int(entry.rsplit(":", 2)[1]), 1, 100000
        ), _checkout_bounded(int(entry.rsplit(":", 2)[2]), 1, 65535)
        if line is None or column is None:
            return None
        frames.append({"file": match.group(1), "line": line, "column": column})
    return frames


def _parse_checkout_failure(stderr: str) -> dict[str, Any] | None:
    """Reduce the diagnostic line on stderr to fixed fields; ``None`` if unusable."""

    text = str(stderr or "")
    if len(text.encode("utf-8", "replace")) > _CHECKOUT_DIAGNOSTIC_MAX_BYTES:
        return None
    return _parse_checkout_diagnostic((text,))


def _checkout_diagnostic_streams(
    stdout: str, stderr: str
) -> tuple[str, ...]:
    """Both captured streams, in order, for one combined parse."""

    return (str(stdout or ""), str(stderr or ""))


_PICKER_STATUS_INVALID = object()


def _checkout_picker_status(diagnostic: dict[str, Any]) -> Any:
    """The optional fixed picker enum, ``None`` when absent, or the sentinel."""

    value = diagnostic.get("pickerStatus")
    if value is None or value == "":
        return None
    if isinstance(value, str) and value in CHECKOUT_PICKER_STATUSES:
        return value
    return _PICKER_STATUS_INVALID


def _parse_checkout_diagnostic(streams: tuple[str, ...]) -> dict[str, Any] | None:
    """Reduce the one fixed diagnostic line across ``streams``; ``None`` if unusable."""

    # Duplicates, malformed or oversized prefix lines are rejected across the
    # whole capture, never one accepted per stream: the byte bound applies to
    # the combined text and the single-line rule to every prefix line in it.
    texts = [str(stream or "") for stream in streams]
    if sum(len(text.encode("utf-8", "replace")) for text in texts) > (
        _CHECKOUT_DIAGNOSTIC_MAX_BYTES
    ):
        return None
    found: list[dict[str, Any]] = []
    # Counted before parsing, so a malformed first prefix line still makes
    # any second prefix line ambiguous. Same split as the presence check in
    # _parse_checkout_startup: only splitlines() line boundaries count.
    seen = False
    for text in texts:
        for raw in text.splitlines():
            line = raw.rstrip("\r")
            if not line.startswith(_CHECKOUT_DIAGNOSTIC_PREFIX):
                continue
            if seen or len(line.encode("utf-8", "replace")) > _CHECKOUT_DIAGNOSTIC_MAX_LINE:
                return None
            seen = True
            try:
                payload = json.loads(line[len(_CHECKOUT_DIAGNOSTIC_PREFIX) :])
            except (ValueError, TypeError, RecursionError):
                continue
            if isinstance(payload, dict):
                found.append(payload)
    if not found:
        return None
    diagnostic = found[0]
    # Validated before any other field: a malformed frame list rejects the
    # whole record, while an absent one keeps the existing projection.
    absent_frames = diagnostic.get("frames") in (None, [], ())
    source_frames = _checkout_source_frames(diagnostic.get("frames"))
    if not absent_frames and source_frames is None:
        return None
    # An absent, null or empty picker status keeps the existing projection;
    # only its fixed enum survives and any other value rejects the record.
    picker_status = _checkout_picker_status(diagnostic)
    if picker_status is _PICKER_STATUS_INVALID:
        return None
    # Mirrors the native sender, which writes pickerStatus only when no native
    # helper error is the original failure: the two never coexist in one
    # record, so their coexistence rejects the whole record.
    if picker_status is not None and "nativeError" in diagnostic:
        return None
    native = _checkout_failed_native(diagnostic.get("nativeError"))
    # The human "reason" text is never copied; it only selects a fixed kind
    # for an allowlisted stage. A stage outside the allowlist is unclassified.
    stage = diagnostic.get("stage")
    if not isinstance(stage, str) or stage not in _CHECKOUT_FAILED_STAGES:
        # The record is already known to be unusable: no optional field is
        # attributed to it, including a picker status no picker failure set.
        return {"stage": "unclassified", "kind": "unclassified", "native": None}
    optional = {"sourceFrames": source_frames} if source_frames else {}
    if picker_status is not None:
        optional["pickerStatus"] = picker_status
    if native is not None:
        return {
            "stage": stage, "kind": "native-helper", "native": native,
            **optional,
        }
    if "nativeError" in diagnostic or not isinstance(
        diagnostic.get("reason"), str
    ):
        return {"stage": "unclassified", "kind": "unclassified", "native": None}
    return {"stage": stage, "kind": "acceptance-failure", "native": None,
            **optional}


def _record_checkout_failure(
    ctx: E2EContext, stdout: str, stderr: str, returncode: int
) -> None:
    """Attach the fixed failure record before the existing generic assertion."""

    streams = _checkout_diagnostic_streams(stdout, stderr)
    record = _parse_checkout_diagnostic(streams) or {
        "stage": "unclassified",
        "kind": "unclassified",
        "native": None,
    }
    record.update(_parse_checkout_startup(stdout, stderr))
    record["exit"] = (
        f"exited {returncode}" if _checkout_bounded(returncode, 1, 255) else "exited"
    )
    ctx.record_evidence({CHECKOUT_FAILURE_EVIDENCE_KEY: record})


def _checkout_child_umask() -> None:
    os.umask(0o077)


def _invoke_checkout_journey(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout: float,
) -> tuple[int, str, str]:
    """Run the native script with captured output; output never leaves memory."""

    proc = subprocess.Popen(
        command,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
        preexec_fn=_checkout_child_umask,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate_process_group(proc, grace=5.0, owned_group=proc.pid)
        try:
            stdout, stderr = proc.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        raise
    return proc.returncode, stdout or "", stderr or ""


def _checkout_run(
    ctx: E2EContext, artifacts: dict[str, Any], timeout: float
) -> dict[str, Any]:
    _checkout_execution_environment(artifacts)
    node = artifacts.get("node")
    if node is None:
        raise _checkout_pending(
            "native checkout prerequisites are absent: node runtime"
        )
    private = Path(tempfile.mkdtemp(prefix="lk-", dir="/tmp"))
    try:
        os.chmod(private, 0o700)
        for name in ("cache", "config", "data", "state", "runtime"):
            directory = private / name
            directory.mkdir(mode=0o700)
        env = dict(os.environ)
        for stale in (
            "LOCKLARK_TEST_SHARED_CLIPBOARD",
            "LOCKLARK_TEST_FAILURE_STAGE",
            "LOCKLARK_TEST_BROWSER_PARITY",
        ):
            env.pop(stale, None)
        env.update(
            {
                "TMPDIR": str(private),
                "XDG_CACHE_HOME": str(private / "cache"),
                "XDG_CONFIG_HOME": str(private / "config"),
                "XDG_DATA_HOME": str(private / "data"),
                "XDG_STATE_HOME": str(private / "state"),
                "XDG_RUNTIME_DIR": str(private / "runtime"),
                "LOCKLARK_TEST_CHECKOUT_FRAMES": "1",
                "LOCKLARK_TEST_BROWSER": "chromium",
                "LOCKLARK_BROWSER_HOST": str(artifacts["chromium_host"]),
                "LOCKLARK_BROWSER_REGISTER": str(
                    artifacts["browser_register"]
                ),
                "LOCKLARK_BROWSER_FIXTURE": str(artifacts["fixture"]),
                "LOCKLARK_TEST_BROWSER_EXECUTABLE": str(
                    artifacts["chromium"]
                ),
            }
        )
        if artifacts.get("playwright") is not None:
            env["LOCKLARK_TEST_PLAYWRIGHT"] = str(artifacts["playwright"])
        go = shutil.which("go") or (os.environ.get("LOCKLARK_GO") or "").strip()
        if go:
            env["LOCKLARK_GO"] = go
        command = [
            "dbus-run-session",
            "--",
            "xvfb-run",
            "-a",
            "-s",
            "-screen 0 1280x900x24",
            str(node),
            "scripts/browser_native_acceptance.mjs",
        ]
        try:
            returncode, stdout, stderr = _invoke_checkout_journey(
                command,
                env=env,
                cwd=Path(ctx.repo_root),
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "native checkout acceptance timed out"
            ) from None
        if returncode != 0:
            _record_checkout_failure(ctx, stdout, stderr, returncode)
            raise AssertionError(
                f"native checkout acceptance exited with status {returncode}"
            )
        observed_stages, summary = _parse_checkout_stdout(stdout)
        if not summary:
            raise AssertionError(
                "native checkout acceptance did not emit the expected PASS summary"
            )
        missing = [
            stage
            for stage in CHECKOUT_REQUIRED_STAGES
            if stage not in observed_stages
        ]
        branch = _checkout_branch_stage(CHECKOUT_BRANCH_CASE_ID, observed_stages)
        if branch is None:
            # A cross-site run must prove exactly one outcome: either the
            # child was excluded or it reached the native review.  Name only
            # the fixed branch IDs, which are already allowlisted.
            missing.extend(
                stage
                for stage in _CHECKOUT_BRANCH_STAGES[CHECKOUT_BRANCH_CASE_ID]
                if stage not in missing
            )
        if missing:
            # Name only fixed allowlisted stage IDs; captured output never leaks.
            raise AssertionError(
                "native checkout acceptance omitted expected checkout stage(s): "
                + ", ".join(missing)
            )
        source_identity = _checkout_source_identity(ctx.repo_root)
        artifact_hashes = _checkout_artifact_hashes(artifacts)
        evidence = {
            "schema": CHECKOUT_EVIDENCE_SCHEMA,
            "schema_version": CHECKOUT_EVIDENCE_VERSION,
            "journey": CHECKOUT_JOURNEY_ID,
            "status": "PASS",
            "cases": _checkout_cases_evidence(observed_stages),
            "source": source_identity,
            "artifacts": artifact_hashes,
            "tools": _checkout_tool_metadata(artifacts, env),
        }
        _checkout_evidence_structure(evidence)
        _checkout_evidence_matches(evidence, source_identity, artifact_hashes)
        return evidence
    finally:
        shutil.rmtree(private, ignore_errors=True)


def _load_checkout_evidence(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > _CHECKOUT_EVIDENCE_MAX_BYTES:
            raise AssertionError("checkout evidence is malformed")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except AssertionError:
        raise
    except (OSError, ValueError, TypeError):
        raise AssertionError("checkout evidence could not be read or parsed") from None
    _checkout_evidence_structure(payload)
    return payload


def _write_checkout_evidence(path: Path, evidence: dict[str, Any]) -> None:
    text = json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2)
    try:
        path.write_text(text + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        raise AssertionError(
            "checkout evidence output could not be written"
        ) from None


def _revalidate_checkout_cache_hit(
    ctx: E2EContext, cached: dict[str, Any], evidence_raw: str, mode: str
) -> None:
    """Recheck every bound input before a cached proof may be returned.

    A cached proof is only reused when the consumed evidence (in evidence
    mode) or the cached success proof (in native mode) still matches the
    current source identity and binary hashes.  The journey never reruns here.
    """

    if mode == "evidence":
        if not evidence_raw:
            raise AssertionError("checkout evidence could not be read or parsed")
        proof = _load_checkout_evidence(Path(evidence_raw))
    else:
        proof = cached
    _checkout_evidence_structure(proof)
    _checkout_evidence_matches(
        proof,
        _checkout_source_identity(ctx.repo_root),
        _checkout_artifact_hashes(_resolve_checkout_artifacts(ctx)),
    )


def checkout_native_acceptance(
    ctx: E2EContext, *, timeout: float = _CHECKOUT_TIMEOUT
) -> dict[str, Any]:
    """Return validated sanitized evidence for the native Chromium checkout.

    Enablement is explicit: an existing evidence manifest is consumed when
    ``LOCKLARK_E2E_CHECKOUT_EVIDENCE`` is set, otherwise the real journey runs
    only with ``LOCKLARK_E2E_CHECKOUT_NATIVE=1``.  A missing opt-in or runtime
    prerequisite is PENDING_FEATURE; any attempted journey or evidence failure
    is an AssertionError (FAIL).  Only fixed case/stage labels, hashes, the git
    revision and safe version metadata are returned or written.
    """

    evidence_raw = (
        os.environ.get("LOCKLARK_E2E_CHECKOUT_EVIDENCE") or ""
    ).strip()
    native_enabled = (
        os.environ.get("LOCKLARK_E2E_CHECKOUT_NATIVE") or ""
    ).strip() == "1"
    if not evidence_raw and not native_enabled:
        raise _checkout_pending(
            "native Chromium checkout acceptance is not enabled"
        )

    repo_key = str(Path(ctx.repo_root).resolve())
    bin_key = str(Path(ctx.bin_dir).resolve())
    mode = "evidence" if evidence_raw else "native"
    cache_key = (repo_key, bin_key, evidence_raw, mode)
    cached = _CHECKOUT_JOURNEY_CACHE.get(cache_key)
    if cached is not None:
        _revalidate_checkout_cache_hit(ctx, cached, evidence_raw, mode)
        if mode == "native":
            output = (
                os.environ.get("LOCKLARK_E2E_CHECKOUT_EVIDENCE_OUT") or ""
            ).strip()
            if output:
                _write_checkout_evidence(Path(output), cached)
        return copy.deepcopy(cached)

    if evidence_raw:
        evidence = _load_checkout_evidence(Path(evidence_raw))
        source_identity = _checkout_source_identity(ctx.repo_root)
        artifacts = _resolve_checkout_artifacts(ctx)
        artifact_hashes = _checkout_artifact_hashes(artifacts)
        _checkout_evidence_matches(evidence, source_identity, artifact_hashes)
        result = evidence
    else:
        artifacts = _resolve_checkout_artifacts(ctx)
        result = _checkout_run(ctx, artifacts, timeout)
        output = (
            os.environ.get("LOCKLARK_E2E_CHECKOUT_EVIDENCE_OUT") or ""
        ).strip()
        if output:
            _write_checkout_evidence(Path(output), result)

    _CHECKOUT_JOURNEY_CACHE[cache_key] = copy.deepcopy(result)
    return copy.deepcopy(result)


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
    "HIBP_FIXED_HOST",
    "HIBP_HTTPS_PORT",
    "HIBP_PREFIX_RE",
    "HIBP_RANGE_SEGMENT",
    "LocalHIBPRangeProxy",
    "HIBP_RANGE_SEGMENT",
    "LocalHIBPRangeServer",
    "f13_cli_hibp_range_lookups",
    "local_hibp_range_server",
    "HIBP_NETWORK_PROMPT",
    "CHECKOUT_BINARY_ROLES",
    "CHECKOUT_BRANCH_CASE_ID",
    "CHECKOUT_CASE_IDS",
    "CHECKOUT_CASES",
    "CHECKOUT_EVIDENCE_SCHEMA",
    "CHECKOUT_OPTIONAL_STAGES",
    "CHECKOUT_PASS_SUMMARY",
    "CHECKOUT_REQUIRED_STAGES",
    "CHECKOUT_SOURCE_FILES",
    "card_fill_explicit_authorization_component",
    "checkout_native_acceptance",
    "f13_cli_hibp_opt_in",
    "HEX32_RE",
    "F14_REQUIRED_PROFILES",
    "HEX32_RE",
    "HEX64_RE",
    "PARITY_STATUSES",
    "TrapListener",
    "add_item",
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
    "f2_passkey_management_ready",
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
    "legacy_rich_1pux",
    "init_vault",
    "item_metadata",
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
    "pykeepass_peer",
    "read_kdbx_entries",
    "require_hex32",
    "require_hex64",
    "reveal_login",
    "sha256_file",
    "shell_function_body",
    "simple_1pux",
    "typed_field",
    "typed_section",
    "source_files",
    "source_text",
    "sources_contain",
    "write_1pux",
    "write_typed_item",
]
