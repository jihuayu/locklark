#!/usr/bin/env python3
"""Parse and validate the browser parity evidence mapping.

The checker is intentionally dependency-free and read-only.  It parses the
checklist with an anchored stable-ID regex, then validates
``docs/browser-parity-evidence.json`` against the checklist and the repository
tree.

It refuses:

* duplicate, missing or unknown stable IDs;
* absolute paths, ``..`` escapes or paths outside the repository;
* implementation/test paths that do not exist;
* incomplete evidence records;
* private artifact keys such as passwords, screenshots or response bodies;
* any claim that the fixed 1Password reference was verified.  The only
  permitted non-``unverified`` reference state is a previously approved
  difference, and that row must carry its decision reference.

Usage:
    python3 scripts/check_browser_parity_evidence.py
    python3 scripts/check_browser_parity_evidence.py --json
    python3 scripts/check_browser_parity_evidence.py --list-ids
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "locklark.browser-parity-evidence.v1"
CHECKLIST_REL = "docs/browser-parity-checklist.md"
EVIDENCE_REL = "docs/browser-parity-evidence.json"
EXPECTED_ROW_COUNT = 65

STATUS_VOCABULARY = (
    "未实现",
    "已实现未对照",
    "已实测",
    "平台不适用",
    "经用户确认的差异",
)
EVIDENCE_LEVELS = ("E0", "E1", "E2", "E3", "E4")
EVIDENCE_STATES = (
    "not-run-in-this-change",
    "path-exists-only",
    "passed",
    "failed",
    "unavailable",
)
REFERENCE_UNVERIFIED = "unverified"
REFERENCE_ACCEPTED_DIFFERENCE = "accepted_difference"
FABRICATED_REFERENCE_STATES = {
    "verified",
    "pass",
    "passed",
    "reference-pass",
    "reference_verified",
    "已实测",
    "已对照",
}

# The 65 stable IDs from the historical 1Password 8.12.44.33 baseline.  The
# list is duplicated here as a tripwire: editing the checklist cannot silently
# redefine the parity contract, and the evidence file cannot invent an ID.
EXPECTED_STABLE_IDS = (
    "B1.1", "B1.2", "B1.3", "B1.4", "B1.5",
    "B2.1", "B2.2",
    "B3.1", "B3.2", "B3.3", "B3.4", "B3.5", "B3.6",
    "B4.1", "B4.2", "B4.3", "B4.4",
    "B5.1", "B5.2", "B5.3", "B5.4", "B5.5",
    "B6.1", "B6.2", "B6.3", "B6.4",
    "B7.1", "B7.2", "B7.3",
    "B8.1", "B8.2", "B8.3", "B8.4",
    "B9.1", "B9.2", "B9.3", "B9.4", "B9.5",
    "B10.1", "B10.2", "B10.3",
    "B11.1", "B11.2", "B11.3",
    "B12a.1", "B12a.2",
    "B12b.1", "B12b.2", "B12b.3",
    "B13.1", "B13.2", "B13.3",
    "B14.1", "B14.2",
    "B15.1", "B15.2", "B15.3", "B15.4", "B15.5", "B15.6",
    "B16.1", "B16.2", "B16.3",
    "B17.1", "B17.2",
)

# Anchored four-column table row.  An ID only counts when it is the first cell
# of a Markdown row, so prose that mentions B1.1 is never treated as a row.
ROW_RE = re.compile(
    r"^\|\s*(?P<id>B\d+[a-z]?\.\d+)\s*"
    r"\|(?P<behavior>[^|]*)\|(?P<status>[^|]*)\|(?P<notes>[^|]*)\|\s*$"
)

FORBIDDEN_KEYS = {
    "password",
    "passwords",
    "secret",
    "secrets",
    "token",
    "tokens",
    "body",
    "request_body",
    "response_body",
    "screenshot",
    "screenshots",
    "html",
    "dom",
    "dom_snapshot",
    "fields",
    "values",
    "field_values",
    "cookie",
    "cookies",
    "header",
    "headers",
    "vault_data",
    "private_key",
    "credential",
    "credentials",
    "user_handle",
}
FORBIDDEN_PATH_FRAGMENTS = (
    "/workspace/",
    "1p-ext",
    "rea-m3",
    "tmp/ref",
    "file://",
)
FORBIDDEN_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".kdbx", ".log",
    ".jsonl", ".har", ".webm", ".pdf", ".crx", ".xpi",
)
DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


class EvidenceError(Exception):
    """Raised for unusable inputs, not for validation findings."""


def repository_root(start: Path | None = None) -> Path:
    root = (start or Path(__file__).resolve().parent).resolve()
    for candidate in (root, *root.parents):
        if (candidate / CHECKLIST_REL).is_file():
            return candidate
    raise EvidenceError(f"cannot locate {CHECKLIST_REL} above {root}")


def parse_checklist(path: Path) -> list[dict[str, str]]:
    """Return checklist rows in file order using the anchored ID regex."""
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            match = ROW_RE.match(raw.rstrip("\n"))
            if not match:
                continue
            rows.append(
                {
                    "id": match.group("id").strip(),
                    "behavior": match.group("behavior").strip(),
                    "status": match.group("status").strip(),
                    "notes": match.group("notes").strip(),
                    "line": str(line_number),
                }
            )
    return rows


def _add(errors: list[str], message: str) -> None:
    errors.append(message)


def _walk_items(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_items(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_items(child, f"{path}[{index}]")


def _scan_private_content(value: Any, where: str, errors: list[str]) -> None:
    for item_path, item in _walk_items(value, where):
        if isinstance(item, dict):
            for key in item:
                if str(key).lower() in FORBIDDEN_KEYS:
                    _add(errors, f"{item_path}: forbidden private artifact key {key!r}")
        if isinstance(item, str):
            lowered = item.lower()
            for fragment in FORBIDDEN_PATH_FRAGMENTS:
                if fragment.lower() in lowered:
                    _add(errors, f"{item_path}: private/external path fragment {fragment!r}")
            if item.startswith("/") or DRIVE_RE.match(item):
                _add(errors, f"{item_path}: absolute path is not allowed")


def _check_repo_path(
    root: Path,
    value: Any,
    where: str,
    errors: list[str],
    *,
    must_be_file: bool,
) -> None:
    if not isinstance(value, str) or not value.strip():
        _add(errors, f"{where}: path must be a non-empty string")
        return
    if value != value.strip():
        _add(errors, f"{where}: path must not have leading/trailing whitespace")
        return
    if value.startswith(("~", "/", "\\")) or DRIVE_RE.match(value):
        _add(errors, f"{where}: absolute or home-relative path {value!r}")
        return
    if "\\" in value:
        _add(errors, f"{where}: backslash path {value!r}")
        return
    parts = Path(value).parts
    if any(part == ".." for part in parts):
        _add(errors, f"{where}: path escape {value!r}")
        return
    if value.startswith("./") or "/./" in value:
        _add(errors, f"{where}: path must be exact repository-relative {value!r}")
        return
    lowered = value.lower()
    for fragment in FORBIDDEN_PATH_FRAGMENTS:
        if fragment.lower() in lowered:
            _add(errors, f"{where}: private/external path {value!r}")
            return
    if lowered.endswith(FORBIDDEN_SUFFIXES):
        _add(errors, f"{where}: private artifact type {value!r}")
        return
    resolved = (root / value).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        _add(errors, f"{where}: path escapes repository {value!r}")
        return
    if not resolved.exists():
        _add(errors, f"{where}: path does not exist {value!r}")
        return
    if must_be_file and not resolved.is_file():
        _add(errors, f"{where}: test path is not a file {value!r}")


def _check_string_list(
    row: dict[str, Any], key: str, where: str, errors: list[str]
) -> list[str]:
    value = row.get(key)
    if not isinstance(value, list) or not value:
        _add(errors, f"{where}.{key}: non-empty list required")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            _add(errors, f"{where}.{key}[{index}]: non-empty string required")
            continue
        result.append(item)
    return result


def _check_test_result(
    row: dict[str, Any], row_id: str, head: str, errors: list[str]
) -> None:
    state = row.get("evidence_state")
    if state not in ("passed", "failed"):
        return
    result = row.get("test_result")
    if not isinstance(result, dict):
        _add(errors, f"{row_id}: evidence_state {state!r} requires test_result")
        return
    for key in ("command", "head", "summary"):
        if not isinstance(result.get(key), str) or not result[key].strip():
            _add(errors, f"{row_id}.test_result.{key}: non-empty string required")
    if result.get("head") != head:
        _add(errors, f"{row_id}.test_result.head: must match mapping head {head!r}")


def _check_command_references(
    commands: list[str], test_paths: list[str], row_id: str, errors: list[str]
) -> None:
    for path in test_paths:
        parent = str(Path(path).parent)
        if parent == ".":
            parent = ""
        if not any(path in command or (parent and parent in command) for command in commands):
            _add(
                errors,
                f"{row_id}: no test_command references checked-in test path {path!r}",
            )


def validate_checklist(rows: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    ids = [row["id"] for row in rows]
    seen: set[str] = set()
    duplicates: set[str] = set()
    for row_id in ids:
        if row_id in seen:
            duplicates.add(row_id)
        seen.add(row_id)
    for row_id in sorted(duplicates):
        _add(errors, f"checklist: duplicate stable ID {row_id}")
    expected = set(EXPECTED_STABLE_IDS)
    for row_id in sorted(expected - seen):
        _add(errors, f"checklist: missing known stable ID {row_id}")
    for row_id in sorted(seen - expected):
        _add(errors, f"checklist: unknown stable ID {row_id}")
    if len(rows) != EXPECTED_ROW_COUNT:
        _add(
            errors,
            f"checklist: expected {EXPECTED_ROW_COUNT} rows, found {len(rows)}",
        )
    for row in rows:
        if row["status"] not in STATUS_VOCABULARY:
            _add(
                errors,
                f"checklist {row['id']}: unknown status {row['status']!r}",
            )
    return errors


def validate_evidence(
    evidence: Any, checklist_rows: list[dict[str, str]], root: Path
) -> dict[str, Any]:
    errors: list[str] = validate_checklist(checklist_rows)
    warnings: list[str] = []

    if not isinstance(evidence, dict):
        return {
            "ok": False,
            "errors": errors + ["evidence: top-level object required"],
            "warnings": warnings,
            "row_count": 0,
            "stable_id_count": 0,
            "reference_status": None,
        }

    head = evidence.get("head")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        _add(errors, "head: 40-character lowercase git SHA required")
        head = ""

    if evidence.get("schema") != SCHEMA:
        _add(errors, f"schema: must be {SCHEMA!r}")
    if evidence.get("source_checklist") != CHECKLIST_REL:
        _add(errors, f"source_checklist: must be {CHECKLIST_REL!r}")
    if evidence.get("stable_id_count") != EXPECTED_ROW_COUNT:
        _add(errors, f"stable_id_count: must be {EXPECTED_ROW_COUNT}")
    if evidence.get("claim_scope") != "implementation-and-test-path-map-only":
        _add(errors, "claim_scope: mapping-only scope required")

    reference = evidence.get("reference")
    if not isinstance(reference, dict):
        _add(errors, "reference: object required")
        reference = {}
    if reference.get("status") != REFERENCE_UNVERIFIED:
        _add(
            errors,
            "reference.status: fixed reference comparison must remain "
            f"{REFERENCE_UNVERIFIED!r}",
        )
    if reference.get("authorized_fixed_reference_install") is not False:
        _add(errors, "reference.authorized_fixed_reference_install: must be false")

    rows = evidence.get("rows")
    if not isinstance(rows, list):
        _add(errors, "rows: list required")
        rows = []

    checklist_by_id = {row["id"]: row for row in checklist_rows}
    evidence_ids: list[str] = []
    for index, row in enumerate(rows):
        where = f"rows[{index}]"
        if not isinstance(row, dict):
            _add(errors, f"{where}: object required")
            continue
        row_id = row.get("id")
        if not isinstance(row_id, str):
            _add(errors, f"{where}.id: string required")
            continue
        where = row_id
        evidence_ids.append(row_id)

        if row_id not in checklist_by_id:
            _add(errors, f"{row_id}: unknown stable ID (not in checklist)")
        else:
            checklist_row = checklist_by_id[row_id]
            if row.get("behavior") != checklist_row["behavior"]:
                _add(errors, f"{row_id}: behavior does not match checklist text")
            if row.get("implementation_status") != checklist_row["status"]:
                _add(
                    errors,
                    f"{row_id}: implementation_status does not match checklist "
                    f"({row.get('implementation_status')!r} != {checklist_row['status']!r})",
                )

        status = row.get("implementation_status")
        if status not in STATUS_VOCABULARY:
            _add(errors, f"{row_id}: unknown implementation_status {status!r}")
        if status == "已实测":
            _add(
                errors,
                f"{row_id}: 已实测 is not permitted while the fixed reference "
                "install remains unauthorized",
            )

        reference_status = row.get("reference_status")
        if reference_status in FABRICATED_REFERENCE_STATES:
            _add(
                errors,
                f"{row_id}: fabricated reference pass {reference_status!r}; "
                "the fixed reference is not installed or compared",
            )
        elif status == "经用户确认的差异":
            if reference_status != REFERENCE_ACCEPTED_DIFFERENCE:
                _add(
                    errors,
                    f"{row_id}: accepted difference requires "
                    f"reference_status {REFERENCE_ACCEPTED_DIFFERENCE!r}",
                )
            decision_ref = row.get("decision_ref")
            if not isinstance(decision_ref, str):
                _add(errors, f"{row_id}: accepted difference requires decision_ref")
            else:
                _check_repo_path(
                    root, decision_ref, f"{row_id}.decision_ref", errors,
                    must_be_file=True,
                )
            if not isinstance(row.get("decision_date"), str):
                _add(errors, f"{row_id}: accepted difference requires decision_date")
        elif reference_status != REFERENCE_UNVERIFIED:
            _add(
                errors,
                f"{row_id}: reference_status must be {REFERENCE_UNVERIFIED!r} "
                "without an authorized fixed-reference comparison",
            )

        implementation_paths = _check_string_list(
            row, "implementation_paths", row_id, errors
        )
        test_paths = _check_string_list(row, "test_paths", row_id, errors)
        commands = _check_string_list(row, "test_commands", row_id, errors)
        limitations = _check_string_list(row, "limitations", row_id, errors)
        if not limitations:
            _add(errors, f"{row_id}: at least one limitation is required")

        for path_index, path in enumerate(implementation_paths):
            _check_repo_path(
                root, path, f"{row_id}.implementation_paths[{path_index}]",
                errors, must_be_file=False,
            )
        for path_index, path in enumerate(test_paths):
            _check_repo_path(
                root, path, f"{row_id}.test_paths[{path_index}]",
                errors, must_be_file=True,
            )
        _check_command_references(commands, test_paths, row_id, errors)
        for command_index, command in enumerate(commands):
            if len(command) > 500:
                _add(errors, f"{row_id}.test_commands[{command_index}]: too long")
            if any(fragment.lower() in command.lower() for fragment in FORBIDDEN_PATH_FRAGMENTS):
                _add(
                    errors,
                    f"{row_id}.test_commands[{command_index}]: private/external path",
                )

        if row.get("evidence_level") not in EVIDENCE_LEVELS:
            _add(errors, f"{row_id}: evidence_level must be one of {EVIDENCE_LEVELS}")
        if row.get("evidence_state") not in EVIDENCE_STATES:
            _add(errors, f"{row_id}: evidence_state must be one of {EVIDENCE_STATES}")
        _check_test_result(row, row_id, head, errors)

        notes = row.get("notes")
        if not isinstance(notes, str) or len(notes.strip()) < 20:
            _add(errors, f"{row_id}: notes must explain the current evidence (>=20 chars)")

        _scan_private_content(row, row_id, errors)

    seen: set[str] = set()
    duplicates: set[str] = set()
    for row_id in evidence_ids:
        if row_id in seen:
            duplicates.add(row_id)
        seen.add(row_id)
    for row_id in sorted(duplicates):
        _add(errors, f"{row_id}: duplicate stable ID in evidence")
    expected = set(EXPECTED_STABLE_IDS)
    for row_id in sorted(expected - seen):
        _add(errors, f"{row_id}: missing stable ID from evidence")
    for row_id in sorted(seen - expected):
        _add(errors, f"{row_id}: unknown stable ID in evidence")
    if len(rows) != EXPECTED_ROW_COUNT:
        _add(errors, f"rows: expected {EXPECTED_ROW_COUNT}, found {len(rows)}")
    if len(seen) != EXPECTED_ROW_COUNT:
        _add(errors, f"rows: expected {EXPECTED_ROW_COUNT} unique IDs, found {len(seen)}")

    accessibility = evidence.get("accessibility")
    if not isinstance(accessibility, dict):
        _add(errors, "accessibility: object required")
    else:
        if accessibility.get("automated_driver_status") not in (
            "not-added-this-stage",
            "implemented-unrun",
            "run-current-head",
        ):
            _add(errors, "accessibility.automated_driver_status: unknown state")
        if accessibility.get("real_screen_reader_status") != "open":
            _add(errors, "accessibility.real_screen_reader_status: must be 'open'")
        if accessibility.get("owner_issue") != 57:
            _add(errors, "accessibility.owner_issue: must be 57")

    _scan_private_content(reference, "reference", errors)
    _scan_private_content(accessibility, "accessibility", errors)

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "row_count": len(rows),
        "stable_id_count": len(seen),
        "reference_status": reference.get("status"),
    }


def load_inputs(
    root: Path, evidence_path: Path, checklist_path: Path
) -> tuple[Any, list[dict[str, str]]]:
    try:
        checklist_rows = parse_checklist(checklist_path)
    except OSError as error:
        raise EvidenceError(f"cannot read checklist: {error}") from error
    try:
        with evidence_path.open("r", encoding="utf-8") as handle:
            evidence = json.load(handle)
    except OSError as error:
        raise EvidenceError(f"cannot read evidence: {error}") from error
    except json.JSONDecodeError as error:
        raise EvidenceError(f"invalid evidence JSON: {error}") from error
    return evidence, checklist_rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, help="repository root")
    parser.add_argument("--checklist", type=Path, help="checklist path")
    parser.add_argument("--evidence", type=Path, help="evidence JSON path")
    parser.add_argument("--json", action="store_true", help="print JSON report")
    parser.add_argument("--list-ids", action="store_true", help="print parsed IDs")
    args = parser.parse_args(argv)

    try:
        root = (args.root or repository_root()).resolve()
        checklist_path = (args.checklist or root / CHECKLIST_REL).resolve()
        evidence_path = (args.evidence or root / EVIDENCE_REL).resolve()
        if args.list_ids:
            for row in parse_checklist(checklist_path):
                print(row["id"])
            return 0
        evidence, checklist_rows = load_inputs(root, evidence_path, checklist_path)
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    report = validate_evidence(evidence, checklist_rows, root)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(
            "browser parity evidence: "
            f"{report['row_count']} rows, "
            f"{report['stable_id_count']} unique IDs, "
            f"reference={report['reference_status']}"
        )
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report["warnings"]:
            print(f"WARN: {warning}", file=sys.stderr)
        if report["ok"]:
            print("OK: 65-row mapping is complete and repository-relative")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
