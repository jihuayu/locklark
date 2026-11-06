"""Hard-failure privacy gate for the real notes display and private probe path."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import urllib.parse

from desktop_login_notes_acceptance import visible_notes


def scan_output(raw, fixture):
    values = set()
    for name in ("Password", "Secret", "Username", "Value", "ExportPassword", "NotesOriginal", "NotesEdited", "NotesRejected", "NotesConflict"):
        value = fixture[name]
        values.add(value)
        if name.startswith("Notes"):
            values.add(visible_notes(value))
            values.update(line for line in value.splitlines() if line.strip())
    for value in values:
        variants = (value.encode(), json.dumps(value, ensure_ascii=True)[1:-1].encode(),
                    json.dumps(value, ensure_ascii=False)[1:-1].encode(), urllib.parse.quote(value, safe="").encode())
        if any(pattern and pattern in raw for pattern in variants):
            raise ValueError("privacy-factor")


def expected_failure(returncode, raw):
    return returncode == 1 and b"FAIL: desktop login notes at private-notes-probe-failure [probe-probe-operation]" in raw


def main():
    root = Path(__file__).resolve().parent.parent
    state = Path(tempfile.mkdtemp(prefix="locklark-notes-privacy-"))
    environment = dict(os.environ, LOCKLARK_TEST_FAILURE_STAGE="probe-input")
    with (state / "controller.log").open("xb") as log:
        os.chmod(log.name, 0o600)
        process = subprocess.Popen([sys.executable, str(root / "scripts/desktop_login_notes_acceptance.py")],
                                   cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise ValueError("privacy-timeout") from None
    raw = (state / "controller.log").read_bytes()
    if not expected_failure(process.returncode, raw):
        raise ValueError("privacy-failure-stage")
    match = re.search(rb"Desktop login notes private state: (/tmp/locklark-desktop-acceptance-[a-zA-Z0-9_]+)", raw)
    if not match:
        raise ValueError("privacy-state")
    private = Path(match[1].decode("ascii"))
    fixture_path = private / "vault/fixture.json"
    fixture = json.loads(fixture_path.read_text())
    scan_output(raw, fixture)
    for path in private.rglob("*"):
        if path.suffix == ".png":
            raise ValueError("privacy-screenshot")
        if path.is_file() and path != fixture_path and path.suffix in (".log", ".txt", ".json", ".jsonl"):
            scan_output(path.read_bytes(), fixture)
    print("PASS: real notes display then probe input failure exits 1; full controller/native/diagnostic canary scan; no screenshots")
    print("Private notes fault artifacts: " + str(state))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        allowed = {"privacy-factor", "privacy-timeout", "privacy-failure-stage", "privacy-state", "privacy-screenshot"}
        reason = error.args[0] if type(error) is ValueError and len(error.args) == 1 and error.args[0] in allowed else "privacy-unexpected"
        print("FAIL: notes privacy acceptance (" + reason + ")", file=sys.stderr)
        sys.exit(1)
