"""Normal CLI import and real MyGo notes UI; all bodies stay in private pipes.

Caller provides an isolated DISPLAY/private D-Bus session. This tool never reads
editable text or screenshots a window that might contain an authorized secret.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unicodedata

from desktop_native_acceptance import Acceptance, AcceptanceFailure, ROOT, MARKER, require
from login_notes_fixture import import_notes, factors
from login_notes_probe import NotesMetadataReader
from personal_acceptance import invoke
from browser_native_x11 import failure_reason


def visible_notes(value):
    return "".join("\\u{%X}" % ord(char) if char not in "\n\t" and
                   unicodedata.category(char) in ("Cc", "Cf") else char for char in value)


def notes_events(snapshot, action, item_id):
    return [event for event in snapshot["events"] if event["action"] == action and event.get("item_id") == item_id]


class NotesAcceptance(Acceptance):
    def __init__(self):
        super().__init__()
        self.cli = str(Path(os.environ["LOCKLARK_CLI_HOST"]).resolve(strict=True))
        self.reader = None
        self.owner = None
        self.owner_healthy = True
        self.completed = []
        self.last_metadata = {}
        self.export_sequence = 0
        self.last_clipboard = {}
        self.baseline = os.environ.get("LOCKLARK_TEST_NOTES_BASELINE") == "1"

    def phase(self, value):
        self.stage = value
        self.reason = "acceptance"
        self.emit("Desktop login notes stage: " + value)

    def otp(self, _timestamp):
        return ""  # This fixture contains no OTP configuration or short codes.

    def register_notes(self, value):
        if not value:
            return
        self.values.update((value, visible_notes(value)))
        # Detect partial line disclosures as well as a complete body.
        self.values.update(line for line in value.splitlines() if line.strip())

    def observe(self):
        snapshot = super().observe()
        for item in snapshot["items"]:
            self.register_notes(item.get("Notes", ""))
        return snapshot

    def start_probe(self):
        child = subprocess.Popen([sys.executable, str(ROOT / "scripts/desktop_native_probe.py")],
                                 env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=self.log, text=True, bufsize=1)
        self.foreign_owners.append(child)
        require(bool(select.select([child.stdout], [], [], 15)[0]))
        require(json.loads(child.stdout.readline()).get("ready") is True)
        return child

    def owner_request(self, request):
        # Separate the GTK clipboard owner from every AT-SPI query. No editable
        # text is read: paste uses ordinary Ctrl+V and verification uses storage.
        display_probe, display_healthy = self.probe, self.probe_healthy
        self.probe, self.probe_healthy = self.owner, self.owner_healthy
        try:
            return super().probe_request(request)
        finally:
            self.owner_healthy = self.probe_healthy
            self.probe, self.probe_healthy = display_probe, display_healthy

    def clipboard(self, expected=()):
        result = json.loads(self.command([sys.executable, str(ROOT / "scripts/login_notes_clipboard.py")],
                                         (json.dumps({"expected": list(expected)}) + "\n").encode(), timeout=5))
        require(result.get("ok") is True)
        self.last_clipboard = {"empty": result.get("empty"), "matches": result.get("matches")}
        return result

    def paste(self, value):
        self.owner_request({"op": "own-clipboard", "marker": value})
        self.input([{"click_label": "备注正文（可见多行）"},
                    {"key": "Control_L+a"}, {"key": "Control_L+v" if value else "BackSpace"}])

    def metadata(self, row):
        try:
            if self.reader is None:
                self.reader = NotesMetadataReader(self.app.pid)
            self.last_metadata = self.reader.inspect(row["id"], row["revision"])
            return self.last_metadata
        except Exception as error:
            self.reason = "notes-metadata-" + failure_reason(error)
            raise AcceptanceFailure() from None

    def setup(self):
        self.phase("normal-cli-import" if not self.baseline else "baseline-cli-import-without-notes")
        self.command([self.go, "build", "-o", str(self.fixture_binary), "./scripts/desktop_acceptance_fixture"])
        self.fixture = import_notes(self.cli, self.state / "vault", with_notes=not self.baseline)
        self.values.update(self.fixture[key] for key in ("Password", "Secret", "Username", "Value", "ExportPassword"))
        for key in ("NotesOriginal", "NotesEdited", "NotesRejected", "NotesConflict"):
            self.register_notes(self.fixture[key])
        self.app = subprocess.Popen([str(self.host)], env=self.env, stdout=self.log, stderr=self.log)
        self.probe = self.start_probe()
        self.owner = self.start_probe()
        self.unlock()
        self.select_notes()
        self.owner_request({"op": "own-clipboard", "marker": MARKER})

    def select_notes(self):
        self.click("Notes imported login · active")
        self.wait("显示密码")

    def row(self, snapshot=None):
        return self.target(self.observe() if snapshot is None else snapshot, "Notes imported login")

    def audit_increment(self, before, after, action, row):
        old = notes_events(before, action, row["id"])
        new = notes_events(after, action, row["id"])
        require(len(new) == len(old) + 1 and new[-1]["result"] == "intent" and new[-1]["base_revision"] == row["revision"])

    def edit(self, row):
        before = self.observe()
        self.click("编辑备注")
        self.wait("保存备注")
        self.eventually(lambda: self.metadata(row)["editor_present"])
        require(self.last_metadata["id_matches"] and self.last_metadata["revision_matches"])
        self.audit_increment(before, self.observe(), "item.desktop.edit.notes", row)

    def saved(self, expected):
        before = self.observe()
        previous = self.row(before)
        self.click("保存备注")
        self.wait("新建登录")
        self.eventually(lambda: self.row()["Notes"] == expected)
        self.select_notes()
        after = self.observe()
        writes = self.events(after, "item.edit.notes")
        require(len(writes) == len(self.events(before, "item.edit.notes")) + 1 and writes[-1]["result"] == "succeeded" and
                writes[-1]["item_id"] == previous["id"] and writes[-1]["base_revision"] == previous["revision"])
        current = self.row(after)
        require({key: value for key, value in previous.items() if key not in ("Notes", "revision")} ==
                {key: value for key, value in current.items() if key not in ("Notes", "revision")})
        require(not self.metadata(self.row())["editor_present"] and self.displays_empty())
        return self.row()

    def export_check(self, alias):
        self.export_sequence += 1
        target = self.state / ("portable-" + alias + "-" + str(self.export_sequence) + ".kdbx")
        invoke(self.cli, "export-kdbx", self.fixture["Path"], factors(self.fixture) +
               [("新导出密码（至少 12 字符）", self.fixture["ExportPassword"]),
                ("再次输入导出密码", self.fixture["ExportPassword"]), ("输入 SAVE 确认加密导出", "SAVE")],
               options=("--out", str(target)), forbidden=tuple(self.values))
        python = os.environ.get("LOCKLARK_TEST_PYKEEPASS", sys.executable)
        result = json.loads(self.command([python, str(ROOT / "scripts/login_notes_fixture.py"), "check",
                                          str(self.fixture_path), str(target), alias]))
        require(result == {"notes_exact": True, "protected_notes": alias != "empty", "source_unchanged": True, "id_matches": True})

    def scenarios(self):
        self.phase("selection-is-metadata-only")
        initial = self.observe()
        row = self.row(initial)
        require(row["Notes"] == self.fixture["NotesOriginal"] and self.displays_empty())
        require(not any(event["action"].startswith("item.desktop.") and event["action"].endswith(".notes") for event in initial["events"]))
        self.assert_independent_clipboard(MARKER)
        self.completed.append("normal multiline CLI import; metadata selection discloses no notes")

        self.phase("explicit-notes-show-copy")
        self.click("显示备注")
        self.eventually(lambda: self.display(expected=[visible_notes(self.fixture["NotesOriginal"])])["matches"] == [True])
        shown = self.observe()
        self.audit_increment(initial, shown, "item.desktop.show.notes", row)
        self.assert_independent_clipboard(MARKER)
        self.phase("explicit-notes-copy-raw")
        self.click("复制备注")
        expected = self.fixture["NotesOriginal"]
        self.eventually(lambda: self.clipboard([expected, expected.replace("\r\n", "\n")])["matches"][0] is True)
        require(self.owner_request({"op": "clipboard", "expected": [expected.replace("\r\n", "\n").replace("\r", "\n")]})["matches"] == [True])
        self.phase("explicit-notes-copy-audit")
        copied = self.observe()
        self.audit_increment(shown, copied, "item.desktop.copy.notes", row)
        self.phase("disclosure-keeps-items-unchanged")
        self.same_items(initial, copied)
        self.completed.append("explicit audited show formatting and exact raw clipboard copy")

        self.phase("prefill-cancel-enter-is-not-save")
        self.edit(row)
        require(self.displays_empty())
        self.paste(self.fixture["NotesRejected"])
        self.input([{"key": "Return"}])
        require(self.metadata(row)["editor_present"])
        cancelled = self.observe()
        self.same_items(copied, cancelled)
        require(not self.events(cancelled, "item.edit.notes"))
        self.click("取消编辑备注")
        self.wait("显示备注")
        self.same_items(cancelled, self.observe())
        self.completed.append("audited edit prefill; Enter and Cancel do not save")

        self.phase("prefill-roundtrip-without-reading-editor")
        self.edit(row)
        row = self.saved(self.fixture["NotesOriginal"])
        self.export_check("original")
        self.completed.append("unmodified editor prefill preserves raw bytes and protected Notes")

        self.phase("multiline-edit-quick-escape-save")
        self.edit(row)
        self.paste(self.fixture["NotesEdited"])
        self.click("快捷搜索")
        self.wait("关闭快捷搜索")
        self.input([{"text": "Notes draft remains"}, {"key": "Escape"}])
        self.wait("保存备注")
        row = self.saved(self.fixture["NotesEdited"])
        self.export_check("edited")
        self.completed.append("multiline Unicode edit survives temporary search and explicit save; source remains immutable")

        self.phase("stale-revision-save-refused")
        self.edit(row)
        invoke(self.cli, "edit-login", self.fixture["Path"], factors(self.fixture) +
               [("新备注（隐藏单行输入，留空清除；多行请用原生编辑器）", self.fixture["NotesConflict"])],
               options=("--id", row["id"], "--revision", row["revision"], "--field", "notes"), forbidden=tuple(self.values))
        self.paste(self.fixture["NotesRejected"])
        self.click("保存备注")
        self.wait("显示备注")
        independent = self.row()
        require(independent["id"] == row["id"] and independent["Notes"] == self.fixture["NotesConflict"])
        writes = self.events(self.observe(), "item.edit.notes")
        require(writes[-1]["result"] == "conflict" and writes[-1]["item_id"] == row["id"])
        self.completed.append("stale editor cannot overwrite an independent committed revision")

        self.phase("empty-clear-and-source-reconciliation")
        # Refresh the stale selected metadata through the normal list UI.
        self.click("搜索 / 刷新")
        self.wait("新建登录")
        self.select_notes()
        self.edit(independent)
        self.paste("")
        row = self.saved("")
        self.phase("empty-protected-kdbx-reconciliation")
        self.export_check("empty")
        self.phase("restore-edited-notes")
        self.edit(row)
        self.paste(self.fixture["NotesEdited"])
        row = self.saved(self.fixture["NotesEdited"])
        self.completed.append("explicit empty clear omits the KDBX field; original import provenance remains protected")

        self.phase("lock-drops-draft-and-owned-copy")
        self.edit(row)
        self.paste(self.fixture["NotesRejected"])
        self.click("立即锁定")
        self.wait("解锁")
        require(self.displays_empty() and self.row()["Notes"] == self.fixture["NotesEdited"])
        require(self.clipboard([self.fixture["NotesRejected"]])["matches"] == [True])
        self.unlock()
        self.select_notes()
        require(not self.metadata(row)["editor_present"])
        self.click("复制备注")
        self.eventually(lambda: self.clipboard([self.fixture["NotesEdited"]])["matches"] == [True])
        self.click("立即锁定")
        self.wait("解锁")
        require(self.clipboard()["empty"] and self.displays_empty())
        self.completed.append("Lock discards unsaved draft and clears only the owned notes clipboard")

        self.phase("real-process-reopen-explicit-reread")
        self.app.terminate()
        self.app.wait(timeout=5)
        # A display observer belongs to one product process. Keep the separate
        # foreign clipboard owner alive, but release the old AT-SPI client.
        self.probe.terminate()
        self.probe.wait(timeout=5)
        self.foreign_owners.remove(self.probe)
        self.probe = self.start_probe()
        self.probe_healthy = True
        self.app = subprocess.Popen([str(self.host)], env=self.env, stdout=self.log, stderr=self.log)
        self.reader = None
        self.unlock()
        self.select_notes()
        self.phase("reopen-no-automatic-notes")
        require(self.displays_empty())
        self.phase("reopen-explicit-notes-show-copy")
        self.click("显示备注")
        self.eventually(lambda: self.display(expected=[visible_notes(self.fixture["NotesEdited"])])["matches"] == [True])
        self.click("复制备注")
        self.eventually(lambda: self.clipboard([self.fixture["NotesEdited"]])["matches"] == [True])
        self.export_check("edited")
        self.completed.append("fresh process requires explicit read and recovers the edited protected notes")

    def run(self):
        success = False
        try:
            self.setup()
            if self.baseline:
                self.phase("baseline-missing-notes-actions")
                controls = self.controls()
                self.reason = "baseline-notes-actions-absent" if controls["显示密码"]["enabled"] and all(not controls[label]["present"] for label in ("显示备注", "复制备注", "编辑备注")) else "unexpected-baseline-support"
                raise AcceptanceFailure()
            if os.environ.get("LOCKLARK_TEST_FAILURE_STAGE") == "probe-input":
                self.phase("private-notes-probe-failure")
                self.click("显示备注")
                self.eventually(lambda: self.display(expected=[visible_notes(self.fixture["NotesOriginal"])])["matches"] == [True])
                self.probe_request({"op": "unsupported", "private": list(self.values)})
                raise AcceptanceFailure()
            require(not os.environ.get("LOCKLARK_TEST_FAILURE_STAGE"))
            self.scenarios()
            success = True
        except Exception as error:
            failure = {"stage": self.stage, "reason": self.reason,
                       "error_class": {AcceptanceFailure: "acceptance", OSError: "os", json.JSONDecodeError: "json"}.get(type(error), "unexpected"),
                       "native_action": self.native_action, "native_elapsed_ms": self.native_elapsed_ms,
                       "native_failed_index": self.native_failed_index, "metadata": self.last_metadata,
                       "clipboard": self.last_clipboard, "probe_diagnostic": self.probe_diagnostic,
                       "probe_operation": self.probe_operation, "probe_elapsed_ms": self.probe_elapsed_ms}
            try:
                failure["controls"] = self.controls()
            except Exception:
                failure["controls_unavailable"] = True
            self.reason, self.native_action = failure["reason"], failure["native_action"]
            with os.fdopen(os.open(self.diagnostics / "failure.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as out:
                json.dump(failure, out)
        finally:
            self.close()
        lines = ["Desktop login notes private state: " + str(self.state),
                 "PASS: real CLI-imported login notes: " + "; ".join(self.completed) if success else
                 "FAIL: desktop login notes at " + self.stage + " [" + self.reason + "]"]
        try:
            with os.fdopen(os.open(self.state / "controller.log", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as out:
                out.write("\n".join(self.output_lines + lines) + "\n")
            self.scan()
        except Exception:
            print("FAIL: desktop login notes privacy scan", flush=True)
            return 1
        for line in lines:
            print(line, flush=True)
        return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(NotesAcceptance().run())
    except Exception:
        print("FAIL: desktop login notes setup", file=sys.stderr)
        sys.exit(1)
