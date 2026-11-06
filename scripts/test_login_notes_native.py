"""Negative controls for the external notes oracles; no product authorization seam."""
import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from desktop_login_notes_acceptance import visible_notes, notes_events, NotesAcceptance
from desktop_native_acceptance import AcceptanceFailure
from login_notes_fixture import check_export, NotesFixtureFailure
from login_notes_privacy_acceptance import scan_output, expected_failure
from login_notes_clipboard import compare, RawClipboardFailure


class NotesOracleTests(unittest.TestCase):
    def test_visible_preserves_linefeed_tab_and_nonbmp_but_escapes_controls(self):
        self.assertEqual(visible_notes("  多行🔐\r\n\tend \u202e\x00"), "  多行🔐\\u{D}\n\tend \\u{202E}\\u{0}")

    def test_audit_matches_exact_action_target_and_revision(self):
        row = {"id": "a" * 32, "revision": "b" * 64}
        event = {"action": "item.desktop.edit.notes", "item_id": row["id"], "base_revision": row["revision"], "result": "intent"}
        subject = NotesAcceptance.__new__(NotesAcceptance)
        before = {"events": []}
        subject.audit_increment(before, {"events": [event]}, event["action"], row)
        for key, bad in (("item_id", "c" * 32), ("base_revision", "d" * 64), ("action", "item.desktop.copy.notes"), ("result", "succeeded")):
            changed = dict(event, **{key: bad})
            with self.subTest(key=key), self.assertRaises(AcceptanceFailure):
                subject.audit_increment(before, {"events": [changed]}, event["action"], row)
        self.assertEqual(notes_events({"events": [event]}, "item.desktop.edit.password", row["id"]), [])

    def fixture(self):
        return {name: "Private-" + name + "-\u4e2d\U0001f510" for name in ("Password", "Secret", "Username", "Value", "ExportPassword", "NotesOriginal", "NotesEdited", "NotesRejected", "NotesConflict")}

    def test_controller_scan_rejects_raw_json_encoded_and_partial_notes(self):
        fixture = self.fixture()
        fixture["NotesOriginal"] = "First private line\r\nSecond private line🔐\n"
        scan_output(b"fixed stage and booleans only", fixture)
        for value in (fixture["Password"], fixture["NotesOriginal"], "Second private line🔐", visible_notes(fixture["NotesOriginal"]), json.dumps(fixture["NotesEdited"], ensure_ascii=True)[1:-1]):
            with self.subTest(), self.assertRaises(ValueError):
                scan_output(("prefix " + value + " suffix").encode(), fixture)

    def test_fault_requires_actual_fixed_probe_reason_stage_and_exit_one(self):
        actual = b"FAIL: desktop login notes at private-notes-probe-failure [probe-probe-operation]"
        self.assertTrue(expected_failure(1, actual))
        for returncode, message in ((0, actual), (-15, actual), (1, b"FAIL: desktop login notes at private-notes-probe-failure [probe-operation]"), (1, b"FAIL: desktop login notes at unlock [probe-probe-operation]")):
            with self.subTest():
                self.assertFalse(expected_failure(returncode, message))

    def test_raw_reader_rejects_invalid_requests_before_x11_access(self):
        with patch("login_notes_clipboard.Connection") as connection:
            for expected in (None, "body", [False], ["x"] * 9, ["x" * 65537], ["🔐" * 16385]):
                with self.subTest(), self.assertRaises(RawClipboardFailure):
                    compare(expected)
            connection.assert_not_called()

    def test_export_rejects_wrong_notes_unprotected_source_and_source_mutation(self):
        fixture = self.fixture()
        fixture["SourceItem"] = {"details": {"notesPlain": fixture["NotesOriginal"]}}
        fixture["IDs"] = {"notes": "a" * 32}
        class Entry:
            notes = fixture["NotesEdited"]
            notes_protected = True
            source_protected = True
            source = copy.deepcopy(fixture["SourceItem"])
            def _is_property_protected(self, key):
                return self.notes_protected
            def is_custom_property_protected(self, key):
                return self.source_protected
            def get_custom_property(self, key):
                return fixture["IDs"]["notes"] if key == "Locklark.ID" else base64.b64encode(json.dumps({"item": self.source}).encode()).decode()
        entry = Entry()
        module = types.SimpleNamespace(PyKeePass=lambda *_args, **_kwargs: types.SimpleNamespace(entries=[entry]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text(json.dumps(fixture))
            with patch.dict(sys.modules, {"pykeepass": module}), contextlib.redirect_stdout(io.StringIO()) as output:
                check_export(path, "private.kdbx", "edited")
                self.assertNotIn(fixture["NotesEdited"], output.getvalue())
                for field, bad in (("notes", "wrong body"), ("notes_protected", False), ("source_protected", False), ("source", {"details": {"notesPlain": fixture["NotesEdited"]}})):
                    old = getattr(entry, field)
                    setattr(entry, field, bad)
                    with self.subTest(field=field), self.assertRaises(NotesFixtureFailure):
                        check_export(path, "private.kdbx", "edited")
                    setattr(entry, field, old)


if __name__ == "__main__":
    unittest.main()
