"""Test only: edit native entries without Locklark-specific field access APIs."""
import io
import sys
from pykeepass import PyKeePass

source = sys.argv[1]
key = sys.stdin.buffer.read(33)
if len(key) != 32:
    raise ValueError("expected ephemeral fixture key")
db = PyKeePass(source, keyfile=io.BytesIO(key))
if len(sys.argv) == 2:
    doc = next(e for e in db.entries if e.get_custom_property("Locklark.ID") == "doc")
    a, = doc.attachments
    assert db.payload.inner_header.binary[a.id].data == b"\x01RUZH", "lost protected attachment flag"
    sys.exit(0)
target = sys.argv[2]
twins = db.find_entries(title="same")
assert len(twins) == 2 and twins[0].uuid != twins[1].uuid
entries = {e.get_custom_property("Locklark.ID"): e for e in twins}
login, doc = entries["login"], entries["doc"]
assert login.password == "fixture password" and login.otp == "otpauth://totp/example?secret=AAAA"
assert login._is_property_protected("Password") and login._is_property_protected("otp")
attachment, = doc.attachments
assert attachment.filename == "demo.bin" and attachment.data == b"QUJD"
original_id = login.uuid
login.title = "renamed via independent editor"
login.password = "changed fixture"
login.otp = "otpauth://totp/edited?secret=BBBB"
db.delete_binary(attachment.id)
doc.add_attachment(db.add_binary(b"RUZH"), "edited.bin")
db.save(target)
reopened = PyKeePass(target, keyfile=io.BytesIO(key))
entry = reopened.find_entries(uuid=original_id, first=True)
assert entry is not None and entry.title == "renamed via independent editor"
assert entry._is_property_protected("Password") and entry._is_property_protected("otp")
