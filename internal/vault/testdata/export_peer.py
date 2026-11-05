"""Independent synthetic portable KDBX checks; never print source values."""
import base64
import json
import sys
from pykeepass import PyKeePass

expected = json.loads(sys.stdin.buffer.read().decode("utf-8"))
db = PyKeePass(sys.argv[1], password="synthetic-export-password")
params = db.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
assert params["M"].value == 64 << 20 and params["I"].value == 3 and params["P"].value >= 1
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids
assert params["$UUID"].value == kdf_uuids["argon2id"]
assert len(db.entries) == len(expected)
by_id = {e.get_custom_property("Locklark.ID"): e for e in db.entries}
for item in expected:
    e = by_id[item["ID"]]
    assert e.title == item["Title"] and e.get_custom_property("Locklark.Kind") == item["Kind"]
    assert (e.get_custom_property("Locklark.State") or "") == item.get("State", "")
    if item["Kind"] == "login":
        assert (e.username or "") == item["Username"] and (e.password or "") == item["Password"]
        assert (e.otp or "") == item["OTP"]
    else:
        assert len(e.attachments) == 1 and e.attachments[0].filename == item["Filename"]
        assert e.attachments[0].data == base64.b64decode(item["Attachment"])
        assert db.payload.inner_header.binary[e.attachments[0].id].data[0] == int(item["AttachmentProtected"])
try:
    PyKeePass(sys.argv[1], password="wrong-export-password")
    raise AssertionError("wrong password accepted")
except Exception as error:
    assert type(error).__name__ == "CredentialsError"
