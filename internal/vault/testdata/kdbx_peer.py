"""Independent KDBX reader/writer; invoked only with a freshly generated test fixture."""
import base64
import io
import sys
from importlib.metadata import version
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

if version("pykeepass") != "4.2.0":
    raise ValueError("requires pykeepass==4.2.0")
source, current, legacy = sys.argv[1:]
key = sys.stdin.buffer.read(33)
assert len(key) == 32
try:
    PyKeePass(source, keyfile=io.BytesIO(bytes(x ^ 0xff for x in key)))
except CredentialsError:
    pass
else:
    raise ValueError("wrong key opened fixture")

db = PyKeePass(source, keyfile=io.BytesIO(key))
params = db.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
if db.version != (4, 1) or params['$UUID'].value != kdf_uuids['argon2id']:
    raise ValueError(f"unexpected KDBX version or KDF UUID: {db.version}, {params['$UUID'].value.hex()}")
entry, = db.entries
if entry.title != "Preview" or base64.b64decode(entry.notes, validate=True) != b"original fixture":
    raise ValueError("Go payload did not survive independent read")
if not entry._is_property_protected("Notes"):
    raise ValueError("Go Notes were not marked protected")
entry.notes = base64.b64encode(b"edited by independent peer").decode("ascii")
db.save(current)
# Write a distinct legacy Argon2d copy for the backwards-read check.
db.kdbx.header.value.dynamic_header.kdf_parameters.data.dict['$UUID'].value = kdf_uuids['argon2']
db.save(legacy)
for path, algorithm in ((current, "argon2id"), (legacy, "argon2")):
    saved = PyKeePass(path, keyfile=io.BytesIO(key))
    params = saved.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    if params['$UUID'].value != kdf_uuids[algorithm] or not saved.entries[0]._is_property_protected("Notes"):
        raise ValueError("peer save changed the expected KDF or protection flag")
