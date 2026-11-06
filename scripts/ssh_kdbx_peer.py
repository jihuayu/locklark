"""Independent encrypted KDBX SSH oracle; every value uses private files."""
import base64
import json
import os
import pathlib
import sys

def main():
    from Cryptodome.PublicKey import ECC
    from pykeepass import PyKeePass
    os.umask(0o077)
    vault, expectations, output = map(pathlib.Path, sys.argv[1:])
    expected = json.loads(expectations.read_bytes())
    database = PyKeePass(vault, password=expected["password"])
    entries = database.entries
    assert len(entries) == 2
    generated = None
    for entry in entries:
        assert entry.get_custom_property("Locklark.Kind") == "ssh-key"
        protected = entry._element.find("String[Key='Locklark.SSHSeed']/Value")
        assert protected is not None and protected.get("Protected") == "True"
        seed_text = entry.get_custom_property("Locklark.SSHSeed")
        public_text = entry.get_custom_property("Locklark.SSHPublicKey")
        seed, public = base64.b64decode(seed_text, validate=True), base64.b64decode(public_text, validate=True)
        assert len(seed) == 32
        derived = ECC.construct(curve="Ed25519", seed=seed).public_key().export_key(format="OpenSSH").split()[1]
        assert base64.b64decode(derived, validate=True) == public
        if entry.title == "Owned imported SSH":
            assert seed_text == expected["seed"] and public_text == expected["public"]
        else:
            assert entry.title == "Owned generated SSH" and public_text == expected["generated"] and generated is None
            generated = seed_text
    assert generated is not None
    output.write_text(json.dumps({"verified": True, "generated_seed": generated}))
    output.chmod(0o600)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Independent SSH KDBX oracle failed", file=sys.stderr)
        raise SystemExit(1)
