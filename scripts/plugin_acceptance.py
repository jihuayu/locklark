"""Independent Python Ed25519 publisher and separate-process catalog lifecycle.

Uses PyCryptodome installed with the KDBX peer. The signed JS sentinel must never
execute: this is an installer acceptance, not sandbox or runtime verification.
"""
import base64
import concurrent.futures
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import eddsa


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        catalog, pins_file, sentinel = root / "plugins.db", root / "pins.json", root / "MUST-NOT-RUN"
        plugin_id = "example.tools/pull-reader"
        key = ECC.construct(curve="Ed25519", seed=bytes([7]) * 32)
        publisher = key.public_key().export_key(format="raw").hex()
        pins_file.write_text(json.dumps({plugin_id: publisher}), encoding="utf-8")

        def invoke(*args, ok=True):
            result = subprocess.run([binary, "plugin", *map(str, args)], capture_output=True, text=True, timeout=20)
            assert (result.returncode == 0) == ok, (args, result.stdout, result.stderr)
            assert "MUST-NOT-RUN" not in result.stdout + result.stderr
            assert not sentinel.exists(), "installer executed signed code"
            if not ok:
                assert not result.stdout.strip(), "partial result after failure"
                return result.stderr
            return json.loads(result.stdout)

        def package(version):
            data = {"schema": 1, "id": plugin_id, "version": version, "publisher": publisher,
                    "runtime": "bun-1.4.4/bundled-v1", "capabilities": ["github.pulls.get"],
                    "dependencies": [{"name": "synthetic-dependency", "version": "1.2.3", "sha256": hashlib.sha256(b"synthetic source").hexdigest()}],
                    "bundle": base64.b64encode(("await Bun.write(" + json.dumps(str(sentinel)) + ", 'executed');").encode()).decode(), "signature": None}
            data["signature"] = base64.b64encode(eddsa.new(key, "rfc8032").sign(b"locklark/plugin-package/signature/v1\0" + encoded(data))).decode()
            raw = encoded(data)
            path = root / (str(version) + ".llplugin")
            path.write_bytes(raw)
            return path, hashlib.sha256(b"locklark/plugin-package/digest/v1\0" + raw).hexdigest()

        def install(parent, path, digest, ok=True):
            return invoke("install", "--file", catalog, "--parent", parent, "--pins", pins_file, "--package", path,
                          "--id", plugin_id, "--publisher", publisher, "--digest", digest, ok=ok)

        first = invoke("init", "--file", catalog)
        initial_file = catalog.read_bytes()
        one, one_digest = package(1)
        report = invoke("inspect", "--package", one, "--id", plugin_id, "--publisher", publisher)
        assert report["plugin"]["package_digest"] == one_digest and report["execution"] == "disabled"
        installed = install(first["checkpoint"], one, one_digest)
        assert installed["plugins"][0]["version"] == 1 and installed["execution"] == "disabled"
        assert "version must increase" in install(installed["checkpoint"], one, one_digest, ok=False)
        two, two_digest = package(2)
        assert "catalog changed" in install(first["checkpoint"], two, two_digest, ok=False)
        assert "invalid plugin" in install(installed["checkpoint"], two, one_digest, ok=False)
        upgraded = install(installed["checkpoint"], two, two_digest)
        three, three_digest = package(3)
        args = [binary, "plugin", "install", "--file", str(catalog), "--parent", upgraded["checkpoint"], "--pins", str(pins_file),
                "--package", str(three), "--id", plugin_id, "--publisher", publisher, "--digest", three_digest]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(subprocess.run, args, capture_output=True, text=True, timeout=20) for _ in range(2)]
            results = [future.result() for future in futures]
        assert sorted(result.returncode for result in results) == [0, 1]
        loser = next(result for result in results if result.returncode != 0)
        assert "catalog changed" in loser.stderr and not loser.stdout
        current = json.loads(next(result.stdout for result in results if result.returncode == 0))
        revoked = invoke("revoke", "--file", catalog, "--parent", current["checkpoint"], "--pins", pins_file, "--id", plugin_id)
        assert revoked["plugins"][0]["revoked"]
        four, four_digest = package(4)
        assert "permanently revoked" in install(revoked["checkpoint"], four, four_digest, ok=False)
        assert invoke("list", "--file", catalog, "--anchor", first["checkpoint"], "--pins", pins_file) == revoked
        events = invoke("audit", "--file", catalog, "--anchor", revoked["checkpoint"], "--pins", pins_file)
        assert [event["action"] for event in events] == ["catalog.create", "plugin.install", "plugin.install", "plugin.install", "plugin.revoke"]
        pins_file.write_text("{}", encoding="utf-8")
        invoke("list", "--file", catalog, "--anchor", revoked["checkpoint"], "--pins", pins_file, ok=False)
        pins_file.write_text(json.dumps({plugin_id: publisher}), encoding="utf-8")
        invoke("run", "--file", catalog, ok=False)
        catalog.write_bytes(initial_file)
        invoke("list", "--file", catalog, "--anchor", revoked["checkpoint"], "--pins", pins_file, ok=False)
        assert not sentinel.exists()
    print("PASS: independent Ed25519, inspect/install/update/revoke, pinned identity, process CAS, rollback refusal, no execution")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
