"""Check the old single-payload CLI and the current native-items CLI with synthetic data."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile


def run(exe, *args, succeeds=True):
    result = subprocess.run([exe, *args], capture_output=True, timeout=60)
    if (result.returncode == 0) != succeeds:
        raise RuntimeError(f"{Path(exe).name} {args[0]}: unexpected exit {result.returncode}")


def check(old, new):
    with tempfile.TemporaryDirectory(prefix="locklark-native-upgrade-") as directory:
        root = Path(directory)
        for tag, exe in (("legacy", old), ("native", new)):
            case = root / tag
            run(exe, "demo", "--out", case, "--session", "native-upgrade", "--reason", "synthetic upgrade check")
            for epoch in (1, 3):
                bundle = case / "share" / f"epoch-{epoch}"
                run(new, "fixture-export", "--bundle", bundle, "--device", case / "clients/B",
                    "--epoch", str(epoch), "--out", root / f"{tag}-{epoch}.1pux")
            run(new, "inspect", "--bundle", case / "share/epoch-3", "--device", case / "clients/A",
                "--epoch", "3", succeeds=False)
        for epoch in (1, 3):
            hashes = {hashlib.sha256((root / f"{tag}-{epoch}.1pux").read_bytes()).digest()
                      for tag in ("legacy", "native")}
            if len(hashes) != 1:
                raise ValueError(f"epoch {epoch} differed between layouts")
        run(old, "inspect", "--bundle", root / "native/share/epoch-3", "--device", root / "native/clients/B",
            "--epoch", "3", succeeds=False)
    print("PASS: legacy/native 1PUX exports match; revoked access and incompatible reader rejected")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: python scripts/native_upgrade.py LEGACY_CLI CURRENT_CLI")
    check(*(Path(arg).resolve(strict=True) for arg in sys.argv[1:]))
