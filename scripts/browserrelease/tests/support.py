"""Private synthetic fixtures: temporary extension tree, commits and raw ZIPs."""

from __future__ import annotations

import io
import os
import shutil
import stat
import struct
import subprocess
import warnings
import zipfile
import zlib
from pathlib import Path

from browserrelease import allowlist, zipbuild

REPO_ROOT = Path(__file__).resolve().parents[3]
GIT_ENVIRONMENT = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}
GIT_IDENTITY = [
    "-c",
    "user.email=release@example.invalid",
    "-c",
    "user.name=Release Test",
]


def _git(root: Path, args: list[str]) -> None:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        shell=False,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        env=GIT_ENVIRONMENT,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "synthetic fixture git command failed: "
            + completed.stderr.decode("utf-8", "replace")
        )


def make_root(base: Path) -> Path:
    """Create a committed, clean extension tree with its own throwaway history."""
    root = Path(base) / "repo"
    extension = root / "browser-extension"
    extension.mkdir(parents=True)
    source = REPO_ROOT / "browser-extension"
    for name in [
        "build.js",
        "release-version.json",
        *allowlist.BASE_FILES,
        "safari-native-port.js",
    ]:
        shutil.copyfile(source / name, extension / name)
    (root / ".gitignore").write_text(
        "browser-extension/dist/\n", encoding="utf-8"
    )
    _git(root, ["init", "-q"])
    commit(root, "synthetic release fixture")
    return root


def commit(root: Path, message: str = "synthetic fixture change") -> None:
    _git(root, ["add", "-A"])
    _git(root, [*GIT_IDENTITY, "commit", "-q", "-m", message])


def write_metadata(root: Path, payload: str) -> None:
    (Path(root) / "browser-extension" / "release-version.json").write_text(
        payload, encoding="utf-8"
    )


def patch_build(root: Path, old: str, new: str) -> None:
    path = Path(root) / "browser-extension" / "build.js"
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError("unexpected build script fixture")
    path.write_text(text.replace(old, new), encoding="utf-8")


def crafted_zip(members, comment: bytes = b"", compression=zipfile.ZIP_STORED) -> bytes:
    """Build an archive from explicit (name, data, mode_bits) members."""
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(
            buffer, "w", compression=compression, allowZip64=False
        ) as archive:
            for name, data, mode in members:
                info = zipfile.ZipInfo(name, zipbuild.ZIP_TIMESTAMP)
                info.compress_type = compression
                info.create_system = 3
                info.external_attr = (
                    (mode << 16)
                    if mode
                    else (stat.S_IFREG | zipbuild.ZIP_FILE_MODE) << 16
                )
                info.flag_bits = 0
                info.extra = b""
                info.comment = b""
                archive.writestr(info, data)
            archive.comment = comment
    return buffer.getvalue()


def raw_zip(members) -> bytes:
    """Write a ZIP byte by byte so raw names are not truncated or re-encoded.

    `members` is a list of (local_name, central_name, data) with `bytes` names.
    """
    body = bytearray()
    central = bytearray()
    for local_name, central_name, data in members:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        offset = len(body)
        body += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, crc, len(data), len(data),
            len(local_name), 0,
        )
        body += local_name + data
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0x21, crc, len(data),
            len(data), len(central_name), 0, 0, 0, 0,
            (stat.S_IFREG | zipbuild.ZIP_FILE_MODE) << 16, offset,
        )
        central += central_name
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(central), len(body), 0
    )
    return bytes(body + central + end)


def members_for(product: str, data: bytes = b"x") -> list:
    return [(name, data, 0) for name in allowlist.entries_for(product)]
