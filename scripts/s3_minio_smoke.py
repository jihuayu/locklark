#!/usr/bin/env python3
"""Run the opt-in real-MinIO TLS smoke test for pkg/vaultfilebackend.S3.

The harness starts one short-lived MinIO container from the already-cached
official image by immutable digest, binds it to loopback only, serves TLS with
a self-signed certificate generated for that run, and uses random synthetic
root credentials. It then runs ``TestS3MinioTLSSmoke`` against the real
endpoint (``pkg/vaultfilebackend/s3_minio_smoke_test.go``).

Guarantees:

- The image is never pulled or built. If it is not present locally the run
  fails clearly. Only ``minio/minio@sha256:...`` references are accepted.
- The container is named ``locklark-s3-smoke-<random>``. Every start, inspect,
  stop and remove call uses that exact name; other containers are never
  inspected, stopped or removed.
- The certificate and credentials are generated into a private 0700 temp
  directory with 0600 files.
- No AWS environment, config or credential files are read: ``AWS_*``
  variables are dropped from the test environment. ``HOME`` is neither set
  nor overwritten, no AWS CLI is used, and nothing is written into the
  repository. Product configuration stays empty.
- Nothing under the repository is bind-mounted into the container.

Run from the repository root:

    python3 scripts/s3_minio_smoke.py

Pass ``--keep`` to leave the container and the private directory in place
after a passing run (the harness prints their paths and the loopback
endpoint); otherwise they are removed.

Requires ``go``, ``openssl`` and ``docker`` (or a compatible runtime such as
``podman``, named by ``LOCKLARK_S3_SMOKE_CONTAINER``).

Why the certificate is installed after startup: the official image sets
``MINIO_CONFIG_ENV_FILE``, and while those file variables are set MinIO reads
``MINIO_ROOT_USER``/``MINIO_ROOT_PASSWORD`` but ignores ``MINIO_CERTS_DIR``
(the Server API stays plain HTTP). With no server certificate the image's
entrypoint creates only ``<certs-dir>/CAs`` and MinIO then blocks before it
generates its own temporary pair. This harness therefore starts MinIO with
the generated certificate already named as the server certificate in the
certs dir and picks a free loopback port, so the first listen is HTTPS.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

IMAGE = "minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"
IMAGE_DIGEST = "sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"
CONTAINER_PREFIX = "locklark-s3-smoke-"
GO_TEST = "TestS3MinioTLSSmoke"
TEST_PACKAGE = "./pkg/vaultfilebackend"
CERTS_DIR = "/run/locklark-smoke"
STARTUP_TIMEOUT_SEC = 90
GO_TEST_TIMEOUT_SEC = 300
STOP_TIMEOUT_SEC = 30
LOOPBACK_RE = re.compile(r"(?:127\.0\.0\.1|\[::1\]|localhost):(\d+)")


class SmokeFailure(Exception):
    """A fixed, non-secret smoke failure classification."""


def log(message: str) -> None:
    print(f"[s3-minio-smoke] {message}", flush=True)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def redacted(text: str, secret: str) -> str:
    return text.replace(secret, "<redacted>") if secret else text


def run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 60,
    what: str,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise SmokeFailure(f"{what}: executable not found: {args[0]}") from None
    except subprocess.TimeoutExpired:
        raise SmokeFailure(f"{what}: timed out after {timeout:.0f}s") from None


def text(result: subprocess.CompletedProcess) -> str:
    return (result.stdout + result.stderr).decode("utf-8", "replace")


def container_cli() -> str:
    override = os.environ.get("LOCKLARK_S3_SMOKE_CONTAINER")
    if override:
        return override
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    raise SmokeFailure("no docker or podman CLI found")


def require_local_image(cli: str) -> None:
    result = run([cli, "image", "inspect", "--format", "{{.Id}}", IMAGE], what="inspect pinned image")
    require(
        result.returncode == 0,
        f"pinned image {IMAGE} is not present locally; it is never pulled or built, so load it first",
    )
    require(
        result.stdout.decode().strip() == IMAGE_DIGEST,
        f"local image for the pinned reference has an unexpected ID {result.stdout.decode().strip()!r}",
    )


def write_private(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        while data:
            data = data[os.write(fd, data):]
    finally:
        os.close(fd)
    os.chmod(path, mode)


def generate_certificate(directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Generate a self-signed certificate for 127.0.0.1 and localhost."""
    key = directory / "tls.key"
    cert = directory / "tls.crt"
    result = run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=locklark-s3-smoke",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        what="generate TLS certificate",
    )
    require(result.returncode == 0, "openssl failed to generate the TLS certificate")
    for path in (key, cert):
        os.chmod(path, 0o600)
        st = path.stat()
        require(st.st_mode & 0o077 == 0, f"{path.name} is not 0600")
        require(st.st_size > 0, f"{path.name} is empty")
    return cert, key


def generate_credentials() -> tuple[str, str]:
    # Alphanumeric only: no shell quoting or env-file escaping involved.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    access = "llsmoke" + "".join(secrets.choice(alphabet) for _ in range(16))
    secret = "".join(secrets.choice(alphabet) for _ in range(40))
    return access, secret


def loopback_port(cli: str, container: str) -> int:
    result = run([cli, "port", container, "9000/tcp"], what="read container port")
    require(result.returncode == 0, "container did not publish its S3 port")
    lines = [line.strip() for line in result.stdout.decode().splitlines() if line.strip()]
    require(len(lines) == 1, "container published an unexpected number of S3 ports")
    match = LOOPBACK_RE.fullmatch(lines[0])
    require(match is not None, "container S3 port is not bound to loopback only")
    return int(match.group(1))


def container_running(cli: str, container: str) -> bool:
    state = run([cli, "inspect", "--format", "{{.State.Status}}", container], what="read container state")
    require(state.returncode == 0, "MinIO container disappeared")
    status = state.stdout.decode().strip()
    require(status in {"running", "restarting"}, f"MinIO container stopped before it was ready (state {status!r})")
    return status == "running"


def wait_tls(cli: str, container: str, cert: pathlib.Path) -> int:
    """Wait until the loopback API accepts a verified TLS handshake.

    This is the only readiness signal for the endpoint: it trusts exactly the
    generated certificate, so plain HTTP or an unverified server never passes.
    """
    deadline = time.monotonic() + STARTUP_TIMEOUT_SEC
    while True:
        require(container_running(cli, container), "MinIO container stopped before it was ready")
        port = loopback_port(cli, container)
        result = run(
            [
                "openssl",
                "s_client",
                "-verify_return_error",
                "-connect",
                f"127.0.0.1:{port}",
                "-servername",
                "127.0.0.1",
                "-CAfile",
                str(cert),
            ],
            timeout=15,
            what="TLS readiness probe",
        )
        if result.returncode == 0 and b"Verify return code: 0 (ok)" in result.stdout:
            return port
        require(time.monotonic() < deadline, "MinIO did not accept a verified TLS connection in time")
        time.sleep(0.5)


def remove_container(cli: str, container: str) -> None:
    run([cli, "stop", "--time", "5", container], timeout=STOP_TIMEOUT_SEC, what="stop container")
    for _ in range(40):
        rm = run([cli, "rm", "-f", container], timeout=STOP_TIMEOUT_SEC, what="remove container")
        if rm.returncode == 0 or b"no such" in (rm.stderr or b"").lower():
            return
        time.sleep(0.25)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--go", default="go", help="go executable (default: go)")
    parser.add_argument(
        "--keep",
        action="store_true",
        help="after PASS, leave the container and private directory in place",
    )
    args = parser.parse_args()

    cli = container_cli()
    require_local_image(cli)
    container = CONTAINER_PREFIX + secrets.token_hex(6)
    access, secret = generate_credentials()
    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix=CONTAINER_PREFIX))
    state: dict[str, object] = {"started": False, "passed": False}

    def cleanup() -> None:
        if state["passed"] and args.keep:
            log(f"kept container {container} and private directory {temp_dir}")
            return
        if state["started"]:
            # Only this run's container, addressed by its unique name. Its
            # data lives on the container's writable layer and disappears
            # with it.
            remove_container(cli, container)
        shutil.rmtree(temp_dir, ignore_errors=True)

    def on_signal(signum: int, _frame: object) -> None:
        raise SmokeFailure(f"interrupted by signal {signum}")

    signals = (signal.SIGINT, signal.SIGTERM)
    old_handlers = {sig: signal.signal(sig, on_signal) for sig in signals}
    try:
        os.chmod(temp_dir, 0o700)
        require(temp_dir.stat().st_mode & 0o077 == 0, "private temp directory is not 0700")
        cert, key = generate_certificate(temp_dir)
        verify = temp_dir / "verify.crt"
        write_private(verify, cert.read_bytes())
        write_private(
            temp_dir / "minio.env",
            f"MINIO_SMOKE_CONTAINER={container}\n".encode(),
            0o600,
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            host_port = probe.getsockname()[1]

        log(f"starting {CONTAINER_PREFIX}* from the pinned local image on 127.0.0.1:{host_port}")
        start = run(
            [
                cli,
                "run",
                "--detach",
                "--name",
                container,
                "--network",
                "bridge",
                # Loopback only: a fixed free loopback port, chosen above.
                "--publish",
                f"127.0.0.1:{host_port}:9000",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                # The image's empty credential-file defaults make MinIO read
                # its root credentials from these variables instead.
                "--env",
                "MINIO_ROOT_USER_FILE=",
                "--env",
                "MINIO_ROOT_PASSWORD_FILE=",
                "--env",
                "MINIO_KMS_SECRET_KEY_FILE=",
                "--env",
                "MINIO_CONFIG_ENV_FILE=",
                "--env",
                "MINIO_BROWSER=off",
                "--env",
                "MINIO_UPDATE=off",
                "--env",
                "MINIO_ROOT_USER=" + access,
                "--env",
                "MINIO_ROOT_PASSWORD=" + secret,
                "--mount",
                f"type=bind,source={cert},destination={CERTS_DIR}/public.crt,readonly",
                "--mount",
                f"type=bind,source={key},destination={CERTS_DIR}/private.key,readonly",
                IMAGE,
                "server",
                "/data",
                "--address",
                ":9000",
                "--certs-dir",
                CERTS_DIR,
            ],
            env={**os.environ},
            what="start container",
        )
        state["started"] = start.returncode == 0
        require(
            state["started"],
            "failed to start the MinIO container: " + redacted(text(start).strip(), secret),
        )
        endpoint = f"https://127.0.0.1:{host_port}"
        write_private(
            temp_dir / "minio.env",
            f"MINIO_SMOKE_CONTAINER={container}\nMINIO_SMOKE_ENDPOINT={endpoint}\nMINIO_SMOKE_CA_FILE={verify}\n".encode(),
            0o600,
        )

        log("waiting for MinIO to serve the generated certificate over TLS")
        port = wait_tls(cli, container, verify)
        require(port == host_port, "container S3 port does not match the published loopback port")

        env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        env.update(
            {
                "MINIO_SMOKE_ENABLE": "1",
                "MINIO_SMOKE_ENDPOINT": endpoint,
                "MINIO_SMOKE_CA_FILE": str(verify),
                "MINIO_SMOKE_ACCESS_KEY": access,
                "MINIO_SMOKE_SECRET_KEY": secret,
            }
        )
        command = [args.go, "test", "-count=1", "-v", "-run", f"^{GO_TEST}$", TEST_PACKAGE]
        log("running " + " ".join(command))
        test = run(command, env=env, timeout=GO_TEST_TIMEOUT_SEC, what="go test")
        output = redacted(text(test), secret)
        sys.stderr.write(output)
        require(test.returncode == 0, "go test failed (see output above)")
        require(f"--- PASS: {GO_TEST} " in output, "go test did not report a passing smoke test")
        require("--- SKIP" not in output, "smoke test was skipped, not run")
        state["passed"] = True
        log(f"PASS: real MinIO TLS smoke test (container {container}, {endpoint})")
        return 0
    except SmokeFailure as exc:
        print(f"[s3-minio-smoke] FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        cleanup()
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
