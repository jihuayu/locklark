#!/usr/bin/env bash
set -euo pipefail
script_root="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$script_root/device_credential_acceptance.py" "$@"
