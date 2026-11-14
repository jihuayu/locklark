#!/usr/bin/env python3
"""Private go shim: pin only gomobile init's exact gobind@latest request."""
import os
import re
import sys

LOOPBACK_PACKAGE = "golang.org/x/mobile/cmd/gobind"
LOCAL_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def fail(message):
    print("mobile-go-shim: " + message, file=sys.stderr)
    return 2


def main():
    real_go = os.environ.get("LOCKLARK_REAL_GO", "")
    version = os.environ.get("LOCKLARK_MOBILE_VERSION", "")
    if not real_go or not os.path.isabs(real_go) or not os.access(real_go, os.X_OK):
        return fail("real Go executable unavailable")
    if not LOCAL_VERSION.match(version):
        return fail("pinned x/mobile version unavailable")
    args = sys.argv[1:]
    if args == ["install", LOOPBACK_PACKAGE + "@latest"]:
        args = ["install", LOOPBACK_PACKAGE + "@" + version]
    os.execv(real_go, [real_go] + args)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
