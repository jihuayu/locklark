"""Private-pipe TOTP oracle independent of the Go implementation."""
import base64
import hashlib
import hmac
import json
import struct
import sys


def codes(request):
    seed = request["seed"]
    digits = request["digits"]
    first, last = request["first"], request["last"]
    if digits not in (6, 8) or not isinstance(first, int) or not isinstance(last, int):
        raise ValueError()
    if first < 0 or last < first or last - first > 2:
        raise ValueError()
    secret = base64.b32decode(seed + "=" * (-len(seed) % 8))
    result = []
    for counter in range(first, last + 1):
        digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % (10 ** digits)
        result.append(str(value).zfill(digits))
    return result


if __name__ == "__main__":
    try:
        request = json.loads(sys.stdin.buffer.read(4097))
        sys.stdout.write(json.dumps(codes(request)))
    except Exception:
        sys.stderr.write("Private OTP oracle failed\n")
        sys.exit(1)
