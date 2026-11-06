#!/usr/bin/env python3
"""Choose a proven available runtime/type pair, never an existing device UDID."""
import json
import sys


def select(runtimes, devices):
    candidates = []
    for runtime in runtimes.get("runtimes", []):
        identifier = runtime.get("identifier", "")
        if not runtime.get("isAvailable") or not identifier.startswith("com.apple.CoreSimulator.SimRuntime.iOS-"):
            continue
        for device in devices.get("devices", {}).get(identifier, []):
            device_type = device.get("deviceTypeIdentifier", "")
            if device.get("isAvailable") and device_type.startswith("com.apple.CoreSimulator.SimDeviceType.iPhone-"):
                try:
                    version = tuple(int(part) for part in runtime["version"].split("."))
                except (KeyError, ValueError):
                    continue
                candidates.append((version, identifier, device_type))
    if not candidates:
        raise ValueError("no available compatible iPhone/runtime pair")
    _, runtime, device_type = sorted(candidates)[-1]
    return runtime, device_type


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        runtimes = json.load(f)
    with open(sys.argv[2]) as f:
        devices = json.load(f)
    print(*select(runtimes, devices))
