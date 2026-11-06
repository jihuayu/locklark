#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
from device_policy import validate_test_bundle_base, validate_device_id, validate_team_id, require_fresh_test_apps

try:
    if len(sys.argv) not in {1, 2}:
        raise ValueError("unexpected physical acceptance arguments")
    base = validate_test_bundle_base(os.environ.get("IOS_TEST_BUNDLE_BASE"))
    validate_device_id(os.environ.get("IOS_DEVICE_ID"))
    validate_team_id(os.environ.get("IOS_DEVELOPMENT_TEAM"))
    if len(sys.argv) == 2:
        require_fresh_test_apps(json.loads(Path(sys.argv[1]).read_text()), base)
except Exception:
    print("ios physical configuration or fresh-test inventory FAIL")
    sys.exit(1)
print("ios physical fresh-test inventory PASS" if len(sys.argv) == 2 else "ios physical configuration PASS")
