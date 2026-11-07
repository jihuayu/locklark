"""Locklark M5 opaque-box E2E test package.

Test modules live next to this file and register cases with
:func:`tests.e2e.harness.register_test` (also exported as ``e2e_test``).  The
runner imports the canonical modules lazily so the infrastructure remains
usable while milestone branches are still landing.
"""

from .harness import (
    CHROMIUM_EXT_ORIGIN,
    CLIResult,
    E2EContext,
    FIREFOX_EXT_ID,
    ISSUED_TOKEN_RE,
    NativeProbeResult,
    PTYResult,
    RECOVERY_KIT_RE,
    REGISTRY,
    SECRET_KEY_RE,
    TestCaseSpec,
    VALID_FEATURES,
    VALID_TIERS,
    FeatureNotImplementedError,
    e2e_test,
    encode_native_frame,
    ensure_binaries_built,
    ensure_vm_temp_root,
    get_registered_tests,
    read_native_frame,
    register_test,
)

__all__ = [
    "CHROMIUM_EXT_ORIGIN",
    "CLIResult",
    "E2EContext",
    "FIREFOX_EXT_ID",
    "FeatureNotImplementedError",
    "ISSUED_TOKEN_RE",
    "NativeProbeResult",
    "PTYResult",
    "RECOVERY_KIT_RE",
    "REGISTRY",
    "SECRET_KEY_RE",
    "TestCaseSpec",
    "VALID_FEATURES",
    "VALID_TIERS",
    "e2e_test",
    "encode_native_frame",
    "ensure_binaries_built",
    "ensure_vm_temp_root",
    "get_registered_tests",
    "read_native_frame",
    "register_test",
]
