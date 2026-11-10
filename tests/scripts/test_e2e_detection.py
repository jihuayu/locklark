"""Regression tests for stale/over-permissive E2E feature detection."""

from __future__ import annotations

import json
import hashlib
import http.client
import os
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.e2e.harness import CLIResult, FeatureNotImplementedError  # noqa: E402
from tests.e2e import harness, support  # noqa: E402


class FakeContext:
    def __init__(
        self,
        responses: dict[tuple[str, ...], tuple[int, str, str]],
        repo_root: Path | None = None,
        extension_dir: Path | None = None,
        node_result: tuple[int, str, str] | None = None,
        go_result: tuple[int, str, str] | None = None,
    ):
        self.responses = responses
        self.calls: list[tuple[str, ...]] = []
        self.repo_root = repo_root or Path(".")
        self.extension_dir = extension_dir
        self.node_result = node_result
        self.go_result = go_result

    def ensure_extension_built(self) -> tuple[Path, Path]:
        if self.extension_dir is None:
            raise AssertionError("this fake context ships no built extension")
        return self.extension_dir, self.extension_dir

    def run_cli(self, args, **_: object) -> CLIResult:
        key = tuple(str(arg) for arg in args)
        self.calls.append(key)
        if key[0] == "--test" and self.node_result is not None:
            rc, stdout, stderr = self.node_result
            return CLIResult(rc, stdout, stderr, list(key))
        if key[0] == "test" and self.go_result is not None:
            rc, stdout, stderr = self.go_result
            return CLIResult(rc, stdout, stderr, list(key))
        rc, stdout, stderr = self.responses.get(
            key, (1, "", "unknown command; see locklark help")
        )
        return CLIResult(rc, stdout, stderr, list(key))


def _profiles_json() -> str:
    entries = [
        {
            "name": name,
            "id": profile_id,
            "slots": (
                [
                    {"name": "access_key_id", "kind": "login", "field": "username"},
                    {"name": "secret_access_key", "kind": "login", "field": "password"},
                ]
                if name == "aws"
                else [{"name": "token", "kind": "login", "field": "password"}]
            ),
            "max_timeout": 300,
        }
        for name, profile_id in support.F14_REQUIRED_PROFILES.items()
    ]
    return json.dumps(entries)


TOP_HELP = (
    "  cli profiles\n"
    "  cli list [--binding PATH]\n"
    "  cli shell-init [bash|zsh|fish|powershell|pwsh] [--binding PATH]\n"
    "  cli run <tool> [--binding PATH] [--cwd ABS_DIR] [--timeout SECONDS] -- [ARG...]\n"
)
RUN_HELP = (
    "usage: locklark cli run <tool> [--binding PATH] [--cwd ABS_DIR] "
    "[--timeout SECONDS] -- [ARG...]\n"
)
SHELL_SCRIPT = (
    "# Locklark CLI wrappers (bash/zsh)\n"
    'gh() {\n  command "/opt/locklark" cli run gh -- "$@"\n}\n'
)


class F14DetectionTests(unittest.TestCase):
    def test_structured_profiles_detect_capability_with_empty_binding_store(self):
        ctx = FakeContext(
            {
                ("help",): (0, TOP_HELP, ""),
                ("cli", "profiles"): (0, _profiles_json(), ""),
                ("cli", "list"): (0, '{"version":1,"bindings":{}}', ""),
            }
        )
        self.assertTrue(support.f14_cli_profiles_ready(ctx))
        self.assertNotIn(("cli", "list"), ctx.calls)

    def test_malformed_profiles_are_a_failure_not_absence(self):
        ctx = FakeContext(
            {
                ("help",): (0, TOP_HELP, ""),
                ("cli", "profiles"): (0, '{"profiles":[]}', ""),
            }
        )
        with self.assertRaisesRegex(AssertionError, "JSON list"):
            support.f14_cli_profiles_ready(ctx)

    def test_nonzero_advertised_profiles_is_a_failure_not_absence(self):
        ctx = FakeContext(
            {
                ("help",): (0, TOP_HELP, ""),
                ("cli", "profiles"): (1, "", "profile registry broken"),
            }
        )
        with self.assertRaisesRegex(AssertionError, "advertised"):
            support.f14_cli_profiles_ready(ctx)

    def test_missing_profiles_command_is_real_absence(self):
        ctx = FakeContext({("help",): (0, "locklark help\n", "")})
        self.assertFalse(support.f14_cli_profiles_ready(ctx))
        self.assertNotIn(("cli", "profiles"), ctx.calls)


class F15DetectionTests(unittest.TestCase):
    def test_public_run_contract_detected_without_internal_identifiers(self):
        ctx = FakeContext(
            {
                ("help",): (0, TOP_HELP, ""),
                ("cli", "profiles"): (0, _profiles_json(), ""),
                ("cli", "run", "--help"): (0, RUN_HELP, ""),
            }
        )
        self.assertTrue(support.f15_run_bundle_ready(ctx))
        self.assertNotIn("RunBundle", RUN_HELP)

    def test_broken_advertised_run_help_is_a_failure(self):
        ctx = FakeContext(
            {
                ("help",): (0, TOP_HELP, ""),
                ("cli", "profiles"): (0, _profiles_json(), ""),
                ("cli", "run", "--help"): (0, "usage: unrelated\n", ""),
            }
        )
        with self.assertRaisesRegex(AssertionError, "missing public options"):
            support.f15_run_bundle_ready(ctx)

    def test_missing_run_command_is_real_absence(self):
        ctx = FakeContext({("help",): (0, "  cli profiles\n", "")})
        self.assertFalse(support.f15_run_bundle_ready(ctx))


class F16DetectionTests(unittest.TestCase):
    def _ctx(self, shell: tuple[int, str, str]) -> FakeContext:
        return FakeContext(
            {
                ("help",): (0, TOP_HELP, ""),
                ("cli", "shell-init", "bash"): shell,
            }
        )

    def test_function_and_forwarded_arguments_detect_shell_capability(self):
        self.assertTrue(support.f16_cli_shell_ready(self._ctx((0, SHELL_SCRIPT, ""))))

    def test_successful_but_malformed_shell_init_is_a_failure(self):
        with self.assertRaisesRegex(AssertionError, "gh function"):
            support.f16_cli_shell_ready(self._ctx((0, "# no functions\n", "")))

    def test_nonzero_advertised_shell_init_is_a_failure(self):
        with self.assertRaisesRegex(AssertionError, "advertised"):
            support.f16_cli_shell_ready(self._ctx((1, "", "broken shell renderer")))

    def test_missing_shell_init_is_real_absence(self):
        ctx = FakeContext({("help",): (0, "  cli profiles\n", "")})
        self.assertFalse(support.f16_cli_shell_ready(ctx))


class PasskeyManagementDetectionTests(unittest.TestCase):
    def _ctx(self, extension: bool, native: bool) -> FakeContext:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        files = {
            "browser-extension/core.js": "passkey-management-v1" if extension else "passkey-v1",
            "internal/browserhost/types_v2.go": "passkey-management-v1" if native else "passkey-v1",
            "internal/browserhost/protocol.go": '"passkey-remove"' if native else '"passkey-get"',
        }
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return FakeContext({}, repo_root=root, extension_dir=root / "browser-extension")

    def test_extension_without_native_management_is_absent(self):
        self.assertFalse(support.f2_passkey_management_ready(self._ctx(True, False)))

    def test_native_without_extension_management_is_absent(self):
        self.assertFalse(support.f2_passkey_management_ready(self._ctx(False, True)))

    def test_both_protocol_surfaces_enable_component_contracts(self):
        self.assertTrue(support.f2_passkey_management_ready(self._ctx(True, True)))


class F17DetectionTests(unittest.TestCase):
    def _ctx(self, files: dict[str, str]) -> FakeContext:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return FakeContext(
            {
                ("help",): (0, TOP_HELP, ""),
                ("cli", "profiles"): (0, _profiles_json(), ""),
            },
            repo_root=root,
        )

    def test_desktop_broker_without_cli_client_stays_pending(self):
        ctx = self._ctx(
            {"internal/desktop/ipc_broker.go": "startBrowserBroker handleCLIRun"}
        )
        self.assertTrue(support.desktop_broker_implemented(ctx))
        self.assertFalse(support.cli_broker_client_implemented(ctx))
        self.assertFalse(support.f17_broker_ready(ctx))

    def test_broker_and_cli_client_enable_capability(self):
        ctx = self._ctx(
            {
                "internal/desktop/ipc_broker.go": "startBrowserBroker handleCLIRun",
                "cmd/locklark/cli.go": "RequestCLIRun",
            }
        )
        self.assertTrue(support.f17_broker_ready(ctx))


class CoverageMetadataTests(unittest.TestCase):
    def _register(self, test_id, tier, summary, **kwargs):
        fn = lambda ctx: None
        harness.register_test(test_id, tier, ["F1"], summary, **kwargs)(fn)
        self.addCleanup(lambda: harness.REGISTRY.pop(test_id, None))
        return harness.REGISTRY[test_id]

    def test_tier3_and_tier4_default_to_capability_probe(self):
        self.assertEqual(
            self._register("UNIT_COV_T3", 3, "journey wording").coverage_kind,
            "capability_probe",
        )
        self.assertEqual(
            self._register("UNIT_COV_T4", 4, "journey wording").coverage_kind,
            "capability_probe",
        )

    def test_capability_probe_summary_prefix_marks_source_only_case(self):
        self.assertEqual(
            self._register("UNIT_COV_PROBE", 1, "Capability probe: source contract").coverage_kind,
            "capability_probe",
        )
        self.assertEqual(
            self._register("UNIT_COV_FUNC", 1, "real user journey").coverage_kind,
            "functional",
        )

    def test_component_contract_coverage_kind_is_accepted(self):
        self.assertEqual(
            self._register(
                "UNIT_COV_COMPONENT", 1, "executed component test", coverage_kind="component_contract"
            ).coverage_kind,
            "component_contract",
        )

    def test_invalid_coverage_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            self._register("UNIT_COV_BAD", 1, "x", coverage_kind="claims")


class AutoLoginDetectionTests(unittest.TestCase):
    """F1/F2 auto-submit probes must use the shipped ``autoLogin`` contract."""

    def _ctx(self, files: dict[str, str]) -> FakeContext:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        extension = root / "browser-extension"
        (extension / "test").mkdir(parents=True)
        for name, body in files.items():
            (extension / name).write_text(body, encoding="utf-8")
        return FakeContext(
            {("help",): (0, "locklark help\n", "")},
            repo_root=root,
            extension_dir=extension,
        )

    def test_real_auto_login_contract_is_detected(self):
        ctx = self._ctx(
            {
                "background.js": "let autoLogin = true; const loginOverrides = {};",
                "content.js": "",
                "core.js": "if (autoLogin === true) form.requestSubmit();",
                "popup.js": "state.autoLogin",
                "options.js": '"opt-auto-login": "autoLogin"',
            }
        )
        self.assertTrue(support.f2_autologin_ready(ctx))
        self.assertTrue(support.f1_autosubmit_ready(ctx))

    def test_stale_auto_submit_literal_is_not_evidence(self):
        # A bundle carrying only the retired literal would make the old adapter
        # pass; the real probe must report absence (a FAIL), never a scenario
        # where a nonexistent identifier proves the feature shipped.
        ctx = self._ctx(
            {
                "background.js": "// legacy autoSubmit comment only",
                "content.js": "",
                "core.js": "// autoSubmit was never a real identifier",
                "popup.js": "",
                "options.js": "",
            }
        )
        self.assertFalse(support.f2_autologin_ready(ctx))
        self.assertFalse(support.f1_autosubmit_ready(ctx))


class F11FillContractDetectionTests(unittest.TestCase):
    """F11 probes must execute the shipped fill contract, not the CLI surface."""

    M3_TEST = "browser-extension/test/m3_fill_v2.test.js"

    def _ctx(self, core: str, **kwargs: object) -> FakeContext:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        extension = root / "browser-extension"
        (extension / "test").mkdir(parents=True)
        (extension / "test" / "m3_fill_v2.test.js").write_text(
            "// M3 component contract\n", encoding="utf-8"
        )
        (extension / "core.js").write_text(core, encoding="utf-8")
        (extension / "content.js").write_text(core, encoding="utf-8")
        return FakeContext(
            {("help",): (0, "locklark help\n", "")},
            repo_root=root,
            extension_dir=extension,
            **kwargs,
        )

    def test_identity_and_card_fill_detected_while_cli_add_item_is_absent(self):
        ctx = self._ctx(
            "exports.fillIdentityDocument = autofillDocument;"
            "exports.fillCardDocument = autofillDocument; // credit_card"
        )
        # The CLI command-surface gap is real...
        self.assertFalse(support.f11_identity_ready(ctx))
        # ...but it is not evidence that identity/card fill is missing.
        self.assertTrue(support.f11_fill_contract_ready(ctx))

    def test_missing_fill_entrypoints_are_real_absence(self):
        ctx = self._ctx("// content script without any fill contract")
        self.assertFalse(support.f11_fill_contract_ready(ctx))

    def test_node_pattern_that_selects_no_tests_is_a_failure(self):
        ctx = self._ctx(
            "fillIdentityDocument fillCardDocument credit_card",
            node_result=(
                0,
                "\u2139 tests 4\n\u2139 pass 0\n\u2139 fail 0\n\u2139 skipped 4\n",
                "",
            ),
        )
        with self.assertRaises(AssertionError) as caught:
            support.node_test_pattern(ctx, self.M3_TEST, "M3 renamed test", min_passed=1)
        self.assertIn("stale adapter", str(caught.exception))
        self.assertNotIsInstance(caught.exception, FeatureNotImplementedError)

    def test_failing_component_test_is_a_failure_not_a_missing_feature(self):
        ctx = self._ctx(
            "fillIdentityDocument fillCardDocument credit_card",
            node_result=(
                1,
                "\u2716 M3 fillIdentityDocument fills identity inputs and selects\n"
                "\u2139 tests 1\n\u2139 pass 0\n\u2139 fail 1\n",
                "",
            ),
        )
        with self.assertRaises(AssertionError) as caught:
            support.node_test_pattern(ctx, self.M3_TEST, "M3 fillIdentityDocument", min_passed=1)
        self.assertNotIsInstance(caught.exception, FeatureNotImplementedError)

    def test_selected_component_tests_are_counted(self):
        ctx = self._ctx(
            "fillIdentityDocument fillCardDocument credit_card",
            node_result=(
                0,
                "\u2139 tests 3\n\u2139 pass 2\n\u2139 fail 0\n\u2139 skipped 1\n",
                "",
            ),
        )
        counts = support.node_test_pattern(ctx, self.M3_TEST, "M3 fill", min_passed=2)
        self.assertEqual(counts["pass"], 2)
        self.assertEqual(ctx.calls[0][0], "--test")
        self.assertTrue(ctx.calls[0][1].startswith("--test-name-pattern="))


class F13HostWatchtowerDetectionTests(unittest.TestCase):
    """F13 must separate CLI health flags from the shipped Watchtower service."""

    def _ctx(self, files: dict[str, str], *, help_text: str = "locklark help\n") -> FakeContext:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for relative, body in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        extension = root / "browser-extension"
        extension.mkdir(parents=True, exist_ok=True)
        return FakeContext(
            {("help",): (0, help_text, "")}, repo_root=root, extension_dir=extension
        )

    def test_host_watchtower_detected_without_cli_health_flags(self):
        ctx = self._ctx(
            {
                "internal/watchtower/watchtower.go": (
                    'type Finding struct { UnsecuredHTTP bool `json:"unsecured_http"` }'
                )
            }
        )
        self.assertTrue(support.f13_watchtower_ready(ctx))
        self.assertFalse(support.f13_cli_health_flags(ctx))

    def test_help_flags_alone_do_not_prove_the_hibp_client(self):
        # The old `--check-breached`/`--hibp-endpoint` probes are stale; the
        # landed option is the literal `--hibp true` pair advertised by the
        # personal help surface.
        ctx = self._ctx(
            {},
            help_text="locklark help\n  health --file PATH [--hibp true]\n",
        )
        self.assertTrue(support.f13_cli_health_flags(ctx))
        self.assertFalse(support.f13_hibp_client_ready(ctx))
        self.assertFalse(support.f13_watchtower_ready(ctx))

    def test_old_health_flags_are_not_evidence_of_the_landed_contract(self):
        ctx = self._ctx(
            {},
            help_text="locklark help\n  --check-breached\n  --hibp-endpoint URL\n",
        )
        self.assertFalse(support.f13_cli_health_flags(ctx))
        self.assertFalse(support.f13_hibp_client_ready(ctx))

    def test_hibp_client_contract_detected_in_host_sources(self):
        ctx = self._ctx(
            {
                "internal/watchtower/hibp.go": (
                    'DefaultHIBPEndpoint = "https://api.pwnedpasswords.com/range/"\n'
                    "var hibpPrefix = regexp.MustCompile(...)\n"
                    "func (c *HIBPClient) LookupCandidates(...)\n"
                ),
                "internal/browserhost/protocol.go": (
                    'IncludeHIBP bool `json:"include_hibp"`'
                ),
            }
        )
        self.assertTrue(support.f13_hibp_client_ready(ctx))

    def test_go_package_test_requires_executed_tests(self):
        ctx = self._ctx({"go.mod": "module example.test\n"})
        ctx.go_result = (0, "ok  example.test/internal/watchtower  0.01s\n", "")
        with mock.patch.object(support, "go_tool", lambda: "/usr/bin/go"):
            with self.assertRaises(AssertionError) as caught:
                support.go_package_test(ctx, "./internal/watchtower", "TestRenamed")
            self.assertIn("stale adapter", str(caught.exception))
            self.assertNotIsInstance(caught.exception, FeatureNotImplementedError)
            ctx.go_result = (
                0,
                "=== RUN   TestLookupCandidatesGroupsPrefixes\n"
                "--- PASS: TestLookupCandidatesGroupsPrefixes (0.00s)\n"
                "PASS\nok  example.test/internal/watchtower  0.01s\n",
                "",
            )
            counts = support.go_package_test(
                ctx, "./internal/watchtower", "TestLookupCandidatesGroupsPrefixes"
            )
        self.assertEqual(counts["pass"], 1)

    def test_missing_go_toolchain_is_a_blocked_assertion(self):
        ctx = self._ctx({"go.mod": "module example.test\n"})
        with mock.patch.object(support, "go_tool", lambda: None):
            with self.assertRaisesRegex(AssertionError, "validation blocked"):
                support.go_package_test(ctx, "./internal/watchtower", "TestAnything")


class F13CLIHIBPDetectionTests(unittest.TestCase):
    """#103: the opt-in gate is the literal `--hibp true` pair, not old flags."""

    def _ctx(self, responses: dict[tuple[str, ...], tuple[int, str, str]]) -> FakeContext:
        return FakeContext(responses)

    def test_personal_help_hibp_pair_detected(self):
        ctx = self._ctx(
            {
                ("help",): (0, "locklark help\n", ""),
                ("personal", "help"): (0, "  health --file PATH [--hibp true]\n", ""),
            }
        )
        self.assertTrue(support.f13_cli_health_flags(ctx))

    def test_health_help_is_read_even_when_it_exits_non_zero(self):
        ctx = self._ctx(
            {
                ("help",): (0, "locklark help\n", ""),
                ("personal", "help"): (0, "usage: locklark personal\n", ""),
                ("personal", "health", "--help"): (
                    1,
                    "usage: locklark personal health --file PATH [--hibp true]\n",
                    "",
                ),
            }
        )
        self.assertTrue(support.f13_cli_health_flags(ctx))

    def test_stale_check_breached_and_endpoint_flags_are_not_evidence(self):
        ctx = self._ctx(
            {
                ("help",): (0, "  --check-breached\n  --hibp-endpoint URL\n", ""),
                ("personal", "help"): (0, "usage: locklark personal\n", ""),
            }
        )
        self.assertFalse(support.f13_cli_health_flags(ctx))

    def test_bare_hibp_without_true_is_not_the_landed_contract(self):
        ctx = self._ctx(
            {
                ("help",): (0, "locklark help\n", ""),
                ("personal", "help"): (0, "  health --file PATH [--hibp]\n", ""),
            }
        )
        self.assertFalse(support.f13_cli_health_flags(ctx))

    def test_loopback_proxy_answers_both_prefixes_independently(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is required for the loopback HIBP proxy")
        ctx = mock.Mock()
        ctx.temp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, ctx.temp_dir, True)

        breached = "Synthetic-Breached-Pass!2026"
        clean = "Synthetic-Clean-Pass!2026-Xy9"
        breached_hash = hashlib.sha1(breached.encode("utf-8")).hexdigest().upper()
        clean_hash = hashlib.sha1(clean.encode("utf-8")).hexdigest().upper()
        responses = {
            breached_hash[:5]: ((breached_hash[5:], 2),),
            clean_hash[:5]: (),
        }

        proxy = support.local_hibp_range_proxy(ctx, responses)
        self.addCleanup(proxy.close)
        tls = ssl.create_default_context(cafile=str(proxy.cert))
        bodies: dict[str, str] = {}
        for prefix in responses:
            conn = http.client.HTTPSConnection(
                "127.0.0.1", proxy.proxy_port, context=tls, timeout=15
            )
            conn.set_tunnel(support.HIBP_FIXED_HOST, support.HIBP_HTTPS_PORT)
            conn.request("GET", f"/range/{prefix}", headers={"Add-Padding": "true"})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            bodies[prefix] = response.read().decode("ascii")
            conn.close()

        # The child environment only adds the loopback proxy and throwaway
        # trust anchor: no hosts/DNS edit, no port 443 listener, no root.
        self.assertEqual(
            proxy.env["HTTPS_PROXY"], f"http://127.0.0.1:{proxy.proxy_port}"
        )
        self.assertEqual(proxy.env["https_proxy"], proxy.env["HTTPS_PROXY"])
        self.assertEqual(proxy.env["NO_PROXY"], "")
        self.assertEqual(proxy.env["no_proxy"], "")
        self.assertNotEqual(proxy.proxy_port, 443)
        self.assertNotEqual(proxy.port, 443)

        records = {record["prefix"]: record for record in proxy.requests}
        self.assertEqual(set(records), set(responses))
        for prefix, expected_lines in responses.items():
            served = tuple(
                (line["suffix"], line["count"])
                for line in records[prefix]["suffixes"]
            )
            self.assertEqual(served, expected_lines)
            self.assertEqual(records[prefix]["body"], bodies[prefix])
            for suffix, count in expected_lines:
                self.assertIn(f"{suffix}:{count}\r\n", bodies[prefix])
            self.assertTrue(bodies[prefix].endswith("0" * 35 + ":0\r\n"))
        # Independent answers: the clean prefix must not receive the breached
        # suffix or its count.
        self.assertNotEqual(
            bodies[breached_hash[:5]], bodies[clean_hash[:5]]
        )
        self.assertNotIn(breached_hash[5:], bodies[clean_hash[:5]])

        # Any other CONNECT target is refused; only the fixed host is opened.
        refused = http.client.HTTPSConnection(
            "127.0.0.1", proxy.proxy_port, context=tls, timeout=15
        )
        refused.set_tunnel("example.test", 443)
        with self.assertRaises(OSError):
            refused.request("GET", "/")
        self.assertIn("example.test:443", proxy.refused)

    def test_route_that_never_reaches_the_proxy_is_pending_not_a_pass(self):
        # No CONNECT ever arrived: the outcome must be "pending" so the caller
        # reports PENDING_FEATURE, never PASS or a silent success.
        ctx = mock.Mock()
        ctx.temp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, ctx.temp_dir, True)

        class DummyProxy:
            def __init__(self) -> None:
                self.connections: list[str] = []
                self.requests: list[dict[str, object]] = []
                self.refused: list[str] = []
                self.env = {"HTTPS_PROXY": "http://127.0.0.1:1"}

            def close(self) -> None:
                pass

        ctx.run_pty_cli.return_value = support.PTYResult(
            1,
            "",
            "HIBP network check cancelled",
            [],
            True,
        )
        with mock.patch.object(
            support, "local_hibp_range_proxy", lambda _ctx, _responses: DummyProxy()
        ):
            observed = support.f13_cli_hibp_range_lookups(
                ctx, {"path": "vault.ll", "password": "p", "secret": "s"}, {"ABCDE": ()}
            )
        self.assertEqual(observed["status"], "pending")
        self.assertEqual(observed["connections"], [])

    def _declined_opt_in(self, before, after):
        ctx = mock.Mock()
        ctx.run_cli.return_value = CLIResult(
            1, "", "usage: locklark personal health --file PATH [--hibp true]", []
        )
        declined = support.PTYResult(
            1,
            "",
            "输入 NETWORK 确认联网查询泄露前缀\r\nHIBP network check cancelled\r\n",
            [],
            True,
        )
        with (
            mock.patch.object(support, "f13_cli_health_flags", return_value=True),
            mock.patch.object(support, "audit_events", side_effect=[before, after]),
            mock.patch.object(support, "pty", return_value=declined),
        ):
            observed = support.f13_cli_hibp_opt_in(
                ctx, {"path": "vault.ll", "password": "p", "secret": "s"}
            )
        return ctx, observed

    def test_declined_consent_delta_ignores_audit_list_noise(self):
        before = [{"action": "vault.create"}, {"action": "audit.list"}]
        after = before + [{"action": "audit.list"}]
        ctx, observed = self._declined_opt_in(before, after)
        self.assertEqual(observed["declined_rc"], 1)
        self.assertEqual(observed["declined_error"], "HIBP network check cancelled")
        self.assertEqual(observed["audit_delta"], [])
        ctx.require_feature.assert_called_once()
        self.assertTrue(ctx.require_feature.call_args.args[1])

    def test_declined_consent_rejects_any_unlock_or_hibp_audit_increment(self):
        before = [{"action": "vault.create"}, {"action": "audit.list"}]
        after = before + [
            {"action": "audit.list"},
            {"action": "desktop.unlock"},
        ]
        with self.assertRaisesRegex(AssertionError, "wrote audit events"):
            self._declined_opt_in(before, after)


class PyKeePassExportDetectionTests(unittest.TestCase):
    def test_reader_keeps_export_password_off_argv_and_projects_entries(self):
        projection = [
            {
                "title": "Corp SSO",
                "username": "alice",
                "password": "P@ssw0rd-2026",
                "url": "https://sso.corp.example.test/login",
                "notes": "",
            }
        ]
        proc = mock.Mock(returncode=0, stdout=json.dumps(projection).encode(), stderr=b"")
        with (
            mock.patch.object(support, "pykeepass_peer", return_value="/peer/python"),
            mock.patch.object(support.subprocess, "run", return_value=proc) as run,
        ):
            entries = support.read_kdbx_entries(
                Path("/tmp/export.kdbx"), "export-pass-2026"
            )
        self.assertEqual(entries, projection)
        argv = run.call_args.args[0]
        self.assertNotIn("export-pass-2026", argv)
        self.assertEqual(
            json.loads(run.call_args.kwargs["input"]),
            {"password": "export-pass-2026"},
        )
        self.assertEqual(argv[0], "/peer/python")
        self.assertIn("from pykeepass import PyKeePass", argv[2])

    def test_missing_pykeepass_peer_is_a_blocked_assertion(self):
        with mock.patch.object(support, "pykeepass_peer", return_value=None):
            with self.assertRaisesRegex(AssertionError, "validation blocked"):
                support.read_kdbx_entries(Path("/tmp/export.kdbx"), "export-pass-2026")


class F11CardFillAuthorizationDetectionTests(unittest.TestCase):
    """T2_F11_05 is a component explicit-authorization contract.

    It must not be described as page-load wiring evidence.
    """

    def _core(self) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        path = root / "core.js"
        path.write_text(
            "module.exports = { fillCardDocument: function (origin, data) "
            "{ return false; } };\n",
            encoding="utf-8",
        )
        return path

    def _run(self, harness_body: str) -> dict[str, object]:
        ctx = mock.Mock()
        ctx.temp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, ctx.temp_dir, True)
        ctx.repo_root = ROOT
        ctx.run_cli.return_value = CLIResult(
            0, json.dumps({"beforeAuthorization": ["", "", "", ""]}), "", []
        )
        return support.card_fill_explicit_authorization_component(ctx, self._core())

    def test_harness_is_executed_against_the_built_bundle(self):
        observed = self._run("")
        self.assertEqual(observed["beforeAuthorization"], ["", "", "", ""])

    def test_pty_result_is_exported_for_detection_tests(self):
        self.assertTrue(hasattr(support, "PTYResult"))


class F5RefreshDetectionTests(unittest.TestCase):
    """F5 must probe the real captureFilter/filterCurrent contract."""

    def _ctx(self, app_source: str) -> FakeContext:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        desktop = root / "internal" / "desktop"
        desktop.mkdir(parents=True)
        (desktop / "app.go").write_text(app_source, encoding="utf-8")
        return FakeContext({("help",): (0, "locklark help\n", "")}, repo_root=root)

    MODERN = (
        "func (a *App) refresh() {\n"
        "\tfilter := a.captureFilter()\n"
        "\ta.run(func() outcome {\n"
        "\t\trows, e := queryRows(s, filter)\n"
        "\t\tif !a.filterCurrent(filter) { return }\n"
        "\t})\n"
        "}\n"
        "clipboardTimer = time.AfterFunc"
    )

    def test_query_and_scope_capture_contract_is_detected(self):
        ctx = self._ctx(self.MODERN)
        self.assertTrue(support.f5_desktop_timer_ready(ctx))
        self.assertTrue(support.f5_filter_refresh_ready(ctx))

    def test_old_refresh_regex_shape_is_not_accepted(self):
        ctx = self._ctx(
            "func (a *App) refresh() {\n"
            "\t// a.query was only mentioned here in the retired shape\n"
            "}\n"
            "clipboardTimer = time.AfterFunc"
        )
        self.assertTrue(support.f5_desktop_timer_ready(ctx))
        self.assertFalse(support.f5_filter_refresh_ready(ctx))


class NativeRelayLifecycleTests(unittest.TestCase):
    """Native-host probes must mirror a real browser pipe and reap their group."""

    def _script(self, body: str) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        path = root / "fake_host.py"
        path.write_text(body, encoding="utf-8")
        return path

    def _spawn(self, script: Path, *args: str, new_session: bool = True) -> subprocess.Popen:
        proc = subprocess.Popen(
            [sys.executable, str(script), *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=new_session,
        )
        if new_session:
            self.addCleanup(harness.terminate_process_group, proc, owned_group=proc.pid)

        def close_pipes() -> None:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except (OSError, ValueError):
                    pass

        self.addCleanup(close_pipes)
        return proc

    def test_first_frame_detection_requires_a_complete_frame(self):
        body = b'{"type":"error","error":"refused"}'
        frame = struct.pack("=I", len(body)) + body
        self.assertIsNone(harness.first_native_frame_end(b""))
        self.assertIsNone(harness.first_native_frame_end(b"\x00\x00"))
        self.assertIsNone(harness.first_native_frame_end(frame[:-1]))
        self.assertEqual(harness.first_native_frame_end(frame), len(frame))
        self.assertIsNone(harness.first_native_frame_end(b"\x00\x00\x00\x00"))

    def test_reply_wait_keeps_stdin_open_until_the_framed_answer(self):
        # Races the reply against an early stdin EOF: if the harness closed
        # stdin immediately (communicate semantics), the host exits without a
        # frame and this test fails.
        script = self._script(
            "import json, select, struct, sys, time\n"
            "header = sys.stdin.buffer.read(4)\n"
            "length = struct.unpack('=I', header)[0]\n"
            "sys.stdin.buffer.read(length)\n"
            "ready, _, _ = select.select([sys.stdin], [], [], 0.3)\n"
            "if ready:\n"
            "    sys.exit(0)\n"
            "body = json.dumps({'type': 'error', 'error': 'refused', 'id': '9' * 32}).encode()\n"
            "sys.stdout.buffer.write(struct.pack('=I', len(body)) + body)\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(1.5)\n"
            "sys.stdin.buffer.read()\n"
        )
        proc = self._spawn(script)
        raw = harness.encode_native_frame(
            {
                "v": 1,
                "id": "9" * 32,
                "type": "match",
                "capability": "a" * 32,
                "origin": "https://login.example.test",
                "tab_id": 1,
                "document_id": "doc-1",
            }
        )
        stdout, _stderr, timed_out = harness.relay_first_frame(proc, raw, timeout=10.0)
        self.assertFalse(timed_out)
        self.assertEqual(harness.first_native_frame_end(stdout), len(stdout))
        self.assertIn(b'"refused"', stdout)
        self.assertIsNotNone(proc.poll())

    def test_early_wrapper_exit_with_sigterm_ignoring_descendant_stays_bounded(self):
        script = self._script(
            "import subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])\n"
            "open(sys.argv[1], 'w').write(str(child.pid))\n"
        )
        pid_file = script.parent / "child.pid"
        proc = self._spawn(script, str(pid_file))
        for _ in range(100):
            if pid_file.is_file() and pid_file.read_text().strip():
                break
            time.sleep(0.05)
        child = int(pid_file.read_text().strip())
        for _ in range(100):
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        self.assertIsNotNone(proc.poll(), "wrapper should have exited")
        raw = harness.encode_native_frame({"v": 1, "id": "8" * 32, "type": "match"})
        started = time.monotonic()
        _stdout, _stderr, timed_out = harness.relay_first_frame(
            proc, raw, timeout=1.0, grace=2.0
        )
        self.assertLess(time.monotonic() - started, 8.0)
        self.assertTrue(timed_out)
        state = ""
        for _ in range(100):
            try:
                state = Path(f"/proc/{child}/stat").read_text().split()[2]
            except OSError:
                state = "gone"
                break
            if state == "Z":
                break
            time.sleep(0.05)
        self.assertIn(state, ("Z", "gone"), f"descendant {child} survived teardown")

    def test_process_group_teardown_reaps_the_whole_session(self):
        script = self._script(
            "import subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "open(sys.argv[1], 'w').write(str(child.pid))\n"
            "time.sleep(60)\n"
        )
        pid_file = script.parent / "grandchild.pid"
        proc = self._spawn(script, str(pid_file))
        for _ in range(100):
            if pid_file.is_file() and pid_file.read_text().strip():
                break
            time.sleep(0.05)
        grandchild = int(pid_file.read_text().strip())
        harness.terminate_process_group(proc, grace=3.0, owned_group=proc.pid)
        self.assertIsNotNone(proc.poll())
        state = ""
        for _ in range(100):
            try:
                state = Path(f"/proc/{grandchild}/stat").read_text().split()[2]
            except OSError:
                state = "gone"
                break
            if state == "Z":
                break
            time.sleep(0.05)
        self.assertIn(state, ("Z", "gone"), f"grandchild {grandchild} survived teardown")

    def test_group_ownership_guard_never_signals_an_unowned_group(self):
        # A sibling in our own group must survive: only a group whose id equals
        # the launched pid (explicit start_new_session ownership) is signalled.
        sibling_script = self._script("import time\ntime.sleep(60)\n")
        sibling = subprocess.Popen(
            [sys.executable, str(sibling_script)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: (sibling.poll() is None and sibling.kill(), sibling.wait()))
        plain = self._spawn(self._script("import time\ntime.sleep(60)\n"), new_session=False)
        self.assertNotEqual(os.getpgid(plain.pid), plain.pid)
        harness.terminate_process_group(plain, grace=2.0)
        self.assertIsNotNone(plain.poll())
        self.assertIsNone(sibling.poll(), "unowned sibling process was signalled")

    def test_native_probe_forwards_the_explicit_reply_wait(self):
        recorded: dict[str, object] = {}

        class ProbeContext:
            def probe_native_host_frame(self, frame, **kwargs):
                recorded.update(kwargs)
                recorded["frame"] = frame
                return "probe"

        frame = {"v": 1, "id": "7" * 32, "type": "match"}
        self.assertEqual(
            support.native_probe(ProbeContext(), frame, timeout=4.0, await_reply=True),
            "probe",
        )
        self.assertTrue(recorded.get("await_reply"))
        self.assertEqual(recorded.get("timeout"), 4.0)
        support.native_probe(ProbeContext(), frame, timeout=4.0)
        self.assertFalse(recorded.get("await_reply"))


class GuiSessionWrappingTests(unittest.TestCase):
    """GUI launches own a private session and an exclusive host stdout pipe."""

    def _which(self, mapping: dict[str, str]):
        def fake(name: str):
            return mapping.get(name)

        return mock.patch.object(harness.shutil, "which", fake)

    def _assert_wrapped(self, command, *, dbus: bool, xvfb: bool, target: list[str]) -> None:
        self.assertEqual(command[0], "sh")
        self.assertEqual(command[1], "-c")
        self.assertEqual(command[2], harness.OWNED_SESSION_WRAPPER)
        self.assertEqual(command[3], "locklark-session")
        rest = command[4:]
        if dbus:
            self.assertEqual(rest[0], "/usr/bin/dbus-run-session")
            self.assertEqual(rest[1], "--")
            rest = rest[2:]
        if xvfb:
            self.assertEqual(rest[0], "/usr/bin/xvfb-run")
            self.assertEqual(rest[1:4], list(harness.XVFB_ARGS))
            rest = rest[4:]
        self.assertEqual(rest[0], "sh")
        self.assertEqual(rest[1], "-c")
        self.assertEqual(rest[2], harness.OWNED_TARGET_WRAPPER)
        self.assertEqual(rest[3], "locklark-native")
        self.assertEqual(rest[4:], target)

    def test_missing_bus_is_wrapped_with_owned_dbus_session(self):
        env = {"DISPLAY": "", "PATH": "/usr/bin"}
        target = ["/opt/locklark-browser-chromium", "origin"]
        with self._which(
            {"xvfb-run": "/usr/bin/xvfb-run", "dbus-run-session": "/usr/bin/dbus-run-session"}
        ):
            command = harness.owned_gui_command(target, env=env, use_xvfb=True)
        self._assert_wrapped(command, dbus=True, xvfb=True, target=target)

    def test_supplied_usable_bus_is_preserved(self):
        socket = Path(tempfile.mkdtemp()) / "bus"
        self.addCleanup(shutil.rmtree, socket.parent, ignore_errors=True)
        socket.touch()
        env = {
            "DISPLAY": ":99",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={socket}",
        }
        self.assertTrue(harness.session_bus_usable(env))
        with self._which(
            {"xvfb-run": "/usr/bin/xvfb-run", "dbus-run-session": "/usr/bin/dbus-run-session"}
        ):
            command = harness.owned_gui_command(["host"], env=env, use_xvfb=False)
        self.assertEqual(command, ["host"])

    def test_empty_bus_and_whitespace_display_are_treated_as_absent(self):
        self.assertFalse(harness.effective_display({"DISPLAY": "   "}))
        self.assertTrue(harness.effective_display({"DISPLAY": ":1"}))
        self.assertFalse(harness.session_bus_usable({"DBUS_SESSION_BUS_ADDRESS": "  "}))
        self.assertFalse(
            harness.session_bus_usable(
                {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/nonexistent/locklark-bus"}
            )
        )
        with self._which(
            {"xvfb-run": "/usr/bin/xvfb-run", "dbus-run-session": "/usr/bin/dbus-run-session"}
        ):
            command = harness.owned_gui_command(["host"], env={"DISPLAY": " "}, use_xvfb=True)
        self._assert_wrapped(command, dbus=True, xvfb=True, target=["host"])

    def test_missing_dbus_wrapper_is_a_validation_blocked_error(self):
        with self._which({"xvfb-run": "/usr/bin/xvfb-run"}):
            with self.assertRaisesRegex(AssertionError, "validation blocked"):
                harness.owned_gui_command(["host"], env={"DISPLAY": ""}, use_xvfb=True)

    def test_missing_xvfb_is_a_validation_blocked_error(self):
        with self._which({"dbus-run-session": "/usr/bin/dbus-run-session"}):
            with self.assertRaisesRegex(AssertionError, "validation blocked"):
                harness.owned_gui_command(["host"], env={}, use_xvfb=True)

    def test_service_stdout_noise_never_enters_the_native_frame_stream(self):
        # Fake dbus-run-session prints the kind of AT-SPI banner seen on CI
        # before exec'ing the rest of the chain: the frame stream must stay exact.
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        fake_dbus = root / "fake-dbus-run-session"
        fake_dbus.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'AT-SPI: accessibility service banner'\n"
            'if [ "$1" = -- ]; then shift; fi\n'
            'exec "$@"\n',
            encoding="utf-8",
        )
        fake_dbus.chmod(0o700)
        fake_xvfb = root / "fake-xvfb-run"
        fake_xvfb.write_text(
            # Match xvfb-run's three configured arguments and fd-3 closure.
            '#!/bin/sh\nshift 3\nexec "$@" 3>&-\n',
            encoding="utf-8",
        )
        fake_xvfb.chmod(0o700)
        host = root / "fake_host.py"
        host.write_text(
            "import json, struct, sys\n"
            "header = sys.stdin.buffer.read(4)\n"
            "length = struct.unpack('=I', header)[0]\n"
            "sys.stdin.buffer.read(length)\n"
            "body = json.dumps({'type': 'error', 'error': 'refused', 'id': '9' * 32}).encode()\n"
            "sys.stdout.buffer.write(struct.pack('=I', len(body)) + body)\n"
            "sys.stdout.buffer.flush()\n"
            "sys.stdin.buffer.read()\n",
            encoding="utf-8",
        )
        target = [sys.executable, str(host)]
        with self._which(
            {"xvfb-run": str(fake_xvfb), "dbus-run-session": str(fake_dbus)}
        ):
            command = harness.owned_gui_command(
                target, env={"DISPLAY": ""}, use_xvfb=True
            )
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.addCleanup(harness.terminate_process_group, proc, owned_group=proc.pid)
        raw = harness.encode_native_frame(
            {"v": 1, "id": "9" * 32, "type": "match", "tab_id": 1}
        )
        stdout, stderr, timed_out = harness.relay_first_frame(proc, raw, timeout=10.0)
        self.assertFalse(timed_out, stderr.decode("utf-8", "replace"))
        body = json.dumps({"type": "error", "error": "refused", "id": "9" * 32}).encode()
        expected = struct.pack("=I", len(body)) + body
        self.assertEqual(stdout, expected)
        self.assertNotIn(b"AT-SPI", stdout)
        self.assertIn(b"AT-SPI", stderr)


if __name__ == "__main__":
    unittest.main()
