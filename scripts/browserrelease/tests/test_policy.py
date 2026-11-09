"""Tests for the fixed manifest policy against real generated manifests."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from browserrelease import allowlist, build, manifestcheck, policy
from browserrelease.errors import ReleaseError
from browserrelease.tests import support

VERSION = "0.1.0"


class ManifestPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.root = support.make_root(Path(cls._temporary.name))
        cls.manifests = {}
        for product in allowlist.PRODUCTS:
            build.run_build(cls.root, product)
            generated = cls.root / "browser-extension" / "dist" / product
            cls.manifests[product] = json.loads(
                (generated / "manifest.json").read_text(encoding="utf-8")
            )

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def accepts(self, manifest, product):
        return manifestcheck.validate_manifest(manifest, product, VERSION)

    def refuses(self, manifest, product, version=VERSION):
        with self.assertRaises(ReleaseError):
            manifestcheck.validate_manifest(manifest, product, version)

    def test_accepts_every_real_product_manifest(self):
        for product in allowlist.PRODUCTS:
            with self.subTest(product=product):
                self.assertEqual(self.accepts(self.manifests[product], product), self.manifests[product])
                self.assertEqual(
                    self.manifests[product]["version"],
                    VERSION,
                )

    def test_refuses_a_version_that_differs_from_the_central_document(self):
        for product in allowlist.PRODUCTS:
            with self.subTest(product=product):
                self.refuses(self.manifests[product], product, "0.2.0")

    def test_refuses_extra_or_privileged_permissions(self):
        for product in allowlist.PRODUCTS:
            for extra in ("clipboardRead", "cookies", "identity", "tabs"):
                with self.subTest(product=product, extra=extra):
                    manifest = copy.deepcopy(self.manifests[product])
                    manifest["permissions"].append(extra)
                    self.refuses(manifest, product)
            with self.subTest(product=product, case="optional_permissions"):
                manifest = copy.deepcopy(self.manifests[product])
                manifest["optional_permissions"] = ["clipboardRead"]
                self.refuses(manifest, product)

    def test_refuses_a_missing_product_permission(self):
        manifest = copy.deepcopy(self.manifests["chromium"])
        manifest["permissions"].remove("contextMenus")
        self.refuses(manifest, "chromium")

    def test_refuses_forbidden_top_level_surfaces(self):
        for extra in ("externally_connectable", "oauth2", "sso"):
            with self.subTest(extra=extra):
                manifest = copy.deepcopy(self.manifests["chromium"])
                manifest[extra] = {"matches": ["https://*/*"]}
                self.refuses(manifest, "chromium")

    def test_refuses_changed_browser_identity(self):
        firefox = copy.deepcopy(self.manifests["firefox"])
        firefox["browser_specific_settings"]["gecko"]["id"] = "other@example.invalid"
        self.refuses(firefox, "firefox")
        firefox = copy.deepcopy(self.manifests["firefox"])
        firefox["browser_specific_settings"]["gecko"]["strict_min_version"] = "100.0"
        self.refuses(firefox, "firefox")
        chromium = copy.deepcopy(self.manifests["chromium"])
        chromium["key"] = "MIIBOgIBAAJBAK"
        self.refuses(chromium, "chromium")
        chromium = copy.deepcopy(self.manifests["chromium"])
        chromium["minimum_chrome_version"] = "100"
        self.refuses(chromium, "chromium")

    def test_safari_carries_no_chromium_or_gecko_identity(self):
        safari = copy.deepcopy(self.manifests["safari"])
        safari["key"] = allowlist.CHROMIUM_KEY
        self.refuses(safari, "safari")
        safari = copy.deepcopy(self.manifests["safari"])
        safari["browser_specific_settings"] = {
            "gecko": {"id": allowlist.FIREFOX_ID}
        }
        self.refuses(safari, "safari")
        self.assertEqual(
            policy.EXPECTED_BACKGROUND["safari"],
            {"scripts": ["safari-native-port.js", "core.js", "background.js"]},
        )

    def test_refuses_changed_content_script_policy(self):
        manifest = copy.deepcopy(self.manifests["chromium"])
        manifest["content_scripts"][1]["world"] = "ISOLATED"
        self.refuses(manifest, "chromium")
        manifest = copy.deepcopy(self.manifests["chromium"])
        manifest["content_scripts"][0]["all_frames"] = False
        self.refuses(manifest, "chromium")
        manifest = copy.deepcopy(self.manifests["chromium"])
        manifest["host_permissions"].append("http://*/*")
        self.refuses(manifest, "chromium")

    def test_refuses_unknown_product(self):
        self.refuses(self.manifests["chromium"], "edge")
