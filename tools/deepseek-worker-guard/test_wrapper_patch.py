"""Secret-free checks for the DSh worker-guard wrapper patch artifact.

The tests read ``deepseek_agent.py.patch`` next to this file and apply it, in
memory, to an inert snapshot of the unpatched ``patch_payload`` builder
embedded below.  They never import or execute the live wrapper, never read
credentials or environment variables, never start DSh, and never run a shell
or Git command.

Run with ``python3 tools/deepseek-worker-guard/test_wrapper_patch.py`` (the
hyphenated directory name is not a valid dotted module path).
"""

import ast
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PATCH_PATH = os.path.join(HERE, "deepseek_agent.py.patch")

WRAPPER_PATH = ("/Users/jihuayu/.local/share/rootyard-deepseek-skill-source-20261110"
                "/deepseek-subagent/scripts/deepseek_agent.py")

# Verbatim tail of the unpatched wrapper (the closing lines of `result()` and
# the payload builder) into which the artifact's hunk applies.  Inert text
# only: it is never imported or executed.
ORIGINAL_PAYLOAD_SOURCE = '''\
    return {
        "id": state.get("id"), "status": state.get("status"),
        "answer": state.get("answer") if state.get("status") == "completed" else None,
        "error": state.get("error"), "usage": state.get("usage", {}),
        "tool_calls": state.get("tool_calls", 0),
        "native_session_id": state.get("native_session_id"),
        "session_dir": str(path), "result_file": str(path / "result.json"),
    }


def patch_payload(model, base_url, max_tokens):
    return [
        {"id": "agent-default-model",
         "config": {"provider": "deepseek-gateway", "model": model}},
        {"id": "llm-pi-ai",
         "config": {"providers": {"deepseek-gateway": {
             "apiKeyEnv": "DEEPSEEK_API_KEY",
             "api": "openai-completions",
             "baseURL": base_url,
             "reasoning": "off",
             "defaultMaxTokens": max_tokens,
             "streamIdleTimeoutMs": 300000,
             "models": [{
                 "id": model,
                 "contextWindow": 1000000,
                 "maxTokens": max_tokens,
                 "reasoningEfforts": {"off": None, "high": "high"},
                 "compat": {"thinkingFormat": "deepseek", "maxTokensField": "max_tokens"},
             }],
             "retryPolicy": {"mode": "normal", "maxRetries": 1},
         }}}},
        {"id": "llm-deepseek", "disabled": True},
        {"id": "session-log-deepseek", "config": {"enabled": False}},
        {"id": "tool-web", "disabled": True},
    ]
'''

ORIGINAL_ITEM_IDS = ["agent-default-model", "llm-pi-ai", "llm-deepseek",
                     "session-log-deepseek", "tool-web"]

# Inert dummy values: a reserved TEST-NET address, a fake model name and an
# obviously synthetic absolute module path.  None of these are credentials.
DUMMY_BASE_URL = "https://192.0.2.10:8443/v1"
DUMMY_MODEL = "dummy/model-test-only"
DUMMY_MAX_TOKENS = 1234
DUMMY_MODULE = "/dummy/placeholder/deepseek-worker-guard/index.mjs"


def _guarded(source_text):
    """Wrap the canned tail at module level so it can be parsed."""
    return "def _wrapper_tail():\n" + source_text


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
ADDED_RE = re.compile(r"^\+(?!\+\+)")
REMOVED_RE = re.compile(r"^-(?!--)")
ENV_NAME_RE = re.compile(r"""environ(?:\.get\(|\[)\s*['"]([A-Z][A-Z0-9_]*)['"]""")
SECRET_LITERAL_RE = re.compile(
    r"""(?i)['"]?(?:api[_-]?key|apikey|secret|token|password)['"]?\s*[:=]\s*['"][^'"]+['"]""")

GUARD_ENTRY = {"insert": [{"id": "deepseek-worker-guard",
                           "name": DUMMY_MODULE,
                           "inject": ["tools"]}]}


def added_lines(patch_text):
    return [line[1:] for line in patch_text.splitlines() if ADDED_RE.match(line)]


def removed_lines(patch_text):
    return [line[1:] for line in patch_text.splitlines() if REMOVED_RE.match(line)]


def _path_from(line):
    return line[4:].split("\t", 1)[0]


def parse_patch(patch_text):
    """Return (old_path, new_path, [(old_start, old_count, new_start, new_count, body)])."""
    rows = patch_text.splitlines()
    if not rows[0].startswith("--- ") or not rows[1].startswith("+++ "):
        raise AssertionError("missing unified diff file headers")
    hunks = []
    index = 2
    while index < len(rows):
        match = HUNK_RE.match(rows[index])
        if not match:
            raise AssertionError("unexpected patch line: %r" % rows[index])
        old_start, old_count = int(match.group(1)), int(match.group(2) or 1)
        new_start, new_count = int(match.group(3)), int(match.group(4) or 1)
        index += 1
        body = []
        while index < len(rows) and not HUNK_RE.match(rows[index]):
            body.append(rows[index])
            index += 1
        hunks.append((old_start, old_count, new_start, new_count, body))
    return _path_from(rows[0]), _path_from(rows[1]), hunks


def apply_patch(original, patch_text):
    """Apply the single-file artifact to ``original`` text, purely in memory.

    ``original`` holds only the canned tail of the wrapper, so each hunk is
    located by its first old-side line rather than by absolute file line.
    """
    _, _, hunks = parse_patch(patch_text)
    src = original.splitlines()
    result = []
    cursor = 0
    for _, old_count, _, _, body in hunks:
        tags = []
        for line in body:
            if line.startswith("+"):
                tags.append(("+", line[1:]))
            elif line.startswith("-"):
                tags.append(("-", line[1:]))
            else:
                tags.append((" ", line[1:]))
        if sum(1 for tag, _ in tags if tag != "+") != old_count:
            raise AssertionError("hunk old-count mismatch")
        first = next(text for tag, text in tags if tag != "+")
        start = cursor + src[cursor:].index(first)
        result.extend(src[cursor:start])
        cursor = start
        for tag, text in tags:
            if tag == "+":
                result.append(text)
            elif tag == " ":
                if cursor >= len(src) or src[cursor] != text:
                    raise AssertionError("context mismatch at %r" % text)
                result.append(text)
                cursor += 1
            else:
                if cursor >= len(src) or src[cursor] != text:
                    raise AssertionError("removed line mismatch at %r" % text)
                cursor += 1
    result.extend(src[cursor:])
    return "\n".join(result) + ("\n" if original.endswith("\n") else "")


def simulated_payload(source_text, model, base_url, max_tokens, guard_module):
    """Statically evaluate the patched payload builder without importing it."""
    tree = ast.parse(_guarded(source_text))
    funcs = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

    def eval_expr(node):
        if isinstance(node, ast.Name) and node.id in ("model", "base_url", "max_tokens"):
            return {"model": model, "base_url": base_url, "max_tokens": max_tokens}[node.id]
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "worker_guard_module":
            # Mirror the fail-closed validation; no environment is read.
            if not guard_module or not os.path.isabs(guard_module):
                raise ValueError("Worker guard module is not configured.")
            return guard_module
        if isinstance(node, ast.Dict):
            return {eval_expr(key): eval_expr(value) for key, value in zip(node.keys, node.values)}
        if isinstance(node, ast.List):
            return [eval_expr(element) for element in node.elts]
        return ast.literal_eval(node)

    returns = [node for node in funcs["patch_payload"].body if isinstance(node, ast.Return)]
    if len(returns) != 1:
        raise AssertionError("patch_payload must return its payload exactly once")
    return eval_expr(returns[0].value)


class WrapperPatchArtifactTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(PATCH_PATH, "r", encoding="utf-8") as handle:
            cls.patch = handle.read()
        cls.added = added_lines(cls.patch)
        cls.removed = removed_lines(cls.patch)
        cls.old_path, cls.new_path, cls.hunks = parse_patch(cls.patch)
        cls.patched_source = apply_patch(ORIGINAL_PAYLOAD_SOURCE, cls.patch)

    def test_diff_targets_exact_wrapper_path(self):
        self.assertEqual([self.old_path, self.new_path], [WRAPPER_PATH, WRAPPER_PATH])
        self.assertTrue(os.path.isabs(WRAPPER_PATH))

    def test_guard_is_first_root_item_with_no_outer_id(self):
        funcs = {node.name: node for node in ast.parse(_guarded(self.patched_source)).body
                 if isinstance(node, ast.FunctionDef)}
        ret = [node for node in funcs["patch_payload"].body if isinstance(node, ast.Return)][0]
        first = ret.value.elts[0]
        self.assertIsInstance(first, ast.Dict)
        self.assertEqual([key.value for key in first.keys], ["insert"])
        self.assertNotIn("id", [key.value for key in first.keys])

    def test_guard_entry_has_exactly_expected_fields(self):
        payload = simulated_payload(self.patched_source, DUMMY_MODEL, DUMMY_BASE_URL,
                                    DUMMY_MAX_TOKENS, DUMMY_MODULE)
        self.assertEqual(payload[0], GUARD_ENTRY)
        entry = payload[0]["insert"][0]
        self.assertEqual(sorted(entry), ["id", "inject", "name"])
        self.assertEqual(entry["id"], "deepseek-worker-guard")
        self.assertEqual(entry["inject"], ["tools"])
        self.assertEqual(entry["name"], DUMMY_MODULE)

    def test_module_path_comes_from_absolute_validated_override(self):
        body = [line for line in self.added if "DEEPSEEK_WORKER_GUARD_MODULE" in line]
        self.assertEqual(len(body), 1, body)
        self.assertIn('os.environ.get("DEEPSEEK_WORKER_GUARD_MODULE")', body[0])
        self.assertIn("os.path.isabs(module)", self.patch)
        helper = [line for line in self.added if line.strip().startswith("raise AgentError(")]
        self.assertEqual(len(helper), 1, helper)
        self.assertIn("is not configured", helper[0])
        self.assertFalse(re.search(r"(?:os\.environ|os\.path\.isabs)", helper[0]))

    def test_only_new_environment_setting_is_module_path(self):
        self.assertEqual(set(ENV_NAME_RE.findall(self.patch)), {"DEEPSEEK_WORKER_GUARD_MODULE"})

    def test_patch_hardcodes_no_module_path(self):
        self.assertNotIn("locklark-worker-guard", self.patch)
        self.assertNotIn("dsh-patch-scratch", self.patch)
        for line in self.added:
            if line.strip().startswith(('"', "'")):
                self.assertFalse(os.path.isabs(line.strip().strip('",\'')), line)
        self.assertNotRegex(self.patch, r"""(?:name|module)\s*[:=]\s*["']/""")

    def test_existing_payload_items_are_preserved_intact(self):
        self.assertEqual(self.removed, [])
        before = simulated_payload(ORIGINAL_PAYLOAD_SOURCE, DUMMY_MODEL, DUMMY_BASE_URL,
                                   DUMMY_MAX_TOKENS, None)
        after = simulated_payload(self.patched_source, DUMMY_MODEL, DUMMY_BASE_URL,
                                  DUMMY_MAX_TOKENS, DUMMY_MODULE)
        self.assertEqual([item["id"] for item in before], ORIGINAL_ITEM_IDS)
        self.assertEqual(len(after), len(before) + 1)
        self.assertEqual([item["id"] for item in after[1:]], ORIGINAL_ITEM_IDS)
        self.assertEqual(after[1:], before)
        self.assertEqual(json.dumps(after[1:], sort_keys=True),
                         json.dumps(before, sort_keys=True))
        for item in after[1:]:
            self.assertNotIn("insert", item)

    def test_guard_fails_closed_on_missing_or_relative_module(self):
        for bad in (None, "", "relative/guard.mjs", "./guard.mjs", "~/guard.mjs", "guard.mjs"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                simulated_payload(self.patched_source, DUMMY_MODEL, DUMMY_BASE_URL,
                                  DUMMY_MAX_TOKENS, bad)
        for good in (DUMMY_MODULE, "/opt/guard/index.mjs"):
            payload = simulated_payload(self.patched_source, DUMMY_MODEL, DUMMY_BASE_URL,
                                        DUMMY_MAX_TOKENS, good)
            self.assertEqual(payload[0]["insert"][0]["name"], good)

    def test_patch_and_harness_contain_no_credential_values(self):
        with open(os.path.abspath(__file__), "r", encoding="utf-8") as handle:
            source = handle.read()
        secrets_to_detect = ["sk" + "-" + "x", "Bearer" + " x", "credentials" + ".json",
                             "DEEPSEEK_API_KEY" + "="]
        for text in (self.patch, ORIGINAL_PAYLOAD_SOURCE, source):
            self.assertIsNone(SECRET_LITERAL_RE.search(text))
            for marker in secrets_to_detect:
                self.assertNotIn(marker, text)
        self.assertNotIn(DUMMY_BASE_URL, self.patch)
        self.assertNotIn(DUMMY_MODEL, self.patch)


if __name__ == "__main__":
    unittest.main()
