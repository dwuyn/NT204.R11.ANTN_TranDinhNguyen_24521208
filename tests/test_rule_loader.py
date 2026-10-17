"""Unit tests cho Rule Loader (core.loader)."""

import os
import tempfile
import unittest

from core.loader import RuleLoader

VALID_1 = 'alert tcp any any -> 10.0.0.20 80 (msg:"HTTP GET"; content:"GET"; sid:1001; rev:1;)'
VALID_2 = 'alert udp any any -> any 53 (msg:"DNS query"; content:"test"; sid:1002; rev:2;)'
INVALID = 'alert tcp any any -> any any (msg:"broken"; sid:abc;)'
UNSUPPORTED = 'alert tcp any any -> any any (msg:"pcre rule"; pcre:"/a/"; sid:1003;)'


class LoaderTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write_file(self, name: str, content: str) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path


class TestRuleLoader(LoaderTestBase):
    def test_skips_comments_and_blank_lines(self):
        path = self.write_file(
            "basic.rules",
            "# comment line\n\n" + VALID_1 + "\n   \n# another comment\n" + VALID_2 + "\n",
        )
        result = RuleLoader().load_files([path])
        self.assertEqual(len(result.valid), 2)
        self.assertEqual(result.invalid, [])
        self.assertEqual(result.unsupported, [])
        self.assertEqual(result.files, [path])
        self.assertEqual({rule.sid for rule in result.valid}, {1001, 1002})

    def test_invalid_rule_does_not_stop_loading(self):
        path = self.write_file("mixed.rules", VALID_1 + "\n" + INVALID + "\n" + VALID_2 + "\n")
        result = RuleLoader().load_files([path])
        self.assertEqual(len(result.valid), 2)
        self.assertEqual(len(result.invalid), 1)
        self.assertEqual(result.invalid[0].line_no, 2)
        self.assertIn("invalid rule at", result.warnings[0])
        self.assertIn(":2:", result.warnings[0])

    def test_unsupported_rule_reported_and_load_continues(self):
        path = self.write_file("unsupported.rules", UNSUPPORTED + "\n" + VALID_1 + "\n")
        result = RuleLoader().load_files([path])
        self.assertEqual(len(result.unsupported), 1)
        self.assertIn("unsupported keyword: pcre", result.unsupported[0].reason)
        self.assertEqual(len(result.valid), 1)

    def test_multiple_files_and_missing_file(self):
        first = self.write_file("a.rules", VALID_1 + "\n")
        second = self.write_file("b.rules", VALID_2 + "\n")
        missing = os.path.join(self.tmpdir, "missing.rules")
        result = RuleLoader().load_files([first, missing, second])
        self.assertEqual(len(result.valid), 2)
        self.assertEqual(result.files, [first, second])
        self.assertTrue(any("cannot read rule file" in warning for warning in result.warnings))

    def test_disabled_rule_by_sid(self):
        path = self.write_file("disable.rules", VALID_1 + "\n" + VALID_2 + "\n")
        result = RuleLoader(disabled_sids=[1002]).load_files([path])
        self.assertEqual([rule.sid for rule in result.valid], [1001])
        self.assertEqual(result.disabled_rules, [1002])
        self.assertTrue(any("rule disabled by config: sid=1002" in warning for warning in result.warnings))

    def test_disabled_file(self):
        path = self.write_file("disabled.rules", VALID_1 + "\n")
        result = RuleLoader(disabled_files=[path]).load_files([path])
        self.assertEqual(result.valid, [])
        self.assertEqual(result.files, [])
        self.assertEqual(result.disabled_files, [path])

    def test_disabled_file_by_basename(self):
        path = self.write_file("by_name.rules", VALID_1 + "\n")
        result = RuleLoader(disabled_files=["by_name.rules"]).load_files([path])
        self.assertEqual(result.valid, [])
        self.assertEqual(result.disabled_files, [path])

    def test_duplicate_sid_ignored(self):
        path = self.write_file("dupes.rules", VALID_1 + "\n" + VALID_1 + "\n")
        result = RuleLoader().load_files([path])
        self.assertEqual(len(result.valid), 1)
        self.assertTrue(any("duplicate sid ignored: sid=1001" in warning for warning in result.warnings))

    def test_include_directive_warned_not_parsed(self):
        path = self.write_file("inc.rules", "include other.rules\n" + VALID_1 + "\n")
        result = RuleLoader().load_files([path])
        self.assertEqual(len(result.valid), 1)
        self.assertEqual(result.invalid, [])
        self.assertEqual(result.unsupported, [])
        self.assertTrue(any("unsupported include directive" in warning for warning in result.warnings))

    def test_invalid_utf8_file_does_not_crash(self):
        path = os.path.join(self.tmpdir, "binary.rules")
        with open(path, "wb") as handle:
            handle.write(b"# comment with bad byte \xe9\xfa\n" + VALID_1.encode() + b"\n")
        result = RuleLoader().load_files([path])
        self.assertEqual(len(result.valid), 1)

    def test_line_numbers_recorded_on_rule(self):
        path = self.write_file("lines.rules", "# c\n\n" + VALID_1 + "\n")
        result = RuleLoader().load_files([path])
        rule = result.valid[0]
        self.assertEqual(rule.line_no, 3)
        self.assertEqual(rule.rule_file, path)

    def test_result_stats_and_to_dict(self):
        path = self.write_file("stats.rules", VALID_1 + "\n" + INVALID + "\n" + UNSUPPORTED + "\n")
        result = RuleLoader().load_files([path])
        stats = result.stats()
        self.assertEqual(stats["files_loaded"], 1)
        self.assertEqual(stats["valid"], 1)
        self.assertEqual(stats["invalid"], 1)
        self.assertEqual(stats["unsupported"], 1)
        data = result.to_dict()
        self.assertEqual(data["stats"]["valid"], 1)
        self.assertEqual(data["valid"][0]["sid"], 1001)
        self.assertEqual(data["invalid"][0]["line_no"], 2)
        self.assertIn("unsupported keyword", data["unsupported"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
