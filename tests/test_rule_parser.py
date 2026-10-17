"""Unit tests cho Rule Parser & Validator (core.parser)."""

import unittest

from core.models import STATUS_INVALID, STATUS_UNSUPPORTED
from core.parser import RuleParser


def _parse(text: str):
    return RuleParser.parse(text, "test.rules", 1)


class TestValidRules(unittest.TestCase):
    def test_full_valid_rule(self):
        text = (
            'alert tcp any any -> 10.0.0.0/8 80 (msg:"Directory traversal detected"; '
            'content:"../"; nocase; depth:20; flow:to_server,established; '
            "flags:PA; dsize:>0; classtype:attempted-admin; priority:1; sid:100001; rev:1;)"
        )
        outcome = _parse(text)
        self.assertTrue(outcome.ok, outcome.reason)
        rule = outcome.rule
        self.assertEqual(rule.sid, 100001)
        self.assertEqual(rule.rev, 1)
        self.assertEqual(rule.msg, "Directory traversal detected")
        self.assertEqual(rule.header.protocol, "tcp")
        self.assertEqual(rule.header.direction, "->")

        data = rule.to_dict()
        self.assertTrue(data["header"]["src_ip"]["any"])
        self.assertEqual(data["header"]["dst_ip"]["network"], "10.0.0.0/8")
        self.assertEqual(data["header"]["dst_port"], {"lo": 80, "hi": 80, "text": "80"})
        self.assertEqual(data["contents"][0]["content"], "../")
        self.assertTrue(data["contents"][0]["nocase"])
        self.assertEqual(data["contents"][0]["depth"], 20)
        self.assertEqual(data["flow"], ["to_server", "established"])
        self.assertEqual(data["flags"]["flags"], "PA")
        self.assertEqual(data["dsize"], {"op": "gt", "value": 0, "text": ">0"})
        self.assertEqual(data["classtype"], "attempted-admin")
        self.assertEqual(data["priority"], 1)
        self.assertEqual(data["rule_file"], "test.rules")
        self.assertEqual(data["line_no"], 1)

    def test_ip_variants(self):
        cases = [
            ("any", True, None),
            ("10.0.0.5", False, "10.0.0.5/32"),
            ("192.168.1.0/24", False, "192.168.1.0/24"),
        ]
        for text, is_any, network in cases:
            with self.subTest(ip=text):
                outcome = _parse(f'alert tcp {text} any -> any any (msg:"m"; sid:1;)')
                self.assertTrue(outcome.ok, outcome.reason)
                spec = outcome.rule.header.src_ip
                self.assertEqual(spec.any, is_any)
                self.assertEqual(str(spec.network) if spec.network else None, network)

    def test_port_variants(self):
        cases = {
            "any": (None, None),
            "80": (80, 80),
            "1024:2048": (1024, 2048),
            "1024:": (1024, None),
            ":1024": (None, 1024),
        }
        for text, (lo, hi) in cases.items():
            with self.subTest(port=text):
                outcome = _parse(f'alert udp any {text} -> any any (msg:"m"; sid:2;)')
                self.assertTrue(outcome.ok, outcome.reason)
                spec = outcome.rule.header.src_port
                self.assertEqual((spec.lo, spec.hi), (lo, hi))

    def test_rev_classtype_priority_defaults(self):
        outcome = _parse('alert tcp any any -> any any (msg:"m"; sid:7;)')
        self.assertTrue(outcome.ok, outcome.reason)
        self.assertEqual(outcome.rule.rev, 0)
        self.assertIsNone(outcome.rule.classtype)
        self.assertIsNone(outcome.rule.priority)
        self.assertIsNone(outcome.rule.flags)
        self.assertIsNone(outcome.rule.dsize)
        self.assertEqual(outcome.rule.flow, [])

    def test_content_escapes_and_hex(self):
        text = (
            r'alert tcp any any -> any any (msg:"m"; content:"a\;b"; '
            r'content:"say \"hi\""; content:"hex|41 42|end"; sid:3;)'
        )
        outcome = _parse(text)
        self.assertTrue(outcome.ok, outcome.reason)
        contents = [option.content for option in outcome.rule.contents]
        self.assertEqual(contents, ["a;b", 'say "hi"', "hexABend"])

    def test_two_contents_modifiers_attach_to_previous(self):
        text = (
            'alert tcp any any -> any any (msg:"m"; content:"GET"; nocase; '
            'content:"/admin"; depth:10; distance:5; sid:4;)'
        )
        outcome = _parse(text)
        self.assertTrue(outcome.ok, outcome.reason)
        first, second = outcome.rule.contents
        self.assertTrue(first.nocase)
        self.assertIsNone(first.depth)
        self.assertFalse(second.nocase)
        self.assertEqual(second.depth, 10)
        self.assertEqual(second.distance, 5)

    def test_msg_with_parenthesis_and_semicolon(self):
        text = 'alert tcp any any -> any any (msg:"test (x); note"; sid:5;)'
        outcome = _parse(text)
        self.assertTrue(outcome.ok, outcome.reason)
        self.assertEqual(outcome.rule.msg, "test (x); note")


class TestInvalidRules(unittest.TestCase):
    def _assert_invalid(self, text: str, reason_part: str):
        outcome = _parse(text)
        self.assertEqual(outcome.status, STATUS_INVALID, f"{text} -> {outcome.reason}")
        self.assertIn(reason_part, outcome.reason or "")

    def test_syntax_and_empty(self):
        self._assert_invalid('alert tcp any any -> any 80 msg:"m"; sid:1;', "invalid rule syntax")
        self._assert_invalid("", "empty rule")
        self._assert_invalid("   ", "empty rule")
        self._assert_invalid("# comment", "empty rule")

    def test_required_options(self):
        self._assert_invalid('alert tcp any any -> any any (msg:"m";)', "missing required option: sid")
        self._assert_invalid("alert tcp any any -> any any (sid:1;)", "missing required option: msg")

    def test_bad_values(self):
        cases = [
            ('alert tcp any any -> any any (msg:"m"; sid:0;)', "invalid sid"),
            ('alert tcp any any -> any any (msg:"m"; sid:abc;)', "invalid sid"),
            ('alert tcp any any -> any any (msg:"m"; sid:1; sid:2;)', "duplicate option: sid"),
            ('alert tcp any any -> any any (msg:"m"; rev:abc; sid:1;)', "invalid rev"),
            ('alert tcp any any -> any any (msg:m; sid:1;)', "invalid msg"),
            ('alert tcp any any -> any any (msg:"m"; priority:abc; sid:1;)', "invalid priority"),
            ('alert tcp any any -> any any (msg:"m"; classtype:"bad type!"; sid:1;)', "invalid classtype"),
            ('alert tcp any any -> any any (msg:"m"; flags:ZZ; sid:1;)', "invalid flags"),
            ('alert tcp any any -> any any (msg:"m"; dsize:abc; sid:1;)', "invalid dsize"),
            ('alert tcp any any -> any any (msg:"m"; flow:; sid:1;)', "invalid flow"),
            ('alert tcp any any -> 10.0.0.999 any (msg:"m"; sid:1;)', "invalid IP address"),
            ('alert tcp any 70000 -> any any (msg:"m"; sid:1;)', "invalid port"),
            ('alert tcp any 90:80 -> any any (msg:"m"; sid:1;)', "invalid port range"),
            ('alert tcp any : -> any any (msg:"m"; sid:1;)', "invalid port"),
            ('alert tcp any any -> any any (msg:"m"; depth:10; sid:1;)', "content modifier without preceding content"),
            ('alert tcp any any -> any any (msg:"m"; content:abc; sid:1;)', "invalid content"),
            ('alert tcp any any -> any any (msg:"m"; content:"bad|zz|"; sid:1;)', "invalid content"),
            ('alert tcp any any -> any any (msg:"m"; content:"a"; nocase:1; sid:1;)', "invalid nocase"),
        ]
        for text, reason_part in cases:
            with self.subTest(rule=text):
                self._assert_invalid(text, reason_part)


class TestUnsupportedRules(unittest.TestCase):
    def _assert_unsupported(self, text: str, reason_part: str):
        outcome = _parse(text)
        self.assertEqual(outcome.status, STATUS_UNSUPPORTED, f"{text} -> {outcome.reason}")
        self.assertIn(reason_part, outcome.reason or "")

    def test_out_of_scope(self):
        cases = [
            ('drop tcp any any -> any any (msg:"m"; sid:1;)', "unsupported action: drop"),
            ('alert icmp any any -> any any (msg:"m"; sid:1;)', "unsupported protocol: icmp"),
            ('alert tcp any any -> any any (msg:"m"; pcre:"/a/"; sid:1;)', "unsupported keyword: pcre"),
            ('alert tcp any any -> any any (msg:"m"; http_uri; sid:1;)', "unsupported keyword: http_uri"),
            ('alert tcp !10.0.0.0/8 any -> any any (msg:"m"; sid:1;)', "unsupported negated address"),
            ('alert tcp [10.0.0.0/8,192.168.0.0/16] any -> any any (msg:"m"; sid:1;)', "unsupported address list"),
            ('alert tcp 2001:db8::/32 any -> any any (msg:"m"; sid:1;)', "unsupported IPv6 address"),
            ('alert tcp any !80 -> any any (msg:"m"; sid:1;)', "unsupported negated port"),
            ('alert tcp any [80,443] -> any any (msg:"m"; sid:1;)', "unsupported port list"),
            ('alert tcp any 80,443 -> any any (msg:"m"; sid:1;)', "unsupported port list"),
            ('alert tcp any any -> any any (msg:"m"; flags:!S; sid:1;)', "unsupported flags modifier"),
            ('alert tcp any any -> any any (msg:"m"; dsize:100<>500; sid:1;)', "unsupported dsize range"),
            ('alert tcp any any -> any any (msg:"m"; flow:from_client; sid:1;)', "unsupported flow keyword: from_client"),
        ]
        for text, reason_part in cases:
            with self.subTest(rule=text):
                self._assert_unsupported(text, reason_part)

    def test_unsupported_does_not_crash_on_mixed_options(self):
        text = 'alert tcp any any -> any any (msg:"m"; content:"GET"; byte_test:1,=,65; sid:1;)'
        outcome = _parse(text)
        self.assertEqual(outcome.status, STATUS_UNSUPPORTED)
        self.assertIn("unsupported keyword: byte_test", outcome.reason)


if __name__ == "__main__":
    unittest.main()
