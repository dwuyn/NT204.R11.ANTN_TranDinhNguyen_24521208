"""Unit tests cho data model của Core Engine (core.models)."""

import ipaddress
import json
import unittest

from core.models import (
    DIRECTION_BIDI,
    STATUS_VALID,
    ContentMatch,
    ContentOption,
    FlagSpec,
    IPSpec,
    MatchResult,
    ParseOutcome,
    PortSpec,
    Rule,
    RuleHeader,
    SizeSpec,
)


class TestIPSpec(unittest.TestCase):
    def test_any_matches_everything(self):
        spec = IPSpec(any=True, text="any")
        self.assertTrue(spec.contains("10.0.0.1"))
        self.assertTrue(spec.contains("255.255.255.255"))

    def test_single_ip_and_cidr(self):
        single = IPSpec(any=False, network=ipaddress.ip_network("10.0.0.5/32"), text="10.0.0.5")
        self.assertTrue(single.contains("10.0.0.5"))
        self.assertFalse(single.contains("10.0.0.6"))

        cidr = IPSpec(any=False, network=ipaddress.ip_network("192.168.1.0/24"), text="192.168.1.0/24")
        self.assertTrue(cidr.contains("192.168.1.200"))
        self.assertFalse(cidr.contains("192.168.2.1"))

    def test_invalid_ip_is_no_match(self):
        spec = IPSpec(any=False, network=ipaddress.ip_network("10.0.0.0/8"), text="10.0.0.0/8")
        self.assertFalse(spec.contains("not-an-ip"))
        self.assertFalse(spec.contains(""))


class TestPortSpec(unittest.TestCase):
    def test_any(self):
        self.assertTrue(PortSpec().contains(0))
        self.assertTrue(PortSpec().contains(65535))

    def test_single_port(self):
        spec = PortSpec(lo=80, hi=80, text="80")
        self.assertTrue(spec.contains(80))
        self.assertFalse(spec.contains(81))

    def test_range_and_open_ranges(self):
        closed = PortSpec(lo=1024, hi=2048, text="1024:2048")
        self.assertTrue(closed.contains(1024))
        self.assertTrue(closed.contains(1500))
        self.assertFalse(closed.contains(2049))

        lower_open = PortSpec(lo=1024, hi=None, text="1024:")
        self.assertTrue(lower_open.contains(65000))
        self.assertFalse(lower_open.contains(1023))

        upper_open = PortSpec(lo=None, hi=1024, text=":1024")
        self.assertTrue(upper_open.contains(80))
        self.assertFalse(upper_open.contains(1025))


class TestFlagSpec(unittest.TestCase):
    def test_subset_match(self):
        syn = FlagSpec(flags="S", text="S")
        self.assertTrue(syn.matches(["SYN"]))
        self.assertTrue(syn.matches(["SYN", "ACK"]))
        self.assertFalse(syn.matches(["ACK"]))

    def test_multiple_letters_need_all(self):
        syn_ack = FlagSpec(flags="SA", text="SA")
        self.assertTrue(syn_ack.matches(["SYN", "ACK"]))
        self.assertFalse(syn_ack.matches(["SYN"]))

    def test_psh_ack(self):
        psh_ack = FlagSpec(flags="PA", text="PA")
        self.assertTrue(psh_ack.matches(["PSH", "ACK"]))
        self.assertFalse(psh_ack.matches(["ACK"]))


class TestSizeSpec(unittest.TestCase):
    def test_operators(self):
        self.assertTrue(SizeSpec(op="eq", value=100, text="100").matches(100))
        self.assertFalse(SizeSpec(op="eq", value=100, text="100").matches(101))
        self.assertTrue(SizeSpec(op="gt", value=100, text=">100").matches(101))
        self.assertFalse(SizeSpec(op="gt", value=100, text=">100").matches(100))
        self.assertTrue(SizeSpec(op="lt", value=100, text="<100").matches(99))
        self.assertFalse(SizeSpec(op="lt", value=100, text="<100").matches(100))


class TestRuleObjects(unittest.TestCase):
    def test_rule_to_dict_round_trips_through_json(self):
        rule = Rule(
            header=RuleHeader(
                action="alert",
                protocol="tcp",
                src_ip=IPSpec(any=True, text="any"),
                src_port=PortSpec(lo=None, hi=None, text="any"),
                direction=DIRECTION_BIDI,
                dst_ip=IPSpec(any=False, network=ipaddress.ip_network("10.0.0.0/8"), text="10.0.0.0/8"),
                dst_port=PortSpec(lo=80, hi=80, text="80"),
            ),
            msg="Directory traversal detected",
            sid=100001,
            rev=1,
            priority=1,
            contents=[ContentOption(content="../", nocase=True, depth=20, text='content:"../"')],
            flow=["to_server", "established"],
            flags=FlagSpec(flags="PA", text="PA"),
            dsize=SizeSpec(op="gt", value=0, text=">0"),
            rule_file="local.rules",
            line_no=3,
        )
        data = json.loads(json.dumps(rule.to_dict()))
        self.assertEqual(data["sid"], 100001)
        self.assertEqual(data["header"]["direction"], "<>")
        self.assertEqual(data["header"]["dst_port"]["lo"], 80)
        self.assertEqual(data["contents"][0]["depth"], 20)
        self.assertTrue(data["contents"][0]["nocase"])
        self.assertEqual(data["flow"], ["to_server", "established"])

    def test_parse_outcome_helpers(self):
        rule = Rule(sid=42)
        outcome = ParseOutcome(status=STATUS_VALID, rule=rule, line_no=1)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.to_dict()["sid"], 42)

        bad = ParseOutcome(status="invalid", reason="syntax error", line_no=2)
        self.assertFalse(bad.ok)
        self.assertIsNone(bad.to_dict()["sid"])

    def test_match_result_exposes_sid(self):
        rule = Rule(sid=9001)
        result = MatchResult(rule=rule, contents=[ContentMatch(content="GET", offset=0, length=3)])
        self.assertEqual(result.sid, 9001)
        self.assertEqual(result.to_dict()["contents"][0]["length"], 3)


if __name__ == "__main__":
    unittest.main()
