"""Unit tests cho Rule Matching Engine (core.matcher)."""

import unittest

from core.matcher import RuleMatcher
from core.parser import RuleParser
from parsers.models import (
    ApplicationLayer,
    FlowRef,
    NetworkLayer,
    NormalizedEvent,
    TransportLayer,
)


def make_rule(text: str):
    outcome = RuleParser.parse(text, "test.rules", 1)
    assert outcome.ok, outcome.reason
    return outcome.rule


def make_flow(direction: str = "forward", state: str = "ESTABLISHED") -> FlowRef:
    return FlowRef(
        flow_id="TCP-10.0.0.10:52000-10.0.0.20:80",
        direction=direction,
        state=state,
        is_new_flow=False,
    )


def make_event(
    src_ip: str = "10.0.0.10",
    dst_ip: str = "10.0.0.20",
    src_port: int = 52000,
    dst_port: int = 80,
    layer: str = "TCP",
    flags=None,
    payload_len: int = 0,
    flow=None,
) -> NormalizedEvent:
    return NormalizedEvent(
        packet_id=1,
        timestamp=1000.0,
        raw_len=payload_len + 54,
        network=NetworkLayer(src_ip=src_ip, dst_ip=dst_ip, proto=layer),
        transport=TransportLayer(
            layer=layer,
            src_port=src_port,
            dst_port=dst_port,
            flags=list(flags or []),
            payload_len=payload_len,
        ),
        application=ApplicationLayer(protocol="HTTP", type="request"),
        flow=flow,
    )


class TestHeaderMatching(unittest.TestCase):
    def test_dst_port_and_ip(self):
        rule = make_rule('alert tcp any any -> 10.0.0.20 80 (msg:"m"; sid:1;)')
        self.assertIsNotNone(RuleMatcher.match(rule, make_event()))
        self.assertIsNone(RuleMatcher.match(rule, make_event(dst_port=8080)))
        self.assertIsNone(RuleMatcher.match(rule, make_event(dst_ip="10.0.0.99")))

    def test_protocol_mismatch(self):
        rule = make_rule('alert udp any any -> any 53 (msg:"m"; sid:2;)')
        self.assertIsNone(RuleMatcher.match(rule, make_event(dst_port=53)))

    def test_uni_direction_only_matches_written_orientation(self):
        rule = make_rule('alert tcp 10.0.0.10 any -> 10.0.0.20 80 (msg:"m"; sid:3;)')
        forward = make_event()
        backward = make_event(src_ip="10.0.0.20", dst_ip="10.0.0.10", src_port=80, dst_port=52000)
        self.assertIsNotNone(RuleMatcher.match(rule, forward))
        self.assertIsNone(RuleMatcher.match(rule, backward))

    def test_bidi_rule_matches_both_orientations(self):
        rule = make_rule('alert tcp 10.0.0.10 52000 <> 10.0.0.20 80 (msg:"m"; sid:4;)')
        forward = make_event()
        backward = make_event(src_ip="10.0.0.20", dst_ip="10.0.0.10", src_port=80, dst_port=52000)
        self.assertIsNotNone(RuleMatcher.match(rule, forward))
        self.assertIsNotNone(RuleMatcher.match(rule, backward))

    def test_cidr_and_port_range(self):
        rule = make_rule('alert tcp 10.0.0.0/8 any -> 192.168.0.0/16 1024:2048 (msg:"m"; sid:5;)')
        event = make_event(dst_ip="192.168.1.10", dst_port=1500)
        self.assertIsNotNone(RuleMatcher.match(rule, event))
        self.assertIsNone(RuleMatcher.match(rule, make_event(dst_ip="172.16.0.1", dst_port=1500)))
        self.assertIsNone(RuleMatcher.match(rule, make_event(dst_ip="192.168.1.10", dst_port=80)))


class TestContentMatching(unittest.TestCase):
    def test_case_sensitive_by_default(self):
        rule = make_rule('alert tcp any any -> any any (msg:"m"; content:"/Admin"; sid:10;)')
        self.assertIsNotNone(RuleMatcher.match(rule, make_event(), b"GET /Admin HTTP/1.1"))
        self.assertIsNone(RuleMatcher.match(rule, make_event(), b"GET /admin HTTP/1.1"))

    def test_nocase_matches_and_reports_position(self):
        rule = make_rule('alert tcp any any -> any any (msg:"m"; content:"/admin"; nocase; sid:11;)')
        result = RuleMatcher.match(rule, make_event(), b"GET /AdMiN HTTP/1.1")
        self.assertIsNotNone(result)
        self.assertEqual(result.contents[0].offset, 4)
        self.assertEqual(result.contents[0].length, 6)
        self.assertTrue(result.contents[0].nocase)
        self.assertEqual(result.contents[0].content, "/admin")

    def test_nocase_is_ascii_only(self):
        # 0xC9 ('É' latin-1) không được hạ thành 0xE9 ('é') như Unicode lower.
        rule = make_rule('alert tcp any any -> any any (msg:"m"; content:"caf\xe9"; nocase; sid:12;)')
        self.assertIsNone(RuleMatcher.match(rule, make_event(), b"caf\xc9"))

    def test_offset_and_depth_window(self):
        payload = b"0123456789NEEDLE"
        rule = make_rule('alert tcp any any -> any any (msg:"m"; content:"NEEDLE"; offset:10; sid:13;)')
        result = RuleMatcher.match(rule, make_event(), payload)
        self.assertIsNotNone(result)
        self.assertEqual(result.contents[0].offset, 10)

        depth_miss = make_rule('alert tcp any any -> any any (msg:"m"; content:"NEEDLE"; depth:5; sid:14;)')
        self.assertIsNone(RuleMatcher.match(depth_miss, make_event(), payload))

        exact_window = make_rule(
            'alert tcp any any -> any any (msg:"m"; content:"NEEDLE"; offset:10; depth:6; sid:15;)'
        )
        self.assertIsNotNone(RuleMatcher.match(exact_window, make_event(), payload))

        short_window = make_rule(
            'alert tcp any any -> any any (msg:"m"; content:"NEEDLE"; offset:10; depth:5; sid:16;)'
        )
        self.assertIsNone(RuleMatcher.match(short_window, make_event(), payload))

    def test_offset_beyond_payload_never_matches(self):
        rule = make_rule('alert tcp any any -> any any (msg:"m"; content:"A"; offset:99; sid:17;)')
        self.assertIsNone(RuleMatcher.match(rule, make_event(), b"AAAA"))

    def test_distance_and_within(self):
        payload = b"AAABBBBCCCC"
        rule = make_rule(
            'alert tcp any any -> any any (msg:"m"; content:"AAA"; content:"CCC"; '
            "distance:4; within:4; sid:18;)"
        )
        result = RuleMatcher.match(rule, make_event(), payload)
        self.assertIsNotNone(result)
        self.assertEqual(result.contents[1].offset, 7)

        too_narrow = make_rule(
            'alert tcp any any -> any any (msg:"m"; content:"AAA"; content:"CCC"; '
            "distance:4; within:2; sid:19;)"
        )
        self.assertIsNone(RuleMatcher.match(too_narrow, make_event(), payload))

    def test_plain_contents_search_independently(self):
        # Không có distance/within, mỗi content được tìm độc lập trên toàn
        # payload (đúng Snort): thứ tự xuất hiện không bắt buộc.
        payload = b"CCCCBBBAAAA"
        rule = make_rule(
            'alert tcp any any -> any any (msg:"m"; content:"AAA"; content:"CCC"; sid:20;)'
        )
        result = RuleMatcher.match(rule, make_event(), payload)
        self.assertIsNotNone(result)
        self.assertEqual(result.contents[0].offset, 7)
        self.assertEqual(result.contents[1].offset, 0)

    def test_distance_zero_enforces_order(self):
        # distance:0 buộc content sau phải nằm sau content trước.
        payload = b"CCCCBBBAAAA"
        rule = make_rule(
            'alert tcp any any -> any any (msg:"m"; content:"AAA"; content:"CCC"; '
            "distance:0; sid:22;)"
        )
        self.assertIsNone(RuleMatcher.match(rule, make_event(), payload))

    def test_rule_without_content_matches_after_header(self):
        rule = make_rule('alert tcp any any -> any any (msg:"m"; sid:21;)')
        result = RuleMatcher.match(rule, make_event(), b"anything")
        self.assertIsNotNone(result)
        self.assertEqual(result.contents, [])


class TestFlowFlagsDsize(unittest.TestCase):
    def test_flow_to_server_established(self):
        rule = make_rule(
            'alert tcp any any -> any any (msg:"m"; flow:to_server,established; sid:30;)'
        )
        self.assertIsNotNone(RuleMatcher.match(rule, make_event(flow=make_flow("forward", "ESTABLISHED"))))
        self.assertIsNone(RuleMatcher.match(rule, make_event(flow=make_flow("backward", "ESTABLISHED"))))
        self.assertIsNone(RuleMatcher.match(rule, make_event(flow=make_flow("forward", "HANDSHAKE"))))
        self.assertIsNone(RuleMatcher.match(rule, make_event(flow=None)))

    def test_flow_to_client(self):
        rule = make_rule('alert tcp any any -> any any (msg:"m"; flow:to_client; sid:31;)')
        self.assertIsNotNone(RuleMatcher.match(rule, make_event(flow=make_flow("backward"))))
        self.assertIsNone(RuleMatcher.match(rule, make_event(flow=make_flow("forward"))))

    def test_flow_not_established(self):
        rule = make_rule('alert tcp any any -> any any (msg:"m"; flow:not_established; sid:32;)')
        self.assertIsNotNone(RuleMatcher.match(rule, make_event(flow=make_flow("forward", "HANDSHAKE"))))
        self.assertIsNotNone(RuleMatcher.match(rule, make_event(flow=make_flow("forward", "NEW"))))
        self.assertIsNone(RuleMatcher.match(rule, make_event(flow=make_flow("forward", "ESTABLISHED"))))

    def test_flags(self):
        syn_rule = make_rule('alert tcp any any -> any any (msg:"m"; flags:S; sid:33;)')
        self.assertIsNotNone(RuleMatcher.match(syn_rule, make_event(flags=["SYN"])))
        self.assertIsNotNone(RuleMatcher.match(syn_rule, make_event(flags=["SYN", "ACK"])))
        self.assertIsNone(RuleMatcher.match(syn_rule, make_event(flags=["ACK"])))

        pa_rule = make_rule('alert tcp any any -> any any (msg:"m"; flags:PA; sid:34;)')
        self.assertIsNotNone(RuleMatcher.match(pa_rule, make_event(flags=["PSH", "ACK"])))
        self.assertIsNone(RuleMatcher.match(pa_rule, make_event(flags=["PSH"])))

    def test_dsize(self):
        big = make_rule('alert tcp any any -> any any (msg:"m"; dsize:>100; sid:35;)')
        self.assertIsNotNone(RuleMatcher.match(big, make_event(payload_len=200)))
        self.assertIsNone(RuleMatcher.match(big, make_event(payload_len=50)))

        exact = make_rule('alert tcp any any -> any any (msg:"m"; dsize:100; sid:36;)')
        self.assertIsNotNone(RuleMatcher.match(exact, make_event(payload_len=100)))
        self.assertIsNone(RuleMatcher.match(exact, make_event(payload_len=101)))


class TestMatchResultInfo(unittest.TestCase):
    def test_match_result_fields_and_sid(self):
        rule = make_rule(
            'alert tcp any any -> 10.0.0.20 80 (msg:"m"; content:"GET"; '
            "flow:to_server,established; flags:PA; dsize:>0; sid:100001; rev:1;)"
        )
        event = make_event(flags=["PSH", "ACK"], payload_len=50, flow=make_flow())
        result = RuleMatcher.match(rule, event, b"GET / HTTP/1.1")
        self.assertIsNotNone(result)
        self.assertEqual(result.sid, 100001)
        self.assertIn("flow:to_server,established", result.fields)
        self.assertIn("flags:PA", result.fields)
        self.assertIn("dsize:>0", result.fields)
        self.assertEqual(result.to_dict()["contents"][0]["content"], "GET")

    def test_udp_dns_query_rule(self):
        rule = make_rule('alert udp any any -> any 53 (msg:"m"; content:"evil"; sid:40;)')
        event = make_event(layer="UDP", dst_port=53, payload_len=30, flow=make_flow("forward"))
        self.assertIsNotNone(RuleMatcher.match(rule, event, b"\x12\x34evil.example"))
        self.assertIsNone(RuleMatcher.match(rule, event, b"\x12\x34safe.example"))


if __name__ == "__main__":
    unittest.main()
