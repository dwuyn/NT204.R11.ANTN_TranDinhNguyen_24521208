"""Unit tests cho Detection Event Generator (core.detection)."""

import json
import unittest

from core.detection import DetectionEventGenerator
from core.matcher import RuleMatcher
from core.parser import RuleParser
from parsers.models import (
    ApplicationLayer,
    FlowRef,
    NetworkLayer,
    NormalizedEvent,
    TransportLayer,
)

RULE_TEXT = (
    'alert tcp any any -> 10.0.0.20 80 (msg:"Directory traversal detected"; '
    'content:"../"; nocase; flow:to_server,established; flags:PA; '
    "classtype:attempted-admin; priority:1; sid:100001; rev:3;)"
)


def make_event(flow=None, app_protocol="HTTP") -> NormalizedEvent:
    return NormalizedEvent(
        packet_id=7,
        timestamp=1700000000.1234567,
        raw_len=220,
        network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
        transport=TransportLayer(
            layer="TCP",
            src_port=52000,
            dst_port=80,
            flags=["PSH", "ACK"],
            payload_len=166,
        ),
        application=ApplicationLayer(protocol=app_protocol, type="request"),
        flow=flow
        if flow is not None
        else FlowRef(
            flow_id="TCP-10.0.0.10:52000-10.0.0.20:80",
            direction="forward",
            state="ESTABLISHED",
            is_new_flow=False,
        ),
    )


def build_detection(event=None):
    event = event or make_event()
    outcome = RuleParser.parse(RULE_TEXT, "TEST/BT3/t14/rules.rules", 1)
    assert outcome.ok, outcome.reason
    rule = outcome.rule
    match = RuleMatcher.match(rule, event, b"GET /download?file=../../etc/passwd HTTP/1.1")
    assert match is not None
    return DetectionEventGenerator.generate(rule, match, event)


class TestDetectionEvent(unittest.TestCase):
    def test_full_field_set(self):
        detection = build_detection()
        data = detection.to_dict()

        self.assertEqual(data["sid"], 100001)
        self.assertEqual(data["rev"], 3)
        self.assertEqual(data["msg"], "Directory traversal detected")
        self.assertEqual(data["action"], "alert")
        self.assertEqual(data["classtype"], "attempted-admin")
        self.assertEqual(data["priority"], 1)
        self.assertEqual(data["protocol"], "TCP")
        self.assertEqual(data["application_protocol"], "HTTP")
        self.assertEqual(data["src_ip"], "10.0.0.10")
        self.assertEqual(data["src_port"], 52000)
        self.assertEqual(data["dst_ip"], "10.0.0.20")
        self.assertEqual(data["dst_port"], 80)
        self.assertEqual(data["flow_id"], "TCP-10.0.0.10:52000-10.0.0.20:80")
        self.assertEqual(data["flow_state"], "ESTABLISHED")
        self.assertEqual(data["direction"], "forward")
        self.assertEqual(data["rule_file"], "TEST/BT3/t14/rules.rules")
        self.assertEqual(data["packet_id"], 7)
        self.assertEqual(data["timestamp"], 1700000000.123457)  # làm tròn 6 chữ số
        self.assertTrue(data["timestamp_iso"].startswith("2023-11-14T"))

    def test_matched_info(self):
        detection = build_detection()
        matched = detection.to_dict()["matched"]
        self.assertEqual(len(matched["contents"]), 1)
        content = matched["contents"][0]
        self.assertEqual(content["content"], "../")
        self.assertTrue(content["nocase"])
        self.assertIsInstance(content["offset"], int)
        self.assertIn("flow:to_server,established", matched["fields"])
        self.assertIn("flags:PA", matched["fields"])

    def test_json_round_trip(self):
        detection = build_detection()
        parsed = json.loads(detection.to_json())
        self.assertEqual(parsed, detection.to_dict())

    def test_optional_fields_none(self):
        event = make_event()
        outcome = RuleParser.parse('alert udp any any -> any 53 (msg:"dns"; sid:55;)', "r.rules", 1)
        rule = outcome.rule
        match = RuleMatcher.match(rule, event, b"x")
        self.assertIsNone(match)  # TCP event không khớp rule UDP

        udp_event = make_event()
        udp_event.transport = TransportLayer(layer="UDP", src_port=50000, dst_port=53, payload_len=10)
        match = RuleMatcher.match(rule, udp_event, b"\x00\x01")
        detection = DetectionEventGenerator.generate(rule, match, udp_event)
        data = detection.to_dict()
        self.assertIsNone(data["classtype"])
        self.assertIsNone(data["priority"])
        self.assertEqual(data["rev"], 0)

    def test_no_flow_context_yields_empty_flow_fields(self):
        event = make_event()
        event.flow = None
        outcome = RuleParser.parse('alert tcp any any -> any 80 (msg:"m"; sid:66;)', "r.rules", 1)
        rule = outcome.rule
        match = RuleMatcher.match(rule, event, b"")
        detection = DetectionEventGenerator.generate(rule, match, event)
        data = detection.to_dict()
        self.assertEqual(data["flow_id"], "")
        self.assertEqual(data["flow_state"], "")
        self.assertEqual(data["direction"], "")

    def test_format_summary(self):
        summary = build_detection().format_summary()
        self.assertIn("[ALERT] sid=100001", summary)
        self.assertIn("Directory traversal detected", summary)
        self.assertIn("10.0.0.10:52000 -> 10.0.0.20:80", summary)
        self.assertIn("TCP/HTTP", summary)
        self.assertIn("flow=TCP-10.0.0.10:52000-10.0.0.20:80", summary)


if __name__ == "__main__":
    unittest.main()
