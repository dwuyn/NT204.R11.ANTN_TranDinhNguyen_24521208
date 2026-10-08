"""Unit tests for NormalizedEvent models and JsonLinesLogger."""

import json
import os
import tempfile
import unittest

from parsers.models import (
    ApplicationLayer,
    DecodeInfo,
    FlowRef,
    NetworkLayer,
    NormalizedEvent,
    PreprocessInfo,
    TransportLayer,
)
from storage.logger import JsonLinesLogger


class TestNormalizedEventModels(unittest.TestCase):
    def test_normalized_event_serialization(self):
        net = NetworkLayer(
            layer="IPv4",
            src_ip="192.168.1.50",
            dst_ip="93.184.216.34",
            proto="TCP",
            ttl=64,
            id=54321,
            flags=["DF"],
            total_len=60,
        )
        trans = TransportLayer(
            layer="TCP",
            src_port=49152,
            dst_port=80,
            seq=1000,
            ack=0,
            flags=["SYN"],
            window=65535,
            payload_len=0,
        )
        app = ApplicationLayer(
            protocol="HTTP",
            type="request",
            details={"method": "GET", "uri": "/index.html"},
        )
        event = NormalizedEvent(
            packet_id=1,
            timestamp=1710892800.123456,
            raw_len=74,
            network=net,
            transport=trans,
            application=app,
            errors=[],
        )

        event_dict = event.to_dict()
        self.assertEqual(event_dict["packet_id"], 1)
        self.assertEqual(event_dict["network"]["src_ip"], "192.168.1.50")
        self.assertEqual(event_dict["transport"]["flags"], ["SYN"])
        self.assertEqual(event_dict["application"]["details"]["method"], "GET")

        # Check JSON validity
        json_str = event.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["packet_id"], 1)
        self.assertEqual(parsed["network"]["proto"], "TCP")
        self.assertEqual(parsed["transport"]["dst_port"], 80)

    def test_json_lines_logger(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "events.jsonl")
            event1 = NormalizedEvent(
                packet_id=1,
                timestamp=1000.0,
                raw_len=64,
                network=NetworkLayer(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="UDP"),
                transport=TransportLayer(layer="UDP", src_port=53, dst_port=5353, payload_len=20),
            )
            event2 = NormalizedEvent(
                packet_id=2,
                timestamp=1001.0,
                raw_len=128,
                network=NetworkLayer(src_ip="10.0.0.2", dst_ip="10.0.0.1", proto="UDP"),
                transport=TransportLayer(layer="UDP", src_port=5353, dst_port=53, payload_len=84),
            )

            with JsonLinesLogger(filepath=log_path, console_summary=False) as logger:
                logger.log(event1)
                logger.log(event2)

            # Read back and verify lines
            with open(log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            self.assertEqual(len(lines), 2)
            item1 = json.loads(lines[0])
            item2 = json.loads(lines[1])
            self.assertEqual(item1["packet_id"], 1)
            self.assertEqual(item2["packet_id"], 2)

    def test_summary_formatter(self):
        event = NormalizedEvent(
            packet_id=5,
            timestamp=1000.0,
            raw_len=74,
            network=NetworkLayer(src_ip="192.168.1.1", dst_ip="192.168.1.2", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=1234, dst_port=80, flags=["SYN"]),
            application=ApplicationLayer(protocol="HTTP", type="request"),
        )
        summary = JsonLinesLogger.format_summary(event)
        self.assertIn("[0005]", summary)
        self.assertIn("192.168.1.1 -> 192.168.1.2", summary)
        self.assertIn(":1234 -> :80 [SYN]", summary)
        self.assertIn("HTTP (request)", summary)


class TestAssignmentTwoSchema(unittest.TestCase):
    def test_pipeline_one_event_has_null_sections(self):
        event = NormalizedEvent(packet_id=1, timestamp=1000.0, raw_len=64)
        data = event.to_dict()
        self.assertIsNone(data["decode"])
        self.assertIsNone(data["preprocess"])
        self.assertIsNone(data["flow"])

    def test_event_with_all_sections_serializes(self):
        event = NormalizedEvent(
            packet_id=7,
            timestamp=1700000000.0,
            raw_len=120,
            network=NetworkLayer(src_ip="10.0.0.10", dst_ip="10.0.0.20", proto="TCP"),
            transport=TransportLayer(layer="TCP", src_port=52000, dst_port=80, payload_len=56),
            application=ApplicationLayer(protocol="HTTP", type="request"),
            decode=DecodeInfo(
                decode_status="decoded",
                decoders=["percent_url"],
                fields={"uri_decoded": "/search?q=' OR 1=1"},
            ),
            preprocess=PreprocessInfo(
                preprocess_status="valid",
                processing_action="forward",
                normalizations=["protocol_name"],
            ),
            flow=FlowRef(
                flow_id="TCP-10.0.0.10:52000-10.0.0.20:80",
                direction="forward",
                state="ESTABLISHED",
                is_new_flow=True,
            ),
        )
        data = event.to_dict()
        self.assertEqual(data["decode"]["decode_status"], "decoded")
        self.assertEqual(data["decode"]["decoders"], ["percent_url"])
        self.assertEqual(data["decode"]["fields"]["uri_decoded"], "/search?q=' OR 1=1")
        self.assertEqual(data["decode"]["warnings"], [])
        self.assertEqual(data["preprocess"]["preprocess_status"], "valid")
        self.assertEqual(data["preprocess"]["processing_action"], "forward")
        self.assertIsNone(data["preprocess"]["reason"])
        self.assertEqual(data["preprocess"]["normalizations"], ["protocol_name"])
        self.assertEqual(data["flow"]["flow_id"], "TCP-10.0.0.10:52000-10.0.0.20:80")
        self.assertEqual(data["flow"]["direction"], "forward")
        self.assertTrue(data["flow"]["is_new_flow"])

        round_tripped = json.loads(event.to_json())
        self.assertEqual(round_tripped, data)

    def test_section_dataclasses_do_not_share_mutable_state(self):
        first = DecodeInfo()
        second = DecodeInfo()
        first.decoders.append("base64")
        first.fields["k"] = "v"
        first.warnings.append("w")
        self.assertEqual(second.decoders, [])
        self.assertEqual(second.fields, {})
        self.assertEqual(second.warnings, [])

        first_pre = PreprocessInfo()
        second_pre = PreprocessInfo()
        first_pre.normalizations.append("uri_path")
        first_pre.warnings.append("duplicate_header_name")
        self.assertEqual(second_pre.normalizations, [])
        self.assertEqual(second_pre.warnings, [])

    def test_decode_info_defaults(self):
        info = DecodeInfo().to_dict()
        self.assertEqual(info, {
            "decode_status": "unchanged",
            "decoders": [],
            "fields": {},
            "warnings": [],
        })


if __name__ == "__main__":
    unittest.main()
