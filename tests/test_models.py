"""Unit tests for NormalizedEvent models and JsonLinesLogger."""

import json
import os
import tempfile
import unittest

from parsers.models import ApplicationLayer, NetworkLayer, NormalizedEvent, TransportLayer
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


if __name__ == "__main__":
    unittest.main()
