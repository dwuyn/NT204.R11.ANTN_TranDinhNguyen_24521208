"""Unit tests for pipeline/pipeline.py."""

import unittest
from scapy.all import ARP, DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from capture.capturer import CapturedPacket
from pipeline.pipeline import ParsingPipeline


class TestParsingPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = ParsingPipeline()

    def test_pipeline_http_packet(self):
        payload = b"GET /status HTTP/1.1\r\nHost: api.test\r\n\r\n"
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="PA") / Raw(payload)
        captured = CapturedPacket(packet_id=1, timestamp=100.0, packet=pkt, raw_bytes=bytes(pkt))

        event = self.pipeline.process_packet(captured)

        self.assertEqual(event.packet_id, 1)
        self.assertEqual(event.network.src_ip, "10.0.0.1")
        self.assertEqual(event.transport.layer, "TCP")
        self.assertEqual(event.transport.dst_port, 80)
        self.assertEqual(event.application.protocol, "HTTP")
        self.assertEqual(event.application.details["method"], "GET")
        self.assertEqual(event.errors, [])

    def test_pipeline_dns_packet(self):
        pkt = IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(id=0x1111, rd=1, qd=DNSQR(qname="uit.edu.vn"))
        captured = CapturedPacket(packet_id=2, timestamp=101.0, packet=pkt, raw_bytes=bytes(pkt))

        event = self.pipeline.process_packet(captured)

        self.assertEqual(event.packet_id, 2)
        self.assertEqual(event.network.proto, "UDP")
        self.assertEqual(event.transport.dst_port, 53)
        self.assertEqual(event.application.protocol, "DNS")
        self.assertEqual(event.application.type, "query")
        self.assertEqual(event.application.details["queries"][0]["name"], "uit.edu.vn")

    def test_pipeline_tcp_handshake_syn(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=44444, dport=443, flags="S", seq=100)
        captured = CapturedPacket(packet_id=3, timestamp=102.0, packet=pkt, raw_bytes=bytes(pkt))

        event = self.pipeline.process_packet(captured)

        self.assertEqual(event.transport.flags, ["SYN"])
        self.assertEqual(event.transport.handshake, "SYN")
        self.assertEqual(event.errors, [])

    def test_pipeline_non_ip_packet(self):
        pkt = Ether() / ARP()
        captured = CapturedPacket(packet_id=4, timestamp=103.0, packet=pkt, raw_bytes=bytes(pkt))

        event = self.pipeline.process_packet(captured)

        self.assertIsNone(event.network)
        self.assertIsNone(event.transport)
        self.assertEqual(event.errors, [])

    def test_pipeline_corrupted_packet_never_crashes(self):
        class MalformedPacket:
            def haslayer(self, layer):
                raise RuntimeError("Catastrophic header failure")
            def __len__(self):
                return 10

        captured = CapturedPacket(packet_id=5, timestamp=104.0, packet=MalformedPacket(), raw_bytes=b"")
        event = self.pipeline.process_packet(captured)

        self.assertEqual(event.packet_id, 5)
        self.assertTrue(len(event.errors) > 0)
        self.assertIn("Catastrophic header failure", event.errors[0])


    def test_parse_returns_event_and_raw_payload(self):
        payload = b"POST /api/login HTTP/1.1\r\nHost: api.test\r\n\r\nuser=test"
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50001, dport=80, flags="PA") / Raw(payload)
        captured = CapturedPacket(packet_id=6, timestamp=105.0, packet=pkt, raw_bytes=bytes(pkt))

        event, raw_payload = self.pipeline.parse(captured)

        self.assertEqual(raw_payload, payload)
        self.assertEqual(event.application.details["uri"], "/api/login")

    def test_parse_returns_empty_payload_without_transport(self):
        pkt = Ether() / ARP()
        captured = CapturedPacket(packet_id=7, timestamp=106.0, packet=pkt, raw_bytes=bytes(pkt))

        event, raw_payload = self.pipeline.parse(captured)

        self.assertEqual(raw_payload, b"")
        self.assertIsNone(event.network)

    def test_process_packet_still_matches_parse(self):
        payload = b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n"
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50002, dport=80, flags="PA") / Raw(payload)
        captured = CapturedPacket(packet_id=8, timestamp=107.0, packet=pkt, raw_bytes=bytes(pkt))

        event = self.pipeline.process_packet(captured)

        self.assertEqual(event.to_dict()["application"]["details"]["uri"], "/x")
        self.assertIsNone(event.decode)  # decode is attached by the engine, not the parser


if __name__ == "__main__":
    unittest.main()
