"""Unit tests for parsers/transport.py."""

import unittest
from scapy.all import ICMP, IP, Raw, TCP, UDP

from parsers.transport import TransportParser


class TestTransportParser(unittest.TestCase):
    def test_tcp_handshake_syn(self):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=50000, dport=80, flags="S", seq=100)
        layer, payload, errors = TransportParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertEqual(errors, [])
        self.assertEqual(layer.layer, "TCP")
        self.assertEqual(layer.src_port, 50000)
        self.assertEqual(layer.dst_port, 80)
        self.assertEqual(layer.flags, ["SYN"])
        self.assertEqual(layer.handshake, "SYN")
        self.assertEqual(layer.payload_len, 0)
        self.assertEqual(payload, b"")

    def test_tcp_handshake_syn_ack(self):
        pkt = IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=80, dport=50000, flags="SA", seq=200, ack=101)
        layer, payload, errors = TransportParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertIn("SYN", layer.flags)
        self.assertIn("ACK", layer.flags)
        self.assertEqual(layer.handshake, "SYN-ACK")
        self.assertEqual(layer.seq, 200)
        self.assertEqual(layer.ack, 101)

    def test_tcp_handshake_ack(self):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=50000, dport=80, flags="A", seq=101, ack=201)
        layer, payload, errors = TransportParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertEqual(layer.flags, ["ACK"])
        self.assertEqual(layer.handshake, "ACK")
        self.assertEqual(layer.payload_len, 0)

    def test_tcp_data_packet(self):
        data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=50000, dport=80, flags="PA", seq=101, ack=201) / Raw(data)
        layer, payload, errors = TransportParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertEqual(layer.layer, "TCP")
        self.assertIn("PSH", layer.flags)
        self.assertIn("ACK", layer.flags)
        self.assertIsNone(layer.handshake)
        self.assertEqual(layer.payload_len, len(data))
        self.assertEqual(payload, data)

    def test_udp_packet(self):
        data = b"\x12\x34\x01\x00\x00\x01"
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=54321) / Raw(data)
        layer, payload, errors = TransportParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertEqual(layer.layer, "UDP")
        self.assertEqual(layer.src_port, 53)
        self.assertEqual(layer.dst_port, 54321)
        self.assertEqual(layer.payload_len, len(data))
        self.assertEqual(payload, data)

    def test_non_transport_packet(self):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        layer, payload, errors = TransportParser.parse(pkt)

        self.assertIsNone(layer)
        self.assertEqual(payload, b"")
        self.assertEqual(errors, [])

    def test_malformed_transport_packet(self):
        class MockCorruptTCPPacket:
            def haslayer(self, layer):
                return True
            def __getitem__(self, item):
                raise ValueError("Corrupted TCP header")

        layer, payload, errors = TransportParser.parse(MockCorruptTCPPacket())
        self.assertIsNone(layer)
        self.assertEqual(payload, b"")
        self.assertEqual(len(errors), 1)
        self.assertIn("Corrupted TCP header", errors[0])


if __name__ == "__main__":
    unittest.main()
