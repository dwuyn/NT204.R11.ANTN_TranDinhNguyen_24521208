"""Unit tests for parsers/network.py."""

import unittest
from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP

from parsers.network import NetworkParser


class TestNetworkParser(unittest.TestCase):
    def test_parse_ipv4_tcp(self):
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1", ttl=64, id=1234, flags="DF") / TCP(sport=1234, dport=80)
        layer, errors = NetworkParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertEqual(errors, [])
        self.assertEqual(layer.layer, "IPv4")
        self.assertEqual(layer.src_ip, "192.168.1.100")
        self.assertEqual(layer.dst_ip, "10.0.0.1")
        self.assertEqual(layer.proto, "TCP")
        self.assertEqual(layer.ttl, 64)
        self.assertEqual(layer.id, 1234)
        self.assertIn("DF", layer.flags)

    def test_parse_ipv4_udp(self):
        pkt = IP(src="8.8.8.8", dst="192.168.1.50", proto=17) / UDP(sport=53, dport=54321)
        layer, errors = NetworkParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertEqual(errors, [])
        self.assertEqual(layer.proto, "UDP")
        self.assertEqual(layer.src_ip, "8.8.8.8")
        self.assertEqual(layer.dst_ip, "192.168.1.50")

    def test_parse_ipv4_icmp(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        layer, errors = NetworkParser.parse(pkt)

        self.assertIsNotNone(layer)
        self.assertEqual(layer.proto, "ICMP")

    def test_parse_non_ipv4(self):
        # ARP packet without IP layer
        arp_pkt = Ether() / ARP()
        layer, errors = NetworkParser.parse(arp_pkt)

        self.assertIsNone(layer)
        self.assertEqual(errors, [])

    def test_parse_malformed_packet(self):
        # Raw bytes or object that throws when accessing attributes
        class MockCorruptPacket:
            def haslayer(self, layer):
                return True
            def __getitem__(self, item):
                raise ValueError("Corrupted IP header bytes")

        layer, errors = NetworkParser.parse(MockCorruptPacket())
        self.assertIsNone(layer)
        self.assertEqual(len(errors), 1)
        self.assertIn("Corrupted IP header bytes", errors[0])


if __name__ == "__main__":
    unittest.main()
