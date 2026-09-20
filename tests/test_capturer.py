"""Unit tests for capture/capturer.py."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from scapy.all import IP, TCP, UDP, wrpcap

from capture.capturer import CapturedPacket, PacketCapture


class TestPacketCapture(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.tmpdir.name, "sample.pcap")

        # Create a small synthetic PCAP with 2 packets
        pkt1 = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="S")
        pkt2 = IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=53, dport=5353)
        wrpcap(self.pcap_path, [pkt1, pkt2])

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_read_pcap_success(self):
        packets = list(PacketCapture.read_pcap(self.pcap_path))
        self.assertEqual(len(packets), 2)

        # Check packet 1
        p1 = packets[0]
        self.assertIsInstance(p1, CapturedPacket)
        self.assertEqual(p1.packet_id, 1)
        self.assertGreater(p1.timestamp, 0)
        self.assertTrue(len(p1.raw_bytes) > 0)
        self.assertTrue(p1.packet.haslayer(TCP))

        # Check packet 2
        p2 = packets[1]
        self.assertEqual(p2.packet_id, 2)
        self.assertTrue(p2.packet.haslayer(UDP))

    def test_read_pcap_not_found(self):
        with self.assertRaises(FileNotFoundError):
            list(PacketCapture.read_pcap("/non/existent/path/file.pcap"))

    def test_read_empty_pcap(self):
        empty_pcap = os.path.join(self.tmpdir.name, "empty.pcap")
        wrpcap(empty_pcap, [])
        packets = list(PacketCapture.read_pcap(empty_pcap))
        self.assertEqual(len(packets), 0)

    @patch("capture.capturer.sniff")
    def test_capture_live_mocked(self, mock_sniff):
        pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=5000)
        pkt2 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=5000, dport=80)

        def fake_sniff(**kwargs):
            callback = kwargs.get("prn")
            if callback:
                callback(pkt1)
                callback(pkt2)

        mock_sniff.side_effect = fake_sniff

        captured = list(PacketCapture.capture_live(interface="eth0", count=2))
        self.assertEqual(len(captured), 2)
        self.assertEqual(captured[0].packet_id, 1)
        self.assertEqual(captured[1].packet_id, 2)
        self.assertTrue(captured[0].packet.haslayer(IP))

    def test_capture_live_permission_denied(self):
        if os.geteuid() != 0:
            # Without root, sniffing a real interface should raise PermissionError with friendly message
            with self.assertRaises(PermissionError) as ctx:
                list(PacketCapture.capture_live(interface="lo", count=1, timeout=0.1))
            self.assertIn("requires root privileges", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
