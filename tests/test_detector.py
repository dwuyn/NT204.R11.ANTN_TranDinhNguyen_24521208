"""Unit tests for parsers/detector.py."""

import unittest
from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP

from parsers.detector import AppProtocolDetector
from parsers.models import TransportLayer


class TestAppProtocolDetector(unittest.TestCase):
    def test_http_request_standard_port(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = IP() / TCP(sport=54321, dport=80) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=54321, dst_port=80, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "HTTP")
        self.assertEqual(method, "payload_signature")

    def test_http_request_non_standard_port(self):
        # Non-standard port 8888 or 9090
        payload = b"POST /api/login HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\nuser=test"
        pkt = IP() / TCP(sport=54321, dport=9090) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=54321, dst_port=9090, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "HTTP")
        self.assertEqual(method, "payload_signature")

    def test_http_response_detection(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        pkt = IP() / TCP(sport=8080, dport=54321) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=8080, dst_port=54321, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "HTTP")
        self.assertEqual(method, "payload_signature")

    def test_dns_scapy_layer(self):
        pkt = IP() / UDP(sport=53, dport=12345) / DNS(rd=1, qd=DNSQR(qname="google.com"))
        trans = TransportLayer(layer="UDP", src_port=53, dst_port=12345, payload_len=28)
        payload = bytes(pkt[UDP].payload)

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "DNS")
        self.assertEqual(method, "scapy_layer")

    def test_dns_non_standard_port_raw_payload(self):
        # DNS wire payload over custom UDP port 44556
        raw_dns = bytes(DNS(rd=1, qd=DNSQR(qname="uit.edu.vn")))
        pkt = IP() / UDP(sport=44556, dport=44557) / Raw(raw_dns)
        trans = TransportLayer(layer="UDP", src_port=44556, dst_port=44557, payload_len=len(raw_dns))

        proto, method = AppProtocolDetector.detect(pkt, trans, raw_dns)
        self.assertEqual(proto, "DNS")
        self.assertEqual(method, "payload_signature")

    def test_smtp_command_standard_port(self):
        payload = b"HELO mail.example.com\r\n"
        pkt = IP() / TCP(sport=54321, dport=25) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=54321, dst_port=25, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "SMTP")
        self.assertEqual(method, "payload_signature")

    def test_smtp_command_non_standard_port(self):
        # SMTP on non-standard port 25255
        payload = b"MAIL FROM:<sender@test.com>\r\n"
        pkt = IP() / TCP(sport=54321, dport=25255) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=54321, dst_port=25255, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "SMTP")
        self.assertEqual(method, "payload_signature")

    def test_smtp_response_greeting(self):
        payload = b"220 smtp.relay.com ESMTP Service Ready\r\n"
        pkt = IP() / TCP(sport=25, dport=54321) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=25, dst_port=54321, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "SMTP")
        self.assertEqual(method, "payload_signature")

    def test_unknown_protocol(self):
        payload = b"\xde\xad\xbe\xef\x01\x02\x03\x04"
        pkt = IP() / TCP(sport=9999, dport=8888) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=9999, dst_port=8888, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "UNKNOWN")
        self.assertEqual(method, "default")

    def test_empty_payload(self):
        pkt = IP() / TCP(sport=54321, dport=80, flags="A")
        trans = TransportLayer(layer="TCP", src_port=54321, dst_port=80, payload_len=0)

        proto, method = AppProtocolDetector.detect(pkt, trans, b"")
        self.assertEqual(proto, "UNKNOWN")
        self.assertEqual(method, "none")


if __name__ == "__main__":
    unittest.main()
