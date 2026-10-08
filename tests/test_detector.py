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

    def test_plain_text_on_http_port_is_not_http(self):
        payload = b"User data stream payload over TCP connection"
        pkt = IP() / TCP(sport=51234, dport=80) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=51234, dst_port=80, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "UNKNOWN")
        self.assertEqual(method, "default")

    def test_plain_text_on_smtp_port_is_not_smtp(self):
        payload = b"custom application handshake bytes"
        pkt = IP() / TCP(sport=45000, dport=25) / Raw(payload)
        trans = TransportLayer(layer="TCP", src_port=45000, dst_port=25, payload_len=len(payload))

        proto, method = AppProtocolDetector.detect(pkt, trans, payload)
        self.assertEqual(proto, "UNKNOWN")
        self.assertEqual(method, "default")


class TestMimeDetection(unittest.TestCase):
    MIME_BLOCK = (
        b"From: sender@uit.edu.vn\r\n"
        b"To: rcpt@uit.edu.vn\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"SGVsbG8gV29ybGQh"
    )

    def test_mime_data_on_standard_port_is_smtp(self):
        pkt = IP(src="10.0.0.10", dst="10.0.0.25") / TCP(sport=45000, dport=25, flags="PA") / Raw(
            self.MIME_BLOCK
        )
        transport = TransportLayer(layer="TCP", src_port=45000, dst_port=25, payload_len=len(self.MIME_BLOCK))

        protocol, method = AppProtocolDetector.detect(pkt, transport, self.MIME_BLOCK)
        self.assertEqual(protocol, "SMTP")
        self.assertEqual(method, "payload_signature")

    def test_mime_data_on_non_standard_port_is_smtp(self):
        pkt = IP(src="10.0.0.10", dst="10.0.0.25") / TCP(sport=45000, dport=8025, flags="PA") / Raw(
            self.MIME_BLOCK
        )
        transport = TransportLayer(layer="TCP", src_port=45000, dst_port=8025, payload_len=len(self.MIME_BLOCK))

        protocol, method = AppProtocolDetector.detect(pkt, transport, self.MIME_BLOCK)
        self.assertEqual(protocol, "SMTP")
        self.assertEqual(method, "payload_signature")

    def test_quoted_printable_marker_is_mime(self):
        payload = (
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"Xin ch=C3=A0o"
        )
        self.assertTrue(AppProtocolDetector.is_mime_payload(payload))

    def test_content_type_only_is_not_mime(self):
        payload = b"Content-Type: text/plain\r\n\r\nhello world"
        self.assertFalse(AppProtocolDetector.is_mime_payload(payload))

    def test_http_request_is_not_mime(self):
        payload = b"GET /x HTTP/1.1\r\nHost: a\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        self.assertFalse(AppProtocolDetector.is_mime_payload(payload))
        self.assertTrue(AppProtocolDetector.is_http_payload(payload))

    def test_plain_text_line_is_not_mime(self):
        self.assertFalse(AppProtocolDetector.is_mime_payload(b"just some plain text"))
        self.assertFalse(AppProtocolDetector.is_mime_payload(b""))
        self.assertFalse(AppProtocolDetector.is_mime_payload(b"\xde\xad\xbe\xef"))

    def test_mime_marker_outside_header_block_is_ignored(self):
        payload = (
            b"From: a@b.c\r\n"
            b"\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
        )
        self.assertFalse(AppProtocolDetector.is_mime_payload(payload))

    def test_existing_http_and_smtp_detection_unchanged(self):
        payload = b"POST /api/login HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\nuser=test"
        self.assertEqual(AppProtocolDetector.detect(IP() / TCP(), None, payload), ("HTTP", "payload_signature"))
        self.assertEqual(
            AppProtocolDetector.detect(IP() / TCP(), None, b"MAIL FROM:<a@b.c>\r\n"),
            ("SMTP", "payload_signature"),
        )
        self.assertEqual(
            AppProtocolDetector.detect(IP() / TCP(), None, b"\xde\xad\xbe\xef\x01\x02\x03\x04"),
            ("UNKNOWN", "default"),
        )


if __name__ == "__main__":
    unittest.main()
