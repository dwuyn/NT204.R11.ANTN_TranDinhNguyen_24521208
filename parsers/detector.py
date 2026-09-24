"""Application Protocol Detector.

Detects application layer protocols (HTTP/1.x, DNS, SMTP) by combining
payload inspection (deep packet analysis) and port heuristics.
Supports detection on non-standard ports to satisfy assignment requirements.
"""

import re
from typing import Optional, Tuple

from scapy.all import Packet
from scapy.layers.dns import DNS

from parsers.models import TransportLayer

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
)

HTTP_RESPONSES = (
    b"HTTP/1.0 ",
    b"HTTP/1.1 ",
    b"HTTP/2.0 ",
)

# SMTP client commands (case-insensitive)
SMTP_COMMAND_RE = re.compile(
    rb"^(HELO\b|EHLO\b|MAIL\s+FROM\s*:|RCPT\s+TO\s*:|DATA\b|QUIT\b|RSET\b|STARTTLS\b|VRFY\b|EXPN\b|AUTH\b)",
    re.IGNORECASE,
)

# SMTP response line: 3 digits followed by space or hyphen (e.g. "220 ", "250-")
SMTP_RESPONSE_RE = re.compile(rb"^[2345]\d{2}[ -]")

HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 8443}
DNS_PORTS = {53, 5353}
SMTP_PORTS = {25, 587, 465, 2525}

DNS_VALID_CHARS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."


class AppProtocolDetector:
    """Detects Layer 7 application protocols via payload inspection and port signals."""

    @classmethod
    def is_http_payload(cls, payload: bytes) -> bool:
        """Check if payload begins with HTTP request method or response status line."""
        stripped = payload.lstrip()
        if not stripped:
            return False
        # Check HTTP request methods
        for method in HTTP_METHODS:
            if stripped.startswith(method):
                return True
        # Check HTTP response status line
        for resp in HTTP_RESPONSES:
            if stripped.startswith(resp):
                return True
        return False

    @classmethod
    def is_smtp_payload(cls, payload: bytes) -> bool:
        """Check if payload matches SMTP commands or server status responses."""
        stripped = payload.lstrip()
        if not stripped:
            return False

        # Check SMTP command regex (handles HELO, EHLO, MAIL FROM:<...>, etc.)
        if SMTP_COMMAND_RE.match(stripped):
            return True

        # Check SMTP response code (e.g., "220 mail.server.com", "250-OK", "354 Go ahead")
        if SMTP_RESPONSE_RE.match(stripped):
            return True

        return False

    @classmethod
    def is_dns_payload(cls, payload: bytes) -> bool:
        """Check if payload is a valid DNS wire-format message."""
        if len(payload) < 12:
            return False
        try:
            dns = DNS(payload)
            # Check opcode (standard query or status)
            if dns.opcode not in (0, 1, 2, 4, 5):
                return False

            # Query (qr == 0): expect valid qname
            if dns.qr == 0:
                if dns.qdcount >= 1 and dns.qd is not None:
                    qname = getattr(dns.qd, "qname", b"")
                    if qname and isinstance(qname, bytes) and len(qname) > 1:
                        if all(c in DNS_VALID_CHARS for c in qname):
                            return True
            # Response (qr == 1): expect answers or valid rcode
            elif dns.qr == 1:
                if (dns.ancount >= 1 and dns.an is not None) or dns.rcode != 0:
                    return True
        except Exception:
            pass
        return False

    @classmethod
    def detect(
        cls,
        packet: Packet,
        transport: Optional[TransportLayer],
        payload: bytes,
    ) -> Tuple[str, str]:
        """Detect the application protocol from packet, transport metadata, and payload.

        Args:
            packet: The Scapy packet.
            transport: Normalized TransportLayer metadata.
            payload: Raw bytes extracted from transport layer.

        Returns:
            Tuple of (protocol_name, detection_method).
            protocol_name: "HTTP", "DNS", "SMTP", or "UNKNOWN".
            detection_method: "payload_signature", "scapy_layer", "port_heuristic", or "none".
        """
        # 1. Scapy layer check for DNS
        if packet.haslayer(DNS):
            return "DNS", "scapy_layer"

        # If there is no payload, no application data is present
        if not payload:
            return "UNKNOWN", "none"

        # 2. Payload-based detection (prioritized over ports to detect non-standard ports)
        if cls.is_http_payload(payload):
            return "HTTP", "payload_signature"

        if cls.is_smtp_payload(payload):
            return "SMTP", "payload_signature"

        if cls.is_dns_payload(payload):
            return "DNS", "payload_signature"

        # 3. Port-based fallback heuristics if payload signature was inconclusive
        # Only fallback to text protocols if payload is mostly printable ASCII
        if transport:
            ports = {transport.src_port, transport.dst_port}
            if ports & DNS_PORTS:
                return "DNS", "port_heuristic"

            is_printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in payload[:100])
            if is_printable:
                if ports & HTTP_PORTS:
                    return "HTTP", "port_heuristic"
                if ports & SMTP_PORTS:
                    return "SMTP", "port_heuristic"

        return "UNKNOWN", "default"
