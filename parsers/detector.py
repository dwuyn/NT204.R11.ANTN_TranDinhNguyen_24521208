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

# MIME (e-mail) message data: first line is a header "Key: value", and the
# header block carries a transfer-encoding / MIME version marker.
MIME_HEADER_KEY_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9-]*:")
MIME_TRANSFER_HEADER_RE = re.compile(rb"(?im)^(content-transfer-encoding|mime-version):")

# Only the first 4 KiB are inspected when looking for MIME markers.
MIME_HEADER_SCAN_LIMIT = 4096

DNS_PORTS = {53, 5353}

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
    def is_mime_payload(cls, payload: bytes) -> bool:
        """Check if payload is e-mail MIME message data (headers + body).

        Used for SMTP DATA transfers, which carry no SMTP command/response
        line but are still SMTP traffic. Requires both a header-style first
        line and an explicit MIME marker in the header block, so that plain
        text bodies are not misclassified.
        """
        stripped = payload.lstrip(b"\r\n")
        if not stripped:
            return False

        first_line = stripped.split(b"\n", 1)[0].rstrip(b"\r")
        if not MIME_HEADER_KEY_RE.match(first_line):
            return False

        head = stripped[:MIME_HEADER_SCAN_LIMIT]
        for separator in (b"\r\n\r\n", b"\n\n"):
            if separator in head:
                head = head.split(separator, 1)[0]
                break
        return bool(MIME_TRANSFER_HEADER_RE.search(head))

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

        # SMTP DATA phase: an e-mail message (MIME headers + body) with no
        # SMTP command/response line of its own.
        if cls.is_mime_payload(payload):
            return "SMTP", "payload_signature"

        if cls.is_dns_payload(payload):
            return "DNS", "payload_signature"

        # 3. Port-based fallback: DNS is binary and has no reliable text
        # signature on every message, so its port is still a useful signal.
        # HTTP/SMTP are detected by payload signature only, to avoid flagging
        # arbitrary printable TCP payloads on port 80/25 as those protocols.
        if transport:
            ports = {transport.src_port, transport.dst_port}
            if ports & DNS_PORTS:
                return "DNS", "port_heuristic"

        return "UNKNOWN", "default"
