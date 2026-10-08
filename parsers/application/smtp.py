"""SMTP Application Protocol Parser.

Parses SMTP client commands (HELO, EHLO, MAIL FROM, RCPT TO, DATA, QUIT, etc.)
and SMTP server responses (status codes 220, 250, 354, 550, etc.) from raw payload bytes.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from parsers.detector import AppProtocolDetector
from parsers.models import ApplicationLayer

SMTP_CMD_PATTERN = re.compile(
    r"^(HELO|EHLO|MAIL\s+FROM\s*:|RCPT\s+TO\s*:|DATA|QUIT|RSET|STARTTLS|VRFY|EXPN|AUTH|NOOP)(?:[\s:]*(.*))?$",
    re.IGNORECASE,
)

SMTP_RESP_PATTERN = re.compile(r"^([2345]\d{2})([ -])(.*)$")


class SmtpParser:
    """Parses SMTP commands, responses and DATA-phase MIME messages."""

    @classmethod
    def parse(cls, payload: bytes) -> Tuple[Optional[ApplicationLayer], List[str]]:
        """Parse raw payload bytes into a normalized ApplicationLayer object.

        Args:
            payload: Raw bytes from transport layer.

        Returns:
            Tuple of (ApplicationLayer or None, list of errors).
        """
        errors: List[str] = []
        if not payload:
            return None, errors

        try:
            text = payload.decode("latin-1", errors="replace")
            lines = [line.strip("\r") for line in text.split("\n") if line.strip("\r").strip()]
            if not lines:
                return None, errors

            first_line = lines[0].strip()

            # Check if this is an SMTP Response (starts with 3-digit code)
            resp_match = SMTP_RESP_PATTERN.match(first_line)
            if resp_match:
                code_str, sep, msg = resp_match.groups()
                status_code = int(code_str)

                # Collect full message text from multi-line responses (e.g., 250-...)
                messages: List[str] = [msg.strip()]
                for line in lines[1:]:
                    m = SMTP_RESP_PATTERN.match(line.strip())
                    if m:
                        messages.append(m.group(3).strip())
                    else:
                        messages.append(line.strip())

                details: Dict[str, Any] = {
                    "status_code": status_code,
                    "message": " \n ".join(messages),
                    "raw_lines": lines,
                }
                return ApplicationLayer(protocol="SMTP", type="response", details=details), errors

            # Check if this is an SMTP Command
            cmd_match = SMTP_CMD_PATTERN.match(first_line)
            if cmd_match:
                raw_cmd, raw_arg = cmd_match.groups()
                clean_cmd = raw_cmd.upper().replace("  ", " ")
                # Normalize command name (e.g. "MAIL FROM:" -> "MAIL FROM")
                if clean_cmd.endswith(":"):
                    cmd_name = clean_cmd[:-1].strip()
                else:
                    cmd_name = clean_cmd.strip()

                arg = (raw_arg or "").strip()
                # Clean enclosing brackets for emails if present
                details = {
                    "command": cmd_name,
                    "argument": arg,
                    "raw_line": first_line,
                }
                return ApplicationLayer(protocol="SMTP", type="command", details=details), errors

            # SMTP DATA phase: an e-mail message (MIME headers + body) that
            # carries no SMTP command/response line of its own.
            if AppProtocolDetector.is_mime_payload(payload):
                return cls._parse_mime(payload), errors

            # If payload doesn't match standard SMTP patterns
            errors.append(f"Unrecognized SMTP line: {first_line}")
            return None, errors

        except Exception as exc:
            errors.append(f"SMTP parse error: {str(exc)}")
            return None, errors

    @classmethod
    def _split_message(cls, payload: bytes) -> Tuple[bytes, bytes]:
        """Split a MIME message into its header block and body."""
        if b"\r\n\r\n" in payload:
            header_raw, body_raw = payload.split(b"\r\n\r\n", 1)
        elif b"\n\n" in payload:
            header_raw, body_raw = payload.split(b"\n\n", 1)
        else:
            header_raw, body_raw = payload, b""
        return header_raw, body_raw

    @classmethod
    def _parse_header_block(cls, header_raw: bytes) -> Dict[str, str]:
        """Parse ``Key: value`` lines; original key case kept, first value wins."""
        headers: Dict[str, str] = {}
        text = header_raw.decode("latin-1", errors="replace")
        for line in text.split("\n"):
            line = line.strip("\r")
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key and key not in headers:
                headers[key] = value.strip()
        return headers

    @classmethod
    def _parse_mime(cls, payload: bytes) -> ApplicationLayer:
        """Parse an e-mail message body into an SMTP ``data`` ApplicationLayer."""
        header_raw, body_raw = cls._split_message(payload)
        details: Dict[str, Any] = {
            "headers": cls._parse_header_block(header_raw),
            "body": body_raw.decode("latin-1", errors="replace"),
            "mime": True,
        }
        return ApplicationLayer(protocol="SMTP", type="data", details=details)
