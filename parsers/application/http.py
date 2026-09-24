"""HTTP/1.x Application Protocol Parser.

Parses HTTP requests (method, URI, headers, body) and HTTP responses
(status code, reason phrase, headers, body) from raw payload bytes.
Handles malformed lines and binary bodies gracefully.
"""

from typing import Any, Dict, List, Optional, Tuple

from parsers.models import ApplicationLayer


class HttpParser:
    """Parses HTTP/1.x requests and responses."""

    @classmethod
    def parse(cls, payload: bytes) -> Tuple[Optional[ApplicationLayer], List[str]]:
        """Parse raw payload bytes into a normalized ApplicationLayer object.

        Args:
            payload: Raw bytes extracted from transport layer.

        Returns:
            Tuple of (ApplicationLayer or None, list of errors).
        """
        errors: List[str] = []
        if not payload:
            return None, errors

        try:
            # Separate headers and body using standard HTTP delimiters
            if b"\r\n\r\n" in payload:
                header_raw, body_raw = payload.split(b"\r\n\r\n", 1)
            elif b"\n\n" in payload:
                header_raw, body_raw = payload.split(b"\n\n", 1)
            else:
                header_raw, body_raw = payload, b""

            header_text = header_raw.decode("latin-1", errors="replace")
            lines = [line.strip("\r") for line in header_text.split("\n")]
            if not lines or not lines[0]:
                return None, errors

            first_line = lines[0].strip()
            parts = first_line.split(" ", 2)

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if not line or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

            # Decode body safely
            try:
                body = body_raw.decode("utf-8")
            except UnicodeDecodeError:
                body = body_raw.decode("latin-1", errors="replace")

            # Check if this is an HTTP Response
            if parts[0].upper().startswith("HTTP/"):
                version = parts[0]
                status_code = 0
                reason = ""
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        errors.append(f"Invalid HTTP status code: {parts[1]}")
                if len(parts) >= 3:
                    reason = parts[2]

                details: Dict[str, Any] = {
                    "version": version,
                    "status_code": status_code,
                    "reason": reason,
                    "headers": headers,
                    "body": body,
                }
                return ApplicationLayer(protocol="HTTP", type="response", details=details), errors

            # Otherwise, treat as HTTP Request
            elif len(parts) >= 2:
                method = parts[0].upper()
                uri = parts[1]
                version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

                details = {
                    "method": method,
                    "uri": uri,
                    "version": version,
                    "headers": headers,
                    "body": body,
                }
                return ApplicationLayer(protocol="HTTP", type="request", details=details), errors

            else:
                errors.append(f"Unrecognized HTTP start line: {first_line}")
                return None, errors

        except Exception as exc:
            errors.append(f"HTTP parse error: {str(exc)}")
            return None, errors
