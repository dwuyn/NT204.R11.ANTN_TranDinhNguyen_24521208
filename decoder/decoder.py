"""Decoder stage: decodes application payloads into normalized text fields.

Responsibilities:
  * percent/URL decoding (``%27``) and ``+`` -> space (form bodies),
  * HTML entity decoding (``&lt;script&gt;``) for HTML-ish text bodies,
  * form-urlencoded body splitting into fields,
  * MIME transfer-encoding decoding (base64, quoted-printable) and RFC 2047
    header decoding,
  * character decoding (ASCII/UTF-8) with replacement on invalid byte
    sequences instead of crashing.

Every failure mode is captured in ``event.decode`` (``decode_status``,
``warnings``) so that a single malformed packet never stops the pipeline.
"""

import base64
import binascii
import html
import quopri
import re
from email.header import decode_header, make_header
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote_to_bytes

from config import DecoderConfig
from parsers.models import DecodeInfo, NormalizedEvent

# ``decode_status`` priority: a later stage never downgrades the status.
_STATUS_PRIORITY = {
    "unchanged": 0,
    "skipped": 1,
    "decoded": 2,
    "partial": 3,
    "error": 4,
}

# Content types whose bodies are treated as generic text (decode to str).
TEXT_CONTENT_TYPES = frozenset({
    "application/javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
})

# Content types whose decoded bodies additionally get HTML entity decoding.
HTML_CONTENT_TYPES = frozenset({
    "text/html",
    "text/plain",
    "text/xml",
    "application/xhtml+xml",
})

# Declared charset -> Python codec. Unknown charsets fall back to UTF-8 with a
# warning instead of failing the packet.
CHARSET_ALIASES = {
    "utf-8": "utf-8",
    "utf8": "utf-8",
    "us-ascii": "ascii",
    "ascii": "ascii",
    "latin-1": "latin-1",
    "latin1": "latin-1",
    "iso-8859-1": "latin-1",
    "windows-1252": "windows-1252",
    "cp1252": "windows-1252",
}


def _escalate(info: DecodeInfo, status: str) -> None:
    """Raise ``info.decode_status`` to ``status`` when it has higher priority."""
    if _STATUS_PRIORITY[status] > _STATUS_PRIORITY.get(info.decode_status, 0):
        info.decode_status = status


def _add_warning(info: DecodeInfo, warning: str) -> None:
    """Append ``warning`` once, preserving insertion order."""
    if warning not in info.warnings:
        info.warnings.append(warning)


def _add_decoder(info: DecodeInfo, name: str) -> None:
    """Record that a decoder transformed data (implies ``decoded`` status)."""
    if name not in info.decoders:
        info.decoders.append(name)
    _escalate(info, "decoded")


def _split_body(payload: bytes) -> bytes:
    """Return the body that follows the first header/body separator."""
    if b"\r\n\r\n" in payload:
        return payload.split(b"\r\n\r\n", 1)[1]
    if b"\n\n" in payload:
        return payload.split(b"\n\n", 1)[1]
    return b""


def _header_value(headers: Any, name: str) -> Optional[str]:
    """Case-insensitive header lookup that tolerates non-dict input."""
    if not isinstance(headers, dict):
        return None
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return value if isinstance(value, str) else str(value)
    return None


def _parse_content_type(value: Optional[str]) -> Tuple[str, Dict[str, str]]:
    """Split ``text/html; charset=utf-8`` into main type and parameters."""
    if not value:
        return "", {}
    parts = value.split(";")
    main = parts[0].strip().lower()
    params: Dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, param_value = part.split("=", 1)
            params[key.strip().lower()] = param_value.strip().strip('"')
    return main, params


def _resolve_charset(declared: Optional[str], info: DecodeInfo) -> str:
    """Map a declared charset to a Python codec, warning on unknown values."""
    if not declared:
        return "utf-8"
    key = declared.strip().lower().strip('"')
    codec = CHARSET_ALIASES.get(key)
    if codec is None:
        _add_warning(info, "unknown_charset")
        return "utf-8"
    return codec


def _decode_text(raw: bytes, charset: str, info: DecodeInfo) -> Tuple[str, bool]:
    """Decode bytes strictly; on failure replace bytes and mark ``partial``."""
    try:
        return raw.decode(charset), True
    except (UnicodeDecodeError, LookupError):
        _add_warning(info, "invalid_utf8_sequence")
        _escalate(info, "partial")
        return raw.decode("utf-8", errors="replace"), False


def _split_message(payload: bytes) -> Tuple[bytes, bytes]:
    """Split a message into its header block and body at the first blank line."""
    if b"\r\n\r\n" in payload:
        return tuple(payload.split(b"\r\n\r\n", 1))  # type: ignore[return-value]
    if b"\n\n" in payload:
        return tuple(payload.split(b"\n\n", 1))  # type: ignore[return-value]
    return payload, b""


def _parse_raw_headers(header_raw: bytes) -> Dict[str, str]:
    """Parse ``Key: value`` lines, keeping the original key case.

    The first occurrence of a duplicated header wins, matching the SMTP parser.
    """
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


class Decoder:
    """Decodes the application payload of a normalized event.

    The decoder never raises: unexpected exceptions are converted into
    ``decode_status == "error"`` with a ``decode_exception`` warning.
    """

    def __init__(self, config: DecoderConfig) -> None:
        self.config = config

    def decode(self, event: NormalizedEvent, payload: bytes) -> None:
        """Attach ``event.decode`` describing the decoded payload."""
        info = DecodeInfo()
        try:
            self._decode_safely(event, payload or b"", info)
        except Exception:
            _add_warning(info, "decode_exception")
            _escalate(info, "error")
        event.decode = info

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _decode_safely(self, event: NormalizedEvent, payload: bytes, info: DecodeInfo) -> None:
        if len(payload) > self.config.max_decode_size:
            _add_warning(info, "payload_too_large")
            _escalate(info, "skipped")
            return

        app = event.application
        protocol = app.protocol if app is not None else ""

        if protocol == "HTTP":
            self._decode_http(event, payload, info)
            self._check_payload_text(payload, info)
        elif protocol == "DNS":
            # DNS wire format is binary by design; no text decoding applies.
            return
        elif protocol == "SMTP" and app.type == "data":
            # MIME message bodies are decoded through their own charset, so the
            # raw-payload UTF-8 check would produce false "partial" verdicts.
            if self.config.decode_mime:
                self._decode_mime(payload, info)
            return
        else:
            self._check_payload_text(payload, info)

    def _check_payload_text(self, payload: bytes, info: DecodeInfo) -> None:
        """Mark ``partial`` when the payload itself is not valid UTF-8."""
        if not payload:
            return
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            _add_warning(info, "invalid_utf8_sequence")
            _escalate(info, "partial")

    def _decode_mime(self, payload: bytes, info: DecodeInfo) -> None:
        """Decode an e-mail (SMTP DATA) message: transfer encoding, charset, RFC 2047."""
        header_raw, body_raw = _split_message(payload)
        headers = _parse_raw_headers(header_raw)

        declared = _header_value(headers, "content-transfer-encoding")
        cte = (declared or "").strip().lower()
        if declared is not None:
            info.fields["content_transfer_encoding"] = cte or None

        decoded_body = body_raw
        if cte == "base64":
            compact = re.sub(rb"\s+", b"", body_raw)
            try:
                decoded_body = base64.b64decode(compact, validate=False)
                _add_decoder(info, "base64")
            except (binascii.Error, ValueError):
                _add_warning(info, "base64_decode_error")
                _escalate(info, "partial")
                decoded_body = body_raw
        elif cte == "quoted-printable":
            decoded_body = quopri.decodestring(body_raw)
            _add_decoder(info, "quoted_printable")
        # 7bit / 8bit / binary / absent / unknown: the body is used as-is.

        main, params = _parse_content_type(_header_value(headers, "content-type"))
        charset = _resolve_charset(params.get("charset"), info)
        text, _ok = _decode_text(decoded_body, charset, info)
        if self.config.decode_html_entities and main in ("text/html", "application/xhtml+xml"):
            text = html.unescape(text)
            _add_decoder(info, "html_entities")
        info.fields["mime_charset"] = charset
        info.fields["mime_body_decoded"] = text

        decoded_headers: Dict[str, str] = {}
        for key, value in headers.items():
            if "=?" not in value or "?=" not in value:
                continue
            try:
                decoded_headers[key] = str(make_header(decode_header(value)))
                _add_decoder(info, "rfc2047")
            except Exception:
                _add_warning(info, "rfc2047_decode_error")
        if decoded_headers:
            info.fields["headers_decoded"] = decoded_headers

    def _decode_http(self, event: NormalizedEvent, payload: bytes, info: DecodeInfo) -> None:
        app = event.application
        if app is None:
            return
        details = app.details if isinstance(app.details, dict) else {}

        if app.type == "request":
            uri = details.get("uri")
            if isinstance(uri, str) and uri:
                decoded, _ok = _decode_text(unquote_to_bytes(uri), "utf-8", info)
                info.fields["uri_decoded"] = decoded
                if "%" in uri:
                    _add_decoder(info, "percent_url")

        body_raw = _split_body(payload)
        if not body_raw:
            return

        main, params = _parse_content_type(_header_value(details.get("headers"), "content-type"))
        if main == "application/x-www-form-urlencoded":
            if self.config.decode_form_urlencoded:
                self._decode_form_body(body_raw, info)
            return
        self._decode_http_body(body_raw, main, params, info)

    def _decode_form_body(self, body_raw: bytes, info: DecodeInfo) -> None:
        """Split ``k=v&k2=v2`` form bodies into decoded key/value pairs."""
        form_fields: Dict[str, str] = {}
        pieces = []
        all_ok = True
        for chunk in body_raw.split(b"&"):
            if not chunk:
                continue
            key_raw, _, value_raw = chunk.partition(b"=")
            key, key_ok = _decode_text(unquote_to_bytes(key_raw.replace(b"+", b" ")), "utf-8", info)
            value, value_ok = _decode_text(
                unquote_to_bytes(value_raw.replace(b"+", b" ")), "utf-8", info
            )
            all_ok = all_ok and key_ok and value_ok
            pieces.append(f"{key}={value}")
            if key in form_fields:
                _add_warning(info, "duplicate_form_field")
            else:
                form_fields[key] = value

        info.fields["body_decoded"] = "&".join(pieces)
        info.fields["form_fields"] = form_fields
        info.fields["body_charset"] = "utf-8"
        info.fields["body_decode_status"] = "ok" if all_ok else "partial"
        _add_decoder(info, "form_urlencoded")

    def _decode_http_body(
        self, body_raw: bytes, main: str, params: Dict[str, str], info: DecodeInfo
    ) -> None:
        """Decode a non-form HTTP body according to its declared content type."""
        if not main:
            # No content type: only accept bodies that are unambiguously text.
            try:
                text = body_raw.decode("utf-8")
            except UnicodeDecodeError:
                info.fields["body_decode_status"] = "skipped"
                return
            info.fields["body_charset"] = "utf-8"
            info.fields["body_decode_status"] = "ok"
            if self.config.decode_html_entities:
                text = html.unescape(text)
                _add_decoder(info, "html_entities")
            info.fields["body_decoded"] = text
            return

        if not (main.startswith("text/") or main in TEXT_CONTENT_TYPES):
            info.fields["body_decode_status"] = "skipped"
            _add_warning(info, "binary_body_not_decoded")
            return

        charset = _resolve_charset(params.get("charset"), info)
        text, ok = _decode_text(body_raw, charset, info)
        info.fields["body_charset"] = charset
        info.fields["body_decode_status"] = "ok" if ok else "partial"
        if self.config.decode_html_entities and main in HTML_CONTENT_TYPES:
            text = html.unescape(text)
            _add_decoder(info, "html_entities")
        info.fields["body_decoded"] = text
