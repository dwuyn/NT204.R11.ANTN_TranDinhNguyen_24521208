"""Preprocessor stage: validation and normalization of normalized events.

Validation classifies every event as ``valid`` / ``partial`` / ``invalid`` with
a machine-readable ``reason`` (first matching rule wins, additional matches are
reported as warnings). Normalization canonicalizes protocol names, IP
addresses, HTTP header names, ``Host`` values, DNS domain names and HTTP URI
paths, recording every category that actually changed a value.

The preprocessor never raises: unexpected exceptions degrade the event to
``invalid`` with reason ``preprocess_exception``.
"""

import ipaddress
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from config import PreprocessorConfig
from parsers.models import NormalizedEvent, PreprocessInfo

# Protocol aliases: anything else is upper-cased; ``PROTO_<n>`` names are kept.
PROTOCOL_ALIASES = {
    "IPV6-ICMP": "ICMPV6",
    "IPV6-ICMPV6": "ICMPV6",
}

# Header names whose canonical form is not plain ``Xxx-Yyy`` capitalization.
HEADER_NAME_OVERRIDES = {
    "dnt": "DNT",
    "etag": "ETag",
    "te": "TE",
    "content-md5": "Content-MD5",
    "www-authenticate": "WWW-Authenticate",
}

HEX_ESCAPE_RE = re.compile(r"%([0-9a-fA-F]{2})")
SCHEME_AUTHORITY_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://(?P<authority>[^/?#]*)(?P<path>.*)$"
)
FUTURE_TIMESTAMP_SLACK = 86400  # seconds


def _add_warning(info: PreprocessInfo, warning: str) -> None:
    """Append ``warning`` once, preserving insertion order."""
    if warning not in info.warnings:
        info.warnings.append(warning)


def _canonical_protocol(value: Any) -> Any:
    """Upper-case a protocol name and map known aliases."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    upper = text.upper()
    return PROTOCOL_ALIASES.get(upper, upper)


def _canonical_header_name(key: str) -> str:
    """Convert a header name to ``Xxx-Yyy`` form (``content-TYPE`` -> ``Content-Type``)."""
    text = key.strip()
    lower = text.lower()
    if not lower:
        return key
    override = HEADER_NAME_OVERRIDES.get(lower)
    if override is not None:
        return override
    return "-".join(part.capitalize() for part in lower.split("-"))


def _lowercase_host(value: str) -> str:
    """Lower-case the host part of ``host:port`` / ``[ipv6]:port`` values."""
    text = value.strip()
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            return "[" + text[1:end].lower() + "]" + text[end + 1:]
        return text
    host, sep, port = text.partition(":")
    return host.lower() + sep + port


def _lowercase_authority(value: str) -> str:
    """Lower-case the host of an authority, keeping userinfo/port untouched."""
    userinfo, at, hostport = value.rpartition("@")
    if at:
        return userinfo + "@" + _lowercase_host(hostport)
    return _lowercase_host(value)


def _normalize_path(path: str) -> str:
    """Collapse ``//``, drop dot-segments and keep a meaningful trailing slash."""
    collapsed = re.sub(r"/{2,}", "/", path)
    trailing = collapsed.endswith(("/", "/.", "/.."))
    segments: List[str] = []
    for segment in collapsed.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if segments and segments[-1] not in ("", ".."):
                segments.pop()
            continue
        segments.append(segment)
    normalized = "/".join(segments)
    if trailing and normalized and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _normalize_uri_text(value: str) -> str:
    """Normalize an HTTP URI: escape case, path segments and scheme/authority."""
    path, sep, query = value.partition("?")
    path = HEX_ESCAPE_RE.sub(lambda m: "%" + m.group(1).upper(), path)
    if sep:
        query = HEX_ESCAPE_RE.sub(lambda m: "%" + m.group(1).upper(), query)

    match = SCHEME_AUTHORITY_RE.match(path)
    if match:
        scheme = match.group("scheme").lower()
        authority = _lowercase_authority(match.group("authority"))
        path = f"{scheme}://{authority}{_normalize_path(match.group('path'))}"
    else:
        path = _normalize_path(path)

    return path + sep + query


class Preprocessor:
    """Validates and normalizes a :class:`NormalizedEvent` in place."""

    def __init__(self, config: PreprocessorConfig) -> None:
        self.config = config

    def process(self, event: NormalizedEvent) -> PreprocessInfo:
        """Attach ``event.preprocess`` describing validation and normalization."""
        info = PreprocessInfo()
        try:
            primary, extra = self._validate(event)
            for reason in extra:
                _add_warning(info, reason)
            if primary is None:
                info.preprocess_status = "valid"
                info.reason = None
            else:
                status, reason = primary
                info.preprocess_status = status
                info.reason = reason
            info.normalizations = self._normalize(event, info)
        except Exception:
            info.preprocess_status = "invalid"
            info.reason = "preprocess_exception"
            _add_warning(info, "preprocess_exception")

        if info.preprocess_status == "invalid" and self.config.drop_invalid:
            info.processing_action = "dropped"
        else:
            info.processing_action = "forward"

        event.preprocess = info
        return info

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, event: NormalizedEvent) -> Tuple[Optional[Tuple[str, str]], List[str]]:
        """Return (primary problem, extra reasons) in rule-priority order."""
        checks: List[Tuple[str, str]] = []
        checks.extend(self._check_timestamp(event))
        checks.extend(self._check_network(event))
        checks.extend(self._check_transport(event))
        checks.extend(self._check_application(event))
        checks.extend(self._check_future_timestamp(event))

        if not checks:
            return None, []
        primary, *extra = checks
        return primary, [reason for _status, reason in extra]

    def _check_timestamp(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        timestamp = event.timestamp
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or timestamp <= 0:
            return [("invalid", "invalid_timestamp")]
        return []

    def _check_network(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        network = event.network
        if network is None:
            return [("invalid", "missing_network_layer")]
        for value in (network.src_ip, network.dst_ip):
            if not isinstance(value, str) or not value.strip():
                return [("invalid", "invalid_ip_address")]
            try:
                ipaddress.ip_address(value.strip())
            except ValueError:
                return [("invalid", "invalid_ip_address")]
        return []

    def _check_transport(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        transport = event.transport
        if transport is None:
            return [("partial", "missing_transport_layer")]
        reasons: List[Tuple[str, str]] = []
        for port in (transport.src_port, transport.dst_port):
            if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
                reasons.append(("invalid", "invalid_port"))
                break
        if str(transport.layer).strip().upper() not in ("TCP", "UDP"):
            reasons.append(("partial", "unsupported_transport_protocol"))
        return reasons

    def _check_application(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        application = event.application
        if application is None:
            return [("partial", "no_application_layer")]
        if str(application.protocol).strip().upper() == "UNKNOWN":
            return [("partial", "unsupported_protocol")]
        return []

    def _check_future_timestamp(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        timestamp = event.timestamp
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            return []
        try:
            if timestamp > time.time() + FUTURE_TIMESTAMP_SLACK:
                return [("partial", "timestamp_in_future")]
        except (OverflowError, OSError, ValueError):
            return []
        return []

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def _normalize(self, event: NormalizedEvent, info: PreprocessInfo) -> List[str]:
        """Normalize the event in place, returning the categories that changed."""
        normalizations: List[str] = []
        if self._normalize_protocol_names(event):
            normalizations.append("protocol_name")
        if self._normalize_ip_addresses(event):
            normalizations.append("ip_address")
        if self.config.normalize_headers and self._normalize_http_headers(event, info):
            normalizations.append("http_header_names")
        if self.config.normalize_domains and self._normalize_domains(event):
            normalizations.append("domain_lowercase")
        if self._normalize_host_header(event):
            normalizations.append("host_header")
        if self.config.normalize_uri and self._normalize_uri(event):
            normalizations.append("uri_path")
        return normalizations

    @staticmethod
    def _http_details(event: NormalizedEvent) -> Optional[Dict[str, Any]]:
        """Return HTTP application details, or None when not an HTTP event."""
        application = event.application
        if application is None or str(application.protocol).strip().upper() != "HTTP":
            return None
        details = application.details
        return details if isinstance(details, dict) else None

    def _normalize_protocol_names(self, event: NormalizedEvent) -> bool:
        changed = False
        if event.network is not None:
            canonical = _canonical_protocol(event.network.proto)
            if canonical != event.network.proto:
                event.network.proto = canonical
                changed = True
        if event.transport is not None:
            canonical = _canonical_protocol(event.transport.layer)
            if canonical != event.transport.layer:
                event.transport.layer = canonical
                changed = True
        if event.application is not None:
            canonical = str(event.application.protocol).strip().upper()
            if canonical != event.application.protocol:
                event.application.protocol = canonical
                changed = True
        return changed

    def _normalize_ip_addresses(self, event: NormalizedEvent) -> bool:
        network = event.network
        if network is None:
            return False
        changed = False
        for attribute in ("src_ip", "dst_ip"):
            value = getattr(network, attribute, None)
            if not isinstance(value, str):
                continue
            try:
                canonical = str(ipaddress.ip_address(value.strip()))
            except ValueError:
                continue
            if canonical != value:
                setattr(network, attribute, canonical)
                changed = True
        return changed

    def _normalize_http_headers(self, event: NormalizedEvent, info: PreprocessInfo) -> bool:
        details = self._http_details(event)
        if details is None:
            return False
        headers = details.get("headers")
        if not isinstance(headers, dict) or not headers:
            return False

        canonical_headers: Dict[Any, Any] = {}
        changed = False
        for key, value in headers.items():
            if not isinstance(key, str):
                canonical_headers[key] = value
                continue
            canonical = _canonical_header_name(key)
            if canonical != key:
                changed = True
            if canonical in canonical_headers:
                _add_warning(info, "duplicate_header_name")
                continue
            canonical_headers[canonical] = value
        details["headers"] = canonical_headers
        return changed

    def _normalize_domains(self, event: NormalizedEvent) -> bool:
        application = event.application
        if application is None or str(application.protocol).strip().upper() != "DNS":
            return False
        details = application.details
        if not isinstance(details, dict):
            return False

        changed = False
        for list_key in ("queries", "answers"):
            entries = details.get(list_key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                if isinstance(name, str) and name != name.lower():
                    entry["name"] = name.lower()
                    changed = True
        return changed

    def _normalize_host_header(self, event: NormalizedEvent) -> bool:
        details = self._http_details(event)
        if details is None:
            return False
        headers = details.get("headers")
        if not isinstance(headers, dict):
            return False

        for key, value in headers.items():
            if not isinstance(key, str) or key.lower() != "host":
                continue
            if not isinstance(value, str) or not value:
                return False
            normalized = _lowercase_host(value)
            if normalized == value:
                return False
            headers[key] = normalized
            return True
        return False

    def _normalize_uri(self, event: NormalizedEvent) -> bool:
        details = self._http_details(event)
        if details is None or event.application.type != "request":
            return False
        uri = details.get("uri")
        if not isinstance(uri, str) or not uri:
            return False

        source = uri
        if event.decode is not None and isinstance(event.decode.fields, dict):
            decoded = event.decode.fields.get("uri_decoded")
            if isinstance(decoded, str) and decoded:
                source = decoded

        normalized = _normalize_uri_text(source)
        details["uri_normalized"] = normalized
        return normalized != source
