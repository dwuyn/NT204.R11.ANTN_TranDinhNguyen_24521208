"""Rule Parser & Validator (module 4.2 của đề bài).

Biến một dòng rule Snort (đã qua Rule Loader) thành Internal Rule Object:
tách Rule Header và Rule Options, kiểm tra cú pháp, protocol/keyword được hỗ
trợ, kiểu dữ liệu và các trường bắt buộc; phân loại kết quả thành
``valid`` / ``invalid`` / ``unsupported`` kèm lý do.

Chỉ các keyword trong phạm vi bài tập được chấp nhận; keyword ngoài phạm vi
bị đánh ``unsupported`` (không làm chương trình dừng).
"""

import ipaddress
import re
from typing import List, Optional, Tuple

from core.models import (
    STATUS_INVALID,
    STATUS_UNSUPPORTED,
    STATUS_VALID,
    SUPPORTED_ACTIONS,
    SUPPORTED_FLOW_KEYWORDS,
    SUPPORTED_PROTOCOLS,
    ContentOption,
    FlagSpec,
    IPSpec,
    ParseOutcome,
    PortSpec,
    Rule,
    RuleHeader,
    SizeSpec,
)

# Header:  action proto src_ip src_port (->|<>) dst_ip dst_port (options)
_HEADER_RE = re.compile(
    r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s+"
    r"(?P<direction>->|<>)\s+(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s*"
    r"\((?P<options>.*)\)\s*$"
)
_PORT_RANGE_RE = re.compile(r"^(\d*):(\d*)$")
_FLAGS_RE = re.compile(r"^[FSRPAU012]+$")
_DSIZE_RE = re.compile(r"^([<>])?(\d+)$")
_CLASSTYPE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

# Option chỉ xuất hiện một lần trong một rule.
_SINGLE_OPTIONS = (
    "msg",
    "sid",
    "rev",
    "classtype",
    "priority",
    "flags",
    "dsize",
    "flow",
)
# Modifier áp cho option content đứng ngay trước nó (đúng ngữ nghĩa Snort).
_CONTENT_MODIFIERS = ("nocase", "offset", "depth", "distance", "within")

_ESCAPES = {
    '"': '"',
    "\\": "\\",
    ";": ";",
    ":": ":",
    "n": "\n",
    "t": "\t",
    "r": "\r",
}


class _RuleError(Exception):
    """Lỗi nội bộ khiến rule bị đánh invalid hoặc unsupported kèm lý do."""

    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _invalid(reason: str) -> "_RuleError":
    return _RuleError(STATUS_INVALID, reason)


def _unsupported(reason: str) -> "_RuleError":
    return _RuleError(STATUS_UNSUPPORTED, reason)


class RuleParser:
    """Parser/validator cho một dòng rule Snort trong phạm vi bài tập."""

    @classmethod
    def parse(cls, text: str, rule_file: str = "", line_no: int = 0) -> ParseOutcome:
        """Parse một dòng rule; trả về ParseOutcome (không bao giờ raise)."""
        raw = text or ""
        cleaned = raw.strip()

        def outcome(status: str, reason: Optional[str]) -> ParseOutcome:
            return ParseOutcome(
                status=status,
                reason=reason,
                raw=raw,
                rule_file=rule_file,
                line_no=line_no,
            )

        if not cleaned or cleaned.startswith("#"):
            return outcome(STATUS_INVALID, "empty rule")

        match = _HEADER_RE.match(cleaned)
        if match is None:
            return outcome(STATUS_INVALID, "invalid rule syntax")

        try:
            header = cls._parse_header(match)
            rule = Rule(header=header, rule_file=rule_file, line_no=line_no, raw=cleaned)
            cls._parse_options(match.group("options"), rule)
        except _RuleError as exc:
            return outcome(exc.status, exc.reason)

        return ParseOutcome(
            status=STATUS_VALID,
            rule=rule,
            raw=raw,
            rule_file=rule_file,
            line_no=line_no,
        )

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    @classmethod
    def _parse_header(cls, match: "re.Match[str]") -> RuleHeader:
        action = match.group("action").lower()
        if action not in SUPPORTED_ACTIONS:
            raise _unsupported(f"unsupported action: {match.group('action')}")

        protocol = match.group("proto").lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise _unsupported(f"unsupported protocol: {match.group('proto')}")

        return RuleHeader(
            action=action,
            protocol=protocol,
            src_ip=_parse_ip_spec(match.group("src_ip")),
            src_port=_parse_port_spec(match.group("src_port")),
            direction=match.group("direction"),
            dst_ip=_parse_ip_spec(match.group("dst_ip")),
            dst_port=_parse_port_spec(match.group("dst_port")),
        )

    # ------------------------------------------------------------------
    # Options
    # ------------------------------------------------------------------

    @classmethod
    def _parse_options(cls, options_text: str, rule: Rule) -> None:
        seen_single = set()
        current_content: Optional[ContentOption] = None
        sid_seen = False
        msg_seen = False

        for part in _split_options(options_text):
            if ":" in part:
                key, value = part.split(":", 1)
                value = value.strip()
            else:
                key, value = part, None
            key = key.strip().lower()

            # Modifier của content: áp cho option content đứng ngay trước.
            if key in _CONTENT_MODIFIERS:
                if current_content is None:
                    raise _invalid(f"content modifier without preceding content: {key}")
                if key == "nocase":
                    if value not in (None, ""):
                        raise _invalid("invalid nocase: value not allowed")
                    current_content.nocase = True
                else:
                    setattr(current_content, key, _parse_count(key, value))
                continue

            if key == "content":
                if value is None:
                    raise _invalid("missing value for option: content")
                decoded, error = _decode_content(value)
                if error is not None:
                    raise _invalid(f"invalid content: {error}")
                current_content = ContentOption(content=decoded, text=part)
                rule.contents.append(current_content)
                continue

            if key not in _SINGLE_OPTIONS:
                raise _unsupported(f"unsupported keyword: {key}")

            if key in seen_single:
                raise _invalid(f"duplicate option: {key}")
            seen_single.add(key)

            if key == "msg":
                decoded, error = _decode_text(value)
                if error is not None:
                    raise _invalid(f"invalid msg: {error}")
                rule.msg = decoded
                msg_seen = True
            elif key == "sid":
                rule.sid = _parse_sid(value)
                sid_seen = True
            elif key == "rev":
                rule.rev = _parse_count("rev", value)
            elif key == "classtype":
                rule.classtype = _parse_classtype(value)
            elif key == "priority":
                rule.priority = _parse_priority(value)
            elif key == "flags":
                rule.flags = _parse_flags(value)
            elif key == "dsize":
                rule.dsize = _parse_dsize(value)
            elif key == "flow":
                rule.flow = _parse_flow(value)

        # Các trường bắt buộc: sid và msg (msg dùng cho Detection Event).
        if not sid_seen:
            raise _invalid("missing required option: sid")
        if not msg_seen:
            raise _invalid("missing required option: msg")


# ----------------------------------------------------------------------
# Helpers parse từng thành phần
# ----------------------------------------------------------------------


def _parse_ip_spec(text: str) -> IPSpec:
    if text.lower() == "any":
        return IPSpec(any=True, text=text)
    if text.startswith("!"):
        raise _unsupported(f"unsupported negated address: {text}")
    if text.startswith("["):
        raise _unsupported(f"unsupported address list: {text}")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise _invalid(f"invalid IP address: {text}") from None
    if network.version != 4:
        raise _unsupported(f"unsupported IPv6 address: {text}")
    return IPSpec(any=False, network=network, text=text)


def _parse_port_spec(text: str) -> PortSpec:
    if text.lower() == "any":
        return PortSpec(text=text)
    if text.startswith("!"):
        raise _unsupported(f"unsupported negated port: {text}")
    if text.startswith("[") or "," in text:
        raise _unsupported(f"unsupported port list: {text}")

    range_match = _PORT_RANGE_RE.match(text)
    if range_match is not None:
        lower_text, upper_text = range_match.group(1), range_match.group(2)
        if not lower_text and not upper_text:
            raise _invalid(f"invalid port: {text}")
        lower = _port_value(lower_text) if lower_text else None
        upper = _port_value(upper_text) if upper_text else None
        if lower is not None and upper is not None and lower > upper:
            raise _invalid(f"invalid port range: {text}")
        return PortSpec(lo=lower, hi=upper, text=text)

    if text.isdigit():
        port = _port_value(text)
        return PortSpec(lo=port, hi=port, text=text)

    raise _invalid(f"invalid port: {text}")


def _port_value(text: str) -> int:
    value = int(text)
    if value < 0 or value > 65535:
        raise _invalid(f"invalid port: {text}")
    return value


def _parse_sid(value: Optional[str]) -> int:
    if value is None:
        raise _invalid("missing value for option: sid")
    if not value.isdigit():
        raise _invalid(f"invalid sid: {value}")
    sid = int(value)
    if sid <= 0:
        raise _invalid(f"invalid sid: {value}")
    return sid


def _parse_count(key: str, value: Optional[str]) -> int:
    if value is None:
        raise _invalid(f"missing value for option: {key}")
    if not value.isdigit():
        raise _invalid(f"invalid {key}: {value}")
    return int(value)


def _parse_classtype(value: Optional[str]) -> str:
    if value is None:
        raise _invalid("missing value for option: classtype")
    cleaned = value.strip('"')
    if not _CLASSTYPE_RE.match(cleaned):
        raise _invalid(f"invalid classtype: {value}")
    return cleaned


def _parse_priority(value: Optional[str]) -> int:
    if value is None:
        raise _invalid("missing value for option: priority")
    if not value.isdigit():
        raise _invalid(f"invalid priority: {value}")
    return int(value)


def _parse_flags(value: Optional[str]) -> FlagSpec:
    if value is None:
        raise _invalid("missing value for option: flags")
    for modifier in ("!", "*", "+"):
        if modifier in value:
            raise _unsupported(f"unsupported flags modifier in: {value}")
    upper = value.upper().strip('"')
    if not _FLAGS_RE.match(upper):
        raise _invalid(f"invalid flags: {value}")
    return FlagSpec(flags=upper, text=value)


def _parse_dsize(value: Optional[str]) -> SizeSpec:
    if value is None:
        raise _invalid("missing value for option: dsize")
    if "<>" in value:
        raise _unsupported(f"unsupported dsize range: {value}")
    match = _DSIZE_RE.match(value)
    if match is None:
        raise _invalid(f"invalid dsize: {value}")
    op = {"": "eq", ">": "gt", "<": "lt"}[match.group(1) or ""]
    return SizeSpec(op=op, value=int(match.group(2)), text=value)


def _parse_flow(value: Optional[str]) -> List[str]:
    if value is None:
        raise _invalid("missing value for option: flow")
    tokens = [token.strip().lower() for token in value.strip('"').split(",") if token.strip()]
    if not tokens:
        raise _invalid("invalid flow: empty value")
    for token in tokens:
        if token not in SUPPORTED_FLOW_KEYWORDS:
            raise _unsupported(f"unsupported flow keyword: {token}")
    return tokens


# ----------------------------------------------------------------------
# Tách options và giải mã chuỗi có quote
# ----------------------------------------------------------------------


def _split_options(options_text: str) -> List[str]:
    """Tách chuỗi options theo ``;`` nhưng bỏ qua dấu ``;`` nằm trong quote."""
    parts: List[str] = []
    buffer: List[str] = []
    in_quote = False
    escaped = False
    for char in options_text:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
        if char == ";" and not in_quote:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    parts.append("".join(buffer))
    return [part.strip() for part in parts if part.strip()]


def _decode_content(value: str) -> Tuple[Optional[str], Optional[str]]:
    """Giải mã giá trị content: bỏ quote, xử lý escape và khối hex ``|..|``.

    Trả về (chuỗi latin-1, None) hoặc (None, lý do lỗi). Chuỗi latin-1 giữ
    quan hệ 1-1 giữa ký tự và byte để matching byte-exact như Snort.
    """
    stripped = value.strip()
    if not stripped.startswith('"'):
        return None, "value must be a quoted string"

    buffer = bytearray()
    index = 1
    length = len(stripped)
    while index < length:
        char = stripped[index]
        if char == '"':
            if stripped[index + 1 :].strip():
                return None, "trailing characters after quoted string"
            return buffer.decode("latin-1"), None
        if char == "\\":
            if index + 1 >= length:
                return None, "dangling escape character"
            nxt = stripped[index + 1]
            if nxt not in _ESCAPES:
                return None, f"unsupported escape \\{nxt}"
            buffer.extend(_ESCAPES[nxt].encode("latin-1"))
            index += 2
            continue
        if char == "|":
            end = stripped.find("|", index + 1)
            if end == -1:
                return None, "unterminated hex block"
            hex_text = stripped[index + 1 : end].replace(" ", "")
            if len(hex_text) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", hex_text):
                return None, "invalid hex block"
            buffer.extend(bytes.fromhex(hex_text))
            index = end + 1
            continue
        try:
            buffer.extend(char.encode("latin-1"))
        except UnicodeEncodeError:
            buffer.extend(char.encode("utf-8"))
        index += 1
    return None, "unterminated quoted string"


def _decode_text(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Giải mã chuỗi text (msg): bỏ quote và xử lý escape cơ bản."""
    if value is None:
        return None, "missing quoted string"
    stripped = value.strip()
    if not stripped.startswith('"'):
        return None, "value must be a quoted string"

    out: List[str] = []
    index = 1
    length = len(stripped)
    while index < length:
        char = stripped[index]
        if char == '"':
            if stripped[index + 1 :].strip():
                return None, "trailing characters after quoted string"
            return "".join(out), None
        if char == "\\":
            if index + 1 >= length:
                return None, "dangling escape character"
            nxt = stripped[index + 1]
            if nxt not in _ESCAPES:
                return None, f"unsupported escape \\{nxt}"
            out.append(_ESCAPES[nxt])
            index += 2
            continue
        out.append(char)
        index += 1
    return None, "unterminated quoted string"
