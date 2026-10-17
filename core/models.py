"""Data model của Core Engine.

Biểu diễn cấu trúc của một Snort rule trong phạm vi được hỗ trợ (header, các
option content/flow/flags/dsize/classtype/priority) cùng kết quả match trung
gian. Việc biến *văn bản* rule thành các object này thuộc ``core.parser``;
việc so khớp chúng với event thuộc ``core.matcher``.

Tất cả rule đều là dữ liệu nạp từ file ``.rules``; engine không hard-code
signature nào trong source code.
"""

from dataclasses import dataclass, field
import ipaddress
from typing import Any, Dict, List, Optional

# --- Literal trạng thái kết quả parse ----------------------------------------
STATUS_VALID = "valid"
STATUS_INVALID = "invalid"
STATUS_UNSUPPORTED = "unsupported"

# --- Literal của rule header --------------------------------------------------
SUPPORTED_ACTIONS = ("alert",)
SUPPORTED_PROTOCOLS = ("tcp", "udp")

DIRECTION_UNI = "->"
DIRECTION_BIDI = "<>"

# --- Literal của option flow --------------------------------------------------
FLOW_TO_SERVER = "to_server"
FLOW_TO_CLIENT = "to_client"
FLOW_ESTABLISHED = "established"
FLOW_NOT_ESTABLISHED = "not_established"
SUPPORTED_FLOW_KEYWORDS = (
    FLOW_TO_SERVER,
    FLOW_TO_CLIENT,
    FLOW_ESTABLISHED,
    FLOW_NOT_ESTABLISHED,
)

# Chữ cái cờ TCP (Snort) -> tên cờ đã chuẩn hóa của transport parser.
FLAG_LETTERS: Dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "2": "ECE",
    "1": "CWR",
    "0": "NS",
}


@dataclass
class IPSpec:
    """Vế địa chỉ của rule header: ``any``, IPv4 đơn hoặc một khối CIDR."""
    any: bool = True
    network: Optional[ipaddress.IPv4Network] = None
    text: str = "any"

    def contains(self, ip: str) -> bool:
        """True nếu ``ip`` nằm trong spec này (spec ``any`` khớp mọi địa chỉ)."""
        if self.any:
            return True
        if self.network is None:
            return False
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "any": self.any,
            "network": str(self.network) if self.network is not None else None,
            "text": self.text,
        }


@dataclass
class PortSpec:
    """Vế cổng của rule header: ``any``, cổng đơn hoặc dải cổng.

    ``lo``/``hi`` bao gồm hai đầu; ``None`` nghĩa là để mở (``1024:`` không có
    cận trên, ``:1024`` không có cận dưới).
    """
    lo: Optional[int] = None
    hi: Optional[int] = None
    text: str = "any"

    @property
    def any(self) -> bool:
        return self.lo is None and self.hi is None

    def contains(self, port: int) -> bool:
        if self.any:
            return True
        if self.lo is not None and port < self.lo:
            return False
        if self.hi is not None and port > self.hi:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {"lo": self.lo, "hi": self.hi, "text": self.text}


@dataclass
class FlagSpec:
    """Tập cờ TCP của option ``flags:`` (chữ cái như ``S``, ``PA``)."""
    flags: str = ""
    text: str = ""

    def matches(self, packet_flags: List[str]) -> bool:
        """True nếu mọi chữ cái trong rule đều có mặt trong cờ của packet."""
        present = {str(flag).upper() for flag in packet_flags}
        return all(FLAG_LETTERS.get(ch, ch) in present for ch in self.flags.upper())

    def to_dict(self) -> Dict[str, Any]:
        return {"flags": self.flags, "text": self.text}


@dataclass
class SizeSpec:
    """So sánh của option ``dsize:`` (chỉ ``N``, ``>N``, ``<N`` trong phạm vi)."""
    op: str = "eq"  # eq | gt | lt
    value: int = 0
    text: str = ""

    def matches(self, size: int) -> bool:
        if self.op == "gt":
            return size > self.value
        if self.op == "lt":
            return size < self.value
        return size == self.value

    def to_dict(self) -> Dict[str, Any]:
        return {"op": self.op, "value": self.value, "text": self.text}


@dataclass
class ContentOption:
    """Một option ``content:`` cùng các modifier áp cho chính nó.

    ``content`` được lưu dưới dạng chuỗi latin-1 (1 byte = 1 ký tự) để việc
    tìm kiếm con byte-exact; ``nocase`` chỉ không phân biệt hoa thường ASCII
    giống Snort.
    """
    content: str
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None
    text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "nocase": self.nocase,
            "offset": self.offset,
            "depth": self.depth,
            "distance": self.distance,
            "within": self.within,
            "text": self.text,
        }


@dataclass
class RuleHeader:
    """Phần header của rule: action, protocol, hai vế địa chỉ/cổng và chiều."""
    action: str = "alert"
    protocol: str = "tcp"
    src_ip: IPSpec = field(default_factory=IPSpec)
    src_port: PortSpec = field(default_factory=PortSpec)
    direction: str = DIRECTION_UNI
    dst_ip: IPSpec = field(default_factory=IPSpec)
    dst_port: PortSpec = field(default_factory=PortSpec)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "protocol": self.protocol,
            "src_ip": self.src_ip.to_dict(),
            "src_port": self.src_port.to_dict(),
            "direction": self.direction,
            "dst_ip": self.dst_ip.to_dict(),
            "dst_port": self.dst_port.to_dict(),
        }


@dataclass
class Rule:
    """Internal Rule Object: một rule Snort đã được validate."""
    header: RuleHeader = field(default_factory=RuleHeader)
    msg: str = ""
    sid: int = 0
    rev: int = 0
    classtype: Optional[str] = None
    priority: Optional[int] = None
    contents: List[ContentOption] = field(default_factory=list)
    flow: List[str] = field(default_factory=list)
    flags: Optional[FlagSpec] = None
    dsize: Optional[SizeSpec] = None
    rule_file: str = ""
    line_no: int = 0
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "msg": self.msg,
            "sid": self.sid,
            "rev": self.rev,
            "classtype": self.classtype,
            "priority": self.priority,
            "contents": [content.to_dict() for content in self.contents],
            "flow": list(self.flow),
            "flags": self.flags.to_dict() if self.flags is not None else None,
            "dsize": self.dsize.to_dict() if self.dsize is not None else None,
            "rule_file": self.rule_file,
            "line_no": self.line_no,
        }


@dataclass
class ParseOutcome:
    """Kết quả parse một dòng rule: valid / invalid / unsupported + lý do."""
    status: str
    rule: Optional[Rule] = None
    reason: Optional[str] = None
    raw: str = ""
    rule_file: str = ""
    line_no: int = 0

    @property
    def ok(self) -> bool:
        return self.status == STATUS_VALID

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "rule_file": self.rule_file,
            "line_no": self.line_no,
            "raw": self.raw,
            "sid": self.rule.sid if self.rule is not None else None,
        }


@dataclass
class ContentMatch:
    """Vị trí khớp của một option content trong payload."""
    content: str
    offset: int
    length: int
    nocase: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "offset": self.offset,
            "length": self.length,
            "nocase": self.nocase,
        }


@dataclass
class MatchResult:
    """Kết quả khi một rule thỏa mãn event: thông tin match để sinh Detection Event."""
    rule: Rule
    contents: List[ContentMatch] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)

    @property
    def sid(self) -> int:
        return self.rule.sid

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sid": self.rule.sid,
            "contents": [content.to_dict() for content in self.contents],
            "fields": list(self.fields),
        }
