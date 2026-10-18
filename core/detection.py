"""Detection Event Generator (module 4.6 của đề bài).

Sinh Detection Event thống nhất khi một rule match, để Alert/Logging/Response
(bài tập tiếp theo) sử dụng. Matching Engine **không** in cảnh báo trực tiếp;
mọi thông tin cần thiết được đóng gói tại đây.

Event tối thiểu gồm: timestamp, sid, rev, msg, priority/classtype (nếu có),
5-tuple + protocol, application_protocol, flow_id và thông tin match.
"""

from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional

from core.models import MatchResult, Rule
from parsers.models import NormalizedEvent


@dataclass
class DetectionEvent:
    """Một kết quả phát hiện (một rule match một event)."""
    packet_id: int
    timestamp: float
    timestamp_iso: str
    action: str
    sid: int
    rev: int
    msg: str
    protocol: str
    application_protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    direction: str = ""
    flow_id: str = ""
    flow_state: str = ""
    classtype: Optional[str] = None
    priority: Optional[int] = None
    matched: Dict[str, Any] = field(default_factory=dict)
    rule_file: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "action": self.action,
            "sid": self.sid,
            "rev": self.rev,
            "msg": self.msg,
            "classtype": self.classtype,
            "priority": self.priority,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "direction": self.direction,
            "flow_id": self.flow_id,
            "flow_state": self.flow_state,
            "matched": self.matched,
            "rule_file": self.rule_file,
        }

    def to_json(self) -> str:
        """Serialize detection event to a single JSON line string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def format_summary(self) -> str:
        """Dòng cảnh báo ngắn gọn cho console."""
        return (
            f"[ALERT] sid={self.sid} rev={self.rev} \"{self.msg}\" "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"({self.protocol}/{self.application_protocol or 'UNKNOWN'}) "
            f"flow={self.flow_id or 'n/a'}"
        )


class DetectionEventGenerator:
    """Tạo DetectionEvent từ (rule, match result, event)."""

    @staticmethod
    def generate(rule: Rule, match: MatchResult, event: NormalizedEvent) -> DetectionEvent:
        network = event.network
        transport = event.transport
        flow = event.flow

        application_protocol = ""
        if event.application is not None and event.application.protocol:
            application_protocol = event.application.protocol

        protocol = rule.header.protocol.upper()
        if transport is not None and transport.layer:
            protocol = str(transport.layer).strip().upper()

        return DetectionEvent(
            packet_id=event.packet_id,
            timestamp=round(event.timestamp, 6),
            timestamp_iso=event.timestamp_iso,
            action=rule.header.action,
            sid=rule.sid,
            rev=rule.rev,
            msg=rule.msg,
            classtype=rule.classtype,
            priority=rule.priority,
            protocol=protocol,
            application_protocol=application_protocol,
            src_ip=network.src_ip if network is not None else "",
            src_port=transport.src_port if transport is not None else 0,
            dst_ip=network.dst_ip if network is not None else "",
            dst_port=transport.dst_port if transport is not None else 0,
            direction=flow.direction if flow is not None else "",
            flow_id=flow.flow_id if flow is not None else "",
            flow_state=flow.state if flow is not None else "",
            matched={
                "contents": [content.to_dict() for content in match.contents],
                "fields": list(match.fields),
            },
            rule_file=rule.rule_file,
        )
