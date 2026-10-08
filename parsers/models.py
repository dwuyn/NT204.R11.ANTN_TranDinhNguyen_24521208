"""Normalized event data models for IDS packet inspection."""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional


@dataclass
class NetworkLayer:
    """Represents normalized Layer 3 (Network) metadata."""
    layer: str = "IPv4"
    src_ip: str = ""
    dst_ip: str = ""
    proto: str = ""
    ttl: int = 0
    id: int = 0
    ihl: int = 5
    tos: int = 0
    total_len: int = 0
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "proto": self.proto,
            "ttl": self.ttl,
            "id": self.id,
            "ihl": self.ihl,
            "tos": self.tos,
            "total_len": self.total_len,
            "flags": list(self.flags),
        }


@dataclass
class TransportLayer:
    """Represents normalized Layer 4 (Transport) metadata."""
    layer: str = ""  # TCP or UDP
    src_port: int = 0
    dst_port: int = 0
    seq: Optional[int] = None
    ack: Optional[int] = None
    flags: List[str] = field(default_factory=list)
    handshake: Optional[str] = None  # SYN, SYN-ACK, ACK
    window: Optional[int] = None
    data_offset: Optional[int] = None
    checksum: Optional[int] = None
    payload_len: int = 0

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "layer": self.layer,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "payload_len": self.payload_len,
        }
        if self.seq is not None:
            data["seq"] = self.seq
        if self.ack is not None:
            data["ack"] = self.ack
        if self.flags:
            data["flags"] = list(self.flags)
        if self.handshake is not None:
            data["handshake"] = self.handshake
        if self.window is not None:
            data["window"] = self.window
        if self.data_offset is not None:
            data["data_offset"] = self.data_offset
        if self.checksum is not None:
            data["checksum"] = self.checksum
        return data


@dataclass
class ApplicationLayer:
    """Represents normalized Layer 7 (Application) metadata."""
    protocol: str = "UNKNOWN"  # HTTP, DNS, SMTP, UNKNOWN
    type: str = ""  # request, response, query, command, etc.
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "type": self.type,
            "details": self.details,
        }


@dataclass
class DecodeInfo:
    """Decoded representation of an event's application payload."""
    decode_status: str = "unchanged"  # error, partial, decoded, skipped, unchanged
    decoders: List[str] = field(default_factory=list)
    fields: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decode_status": self.decode_status,
            "decoders": list(self.decoders),
            "fields": dict(self.fields),
            "warnings": list(self.warnings),
        }


@dataclass
class PreprocessInfo:
    """Validation/normalization outcome produced by the preprocessor."""
    preprocess_status: str = ""  # valid, partial, invalid
    processing_action: str = ""  # forward, dropped
    reason: Optional[str] = None
    normalizations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "preprocess_status": self.preprocess_status,
            "processing_action": self.processing_action,
            "reason": self.reason,
            "normalizations": list(self.normalizations),
            "warnings": list(self.warnings),
        }


@dataclass
class FlowRef:
    """Reference to the flow an event was attributed to."""
    flow_id: str = ""
    direction: str = ""  # forward, backward
    state: str = ""
    is_new_flow: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "direction": self.direction,
            "state": self.state,
            "is_new_flow": self.is_new_flow,
        }


@dataclass
class NormalizedEvent:
    """Standardized event structure representing a parsed packet for IDS analysis."""
    packet_id: int
    timestamp: float
    raw_len: int
    timestamp_iso: str = ""
    network: Optional[NetworkLayer] = None
    transport: Optional[TransportLayer] = None
    application: Optional[ApplicationLayer] = None
    errors: List[str] = field(default_factory=list)
    decode: Optional[DecodeInfo] = None
    preprocess: Optional[PreprocessInfo] = None
    flow: Optional[FlowRef] = None

    def __post_init__(self) -> None:
        if not self.timestamp_iso and self.timestamp:
            try:
                dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
                self.timestamp_iso = dt.isoformat()
            except Exception:
                self.timestamp_iso = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert the normalized event into a JSON-compatible dictionary."""
        return {
            "packet_id": self.packet_id,
            "timestamp": round(self.timestamp, 6),
            "timestamp_iso": self.timestamp_iso,
            "raw_len": self.raw_len,
            "network": self.network.to_dict() if self.network else None,
            "transport": self.transport.to_dict() if self.transport else None,
            "application": self.application.to_dict() if self.application else None,
            "decode": self.decode.to_dict() if self.decode else None,
            "preprocess": self.preprocess.to_dict() if self.preprocess else None,
            "flow": self.flow.to_dict() if self.flow else None,
            "errors": list(self.errors),
        }

    def to_json(self) -> str:
        """Serialize event to a single JSON line string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)
