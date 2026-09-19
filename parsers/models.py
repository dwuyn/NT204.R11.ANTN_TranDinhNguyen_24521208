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
            "errors": list(self.errors),
        }

    def to_json(self) -> str:
        """Serialize event to a single JSON line string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)
