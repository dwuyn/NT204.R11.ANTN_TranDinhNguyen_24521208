"""Per-flow data model for the flow/connection tracker.

A flow is identified by its 5-tuple (protocol + both endpoints). The endpoint
of the first observed packet becomes endpoint A ("initiator"); packets flowing
A -> B are ``forward``, packets flowing B -> A are ``backward``.
"""

from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional, Set

# TCP connection states (UDP flows are always ESTABLISHED).
STATE_NEW = "NEW"
STATE_HANDSHAKE = "HANDSHAKE"
STATE_ESTABLISHED = "ESTABLISHED"
STATE_CLOSING = "CLOSING"
STATE_CLOSED = "CLOSED"
STATE_RESET = "RESET"

TCP_STATES = (
    STATE_NEW,
    STATE_HANDSHAKE,
    STATE_ESTABLISHED,
    STATE_CLOSING,
    STATE_CLOSED,
    STATE_RESET,
)

# Why a flow record was emitted.
CLOSE_FIN = "fin"
CLOSE_RST = "rst"
CLOSE_TIMEOUT = "timeout"
CLOSE_OVERFLOW = "overflow"
CLOSE_END_OF_CAPTURE = "end_of_capture"

CLOSE_REASONS = (CLOSE_FIN, CLOSE_RST, CLOSE_TIMEOUT, CLOSE_OVERFLOW, CLOSE_END_OF_CAPTURE)

DIRECTION_FORWARD = "forward"
DIRECTION_BACKWARD = "backward"

# Timestamps are rounded to microseconds in the JSON output so that replayed
# captures produce byte-identical records.
TIME_PRECISION = 6


@dataclass
class FlowCounters:
    """Per-direction packet and byte counters."""
    packet_count: int = 0
    byte_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }


@dataclass
class Flow:
    """State and statistics of one bidirectional flow."""
    flow_id: str
    flow_seq: int
    protocol: str
    endpoint_a: Dict[str, Any]
    endpoint_b: Dict[str, Any]
    start_time: float
    last_seen: float
    state: str = STATE_NEW
    application_protocol: Optional[str] = None
    forward: FlowCounters = field(default_factory=FlowCounters)
    backward: FlowCounters = field(default_factory=FlowCounters)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    closed: bool = False
    close_reason: Optional[str] = None
    # Directions that already contributed a FIN, used to detect a full close.
    fin_directions: Set[str] = field(default_factory=set, repr=False)

    @property
    def packet_count(self) -> int:
        return self.forward.packet_count + self.backward.packet_count

    @property
    def byte_count(self) -> int:
        return self.forward.byte_count + self.backward.byte_count

    @property
    def duration(self) -> float:
        """Flow duration in seconds, rounded to the reported precision."""
        return round(self.last_seen - self.start_time, TIME_PRECISION)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the flow into its JSON-compatible record."""
        return {
            "flow_id": self.flow_id,
            "flow_seq": self.flow_seq,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "endpoint_a": dict(self.endpoint_a),
            "endpoint_b": dict(self.endpoint_b),
            "state": self.state,
            "start_time": round(self.start_time, TIME_PRECISION),
            "last_seen": round(self.last_seen, TIME_PRECISION),
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward": self.forward.to_dict(),
            "backward": self.backward.to_dict(),
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "closed": self.closed,
            "close_reason": self.close_reason,
        }

    def to_json(self) -> str:
        """Serialize the flow record to a single JSON line string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)
