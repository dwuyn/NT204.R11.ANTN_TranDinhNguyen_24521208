"""Flow/Connection Tracker.

Groups normalized events into bidirectional flows keyed by their 5-tuple,
maintains a TCP state machine (NEW/HANDSHAKE -> ESTABLISHED -> CLOSING ->
CLOSED/RESET), expires idle flows using configurable TCP/UDP timeouts, enforces
a maximum number of active flows, and reports per-flow statistics.

The tracker clock is the packet timestamp (``event.timestamp``), so replaying a
PCAP file is fully deterministic; live capture behaves the same way because the
capturer derives timestamps from ``pkt.time``.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

from config import FlowConfig
from flow.models import (
    CLOSE_END_OF_CAPTURE,
    CLOSE_FIN,
    CLOSE_OVERFLOW,
    CLOSE_RST,
    CLOSE_TIMEOUT,
    CLOSE_REASONS,
    DIRECTION_BACKWARD,
    DIRECTION_FORWARD,
    STATE_CLOSED,
    STATE_CLOSING,
    STATE_ESTABLISHED,
    STATE_HANDSHAKE,
    STATE_NEW,
    STATE_RESET,
    Flow,
)
from parsers.models import FlowRef, NormalizedEvent

FlowKey = Tuple[str, str, int, str, int]

TCP_PROTOCOL = "TCP"
UDP_PROTOCOL = "UDP"


class FlowTracker:
    """Tracks bidirectional flows over a stream of normalized events."""

    def __init__(
        self,
        config: FlowConfig,
        on_flow_closed: Optional[Callable[[Flow], None]] = None,
    ) -> None:
        self.config = config
        self._on_flow_closed = on_flow_closed
        self._flows: Dict[FlowKey, Flow] = {}
        self._flows_created = 0
        self._flows_closed = 0
        self._closed_by_reason: Dict[str, int] = {reason: 0 for reason in CLOSE_REASONS}
        self._last_timestamp: Optional[float] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, event: NormalizedEvent) -> Optional[Flow]:
        """Attribute ``event`` to its flow, creating/updating it as needed.

        Returns the flow, or None when the event carries no transport layer
        (such events get no ``flow`` reference).
        """
        timestamp = event.timestamp
        self._last_timestamp = timestamp
        self.expire_idle(timestamp)

        network = event.network
        transport = event.transport
        if network is None or transport is None:
            return None

        protocol = str(transport.layer).strip().upper()
        src_ip = network.src_ip
        dst_ip = network.dst_ip
        src_port = transport.src_port
        dst_port = transport.dst_port

        key: FlowKey = (protocol, src_ip, src_port, dst_ip, dst_port)
        reverse: FlowKey = (protocol, dst_ip, dst_port, src_ip, src_port)

        flow = self._flows.get(key)
        flow_key = key
        direction = DIRECTION_FORWARD
        if flow is None:
            flow = self._flows.get(reverse)
            flow_key = reverse
            direction = DIRECTION_BACKWARD
        is_new_flow = flow is None
        if flow is None:
            flow = self._create_flow(key, protocol, src_ip, src_port, dst_ip, dst_port, timestamp)
            flow_key = key
            direction = DIRECTION_FORWARD

        self._apply_packet(flow_key, flow, event, direction)
        event.flow = FlowRef(
            flow_id=flow.flow_id,
            direction=direction,
            state=flow.state,
            is_new_flow=is_new_flow,
        )
        return flow

    def expire_idle(self, now: float) -> int:
        """Close every flow whose idle time exceeds its protocol timeout."""
        expired: List[Tuple[FlowKey, Flow]] = []
        for key, flow in self._flows.items():
            if now - flow.last_seen > self._timeout_for(flow.protocol):
                expired.append((key, flow))
        for key, flow in expired:
            self._close(key, flow, CLOSE_TIMEOUT)
        return len(expired)

    def finalize(self) -> int:
        """Flush remaining flows at end of capture; returns how many were closed."""
        if self._last_timestamp is None:
            return 0
        closed = self.expire_idle(self._last_timestamp)
        if self.config.flush_on_eof:
            for key, flow in list(self._flows.items()):
                self._close(key, flow, CLOSE_END_OF_CAPTURE)
                closed += 1
        return closed

    @property
    def active_count(self) -> int:
        return len(self._flows)

    def stats(self) -> Dict[str, Any]:
        """Return tracker counters for the run summary."""
        return {
            "flows_created": self._flows_created,
            "flows_closed": self._flows_closed,
            "closed_by_reason": dict(self._closed_by_reason),
            "active": len(self._flows),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _timeout_for(self, protocol: str) -> float:
        if protocol == TCP_PROTOCOL:
            return self.config.tcp_idle_timeout
        return self.config.udp_idle_timeout

    def _create_flow(
        self,
        key: FlowKey,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        timestamp: float,
    ) -> Flow:
        while len(self._flows) >= self.config.max_active_flows and self._flows:
            self._evict_oldest()

        self._flows_created += 1
        flow = Flow(
            flow_id=f"{protocol}-{src_ip}:{src_port}-{dst_ip}:{dst_port}",
            flow_seq=self._flows_created,
            protocol=protocol,
            endpoint_a={"ip": src_ip, "port": src_port},
            endpoint_b={"ip": dst_ip, "port": dst_port},
            start_time=timestamp,
            last_seen=timestamp,
            # UDP has no observable handshake, so it starts established.
            state=STATE_NEW if protocol == TCP_PROTOCOL else STATE_ESTABLISHED,
        )
        self._flows[key] = flow
        return flow

    def _evict_oldest(self) -> None:
        """Close the least recently seen flow to make room for a new one."""
        key = min(self._flows, key=lambda item: self._flows[item].last_seen)
        self._close(key, self._flows[key], CLOSE_OVERFLOW)

    def _apply_packet(
        self, key: FlowKey, flow: Flow, event: NormalizedEvent, direction: str
    ) -> None:
        """Update counters, timestamps, protocol and state for one packet."""
        timestamp = event.timestamp
        size = event.raw_len or 0
        counters = flow.forward if direction == DIRECTION_FORWARD else flow.backward
        counters.packet_count += 1
        counters.byte_count += size
        flow.start_time = min(flow.start_time, timestamp)
        flow.last_seen = max(flow.last_seen, timestamp)

        flags = self._flags_of(event)
        if flow.protocol == TCP_PROTOCOL:
            if "SYN" in flags:
                flow.syn_count += 1
            if "ACK" in flags:
                flow.ack_count += 1
            if "FIN" in flags:
                flow.fin_count += 1
            if "RST" in flags:
                flow.rst_count += 1

        application = event.application
        if application is not None:
            protocol = str(application.protocol).strip().upper()
            if protocol and protocol != "UNKNOWN":
                flow.application_protocol = protocol

        # The state machine needs the FIN directions seen *before* this packet
        # to recognise a full close (FIN from both sides).
        flow.state = self._next_state(flow, flags, direction)
        if "FIN" in flags:
            flow.fin_directions.add(direction)

        if flow.state == STATE_CLOSED:
            self._close(key, flow, CLOSE_FIN)
        elif flow.state == STATE_RESET:
            self._close(key, flow, CLOSE_RST)

    @staticmethod
    def _flags_of(event: NormalizedEvent) -> List[str]:
        transport = event.transport
        if transport is None or not transport.flags:
            return []
        return [str(flag).upper() for flag in transport.flags]

    def _next_state(self, flow: Flow, flags: List[str], direction: str) -> str:
        """Compute the next flow state from the current state and packet flags."""
        if flow.protocol != TCP_PROTOCOL:
            return STATE_ESTABLISHED

        state = flow.state
        if state == STATE_NEW:
            if "RST" in flags:
                return STATE_RESET
            if "FIN" in flags:
                return STATE_CLOSING
            if "SYN" in flags:
                return STATE_HANDSHAKE
            return STATE_ESTABLISHED

        if state == STATE_HANDSHAKE:
            if "RST" in flags:
                return STATE_RESET
            if "FIN" in flags:
                return STATE_CLOSING
            if "ACK" in flags and "SYN" not in flags:
                return STATE_ESTABLISHED
            return state

        if state == STATE_ESTABLISHED:
            if "RST" in flags:
                return STATE_RESET
            if "FIN" in flags:
                return STATE_CLOSING
            return state

        if state == STATE_CLOSING:
            if "RST" in flags:
                return STATE_RESET
            if "FIN" in flags and flow.fin_directions and direction not in flow.fin_directions:
                return STATE_CLOSED
            return state

        # CLOSED and RESET are terminal.
        return state

    def _close(self, key: FlowKey, flow: Flow, reason: str) -> None:
        """Emit a flow record and drop it from the active table."""
        if flow.closed:
            return
        flow.closed = True
        flow.close_reason = reason
        self._flows.pop(key, None)
        self._flows_closed += 1
        if reason in self._closed_by_reason:
            self._closed_by_reason[reason] += 1
        if self._on_flow_closed is not None:
            self._on_flow_closed(flow)
