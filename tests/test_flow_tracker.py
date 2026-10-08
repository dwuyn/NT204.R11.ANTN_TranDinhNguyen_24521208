"""Unit tests for the flow/connection tracker."""

import unittest

from config import FlowConfig
from flow.models import (
    CLOSE_END_OF_CAPTURE,
    CLOSE_FIN,
    CLOSE_OVERFLOW,
    CLOSE_RST,
    CLOSE_TIMEOUT,
    STATE_CLOSED,
    STATE_ESTABLISHED,
    STATE_HANDSHAKE,
    STATE_RESET,
    Flow,
)
from flow.tracker import FlowTracker
from parsers.models import ApplicationLayer, NetworkLayer, NormalizedEvent, TransportLayer

T0 = 1700000000.0


def _event(
    timestamp: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    layer: str = "TCP",
    flags=None,
    raw_len: int = 60,
    application=None,
) -> NormalizedEvent:
    return NormalizedEvent(
        packet_id=int(timestamp * 1000),
        timestamp=timestamp,
        raw_len=raw_len,
        network=NetworkLayer(src_ip=src_ip, dst_ip=dst_ip, proto=layer),
        transport=TransportLayer(
            layer=layer,
            src_port=src_port,
            dst_port=dst_port,
            flags=list(flags or []),
        ),
        application=application,
    )


def _http_request() -> ApplicationLayer:
    return ApplicationLayer(protocol="HTTP", type="request", details={"uri": "/"})


def _dns_query() -> ApplicationLayer:
    return ApplicationLayer(protocol="DNS", type="query", details={"queries": []})


class FlowTrackerTestBase(unittest.TestCase):
    def setUp(self):
        self.closed: list = []
        self.tracker = FlowTracker(FlowConfig(), on_flow_closed=self.closed.append)

    def flow_by_id(self, flow_id: str) -> Flow:
        matches = [flow for flow in self.closed if flow.flow_id == flow_id]
        self.assertEqual(len(matches), 1, msg=f"expected exactly one closed flow {flow_id}")
        return matches[0]


class TestTcpFlowStates(FlowTrackerTestBase):
    def test_handshake_flow(self):
        flow_id = "TCP-10.0.0.10:51234-10.0.0.1:80"
        e1 = _event(T0, "10.0.0.10", "10.0.0.1", 51234, 80, flags=["SYN"])
        e2 = _event(T0 + 0.001, "10.0.0.1", "10.0.0.10", 80, 51234, flags=["SYN", "ACK"])
        e3 = _event(T0 + 0.002, "10.0.0.10", "10.0.0.1", 51234, 80, flags=["ACK"])

        self.assertIsNotNone(self.tracker.observe(e1))
        self.tracker.observe(e2)
        self.tracker.observe(e3)

        self.assertTrue(e1.flow.is_new_flow)
        self.assertEqual(e1.flow.state, STATE_HANDSHAKE)
        self.assertEqual(e1.flow.direction, "forward")
        self.assertEqual(e2.flow.direction, "backward")
        self.assertEqual(e2.flow.flow_id, flow_id)
        self.assertEqual(e3.flow.state, STATE_ESTABLISHED)
        self.assertFalse(e3.flow.is_new_flow)

        self.assertEqual(self.tracker.finalize(), 1)
        flow = self.flow_by_id(flow_id)
        record = flow.to_dict()
        self.assertEqual(record["state"], STATE_ESTABLISHED)
        self.assertEqual(record["close_reason"], CLOSE_END_OF_CAPTURE)
        self.assertEqual(record["packet_count"], 3)
        self.assertEqual(record["forward"]["packet_count"], 2)
        self.assertEqual(record["backward"]["packet_count"], 1)
        self.assertEqual(record["syn_count"], 2)
        self.assertEqual(record["ack_count"], 2)
        self.assertEqual(record["fin_count"], 0)
        self.assertEqual(record["rst_count"], 0)

    def test_bidirectional_packets_share_one_flow(self):
        flow_id = "TCP-10.0.0.10:52000-10.0.0.20:80"
        request = _event(T0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["PSH", "ACK"], application=_http_request())
        response = _event(T0 + 0.01, "10.0.0.20", "10.0.0.10", 80, 52000, flags=["PSH", "ACK"], raw_len=80)

        self.tracker.observe(request)
        self.tracker.observe(response)
        self.tracker.finalize()

        self.assertEqual(request.flow.flow_id, response.flow.flow_id)
        self.assertEqual(request.flow.direction, "forward")
        self.assertEqual(response.flow.direction, "backward")
        flow = self.flow_by_id(flow_id)
        self.assertEqual(flow.forward.packet_count, 1)
        self.assertEqual(flow.backward.packet_count, 1)
        self.assertEqual(flow.byte_count, 140)
        self.assertEqual(flow.application_protocol, "HTTP")

    def test_fin_close_and_reset(self):
        flow_a = "TCP-10.0.0.10:51001-10.0.0.30:80"
        flow_b = "TCP-10.0.0.10:51002-10.0.0.30:8080"
        packets = [
            _event(T0, "10.0.0.10", "10.0.0.30", 51001, 80, flags=["SYN"]),
            _event(T0 + 0.1, "10.0.0.30", "10.0.0.10", 80, 51001, flags=["SYN", "ACK"]),
            _event(T0 + 0.2, "10.0.0.10", "10.0.0.30", 51001, 80, flags=["ACK"]),
            _event(T0 + 0.3, "10.0.0.10", "10.0.0.30", 51001, 80, flags=["FIN", "ACK"]),
            _event(T0 + 0.4, "10.0.0.30", "10.0.0.10", 80, 51001, flags=["ACK"]),
            _event(T0 + 0.5, "10.0.0.30", "10.0.0.10", 80, 51001, flags=["FIN", "ACK"]),
            _event(T0 + 0.6, "10.0.0.10", "10.0.0.30", 51002, 8080, flags=["SYN"]),
            _event(T0 + 0.7, "10.0.0.10", "10.0.0.30", 51002, 8080, flags=["RST"]),
        ]
        for packet in packets:
            self.tracker.observe(packet)

        self.assertEqual(packets[3].flow.state, "CLOSING")
        self.assertEqual(packets[5].flow.state, STATE_CLOSED)
        self.assertEqual(packets[6].flow.state, STATE_HANDSHAKE)
        self.assertEqual(packets[7].flow.state, STATE_RESET)

        # Both flows closed as soon as their terminal packet was seen.
        self.assertEqual(len(self.closed), 2)
        self.assertEqual(self.tracker.active_count, 0)
        self.assertEqual(self.flow_by_id(flow_a).close_reason, CLOSE_FIN)
        self.assertEqual(self.flow_by_id(flow_a).fin_count, 2)
        self.assertEqual(self.flow_by_id(flow_a).state, STATE_CLOSED)
        self.assertEqual(self.flow_by_id(flow_b).close_reason, CLOSE_RST)
        self.assertEqual(self.flow_by_id(flow_b).rst_count, 1)
        self.assertEqual(self.tracker.stats()["closed_by_reason"][CLOSE_FIN], 1)

    def test_flow_id_reuse_after_close_gets_new_sequence(self):
        e1 = _event(T0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"])
        e2 = _event(T0 + 0.1, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["RST"])
        e3 = _event(T0 + 1.0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"])
        for packet in (e1, e2, e3):
            self.tracker.observe(packet)
        self.tracker.finalize()

        seqs = [flow.flow_seq for flow in self.closed if flow.flow_id == "TCP-10.0.0.10:52000-10.0.0.20:80"]
        self.assertEqual(seqs, [1, 2])
        self.assertTrue(e3.flow.is_new_flow)


class TestUdpAndTimeouts(FlowTrackerTestBase):
    def test_udp_flow_is_established_immediately(self):
        flow_id = "UDP-192.168.1.100:53000-8.8.8.8:53"
        query = _event(T0, "192.168.1.100", "8.8.8.8", 53000, 53, layer="UDP", raw_len=70, application=_dns_query())
        response = _event(T0 + 0.005, "8.8.8.8", "192.168.1.100", 53, 53000, layer="UDP", raw_len=120)

        self.tracker.observe(query)
        self.tracker.observe(response)
        self.assertEqual(query.flow.state, STATE_ESTABLISHED)
        self.tracker.finalize()

        flow = self.flow_by_id(flow_id)
        self.assertEqual(flow.protocol, "UDP")
        self.assertEqual(flow.state, STATE_ESTABLISHED)
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.byte_count, 190)
        self.assertEqual(flow.forward.packet_count, 1)
        self.assertEqual(flow.backward.packet_count, 1)
        self.assertEqual(flow.syn_count, 0)
        self.assertEqual(flow.ack_count, 0)
        self.assertEqual(flow.application_protocol, "DNS")

    def test_idle_timeout_closes_flow(self):
        flow1 = _event(T0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"])
        flow1_ack = _event(T0 + 0.01, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["ACK"])
        flow2 = _event(T0 + 30.0, "10.0.0.11", "10.0.0.20", 53000, 8080, flags=["SYN"])

        self.tracker.observe(flow1)
        self.tracker.observe(flow1_ack)
        self.assertEqual(self.tracker.active_count, 1)

        self.tracker.observe(flow2)  # 29.99s of silence > default? no: default TCP timeout is 120s
        self.assertEqual(self.tracker.active_count, 2)

        self.assertEqual(self.tracker.expire_idle(T0 + 30.0), 0)
        self.assertEqual(self.tracker.expire_idle(T0 + 200.0), 2)
        self.assertEqual(self.tracker.active_count, 0)
        self.assertEqual(self.closed[0].close_reason, CLOSE_TIMEOUT)

    def test_configurable_tcp_timeout(self):
        tracker = FlowTracker(FlowConfig(tcp_idle_timeout=5.0), on_flow_closed=self.closed.append)
        tracker.observe(_event(T0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"]))
        tracker.observe(_event(T0 + 0.01, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["ACK"]))
        tracker.observe(_event(T0 + 30.0, "10.0.0.11", "10.0.0.20", 53000, 8080, flags=["SYN"]))

        flow1 = [flow for flow in self.closed if flow.flow_id == "TCP-10.0.0.10:52000-10.0.0.20:80"]
        self.assertEqual(len(flow1), 1)
        self.assertEqual(flow1[0].close_reason, CLOSE_TIMEOUT)
        self.assertEqual(flow1[0].state, STATE_ESTABLISHED)
        self.assertEqual(flow1[0].packet_count, 2)

        self.assertEqual(tracker.finalize(), 1)
        flow2 = [flow for flow in self.closed if flow.flow_id == "TCP-10.0.0.11:53000-10.0.0.20:8080"]
        self.assertEqual(flow2[0].close_reason, CLOSE_END_OF_CAPTURE)

    def test_timeout_boundary_is_not_expired(self):
        self.tracker = FlowTracker(FlowConfig(tcp_idle_timeout=5.0), on_flow_closed=self.closed.append)
        self.tracker.observe(_event(T0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"]))

        self.assertEqual(self.tracker.expire_idle(T0 + 5.0), 0)
        self.assertEqual(self.tracker.active_count, 1)
        self.assertEqual(self.tracker.expire_idle(T0 + 5.0001), 1)

    def test_udp_and_tcp_use_different_timeouts(self):
        tracker = FlowTracker(
            FlowConfig(tcp_idle_timeout=100.0, udp_idle_timeout=30.0),
            on_flow_closed=self.closed.append,
        )
        tracker.observe(_event(T0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"]))
        tracker.observe(_event(T0, "10.0.0.10", "8.8.8.8", 53000, 53, layer="UDP"))

        self.assertEqual(tracker.expire_idle(T0 + 31.0), 1)
        closed_ids = [flow.flow_id for flow in self.closed]
        self.assertEqual(closed_ids, ["UDP-10.0.0.10:53000-8.8.8.8:53"])
        self.assertEqual(tracker.active_count, 1)

    def test_finalize_without_packets_closes_nothing(self):
        self.assertEqual(self.tracker.finalize(), 0)
        self.assertEqual(self.tracker.stats()["flows_created"], 0)

    def test_flush_on_eof_can_be_disabled(self):
        tracker = FlowTracker(FlowConfig(flush_on_eof=False), on_flow_closed=self.closed.append)
        tracker.observe(_event(T0, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"]))

        self.assertEqual(tracker.finalize(), 0)
        self.assertEqual(tracker.active_count, 1)
        self.assertEqual(self.closed, [])


class TestFlowStatistics(FlowTrackerTestBase):
    def test_counters_and_duration(self):
        flow_id = "TCP-10.1.1.1:40000-10.1.1.2:80"
        flags = [
            ["SYN"],
            ["SYN", "ACK"],
            ["ACK"],
            ["PSH", "ACK"],
            ["PSH", "ACK"],
            ["FIN", "ACK"],
            ["ACK"],
            ["FIN", "ACK"],
        ]
        srcs = [
            ("10.1.1.1", "10.1.1.2", 40000, 80),
            ("10.1.1.2", "10.1.1.1", 80, 40000),
            ("10.1.1.1", "10.1.1.2", 40000, 80),
            ("10.1.1.1", "10.1.1.2", 40000, 80),
            ("10.1.1.2", "10.1.1.1", 80, 40000),
            ("10.1.1.1", "10.1.1.2", 40000, 80),
            ("10.1.1.2", "10.1.1.1", 80, 40000),
            ("10.1.1.2", "10.1.1.1", 80, 40000),
        ]
        for index, (packet_flags, (src, dst, sport, dport)) in enumerate(zip(flags, srcs)):
            self.tracker.observe(
                _event(T0 + 0.1 * index, src, dst, sport, dport, flags=packet_flags, raw_len=100)
            )

        flow = self.flow_by_id(flow_id)
        record = flow.to_dict()
        self.assertEqual(record["packet_count"], 8)
        self.assertEqual(record["byte_count"], 800)
        self.assertEqual(record["forward"]["packet_count"], 4)
        self.assertEqual(record["backward"]["packet_count"], 4)
        self.assertEqual(record["forward"]["byte_count"], 400)
        self.assertEqual(record["backward"]["byte_count"], 400)
        self.assertEqual(record["syn_count"], 2)
        self.assertEqual(record["ack_count"], 7)
        self.assertEqual(record["fin_count"], 2)
        self.assertEqual(record["rst_count"], 0)
        self.assertEqual(record["start_time"], T0)
        self.assertEqual(record["last_seen"], T0 + 0.7)
        self.assertEqual(record["duration"], 0.7)
        self.assertEqual(record["state"], STATE_CLOSED)
        self.assertEqual(record["close_reason"], CLOSE_FIN)
        self.assertEqual(record["endpoint_a"], {"ip": "10.1.1.1", "port": 40000})
        self.assertEqual(record["endpoint_b"], {"ip": "10.1.1.2", "port": 80})
        self.assertEqual(flow.duration, round(flow.last_seen - flow.start_time, 6))

    def test_concurrent_flows(self):
        quintuples = [
            ("10.0.0.10", "10.0.0.20", 52000, 80),
            ("10.0.0.11", "10.0.0.20", 52001, 80),
            ("10.0.0.10", "10.0.0.30", 52002, 443),
        ]
        for round_index in range(2):
            for index, (src, dst, sport, dport) in enumerate(quintuples):
                self.tracker.observe(
                    _event(T0 + 0.01 * (round_index * 3 + index), src, dst, sport, dport, flags=["PSH", "ACK"])
                )

        self.assertEqual(self.tracker.active_count, 3)
        self.assertEqual(self.tracker.finalize(), 3)
        self.assertEqual(len(self.closed), 3)
        self.assertEqual(
            sorted(flow.flow_id for flow in self.closed),
            [
                "TCP-10.0.0.10:52000-10.0.0.20:80",
                "TCP-10.0.0.10:52002-10.0.0.30:443",
                "TCP-10.0.0.11:52001-10.0.0.20:80",
            ],
        )
        for flow in self.closed:
            self.assertEqual(flow.packet_count, 2)

    def test_max_active_flows_evicts_oldest(self):
        tracker = FlowTracker(FlowConfig(max_active_flows=2), on_flow_closed=self.closed.append)
        tracker.observe(_event(T0, "10.0.0.1", "10.0.0.9", 1000, 80, flags=["SYN"]))
        tracker.observe(_event(T0 + 1, "10.0.0.2", "10.0.0.9", 1001, 80, flags=["SYN"]))
        tracker.observe(_event(T0 + 2, "10.0.0.3", "10.0.0.9", 1002, 80, flags=["SYN"]))

        self.assertEqual(tracker.active_count, 2)
        self.assertEqual(len(self.closed), 1)
        self.assertEqual(self.closed[0].flow_id, "TCP-10.0.0.1:1000-10.0.0.9:80")
        self.assertEqual(self.closed[0].close_reason, CLOSE_OVERFLOW)

        stats = tracker.stats()
        self.assertEqual(stats["flows_created"], 3)
        self.assertEqual(stats["closed_by_reason"][CLOSE_OVERFLOW], 1)
        self.assertEqual(stats["active"], 2)

    def test_unknown_application_protocol_is_ignored(self):
        event = _event(
            T0,
            "10.0.0.10",
            "10.0.0.20",
            52000,
            9999,
            flags=["PSH", "ACK"],
            application=ApplicationLayer(protocol="UNKNOWN", type="default", details={}),
        )
        self.tracker.observe(event)
        self.tracker.finalize()

        self.assertIsNone(self.closed[0].application_protocol)


class TestEventsWithoutTransport(FlowTrackerTestBase):
    def test_observe_returns_none_without_transport(self):
        event = NormalizedEvent(
            packet_id=1,
            timestamp=T0,
            raw_len=42,
            network=None,
            transport=None,
        )
        self.assertIsNone(self.tracker.observe(event))
        self.assertIsNone(event.flow)
        self.assertEqual(self.tracker.active_count, 0)

    def test_mixed_events_do_not_break_tracking(self):
        arp = NormalizedEvent(packet_id=1, timestamp=T0, raw_len=42)
        tcp = _event(T0 + 0.1, "10.0.0.10", "10.0.0.20", 52000, 80, flags=["SYN"])

        self.tracker.observe(arp)
        self.tracker.observe(tcp)
        self.assertEqual(self.tracker.active_count, 1)
        self.assertIsNone(arp.flow)
        self.assertIsNotNone(tcp.flow)


if __name__ == "__main__":
    unittest.main()
