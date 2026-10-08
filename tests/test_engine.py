"""Unit tests for the end-to-end IDS engine (parse -> decode -> preprocess -> flow)."""

import unittest
from scapy.all import ARP, IP, Raw, TCP, UDP

from capture.capturer import CapturedPacket
from config import IDSConfig, DecoderConfig, PreprocessorConfig
from pipeline.engine import IDSEngine

T0 = 1700000000.0
FORM_BODY = b"username=admin&password=a%20b"


def _captured(packet, packet_id: int, timestamp: float) -> CapturedPacket:
    return CapturedPacket(
        packet_id=packet_id,
        timestamp=timestamp,
        packet=packet,
        raw_bytes=bytes(packet),
    )


def _http_request_packet() -> object:
    header = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: IDS.LOCAL\r\n"
        b"content-TYPE: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(FORM_BODY)).encode() + b"\r\n\r\n"
    )
    return IP(src="10.0.0.10", dst="10.0.0.20") / TCP(
        sport=52000, dport=80, flags="PA"
    ) / Raw(header + FORM_BODY)


def _handshake_and_close() -> list:
    """SYN, SYN-ACK, ACK, HTTP POST, FIN-ACK (B->A), FIN-ACK (A->B)."""
    return [
        IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="S", seq=1000),
        IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=52000, flags="SA", seq=5000, ack=1001),
        IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="A", seq=1001, ack=5001),
        _http_request_packet(),
        IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=52000, flags="FA", seq=5001, ack=1100),
        IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="FA", seq=1100, ack=5002),
    ]


class TestIDSEngine(unittest.TestCase):
    def test_full_chain_attaches_decode_preprocess_and_flow(self):
        closed: list = []
        engine = IDSEngine(IDSConfig(), on_flow_closed=closed.append)

        events = []
        for index, packet in enumerate(_handshake_and_close()):
            events.append(engine.process_packet(_captured(packet, index + 1, T0 + 0.1 * index)))

        request_event = events[3]
        self.assertIsNotNone(request_event.decode)
        self.assertEqual(request_event.decode.decode_status, "decoded")
        self.assertIn("form_urlencoded", request_event.decode.decoders)
        self.assertEqual(
            request_event.decode.fields["form_fields"], {"username": "admin", "password": "a b"}
        )

        self.assertIsNotNone(request_event.preprocess)
        self.assertEqual(request_event.preprocess.preprocess_status, "valid")
        self.assertIn("http_header_names", request_event.preprocess.normalizations)
        self.assertIn("host_header", request_event.preprocess.normalizations)
        self.assertEqual(request_event.application.details["headers"]["Host"], "ids.local")
        self.assertEqual(request_event.application.details["headers"]["Content-Type"], "application/x-www-form-urlencoded")

        self.assertEqual(request_event.flow.flow_id, "TCP-10.0.0.10:52000-10.0.0.20:80")
        self.assertEqual(request_event.flow.direction, "forward")
        self.assertTrue(events[0].flow.is_new_flow)
        self.assertEqual(events[4].flow.direction, "backward")

        # The flow closes on the second FIN, before end of capture.
        self.assertEqual(len(closed), 1)
        flow = closed[0].to_dict()
        self.assertEqual(flow["state"], "CLOSED")
        self.assertEqual(flow["close_reason"], "fin")
        self.assertEqual(flow["packet_count"], 6)
        self.assertEqual(flow["forward"]["packet_count"], 4)
        self.assertEqual(flow["backward"]["packet_count"], 2)
        self.assertEqual(flow["application_protocol"], "HTTP")
        self.assertEqual(flow["syn_count"], 2)
        self.assertEqual(flow["ack_count"], 5)
        self.assertEqual(flow["fin_count"], 2)

        self.assertEqual(engine.finalize(), 0)
        stats = engine.stats()
        self.assertEqual(stats["packets_processed"], 6)
        self.assertEqual(stats["packets_dropped"], 0)
        self.assertEqual(stats["flows_created"], 1)
        self.assertEqual(stats["flows_closed"], 1)
        self.assertEqual(stats["active"], 0)

    def test_flow_is_flushed_at_end_of_capture(self):
        closed: list = []
        engine = IDSEngine(IDSConfig(), on_flow_closed=closed.append)
        packet = IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="S")
        engine.process_packet(_captured(packet, 1, T0))

        self.assertEqual(closed, [])
        self.assertEqual(engine.finalize(), 1)
        self.assertEqual(closed[0].close_reason, "end_of_capture")

    def test_drop_invalid_skips_flow_tracking(self):
        engine = IDSEngine(IDSConfig(preprocessor=PreprocessorConfig(drop_invalid=True)))
        packet = ARP()
        event = engine.process_packet(_captured(packet, 1, T0))

        self.assertEqual(event.preprocess.processing_action, "dropped")
        self.assertEqual(event.preprocess.reason, "missing_network_layer")
        self.assertIsNone(event.flow)
        self.assertEqual(engine.stats()["packets_dropped"], 1)
        self.assertEqual(engine.stats()["flows_created"], 0)

    def test_drop_invalid_disabled_forwards_and_tracks(self):
        engine = IDSEngine(IDSConfig())
        packet = ARP()
        event = engine.process_packet(_captured(packet, 1, T0))

        self.assertEqual(event.preprocess.processing_action, "forward")
        self.assertIsNone(event.flow)  # no transport layer -> no flow reference
        self.assertEqual(engine.stats()["packets_dropped"], 0)

    def test_max_decode_size_marks_payload_skipped(self):
        engine = IDSEngine(IDSConfig(decoder=DecoderConfig(max_decode_size=16)))
        event = engine.process_packet(_captured(_http_request_packet(), 1, T0))

        self.assertEqual(event.decode.decode_status, "skipped")
        self.assertIn("payload_too_large", event.decode.warnings)

    def test_exclude_unknown_omits_unknown_application_events(self):
        engine = IDSEngine(IDSConfig())
        engine.config.pipeline.include_unknown = False
        engine._parsers.include_unknown = False
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000, dport=40001) / Raw(
            b"\x99\x88\x77\x66binary"
        )
        event = engine.process_packet(_captured(packet, 1, T0))

        self.assertIsNone(event.application)
        self.assertEqual(event.preprocess.reason, "no_application_layer")
        self.assertEqual(event.flow.flow_id, "UDP-10.0.0.1:40000-10.0.0.2:40001")

    def test_udp_dns_flow_is_tracked_and_flushed(self):
        closed: list = []
        engine = IDSEngine(IDSConfig(), on_flow_closed=closed.append)
        query = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(b"\x12\x34\x01\x00" + b"\x00" * 8)
        engine.process_packet(_captured(query, 1, T0))

        self.assertEqual(engine.finalize(), 1)
        flow = closed[0].to_dict()
        self.assertEqual(flow["flow_id"], "UDP-192.168.1.100:53000-8.8.8.8:53")
        self.assertEqual(flow["state"], "ESTABLISHED")
        self.assertEqual(flow["close_reason"], "end_of_capture")


if __name__ == "__main__":
    unittest.main()
