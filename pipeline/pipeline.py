"""Unified packet parsing pipeline.

Implements the multi-stage decoding pipeline:
Raw Packet -> Network Parser -> Transport Parser -> App Detector -> App Parser -> Normalized Event.
Unified for both Live Capture and PCAP import.
"""

from typing import List, Optional, Tuple

from capture.capturer import CapturedPacket
from parsers.application.dns import DnsParser
from parsers.application.http import HttpParser
from parsers.application.smtp import SmtpParser
from parsers.detector import AppProtocolDetector
from parsers.models import ApplicationLayer, NormalizedEvent
from parsers.network import NetworkParser
from parsers.transport import TransportParser


class ParsingPipeline:
    """Processes captured raw packets through protocol parsers into normalized IDS events."""

    def __init__(self, include_unknown: bool = True) -> None:
        self.include_unknown = include_unknown

    def process_packet(self, captured: CapturedPacket) -> NormalizedEvent:
        """Execute the end-to-end parsing pipeline on a single captured packet.

        Guaranteed not to raise unhandled exceptions even on severely malformed packets.
        """
        event, _raw_payload = self.parse(captured)
        return event

    def parse(self, captured: CapturedPacket) -> Tuple[NormalizedEvent, bytes]:
        """Parse a captured packet into a normalized event plus its raw payload.

        The raw transport payload is returned so that later stages (decoder,
        preprocessor, flow tracker) never need access to the Scapy packet.
        """
        all_errors: List[str] = []
        network_layer = None
        transport_layer = None
        application_layer: Optional[ApplicationLayer] = None
        raw_payload = b""

        try:
            # Stage 1: Network Layer Parser (IPv4)
            network_layer, net_errors = NetworkParser.parse(captured.packet)
            if net_errors:
                all_errors.extend(net_errors)

            # Stage 2: Transport Layer Parser (TCP / UDP)
            transport_layer, raw_payload, trans_errors = TransportParser.parse(captured.packet)
            if trans_errors:
                all_errors.extend(trans_errors)

            # Stage 3: Application Protocol Detector
            app_proto, det_method = AppProtocolDetector.detect(
                packet=captured.packet,
                transport=transport_layer,
                payload=raw_payload,
            )

            # Stage 4: Application Protocol Parser
            if app_proto == "HTTP":
                application_layer, app_errors = HttpParser.parse(raw_payload)
                if app_errors:
                    all_errors.extend(app_errors)
                if application_layer:
                    application_layer.details["detection_method"] = det_method

            elif app_proto == "DNS":
                application_layer, app_errors = DnsParser.parse(captured.packet)
                if not application_layer and raw_payload:
                    application_layer, app_errors = DnsParser.parse(raw_payload)
                if app_errors:
                    all_errors.extend(app_errors)
                if application_layer:
                    application_layer.details["detection_method"] = det_method

            elif app_proto == "SMTP":
                application_layer, app_errors = SmtpParser.parse(raw_payload)
                if app_errors:
                    all_errors.extend(app_errors)
                if application_layer:
                    application_layer.details["detection_method"] = det_method

            else:
                if self.include_unknown and (raw_payload or not transport_layer):
                    application_layer = ApplicationLayer(
                        protocol="UNKNOWN",
                        type="unknown",
                        details={"detection_method": det_method},
                    )

        except Exception as exc:
            all_errors.append(f"Pipeline error: {str(exc)}")

        # Stage 5: Normalized IDS Event Assembly
        event = NormalizedEvent(
            packet_id=captured.packet_id,
            timestamp=captured.timestamp,
            raw_len=len(captured.raw_bytes) if captured.raw_bytes else len(captured.packet),
            network=network_layer,
            transport=transport_layer,
            application=application_layer,
            errors=all_errors,
        )
        return event, raw_payload
