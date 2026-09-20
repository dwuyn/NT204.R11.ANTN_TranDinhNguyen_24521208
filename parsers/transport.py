"""Transport Layer (Layer 4) parser for TCP and UDP packets."""

from typing import List, Optional, Tuple

from scapy.all import Packet
from scapy.layers.inet import TCP, UDP

from parsers.models import TransportLayer

TCP_FLAG_MASKS = [
    (0x02, "SYN"),
    (0x10, "ACK"),
    (0x01, "FIN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]


class TransportParser:
    """Parses Layer 4 metadata, supporting TCP (with flag and handshake detection) and UDP."""

    @staticmethod
    def parse_tcp_flags(tcp_layer: TCP) -> List[str]:
        """Decode TCP flags into a standardized list of flag names."""
        flags: List[str] = []
        try:
            flag_val = getattr(tcp_layer, "flags", None)
            if flag_val is not None:
                try:
                    flag_int = int(flag_val)
                    for bit, name in TCP_FLAG_MASKS:
                        if flag_int & bit:
                            flags.append(name)
                except (ValueError, TypeError):
                    flag_str = str(flag_val).upper()
                    if "S" in flag_str:
                        flags.append("SYN")
                    if "A" in flag_str:
                        flags.append("ACK")
                    if "F" in flag_str:
                        flags.append("FIN")
                    if "R" in flag_str:
                        flags.append("RST")
                    if "P" in flag_str:
                        flags.append("PSH")
                    if "U" in flag_str:
                        flags.append("URG")
        except Exception:
            pass
        return flags

    @staticmethod
    def detect_handshake(flags: List[str], payload_len: int) -> Optional[str]:
        """Identify TCP 3-way handshake packets: SYN, SYN-ACK, ACK."""
        if flags == ["SYN"]:
            return "SYN"
        if "SYN" in flags and "ACK" in flags:
            return "SYN-ACK"
        if flags == ["ACK"] and payload_len == 0:
            return "ACK"
        return None

    @classmethod
    def parse(cls, packet: Packet) -> Tuple[Optional[TransportLayer], bytes, List[str]]:
        """Extract normalized transport layer information and raw payload bytes.

        Args:
            packet: Captured Scapy packet.

        Returns:
            A tuple of (TransportLayer or None, raw payload bytes, list of errors).
        """
        errors: List[str] = []

        if packet.haslayer(TCP):
            try:
                tcp: TCP = packet[TCP]
                src_port = int(getattr(tcp, "sport", 0))
                dst_port = int(getattr(tcp, "dport", 0))

                seq_val = getattr(tcp, "seq", None)
                seq = int(seq_val) if seq_val is not None else None

                ack_val = getattr(tcp, "ack", None)
                ack = int(ack_val) if ack_val is not None else None

                window_val = getattr(tcp, "window", None)
                window = int(window_val) if window_val is not None else None

                data_offset_val = getattr(tcp, "dataofs", None)
                data_offset = int(data_offset_val) if data_offset_val is not None else None

                try:
                    payload = bytes(tcp.payload)
                except Exception:
                    payload = b""

                payload_len = len(payload)
                flags = cls.parse_tcp_flags(tcp)
                handshake = cls.detect_handshake(flags, payload_len)

                layer = TransportLayer(
                    layer="TCP",
                    src_port=src_port,
                    dst_port=dst_port,
                    seq=seq,
                    ack=ack,
                    flags=flags,
                    handshake=handshake,
                    window=window,
                    data_offset=data_offset,
                    payload_len=payload_len,
                )
                return layer, payload, errors
            except Exception as exc:
                errors.append(f"TCP parse error: {str(exc)}")
                return None, b"", errors

        elif packet.haslayer(UDP):
            try:
                udp: UDP = packet[UDP]
                src_port = int(getattr(udp, "sport", 0))
                dst_port = int(getattr(udp, "dport", 0))

                len_val = getattr(udp, "len", None)
                if len_val is not None:
                    total_len = int(len_val)
                else:
                    try:
                        total_len = len(udp)
                    except Exception:
                        total_len = 0

                chksum_val = getattr(udp, "chksum", None)
                checksum = int(chksum_val) if chksum_val is not None else None

                try:
                    payload = bytes(udp.payload)
                except Exception:
                    payload = b""

                payload_len = len(payload)

                layer = TransportLayer(
                    layer="UDP",
                    src_port=src_port,
                    dst_port=dst_port,
                    checksum=checksum,
                    payload_len=payload_len,
                )
                return layer, payload, errors
            except Exception as exc:
                errors.append(f"UDP parse error: {str(exc)}")
                return None, b"", errors

        return None, b"", errors
