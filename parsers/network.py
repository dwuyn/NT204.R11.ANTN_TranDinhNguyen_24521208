"""Network Layer (Layer 3) parser for IPv4 packets."""

from typing import List, Optional, Tuple

from scapy.all import Packet
from scapy.layers.inet import IP

from parsers.models import NetworkLayer

# Protocol number to standard string mapping
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}


class NetworkParser:
    """Parses Layer 3 metadata, focusing on IPv4 packets."""

    @staticmethod
    def parse_flags(ip_layer: IP) -> List[str]:
        """Decode IP flags (e.g. DF, MF) into a list of strings."""
        flags: List[str] = []
        try:
            # Scapy FlagValue representation or bitwise check
            flag_val = getattr(ip_layer, "flags", None)
            if flag_val is not None:
                flag_str = str(flag_val).upper()
                if "DF" in flag_str:
                    flags.append("DF")
                if "MF" in flag_str:
                    flags.append("MF")
        except Exception:
            pass
        return flags

    @classmethod
    def parse(cls, packet: Packet) -> Tuple[Optional[NetworkLayer], List[str]]:
        """Extract normalized network layer information from a Scapy packet.

        Args:
            packet: Captured Scapy packet.

        Returns:
            A tuple of (NetworkLayer or None, list of error messages).
        """
        errors: List[str] = []

        if not packet.haslayer(IP):
            # Non-IPv4 packet (ARP, IPv6, raw, etc.)
            return None, errors

        try:
            ip: IP = packet[IP]
            src_ip = str(getattr(ip, "src", ""))
            dst_ip = str(getattr(ip, "dst", ""))
            proto_num = getattr(ip, "proto", 0)
            proto_name = IP_PROTOCOLS.get(proto_num, f"PROTO_{proto_num}")

            ttl_val = getattr(ip, "ttl", 64)
            ttl = int(ttl_val) if ttl_val is not None else 64

            id_val = getattr(ip, "id", 0)
            pkt_id = int(id_val) if id_val is not None else 0

            ihl_val = getattr(ip, "ihl", 5)
            ihl = int(ihl_val) if ihl_val is not None else 5

            tos_val = getattr(ip, "tos", 0)
            tos = int(tos_val) if tos_val is not None else 0

            len_val = getattr(ip, "len", None)
            if len_val is None:
                try:
                    total_len = len(ip)
                except Exception:
                    total_len = 0
            else:
                total_len = int(len_val)

            flags = cls.parse_flags(ip)

            layer = NetworkLayer(
                layer="IPv4",
                src_ip=src_ip,
                dst_ip=dst_ip,
                proto=proto_name,
                ttl=ttl,
                id=pkt_id,
                ihl=ihl,
                tos=tos,
                total_len=total_len,
                flags=flags,
            )
            return layer, errors
        except Exception as exc:
            errors.append(f"IPv4 parse error: {str(exc)}")
            return None, errors
