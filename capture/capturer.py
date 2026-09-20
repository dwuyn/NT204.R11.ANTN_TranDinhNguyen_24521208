"""Packet capture engine supporting both live interface capture and PCAP file import.

Provides a unified streaming generator yielding CapturedPacket instances so downstream
parsing pipelines do not depend on the capture source.
"""

from dataclasses import dataclass
import os
import queue
import threading
import time
from typing import Iterator, Optional

from scapy.all import Packet, PcapReader, sniff


@dataclass
class CapturedPacket:
    """Represents an intercepted packet with metadata before parsing."""
    packet_id: int
    timestamp: float
    packet: Packet
    raw_bytes: bytes


class PacketCapture:
    """Unified packet capture source for live network interfaces and PCAP files."""

    @staticmethod
    def read_pcap(pcap_path: str) -> Iterator[CapturedPacket]:
        """Read packets sequentially from a PCAP file using a streaming reader.

        Args:
            pcap_path: Path to the .pcap or .pcapng file.

        Yields:
            CapturedPacket containing packet ID, capture timestamp, and scapy Packet.

        Raises:
            FileNotFoundError: If the specified PCAP file does not exist.
        """
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        packet_id = 0
        try:
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    packet_id += 1
                    ts = float(getattr(pkt, "time", time.time()))
                    try:
                        raw = bytes(pkt)
                    except Exception:
                        raw = b""
                    yield CapturedPacket(
                        packet_id=packet_id,
                        timestamp=ts,
                        packet=pkt,
                        raw_bytes=raw,
                    )
        except Exception as e:
            # Handle corrupt / truncated PCAP files without crashing completely
            if packet_id == 0 and not isinstance(e, EOFError):
                raise

    @staticmethod
    def capture_live(
        interface: str,
        count: Optional[int] = None,
        bpf_filter: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Iterator[CapturedPacket]:
        """Capture live packets from a network interface as a streaming generator.

        Args:
            interface: Name of the network interface (e.g., 'eth0', 'wlan0', 'lo').
            count: Maximum number of packets to capture (None for infinite).
            bpf_filter: Optional BPF filter string.
            timeout: Optional timeout in seconds to stop sniffing.

        Yields:
            CapturedPacket instances as they arrive on the interface.
        """
        packet_queue: queue.Queue = queue.Queue(maxsize=1000)
        stop_event = threading.Event()
        counter = [0]

        def _packet_callback(pkt: Packet) -> None:
            arrival_time = time.time()
            ts = float(getattr(pkt, "time", arrival_time))
            counter[0] += 1
            pkt_id = counter[0]
            try:
                raw = bytes(pkt)
            except Exception:
                raw = b""

            captured = CapturedPacket(
                packet_id=pkt_id,
                timestamp=ts,
                packet=pkt,
                raw_bytes=raw,
            )
            packet_queue.put(captured)

        def _sniff_thread_worker() -> None:
            try:
                sniff(
                    iface=interface,
                    count=count if count else 0,
                    filter=bpf_filter,
                    timeout=timeout,
                    prn=_packet_callback,
                    store=False,
                    stop_filter=lambda _: stop_event.is_set(),
                )
            except PermissionError as exc:
                packet_queue.put(
                    PermissionError(
                        f"Live packet capture on '{interface}' requires root privileges (run with sudo)."
                    )
                )
            except Exception as exc:
                packet_queue.put(exc)
            finally:
                packet_queue.put(None)  # Sentinel to denote EOF

        thread = threading.Thread(target=_sniff_thread_worker, daemon=True)
        thread.start()

        try:
            while True:
                try:
                    item = packet_queue.get(timeout=0.2)
                except queue.Empty:
                    if not thread.is_alive() and packet_queue.empty():
                        break
                    continue

                if item is None:
                    break
                if isinstance(item, Exception):
                    raise item

                yield item
        finally:
            stop_event.set()
            thread.join(timeout=1.0)
