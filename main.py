#!/usr/bin/env python3
"""Main CLI entrypoint for IDS Packet Capture & Parser.

Supports:
  - Live capture from interface:   python main.py --interface eth0
  - Import from PCAP file:          python main.py --pcap traffic.pcap
  - Saving output to JSON Lines:    python main.py --pcap traffic.pcap --output output.jsonl
  - Packet count limit:             python main.py --interface eth0 --count 100
"""

import argparse
import sys
import time

from capture.capturer import PacketCapture
from pipeline.pipeline import ParsingPipeline
from storage.logger import JsonLinesLogger


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IDS Packet Capture & Parser Module (NT204.R11.ANTN)",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    capture_group = parser.add_mutually_exclusive_group(required=True)
    capture_group.add_argument(
        "--interface",
        "-i",
        type=str,
        help="Network interface for live packet capture (e.g. eth0, wlan0, lo)",
    )
    capture_group.add_argument(
        "--pcap",
        "-p",
        type=str,
        help="Path to PCAP/PCAPNG file to parse",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="output.jsonl",
        help="Path to output JSON Lines file (default: output.jsonl)",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=None,
        help="Maximum number of packets to capture/process",
    )
    parser.add_argument(
        "--bpf",
        type=str,
        default=None,
        help="Berkeley Packet Filter (BPF) expression (e.g. 'tcp or udp')",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress per-packet console summary output",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    pipeline = ParsingPipeline()

    console_summary = not args.quiet
    processed_count = 0
    start_time = time.time()

    print("=" * 60)
    print("  IDS Packet Capture & Parser Engine")
    print("=" * 60)
    if args.pcap:
        print(f"[*] Mode: PCAP Import ({args.pcap})")
        stream = PacketCapture.read_pcap(args.pcap)
    else:
        print(f"[*] Mode: Live Capture on interface '{args.interface}'")
        if args.bpf:
            print(f"[*] BPF Filter: {args.bpf}")
        stream = PacketCapture.capture_live(
            interface=args.interface,
            count=args.count,
            bpf_filter=args.bpf,
        )

    print(f"[*] Writing normalized events to: {args.output}")
    print("-" * 60)

    try:
        with JsonLinesLogger(filepath=args.output, console_summary=console_summary) as logger:
            for captured in stream:
                event = pipeline.process_packet(captured)
                logger.log(event)
                processed_count += 1

                if args.count and processed_count >= args.count:
                    break

    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user (Ctrl+C).")
    except PermissionError as pe:
        print(f"\n[ERROR] Permission Denied: {pe}", file=sys.stderr)
        return 1
    except FileNotFoundError as fe:
        print(f"\n[ERROR] File Error: {fe}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"\n[ERROR] Unexpected error: {exc}", file=sys.stderr)
        return 1

    elapsed = max(time.time() - start_time, 0.0001)
    rate = processed_count / elapsed

    print("-" * 60)
    print(f"[+] Finished: Processed {processed_count} packets in {elapsed:.2f}s ({rate:.1f} pkts/s)")
    print(f"[+] Output saved to: {args.output}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
