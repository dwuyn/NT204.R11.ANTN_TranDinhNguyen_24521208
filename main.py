#!/usr/bin/env python3
"""Main CLI entrypoint for the IDS Capture, Decoder, Preprocessor & Flow Tracker.

Supports:
  - Live capture from interface:   python main.py --interface eth0
  - Import from PCAP file:          python main.py --pcap traffic.pcap
  - Saving output to JSON Lines:    python main.py --pcap traffic.pcap --output output.jsonl
  - Flow records to JSON Lines:     python main.py --pcap traffic.pcap --flows-output flows.jsonl
  - Packet count limit:             python main.py --interface eth0 --count 100
  - JSON configuration file:        python main.py --pcap traffic.pcap --config config.json
  - Overriding timeouts/limits:     python main.py --pcap traffic.pcap --tcp-timeout 5 --drop-invalid
"""

import argparse
import sys
import time

from capture.capturer import PacketCapture
from config import apply_cli_overrides, load_config
from flow.models import Flow
from pipeline.engine import IDSEngine
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

    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to a JSON configuration file (decoder/preprocessor/flow/pipeline sections)",
    )
    parser.add_argument(
        "--flows-output",
        type=str,
        default="flows.jsonl",
        help="Path to the flow records JSON Lines file (default: flows.jsonl)",
    )
    parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=None,
        help="TCP flow idle timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--udp-timeout",
        type=float,
        default=None,
        help="UDP flow idle timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--max-active-flows",
        type=int,
        default=None,
        help="Maximum number of concurrently tracked flows (default: 10000)",
    )
    parser.add_argument(
        "--max-decode-size",
        type=int,
        default=None,
        help="Payload size limit in bytes above which decoding is skipped (default: 1048576)",
    )
    parser.add_argument(
        "--drop-invalid",
        action="store_true",
        help="Drop (do not forward) events the preprocessor classifies as invalid",
    )
    parser.add_argument(
        "--exclude-unknown",
        action="store_true",
        help="Do not emit events for packets with an unknown application protocol",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        config = apply_cli_overrides(load_config(args.config), args)
    except ValueError as exc:
        print(f"[ERROR] Invalid config: {exc}", file=sys.stderr)
        return 2

    console_summary = not args.quiet
    processed_count = 0
    start_time = time.time()

    print("=" * 60)
    print("  IDS Capture, Decoder, Preprocessor & Flow Tracker")
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
    print(f"[*] Writing flow records to: {args.flows_output}")
    print(
        f"[*] Flow tracker: tcp_timeout={config.flow.tcp_idle_timeout}s "
        f"udp_timeout={config.flow.udp_idle_timeout}s "
        f"max_active_flows={config.flow.max_active_flows}"
    )
    print(
        f"[*] Decoder: max_decode_size={config.decoder.max_decode_size} bytes "
        f"decode_html_entities={config.decoder.decode_html_entities}"
    )
    print("-" * 60)

    flows_logger = JsonLinesLogger(filepath=args.flows_output, console_summary=False)

    def on_flow_closed(flow: Flow) -> None:
        flows_logger.log(flow)
        if console_summary:
            print(
                f"[FLOW] {flow.flow_id} state={flow.state} pkts={flow.packet_count} "
                f"bytes={flow.byte_count} reason={flow.close_reason}"
            )

    engine = IDSEngine(config, on_flow_closed=on_flow_closed)

    try:
        with JsonLinesLogger(filepath=args.output, console_summary=console_summary) as logger:
            for captured in stream:
                event = engine.process_packet(captured)
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
    finally:
        flows_flushed = engine.finalize()
        flows_logger.close()

    elapsed = max(time.time() - start_time, 0.0001)
    rate = processed_count / elapsed
    stats = engine.stats()
    reasons = stats["closed_by_reason"]

    print("-" * 60)
    print(f"[+] Finished: Processed {processed_count} packets in {elapsed:.2f}s ({rate:.1f} pkts/s)")
    print(f"[+] Output saved to: {args.output}")
    print(f"[+] Flow records saved to: {args.flows_output}")
    print(
        f"[+] Flows: created={stats['flows_created']} closed={stats['flows_closed']} "
        f"active_flushed={flows_flushed}"
    )
    print(
        f"[+] Flow close reasons: fin={reasons['fin']} rst={reasons['rst']} "
        f"timeout={reasons['timeout']} overflow={reasons['overflow']} "
        f"end_of_capture={reasons['end_of_capture']}"
    )
    print(f"[+] Dropped events (preprocessor): {stats['packets_dropped']}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
