"""Script to generate synthetic test PCAPs for assignment 2.

Covers the 14 mandatory test cases of the Decoder / Preprocessor / Flow Tracker
assignment. Every packet gets an explicit, deterministic timestamp so that
timeout and statistics test cases are reproducible; ``wrpcap``/``PcapReader``
preserve ``pkt.time``, which makes PCAP replay deterministic.

Usage:
    python tests/generate_bt2_test_pcaps.py [case_name ...]
"""

import os
import struct
import sys

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, wrpcap

# Deterministic capture start time for every assignment 2 case.
BT2_T0 = 1700000000.0


def _at(packet, offset: float):
    """Stamp a packet with a deterministic timestamp (BT2_T0 + offset)."""
    packet.time = BT2_T0 + offset
    return packet


def build_cases():
    """Build every assignment 2 test case as {case_name: [packets]}."""
    cases = {}

    # T01: percent-encoded HTTP URL.
    t01 = b"GET /search?q=%27%20OR%201%3D1&lang=en HTTP/1.1\r\nHost: ids.local\r\n\r\n"
    cases["bt2_t01_http_url_decode"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA") / Raw(t01), 0.0)
    ]

    # T02: HTML entity decoding in a text/html response body.
    t02_body = b"<p>Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome</p>"
    t02 = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(t02_body)).encode() + b"\r\n\r\n" + t02_body
    )
    cases["bt2_t02_html_entity"] = [
        _at(IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=52000, flags="PA") / Raw(t02), 0.0)
    ]

    # T03: SMTP DATA phase with MIME base64 and quoted-printable bodies.
    t03_base64 = (
        b"From: sender@uit.edu.vn\r\n"
        b"To: rcpt@uit.edu.vn\r\n"
        b"Subject: =?utf-8?B?VMOhaSBraG9hbg==?=\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgbWVzc2FnZS4="
    )
    t03_qp = (
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n"
        b"H=E1=BB=87 th=E1=BB=91ng IDS =C4=91ang ho=E1=BA=A1t =C4=91=E1=BB=99ng."
    )
    cases["bt2_t03_smtp_mime"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.25") / TCP(sport=45000, dport=25, flags="PA") / Raw(t03_base64), 0.0),
        _at(IP(src="10.0.0.10", dst="10.0.0.25") / TCP(sport=45000, dport=25, flags="PA") / Raw(t03_qp), 0.1),
    ]

    # T04: invalid UTF-8 body + unknown-protocol binary payload.
    t04_body = b"\xff\xfe\xfa invalid \x80"
    t04 = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: ids.local\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(t04_body)).encode() + b"\r\n\r\n" + t04_body
    )
    cases["bt2_t04_invalid_bytes"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA") / Raw(t04), 0.0),
        _at(
            IP(src="10.0.0.11", dst="10.0.0.21")
            / TCP(sport=61000, dport=9999, flags="PA")
            / Raw(b"\x99\x88\x77\x66\x55\x44custom protocol data"),
            0.1,
        ),
    ]

    # T05: normalization of URI path, HTTP header names, Host and DNS names.
    t05 = (
        b"GET //admin//./stats/%2e%2e/secret?q=%2f HTTP/1.1\r\n"
        b"hOSt: IDS.SECURITY.LAB:8080\r\n"
        b"content-TYPE: text/plain\r\n"
        b"\r\n"
    )
    cases["bt2_t05_normalization"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA") / Raw(t05), 0.0),
        _at(
            IP(src="10.0.0.10", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(id=0x4242, rd=1, qd=DNSQR(qname="PORTAL.UIT.EDU.VN.", qtype="A")),
            0.1,
        ),
    ]

    # T06: missing network layer (ARP) and unsupported protocol payload.
    t06_arp = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff")
        / ARP(op=1, psrc="10.0.0.30", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.31")
    )
    t06_udp = (
        Ether(dst="aa:bb:cc:dd:ee:01", src="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.30", dst="10.0.0.31")
        / UDP(sport=40000, dport=40001)
        / Raw(b"\x99\x88\x77\x66binary")
    )
    cases["bt2_t06_missing_field"] = [_at(t06_arp, 0.0), _at(t06_udp, 0.1)]

    # T07: TCP three-way handshake tracked as one flow.
    cases["bt2_t07_tcp_handshake"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=51234, dport=80, flags="S", seq=1000), 0.0),
        _at(IP(src="10.0.0.1", dst="10.0.0.10") / TCP(sport=80, dport=51234, flags="SA", seq=5000, ack=1001), 0.001),
        _at(IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=51234, dport=80, flags="A", seq=1001, ack=5001), 0.002),
    ]

    # T08: bidirectional HTTP request/response on one flow.
    t08_request = b"GET /ping HTTP/1.1\r\nHost: ids.local\r\n\r\n"
    t08_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    cases["bt2_t08_bidirectional"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA") / Raw(t08_request), 0.0),
        _at(IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=52000, flags="PA") / Raw(t08_response), 0.01),
    ]

    # T09: graceful FIN close and a RST close.
    cases["bt2_t09_tcp_close"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.30") / TCP(sport=51001, dport=80, flags="S", seq=1000), 0.0),
        _at(IP(src="10.0.0.30", dst="10.0.0.10") / TCP(sport=80, dport=51001, flags="SA", seq=5000, ack=1001), 0.1),
        _at(IP(src="10.0.0.10", dst="10.0.0.30") / TCP(sport=51001, dport=80, flags="A", seq=1001, ack=5001), 0.2),
        _at(IP(src="10.0.0.10", dst="10.0.0.30") / TCP(sport=51001, dport=80, flags="FA", seq=1001, ack=5001), 0.3),
        _at(IP(src="10.0.0.30", dst="10.0.0.10") / TCP(sport=80, dport=51001, flags="A", seq=5001, ack=1002), 0.4),
        _at(IP(src="10.0.0.30", dst="10.0.0.10") / TCP(sport=80, dport=51001, flags="FA", seq=5001, ack=1002), 0.5),
        _at(IP(src="10.0.0.10", dst="10.0.0.30") / TCP(sport=51002, dport=8080, flags="S", seq=2000), 0.6),
        _at(IP(src="10.0.0.10", dst="10.0.0.30") / TCP(sport=51002, dport=8080, flags="R", seq=2001), 0.7),
    ]

    # T10: UDP DNS query/response tracked as one flow.
    cases["bt2_t10_udp_dns"] = [
        _at(
            IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(id=0x1337, rd=1, qd=DNSQR(qname="portal.uit.edu.vn", qtype="A")),
            0.0,
        ),
        _at(
            IP(src="8.8.8.8", dst="192.168.1.100")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=0x1337,
                qr=1,
                aa=1,
                qd=DNSQR(qname="portal.uit.edu.vn", qtype="A"),
                an=DNSRR(rrname="portal.uit.edu.vn", type="A", rdata="118.69.123.45", ttl=300),
            ),
            0.005,
        ),
    ]

    # T11: three concurrent flows interleaved in time.
    t11_flows = [
        ("10.0.0.10", "10.0.0.20", 52000, 80, "/f1"),
        ("10.0.0.11", "10.0.0.20", 52001, 80, "/f2"),
        ("10.0.0.10", "10.0.0.30", 52002, 443, "/f3"),
    ]
    t11_packets = []
    offset = 0.0
    for round_index in range(2):
        for src, dst, sport, dport, path in t11_flows:
            suffix = b"" if round_index == 0 else b"b"
            payload = b"GET " + path.encode() + suffix + b" HTTP/1.1\r\nHost: a\r\n\r\n"
            t11_packets.append(
                _at(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(payload), offset)
            )
            offset += 0.01
    cases["bt2_t11_concurrent_flows"] = t11_packets

    # T12: TCP idle timeout (flow 1 goes silent for 30s).
    cases["bt2_t12_idle_timeout"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="S", seq=1000), 0.0),
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="A", seq=1001), 0.01),
        _at(IP(src="10.0.0.11", dst="10.0.0.20") / TCP(sport=53000, dport=8080, flags="S", seq=2000), 30.0),
    ]

    # T13: per-flow statistics over a complete connection lifecycle.
    t13_request = b"GET /stats HTTP/1.1\r\nHost: x\r\n\r\n"
    t13_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    cases["bt2_t13_statistics"] = [
        _at(IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=40000, dport=80, flags="S", seq=1000), 0.0),
        _at(IP(src="10.1.1.2", dst="10.1.1.1") / TCP(sport=80, dport=40000, flags="SA", seq=5000, ack=1001), 0.1),
        _at(IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=40000, dport=80, flags="A", seq=1001, ack=5001), 0.2),
        _at(
            IP(src="10.1.1.1", dst="10.1.1.2")
            / TCP(sport=40000, dport=80, flags="PA", seq=1001, ack=5001)
            / Raw(t13_request),
            0.3,
        ),
        _at(
            IP(src="10.1.1.2", dst="10.1.1.1")
            / TCP(sport=80, dport=40000, flags="PA", seq=5001, ack=1001 + len(t13_request))
            / Raw(t13_response),
            0.4,
        ),
        _at(IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=40000, dport=80, flags="FA", seq=1001, ack=5001), 0.5),
        _at(IP(src="10.1.1.2", dst="10.1.1.1") / TCP(sport=80, dport=40000, flags="A", seq=5001, ack=1002), 0.6),
        _at(IP(src="10.1.1.2", dst="10.1.1.1") / TCP(sport=80, dport=40000, flags="FA", seq=5001, ack=1002), 0.7),
    ]

    # T14: malformed events (declared length mismatch, no transport layer).
    cases["bt2_t14_malformed_event"] = [
        _at(IP(src="10.0.0.1", dst="10.0.0.2", len=100) / TCP(sport=80, dport=80), 0.0),
        _at(IP(src="10.0.0.2", dst="10.0.0.1") / Raw(b"\x00\x01\x02"), 0.1),
    ]

    return cases


def generate_cases(base_dir: str = "TEST", only=None):
    """Write every test PCAP below ``base_dir`` (optionally a subset)."""
    for case_name, packets in build_cases().items():
        if only and case_name not in only:
            continue

        case_dir = os.path.join(base_dir, case_name)
        os.makedirs(case_dir, exist_ok=True)
        pcap_path = os.path.join(case_dir, "test.pcap")
        wrpcap(pcap_path, packets)

        if case_name == "bt2_t14_malformed_event":
            # Cut the last pcap record short so the final packet is unreadable
            # while the first one stays intact.
            trunc_path = os.path.join(case_dir, "truncated.pcap")
            with open(pcap_path, "rb") as handle:
                data = handle.read()
            offset = 24
            last = offset
            included = 0
            while offset + 16 <= len(data):
                included = struct.unpack("<I", data[offset + 8:offset + 12])[0]
                last = offset
                offset += 16 + included
            truncated = data[: last + 16 + min(included, 8)]
            with open(trunc_path, "wb") as handle:
                handle.write(truncated)
            os.remove(pcap_path)
            pcap_path = trunc_path

        print(f"[+] Generated {pcap_path} ({len(packets)} packets)")


if __name__ == "__main__":
    generate_cases(only=sys.argv[1:] or None)
