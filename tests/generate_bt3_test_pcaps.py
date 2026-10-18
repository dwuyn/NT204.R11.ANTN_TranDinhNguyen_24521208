"""Script to generate synthetic test artifacts for assignment 3 (Core Engine).

Writes, per mandatory BT3 test case:
  - ``test.rules``: rule file exercising the case scenario.
  - ``test.pcap`` : traffic for engine-kind cases (rule loading cases only get
    the rule file).

Every packet gets an explicit deterministic timestamp (``BT3_T0`` + offset) so
detection timestamps are reproducible.

Usage:
    python tests/generate_bt3_test_pcaps.py [case_name ...]
"""

import os
import sys

from scapy.all import IP, Raw, TCP, UDP, wrpcap

# Deterministic capture start time for every assignment 3 case.
BT3_T0 = 1700000000.0

RULES = {
    # T01: rule loader - mix of valid / invalid / unsupported lines.
    "bt3_t01_rule_loader": """\
# Comment line, ignored by the loader.

alert tcp any any -> 10.0.0.20 80 (msg:"HTTP GET"; content:"GET"; nocase; content:"/index"; sid:1100001; rev:2;)
alert tcp any any -> any 443 (msg:"TLS hello"; content:"|16 03|"; sid:1100002; rev:1;)
alert udp any any -> any 53 (msg:"DNS query"; content:"|01 00|"; offset:2; depth:2; sid:1100003; rev:1;)
alert tcp any any -> any 22 (content:"SSH"; sid:1100004;)
alert tcp any any -> any 80 (msg:"pcre test"; pcre:"/foo/"; sid:1100005;)
""",
    # T02: invalid rules are reported with reasons, load keeps going.
    "bt3_t02_invalid_rule": """\
alert tcp any any -> any 80 (msg:"missing sid";)
alert tcp any any => any 80 (msg:"bad direction"; sid:1100011;)
alert tcp any any -> any abc (msg:"bad port"; sid:1100012;)
""",
    # T03: out-of-scope constructs become unsupported, not crashes.
    "bt3_t03_unsupported_keyword": """\
alert tcp any any -> any 80 (msg:"pcre"; pcre:"/etc/passwd/"; sid:1100013;)
drop tcp any any -> any 80 (msg:"drop action"; sid:1100014;)
alert icmp any any -> any any (msg:"icmp echo"; sid:1100015;)
alert tcp !192.168.1.1 any -> any 80 (msg:"negated src"; sid:1100016;)
""",
    # T04: header parsing - CIDR, port range, bidirectional operator.
    "bt3_t04_header_parse": """\
alert tcp 192.168.1.0/24 1024:2048 -> 10.0.0.5 80 (msg:"cidr range"; sid:1100021; rev:1;)
alert udp any any <> 8.8.8.8 53 (msg:"bidirectional dns"; sid:1100022; rev:1;)
alert tcp 172.16.0.0/12 :1024 -> any 8080 (msg:"open lower bound"; sid:1100023; rev:1;)
""",
    # T05: direction - flow:to_server vs flow:to_client.
    "bt3_t05_direction": """\
alert tcp any any -> any any (msg:"secret prefixed request field"; content:"SECRET"; flow:to_server,established; sid:1100041; rev:1;)
alert tcp any any -> any any (msg:"token in server response"; content:"TOKEN"; flow:to_client,established; sid:1100042; rev:1;)
""",
    # T06: indexer candidates - port/CIDR prefiltering.
    "bt3_t06_indexer_candidates": """\
alert tcp any any -> any 80 (msg:"http any"; content:"GET"; sid:1100031; rev:1;)
alert tcp 10.0.0.0/24 any -> 10.0.0.20 443 (msg:"tls from subnet"; content:"|16 03|"; sid:1100032; rev:1;)
alert udp any any -> any 53 (msg:"dns"; content:"|01 00|"; sid:1100033; rev:1;)
alert tcp any any -> 10.0.0.20 80:90 (msg:"web alt ports"; content:"GET"; sid:1100034; rev:1;)
""",
    # T07: header prefilter - only the rule whose header fits can fire.
    "bt3_t07_header_prefilter": """\
alert tcp any any -> 10.0.0.100 4444 (msg:"evil on service port"; content:"EVIL"; sid:1100051; rev:1;)
alert tcp any any -> any 80 (msg:"evil over http"; content:"EVIL"; sid:1100052; rev:1;)
alert udp any any -> any 53 (msg:"dns version bind attempt"; content:"version.bind"; nocase; sid:1100053; rev:1;)
""",
    # T08: flow state - established vs not_established.
    "bt3_t08_flow_state": """\
alert tcp any any -> any 80 (msg:"established client data"; content:"HELLO"; flow:to_server,established; sid:1100061; rev:1;)
alert tcp any any -> any 80 (msg:"connection not established yet"; flow:not_established; sid:1100062; rev:1;)
""",
    # T09: content nocase (ASCII) vs case-sensitive content.
    "bt3_t09_content_nocase": """\
alert tcp any any -> any 80 (msg:"admin token any case"; content:"admin"; nocase; sid:1100071; rev:1;)
alert tcp any any -> any 80 (msg:"admin token exact case"; content:"ADMIN"; sid:1100072; rev:1;)
""",
    # T10: offset/depth absolute window.
    "bt3_t10_offset_depth": """\
alert tcp any any -> any 80 (msg:"malware marker after headers"; content:"MALWARE"; offset:28; depth:7; sid:1100081; rev:1;)
alert tcp any any -> any 80 (msg:"malware marker near start"; content:"MALWARE"; offset:0; depth:10; sid:1100082; rev:1;)
""",
    # T11: distance/within relative window.
    "bt3_t11_distance_within": """\
alert tcp any any -> any 80 (msg:"commands two bytes apart"; content:"aa"; content:"bb"; distance:2; within:2; sid:1100091; rev:1;)
alert tcp any any -> any 80 (msg:"commands within one byte window"; content:"aa"; content:"bb"; distance:2; within:1; sid:1100092; rev:1;)
""",
    # T12: flags subset + dsize comparison.
    "bt3_t12_flags_dsize": """\
alert tcp any any -> any 80 (msg:"data push larger than ten bytes"; flags:PA; dsize:>10; sid:1100101; rev:1;)
alert tcp any any -> any 80 (msg:"small push data"; flags:PA; dsize:<10; sid:1100102; rev:1;)
alert tcp any any -> any 80 (msg:"connection teardown"; flags:F; dsize:0; sid:1100103; rev:1;)
""",
    # T13: multiple rules matching the same packet (multi-match).
    "bt3_t13_multi_rule_match": """\
alert tcp any any -> any 80 (msg:"http post seen"; content:"POST"; sid:1100111; rev:1;)
alert tcp any any -> any 80 (msg:"established post with data"; content:"POST"; flow:to_server,established; flags:PA; dsize:>0; sid:1100112; rev:1;)
alert tcp any any -> any 80 (msg:"login endpoint"; content:"/login"; sid:1100113; rev:1;)
""",
    # T14: detection event - full field set.
    "bt3_t14_detection_event": """\
alert tcp any any -> any 80 (msg:"Directory traversal detected"; content:"/etc/passwd"; nocase; flow:to_server,established; flags:PA; dsize:>0; classtype:attempted-admin; priority:1; sid:1100121; rev:2;)
""",
}

T05_HTTP_REQUEST = b"GET /data HTTP/1.1\r\nHost: ids.local\r\n\r\nSECRET"
T05_HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nTOKEN=abc"
T13_POST = b"POST /login HTTP/1.1\r\nHost: ids.local\r\nContent-Length: 7\r\n\r\nuser=ab"
T14_TRAVERSAL = b"GET /../etc/passwd HTTP/1.1\r\nHost: ids.local\r\n\r\n"
T10_PAYLOAD = b"GET /x HTTP/1.1\r\nHost: a\r\n\r\nMALWARE"  # MALWARE at offset 28


def _at(packet, offset: float):
    """Stamp a packet with a deterministic timestamp (BT3_T0 + offset)."""
    packet.time = BT3_T0 + offset
    return packet


def _handshake():
    """SYN, SYN-ACK, ACK for 10.0.0.10:52000 -> 10.0.0.20:80."""
    return [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="S", seq=1000), 0.0),
        _at(IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=52000, flags="SA", seq=5000, ack=1001), 0.1),
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="A", seq=1001, ack=5001), 0.2),
    ]


def build_cases():
    """Build every engine-kind case as {case_name: [packets]}."""
    cases = {}

    # T05: to_server request field vs to_client response token.
    cases["bt3_t05_direction"] = _handshake() + [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA", seq=1001, ack=5001) / Raw(T05_HTTP_REQUEST), 0.3),
        _at(IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=80, dport=52000, flags="PA", seq=5001, ack=1001 + len(T05_HTTP_REQUEST)) / Raw(T05_HTTP_RESPONSE), 0.4),
    ]

    # T07: same content, different headers - prefilter decides the winner.
    cases["bt3_t07_header_prefilter"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.50") / TCP(sport=50000, dport=80, flags="PA") / Raw(b"GET /x?q=EVIL HTTP/1.1\r\nHost: t\r\n\r\n"), 0.0),
        _at(IP(src="10.0.0.11", dst="10.0.0.100") / TCP(sport=50001, dport=4444, flags="PA") / Raw(b"EVIL COMMAND"), 0.1),
        _at(IP(src="10.0.0.12", dst="10.0.0.60") / TCP(sport=50002, dport=9999, flags="PA") / Raw(b"EVIL NOISE"), 0.2),
        _at(IP(src="10.0.0.13", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(b"version.bind"), 0.3),
    ]

    # T08: not_established fires on the SYN, established only after the handshake.
    cases["bt3_t08_flow_state"] = _handshake() + [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA", seq=1001, ack=5001) / Raw(b"HELLO ids"), 0.3),
    ]

    # T09: nocase matches mixed case, case-sensitive rule only matches exact.
    cases["bt3_t09_content_nocase"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA") / Raw(b"GET /?user=AdMiN HTTP/1.1\r\n\r\n"), 0.0),
        _at(IP(src="10.0.0.11", dst="10.0.0.20") / TCP(sport=52001, dport=80, flags="PA") / Raw(b"GET /?user=ADMIN HTTP/1.1\r\n\r\n"), 0.1),
    ]

    # T10: offset/depth window.
    cases["bt3_t10_offset_depth"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA") / Raw(T10_PAYLOAD), 0.0),
    ]

    # T11: distance/within window.
    cases["bt3_t11_distance_within"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA") / Raw(b"XXaaYYbbZZ"), 0.0),
    ]

    # T12: flags + dsize, including a FIN teardown packet with empty payload.
    cases["bt3_t12_flags_dsize"] = [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA", seq=1000) / Raw(b"A" * 20), 0.0),
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="F", seq=1020), 0.1),
    ]

    # T13: one packet matching three rules -> three detections.
    cases["bt3_t13_multi_rule_match"] = _handshake() + [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA", seq=1001, ack=5001) / Raw(T13_POST), 0.3),
    ]

    # T14: full detection event fields.
    cases["bt3_t14_detection_event"] = _handshake() + [
        _at(IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=52000, dport=80, flags="PA", seq=1001, ack=5001) / Raw(T14_TRAVERSAL), 0.3),
    ]

    return cases


def generate_cases(base_dir: str = "TEST", only=None):
    """Write every BT3 test artifact below ``base_dir`` (optionally a subset).

    Assignment 3 cases live under ``TEST/BT3/`` with the ``bt3_`` prefix
    stripped from the directory name (``bt3_t01_rule_loader`` ->
    ``TEST/BT3/t01_rule_loader``).
    """
    cases = build_cases()
    for case_name in sorted(set(RULES) | set(cases)):
        if only and case_name not in only:
            continue

        short_name = case_name[len("bt3_"):] if case_name.startswith("bt3_") else case_name
        case_dir = os.path.join(base_dir, "BT3", short_name)
        os.makedirs(case_dir, exist_ok=True)

        rules_path = os.path.join(case_dir, "test.rules")
        with open(rules_path, "w", encoding="utf-8") as handle:
            handle.write(RULES[case_name])
        print(f"[+] Generated {rules_path}")

        if case_name in cases:
            packets = cases[case_name]
            pcap_path = os.path.join(case_dir, "test.pcap")
            wrpcap(pcap_path, packets)
            print(f"[+] Generated {pcap_path} ({len(packets)} packets)")


if __name__ == "__main__":
    generate_cases(only=sys.argv[1:] or None)
