"""Script to generate synthetic test PCAPs for all 12 mandatory test cases."""

import os
import sys

from scapy.all import DNS, DNSQR, DNSRR, IP, Raw, TCP, UDP, wrpcap


def generate_all_cases(base_dir: str = "TEST", only=None):
    cases = {}

    # Case 01: TCP Handshake (SYN, SYN-ACK, ACK)
    c01_p1 = IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=51234, dport=80, flags="S", seq=1000)
    c01_p2 = IP(src="10.0.0.1", dst="10.0.0.10") / TCP(sport=80, dport=51234, flags="SA", seq=5000, ack=1001)
    c01_p3 = IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=51234, dport=80, flags="A", seq=1001, ack=5001)
    cases["test_01_tcp_handshake"] = [c01_p1, c01_p2, c01_p3]

    # Case 02: TCP Data with Payload
    c02_data = b"User data stream payload over TCP connection"
    c02_p1 = IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=51234, dport=80, flags="PA", seq=1001, ack=5001) / Raw(c02_data)
    cases["test_02_tcp_data"] = [c02_p1]

    # Case 03: UDP
    c03_data = b"UDP datagram payload content for IDS inspection"
    c03_p1 = IP(src="192.168.1.100", dst="192.168.1.200") / UDP(sport=12345, dport=54321) / Raw(c03_data)
    cases["test_03_udp"] = [c03_p1]

    # Case 04: HTTP GET Request
    c04_http = b"GET /api/v1/network/stats HTTP/1.1\r\nHost: ids.security.lab\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
    c04_p1 = IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=52000, dport=80, flags="PA") / Raw(c04_http)
    cases["test_04_http_get"] = [c04_p1]

    # Case 05: HTTP POST Request with Body
    c05_body = b"username=admin&password=secretPassword123"
    c05_http = (
        b"POST /api/login HTTP/1.1\r\n"
        b"Host: ids.security.lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(c05_body)).encode() + b"\r\n\r\n" + c05_body
    )
    c05_p1 = IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=52000, dport=80, flags="PA") / Raw(c05_http)
    cases["test_05_http_post"] = [c05_p1]

    # Case 06: HTTP Response
    c06_body = b"<html><body>Access Granted</body></html>"
    c06_http = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(c06_body)).encode() + b"\r\n\r\n" + c06_body
    )
    c06_p1 = IP(src="93.184.216.34", dst="192.168.1.100") / TCP(sport=80, dport=52000, flags="PA") / Raw(c06_http)
    cases["test_06_http_response"] = [c06_p1]

    # Case 07: DNS Query
    c07_p1 = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(
        id=0x1337, qr=0, rd=1, qd=DNSQR(qname="portal.uit.edu.vn", qtype="A")
    )
    cases["test_07_dns_query"] = [c07_p1]

    # Case 08: DNS Response
    c08_p1 = IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=53000) / DNS(
        id=0x1337,
        qr=1,
        aa=1,
        qd=DNSQR(qname="portal.uit.edu.vn", qtype="A"),
        an=DNSRR(rrname="portal.uit.edu.vn", type="A", rdata="118.69.123.45", ttl=300),
    )
    cases["test_08_dns_response"] = [c08_p1]

    # Case 09: SMTP Commands
    c09_p1 = IP(src="192.168.1.100", dst="10.0.0.25") / TCP(sport=45000, dport=25, flags="PA") / Raw(b"EHLO client.ids.local\r\n")
    c09_p2 = IP(src="192.168.1.100", dst="10.0.0.25") / TCP(sport=45000, dport=25, flags="PA") / Raw(b"MAIL FROM:<student@uit.edu.vn>\r\n")
    c09_p3 = IP(src="192.168.1.100", dst="10.0.0.25") / TCP(sport=45000, dport=25, flags="PA") / Raw(b"RCPT TO:<instructor@uit.edu.vn>\r\n")
    cases["test_09_smtp_command"] = [c09_p1, c09_p2, c09_p3]

    # Case 10: SMTP Responses
    c10_p1 = IP(src="10.0.0.25", dst="192.168.1.100") / TCP(sport=25, dport=45000, flags="PA") / Raw(b"220 mail.uit.edu.vn ESMTP Ready\r\n")
    c10_p2 = IP(src="10.0.0.25", dst="192.168.1.100") / TCP(sport=25, dport=45000, flags="PA") / Raw(b"250 2.1.0 Ok sender accepted\r\n")
    c10_p3 = IP(src="10.0.0.25", dst="192.168.1.100") / TCP(sport=25, dport=45000, flags="PA") / Raw(b"354 End data with <CR><LF>.<CR><LF>\r\n")
    cases["test_10_smtp_response"] = [c10_p1, c10_p2, c10_p3]

    # Case 11: Unknown Protocol
    c11_p1 = IP(src="10.0.0.1", dst="10.0.0.2", proto=253) / Raw(b"\xde\xad\xbe\xef\x01\x02\x03\x04")
    c11_p2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=61111, dport=62222, flags="PA") / Raw(b"\xaa\xbb\xcc\xddCustomProtocol")
    cases["test_11_unknown_protocol"] = [c11_p1, c11_p2]

    # Case 12: Malformed Packet
    # Packet with declared length 100 but actual payload truncated, and raw corrupted bytes
    c12_p1 = IP(src="10.0.0.1", dst="10.0.0.2", len=100) / TCP(sport=80, dport=80)
    c12_p2 = IP(src="10.0.0.2", dst="10.0.0.1") / Raw(b"\x00\x01\x02")
    cases["test_12_malformed_packet"] = [c12_p1, c12_p2]

    # Case 13 (bonus): Application protocol detection on non-standard ports.
    # DNS is wrapped in Raw() so the detector cannot rely on a Scapy DNS layer.
    c13_p1 = IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=51000, dport=9000, flags="PA") / Raw(
        b"GET /nonstandard HTTP/1.1\r\nHost: nonstandard.local\r\n\r\n"
    )
    c13_p2 = IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=51000, dport=8025, flags="PA") / Raw(
        b"EHLO client.nonstandard.local\r\n"
    )
    c13_dns = bytes(DNS(id=0x2222, rd=1, qd=DNSQR(qname="nonstandard.example.com", qtype="A")))
    c13_p3 = IP(src="10.0.0.10", dst="8.8.8.8") / UDP(sport=51000, dport=53535) / Raw(c13_dns)
    cases["test_13_non_standard_port"] = [c13_p1, c13_p2, c13_p3]

    for case_name, pkts in cases.items():
        if only and case_name not in only:
            continue
        case_dir = os.path.join(base_dir, case_name)
        os.makedirs(case_dir, exist_ok=True)
        pcap_path = os.path.join(case_dir, "test.pcap")
        wrpcap(pcap_path, pkts)
        print(f"[+] Generated {pcap_path} ({len(pkts)} packets)")


if __name__ == "__main__":
    generate_all_cases(only=sys.argv[1:] or None)
