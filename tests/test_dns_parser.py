"""Unit tests for parsers/application/dns.py."""

import unittest
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

from parsers.application.dns import DnsParser


class TestDnsParser(unittest.TestCase):
    def test_dns_query(self):
        pkt = IP() / UDP(sport=53535, dport=53) / DNS(id=0xAAAA, rd=1, qd=DNSQR(qname="uit.edu.vn", qtype="A"))
        app, errors = DnsParser.parse(pkt)

        self.assertIsNotNone(app)
        self.assertEqual(errors, [])
        self.assertEqual(app.protocol, "DNS")
        self.assertEqual(app.type, "query")
        self.assertEqual(app.details["transaction_id"], 0xAAAA)
        self.assertEqual(app.details["qr"], 0)
        self.assertEqual(len(app.details["queries"]), 1)
        self.assertEqual(app.details["queries"][0]["name"], "uit.edu.vn")
        self.assertEqual(app.details["queries"][0]["type"], "A")
        self.assertEqual(app.details["answers"], [])

    def test_dns_response_with_answers(self):
        pkt = (
            IP()
            / UDP(sport=53, dport=53535)
            / DNS(
                id=0xAAAA,
                qr=1,
                aa=1,
                qd=DNSQR(qname="uit.edu.vn", qtype="A"),
                an=DNSRR(rrname="uit.edu.vn", type="A", rdata="118.69.123.45", ttl=3600),
            )
        )
        app, errors = DnsParser.parse(pkt)

        self.assertIsNotNone(app)
        self.assertEqual(app.protocol, "DNS")
        self.assertEqual(app.type, "response")
        self.assertEqual(app.details["qr"], 1)
        self.assertEqual(len(app.details["answers"]), 1)
        ans = app.details["answers"][0]
        self.assertEqual(ans["name"], "uit.edu.vn")
        self.assertEqual(ans["type"], "A")
        self.assertEqual(ans["rdata"], "118.69.123.45")
        self.assertEqual(ans["ttl"], 3600)

    def test_dns_parse_from_raw_bytes(self):
        raw_dns = bytes(
            DNS(
                id=0xBBBB,
                qr=1,
                qd=DNSQR(qname="google.com", qtype="A"),
                an=DNSRR(rrname="google.com", type="A", rdata="142.250.190.46", ttl=300),
            )
        )
        app, errors = DnsParser.parse(raw_dns)

        self.assertIsNotNone(app)
        self.assertEqual(app.type, "response")
        self.assertEqual(app.details["transaction_id"], 0xBBBB)
        self.assertEqual(len(app.details["answers"]), 1)
        self.assertEqual(app.details["answers"][0]["rdata"], "142.250.190.46")

    def test_non_dns_bytes(self):
        app, errors = DnsParser.parse(b"NOT_A_DNS_PACKET")
        # Either None or invalid
        self.assertTrue(app is None or len(app.details["queries"]) == 0)


if __name__ == "__main__":
    unittest.main()
