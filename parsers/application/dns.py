"""DNS Application Protocol Parser.

Parses DNS queries (domain names, query types) and DNS responses (answer records,
IP addresses, TTLs) from either Scapy DNS layers or raw DNS wire-format bytes.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

from scapy.all import Packet
from scapy.layers.dns import DNS, DNSQR, DNSRR

from parsers.models import ApplicationLayer

DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsParser:
    """Parses DNS queries and responses into normalized structures."""

    @staticmethod
    def _clean_str(val: Any) -> str:
        """Decode and clean domain names or rdata values."""
        if val is None:
            return ""
        if isinstance(val, bytes):
            try:
                s = val.decode("utf-8")
            except UnicodeDecodeError:
                s = val.decode("latin-1", errors="replace")
        else:
            s = str(val)
        return s.rstrip(".")

    @classmethod
    def _get_qtype_name(cls, qtype: Any) -> str:
        """Map DNS query/RR type integer to standard string representation."""
        try:
            val = int(qtype)
            return DNS_QTYPES.get(val, f"TYPE_{val}")
        except (ValueError, TypeError):
            return str(qtype).upper()

    @classmethod
    def parse(cls, target: Union[Packet, bytes]) -> Tuple[Optional[ApplicationLayer], List[str]]:
        """Parse DNS information from a Scapy packet or raw wire bytes.

        Args:
            target: Either a Scapy Packet or raw bytes from transport payload.

        Returns:
            Tuple of (ApplicationLayer or None, list of errors).
        """
        errors: List[str] = []
        dns: Optional[DNS] = None

        if isinstance(target, Packet):
            if target.haslayer(DNS):
                dns = target[DNS]
            else:
                try:
                    payload = bytes(target.payload.payload)
                    if payload:
                        dns = DNS(payload)
                except Exception:
                    pass
        elif isinstance(target, bytes) and target:
            try:
                dns = DNS(target)
            except Exception as exc:
                errors.append(f"DNS decode error: {str(exc)}")
                return None, errors

        if not dns:
            return None, errors

        try:
            tx_id = int(getattr(dns, "id", 0))
            qr = int(getattr(dns, "qr", 0))
            opcode_val = int(getattr(dns, "opcode", 0))
            opcode = "QUERY" if opcode_val == 0 else f"OPCODE_{opcode_val}"
            rcode_val = int(getattr(dns, "rcode", 0))
            rcode = DNS_RCODES.get(rcode_val, f"RCODE_{rcode_val}")

            # Parse Queries (qd)
            queries: List[Dict[str, Any]] = []
            qdcount = int(getattr(dns, "qdcount", 0))
            for i in range(1, qdcount + 1):
                try:
                    qd = dns.getlayer(DNSQR, i)
                    if qd:
                        qname = cls._clean_str(getattr(qd, "qname", ""))
                        if qname:
                            qtype = cls._get_qtype_name(getattr(qd, "qtype", 1))
                            queries.append({"name": qname, "type": qtype})
                except Exception:
                    pass

            # Fallback if getlayer didn't catch qd
            if not queries and isinstance(dns.qd, DNSQR):
                qname = cls._clean_str(getattr(dns.qd, "qname", ""))
                if qname:
                    qtype = cls._get_qtype_name(getattr(dns.qd, "qtype", 1))
                    queries.append({"name": qname, "type": qtype})

            # Parse Answers (an)
            answers: List[Dict[str, Any]] = []
            ancount = int(getattr(dns, "ancount", 0))
            for i in range(1, ancount + 1):
                try:
                    an = dns.getlayer(DNSRR, i)
                    if an:
                        name = cls._clean_str(getattr(an, "rrname", ""))
                        rrtype = cls._get_qtype_name(getattr(an, "type", 1))
                        rdata = cls._clean_str(getattr(an, "rdata", ""))
                        ttl = int(getattr(an, "ttl", 0))
                        answers.append({
                            "name": name,
                            "type": rrtype,
                            "rdata": rdata,
                            "ttl": ttl,
                        })
                except Exception:
                    pass

            # Validate that this is a meaningful DNS message
            if not queries and not answers and qr == 0:
                return None, errors

            event_type = "response" if qr == 1 else "query"
            details: Dict[str, Any] = {
                "transaction_id": tx_id,
                "qr": qr,
                "opcode": opcode,
                "rcode": rcode,
                "queries": queries,
                "answers": answers,
            }

            return ApplicationLayer(protocol="DNS", type=event_type, details=details), errors

        except Exception as exc:
            errors.append(f"DNS parsing error: {str(exc)}")
            return None, errors
