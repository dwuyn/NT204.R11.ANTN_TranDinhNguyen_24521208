"""Runner to execute a test case, generate output.jsonl, and generate report.md.

Each test case has a registered set of assertions (EXPECTATIONS). A case only
reports PASS when every expected JSON subset matches at least one parsed event,
the minimum event count is reached, and (when configured) the minimum number of
flow records is reached and every flow assertion matches.

Registered keys per case:
  min_events   minimum number of parsed events.
  checks       list of JSON subsets; each subset must match at least one event.
  pcap         optional pcap filename (default test.pcap).
  min_flows    optional minimum number of flow records.
  flow_checks  optional list of JSON subsets matched against flow records.
  args         optional extra CLI arguments passed to main.py.
  description  test objective (required to be included in `run_case.py all`).
  criteria     verification criteria (required for `run_case.py all`).

Usage:
  python tests/run_case.py <case_name> "<description>" "<criteria>"
  python tests/run_case.py all
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

# Expected result per test case directory.
#   min_events: minimum number of parsed events.
#   checks: list of JSON subsets; each subset must match at least one event.
#   pcap: optional pcap filename (default test.pcap).
#   min_flows / flow_checks: optional flow record assertions.
#   args: optional extra CLI arguments for main.py.
#   description / criteria: required for `run_case.py all`.
EXPECTATIONS = {
    "test_01_tcp_handshake": {
        "min_events": 3,
        "checks": [
            {"transport": {"handshake": "SYN"}},
            {"transport": {"handshake": "SYN-ACK"}},
            {"transport": {"handshake": "ACK"}},
        ],
    },
    "test_02_tcp_data": {
        "min_events": 1,
        "checks": [
            {"transport": {"layer": "TCP", "payload_len": 44}},
            {"application": {"protocol": "UNKNOWN"}},
        ],
    },
    "test_03_udp": {
        "min_events": 1,
        "checks": [{"transport": {"layer": "UDP", "payload_len": 47}}],
    },
    "test_04_http_get": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "request",
                    "details": {
                        "method": "GET",
                        "uri": "/api/v1/network/stats",
                        "version": "HTTP/1.1",
                    },
                }
            }
        ],
    },
    "test_05_http_post": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "request",
                    "details": {
                        "method": "POST",
                        "uri": "/api/login",
                        "body": "username=admin&password=secretPassword123",
                    },
                }
            }
        ],
    },
    "test_06_http_response": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "type": "response",
                    "details": {"status_code": 200, "reason": "OK"},
                }
            }
        ],
    },
    "test_07_dns_query": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "DNS",
                    "type": "query",
                    "details": {"queries": [{"name": "portal.uit.edu.vn", "type": "A"}]},
                }
            }
        ],
    },
    "test_08_dns_response": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "protocol": "DNS",
                    "type": "response",
                    "details": {
                        "answers": [
                            {
                                "name": "portal.uit.edu.vn",
                                "type": "A",
                                "rdata": "118.69.123.45",
                            }
                        ]
                    },
                }
            }
        ],
    },
    "test_09_smtp_command": {
        "min_events": 3,
        "checks": [
            {"application": {"protocol": "SMTP", "details": {"command": "EHLO"}}},
            {"application": {"protocol": "SMTP", "details": {"command": "MAIL FROM"}}},
            {"application": {"protocol": "SMTP", "details": {"command": "RCPT TO"}}},
        ],
    },
    "test_10_smtp_response": {
        "min_events": 3,
        "checks": [
            {"application": {"protocol": "SMTP", "details": {"status_code": 220}}},
            {"application": {"protocol": "SMTP", "details": {"status_code": 250}}},
            {"application": {"protocol": "SMTP", "details": {"status_code": 354}}},
        ],
    },
    "test_11_unknown_protocol": {
        "min_events": 2,
        "checks": [
            {"application": {"protocol": "UNKNOWN"}},
            {"errors": []},
        ],
    },
    "test_12_malformed_packet": {
        "min_events": 2,
        "checks": [
            {"transport": {"handshake": "SYN"}},
            {"application": {"protocol": "UNKNOWN"}},
        ],
    },
    "test_13_non_standard_port": {
        "min_events": 3,
        "checks": [
            {
                "application": {
                    "protocol": "HTTP",
                    "details": {"method": "GET", "detection_method": "payload_signature"},
                }
            },
            {
                "application": {
                    "protocol": "SMTP",
                    "details": {"command": "EHLO", "detection_method": "payload_signature"},
                }
            },
            {
                "application": {
                    "protocol": "DNS",
                    "details": {"detection_method": "payload_signature"},
                }
            },
        ],
    },
    "test_14_truncated_pcap": {
        "pcap": "truncated.pcap",
        "min_events": 1,
        "checks": [
            {"application": {"protocol": "HTTP", "details": {"method": "GET"}}},
        ],
    },
    # ------------------------------------------------------------------
    # Assignment 2 cases (decoder, preprocessor, flow tracker)
    # ------------------------------------------------------------------
    "bt2_t01_http_url_decode": {
        "min_events": 1,
        "checks": [
            {"application": {"details": {"uri": "/search?q=%27%20OR%201%3D1&lang=en"}}},
            {
                "decode": {
                    "decode_status": "decoded",
                    "fields": {"uri_decoded": "/search?q=' OR 1=1&lang=en"},
                }
            },
            {
                "preprocess": {"preprocess_status": "valid", "processing_action": "forward"},
            },
        ],
        "min_flows": 1,
        "description": "Giải mã percent-encoding trên URI của HTTP request",
        "criteria": (
            "Event HTTP request giữ nguyên URI gốc đã mã hóa, decode.fields.uri_decoded "
            "chứa chuỗi %27%20OR%201%3D1 đã giải mã, event hợp lệ (forward) và có 1 flow TCP."
        ),
    },
    "bt2_t02_html_entity": {
        "min_events": 1,
        "checks": [
            {
                "application": {
                    "details": {
                        "body": "<p>Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome</p>"
                    }
                }
            },
            {
                "decode": {
                    "decoders": ["html_entities"],
                    "fields": {
                        "body_decoded": "<p>Hello <script>alert(1)</script> & welcome</p>",
                        "body_charset": "utf-8",
                        "body_decode_status": "ok",
                    },
                }
            },
        ],
        "description": "Giải mã HTML entity trong body của HTTP response text/html",
        "criteria": (
            "Body gốc vẫn giữ nguyên entity, decode.fields.body_decoded đã unescape "
            "&lt;script&gt; thành <script>, charset là utf-8 và body_decode_status là ok."
        ),
    },
    "bt2_t03_smtp_mime": {
        "min_events": 2,
        "checks": [
            {"application": {"protocol": "SMTP", "type": "data"}},
            {
                "decode": {
                    "fields": {
                        "mime_body_decoded": "Hello World! This is a base64 message.",
                        "content_transfer_encoding": "base64",
                    },
                    "decoders": ["base64"],
                }
            },
            {
                "decode": {
                    "fields": {
                        "mime_body_decoded": "Hệ thống IDS đang hoạt động.",
                        "content_transfer_encoding": "quoted-printable",
                    },
                    "decoders": ["quoted_printable"],
                }
            },
            {"decode": {"fields": {"headers_decoded": {"Subject": "Tái khoan"}}}},
        ],
        "min_flows": 1,
        "flow_checks": [{"application_protocol": "SMTP", "packet_count": 2}],
        "description": "Giải mã MIME base64, quoted-printable và header RFC 2047 trong SMTP DATA",
        "criteria": (
            "Hai packet MIME được nhận là SMTP data, body base64 giải mã thành "
            "'Hello World! This is a base64 message.', body quoted-printable giải mã thành "
            "'Hệ thống IDS đang hoạt động.', header Subject RFC 2047 giải mã thành 'Tái khoan', "
            "và cả hai packet thuộc cùng một flow SMTP."
        ),
    },
    "bt2_t04_invalid_bytes": {
        "min_events": 2,
        "checks": [
            {"decode": {"decode_status": "partial", "warnings": ["invalid_utf8_sequence"]}},
            {"application": {"protocol": "UNKNOWN"}, "decode": {"decode_status": "partial"}},
            {"preprocess": {"preprocess_status": "partial", "reason": "unsupported_protocol"}},
        ],
        "description": "Xử lý byte không hợp lệ UTF-8 và payload giao thức không hỗ trợ",
        "criteria": (
            "Body chứa byte lỗi UTF-8 được giải mã thay thế và gắn trạng thái partial với "
            "warning invalid_utf8_sequence, payload nhị phân lạ được nhận là UNKNOWN và "
            "preprocessor trả về partial/unsupported_protocol."
        ),
    },
    "bt2_t05_normalization": {
        "min_events": 2,
        "checks": [
            {
                "application": {
                    "details": {
                        "headers": {
                            "Content-Type": "text/plain",
                            "Host": "ids.security.lab:8080",
                        }
                    }
                }
            },
            {
                "application": {
                    "details": {
                        "uri_normalized": "/admin/secret?q=/",
                        "uri": "//admin//./stats/%2e%2e/secret?q=%2f",
                    }
                }
            },
            {"preprocess": {"normalizations": ["http_header_names", "uri_path"]}},
            {
                "application": {"details": {"queries": [{"name": "portal.uit.edu.vn"}]}},
                "preprocess": {"normalizations": ["domain_lowercase"]},
            },
        ],
        "min_flows": 2,
        "description": "Chuẩn hóa HTTP header, Host, URI path và tên miền DNS",
        "criteria": (
            "Header 'content-TYPE' thành 'Content-Type', 'hOSt' thành 'Host' với host viết "
            "thường, URI '//admin//./stats/%2e%2e/secret?q=%2f' chuẩn hóa thành "
            "'/admin/secret?q=/', QNAME 'PORTAL.UIT.EDU.VN' thành 'portal.uit.edu.vn' và "
            "preprocess.normalizations ghi nhận đúng các loại đã thay đổi."
        ),
    },
    "bt2_t06_missing_field": {
        "min_events": 2,
        "checks": [
            {
                "network": None,
                "transport": None,
                "flow": None,
                "preprocess": {
                    "preprocess_status": "invalid",
                    "reason": "missing_network_layer",
                },
            },
            {
                "application": {"protocol": "UNKNOWN"},
                "preprocess": {"preprocess_status": "partial", "reason": "unsupported_protocol"},
            },
        ],
        "min_flows": 1,
        "description": "Xử lý event thiếu tầng mạng và thiếu giao thức ứng dụng hỗ trợ",
        "criteria": (
            "Packet ARP không có network/transport layer được đánh invalid với reason "
            "missing_network_layer và không gắn flow; payload UDP lạ được đánh partial với "
            "reason unsupported_protocol nhưng vẫn được theo dõi 1 flow UDP."
        ),
    },
    "bt2_t07_tcp_handshake": {
        "min_events": 3,
        "checks": [
            {
                "transport": {"handshake": "SYN"},
                "flow": {"direction": "forward", "is_new_flow": True, "state": "HANDSHAKE"},
            },
            {"transport": {"handshake": "SYN-ACK"}, "flow": {"direction": "backward"}},
            {
                "transport": {"handshake": "ACK"},
                "flow": {
                    "state": "ESTABLISHED",
                    "flow_id": "TCP-10.0.0.10:51234-10.0.0.1:80",
                },
            },
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "state": "ESTABLISHED",
                "packet_count": 3,
                "forward": {"packet_count": 2},
                "backward": {"packet_count": 1},
                "syn_count": 2,
                "ack_count": 2,
                "fin_count": 0,
                "rst_count": 0,
                "close_reason": "end_of_capture",
            }
        ],
        "description": "Theo dõi flow TCP qua ba bước bắt tay SYN, SYN-ACK, ACK",
        "criteria": (
            "Ba packet cùng 5-tuple tạo đúng 1 flow, state chuyển HANDSHAKE -> ESTABLISHED, "
            "hướng forward/backward chính xác, đếm đủ 2 SYN (SYN-ACK tính vào cả SYN và ACK) "
            "và 2 ACK, flow được flush khi hết capture với close_reason end_of_capture."
        ),
    },
    "bt2_t08_bidirectional": {
        "min_events": 2,
        "checks": [
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
                    "direction": "forward",
                }
            },
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
                    "direction": "backward",
                }
            },
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "packet_count": 2,
                "application_protocol": "HTTP",
                "forward": {"packet_count": 1},
                "backward": {"packet_count": 1},
            }
        ],
        "description": "Gộp request/response hai chiều vào cùng một flow",
        "criteria": (
            "Request và response ngược chiều cùng 5-tuple thuộc một flow duy nhất với "
            "flow_id ổn định, direction lần lượt là forward/backward, mỗi chiều 1 packet "
            "và application_protocol được nhận là HTTP."
        ),
    },
    "bt2_t09_tcp_close": {
        "min_events": 6,
        "checks": [
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
                    "state": "CLOSED",
                }
            },
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
                    "state": "RESET",
                }
            },
        ],
        "min_flows": 2,
        "flow_checks": [
            {
                "flow_id": "TCP-10.0.0.10:51001-10.0.0.30:80",
                "state": "CLOSED",
                "close_reason": "fin",
                "fin_count": 2,
                "packet_count": 6,
            },
            {
                "flow_id": "TCP-10.0.0.10:51002-10.0.0.30:8080",
                "state": "RESET",
                "close_reason": "rst",
                "rst_count": 1,
            },
        ],
        "description": "Đóng flow TCP bằng FIN hai chiều và bằng RST",
        "criteria": (
            "Flow thứ nhất qua chuỗi SYN, SYN-ACK, ACK, FIN, ACK, FIN chuyển sang CLOSED "
            "với close_reason fin và 2 FIN; flow thứ hai SYN rồi RST chuyển sang RESET với "
            "close_reason rst; cả hai flow record đều được ghi."
        ),
    },
    "bt2_t10_udp_dns": {
        "min_events": 2,
        "checks": [
            {
                "application": {"type": "query"},
                "flow": {"flow_id": "UDP-192.168.1.100:53000-8.8.8.8:53"},
            },
            {"application": {"type": "response"}},
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "protocol": "UDP",
                "state": "ESTABLISHED",
                "packet_count": 2,
                "byte_count": 159,
                "forward": {"packet_count": 1},
                "backward": {"packet_count": 1},
                "application_protocol": "DNS",
                "syn_count": 0,
            }
        ],
        "description": "Theo dõi flow UDP cho cặp DNS query/response",
        "criteria": (
            "Query và response DNS cùng 5-tuple tạo đúng 1 flow UDP ở trạng thái ESTABLISHED "
            "ngay từ packet đầu, đếm 2 packet (159 byte) chia đều hai chiều, "
            "application_protocol là DNS và không có cờ TCP nào được đếm."
        ),
    },
    "bt2_t11_concurrent_flows": {
        "min_events": 6,
        "checks": [
            {"flow": {"direction": "forward"}},
        ],
        "min_flows": 3,
        "flow_checks": [
            {"flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80", "packet_count": 2},
            {"flow_id": "TCP-10.0.0.11:52001-10.0.0.20:80", "packet_count": 2},
            {"flow_id": "TCP-10.0.0.10:52002-10.0.0.30:443", "packet_count": 2},
        ],
        "description": "Theo dõi đồng thời ba flow xen kẽ nhau",
        "criteria": (
            "Sáu packet thuộc ba 5-tuple xen kẽ theo thời gian tạo đúng 3 flow record riêng "
            "biệt, mỗi flow nhận đúng 2 packet và flow_id tương ứng từng kết nối."
        ),
    },
    "bt2_t12_idle_timeout": {
        "min_events": 3,
        "checks": [
            {
                "flow": {
                    "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
                    "is_new_flow": True,
                }
            },
        ],
        "min_flows": 2,
        "flow_checks": [
            {
                "flow_id": "TCP-10.0.0.10:52000-10.0.0.20:80",
                "close_reason": "timeout",
                "state": "ESTABLISHED",
                "packet_count": 2,
            },
            {
                "flow_id": "TCP-10.0.0.11:53000-10.0.0.20:8080",
                "close_reason": "end_of_capture",
            },
        ],
        "args": ["--tcp-timeout", "5"],
        "description": "Đóng flow TCP khi vượt idle timeout cấu hình được",
        "criteria": (
            "Với --tcp-timeout 5, flow thứ nhất im lặng 29.99s bị đóng với close_reason "
            "timeout sau khi packet của flow thứ hai xuất hiện, flow thứ hai vẫn active và "
            "được flush khi hết capture với close_reason end_of_capture."
        ),
    },
    "bt2_t13_statistics": {
        "min_events": 8,
        "checks": [
            {"decode": {"fields": {"body_decoded": "OK"}}},
        ],
        "min_flows": 1,
        "flow_checks": [
            {
                "packet_count": 8,
                "byte_count": 392,
                "start_time": 1700000000.0,
                "last_seen": 1700000000.7,
                "duration": 0.7,
                "forward": {"packet_count": 4, "byte_count": 192},
                "backward": {"packet_count": 4, "byte_count": 200},
                "syn_count": 2,
                "ack_count": 7,
                "fin_count": 2,
                "rst_count": 0,
                "state": "CLOSED",
                "close_reason": "fin",
            }
        ],
        "description": "Thống kê chi tiết một flow TCP đầy đủ vòng đời",
        "criteria": (
            "Flow 8 packet từ bắt tay đến khi đóng ghi đúng start_time/last_seen/duration "
            "(0.7s) và byte_count (392 = 192 xuôi + 200 ngược), đếm đúng 2 SYN, 7 ACK, "
            "2 FIN, 0 RST và đóng với close_reason fin."
        ),
    },
    "bt2_t14_malformed_event": {
        "pcap": "truncated.pcap",
        "min_events": 2,
        "checks": [
            {
                "transport": {"layer": "TCP"},
                "preprocess": {
                    "preprocess_status": "partial",
                    "reason": "no_application_layer",
                },
            },
            {
                "network": {"proto": "PROTO_0"},
                "preprocess": {
                    "preprocess_status": "partial",
                    "reason": "missing_transport_layer",
                },
            },
        ],
        "min_flows": 1,
        "description": "Xử lý event lỗi và file PCAP bị cắt cụt",
        "criteria": (
            "PCAP cắt cụt vẫn đọc được, packet IP/TCP không payload được đánh partial với "
            "reason no_application_layer và vẫn tạo flow TCP; packet IP proto 0 không có "
            "transport layer được đánh partial với reason missing_transport_layer."
        ),
    },
}


def _subset_match(actual, expected) -> bool:
    """Return True when expected is contained in actual.

    Dict: every expected key must match recursively.
    List: each expected element must match at least one actual element;
    an empty expected list means the actual list must also be empty.
    """
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(
            key in actual and _subset_match(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        if not expected:
            return actual == []
        return all(any(_subset_match(item, exp) for item in actual) for exp in expected)
    return actual == expected


def _matches_any(events, expected) -> bool:
    return any(_subset_match(event, expected) for event in events)


def _read_jsonl(path: str) -> list:
    """Read a JSON Lines file into a list of records (empty when missing)."""
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _resolve_paths(case_name: str, spec: dict):
    """Return (case_dir, pcap, output, flows, temp_dir) for a case.

    Assignment 1 cases keep their artifacts untouched: their flow records are
    written to a temporary directory because those cases do not assert flows.
    """
    case_dir = os.path.join("TEST", case_name)
    pcap_path = os.path.join(case_dir, spec.get("pcap", "test.pcap"))
    output_path = os.path.join(case_dir, "output.jsonl")
    if case_name.startswith("bt2_"):
        return case_dir, pcap_path, output_path, os.path.join(case_dir, "flows.jsonl"), None
    temp_dir = tempfile.mkdtemp(prefix="ids_flows_")
    return case_dir, pcap_path, output_path, os.path.join(temp_dir, "flows.jsonl"), temp_dir


def run_case(case_name: str, description: str, verification_criteria: str) -> int:
    spec = EXPECTATIONS.get(case_name)
    case_dir, pcap_path, output_path, flows_path, temp_dir = _resolve_paths(case_name, spec or {})
    report_path = os.path.join(case_dir, "report.md")

    if not os.path.isfile(pcap_path):
        print(f"[!] Error: {pcap_path} not found.")
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    try:
        # Run main.py on the pcap
        cmd = [
            sys.executable,
            "main.py",
            "--pcap",
            pcap_path,
            "--output",
            output_path,
            "--flows-output",
            flows_path,
        ] + list(spec.get("args", []) if spec else [])
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[!] main.py failed on {case_name}:\n{res.stderr}")
            return res.returncode

        events = _read_jsonl(output_path)
        flows = _read_jsonl(flows_path)

        # Verify registered assertions
        failures = []
        min_flows = None
        flow_checks = []
        if spec is None:
            failures.append(f"Chưa đăng ký kỳ vọng kiểm thử cho case '{case_name}'.")
            checks = []
            min_events = 0
        else:
            checks = spec["checks"]
            min_events = spec["min_events"]
            if len(events) < min_events:
                failures.append(f"Cần tối thiểu {min_events} event, thực tế {len(events)}.")
            for idx, check in enumerate(checks, start=1):
                if not _matches_any(events, check):
                    failures.append(
                        f"Không event nào khớp kỳ vọng #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )

            min_flows = spec.get("min_flows")
            if min_flows is not None and len(flows) < min_flows:
                failures.append(f"Cần tối thiểu {min_flows} flow record, thực tế {len(flows)}.")
            flow_checks = spec.get("flow_checks", [])
            for idx, check in enumerate(flow_checks, start=1):
                if not _matches_any(flows, check):
                    failures.append(
                        f"Không flow nào khớp kỳ vọng #{idx}: "
                        f"{json.dumps(check, ensure_ascii=False)}"
                    )

        status = "PASS (Thành công)" if not failures else "FAIL (Thất bại)"
        result_lines = (
            "\n".join(f"- {line}" for line in failures)
            if failures
            else "- Tất cả kỳ vọng kiểm thử đều khớp với output thực tế."
        )

        flow_header = ""
        flow_assertions = ""
        flow_section = ""
        if case_name.startswith("bt2_"):
            flow_header = (
                f"- **File Flow Records**: `{flows_path}`\n"
                f"- **Số flow record**: {len(flows)}"
            )
            flow_assertions = f"""- Số flow tối thiểu: **{min_flows if min_flows is not None else 0}**
- Danh sách flow subset bắt buộc phải khớp:
```json
{json.dumps(flow_checks, indent=2, ensure_ascii=False)}
```"""
            flow_section = f"""
## 5. Flow Records (flows.jsonl)
- **Số flow record**: {len(flows)}
- **Số flow tối thiểu**: {min_flows if min_flows is not None else 0}
- **Kỳ vọng flow (JSON subset)**:
```json
{json.dumps(flow_checks, indent=2, ensure_ascii=False)}
```
- **Chi tiết flow records**:
```json
{json.dumps(flows, indent=2, ensure_ascii=False)}
```
"""

        # Write report.md
        report_content = f"""# Test Case Report: {case_name}

- **Mục tiêu**: {description}
- **Yêu cầu kiểm thử**: {verification_criteria}
- **File PCAP**: `{pcap_path}`
- **File Output JSONL**: `{output_path}`
{flow_header}- **Số gói tin đã xử lý**: {len(events)}
- **Trạng thái**: **{status}**

---

## 1. Kết quả Phân tích (Terminal Output)
```text
{res.stdout.strip()}
```

## 2. Kỳ vọng kiểm thử (Assertions)
- Số event tối thiểu: **{min_events}**
- Danh sách JSON subset bắt buộc phải khớp:
```json
{json.dumps(checks, indent=2, ensure_ascii=False)}
```
{flow_assertions}

## 3. Đánh giá tính đúng đắn
{result_lines}
- Chương trình kết thúc bình thường (exit code 0), không crash.
- Cấu trúc dữ liệu đầu ra tuân thủ đúng định dạng JSON chuẩn hóa của đề bài.

## 4. Chi tiết Normalized Events (JSON)
```json
{json.dumps(events, indent=2, ensure_ascii=False)}
```
{flow_section}"""
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"[+] Case {case_name}: {status}. Report written to {report_path}")
        return 0 if not failures else 1
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def run_all() -> int:
    """Run every case that registers a description and criteria."""
    selected = [
        case
        for case, spec in EXPECTATIONS.items()
        if spec.get("description") and spec.get("criteria")
    ]
    if not selected:
        print("No cases registered.")
        return 0

    failed = []
    for case in selected:
        spec = EXPECTATIONS[case]
        if run_case(case, spec["description"], spec["criteria"]) != 0:
            failed.append(case)

    print("-" * 60)
    print(f"[+] {len(selected) - len(failed)}/{len(selected)} cases PASS")
    if failed:
        print(f"[!] FAILED cases: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "all":
        sys.exit(run_all())
    if len(sys.argv) < 4:
        print("Usage: python run_case.py <case_name> <description> <criteria>")
        print("       python run_case.py all")
        sys.exit(1)
    sys.exit(run_case(sys.argv[1], sys.argv[2], sys.argv[3]))
